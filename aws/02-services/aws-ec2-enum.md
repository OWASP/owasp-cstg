---
cstg_id: CSTG-AWS-EC2-ENUM
title: "AWS Ec2 - Enumeration"
provider: aws
service: ec2
phase: services
required_access: read-only-audit
required_permissions:
  - ec2:DescribeInstances
  - ec2:DescribeInstanceAttribute
  - ec2:DescribeSecurityGroups
  - ec2:DescribeNetworkInterfaces
  - ec2:DescribeVpcs
  - ec2:DescribeSubnets
  - ec2:DescribeRouteTables
  - ec2:DescribeVolumes
  - ec2:DescribeSnapshots
  - ec2:DescribeImages
  - ec2:DescribeKeyPairs
  - ec2:DescribeAddresses
  - ec2:DescribeRegions
  - ec2:DescribeInstanceTypes
  - ec2:GetLaunchTemplateData
  - ssm:DescribeInstanceInformation
references:
  - "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html"
  - "https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-state-manager.html"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated enumeration of the EC2 service using read-only/audit access. The goal is to build a complete picture of the compute estate: every instance, its network exposure and Security Groups, attached IAM instance profiles, user-data (a frequent secret store), volumes and snapshots (which may be public or shareable), AMIs, key pairs, Elastic IPs, and SSM-managed status. This inventory feeds directly into [Privilege Escalation](../03-privilege-escalation/aws-ec2-privesc.md) and [Post-Exploitation](../05-post-exploitation/aws-ec2-post-exploitation.md): the attacker is looking for instances with powerful roles, secrets in user-data, readable snapshots, and reachable management paths.

## Prerequisites

- Valid AWS credentials with read/describe access to EC2 (the `ReadOnlyAccess` / `SecurityAudit` managed policies, or the discrete `ec2:Describe*` permissions in the frontmatter). Many `Describe*` calls succeed even with surprisingly narrow policies.
- Knowledge that EC2 is regional: enumeration must iterate every enabled region. `aws ec2 describe-regions` lists them.

## Enumeration

### Regions and account context

```bash
aws sts get-caller-identity
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

### Instances and their key attributes

```bash
REGION=us-east-1
aws ec2 describe-instances --region $REGION \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType,
           AZ:Placement.AvailabilityZone,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,
           Profile:IamInstanceProfile.Arn,Image:ImageId,KeyName:KeyName,Subnet:SubnetId,
           SGs:SecurityGroups[].GroupId,Tags:Tags}' --output json

# Iterate all regions
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $R =="
  aws ec2 describe-instances --region $R \
    --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress,IamInstanceProfile.Arn]' \
    --output text
done
```

### User-data (high-value: secrets often live here)

```bash
aws ec2 describe-instance-attribute --region $REGION \
  --instance-id i-0123456789abcdef0 --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
```

User-data routinely contains bootstrap scripts with hardcoded credentials, database passwords, API tokens, and configuration management secrets.

### Network exposure: Security Groups, ENIs, VPCs

```bash
# Security Groups - look for 0.0.0.0/0 ingress
aws ec2 describe-security-groups --region $REGION \
  --query 'SecurityGroups[].{Id:GroupId,Name:GroupName,
           Ingress:IpPermissions[?contains(to_string(IpRanges[].CidrIp),`0.0.0.0/0`)]}' \
  --output json

aws ec2 describe-network-interfaces --region $REGION \
  --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,PrivateIp:PrivateIpAddress,
           PublicIp:Association.PublicIp,Attached:Attachment.InstanceId}' --output json

aws ec2 describe-vpcs --region $REGION
aws ec2 describe-subnets --region $REGION
aws ec2 describe-route-tables --region $REGION
aws ec2 describe-addresses --region $REGION   # Elastic IPs
```

### Volumes, snapshots, AMIs, key pairs

```bash
aws ec2 describe-volumes --region $REGION \
  --query 'Volumes[].{Id:VolumeId,State:State,Enc:Encrypted,Attach:Attachments[].InstanceId}'

# Snapshots owned by this account
aws ec2 describe-snapshots --owner-ids self --region $REGION \
  --query 'Snapshots[].{Id:SnapshotId,Vol:VolumeId,Enc:Encrypted,Desc:Description}'

# Is a snapshot shared/public? (createVolumePermission)
aws ec2 describe-snapshot-attribute --region $REGION \
  --snapshot-id snap-0123456789abcdef0 --attribute createVolumePermission

# AMIs owned + AMIs explicitly shared with us; check public launch perms
aws ec2 describe-images --owners self --region $REGION
aws ec2 describe-image-attribute --region $REGION \
  --image-id ami-0123456789abcdef0 --attribute launchPermission

aws ec2 describe-key-pairs --region $REGION
```

### SSM-managed instances (path to command execution later)

```bash
aws ssm describe-instance-information --region $REGION \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,
           Platform:PlatformName,Agent:AgentVersion}' --output json
```

Instances with the SSM agent online and an attached SSM-capable role are candidates for `ssm:SendCommand`/Session Manager access in later phases.

## Misconfigurations & Findings

- **Public or broadly-shared EBS snapshots and AMIs.** `createVolumePermission`/`launchPermission` set to `all` (or shared to unknown account IDs) leaks entire disk images, including credentials and keys.
- **Secrets in user-data.** Plaintext passwords/tokens recoverable via `describe-instance-attribute`.
- **Over-privileged instance profiles.** Roles attached to instances that grant `iam:*`, `*:*`, or pass-role/run-instances capabilities (see PrivEsc page).
- **Unencrypted volumes and snapshots.**
- **Permissive Security Groups** (`0.0.0.0/0` ingress on sensitive ports).
- **Stale/unused key pairs and orphaned ENIs/Elastic IPs.**
- **Instances missing from inventory** in non-default regions (shadow infrastructure).

## Exploitation

Enumeration itself is read-only, but it directly enables exploitation:

1. **Mount a readable snapshot.** If a snapshot is shared with the attacker's account, create a volume from it in the attacker's environment, attach it to a controlled instance, and read its contents:
   ```bash
   aws ec2 create-volume --snapshot-id snap-0123456789abcdef0 \
     --availability-zone us-east-1a --region us-east-1
   # attach to attacker instance, then mount and loot at OS level
   ```
2. **Harvest user-data secrets** and authenticate to the discovered services.
3. **Target the most powerful instance profile** identified, then proceed to [Privilege Escalation](../03-privilege-escalation/aws-ec2-privesc.md).

## Detection & Logging

- All `Describe*`/`Get*` EC2 and SSM calls are **management events in CloudTrail** (`eventSource: ec2.amazonaws.com` / `ssm.amazonaws.com`). High-volume describe activity across many regions from a single principal is a strong reconnaissance signal.
- GuardDuty `Discovery:*` and `Recon:IAMUser/*` findings flag enumeration patterns, especially from unusual locations.
- `DescribeInstanceAttribute` with `attribute=userData` is a notable event - legitimate callers rarely read user-data at scale.
- `ModifySnapshotAttribute`/`ModifyImageAttribute` (if the attacker shares a snapshot to their own account) and `CreateVolume` from a foreign account are detectable; cross-account snapshot/AMI sharing is logged in the owning account.

## Remediation & Hardening

- **Audit and lock down sharing.** Ensure no EBS snapshot or AMI has public or unintended cross-account launch/volume permissions; enable "Block Public Access for EBS Snapshots" at the account level.
- **Never store secrets in user-data.** Use SSM Parameter Store/Secrets Manager fetched at runtime via the instance role.
- **Encrypt volumes and snapshots by default** (enable account-level EBS encryption-by-default).
- **Scope audit/read roles** and monitor for anomalous cross-region describe storms.
- **Tag and reconcile inventory** across all regions; remove orphaned resources and unused key pairs.

## Tools

- AWS CLI / SDKs for `Describe*` enumeration.
- Cloud inventory and posture tools that ingest EC2 describe APIs (neutral: any multi-account enumeration framework).
- Offline graphing of IAM/instance-profile relationships to spot privileged instances.

## References

- AWS EC2 API reference for the describe operations above.
- AWS EBS snapshot and AMI permission documentation.
- AWS Systems Manager instance information docs.
- hackingthe.cloud - looting public EBS snapshots.
