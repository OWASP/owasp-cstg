---
cstg_id: CSTG-AWS-RDS-ENUM
title: "AWS Rds - Enumeration"
provider: aws
service: rds
phase: services
required_access: read-only-audit
required_permissions:
  - rds:DescribeDBInstances
  - rds:DescribeDBClusters
  - rds:DescribeDBSnapshots
  - rds:DescribeDBClusterSnapshots
  - rds:DescribeDBSnapshotAttributes
  - rds:DescribeDBClusterSnapshotAttributes
  - rds:DescribeDBSecurityGroups
  - rds:DescribeDBSubnetGroups
  - rds:DescribeDBParameters
  - rds:DescribeDBParameterGroups
  - rds:DescribeDBProxies
  - rds:ListTagsForResource
  - ec2:DescribeSecurityGroups
  - ec2:DescribeSubnets
  - secretsmanager:ListSecrets
references:
  - "https://docs.aws.amazon.com/cli/latest/reference/rds/index.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_IAMDBAuth.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html"
license: CC BY-SA 4.0
---

## Summary

This page covers credentialed enumeration of Amazon RDS and Aurora from a
read-only or audit foothold in an AWS account. The objective is to build a
complete inventory of database instances, clusters, snapshots, parameter and
option configuration, network exposure, encryption posture, and authentication
modes, and to surface the misconfigurations that enable later exploitation:
public accessibility, public/shared snapshots, missing encryption, weak audit
logging, IAM auth gaps, and stored secrets.

Enumeration here is read-only and uses RDS `Describe*` APIs plus supporting EC2
and Secrets Manager reads. Unauthenticated discovery is in
[aws-rds-unauthenticated.md](../01-unauthenticated-external/aws-rds-unauthenticated.md);
actions taken after access is gained are in
[aws-rds-post-exploitation.md](../05-post-exploitation/aws-rds-post-exploitation.md).

## Prerequisites

- A valid principal (user or role) with read access to RDS describe operations
  in the target account/region.
- The permissions listed in the frontmatter; the `Describe*`/`List*` set is
  read-only and covered by the AWS managed policy `AmazonRDSReadOnlyAccess`
  together with `SecurityAudit` for the cross-service reads.
- Knowledge of, or iteration over, the regions in use — RDS is regional, so
  enumeration must be repeated per region.

## Enumeration

### Instances and clusters

```bash
# All instances in a region, with the fields that matter
aws rds describe-db-instances --region us-east-1 \
  --query 'DBInstances[].{id:DBInstanceIdentifier,engine:Engine,ver:EngineVersion,
    public:PubliclyAccessible,endpoint:Endpoint.Address,port:Endpoint.Port,
    encrypted:StorageEncrypted,kms:KmsKeyId,iamauth:IAMDatabaseAuthenticationEnabled,
    sgs:VpcSecurityGroups[].VpcSecurityGroupId,subnet:DBSubnetGroup.DBSubnetGroupName,
    multiaz:MultiAZ,deletionprot:DeletionProtection}'

# Aurora clusters
aws rds describe-db-clusters --region us-east-1 \
  --query 'DBClusters[].{id:DBClusterIdentifier,engine:Engine,
    writer:Endpoint,reader:ReaderEndpoint,public:PubliclyAccessible,
    encrypted:StorageEncrypted,kms:KmsKeyId,iamauth:IAMDatabaseAuthenticationEnabled,
    members:DBClusterMembers[].DBInstanceIdentifier,
    sgs:VpcSecurityGroups[].VpcSecurityGroupId}'
```

Iterate every region:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="
  aws rds describe-db-instances --region "$r" \
    --query 'DBInstances[].[DBInstanceIdentifier,Engine,PubliclyAccessible,Endpoint.Address]' \
    --output text
done
```

### Snapshots and their sharing attributes

```bash
# Manual + automated snapshots owned by this account
aws rds describe-db-snapshots --region us-east-1 \
  --query 'DBSnapshots[].{id:DBSnapshotIdentifier,src:DBInstanceIdentifier,
    type:SnapshotType,enc:Encrypted,kms:KmsKeyId}'

# Who each manual snapshot is shared with (look for "all" or foreign account IDs)
aws rds describe-db-snapshot-attributes \
  --db-snapshot-identifier <snapshot-id> --region us-east-1 \
  --query 'DBSnapshotAttributesResult.DBSnapshotAttributes'

# Aurora cluster snapshots
aws rds describe-db-cluster-snapshots --region us-east-1
aws rds describe-db-cluster-snapshot-attributes \
  --db-cluster-snapshot-identifier <id> --region us-east-1
```

A `restore` attribute value of `all` means the snapshot is public. Foreign
account IDs indicate cross-account sharing — both are findings.

### Network, subnet, and security-group context

```bash
# Subnet groups -> which subnets/VPC the DB lives in
aws rds describe-db-subnet-groups --region us-east-1 \
  --query 'DBSubnetGroups[].{name:DBSubnetGroupName,vpc:VpcId,
    subnets:Subnets[].SubnetIdentifier}'

# Resolve the attached security groups and their inbound rules
aws ec2 describe-security-groups --group-ids <sg-id> --region us-east-1 \
  --query 'SecurityGroups[].IpPermissions'

# Are the subnets public (route to an IGW)?
aws ec2 describe-subnets --subnet-ids <subnet-id> --region us-east-1 \
  --query 'Subnets[].{id:SubnetId,public:MapPublicIpOnLaunch}'
```

### Parameter and option configuration

```bash
# Which parameter group is bound, and is force_ssl / logging on?
aws rds describe-db-parameters --db-parameter-group-name <pg> --region us-east-1 \
  --query "Parameters[?ParameterName=='rds.force_ssl' ||
           ParameterName=='require_secure_transport' ||
           ParameterName=='log_connections' ||
           ParameterName=='general_log' ||
           ParameterName=='server_audit_logging']"

# Audit log export targets per instance
aws rds describe-db-instances --region us-east-1 \
  --query 'DBInstances[].{id:DBInstanceIdentifier,
    logs:EnabledCloudwatchLogsExports}'
```

### RDS Proxy and secrets

```bash
# Proxies front DB connections and reference Secrets Manager secrets + IAM roles
aws rds describe-db-proxies --region us-east-1 \
  --query 'DBProxies[].{name:DBProxyName,auth:Auth,role:RoleArn,
    requiretls:RequireTLS,vpcsg:VpcSecurityGroupIds}'

# Secrets likely holding DB master credentials
aws secretsmanager list-secrets --region us-east-1 \
  --query "SecretList[?contains(Name,'rds') || contains(Name,'db')].{name:Name,arn:ARN}"
```

### IAM database authentication mapping

`IAMDatabaseAuthenticationEnabled` on the instance/cluster shows whether IAM auth
is available. The IAM side — which principals hold `rds-db:connect` and for which
`dbuser` — is read from IAM policies (see
[aws-rds-post-exploitation.md](../05-post-exploitation/aws-rds-post-exploitation.md)).

## Misconfigurations & Findings

- **`PubliclyAccessible = true`** on an instance/cluster, especially with an
  inbound security-group rule from `0.0.0.0/0` on the engine port.
- **Public or cross-account snapshots** (`restore` attribute = `all` or a
  foreign account ID).
- **`StorageEncrypted = false`** — data at rest unencrypted; snapshots inherit
  this, so an unencrypted snapshot can be copied without KMS access.
- **IAM database authentication disabled**, leaving native passwords as the only
  control.
- **TLS not enforced** (`rds.force_ssl`/`require_secure_transport` off) — allows
  plaintext connections.
- **No audit/log exports** (`EnabledCloudwatchLogsExports` empty) — connections
  and queries are not recorded, limiting detection.
- **`DeletionProtection = false`** and no final-snapshot policy — destructive and
  ransom risk.
- **Master credentials in Secrets Manager without rotation**, or hardcoded
  outside Secrets Manager.
- **Overly broad parameter groups** enabling risky features (e.g. SQL Server
  `xp_cmdshell` via option/parameter settings, PostgreSQL extensions).

## Exploitation

This is a read-only enumeration page; it does not itself exploit. The inventory
produced here directly feeds:

- Public/exposed instances and public snapshots →
  [aws-rds-unauthenticated.md](../01-unauthenticated-external/aws-rds-unauthenticated.md).
- Snapshot copy/restore, IAM-auth abuse, master-password reset, RDS Proxy abuse,
  and data exfiltration →
  [aws-rds-post-exploitation.md](../05-post-exploitation/aws-rds-post-exploitation.md).

A useful triage is to rank instances by exposure: public + open SG + unencrypted
+ no logging is the highest-priority target.

## Detection & Logging

- All `Describe*`/`List*` calls above are recorded in CloudTrail as read events
  (e.g. `DescribeDBInstances`, `DescribeDBSnapshotAttributes`). They are
  management-event reads and only captured if the trail logs read events.
- A burst of enumeration from a single principal across many regions and
  services is a recon signal; correlate `rds:Describe*`, `ec2:DescribeSecurityGroups`,
  and `secretsmanager:ListSecrets` from one session.
- `secretsmanager:GetSecretValue` (the actual credential read, beyond listing) is
  a higher-signal event to alert on.
- GuardDuty produces `Discovery:*` findings for anomalous enumeration patterns.

## Remediation & Hardening

- Apply least privilege: grant `AmazonRDSReadOnlyAccess` only to principals that
  need it; restrict `DescribeDBSnapshotAttributes` and Secrets Manager reads.
- Continuously evaluate with AWS Config managed rules:
  `rds-instance-public-access-check`, `rds-snapshots-public-prohibited`,
  `rds-storage-encrypted`, `rds-logging-enabled`, `rds-instance-iam-authentication-enabled`,
  `rds-deletion-protection-enabled`.
- Encrypt all instances and snapshots with KMS; enforce TLS via parameter groups.
- Enable audit log exports to CloudWatch Logs for every engine.
- Store master credentials in Secrets Manager with rotation; prefer IAM database
  authentication or RDS Proxy with IAM auth.

## Tools

- `aws` CLI (`rds`, `ec2`, `secretsmanager`) — primary enumeration.
- Cloud inventory/posture tooling (multi-account graph and posture scanners) —
  to aggregate findings across accounts and regions, neutrally.
- Engine clients — for follow-on validation once access is established.

## References

- AWS — RDS CLI reference (Describe operations).
- AWS — IAM database authentication.
- AWS — RDS security groups.
- AWS — Sharing a DB snapshot.
- AWS — Using RDS Proxy.
