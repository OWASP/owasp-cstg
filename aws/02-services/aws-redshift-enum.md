---
cstg_id: CSTG-AWS-REDSHIFT-ENUM
title: "AWS Redshift - Enumeration"
provider: aws
service: redshift
phase: services
required_access: read-only-audit
required_permissions:
  - redshift:DescribeClusters
  - redshift:DescribeClusterParameterGroups
  - redshift:DescribeClusterParameters
  - redshift:DescribeClusterSubnetGroups
  - redshift:DescribeClusterSecurityGroups
  - redshift:DescribeClusterSnapshots
  - redshift:DescribeLoggingStatus
  - redshift:DescribeClusterDbRevisions
  - redshift:DescribeScheduledActions
  - redshift:DescribeEndpointAccess
  - redshift:DescribeEndpointAuthorization
  - redshift:GetClusterCredentials
  - redshift:GetClusterCredentialsWithIAM
  - redshift-serverless:ListNamespaces
  - redshift-serverless:ListWorkgroups
  - redshift-serverless:GetWorkgroup
  - redshift-serverless:ListSnapshots
  - redshift-data:ListDatabases
  - redshift-data:ListSchemas
  - redshift-data:ListTables
  - redshift-data:ExecuteStatement
  - ec2:DescribeSecurityGroups
  - ec2:DescribeSubnets
tools:
  - aws-cli
  - boto3
  - psql
  - redshift-data-api
  - cloud-inventory-scanners
references:
  - https://docs.aws.amazon.com/redshift/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-identity-based.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/data-api.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/managing-snapshots-console.html
  - https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/Welcome.html
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated enumeration of Amazon Redshift from a read-only / audit perspective: discovering provisioned clusters and Serverless workgroups, mapping their network exposure (public accessibility, security groups, subnet groups, VPC endpoints), reviewing parameter groups for weak settings (SSL, logging), inventorying snapshots and their share status, and identifying authentication paths (master credentials, IAM-based credential vending, and the Data API). The objective is to build a complete picture of every warehouse in scope, its exposure, and the conditions that would allow data access or privilege escalation, without yet modifying anything.

## Prerequisites

- Valid AWS credentials with read/describe access to Redshift, Redshift Serverless, and EC2 networking APIs (a `ReadOnlyAccess`-style or `SecurityAudit`-style identity is sufficient for most steps).
- For in-database enumeration, either the Data API (`redshift-data:*`) or network access plus a credential vended by `GetClusterCredentials`/`GetClusterCredentialsWithIAM`.
- Per-region iteration: Redshift resources are regional. Enumerate every enabled region.

## Enumeration

### Provisioned clusters

```bash
# All clusters in the region: endpoint, public accessibility, VPC, encryption, master user
aws redshift describe-clusters \
  --query 'Clusters[].{Id:ClusterIdentifier,Endpoint:Endpoint.Address,Port:Endpoint.Port,Public:PubliclyAccessible,VPC:VpcId,Encrypted:Encrypted,KmsKeyId:KmsKeyId,MasterUser:MasterUsername,IamRoles:IamRoles,SGs:VpcSecurityGroups}' \
  --output json
```

Key fields to capture per cluster:

- `PubliclyAccessible` - internet exposure (cross-reference [unauthenticated](../01-unauthenticated-external/aws-redshift-unauthenticated.md)).
- `Encrypted` / `KmsKeyId` - at-rest encryption and which KMS key (relevant to snapshot sharing).
- `MasterUsername` - the admin account name (default `awsuser`/`admin` is a finding).
- `IamRoles` - roles attached to the cluster, usable for COPY/UNLOAD to S3 and a lateral-movement vector (see post-exploitation).
- `VpcSecurityGroups`, `ClusterSubnetGroupName` - network placement.

### Network exposure

```bash
# Security groups attached to the cluster
aws ec2 describe-security-groups --group-ids <sg-id> \
  --query 'SecurityGroups[].IpPermissions'

# Subnet group -> subnets (public vs private)
aws redshift describe-cluster-subnet-groups
aws ec2 describe-subnets --subnet-ids <subnet-id> \
  --query 'Subnets[].{Id:SubnetId,Public:MapPublicIpOnLaunch,Cidr:CidrBlock}'

# Managed VPC endpoints (cross-VPC access) and authorizations
aws redshift describe-endpoint-access
aws redshift describe-endpoint-authorization
```

Flag any ingress rule on 5439 (or the configured port) allowing `0.0.0.0/0` or broad ranges, especially combined with `PubliclyAccessible = true`.

### Parameter groups (SSL, logging, query behaviour)

```bash
aws redshift describe-cluster-parameter-groups
aws redshift describe-cluster-parameters --parameter-group-name <pg-name> \
  --query 'Parameters[?ParameterName==`require_ssl` || ParameterName==`enable_user_activity_logging`]'
```

`require_ssl = false` and `enable_user_activity_logging = false` are hardening findings.

### Audit logging status

```bash
aws redshift describe-logging-status --cluster-identifier <id>
```

Records whether connection/user/user-activity logs are delivered to S3 or CloudWatch. Absent logging is a detection gap and is itself a finding.

### Snapshots and their sharing status

```bash
# Manual + automated snapshots
aws redshift describe-cluster-snapshots \
  --query 'Snapshots[].{Id:SnapshotIdentifier,Cluster:ClusterIdentifier,Type:SnapshotType,Encrypted:Encrypted,Owner:OwnerAccount,AccountsWithAccess:AccountsWithRestoreAccess}' \
  --output json
```

Inspect `AccountsWithRestoreAccess`. A snapshot shared with `all` is a public data-exposure finding; a snapshot shared with an unexpected external account ID is a finding. Unencrypted snapshots cannot be shared cross-account but can still be restored within the account.

### Redshift Serverless

```bash
aws redshift-serverless list-namespaces
aws redshift-serverless list-workgroups
aws redshift-serverless get-workgroup --workgroup-name <name> \
  --query 'workgroup.{Endpoint:endpoint.address,Public:publiclyAccessible,SGs:securityGroupIds,Subnets:subnetIds}'
aws redshift-serverless list-snapshots
```

`publiclyAccessible = true` on a workgroup has the same exposure implications as a provisioned cluster.

### In-database enumeration via the Data API

The Data API runs SQL without a persistent connection and authenticates with IAM, Secrets Manager, or temporary credentials. With `redshift-data` permissions and either an attached secret or `GetClusterCredentials`:

```bash
# Provisioned (using a Secrets Manager secret)
aws redshift-data list-databases --cluster-identifier <id> --database dev --secret-arn <arn>
aws redshift-data list-schemas   --cluster-identifier <id> --database dev --secret-arn <arn>
aws redshift-data list-tables    --cluster-identifier <id> --database dev --schema public --secret-arn <arn>

# Serverless
aws redshift-data list-databases --workgroup-name <wg> --database dev

# Execute a read-only statement and fetch the result
SID=$(aws redshift-data execute-statement --cluster-identifier <id> --database dev \
  --secret-arn <arn> --sql 'SELECT current_user, current_database()' --query Id --output text)
aws redshift-data describe-statement --id "$SID"
aws redshift-data get-statement-result --id "$SID"
```

### In-database enumeration via a vended credential

```bash
# Vend a temporary DB password for an existing or auto-created DB user
aws redshift get-cluster-credentials --cluster-identifier <id> --db-user <user> --db-name dev \
  --duration-seconds 3600
# IAM-native variant returning a token tied to the IAM identity
aws redshift get-cluster-credentials-with-iam --cluster-identifier <id> --db-name dev
```

Then enumerate schema and grants directly:

```sql
-- Databases, schemas, tables
SELECT datname FROM pg_database;
SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema');
SELECT * FROM svv_redshift_databases;   -- includes Data Sharing / datashare DBs
SELECT * FROM svv_all_tables LIMIT 100;

-- Users, groups, superusers
SELECT usename, usesuper, usecreatedb FROM pg_user;
SELECT groname, grolist FROM pg_group;

-- Object and column privileges
SELECT * FROM information_schema.table_privileges;
SELECT * FROM information_schema.role_table_grants;

-- Datashares (cross-cluster / cross-account sharing)
SELECT * FROM svv_datashares;
SELECT * FROM svv_datashare_consumers;

-- Federated queries / external schemas (Spectrum, RDS/Aurora federation)
SELECT * FROM svv_external_schemas;
```

`svv_datashares`/`svv_datashare_consumers` reveal cross-account data sharing relationships; external schemas reveal connections out to S3 (Spectrum) and federated RDS/Aurora sources, which expand the data and lateral-movement surface.

## Misconfigurations & Findings

- `PubliclyAccessible = true` on a cluster or workgroup.
- Security group permitting 5439 from `0.0.0.0/0` or broad CIDRs.
- `require_ssl = false` (cleartext auth/queries permitted).
- Audit / user-activity logging disabled.
- Default master username (`awsuser`, `admin`) and/or static master password not rotated to Secrets Manager.
- Snapshots shared publicly (`all`) or with unexpected external accounts.
- Overly broad attached IAM roles (e.g. broad S3 access usable via COPY/UNLOAD).
- Cluster not encrypted at rest.
- Datashares or endpoint authorizations granting access to unexpected consumer accounts.
- Database users with unnecessary `usesuper` (superuser) privileges or broad grants.

## Detection & Logging

All Describe/List/Get calls above are recorded in **CloudTrail** as Redshift, Redshift Serverless, Redshift Data, and EC2 management events. High-volume `Describe*` enumeration from a single principal in a short window is a recon signal. `GetClusterCredentials` / `GetClusterCredentialsWithIAM` and `redshift-data:ExecuteStatement` indicate an identity vending DB access or running SQL; these are useful pivots between IAM activity and in-database activity. In-database queries (when audit logging is enabled) appear in the cluster's connection/user/user-activity logs.

## Remediation & Hardening

- Apply least privilege to the audit identity; restrict `GetClusterCredentials*` and `redshift-data:*` to the principals and clusters that need them.
- Disable public accessibility and tighten security groups (see [unauthenticated](../01-unauthenticated-external/aws-redshift-unauthenticated.md#remediation--hardening)).
- Set `require_ssl = true` and `enable_user_activity_logging = true`.
- Enable cluster audit logging to CloudWatch/S3 and alert on enumeration bursts and credential vending.
- Encrypt clusters and snapshots with customer-managed KMS keys; never share snapshots publicly.
- Review datashare consumers and endpoint authorizations against an allowlist of expected accounts.
- Minimise in-database superusers and broad object grants; rotate master credentials into Secrets Manager and prefer IAM authentication.

## Tools

- `aws-cli`, `boto3` (Redshift / Redshift Serverless / Redshift Data / EC2 APIs)
- `psql`, JDBC/ODBC Redshift drivers
- Redshift Data API (connectionless SQL)
- Cloud inventory / posture scanners for cross-account exposure mapping

## References

- AWS - Amazon Redshift API reference: https://docs.aws.amazon.com/redshift/latest/APIReference/Welcome.html
- AWS - Identity-based access control: https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-identity-based.html
- AWS - Using the Redshift Data API: https://docs.aws.amazon.com/redshift/latest/mgmt/data-api.html
- AWS - Database audit logging: https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html
- AWS - Managing snapshots: https://docs.aws.amazon.com/redshift/latest/mgmt/managing-snapshots-console.html
- AWS - Redshift Serverless API reference: https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/Welcome.html
