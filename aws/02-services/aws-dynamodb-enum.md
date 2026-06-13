---
cstg_id: CSTG-AWS-DYNAMODB-ENUM
title: "AWS Dynamodb - Enumeration"
provider: aws
service: dynamodb
phase: services
required_access: read-only-audit
required_permissions:
  - dynamodb:ListTables
  - dynamodb:DescribeTable
  - dynamodb:ListTagsOfResource
  - dynamodb:DescribeContinuousBackups
  - dynamodb:ListBackups
  - dynamodb:DescribeBackup
  - dynamodb:ListGlobalTables
  - dynamodb:DescribeGlobalTable
  - dynamodb:DescribeTimeToLive
  - dynamodb:DescribeExport
  - dynamodb:ListExports
  - dynamodb:DescribeStream
  - dynamodb:DescribeKinesisStreamingDestination
  - dynamodb:GetResourcePolicy
  - dax:DescribeClusters
tools:
  - AWS CLI
  - Pacu
  - ScoutSuite
  - Prowler
  - CloudMapper
references:
  - "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html"
  - "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazondynamodb.html"
  - "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-resource-based.html"
  - "https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/"
license: CC BY-SA 4.0
---

## Summary

Amazon DynamoDB is a fully managed, serverless key-value and document database. Tables are schemaless beyond their primary key, are accessed exclusively through the AWS API (HTTPS/`DynamoDB_20120810` JSON protocol) rather than a network endpoint a client opens directly, and are governed entirely by IAM and optional resource-based policies. Because DynamoDB frequently stores the highest-value records in an environment - user records, session tokens, credentials, payment metadata, application secrets, IoT telemetry - it is a primary objective in the data layer.

This page covers read-only enumeration of DynamoDB: discovering tables and their configuration, mapping their primary key structure and indexes, identifying backups, exports, streams, global replicas, encryption posture, and resource-based policies, and assessing how those settings expose data or expand the reachable surface. Enumeration is a precursor to the data-extraction and pivoting techniques described in [AWS Dynamodb - Post-Exploitation](../05-post-exploitation/aws-dynamodb-post-exploitation.md). The objective at this phase is to inventory every table and replication/export channel, understand its key schema (necessary to read it efficiently), and flag misconfigurations - permissive resource policies, public exports, unencrypted backups, and streams feeding other consumers.

## Prerequisites

- Read-only/audit credentials for the target account (an STS session, long-term access key, or assumed role) with the DynamoDB describe/list permissions listed in the frontmatter. The `arn:aws:iam::aws:policy/ReadOnlyAccess` and `SecurityAudit` managed policies grant all of these.
- For control-plane enumeration only, table-data read permissions (`dynamodb:Scan`, `dynamodb:Query`, `dynamodb:GetItem`, `dynamodb:BatchGetItem`, `dynamodb:PartiQLSelect`) are NOT required and are intentionally out of scope here; data extraction is covered in the post-exploitation page.
- The region(s) in scope. DynamoDB is region-scoped; a table named `Users` in `us-east-1` is distinct from one in `eu-west-1`. Always enumerate every region in scope.
- Awareness that DynamoDB enumeration is high-volume by region. `DescribeTable` and related read calls are logged to CloudTrail as management events (see Detection & Logging).

## Enumeration

### Identify the caller and region set

```bash
aws sts get-caller-identity
# Regions to sweep
aws account list-regions --query 'Regions[?RegionOptStatus==`ENABLED` || RegionOptStatus==`ENABLED_BY_DEFAULT`].RegionName' --output text 2>/dev/null \
  || aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

### List tables per region

```bash
for region in us-east-1 us-west-2 eu-west-1; do
  echo "== $region =="
  aws dynamodb list-tables --region "$region" --output text
done
```

`ListTables` paginates 100 names at a time; follow `LastEvaluatedTableName` with `--exclusive-start-table-name` for large accounts.

### Describe each table

`DescribeTable` is the core enumeration call. It reveals the key schema, attribute types of key/index attributes, item/byte counts, global and local secondary indexes, stream configuration, SSE settings, the table ARN, and billing mode.

```bash
aws dynamodb describe-table --region us-east-1 --table-name Users
```

Key fields to capture:

- `Table.KeySchema` / `AttributeDefinitions` - the partition key (`HASH`) and optional sort key (`RANGE`). You must know these to build efficient `Query`/`GetItem` calls later.
- `Table.GlobalSecondaryIndexes[]` and `LocalSecondaryIndexes[]` - alternate access patterns; GSIs with `ProjectionType: ALL` expose the full item via a different key, and a GSI may be readable even when scanning the base table is throttled or restricted.
- `Table.ItemCount` / `Table.TableSizeBytes` - approximate size (updated ~every 6 hours). Indicates how much data a full read would pull and whether it is sensitive-by-volume.
- `Table.SSEDescription` - encryption posture. Absent or `Status` with default AWS-owned key vs. `KMSMasterKeyArn` (customer-managed KMS). See Misconfigurations.
- `Table.StreamSpecification` / `Table.LatestStreamArn` - whether a DynamoDB Stream is enabled and its view type.
- `Table.TableArn` - needed for tag, policy, and backup lookups.
- `Table.Replicas[]` - global-table replica regions.

Loop over all tables:

```bash
region=us-east-1
for t in $(aws dynamodb list-tables --region $region --query 'TableNames[]' --output text); do
  aws dynamodb describe-table --region $region --table-name "$t" \
    --query 'Table.{Name:TableName,Keys:KeySchema,GSI:GlobalSecondaryIndexes[].IndexName,SSE:SSEDescription,Stream:LatestStreamArn,Items:ItemCount,Replicas:Replicas[].RegionName}'
done
```

### Tags (often leak ownership, environment, data classification)

```bash
aws dynamodb list-tags-of-resource --region us-east-1 \
  --resource-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users
```

### Resource-based policy

DynamoDB supports resource-based policies on tables, indexes, and streams. A permissive policy can grant cross-account or wildcard principals read/write access independent of IAM.

```bash
aws dynamodb get-resource-policy --region us-east-1 \
  --resource-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users
```

Inspect the returned `Policy` document for `"Principal": "*"`, `"Principal": {"AWS": "*"}`, external account IDs in the principal, or `Allow` on `dynamodb:GetItem`/`Scan`/`Query`/`PartiQLSelect`/`ExportTableToPointInTime` without tight `Condition` constraints.

### Continuous backups (PITR) and on-demand backups

```bash
# Point-in-time recovery status (PITR enables restore to any second in the window)
aws dynamodb describe-continuous-backups --region us-east-1 --table-name Users

# On-demand and AWS Backup-created backups
aws dynamodb list-backups --region us-east-1 --table-name Users
aws dynamodb describe-backup --region us-east-1 \
  --backup-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/backup/01700000000000-aaaaaaaa
```

Backups are an alternate copy of the data and a common forgotten-data finding. PITR being enabled means an attacker with restore permissions can materialize a fresh table from any point in the recovery window.

### Time-to-live, exports, and Kinesis/stream destinations

```bash
aws dynamodb describe-time-to-live --region us-east-1 --table-name Users

# S3 exports - data may be sitting in a bucket
aws dynamodb list-exports --region us-east-1 \
  --table-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users
aws dynamodb describe-export --region us-east-1 \
  --export-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/export/01700000000000-bbbbbbbb

# Kinesis Data Streams replication destination (item changes streamed out)
aws dynamodb describe-kinesis-streaming-destination --region us-east-1 --table-name Users
```

An export records its `S3Bucket`, `S3Prefix`, and whether output was encrypted - follow this into S3 enumeration, since the export may live in a bucket with weaker controls than the table.

### Streams (change data capture)

```bash
aws dynamodbstreams list-streams --region us-east-1 --table-name Users
aws dynamodbstreams describe-stream --region us-east-1 \
  --stream-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/stream/2026-01-01T00:00:00.000
```

`StreamViewType` of `NEW_AND_OLD_IMAGES` or `OLD_IMAGE` means full item contents (including deleted/overwritten values) flow through the stream, typically consumed by a Lambda - map that consumer as a downstream target.

### Global tables (multi-region replication)

```bash
aws dynamodb list-global-tables --region us-east-1
aws dynamodb describe-global-table --region us-east-1 --global-table-name Users
```

Replicas in other regions or accounts are additional read targets; a control gap in any replica region exposes the same data.

### DynamoDB Accelerator (DAX) clusters

DAX is an in-memory cache that sits in a VPC and serves table data with its own IAM actions and security groups.

```bash
aws dax describe-clusters --region us-east-1
aws dax describe-parameter-groups --region us-east-1
aws dax describe-subnet-groups --region us-east-1
```

Note cluster endpoints, security groups, and whether encryption in transit/at rest is enabled - a DAX node reachable from a compromised host can return cached items without a `dynamodb:` API call.

### Raw API form

All of the above are also reachable as signed POSTs to `https://dynamodb.<region>.amazonaws.com/` with header `X-Amz-Target: DynamoDB_20120810.<Operation>`, useful when the CLI is unavailable:

```bash
aws dynamodb list-tables --debug 2>&1 | grep -i x-amz-target
```

## Misconfigurations & Findings

- **Permissive resource-based policy.** A table/stream/index policy allowing `"*"` or a cross-account principal to `GetItem`/`Scan`/`Query`/`PartiQLSelect`/`ExportTableToPointInTime` grants data access outside the account's IAM model. Cross-account `RestoreTableFromBackup`/`ExportTableToPointInTime` can exfiltrate the entire dataset.
- **Encryption with the default AWS-owned key only.** All DynamoDB tables are encrypted at rest, but the default is an AWS-owned key with no customer visibility, no key policy controls, and no separate audit trail. Sensitive tables should use a customer-managed KMS key (CMK) so access can be gated and logged via the key policy and CloudTrail KMS events.
- **Streams with full-image view type feeding broad consumers.** `NEW_AND_OLD_IMAGES`/`OLD_IMAGE` streams expose complete records, including values that were overwritten or deleted, to any IAM principal able to read the stream.
- **Exports to loosely controlled S3 buckets.** Point-in-time exports write JSON/ION to S3; if the destination bucket is public, cross-account readable, or unencrypted, the table contents are exposed independent of DynamoDB permissions.
- **PITR enabled with broad restore permissions.** Combined with `dynamodb:RestoreTableToPointInTime`/`RestoreTableFromBackup`, a principal can clone data into a new table that may not inherit the original's resource policy or tags.
- **GSIs projecting all attributes.** A GSI with `ProjectionType: ALL` lets a principal read every attribute of every item via the index key, sometimes bypassing assumptions that "only the base table holds the full record."
- **Sensitive data inferable from table/index/tag names.** Names like `Sessions`, `ApiKeys`, `Tokens`, `pii-users`, or tags `dataClassification: confidential` signal high-value targets before any item is read.
- **DAX without encryption in transit or with permissive security groups.** A cache node reachable on the network can serve items to a principal that lacks direct table permissions.
- **Global-table replicas in less-controlled regions/accounts.** A replica region with weaker guardrails (no SCP, no detective controls) exposes the same data.

## Exploitation

Enumeration itself is read-only and non-destructive, but it directly enables exploitation. The control-plane facts gathered here feed the data-plane and pivot techniques in [AWS Dynamodb - Post-Exploitation](../05-post-exploitation/aws-dynamodb-post-exploitation.md):

- Key schema from `DescribeTable` lets you build precise `GetItem`/`Query` calls instead of expensive full scans.
- A permissive resource policy discovered via `GetResourcePolicy` may permit cross-account reads or exports you can perform directly from attacker-controlled credentials.
- Identified backups, exports, and PITR windows are alternate copies that can be restored or downloaded without touching the live table.
- Stream and Kinesis destinations identify downstream consumers (Lambdas, analytics pipelines) to pivot into.

When the enumeration credential also holds data-plane permissions, proceed to extraction in the post-exploitation page. Where it does not, the misconfigurations above (public exports, permissive policies, restorable backups) are the exploitation vectors.

## Detection & Logging

- **CloudTrail management events.** All control-plane calls here are recorded in CloudTrail as `eventSource: dynamodb.amazonaws.com` (and `streams.dynamodb.amazonaws.com`, `dax.amazonaws.com`): `ListTables`, `DescribeTable`, `ListTagsOfResource`, `GetResourcePolicy`, `DescribeContinuousBackups`, `ListBackups`, `ListExports`, `DescribeExport`, `DescribeStream`, `ListGlobalTables`, `DescribeKinesisStreamingDestination`. A burst of `ListTables`+`DescribeTable` across many regions from one principal in a short window is a strong enumeration signal.
- **Data-plane events are NOT logged by default.** `GetItem`, `Query`, `Scan`, `PutItem`, `PartiQL*`, and `BatchGetItem` are DynamoDB *data events* and only appear in CloudTrail if data event logging is explicitly enabled for the table in the trail. Control-plane enumeration is therefore far more visible than the subsequent reads - defenders should enable DynamoDB data events on sensitive tables.
- **Cross-region/cross-account patterns.** Enumeration sweeping every region, or `GetResourcePolicy`/`DescribeExport` calls from an unusual principal, are useful detections. GuardDuty does not have a dedicated DynamoDB finding family, so detection relies on CloudTrail analytics (Athena, Security Lake, SIEM) and anomaly rules.
- **KMS events.** For CMK-encrypted tables, related `kms:Decrypt`/`GenerateDataKey` calls appear under `kms.amazonaws.com` and can corroborate access to a specific table's key.

## Remediation & Hardening

- Scope IAM and resource policies to specific tables/indexes and specific actions; avoid `dynamodb:*` and wildcard resources. Constrain `Scan`/`PartiQLSelect` and prefer `dynamodb:LeadingKeys` / `dynamodb:Attributes` condition keys for row/column-level isolation.
- Remove or tightly constrain resource-based policies; never allow `Principal: "*"` or untrusted external accounts. Add `aws:SourceAccount`/`aws:PrincipalOrgID` conditions for any legitimate cross-account access.
- Encrypt sensitive tables with a customer-managed KMS key and lock the key policy; this provides per-table access control and a dedicated audit trail.
- Send exports only to encrypted, private buckets and enforce with bucket policies and S3 Block Public Access; review existing exports for stale data.
- Treat backups and PITR as protected data: restrict `RestoreTable*`, `CreateBackup`, and `ExportTableToPointInTime` to break-glass roles.
- Enable encryption in transit and at rest for DAX and restrict its security groups to required subnets only.
- Enable CloudTrail data events on high-value tables, ship them to a SIEM/Security Lake, and alert on broad enumeration, cross-account reads, and unexpected exports/restores.
- Apply SCPs to block DynamoDB usage in unused regions, reducing the enumeration and replica surface.

## Tools

- **AWS CLI** - `dynamodb`, `dynamodbstreams`, and `dax` command groups for all enumeration calls above.
- **Pacu** - modules for enumerating DynamoDB tables and harvesting data across regions.
- **ScoutSuite** - audits DynamoDB encryption, backups/PITR, and resource policy posture across an account.
- **Prowler** - checks covering DynamoDB PITR, encryption, and accelerator/DAX configuration.
- **CloudMapper** - account-wide resource and trust visualization that includes data stores like DynamoDB.

## References

- AWS - Amazon DynamoDB Developer Guide: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html>
- AWS - DynamoDB API Reference: <https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html>
- AWS - Actions, resources, and condition keys for Amazon DynamoDB: <https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazondynamodb.html>
- AWS - Resource-based policies for DynamoDB: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-resource-based.html>
- AWS - DynamoDB encryption at rest: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html>
- AWS - Logging DynamoDB operations with CloudTrail: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html>
- Hacking the Cloud - AWS enumeration techniques: <https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/>
