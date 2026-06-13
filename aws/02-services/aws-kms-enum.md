---
cstg_id: CSTG-AWS-KMS-ENUM
title: "AWS Kms - Enumeration"
provider: aws
service: kms
phase: services
required_access: read-only-audit
required_permissions:
  - kms:ListKeys
  - kms:ListAliases
  - kms:DescribeKey
  - kms:GetKeyPolicy
  - kms:GetKeyRotationStatus
  - kms:ListResourceTags
  - kms:ListGrants
  - kms:ListKeyPolicies
  - kms:ListRetirableGrants
references:
  - "https://docs.aws.amazon.com/kms/latest/developerguide/overview.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/grants.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/kms/index.html"
  - "https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html"
license: CC BY-SA 4.0
---

## Summary

AWS Key Management Service (KMS) is the central cryptographic trust anchor for an
AWS account. KMS keys (formerly "customer master keys" / CMKs) protect data at
rest across nearly every AWS service: S3 server-side encryption (SSE-KMS), EBS
volume and snapshot encryption, RDS/Aurora storage, DynamoDB, Secrets Manager,
SSM Parameter Store SecureString, SQS, SNS, EFS, Redshift, CloudTrail log
encryption, and more. Whoever can use or control the right KMS key can ultimately
read or unlock the data that key protects.

This page covers enumeration of KMS: discovering keys, aliases, key policies,
grants, rotation status, key origin, and the relationships between keys and the
data they protect. The objective for an assessor is to build a complete picture
of the account's cryptographic surface: which keys exist, who can administer
them, who can use them (`Encrypt`/`Decrypt`/`GenerateDataKey`), whether key
policies or grants over-delegate access, and which keys gate access to
high-value data stores. KMS access is unusual in AWS because key policies (a
resource policy on each key) can grant access independently of IAM, and grants
provide a second, often-overlooked delegation channel. Enumeration here feeds
directly into the privilege-escalation and persistence analyses for KMS.

## Prerequisites

This phase assumes read-only, audit-level credentials in the target account (an
assumed role or access keys with describe/list/get permissions on KMS). The
specific permissions exercised below include `kms:ListKeys`, `kms:ListAliases`,
`kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:ListKeyPolicies`,
`kms:GetKeyRotationStatus`, `kms:ListResourceTags`, `kms:ListGrants`, and
`kms:ListRetirableGrants`. KMS is regional: keys exist per-Region, so enumeration
must be repeated in every Region in scope. Reading a key policy (`GetKeyPolicy`)
or listing grants requires permission either via IAM or via the key's own policy;
a low-privilege principal may be able to list key IDs while being denied policy
reads on individual keys.

## Enumeration

### Identify the caller and Regions

```bash
aws sts get-caller-identity
# Enumerate enabled Regions to iterate over
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

### List keys and aliases

```bash
# All key IDs/ARNs in a Region (includes AWS-managed and AWS-owned visible keys)
aws kms list-keys --region us-east-1

# Aliases map human-readable names to key IDs and reveal service usage
# e.g. alias/aws/s3, alias/aws/ebs, alias/aws/secretsmanager are AWS-managed;
# custom aliases like alias/prod-rds often indicate high-value targets
aws kms list-aliases --region us-east-1
```

`list-aliases` is frequently the fastest way to understand intent: aliases such
as `alias/aws/<service>` denote AWS-managed keys, while customer-named aliases
hint at the data each key protects.

### Describe each key

```bash
aws kms describe-key --key-id <key-id-or-arn> --region us-east-1
```

Key fields in the `KeyMetadata` response:

- `KeyManager` — `AWS` (AWS-managed/owned, policy not editable) vs `CUSTOMER`
  (customer-managed; these are the keys an assessor and an attacker can influence).
- `KeyState` — `Enabled`, `Disabled`, `PendingDeletion`, `PendingImport`,
  `Unavailable` (relevant for external/custom key store keys).
- `KeyUsage` — `ENCRYPT_DECRYPT`, `SIGN_VERIFY`, or `GENERATE_VERIFY_MAC`.
- `KeySpec` — `SYMMETRIC_DEFAULT` or an asymmetric/HMAC spec.
- `Origin` — `AWS_KMS`, `EXTERNAL` (imported key material / BYOK), or
  `AWS_CLOUDHSM`/`EXTERNAL_KEY_STORE` (custom key store).
- `MultiRegion` / `MultiRegionConfiguration` — whether the key is a multi-Region
  primary or replica (a multi-Region key shares material across Regions).
- `DeletionDate`, `PendingDeletionWindowInDays`, `ValidTo` (for imported material).

### Read key policies (the critical control)

```bash
# List policy names attached to a key (KMS supports only the "default" policy name)
aws kms list-key-policies --key-id <key-id> --region us-east-1

# Retrieve the resource policy that governs the key
aws kms get-key-policy --key-id <key-id> --policy-name default \
  --output text --region us-east-1
```

The key policy is the authoritative access-control document for a KMS key. Look
for: principals granted `kms:*` or broad `kms:Decrypt`/`kms:Encrypt`/
`kms:GenerateDataKey`; statements with `"Principal": {"AWS": "*"}` (especially
without a `Condition` constraining `aws:PrincipalAccount`/`aws:SourceArn`/
`kms:ViaService`); cross-account principals; and the presence (or absence) of the
`"Enable IAM User Permissions"` statement that delegates control to IAM (`kms:*`
to `arn:aws:iam::<account>:root`).

### Enumerate grants

Grants are a programmatic delegation mechanism separate from key policies and IAM
policies. They are easy to miss and often used by AWS services on a principal's
behalf.

```bash
aws kms list-grants --key-id <key-id> --region us-east-1
# Grants that the caller could retire (revoke), across keys
aws kms list-retirable-grants \
  --retiring-principal arn:aws:iam::<account>:role/<role> --region us-east-1
```

Each grant exposes `GranteePrincipal`, `RetiringPrincipal`, `Operations`
(e.g. `Decrypt`, `Encrypt`, `GenerateDataKey`, `CreateGrant`), and optional
`Constraints` (`EncryptionContextSubset`/`EncryptionContextEquals`). A grant
allowing `CreateGrant` to a principal is a delegation amplifier.

### Rotation, tags, and public keys

```bash
aws kms get-key-rotation-status --key-id <key-id> --region us-east-1
aws kms list-resource-tags --key-id <key-id> --region us-east-1
# For asymmetric keys, the public key is retrievable
aws kms get-public-key --key-id <key-id> --region us-east-1
```

### Map keys to the data they protect

KMS enumeration is most valuable when correlated with the consumers of each key:

```bash
# S3 buckets using SSE-KMS and which key
aws s3api get-bucket-encryption --bucket <bucket>
# EBS default encryption key for the Region
aws ec2 get-ebs-default-kms-key-id --region us-east-1
aws ec2 get-ebs-encryption-by-default --region us-east-1
# Secrets Manager secret -> KmsKeyId
aws secretsmanager describe-secret --secret-id <secret>
# RDS instance/cluster storage key
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,KmsKeyId]'
# Snapshots and their encryption keys
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[].[SnapshotId,Encrypted,KmsKeyId]'
```

This cross-reference identifies which keys are the lynchpins for sensitive data —
the keys worth scrutinizing in the policy and grant analysis.

## Misconfigurations & Findings

- **Overly permissive key policy.** A key policy granting `kms:Decrypt` or
  `kms:GenerateDataKey*` to `"Principal": {"AWS": "*"}`, or to broad
  organization/account roots, without `Condition` constraints. This can permit
  any (or any cross-account) principal to use the key, defeating the purpose of
  encryption.
- **Missing `kms:ViaService` / source constraints.** Service-integration keys
  that allow use without restricting `kms:ViaService`,
  `kms:CallerAccount`, `aws:SourceArn`, or `aws:SourceAccount` can be used
  outside the intended service path.
- **Wildcard `kms:*` to unexpected principals.** Administrative actions
  (`PutKeyPolicy`, `ScheduleKeyDeletion`, `CreateGrant`) granted to roles that
  should only need cryptographic-use permissions.
- **Grants that over-delegate.** Long-lived grants including `CreateGrant`, or
  grants without encryption-context constraints, that broaden who can decrypt.
- **IAM-delegation enabled with weak IAM.** The key policy delegates `kms:*` to
  the account root (`Enable IAM User Permissions`), meaning any IAM policy can
  govern the key — shifting risk to potentially permissive IAM.
- **Key rotation disabled.** `get-key-rotation-status` returns
  `KeyRotationEnabled: false` on a customer-managed `ENCRYPT_DECRYPT` key,
  prolonging exposure of any single compromised key version.
- **Imported key material (`Origin: EXTERNAL`) without expiry**, or material
  approaching `ValidTo`, indicating BYOK governance gaps.
- **Disabled or pending-deletion keys still referenced** by live data stores,
  which can signal impending data-availability loss or sloppy key lifecycle.
- **Multi-Region keys** widening the blast radius: a compromise of one replica's
  usage path can expose data encrypted with the shared material in any Region.

## Exploitation

Enumeration is a discovery phase; the exploitation it unlocks is documented in
[AWS KMS - Privilege Escalation](../03-privilege-escalation/aws-kms-privesc.md)
and [AWS KMS - Persistence](../06-persistence/aws-kms-persistence.md). The
immediate, in-phase use of read access is decryption of data the caller is
already permitted to decrypt, and selecting targets for later phases:

```bash
# Direct decrypt of a small ciphertext blob (e.g. an exfiltrated KMS envelope key)
aws kms decrypt --ciphertext-blob fileb://ciphertext.bin \
  --key-id <key-id> --output text --query Plaintext | base64 --decode > plaintext.bin

# Re-encrypt to move ciphertext under a key the assessor controls (envelope pivot)
aws kms re-encrypt --ciphertext-blob fileb://ciphertext.bin \
  --destination-key-id <attacker-controlled-key>
```

A key whose policy grants `Decrypt` to the current principal, combined with read
access to ciphertext (an EBS snapshot, an S3 object, a Secrets Manager value),
is a direct data-access path that requires no privilege escalation at all. The
enumeration output above (key-to-data mapping plus policy/grant analysis) is what
identifies those reachable paths.

## Detection & Logging

KMS is one of the most CloudTrail-instrumented services. All control-plane and
most data-plane calls are logged as management events to CloudTrail by default.

- Read/enumeration calls appear as `ListKeys`, `ListAliases`, `DescribeKey`,
  `GetKeyPolicy`, `ListGrants`, `ListResourceTags`, `GetKeyRotationStatus`,
  `GetPublicKey`, `ListRetirableGrants` with `eventSource: kms.amazonaws.com`.
- Cryptographic use appears as `Decrypt`, `Encrypt`, `GenerateDataKey*`,
  `ReEncrypt`. The `requestParameters`/`resources` reveal the key ARN and any
  `encryptionContext`, and `Decrypt`/`GenerateDataKey` events record the calling
  principal — high-volume or anomalous `Decrypt` from an unexpected principal is
  a strong signal.
- Bulk enumeration across many keys and Regions in a short window is a hunting
  signature (e.g., `DescribeKey`/`GetKeyPolicy` fan-out).

Managed detections: GuardDuty does not have a dedicated KMS finding type, but
KMS activity is visible to detections built on CloudTrail (e.g.,
`PenTest:IAMUser/*`, anomalous API usage), AWS Config rules
(`cmk-backing-key-rotation-enabled`, `kms-cmk-not-scheduled-for-deletion`), and
IAM Access Analyzer for cross-account key-policy exposure. Query example:

```
filter eventSource = "kms.amazonaws.com"
  and eventName in ["GetKeyPolicy","ListGrants","DescribeKey"]
| stats count(*) by userIdentity.arn, eventName
```

## Remediation & Hardening

- Treat every key policy as a security boundary: scope principals explicitly,
  avoid `"Principal": {"AWS": "*"}`, and constrain use with conditions such as
  `kms:ViaService`, `kms:CallerAccount`, `aws:SourceArn`, and
  `kms:EncryptionContext:*`.
- Separate **key administrators** (who may run `PutKeyPolicy`,
  `ScheduleKeyDeletion`, `CreateGrant`) from **key users** (who may only
  `Encrypt`/`Decrypt`/`GenerateDataKey`). Do not grant `kms:*`.
- Prefer customer-managed keys over AWS-managed keys when policy control is
  required, and enable automatic key rotation.
- Inventory and prune grants regularly; constrain grants with encryption context
  and avoid granting `CreateGrant` broadly.
- Use IAM Access Analyzer to continuously surface keys shared outside the account
  or organization, and detective controls (Config, CloudTrail alarms) for policy
  changes (`PutKeyPolicy`, `CreateGrant`, `ScheduleKeyDeletion`).
- Restrict who may even read key policies/grants in least-privilege audit roles
  so reconnaissance is itself constrained where feasible.

## Tools

- AWS CLI (`aws kms`) and the KMS API for direct enumeration.
- Cloud security posture and IAM-graph tooling that ingests key policies, grants,
  and key-to-resource relationships to surface exposed or over-permissioned keys.
- IAM Access Analyzer for cross-account key-policy exposure.
- Open-source AWS enumeration suites that include KMS key/policy/grant collection
  modules.

## References

- AWS KMS Developer Guide — Overview:
  https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
- AWS KMS Developer Guide — Key policies:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS KMS Developer Guide — Grants:
  https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- AWS KMS Developer Guide — Logging with CloudTrail:
  https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html
- AWS CLI KMS command reference:
  https://docs.aws.amazon.com/cli/latest/reference/kms/index.html
- AWS KMS API Reference:
  https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html
