---
cstg_id: CSTG-AWS-SECRETS-MANAGER-ENUM
title: "AWS Secrets Manager - Enumeration"
provider: aws
service: secrets-manager
phase: services
required_access: read-only-audit
required_permissions:
  - secretsmanager:ListSecrets
  - secretsmanager:DescribeSecret
  - secretsmanager:GetResourcePolicy
  - secretsmanager:ListSecretVersionIds
  - secretsmanager:GetSecretValue
  - secretsmanager:BatchGetSecretValue
  - kms:Decrypt
  - kms:DescribeKey
  - iam:SimulatePrincipalPolicy
references:
  - "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/"
  - "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html"
  - "https://hackingthe.cloud/aws/enumeration/loot/"
license: CC BY-SA 4.0
---

## Summary

AWS Secrets Manager is a managed store for credentials, API keys, database connection strings, OAuth
tokens, and other secrets, with built-in encryption (via KMS), rotation, cross-account sharing
through resource policies, and replication across regions. From a testing perspective it is one of
the highest-value targets in an account: a single `GetSecretValue` call can yield database
master passwords, third-party API keys, or long-lived IAM credentials that enable immediate lateral
movement or privilege escalation. This page covers authenticated, read-only enumeration from a
credentialed principal - inventorying secrets, reading their metadata, rotation configuration,
encryption keys, and resource policies, mapping which secrets the current principal can actually
read, and (where authorised) retrieving values. Crucially, secret *metadata* (names, descriptions,
tags, ARNs, rotation lambda ARNs) is often readable even when the value is not, and names alone
frequently reveal what the secret protects and where it is used.

Abusing read or write access to secrets to escalate IAM privileges is covered in
[AWS Secrets Manager - Privilege Escalation](../03-privilege-escalation/aws-secrets-manager-privesc.md);
mass harvesting and pivoting on recovered secrets is covered in
[AWS Secrets Manager - Post-Exploitation](../05-post-exploitation/aws-secrets-manager-post-exploitation.md).

## Prerequisites

A principal with read access to the Secrets Manager control plane. The metadata calls
(`ListSecrets`, `DescribeSecret`, `GetResourcePolicy`, `ListSecretVersionIds`) are granted by a
read-only audit role (`SecurityAudit` / `ViewOnlyAccess`) and reveal a great deal without touching
values. Reading a value additionally requires `secretsmanager:GetSecretValue` (or
`BatchGetSecretValue`) **and** `kms:Decrypt` on the secret's encryption key when the secret is
encrypted with a customer-managed key - the KMS key policy or a grant must allow the principal.
Secrets Manager is regional and resolves per region; replicas exist independently in each region.

## Enumeration

Establish identity, then inventory secrets in each region (Secrets Manager is regional):

```bash
aws sts get-caller-identity
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $R =="
  aws secretsmanager list-secrets --region "$R" \
    --query 'SecretList[].{Name:Name,Arn:ARN,KMS:KmsKeyId,Rotation:RotationEnabled,LastAccessed:LastAccessedDate}' \
    --output table
done
```

`ListSecrets` returns rich metadata including the name, description, tags, KMS key, rotation status,
the rotation Lambda ARN, and replication regions. Triage by name and description first - these alone
often identify the protected system:

```bash
aws secretsmanager list-secrets \
  --query 'SecretList[].[Name,Description,Tags]' --output text
# Filter server-side by name, tag, or description:
aws secretsmanager list-secrets \
  --filters Key=name,Values=prod Key=description,Values=database
```

For each secret of interest, pull full metadata, the version inventory, rotation configuration, and
the resource policy:

```bash
S=prod/db/master
aws secretsmanager describe-secret --secret-id "$S"            # KMS key, rotation lambda, replicas
aws secretsmanager list-secret-version-ids --secret-id "$S" --include-deprecated
aws secretsmanager get-resource-policy --secret-id "$S" \
  --query 'ResourcePolicy' --output text                       # cross-account / wildcard grants
```

Retrieve the value (only where authorised by rules of engagement). The current (`AWSCURRENT`) stage is
returned by default; previous values often remain under `AWSPREVIOUS` and other staged version IDs:

```bash
aws secretsmanager get-secret-value --secret-id "$S" --query SecretString --output text
aws secretsmanager get-secret-value --secret-id "$S" --version-stage AWSPREVIOUS --query SecretString --output text
aws secretsmanager get-secret-value --secret-id "$S" --version-id <VersionId> --query SecretString --output text
```

`BatchGetSecretValue` retrieves many secrets in one call (and can select by filter), which is faster
and produces a single CloudTrail event rather than one per secret:

```bash
aws secretsmanager batch-get-secret-value \
  --filters Key=tag-key,Values=environment --query 'SecretValues[].[Name,SecretString]' --output text
aws secretsmanager batch-get-secret-value --secret-id-list "$S" prod/api/stripe
```

Map which secrets the current principal can actually read without triggering many denied
`GetSecretValue` calls, by simulating policy first:

```bash
ARN=$(aws sts get-caller-identity --query Arn --output text)
for s in $(aws secretsmanager list-secrets --query 'SecretList[].ARN' --output text); do
  D=$(aws iam simulate-principal-policy --policy-source-arn "$ARN" \
        --action-names secretsmanager:GetSecretValue --resource-arns "$s" \
        --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)
  echo "$D  $s"
done
```

Resolve the KMS key behind each secret to understand whether decrypt is a separate gate:

```bash
KMS=$(aws secretsmanager describe-secret --secret-id "$S" --query KmsKeyId --output text)
aws kms describe-key --key-id "$KMS" --query 'KeyMetadata.{Arn:Arn,Manager:KeyManager}'
aws kms get-key-policy --key-id "$KMS" --policy-name default --query Policy --output text 2>/dev/null
```

## Misconfigurations & Findings

- **Long-lived IAM credentials stored as secrets** - access key/secret pairs in a secret can be used
  directly and may belong to a more-privileged principal; a top-tier finding.
- **Database master credentials without rotation** - `RotationEnabled: false` on a master/admin
  secret means a single read yields durable access to the data store.
- **Over-broad identity grants** - principals holding `secretsmanager:GetSecretValue` on `Resource: *`
  rather than specific secret ARNs, so any one secret read implies all are reachable.
- **Permissive resource policies** - a resource policy granting `GetSecretValue` to `Principal: "*"`,
  a foreign account without conditions, or `Principal: "*"` gated only by a weak condition.
- **AWS-managed-key encryption (`aws/secretsmanager`)** - encryption with the AWS-managed key means
  any principal with `GetSecretValue` reads the value without a separate KMS gate; a customer-managed
  key with a scoped policy is a stronger boundary.
- **Secrets readable by data-plane roles** - EC2/Lambda/ECS execution roles able to read secrets far
  beyond the workload's need, widening the blast radius of any compute compromise.
- **Deprecated/previous versions retain old secrets** - `AWSPREVIOUS` and deprecated version IDs hold
  pre-rotation values that are still retrievable.
- **Descriptive names and tags** - secret names like `prod/rds/admin` or tags exposing environment and
  owner aid an attacker even without read access to the value.
- **Cross-region replicas** - replicated secrets multiply the surface; a deny in one region may be
  permitted against a replica in another.

## Detection & Logging

Secrets Manager API calls are recorded in **CloudTrail** as management events and are always present
on a trail. `ListSecrets`, `DescribeSecret`, `GetResourcePolicy`, and `ListSecretVersionIds` are
metadata reconnaissance; a burst across many secrets and regions from one principal is a strong
enumeration signal. **`GetSecretValue` and `BatchGetSecretValue` are the high-value events** - the
event records the secret ARN, the version stage, and the calling principal. A single principal
reading many distinct secrets in a short window, reading secrets it has never accessed before, or
reading from an atypical source IP/region is a strong indicator of harvesting; `BatchGetSecretValue`
in particular reads many secrets in one event and should be alerted on. When the secret uses a
customer-managed KMS key, a correlated **KMS `Decrypt`** event appears with the secret ARN in the
encryption context. **GuardDuty** surfaces credential-exfiltration and anomalous-access patterns, and
IAM Access Analyzer flags resource policies that grant external (cross-account/public) access. Note
that `LastAccessedDate` in `DescribeSecret` is day-granular and lags, so it is weak as a real-time
signal but useful for spotting dormant-secret access after the fact.

## Remediation & Hardening

- Apply **least-privilege identity policies** - scope `secretsmanager:GetSecretValue` to specific
  secret ARNs (or a tag/path condition such as `secretsmanager:ResourceTag`), never `Resource: *`.
- Encrypt secrets with **customer-managed KMS keys** and a scoped key policy so `kms:Decrypt` is a
  real second gate; this lets you revoke decrypt independently of secret-read permissions.
- Constrain **resource policies** to specific principals and add `aws:SourceAccount`/`aws:PrincipalOrgID`
  conditions; review with IAM Access Analyzer and avoid `Principal: "*"`.
- **Enable rotation** on credentials so that a single read has a bounded lifetime, and treat any read
  secret as compromised until rotated.
- Avoid storing long-lived IAM access keys as secrets; prefer roles and short-lived credentials.
- Alert in CloudTrail on high-volume or first-time `GetSecretValue`/`BatchGetSecretValue`, on reads
  from unexpected principals/IPs, and on resource-policy changes; enable **GuardDuty**.
- Use **VPC endpoints** with endpoint policies to restrict where secrets can be retrieved from.

## Tools

- **aws-cli** - authoritative enumeration via the `secretsmanager` and `kms` commands.
- **Prowler**, **ScoutSuite** - read-only posture checks for unrotated secrets, permissive resource
  policies, AWS-managed-key encryption, and over-broad grants.
- **CloudFox** - surfaces reachable secrets and the roles that can read them from an offensive vantage.
- **PMapper** - models which principals can reach high-value secrets through the IAM graph.

## References

- AWS - What is AWS Secrets Manager (user guide)
- AWS - Secrets Manager CLI command reference
- AWS - Resource-based policies for Secrets Manager
- hackingthe.cloud - Looting and credential discovery in AWS
