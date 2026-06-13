---
cstg_id: CSTG-AWS-STS-ENUM
title: "AWS Sts - Enumeration"
provider: aws
service: sts
phase: services
required_access: read-only-audit
required_permissions: [sts:GetCallerIdentity, iam:GetUser, iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:ListGroupsForUser, iam:GetAccountAuthorizationDetails, iam:SimulatePrincipalPolicy, iam:ListRoles, iam:GetRole]
tools: [aws-cli, enumerate-iam, pacu, ScoutSuite, smogcloud]
references: ["https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html", "https://hackingthe.cloud/aws/enumeration/whoami/", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"]
license: CC BY-SA 4.0
---

## Summary

The AWS Security Token Service (STS) is the global endpoint that issues short-lived, limited-privilege credentials for IAM principals. Almost every cross-account, federated, and role-based access path in AWS terminates in an STS API call (`AssumeRole`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML`, `GetSessionToken`, `GetFederationToken`). Enumeration of STS itself is therefore less about listing resources and more about establishing identity context: confirming *who* a set of credentials belongs to, *what* type of credential is in hand (long-term user keys vs. temporary session vs. instance/container role), and *which* roles that principal is permitted to assume. This page covers the reconnaissance an assessor performs immediately after obtaining any AWS credential, before attempting privilege escalation or lateral movement.

The attacker objective during this phase is to orient: identify the account ID, principal ARN, and session type; distinguish a foothold's blast radius; and map the set of `sts:AssumeRole` targets that turn a single credential into a graph of reachable identities.

## Prerequisites

- Any valid AWS credential material: long-term access key pair (`AKIA...`), temporary session credentials (`ASIA...` plus a session token), or access via an instance/container/Lambda execution role.
- `sts:GetCallerIdentity` requires **no IAM permission** - it succeeds for any authenticated caller and cannot be denied by identity policy. This makes it the universal first probe.
- Deeper enumeration (resolving attached policies, group membership, assumable roles) requires read access to IAM: `iam:GetUser`, `iam:List*`, `iam:GetAccountAuthorizationDetails`, and ideally `iam:SimulatePrincipalPolicy`. A read-only audit role such as the AWS-managed `SecurityAudit` or `ViewOnlyAccess` policy provides this.

## Enumeration

### Confirm identity (works with any credential)

```bash
# The universal "whoami" - no permission required, never logged as AccessDenied
aws sts get-caller-identity
# {
#   "UserId": "AROAEXAMPLE:session-name",  # or AIDA... for an IAM user
#   "Account": "123456789012",
#   "Arn": "arn:aws:sts::123456789012:assumed-role/AppRole/session-name"
# }
```

Interpret the `Arn` and `UserId` prefix to determine credential type:

| ARN / UserId pattern | Credential type |
|---|---|
| `arn:aws:iam::ACCT:user/NAME`, UserId `AIDA...` | Long-term IAM user keys |
| `arn:aws:sts::ACCT:assumed-role/ROLE/SESSION`, UserId `AROA...:...` | Temporary role session (AssumeRole) |
| `arn:aws:sts::ACCT:federated-user/NAME` | `GetFederationToken` session |
| `arn:aws:iam::ACCT:root` | Account root user (rare, high value) |

Raw API equivalent (no SDK required - useful from a constrained foothold):

```bash
curl "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
# unsigned call returns an error but confirms reachability; signed calls return identity
```

### Determine the source of the credentials

```bash
# EC2 instance role via IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ECS task role
curl -s "${ECS_CONTAINER_METADATA_URI_V4}/task"
echo "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

# Lambda - role surfaced via environment
env | grep -E 'AWS_(EXECUTION_ENV|LAMBDA|REGION|ACCESS)'
```

### Resolve principal privileges (requires IAM read)

```bash
# For an IAM user
aws iam get-user
aws iam list-attached-user-policies --user-name NAME
aws iam list-user-policies            --user-name NAME
aws iam list-groups-for-user          --user-name NAME

# Whole-account authorization snapshot - users, groups, roles, and their policies
aws iam get-account-authorization-details > authz.json

# Enumerate roles and read their trust policies (the AssumeRolePolicyDocument)
aws iam list-roles \
  --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json
aws iam get-role --role-name TARGET_ROLE
```

### Discover which roles the current principal can assume

```bash
# Programmatically test assume-role rights against the simulator
aws iam simulate-principal-policy \
  --policy-source-arn "$(aws sts get-caller-identity --query Arn --output text)" \
  --action-names sts:AssumeRole \
  --resource-arns arn:aws:iam::123456789012:role/TargetRole

# Brute-confirm by attempting the assumption (noisy - generates AssumeRole events)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TargetRole \
  --role-session-name recon
```

Where IAM read is unavailable, automated permission brute-forcers (see Tools) probe a curated list of read/describe/list calls across services and infer effective permissions from success vs. `AccessDenied`. `sts:AssumeRole` reachability is then derived by inspecting each role's trust policy `Principal` block for the current account or principal ARN.

## Misconfigurations & Findings

- **Overly broad role trust policies.** A trust policy whose `Principal` is `{"AWS": "arn:aws:iam::ACCT:root"}` (the entire account) lets *any* principal in the account assume the role if their identity policy allows `sts:AssumeRole`. Enumeration that returns many such roles signals a wide internal lateral graph.
- **Wildcard or third-party `Principal`.** Trust policies allowing `"AWS": "*"`, an external account, or a third-party vendor account without an `sts:ExternalId` condition expose cross-account assumption (see the Confused Deputy problem in the lateral-movement page).
- **Web-identity / OIDC trust without subject conditions.** `AssumeRoleWithWebIdentity` trusts that match a provider (e.g. a CI/CD or Kubernetes OIDC issuer) but omit a `sub`/`aud` condition can be assumed by unintended workloads.
- **Long-lived IAM user keys.** Discovering `AKIA...` keys (especially with no rotation and `PowerUser`/`Admin` attached) is itself a finding; these keys never expire and are the most-leaked credential type.
- **Missing `aws:MultiFactorAuthPresent` / `aws:SourceIp` conditions** on sensitive role trusts, allowing assumption from any network without MFA.
- **`GetFederationToken` / `GetSessionToken` exposure** on broadly-privileged users, enabling minting of derived temporary credentials.

## Exploitation

Pure enumeration is non-destructive, but the data it yields directly seeds later phases:

1. `get-caller-identity` establishes the foothold's account and principal.
2. `get-account-authorization-details` (or simulator probing) reveals the full set of assumable roles - this is the adjacency list for the privilege-escalation and lateral-movement graphs.
3. Trust-policy inspection identifies which assumptions are reachable *now* versus those that require an intermediate hop.

The transition into active exploitation occurs the moment an `aws sts assume-role` is issued against a discovered target - see [AWS STS - Privilege Escalation](../03-privilege-escalation/aws-sts-privesc.md) and [AWS STS - Lateral Movement](../04-lateral-movement/aws-sts-lateral.md).

## Detection & Logging

- **CloudTrail** records `GetCallerIdentity` as a management event with event source `sts.amazonaws.com`. A burst of `GetCallerIdentity` immediately followed by `iam:GetAccountAuthorizationDetails`, `iam:SimulatePrincipalPolicy`, or many `iam:List*`/`iam:Get*` calls is a classic credential-orientation signature.
- STS is a global service; depending on configuration its events appear in `us-east-1` (legacy global trail behaviour) or in the region of the regional STS endpoint used. Ensure trails capture global service events.
- The `userIdentity` block in each event distinguishes `IAMUser`, `AssumedRole`, `FederatedUser`, and `Root`, and includes `accessKeyId` - useful for correlating activity back to a specific leaked key.
- Repeated `AccessDenied` from automated permission brute-forcing (`enumerate-iam`-style tooling) appears as high-volume failed `Describe*`/`List*`/`Get*` events from a single `accessKeyId`.
- Managed detections: **GuardDuty** findings such as `Recon:IAMUser/MaliciousIPCaller`, `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*`, and anomalous-API findings from CloudTrail analytics.

## Remediation & Hardening

- Apply least privilege to IAM read: restrict `iam:GetAccountAuthorizationDetails` and `iam:SimulatePrincipalPolicy` to dedicated audit roles, since they expose the full authorization graph.
- Scope every role trust policy: name explicit principals, add `sts:ExternalId` for third parties, and add `aws:MultiFactorAuthPresent`, `aws:SourceArn`, or `aws:SourceIp` conditions where appropriate.
- Replace long-term IAM user keys with role assumption / IAM Identity Center (SSO) and short-lived credentials; enforce rotation and use IAM Access Analyzer to surface external and unused access.
- Enable CloudTrail (multi-region, with global service events), GuardDuty, and alert on reconnaissance bursts and unusual `GetCallerIdentity` source IPs.
- Use service control policies (SCPs) to constrain which principals may call `sts:AssumeRole` and to which targets.

## Tools

- **aws-cli** - native `sts` and `iam` commands for identity and policy enumeration.
- **enumerate-iam** - brute-forces effective permissions by attempting read-only calls and recording successes.
- **Pacu** - the `iam__enum_permissions`, `iam__enum_users_roles_policies_groups`, and `iam__bruteforce_permissions` modules.
- **ScoutSuite** - multi-account posture scan that flags weak trust policies and stale keys.
- **smogcloud / cloud asset mappers** - correlate principals to externally reachable resources.

## References

- AWS STS API Reference - https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
- IAM temporary security credentials - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
- hackingthe.cloud - Enumerate the permissions associated with credentials - https://hackingthe.cloud/aws/enumeration/whoami/
- IAM global condition context keys - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
