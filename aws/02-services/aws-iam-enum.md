---
cstg_id: CSTG-AWS-IAM-ENUM
title: "AWS Iam - Enumeration"
provider: aws
service: iam
phase: services
required_access: read-only-audit
required_permissions:
  - iam:GetAccountAuthorizationDetails
  - iam:ListUsers
  - iam:ListRoles
  - iam:ListGroups
  - iam:ListPolicies
  - iam:ListAccessKeys
  - iam:GetPolicyVersion
  - iam:ListAttachedUserPolicies
  - iam:ListAttachedRolePolicies
  - iam:GetLoginProfile
  - iam:GenerateCredentialReport
  - iam:GetCredentialReport
  - sts:GetCallerIdentity
tools:
  - aws-cli
  - principal-mapper (pmapper)
  - enumerate-iam
  - cloudsplaining
  - aws-iam-policy-simulator
references:
  - "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/iam/index.html"
  - "https://hackingthe.cloud/aws/enumeration/enum_iam_user_role/"
  - "https://github.com/nccgroup/PMapper"
  - "https://github.com/salesforce/cloudsplaining"
license: CC BY-SA 4.0
---

## Summary

AWS Identity and Access Management (IAM) is the control plane that defines *who* (principals: users, roles, groups, federated identities, the account root) can perform *which* actions on *which* resources, subject to *conditions*. Because every AWS API call is authorized through IAM, a complete and accurate picture of the IAM configuration is the single most valuable artifact a tester or defender can build. Enumeration of IAM answers: which principals exist, what credentials they hold, which managed and inline policies apply to them, which trust relationships allow role assumption, and where over-permissioned or unused access creates attack surface.

The attacker objective during enumeration is to map the full principal-and-permission graph without modifying anything, then identify the principals that grant a path to higher privilege (see [Privilege Escalation](../03-privilege-escalation/aws-iam-privesc.md)), lateral movement (see [Lateral Movement](../04-lateral-movement/aws-iam-lateral.md)), or durable access (see [Persistence](../06-persistence/aws-iam-persistence.md)). The defender objective is identical in data but inverted in intent: produce the same graph to detect drift, unused credentials, and dangerous permission combinations before an adversary does.

## Prerequisites

- Valid credentials for the target account (long-term access key, federated session, or assumed-role session) able to call the read-only `iam:List*`, `iam:Get*`, and `sts:GetCallerIdentity` actions.
- The single most efficient permission is `iam:GetAccountAuthorizationDetails`, which returns users, groups, roles, and all attached/inline policies in one paginated call. Where it is denied, the same picture can be assembled from the granular `List*`/`Get*` actions.
- A credential report requires `iam:GenerateCredentialReport` and `iam:GetCredentialReport`.
- No write permissions are required or used; all techniques below are read-only.

## Enumeration

### Establish the current identity and account

```bash
aws sts get-caller-identity
# -> Account, Arn, UserId. Reveals whether the session is a user, an assumed role,
#    or the root account, and the account ID needed to construct ARNs.
```

### One-shot account authorization dump

The most complete single source. It returns every principal plus every policy document (managed and inline) attached to them:

```bash
aws iam get-account-authorization-details > aad.json

# Filter just the inline policies, which are the most commonly overlooked:
aws iam get-account-authorization-details \
  --filter User Role Group LocalManagedPolicy AWSManagedPolicy
```

### Granular principal enumeration

When `GetAccountAuthorizationDetails` is denied, build the picture piecewise:

```bash
# Users, groups, roles, customer-managed policies
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local           # customer-managed only
aws iam list-instance-profiles                 # EC2 role attachment points

# Per-user attached and inline policies, group membership, MFA, console access
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <name>
aws iam list-groups-for-user --user-name <user>
aws iam list-mfa-devices --user-name <user>
aws iam get-login-profile --user-name <user>   # NoSuchEntity => no console password

# Per-role policies and the all-important trust policy
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
aws iam get-role --role-name <role> \
  --query 'Role.AssumeRolePolicyDocument'       # who may assume this role

# Per-group policies and members
aws iam list-attached-group-policies --group-name <group>
aws iam get-group --group-name <group>
```

### Resolve the effective document for a managed policy

`ListAttachedUserPolicies` returns only ARNs; to read the rules you must fetch the default version:

```bash
ver=$(aws iam get-policy --policy-arn <arn> --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version --policy-arn <arn> --version-id "$ver" \
  --query 'PolicyVersion.Document'
```

### Credentials, key age, and access methods

```bash
# Per-user access keys and their last-used metadata
aws iam list-access-keys --user-name <user>
aws iam get-access-key-last-used --access-key-id <AKIA...>

# Account-wide credential report (CSV): key age, MFA, password age, last-used
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

### Federation, OIDC, and SAML

```bash
aws iam list-saml-providers
aws iam list-open-id-connect-providers
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <arn>
```

OIDC providers (for example, the GitHub Actions or Kubernetes/IRSA endpoints) and SAML providers define which external identities may assume roles; their trust conditions are a frequent source of overly broad federation.

### Account-level policy and posture

```bash
aws iam get-account-password-policy
aws iam get-account-summary               # counts of users, roles, MFA devices, etc.
aws iam list-virtual-mfa-devices
```

### Permission discovery from a low-privilege context

When `iam:List*` is denied, calling APIs and observing `AccessDenied` versus success can fingerprint granted permissions without any IAM read access (a brute-force technique). The `sts:GetCallerIdentity` call always succeeds and never requires permission, making it the universal first probe.

## Misconfigurations & Findings

- **Wildcard administrative access.** Policies containing `"Action": "*"` with `"Resource": "*"`, or `AdministratorAccess` attached to non-administrative principals, machine users, or roles assumable by broad trust policies.
- **Over-permissioned principals with dangerous combinations.** Permissions such as `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PassRole` + `ec2:RunInstances`, `iam:CreateAccessKey`, or `sts:AssumeRole` to a privileged role enable escalation even without `*:*`. These are catalogued in [Privilege Escalation](../03-privilege-escalation/aws-iam-privesc.md).
- **Long-lived and stale access keys.** Keys older than 90 days, keys never rotated, or keys with no recent `AccessKeyLastUsed` activity. Two active keys on a single user often indicates a stalled rotation.
- **Missing MFA.** Console-enabled users (those with a login profile) lacking an MFA device, especially privileged users and the root account.
- **Weak or absent password policy.** No `GetAccountPasswordPolicy` configured, short minimum length, or no expiry.
- **Permissive trust policies.** Roles whose `AssumeRolePolicyDocument` principal is `"AWS": "*"`, an entire external account without an `sts:ExternalId` condition (confused-deputy exposure), or `arn:aws:iam::ACCOUNT:root` granting any principal in another account.
- **Loose federation conditions.** OIDC trust policies that match the audience but not the subject (`sub`) claim, allowing any repository/branch or any pod in a cluster to assume a role.
- **Inline policies hiding grants.** Inline policies are not returned by `list-policies` and are easy to miss; they frequently contain bespoke, over-broad grants.
- **Unused roles and users.** Principals with no recent activity in the credential report or in `GetRole` `RoleLastUsed`, which expand the attack surface without operational value.

## Exploitation

Enumeration itself does not modify the account, but it directly feeds every subsequent phase. The practical exploitation step is to convert the raw dump into an authorization graph and query it for reachable privilege.

```bash
# Build a graph of the account and query for principals that can reach admin
pmapper graph create
pmapper query 'preset privesc *'
pmapper query 'who can do iam:CreateAccessKey with *'
pmapper visualize --filetype svg

# Statically scan all policies for risky actions / resource exposure
cloudsplaining scan --input-file aad.json
```

The output identifies (a) principals with self-escalation permissions, (b) `PassRole` chains into privileged service roles, and (c) trust relationships that let an already-compromised principal pivot. Each finding is actioned in the corresponding phase page. No state is changed during this read-only mapping.

## Detection & Logging

- **CloudTrail** records all IAM management-event reads. High-signal events during reconnaissance include `GetAccountAuthorizationDetails`, `ListUsers`, `ListRoles`, `GetCredentialReport`, `GenerateCredentialReport`, and large bursts of `ListAttachedUserPolicies`/`GetPolicyVersion`. IAM is a global service, so these events appear in the `us-east-1` region trail.
- A single principal calling `GetAccountAuthorizationDetails` followed immediately by `GetCredentialReport` and broad `List*` enumeration is a strong reconnaissance indicator.
- `sts:GetCallerIdentity` is logged but is extremely common and low-signal on its own.
- **GuardDuty** raises findings such as `Discovery:IAMUser/AnomalousBehavior` when a principal performs enumeration that deviates from its established baseline.
- **IAM Access Analyzer** does not detect enumeration but continuously surfaces external-access and unused-access findings that mirror the misconfigurations above.

## Remediation & Hardening

- Apply least privilege: grant `iam:Get*`/`iam:List*` broadly only to dedicated audit roles, and restrict write actions tightly.
- Enforce MFA for all human principals and the root account; use a strong account password policy.
- Rotate access keys on a fixed schedule and remove keys with no recent `AccessKeyLastUsed`; prefer temporary credentials (roles, IAM Identity Center, federation) over long-term keys.
- Scope role trust policies to specific principals and add `sts:ExternalId` (cross-account) and `sub`/`aud` conditions (OIDC/SAML).
- Remove unused users, roles, and policies surfaced by the credential report and IAM Access Analyzer unused-access findings.
- Establish a CloudTrail-based detection for bulk IAM enumeration by non-audit principals and route it to alerting.

## Tools

- **aws-cli** - native `iam` and `sts` command coverage for all enumeration above.
- **principal-mapper (pmapper)** - builds and queries an authorization graph; identifies privilege-escalation and assume-role reachability.
- **enumerate-iam** - brute-forces which API actions a set of credentials can call.
- **cloudsplaining** - static analysis of an account authorization dump to flag risky permissions and resource exposure.
- **aws-iam-policy-simulator / `iam simulate-principal-policy`** - evaluates whether a principal is allowed a given action under current policies and conditions.

## References

- AWS IAM API Reference - GetAccountAuthorizationDetails
- AWS IAM User Guide - Getting credential reports
- AWS CLI Reference - iam
- hackingthe.cloud - IAM user/role enumeration
- NCC Group - PMapper
- Salesforce - Cloudsplaining
