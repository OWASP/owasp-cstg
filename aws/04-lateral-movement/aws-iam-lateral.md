---
cstg_id: CSTG-AWS-IAM-LATERAL
title: "AWS Iam - Lateral Movement"
provider: aws
service: iam
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - sts:AssumeRole
  - sts:AssumeRoleWithWebIdentity
  - sts:AssumeRoleWithSAML
  - sts:GetFederationToken
  - iam:PassRole
  - iam:ListRoles
  - iam:GetRole
tools:
  - aws-cli
  - principal-mapper (pmapper)
  - pacu
  - awscli-sts
references:
  - "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://github.com/nccgroup/PMapper"
license: CC BY-SA 4.0
---

## Summary

Lateral movement through IAM is the use of role assumption and trust relationships to move from one principal's context to another - across roles within the same account, and across accounts within an organization or to/from third parties. Unlike privilege escalation (which raises the level of access), lateral movement changes *which* identity is acting, often to reach resources, accounts, or trust boundaries the original principal could not. The Security Token Service (STS) is the engine: `AssumeRole`, `AssumeRoleWithWebIdentity`, and `AssumeRoleWithSAML` issue temporary credentials for a target role whenever that role's trust policy permits the caller.

The attacker objective is to enumerate every role the current principal can assume (directly or through a chain), assume them, and repeat - building an assume-role graph that may cross account boundaries via cross-account trust, organization roles such as `OrganizationAccountAccessRole`, or federation. Defenders use the same graph to find unintended trust edges. Complete [IAM Enumeration](../02-services/aws-iam-enum.md) first; escalation primitives that *create* new trust edges are in [Privilege Escalation](../03-privilege-escalation/aws-iam-privesc.md).

## Prerequisites

- An assumed-breach foothold with credentials for some principal.
- `sts:AssumeRole` permission on the caller side **and** a target role whose `AssumeRolePolicyDocument` (trust policy) names the caller (directly, via the account `root`, or via wildcard), optionally satisfying any `sts:ExternalId`, MFA, or source-IP conditions.
- For federated movement: a valid OIDC/SAML token whose claims satisfy a role's trust conditions, used with `AssumeRoleWithWebIdentity`/`AssumeRoleWithSAML` (no prior AWS credentials required).
- Enumeration access (`iam:ListRoles`, `iam:GetRole`) helps identify assumable targets, but is not strictly required - assumption can be attempted blindly against guessed role ARNs.

## Enumeration

```bash
# Identify the current identity and account
aws sts get-caller-identity

# List roles and inspect trust policies for principals that include "you"
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}'
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'

# Cross-account / organization access roles to look for
#   - OrganizationAccountAccessRole (member-account admin from management account)
#   - roles with Principal "AWS":"arn:aws:iam::<other-acct>:root"
#   - roles with Principal "Federated": OIDC/SAML provider ARNs
```

Build the reachability graph automatically (including cross-account edges when multiple account graphs are loaded into one organization graph):

```bash
pmapper graph create
pmapper query 'who can do sts:AssumeRole with *'
pmapper orgs create        # organization-wide cross-account assume-role graph
```

## Misconfigurations & Findings

- **Over-broad trust policies.** `Principal: {"AWS": "*"}`, or another whole account's `root` without an `sts:ExternalId` condition (confused-deputy risk for third-party roles).
- **Transitive assume-role chains.** Role A can assume Role B, which can assume Role C, ultimately reaching an admin or cross-account role - each hop individually looks reasonable.
- **Organization access roles left broadly assumable.** `OrganizationAccountAccessRole` in member accounts grants administrator access from the management account; any principal able to assume it gains member-account admin.
- **Loose federation subject matching.** OIDC trust policies matching only `aud` (audience) and not `sub` (subject), letting any repository/branch/workload backed by the provider assume the role.
- **No external ID on third-party roles.** Cross-account roles intended for a vendor that omit `sts:ExternalId` can be assumed by anyone in the trusted account.
- **Missing condition keys.** Trust policies lacking `aws:SourceIp`, `aws:MultiFactorAuthPresent`, or `aws:PrincipalOrgID` constraints.

## Exploitation

### Direct role assumption

```bash
creds=$(aws sts assume-role \
  --role-arn arn:aws:iam::<acct>:role/<target-role> \
  --role-session-name lateral)
export AWS_ACCESS_KEY_ID=$(echo "$creds" | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$creds" | jq -r .Credentials.SessionToken)
aws sts get-caller-identity     # confirm the new identity
```

### Assumption requiring an external ID

```bash
aws sts assume-role --role-arn <arn> --role-session-name x --external-id <known-external-id>
```

### Cross-account / organization movement

From a management-account principal, assume the member-account admin role:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<member-acct>:role/OrganizationAccountAccessRole \
  --role-session-name x
```

### Role chaining

After assuming Role B, use its credentials to assume Role C that only B is trusted to assume. Note that role-chained sessions are capped at one hour:

```bash
# (now operating as Role B)
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/RoleC --role-session-name chain
```

### Federated assumption (no prior AWS credentials)

With an OIDC token whose `aud`/`sub` satisfy a role's trust conditions:

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<acct>:role/<oidc-role> \
  --role-session-name fed \
  --web-identity-token "$OIDC_JWT"
```

With a SAML assertion:

```bash
aws sts assume-role-with-saml \
  --role-arn <role-arn> --principal-arn <saml-provider-arn> \
  --saml-assertion "$B64_SAML"
```

### Federation token

`sts:GetFederationToken` produces a temporary session with a subset of the caller's permissions, usable to create downstream credentials that survive separately from the original key.

## Detection & Logging

- **CloudTrail** logs every assumption as `AssumeRole`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML`, or `GetFederationToken`, including `sourceIdentity`, `userIdentity`, and the target role in `requestParameters`. Cross-account assumptions appear in **both** the trusting and trusted account trails.
- The `roleSessionName` and `sourceIdentity` fields propagate into subsequent events, enabling attribution along a chain.
- High-signal indicators: assumption of `OrganizationAccountAccessRole` by an unusual principal; role chaining (an assumed-role session calling `AssumeRole` again); assumption from a new source IP or geography; `AssumeRoleWithWebIdentity` with an unexpected `sub` claim.
- **GuardDuty** raises `UnauthorizedAccess`/`Discovery` and credential-anomaly findings, and detects use of role credentials from outside AWS (`InstanceCredentialExfiltration` and related) which often follows lateral movement.
- **IAM Access Analyzer** flags roles whose trust policies grant external or organization-wide access.

## Remediation & Hardening

- Scope every trust policy to specific principal ARNs; avoid `root` and `"*"` principals.
- Require `sts:ExternalId` on all third-party cross-account roles and `aws:PrincipalOrgID` for intra-organization trust.
- For OIDC/SAML, constrain on `sub` (and `aud`) claims, not audience alone; pin repository/branch/workload identifiers.
- Add `aws:MultiFactorAuthPresent` and, where feasible, `aws:SourceIp` conditions to sensitive role trust policies.
- Limit and monitor use of `OrganizationAccountAccessRole`; consider replacing standing cross-account roles with IAM Identity Center permission sets.
- Set conservative role `MaxSessionDuration`; remember role chaining caps sessions at one hour.
- Use SCPs to deny assumption of high-value roles except from approved principals, and alert on the CloudTrail events above.

## Tools

- **aws-cli / awscli-sts** - performs all `assume-role*` operations.
- **principal-mapper (pmapper)** - maps assume-role reachability within and across accounts (`orgs create`).
- **pacu** - enumerates assumable roles and automates assumption and chaining.

## References

- AWS STS API Reference - AssumeRole
- AWS IAM User Guide - Roles terms and concepts
- AWS IAM User Guide - Using external ID for third-party access
- hackingthe.cloud - IAM privilege escalation and lateral movement
- NCC Group - PMapper
