---
cstg_id: CSTG-AWS-COGNITO-ENUM
title: "AWS Cognito - Enumeration"
provider: aws
service: cognito
phase: services
required_access: read-only-audit
required_permissions:
  - cognito-idp:ListUserPools
  - cognito-idp:DescribeUserPool
  - cognito-idp:ListUserPoolClients
  - cognito-idp:DescribeUserPoolClient
  - cognito-idp:ListUsers
  - cognito-idp:ListGroups
  - cognito-idp:ListResourceServers
  - cognito-idp:ListIdentityProviders
  - cognito-idp:GetUserPoolMfaConfig
  - cognito-identity:ListIdentityPools
  - cognito-identity:DescribeIdentityPool
  - cognito-identity:GetIdentityPoolRoles
  - cognito-identity:ListIdentities
  - iam:GetRole
  - iam:GetRolePolicy
  - iam:ListAttachedRolePolicies
tools:
  - aws-cli
  - jq
  - pacu
  - prowler
  - scoutsuite
references:
  - "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/attributes-for-access-control.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-settings.html"
  - "https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-only enumeration of Amazon Cognito from inside an AWS account - the inventory and configuration review a tester performs with audit/read-only access, or a defender performs to validate posture. It maps every User Pool and Identity Pool, their app clients, federated identity providers, groups, role mappings, MFA/security settings, and the IAM roles those resources hand out. The objective is to build a complete picture of how Cognito issues identities and AWS credentials in the account, and to surface the misconfigurations that the [unauthenticated](../01-unauthenticated-external/aws-cognito-unauthenticated.md) and [privilege-escalation](../03-privilege-escalation/aws-cognito-privesc.md) pages exploit: guest-enabled pools, over-privileged guest/auth roles, weak role-mapping, exposed app clients, and enumeration-friendly user-pool settings.

## Prerequisites

- **Access level:** Read-only/audit credentials in the target account. The AWS managed `SecurityAudit` and `ReadOnlyAccess` policies cover most of the operations below; resolving the IAM roles handed out by Identity Pools also requires `iam:GetRole`, `iam:GetRolePolicy`, and `iam:ListAttachedRolePolicies`.
- **Key permissions** (neutral list): `cognito-idp:List*`/`Describe*`/`Get*`, `cognito-identity:List*`/`Describe*`/`GetIdentityPoolRoles`, and the IAM read permissions above.
- Cognito is regional - repeat enumeration in every region in scope.

## Enumeration

### User Pools

```bash
# List all User Pools in a region
aws cognito-idp list-user-pools --max-results 60 --region us-east-1

# Full pool configuration: policies, auto-verified attrs, schema, Lambda triggers,
# admin-create-user settings, MFA, advanced security mode
aws cognito-idp describe-user-pool \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1

# MFA configuration in detail
aws cognito-idp get-user-pool-mfa-config \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1
```

Things to capture from `describe-user-pool`: `Policies.PasswordPolicy`, `AutoVerifiedAttributes`, `UsernameAttributes`, `MfaConfiguration`, `AdminCreateUserConfig.AllowAdminCreateUserOnly` (false = public sign-up), `LambdaConfig` (Pre/PostAuthentication, Pre/PostConfirmation, PreTokenGeneration triggers), `UserPoolAddOns.AdvancedSecurityMode`, and the custom `SchemaAttributes`.

### App clients

```bash
aws cognito-idp list-user-pool-clients \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1

aws cognito-idp describe-user-pool-client \
  --user-pool-id us-east-1_AbCdEf123 \
  --client-id 1example23clientid456789ab --region us-east-1
```

Inspect `ExplicitAuthFlows` (presence of `ALLOW_USER_PASSWORD_AUTH` = non-SRP password auth), `GenerateSecret` (a public client has none), `PreventUserExistenceErrors` (`ENABLED` vs `LEGACY`), `AllowedOAuthFlows`/`AllowedOAuthScopes`, `CallbackURLs`, `SupportedIdentityProviders`, and `ReadAttributes`/`WriteAttributes`.

### Users, groups, and federation

```bash
# Enumerate users (sensitive attributes, statuses)
aws cognito-idp list-users --user-pool-id us-east-1_AbCdEf123 --region us-east-1

# Groups - each group may carry an IAM RoleArn (RBAC) and Precedence
aws cognito-idp list-groups --user-pool-id us-east-1_AbCdEf123 --region us-east-1
aws cognito-idp get-group --group-name Admins \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1

# Members of a privileged group
aws cognito-idp list-users-in-group --group-name Admins \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1

# Federated identity providers (SAML/OIDC/social) and their attribute mapping
aws cognito-idp list-identity-providers \
  --user-pool-id us-east-1_AbCdEf123 --region us-east-1
aws cognito-idp describe-identity-provider \
  --user-pool-id us-east-1_AbCdEf123 --provider-name MyOIDC --region us-east-1

# Resource servers (custom OAuth scopes)
aws cognito-idp list-resource-servers \
  --user-pool-id us-east-1_AbCdEf123 --max-results 50 --region us-east-1
```

Group `RoleArn` values are critical: a User Pool group can directly select an IAM role (token-based RBAC) that authenticated users then assume through an Identity Pool. A high-precedence/privileged group is a privilege-escalation target.

### Identity Pools and role mapping

```bash
# List Identity Pools
aws cognito-identity list-identity-pools --max-results 60 --region us-east-1

# Pool config - critically, AllowUnauthenticatedIdentities and linked providers
aws cognito-identity describe-identity-pool \
  --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012 --region us-east-1

# The roles handed out: default Authenticated/Unauthenticated roles + RoleMappings
aws cognito-identity get-identity-pool-roles \
  --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012 --region us-east-1

# Existing identities in the pool
aws cognito-identity list-identities \
  --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012 \
  --max-results 60 --region us-east-1
```

`get-identity-pool-roles` returns `Roles.authenticated`, `Roles.unauthenticated`, and `RoleMappings`. A populated `unauthenticated` role with `AllowUnauthenticatedIdentities=true` is the guest-credential issuer. `RoleMappings` with `Type=Token` and `AmbiguousRoleResolution=AuthenticatedRole` (or rules that select roles from claims) define which IAM role each token receives.

### Resolving the actual IAM permissions

For every role returned (default auth/unauth, group `RoleArn`s, and `RoleMappings` targets), pull the role and its policies and trust relationship:

```bash
ROLE=Cognito_MyPoolUnauth_Role
aws iam get-role --role-name "$ROLE"                       # AssumeRolePolicyDocument (trust)
aws iam list-attached-role-policies --role-name "$ROLE"
aws iam list-role-policies --role-name "$ROLE"
aws iam get-role-policy --role-name "$ROLE" --policy-name inline-policy-name
```

In the trust policy, check the `Condition` block for `cognito-identity.amazonaws.com:aud` (should equal the Identity Pool ID) and `cognito-identity.amazonaws.com:amr` (`authenticated`/`unauthenticated`). A missing or loose condition is a finding.

## Misconfigurations & Findings

- **`AllowUnauthenticatedIdentities = true`** with a non-trivial `unauthenticated` role - anonymous AWS credentials are obtainable (see unauthenticated page).
- **Over-privileged auth/unauth/group roles** - wildcard actions/resources, `iam:PassRole`, `lambda:*`, `s3:*`, `dynamodb:*`, `sts:AssumeRole`, etc. These are the privilege-escalation engine.
- **Weak/ambiguous `RoleMappings`** - `AmbiguousRoleResolution=AuthenticatedRole` or `RulesConfiguration` that lets a chosen/forgeable claim select a more privileged role.
- **Loose role trust policies** - missing `aud`/`amr` conditions, allowing tokens from other pools or the wrong principal type to assume the role.
- **`AdvancedSecurityMode = OFF`** - no threat protection / compromised-credential detection.
- **`PreventUserExistenceErrors` LEGACY/absent** on app clients - enables user enumeration.
- **`ALLOW_USER_PASSWORD_AUTH` enabled** - non-SRP password auth permits straightforward spraying.
- **Public sign-up enabled** (`AllowAdminCreateUserOnly=false`) and/or `AutoVerifiedAttributes` with auto-confirm Lambda - outsiders self-provision authenticated identities.
- **Group `RoleArn` for a privileged role** combined with the ability to add users to the group - direct path to that role.
- **Sensitive data in custom schema attributes** that are user-readable/writable, or surfaced in tokens.
- **Lambda triggers** (PreTokenGeneration, PreAuthentication) that inject claims used for authorization - review for injection / claim-spoofing risk.

## Exploitation

Enumeration is itself read-only; the exploitation of the findings above is documented on the sibling pages. In particular:

- Anonymous credential issuance and self-registration: [Unauthenticated access](../01-unauthenticated-external/aws-cognito-unauthenticated.md).
- Turning over-privileged roles, group RoleArns, and ambiguous role mapping into account compromise: [Privilege escalation](../03-privilege-escalation/aws-cognito-privesc.md).

A practical pivot during enumeration: once an Identity Pool ID and (for authenticated paths) a valid token are known, validate the issued credentials' real scope by assuming the role and running `aws sts get-caller-identity` followed by targeted probes against the services the role policy references.

## Detection & Logging

- **CloudTrail management events** record the read operations above with `eventSource cognito-idp.amazonaws.com` / `cognito-identity.amazonaws.com` (`ListUserPools`, `DescribeUserPool`, `ListUsers`, `GetIdentityPoolRoles`, `ListIdentities`, etc.). A burst of `List*`/`Describe*` Cognito calls from a single principal/IP is a hallmark of reconnaissance.
- **IAM read calls** (`GetRole`, `GetRolePolicy`, `ListAttachedRolePolicies`) correlated with the Cognito enumeration indicate an actor resolving the privileges behind the pools.
- **Anomaly detection** - GuardDuty flags unusual enumeration patterns and credential-discovery behavior; CloudTrail Insights highlights abnormal call-rate spikes for these APIs.
- Enumeration that uses guest credentials will appear under the `assumed-role/Cognito_...Unauth_Role` principal rather than a named user.

## Remediation & Hardening

- Apply least privilege to the enumeration capability itself: scope `SecurityAudit`/read roles and monitor their Cognito/IAM read activity.
- Remediate each finding class as covered on the sibling pages: disable guest identities where unneeded; tighten auth/unauth/group roles and their trust conditions (`aud`, `amr`); use enhanced flow with strict role mapping; enable `PreventUserExistenceErrors`; enable advanced security/threat protection; prefer SRP and enforce MFA.
- Inventory and review custom schema attributes and Lambda triggers; remove sensitive data from client-readable attributes and tokens.
- Tag and regularly re-audit all Identity Pools and the roles they reference; alert on changes to `get-identity-pool-roles` output and on `SetIdentityPoolRoles` events.

## Tools

- **aws-cli + jq** - manual, scriptable enumeration of the operations above.
- **Pacu** - the `cognito__enum` module inventories User/Identity Pools, app clients, and role mappings; companion modules attempt the exploitation paths.
- **Prowler / ScoutSuite** - automated posture checks flag guest-enabled pools, missing user-existence protection, weak password policy, and disabled advanced security.
- **CloudMapper / IAM policy analyzers** - resolve and visualize the effective permissions of the roles handed out by Cognito.

## References

- Cognito User Pools API reference - <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/Welcome.html>
- Cognito Identity API reference - <https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/Welcome.html>
- Role-based access control with Cognito - <https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html>
- Attributes for access control (ABAC) - <https://docs.aws.amazon.com/cognito/latest/developerguide/attributes-for-access-control.html>
- User pool app client settings - <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-settings.html>
- Hacking the Cloud - Cognito Identity Pool excessive privileges - <https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/>
