---
cstg_id: CSTG-AWS-STS-LATERAL
title: "AWS Sts - Lateral Movement"
provider: aws
service: sts
phase: lateral-movement
required_access: assumed-breach
required_permissions: [sts:AssumeRole, sts:AssumeRoleWithWebIdentity, sts:AssumeRoleWithSAML, sts:GetFederationToken, sts:GetSessionToken]
tools: [aws-cli, pacu, PMapper, awsenum, weirdAAL]
references: ["https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html", "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html"]
license: CC BY-SA 4.0
---

## Summary

Lateral movement in AWS is overwhelmingly an STS phenomenon: `sts:AssumeRole` (and its federated variants) is the primitive that lets a principal pivot from one identity to another, and - via cross-account trust - from one account to another. Where privilege escalation aims *upward* within a single identity context, lateral movement chains role assumptions *sideways and across boundaries* to reach data, compute, or trust relationships not directly accessible from the foothold. Because each assumption yields a fresh, short-lived credential set under a new ARN, role chaining is also an effective way to obscure the origin of activity.

The attacker objective is to traverse the account's (and organization's) trust graph - hopping through assumable roles, cross-account trusts, and federated identities - to reach high-value targets while shedding the original principal's identity at each hop.

## Prerequisites

- An assumed-breach foothold with `sts:AssumeRole` (or `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML`) on at least one target role.
- Discovered trust relationships from [AWS STS - Enumeration](../02-services/aws-sts-enum.md): roles whose trust policy `Principal` includes the current principal, the current account root, an external account, or an OIDC/SAML provider.
- For cross-account hops: the target role's trust must allow the source account/principal; an `sts:ExternalId` if required.

## Enumeration

```bash
# Roles I can reach now (trust includes me or account-root)
aws iam list-roles \
  --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json

# Cross-account trusts: look for foreign account IDs / "*" / federated principals
# (inspect each AssumeRolePolicyDocument Principal block)

# Confirm a specific assumption is permitted
aws iam simulate-principal-policy --policy-source-arn <my-arn> \
  --action-names sts:AssumeRole \
  --resource-arns arn:aws:iam::222222222222:role/CrossAcctRole
```

Graph the reachable set with PMapper (`pmapper graph create`, then `pmapper query "who can do sts:AssumeRole with *"`), which models multi-hop role chains across loaded accounts.

## Misconfigurations & Findings

- **Cross-account trust without `sts:ExternalId`** - the classic *confused-deputy*: a role that trusts a third-party/vendor account but omits the external-ID condition can be assumed by any customer of that vendor (or anyone who guesses the role ARN if `Principal` is `*`).
- **`Principal: "*"` or `account-root` trusts** - allow any in-account (or any) principal to assume, collapsing identity isolation.
- **OIDC web-identity trust without `sub`/`aud` conditions** - a role federating a CI provider (GitHub Actions, GitLab) or a Kubernetes/IRSA OIDC issuer that fails to pin the repository/branch/service-account `sub` can be assumed by any workload of that provider via `AssumeRoleWithWebIdentity`.
- **SAML trust with loose `Audience`/issuer conditions** - permits `AssumeRoleWithSAML` from a broader set of IdP assertions than intended.
- **Role chaining tolerated without monitoring** - successive `AssumeRole` hops (A->B->C) used to launder identity; each hop caps at a 1-hour session but is otherwise unconstrained.
- **Hub/landing-zone roles** (e.g. `OrganizationAccountAccessRole`) trusting the management account broadly - a single assumption reaches every member account.

## Exploitation

### Same-account pivot (sts:AssumeRole)

```bash
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/DataReader \
  --role-session-name hop1
export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...; export AWS_SESSION_TOKEN=...
aws s3 ls   # now operating as DataReader
```

### Cross-account pivot

```bash
# Target account 222... trusts source account 111...
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/CrossAcctRole \
  --role-session-name hop2 \
  --external-id SHARED_SECRET   # required only if the trust sets sts:ExternalId
```

### Confused-deputy abuse

If `CrossAcctRole` trusts a vendor account with no `ExternalId` condition, any principal in that vendor account assumes it directly. Where `Principal` is `*` and the role ARN is known/guessable, assumption needs only `sts:AssumeRole` on the caller side.

### Role chaining to obscure origin

```bash
# Hop A -> B
creds=$(aws sts assume-role --role-arn arn:...:role/B --role-session-name a)
# load creds, then hop B -> C under B's identity
aws sts assume-role --role-arn arn:...:role/C --role-session-name b
# CloudTrail now attributes C-scoped activity to role C's session, not the origin user
```

### Web-identity pivot (AssumeRoleWithWebIdentity)

With a valid OIDC token from a trusted issuer (e.g. exfiltrated from a CI runner or a pod's projected service-account token), and a trust policy lacking subject pinning:

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111111111111:role/CI-Deploy \
  --role-session-name web --web-identity-token "$OIDC_JWT"
```

### SAML pivot (AssumeRoleWithSAML)

```bash
aws sts assume-role-with-saml \
  --role-arn arn:aws:iam::111111111111:role/SSO-Admin \
  --principal-arn arn:aws:iam::111111111111:saml-provider/Corp \
  --saml-assertion "$B64_SAML_RESPONSE"
```

### Derived sessions (GetFederationToken / GetSessionToken)

Convert held long-term keys into temporary `federated-user`/session credentials to operate under a different identity string and, with `GetFederationToken`, attach a scoped session policy for the new context.

After each hop, re-run `aws sts get-caller-identity` and the enumeration commands to discover the *next* set of reachable roles from the new vantage point.

## Detection & Logging

- **CloudTrail** logs every `AssumeRole`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML`, `GetFederationToken`, and `GetSessionToken`. Each event's `userIdentity` shows the assuming principal and the resulting session; cross-account assumptions appear in *both* the source (`AssumeRole` request) and target (the session's subsequent activity) account trails.
- Role chaining shows as a sequence of `AssumeRole` events where each session name/`accessKeyId` is the principal of the next - reconstruct the chain by joining `sourceIdentity`/session ARNs. Setting and propagating `sts:SourceIdentity` aids this attribution.
- Web-identity/SAML assumptions from unusual `sourceIPAddress` or with a `sub`/issuer not seen before are strong signals.
- Cross-account `AssumeRole` from an unexpected `recipientAccountId`/source account; assumption of `OrganizationAccountAccessRole` outside change windows.
- Managed detections: **GuardDuty** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`/`InsideAWS`, `Discovery:*`, and cross-account anomaly findings; CloudTrail Lake / Security Lake queries joining sessions across accounts.

## Remediation & Hardening

- Require `sts:ExternalId` on every third-party cross-account role trust; never use `Principal: "*"`.
- Pin OIDC trusts with `StringEquals`/`StringLike` on `token.actions.githubusercontent.com:sub` (repo/branch) or the IRSA service-account `sub`; pin SAML `Audience`.
- Add `aws:SourceArn`, `aws:SourceAccount`, `aws:MultiFactorAuthPresent`, and `aws:SourceIp` conditions to sensitive trusts.
- Enforce `sts:SourceIdentity` so chained sessions retain origin attribution; consider `DenyChaining`-style SCPs limiting role-to-role assumption.
- Use SCPs to restrict which accounts/principals may assume landing-zone roles, and IAM Access Analyzer to continuously surface external and cross-account trust.
- Alert on multi-hop assumption chains, web-identity assumptions from new issuers/IPs, and assumption of organization management roles.

## Tools

- **aws-cli** - all `sts assume-role*` variants and credential handling.
- **Pacu** - role-assumption and cross-account pivot modules; persists harvested sessions.
- **PMapper** - cross-account role-chain reachability graphs.
- **awsenum / weirdAAL** - enumerate and exercise assumable roles and credential reach.

## References

- AWS STS AssumeRole API - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- Using an external ID for third-party access - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
- Creating a role for web identity / OIDC - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
- hackingthe.cloud - IAM privilege escalation and role chaining - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
