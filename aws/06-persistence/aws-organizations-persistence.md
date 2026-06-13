---
cstg_id: CSTG-AWS-ORGANIZATIONS-PERSIST
title: "AWS Organizations - Persistence"
provider: aws
service: organizations
phase: persistence
required_access: assumed-breach
required_permissions:
  - organizations:CreateAccount
  - organizations:CreatePolicy
  - organizations:AttachPolicy
  - organizations:UpdatePolicy
  - organizations:RegisterDelegatedAdministrator
  - organizations:EnableAWSServiceAccess
  - sts:AssumeRole
  - iam:CreateRole
  - iam:UpdateAssumeRolePolicy
tools:
  - AWS CLI
  - AWS SDK
  - graph-based IAM analysis tooling
references:
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate.html
  - https://hackingthe.cloud/aws/post_exploitation/create_a_console_session_from_iam_credentials/
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
license: CC BY-SA 4.0
---

## Summary

Because AWS Organizations is the top of the multi-account control plane, persistence established there is broad and durable — it survives the remediation of individual accounts and reasserts control across the whole estate. Org-level persistence techniques include: creating new attacker-controlled member accounts that inherit a management-account-trusting admin role; planting or weakening SCPs/RCPs so that defensive actions are denied or attacker exceptions are baked into the guardrails themselves; registering an attacker-controlled account as a delegated administrator for security services; and adding cross-account trust to the management account's break-glass role.

The defining property of these techniques is **scope and stealth**: a single SCP can silently exempt a chosen principal across every account, and a delegated-administrator registration grants standing org-wide authority over a security service. Eradication requires understanding and reconciling org-level configuration, not just rotating credentials in one account.

This page assumes an assumed-breach foothold in the management account or a delegated administrator with the relevant write permissions (see CSTG-AWS-ORGANIZATIONS-ENUM and CSTG-AWS-ORGANIZATIONS-PRIVESC).

## Prerequisites

- An assumed-breach principal in the **management account** (or a delegated administrator where the operation supports it) with one or more of the permissions above.
- Most write operations (`CreatePolicy`, `AttachPolicy`, `CreateAccount`, `RegisterDelegatedAdministrator`, `EnableAWSServiceAccess`) can only be performed from the management account or a registered delegated administrator.

## Enumeration

Confirm position and current guardrails before establishing persistence:

```bash
aws sts get-caller-identity
aws organizations describe-organization
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-delegated-administrators
aws organizations list-aws-service-access-for-organization
```

## Misconfigurations & Findings

- **Attacker-created member accounts** that blend into the inventory but are fully attacker-controlled and trusted by the org.
- **SCPs containing principal/account exceptions** (a `Deny` weakened by `aws:PrincipalArn`/`aws:PrincipalAccount` conditions) that quietly preserve attacker access.
- **Protective-deny SCPs** crafted to block *defenders* (e.g. denying `cloudtrail:*`, `guardduty:*`, `config:*`, or `iam:Delete*` for everyone except the attacker), inverting the guardrail concept.
- **Unexpected delegated administrators** for security services, granting standing org-wide control.
- **Newly enabled trusted service access** that establishes service-linked roles across accounts.
- **Modified trust on `OrganizationAccountAccessRole`** or other break-glass roles to add an attacker principal.

## Exploitation

### organizations:CreateAccount — persistent foothold account

A new member account created by the attacker inherits a cross-account admin role trusting the management account and is hard to distinguish from legitimate accounts. It serves as a durable staging/landing account inside the trust boundary:

```bash
aws organizations create-account \
  --email attacker+svc@example.com \
  --account-name "shared-logging" \
  --role-name OrganizationAccountAccessRole
```

Even if the original foothold is cleaned up, this account (and its trust into the management account) persists until explicitly identified and removed.

### organizations:CreatePolicy + AttachPolicy — guardrails as a backdoor

Create an SCP that protects the attacker's access and/or hampers defenders, then attach it at the root so it applies org-wide. Example concept: deny security principals the ability to delete or modify the attacker's resources, or deny everyone except the attacker from disabling a malicious configuration.

```bash
aws organizations create-policy \
  --name "baseline-guardrail" \
  --type SERVICE_CONTROL_POLICY \
  --description "baseline" \
  --content file://persist-scp.json

aws organizations attach-policy \
  --policy-id p-newpolicyid \
  --target-id r-exampl
```

Because SCPs are inherited and apply to member-account principals (not the management account), an attacker operating from the management account remains unaffected while defenders in member accounts are constrained.

### organizations:UpdatePolicy — silent exception in an existing SCP

The stealthiest variant: edit an existing, expected SCP to carve out an exception for the attacker principal rather than creating a new policy. Defenders see the same policy attached and may not diff its content:

```bash
aws organizations update-policy \
  --policy-id p-existingscp \
  --content file://scp-with-attacker-exception.json
```

A `Deny` statement gains a condition like `StringNotEquals aws:PrincipalArn arn:aws:iam::*:role/attacker-role`, preserving the attacker's exemption indefinitely.

### organizations:RegisterDelegatedAdministrator — standing org-wide authority

Registering an attacker-controlled account as delegated administrator for a security service grants persistent, legitimate-looking org-wide control. It survives management-account session expiry and is often overlooked during incident response:

```bash
aws organizations register-delegated-administrator \
  --account-id 333333333333 \
  --service-principal guardduty.amazonaws.com
```

The attacker can then suppress findings, modify member configurations, or disable detection across the org from an account they control (see CSTG-AWS-ORGANIZATIONS-LATERAL).

### organizations:EnableAWSServiceAccess — trusted-service footholds

Enabling trusted access for a service provisions service-linked roles across member accounts, which can be repurposed or relied upon for ongoing access patterns:

```bash
aws organizations enable-aws-service-access \
  --service-principal <service>.amazonaws.com
```

### Trust-policy persistence on break-glass roles

Adding the attacker's principal to the trust policy of `OrganizationAccountAccessRole` (in member accounts) or other admin roles preserves cross-account access even after the original credentials are revoked:

```bash
aws iam update-assume-role-policy \
  --role-name OrganizationAccountAccessRole \
  --policy-document file://expanded-trust.json
```

## Detection & Logging

Organizations write events land in **CloudTrail in the management account** (global service, `us-east-1`). Prioritize alerting on:

- `CreatePolicy`, `AttachPolicy`, `UpdatePolicy` (capture and diff the policy *content*, not just the event).
- `CreateAccount`, `CreateGovCloudAccount`, `AcceptHandshake`.
- `RegisterDelegatedAdministrator`, `EnableAWSServiceAccess`.
- `UpdateAssumeRolePolicy` / `CreateRole` on cross-account admin roles in member accounts.

Detection guidance:

- New member accounts and new delegated administrators should be exceedingly rare and tied to provisioning automation; treat ad-hoc occurrences as suspicious.
- The `UpdatePolicy` exception technique is invisible to event-name-only monitoring — maintain a versioned baseline of all SCP/RCP documents and reconcile continuously to detect carve-outs.
- Periodically diff the trust policies of break-glass and cross-account roles against expected baselines.
- During incident response, explicitly enumerate the org (accounts, SCPs, delegated admins, trusted services) — credential rotation alone does not remove org-level persistence.

## Remediation & Hardening

- Restrict `organizations:*` write actions to a dedicated provisioning role behind change control; deny them everywhere else.
- Version-control all SCP/RCP documents and reconcile live policy content against source of truth on a schedule to catch silent edits and rogue policies.
- Inventory and alert on delegated administrators and trusted services; remove any not explicitly required.
- Periodically reconcile the account list against an authoritative source to surface attacker-created accounts; review the cross-account role name and trust in every member account.
- Lock down and monitor the management account; require MFA and short-lived federated sessions.
- During eradication, audit org-level configuration as a first-class step, not just per-account credentials.

## Tools

- AWS CLI (`aws organizations`, `aws iam`, `aws sts`) and SDKs.
- Graph-based IAM analysis tooling to surface cross-account trust and org-level persistence.
- Posture scanners that baseline and diff SCP/RCP content, delegated admins, and trusted services.

## References

- Service Control Policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- Creating a member account — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html
- AWS services that integrate with Organizations — https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate.html
- hackingthe.cloud — console session from IAM credentials — https://hackingthe.cloud/aws/post_exploitation/create_a_console_session_from_iam_credentials/
- Rhino Security Labs — AWS privilege escalation methods — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
