---
cstg_id: CSTG-AWS-ORGANIZATIONS-PRIVESC
title: "AWS Organizations - Privilege Escalation"
provider: aws
service: organizations
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - organizations:CreateAccount
  - organizations:InviteAccountToOrganization
  - organizations:DetachPolicy
  - organizations:DeletePolicy
  - organizations:UpdatePolicy
  - organizations:DisablePolicyType
  - organizations:RegisterDelegatedAdministrator
  - organizations:LeaveOrganization
  - organizations:RemoveAccountFromOrganization
  - sts:AssumeRole
  - iam:CreateAccountAlias
tools:
  - AWS CLI
  - AWS SDK
  - graph-based IAM analysis tooling
references:
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html
  - https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
license: CC BY-SA 4.0
---

## Summary

In AWS Organizations, "privilege escalation" rarely means escalating IAM permissions within a single account. Instead it means **escalating org-wide authority**: weakening or removing the Service Control Policies (SCPs) and Resource Control Policies (RCPs) that constrain a principal, expanding access into new accounts via account creation, or abusing the management account's unconstrained position. SCPs are *the* guardrail in a multi-account AWS estate; a principal that can detach, delete, weaken, or disable SCP enforcement effectively grants itself (and every other principal) the union of what the SCP previously blocked.

The most important structural fact: **principals in the management account are never subject to SCPs.** SCPs filter the permissions of principals in member accounts only. Therefore any path that lands a principal in the management account (or that lets it modify SCPs from anywhere) is a top-tier escalation. This page covers escalation via SCP manipulation, account creation, delegated-administrator registration, and the management-account exception.

This page assumes an assumed-breach foothold with one or more of the permissions below in the management account or a sufficiently privileged delegated-administrator account. Use CSTG-AWS-ORGANIZATIONS-ENUM to determine which apply.

## Prerequisites

- An assumed-breach principal in the **management account**, or in a **delegated administrator for Organizations** with policy-write permissions (most write operations on SCPs and accounts can only be performed from the management account or, where supported, a registered delegated administrator).
- One or more of the permissions listed above. Because the management account is exempt from SCPs, only IAM (not SCP) constrains a management-account principal.
- Knowledge of the org tree, attached SCPs, and delegated admins from CSTG-AWS-ORGANIZATIONS-ENUM.

## Enumeration

Before attempting escalation, confirm the guardrails in scope and where the principal sits:

```bash
aws sts get-caller-identity
aws organizations describe-organization           # is caller's account == MasterAccountId?
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-policies-for-target --target-id 222222222222 \
  --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-examplepolicyid
aws organizations list-targets-for-policy --policy-id p-examplepolicyid
```

Identify which SCPs deny the actions the assessor wants to perform, and whether the caller has the write permissions to alter them.

## Misconfigurations & Findings

- **`organizations:DetachPolicy` / `DeletePolicy` / `UpdatePolicy` granted to non-administrative principals.** Allows removal of guardrails org-wide.
- **`organizations:DisablePolicyType` granted.** Turns off SCP enforcement entirely for a root, neutralizing every SCP at once.
- **`organizations:CreateAccount` / `InviteAccountToOrganization` granted broadly.** Enables creation of new attacker-controlled accounts that inherit a default-admin cross-account role and default `FullAWSAccess`.
- **Workloads or IAM principals running in the management account.** Any compromise there is automatically SCP-exempt.
- **SCPs that protect data/security services but omit `organizations:*` write actions**, so the guardrails fail to protect themselves.
- **`organizations:RegisterDelegatedAdministrator` granted**, allowing an attacker account to be made a delegated admin for security services and then to reconfigure them.

## Exploitation

### organizations:DetachPolicy

Detaching the restrictive SCP from an account or OU removes the guardrail. If only `FullAWSAccess` remains, the target's principals regain full permissions (subject to IAM). The SCP itself is not deleted, but enforcement on that target stops immediately:

```bash
aws organizations detach-policy \
  --policy-id p-restrictivescp \
  --target-id 222222222222
```

This is high-signal but extremely effective: a single call can re-enable actions an SCP was blocking org-wide (e.g. disabling CloudTrail, creating IAM users, using denied Regions). Detaching from the **root** removes the guardrail from every descendant at once.

### organizations:UpdatePolicy

More subtle than detaching: rewrite the SCP document to carve out an exception for the attacker's principal, account, or action while leaving the policy attached so monitoring still "sees" an SCP in place. A `Deny` SCP can be weakened with a condition that excludes a chosen principal ARN or account, for example adding `Condition: StringNotEquals aws:PrincipalArn arn:...attacker-role`:

```bash
aws organizations update-policy \
  --policy-id p-restrictivescp \
  --content file://weakened-scp.json
```

The org still reports the policy as attached and enabled, but it no longer blocks the chosen identity. This is both an escalation and a persistence/evasion technique (see CSTG-AWS-ORGANIZATIONS-PERSIST).

### organizations:DeletePolicy

Detach (required first) then delete the SCP, permanently removing the guardrail. Noisier and harder to reverse than `UpdatePolicy`, but it removes the constraint entirely:

```bash
aws organizations detach-policy --policy-id p-restrictivescp --target-id r-exampl
aws organizations delete-policy --policy-id p-restrictivescp
```

### organizations:DisablePolicyType

The blunt instrument: disabling the `SERVICE_CONTROL_POLICY` type for a root deactivates *all* SCP enforcement under that root in one call, regardless of how many SCPs are attached. Every member account's principals revert to IAM-only constraints:

```bash
aws organizations disable-policy-type \
  --root-id r-exampl \
  --policy-type SERVICE_CONTROL_POLICY
```

The same applies to `RESOURCE_CONTROL_POLICY` and other policy types. This is the single highest-impact org-level escalation action.

### organizations:CreateAccount / InviteAccountToOrganization

Creating a new member account yields a fresh account that (a) inherits a cross-account admin role trusting the management account (default `OrganizationAccountAccessRole`, name configurable via `--role-name`) and (b) by default has only `FullAWSAccess` attached unless the parent OU's SCPs apply. An attacker who controls account creation gains a new, fully controlled account inside the trust boundary:

```bash
aws organizations create-account \
  --email attacker+new@example.com \
  --account-name "shared-services" \
  --role-name OrganizationAccountAccessRole

# poll status
aws organizations describe-create-account-status \
  --create-account-request-id car-exampleid
```

Then pivot into the new account from the management account (see CSTG-AWS-ORGANIZATIONS-LATERAL). `InviteAccountToOrganization` similarly brings an externally controlled account under the org and its consolidated billing/trust.

### organizations:RegisterDelegatedAdministrator

Registering an attacker-controlled member account as a delegated administrator for a security service (or for Organizations itself) grants that account org-wide authority over the service. For example, becoming the delegated admin for GuardDuty or Security Hub lets the attacker reconfigure detection across the org from a member account they fully control:

```bash
aws organizations register-delegated-administrator \
  --account-id 333333333333 \
  --service-principal guardduty.amazonaws.com
```

This is escalation (org-wide control of the service) and a persistence foothold (CSTG-AWS-ORGANIZATIONS-PERSIST).

### The management-account exception (no specific permission)

Because SCPs do not apply to the management account, *any* IAM-permitted action by a management-account principal bypasses every org guardrail. There is no API to "escalate" here — the escalation is simply landing in the management account. This is why management-account access is the crown jewel and why lateral movement toward it (CSTG-AWS-ORGANIZATIONS-LATERAL) is treated as terminal.

## Detection & Logging

Organizations write events are recorded in **CloudTrail in the management account** (global service, `us-east-1`). High-priority events to alert on:

- `DetachPolicy`, `DeletePolicy`, `UpdatePolicy` on a `SERVICE_CONTROL_POLICY` or `RESOURCE_CONTROL_POLICY`.
- `DisablePolicyType` — should be exceptionally rare; treat as critical.
- `CreateAccount`, `CreateGovCloudAccount`, `InviteAccountToOrganization`, `AcceptHandshake`.
- `RegisterDelegatedAdministrator` / `EnableAWSServiceAccess`.

Detection guidance:

- These are control-plane changes that should originate only from a known IaC/change pipeline. Alert on any of the above from an interactive or unexpected principal.
- `UpdatePolicy` is the stealthiest: monitor the *content diff*, not just the event name — a policy that remains attached can be silently gutted. Capture and compare SCP documents over time.
- Correlate `DetachPolicy`/`DisablePolicyType` with subsequent member-account activity that the SCP previously denied (e.g. `cloudtrail:StopLogging` succeeding right after).

## Remediation & Hardening

- Grant `organizations:*` write actions only to a tightly scoped change-management role; deny them to everyone else. Consider requiring MFA and source-IP/identity conditions.
- Keep the management account empty of workloads and standing credentials; access it only via short-lived federated sessions.
- Protect the guardrails with the guardrails: although the management account is SCP-exempt, ensure member-account principals cannot reach `organizations:*` write actions, and monitor the management account intensively.
- Treat `DisablePolicyType`, `DeletePolicy`, and `DetachPolicy` on protective SCPs as break-glass operations behind approval workflows.
- Store SCP/RCP documents in version control and continuously reconcile live policy content against the source of truth to catch silent `UpdatePolicy` edits.
- Restrict `CreateAccount` and `RegisterDelegatedAdministrator` to the org provisioning pipeline only.

## Tools

- AWS CLI (`aws organizations`, `aws sts`) and SDKs for the actions above.
- Graph-based IAM analysis tooling to identify which principals can reach Organizations write actions and the management account.
- Posture scanners that diff live SCP/RCP content against expected baselines.

## References

- Service Control Policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- Creating a member account — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html
- Accessing member accounts — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html
- hackingthe.cloud — evading GuardDuty — https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/
- Rhino Security Labs — AWS privilege escalation methods — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
