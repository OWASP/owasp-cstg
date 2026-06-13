---
cstg_id: CSTG-AWS-ORGANIZATIONS-ENUM
title: "AWS Organizations - Enumeration"
provider: aws
service: organizations
phase: services
required_access: read-only-audit
required_permissions:
  - organizations:DescribeOrganization
  - organizations:ListAccounts
  - organizations:ListRoots
  - organizations:ListOrganizationalUnitsForParent
  - organizations:ListAccountsForParent
  - organizations:ListPolicies
  - organizations:DescribePolicy
  - organizations:ListTargetsForPolicy
  - organizations:ListDelegatedAdministrators
  - organizations:ListAWSServiceAccessForOrganization
  - organizations:DescribeAccount
tools:
  - AWS CLI
  - AWS SDK
  - cloud security posture scanners
  - graph-based IAM analysis tooling
references:
  - https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html
  - https://hackingthe.cloud/aws/enumeration/enum_iam_user_role_via_assumerolepolicy/
license: CC BY-SA 4.0
---

## Summary

AWS Organizations is the multi-account governance layer that ties many AWS accounts into a single billing and policy domain. It introduces a hierarchy of a **management account** (formerly "master account"), **organizational units (OUs)**, **member accounts**, and **policies** (Service Control Policies, tag policies, backup policies, AI services opt-out policies) attached at the root, OU, or account level. It also defines **delegated administrators** for trusted services and the master `OrganizationAccountAccessRole` trust relationship.

Enumerating Organizations from any account in the org reveals the full account inventory, the OU topology, the guardrails (SCPs) that constrain principals, which services have trusted access, and which member accounts act as delegated administrators for security tooling (GuardDuty, Security Hub, Config, IAM Access Analyzer, etc.). This information is the map an assessor uses to plan lateral movement (CSTG-AWS-ORGANIZATIONS-LATERAL), to find privilege-escalation seams (CSTG-AWS-ORGANIZATIONS-PRIVESC), and to understand which guardrails would (or would not) stop an attack.

Crucially, **most read-only Organizations API calls only succeed from the management account or from an account designated as a delegated administrator for Organizations**. Member accounts generally cannot enumerate the org. The presence or absence of these permissions is itself a strong signal about where in the org a compromised principal sits.

## Prerequisites

- Valid credentials for a principal in an AWS account that is part of an organization.
- For full read visibility: credentials in the **management account** or in an account registered as a **delegated administrator** for `organizations.amazonaws.com`. From a plain member account, almost all `organizations:*` Describe/List calls return `AccessDeniedException` regardless of the principal's IAM policy.
- The listed read-only permissions. A purpose-built read-only audit role (or the AWS managed `AWSOrganizationsReadOnlyAccess` policy) is sufficient.

## Enumeration

### Confirm org membership and identify the management account

The fastest orientation step is `DescribeOrganization`. Notably, **this call succeeds from any member account** and reveals the organization ID, the feature set (`ALL` vs `CONSOLIDATED_BILLING`), and — critically — the **management account ID and email**:

```bash
aws organizations describe-organization
```

```json
{
  "Organization": {
    "Id": "o-exampleorgid",
    "MasterAccountId": "111111111111",
    "MasterAccountEmail": "billing@example.com",
    "FeatureSet": "ALL",
    "AvailablePolicyTypes": [
      { "Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED" }
    ]
  }
}
```

`FeatureSet: ALL` means SCPs and the full policy machinery are available; `CONSOLIDATED_BILLING` means only billing is consolidated and SCPs cannot be used. The `MasterAccountId` is the highest-value lateral-movement target in the org (see CSTG-AWS-ORGANIZATIONS-LATERAL).

Identify the current account and caller for context:

```bash
aws sts get-caller-identity
```

If `Account` equals `MasterAccountId`, the caller is in the management account.

### Inventory all member accounts

```bash
aws organizations list-accounts
aws organizations describe-account --account-id 222222222222
```

`ListAccounts` returns every account's ID, ARN, name, email, join method/date, and status. Account emails frequently leak naming conventions, team ownership, and environment (e.g. `aws-prod-payments@…`, `security-tooling@…`), which directly informs targeting.

### Map the OU hierarchy

```bash
# Find the root(s)
aws organizations list-roots

# Walk down from a parent (root or OU)
aws organizations list-organizational-units-for-parent --parent-id r-exampl
aws organizations list-accounts-for-parent --parent-id ou-exampl-12345678
aws organizations list-parents --child-id 222222222222
```

Recursively descending from the root reconstructs the full tree. The hierarchy matters because SCPs are inherited down the tree — an account's effective guardrails are the intersection of every SCP from the root to the account.

### Enumerate policies (SCPs and others)

```bash
# List all SCPs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# Read a policy document
aws organizations describe-policy --policy-id p-examplepolicyid

# What is each policy attached to?
aws organizations list-targets-for-policy --policy-id p-examplepolicyid

# What policies apply directly to a given target?
aws organizations list-policies-for-target \
  --target-id 222222222222 --filter SERVICE_CONTROL_POLICY
```

Other policy types worth enumerating with the same calls (changing `--filter`): `TAG_POLICY`, `BACKUP_POLICY`, `AISERVICES_OPT_OUT_POLICY`, and the newer `RESOURCE_CONTROL_POLICY` (RCP) and `DECLARATIVE_POLICY_EC2`. The default `FullAWSAccess` SCP (`p-FullAWSAccess`) allows everything; if it is the only attached SCP, **there are effectively no guardrails**.

Reading SCP documents tells the assessor exactly which actions are denied org-wide — for example a `Deny` on `cloudtrail:StopLogging`, `guardduty:DeleteDetector`, or `iam:*` outside a Region. Gaps in these guardrails are the seams exploited elsewhere in this guide.

### Enumerate trusted services and delegated administrators

```bash
# Which AWS services have organization-wide trusted access enabled?
aws organizations list-aws-service-access-for-organization

# Which member accounts are delegated administrators (org-wide)?
aws organizations list-delegated-administrators

# What is a given account delegated for?
aws organizations list-delegated-services-for-account --account-id 333333333333
```

Each service also exposes its own view of delegated administration, which can be cross-checked from the relevant account, e.g.:

```bash
aws guardduty list-organization-admin-accounts
aws securityhub list-organization-admin-accounts
aws accessanalyzer get-account-name 2>/dev/null
aws config describe-organization-config-rules 2>/dev/null
```

Delegated-administrator accounts are high value: they often hold org-wide read (and sometimes write) access to security services, and compromising one can blind or reconfigure org-wide detection.

### Discover the cross-account access role

When Organizations creates a member account, it provisions a role (default name `OrganizationAccountAccessRole`) that trusts the management account and grants `AdministratorAccess`. This is not enumerable through the Organizations API, but its existence is implied. From the management account, test assumption directly (see CSTG-AWS-ORGANIZATIONS-LATERAL):

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/OrganizationAccountAccessRole \
  --role-session-name audit
```

## Misconfigurations & Findings

- **Org enumerable from a member account beyond `DescribeOrganization`.** Indicates the account is a delegated administrator for Organizations or that overly broad trust exists; expands an attacker's reconnaissance dramatically.
- **Only `FullAWSAccess` SCP attached.** No guardrails — any compromised principal's IAM permissions are unconstrained by the org.
- **SCPs that do not protect security/audit services.** Missing `Deny` on actions like `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:Delete*`, `config:Delete*`, `securityhub:Disable*` means detection can be disabled per-account.
- **Sensitive account emails / naming exposed** via `ListAccounts` (predictable, role-based mailboxes that aid social engineering or credential targeting).
- **Many trusted services + delegated admins concentrated in one member account**, creating a single high-value blast-radius target.
- **`CONSOLIDATED_BILLING` feature set**, which precludes SCPs entirely.
- **Management account used for workloads.** The management account is not constrained by SCPs and should be empty of workloads; running applications there is a finding in itself.

## Detection & Logging

All Organizations API calls are recorded in **CloudTrail in the management account** (Organizations is a global service; its events appear in `us-east-1`). Relevant read events: `DescribeOrganization`, `ListAccounts`, `ListRoots`, `ListPolicies`, `DescribePolicy`, `ListTargetsForPolicy`, `ListDelegatedAdministrators`, `ListAWSServiceAccessForOrganization`.

Detection guidance:

- Enumeration appears as a burst of `organizations:List*`/`organizations:Describe*` events from a single principal, especially recursive `ListOrganizationalUnitsForParent`/`ListAccountsForParent` walks.
- `DescribeOrganization` from a member account is benign and common, but a member-account principal succeeding at `ListAccounts` or `ListPolicies` indicates delegated-admin status worth validating.
- Use an organization trail (CloudTrail configured at the org level) so member-account activity is centralized and tamper-resistant; alert on read activity from unexpected principals or from outside expected automation roles.

## Remediation & Hardening

- Restrict `organizations:*` read APIs to a small set of audit/automation roles; deny them broadly via IAM and confirm no member account needs them.
- Keep the management account free of workloads, IAM users, and standing credentials; access it only via federated, short-lived, MFA-protected sessions.
- Attach restrictive SCPs (not just `FullAWSAccess`) that explicitly deny tampering with logging, detection, and guardrails — see the SCP examples in CSTG-AWS-ORGANIZATIONS-PERSIST and CSTG-AWS-ORGANIZATIONS-PRIVESC.
- Minimize the number of delegated administrators and trusted services to only those required.
- Use an **organization CloudTrail** and centralize logs in a dedicated, access-restricted log-archive account.
- Avoid embedding sensitive information in account names/emails.

## Tools

- AWS CLI (`aws organizations`, `aws sts`) and AWS SDKs for scripted enumeration.
- Cloud security posture scanners that ingest the org tree and SCPs to flag missing guardrails.
- Graph-based IAM analysis tooling that models trust relationships and cross-account paths across the org.

## References

- AWS Organizations API Reference — https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html
- AWS Organizations User Guide — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
- Service Control Policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- Trusted access for AWS services — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html
- hackingthe.cloud — AWS enumeration techniques — https://hackingthe.cloud/aws/enumeration/enum_iam_user_role_via_assumerolepolicy/
