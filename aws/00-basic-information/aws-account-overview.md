---
cstg_id: CSTG-AWS-ACCOUNT-OVERVIEW
title: "AWS Account - Overview"
provider: aws
service: account
phase: basic-information
required_access: read-only-audit
required_permissions:
  - sts:GetCallerIdentity
  - iam:GetAccountSummary
  - iam:ListAccountAliases
  - organizations:DescribeOrganization
  - account:GetContactInformation
references:
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
  - "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html"
  - "https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
  - "https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"
license: CC BY-SA 4.0
---

## Summary

An AWS account is the fundamental container for resources, identities, and billing in Amazon Web Services. Every resource (compute instances, storage buckets, databases, network constructs) is owned by exactly one account, and every API call is authenticated against a principal that resolves to an account. The account is therefore the primary trust and security boundary in AWS: cross-account access is explicit and must be granted, whereas access within an account is governed by Identity and Access Management (IAM) policy evaluation.

This page provides the foundational model that the remaining AWS pages in this guide build upon: how accounts are identified, how identities and permissions are structured, how multiple accounts are organized, how requests are authenticated and authorized, and how account-level activity is logged. Understanding this model is a prerequisite for scoping an assessment, interpreting permissions, mapping trust relationships, and reasoning about privilege-escalation and lateral-movement paths.

The attacker objective at the account layer is orientation and expansion: establish which account a credential belongs to, determine the privilege level of the current principal, discover other accounts and the organization structure, identify trust relationships that permit cross-account access, and locate the highest-value identities (the root user, administrative roles, and organization management account) that, if compromised, yield control of the environment.

## Prerequisites

- A set of credentials or a foothold that resolves to an AWS principal (an IAM user's long-term access keys, temporary STS credentials for an assumed role, an instance/container/Lambda execution role, or federated SSO credentials). Some orientation is possible with essentially no permissions because `sts:GetCallerIdentity` is not gated by IAM.
- Read-only audit permissions are sufficient for the enumeration described here. The relevant permissions include `sts:GetCallerIdentity`, `iam:GetAccountSummary`, `iam:GetAccountAuthorizationDetails`, `iam:ListAccountAliases`, `organizations:Describe*`, `organizations:List*`, and `account:Get*`. The AWS-managed `SecurityAudit` and `ViewOnlyAccess` policies grant most of these.
- The AWS CLI or any SDK/HTTP client capable of SigV4-signed requests. All commands below use the AWS CLI v2 form.

## Enumeration

### Identify the current principal and account

`sts:GetCallerIdentity` returns the account ID, the principal's ARN, and the unique principal ID. It requires no specific IAM permission, so it works for almost any valid credential and is the canonical first step.

```bash
aws sts get-caller-identity
# {
#   "UserId": "AROA...:session-name",      # IAM user, or roleId:sessionName for a role
#   "Account": "123456789012",
#   "Arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name"
# }
```

The shape of the `Arn` immediately reveals the principal type:

- `arn:aws:iam::123456789012:user/<name>` - an IAM user with long-term keys.
- `arn:aws:sts::123456789012:assumed-role/<role>/<session>` - temporary credentials from `sts:AssumeRole`, `AssumeRoleWithWebIdentity`, or `AssumeRoleWithSAML`.
- `arn:aws:iam::123456789012:root` - the account root user (rare and high-value).
- A `UserId` beginning `AIDA` is an IAM user; `AROA` is a role; `AKIA`/`ASIA` are access-key-ID prefixes (`AKIA` long-term, `ASIA` temporary).

### Identify the account and its alias

```bash
aws iam list-account-aliases
aws sts get-access-key-info --access-key-id AKIAEXAMPLE   # returns the owning account for any key id
aws account get-contact-information                        # billing/contact details, often org-revealing
aws account get-region-opt-status --region ap-southeast-2  # which opt-in regions are enabled
```

The account alias (if set) is a human-readable label that frequently leaks environment or business-unit naming (for example `acme-prod`, `acme-sandbox`).

### Summarize the account's IAM posture

```bash
aws iam get-account-summary             # counts of users, roles, groups, MFA devices, policies
aws iam get-account-password-policy     # console password policy strength
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local     # customer-managed policies
aws iam get-account-authorization-details   # full dump: principals + attached/inline policies
```

`get-account-authorization-details` is the single most valuable IAM read call: it returns every user, group, role, and managed policy along with their attached and inline policy documents, enabling offline analysis of the entire account permission graph.

### Discover the organization

```bash
aws organizations describe-organization                       # is this account in an org? which is management?
aws organizations list-accounts                                # all member accounts (mgmt account only)
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-xxxx
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-xxxx
aws organizations list-delegated-administrators
```

`describe-organization` works from any member account and reveals the `MasterAccountId` / management account ID and the feature set (`ALL` enables Service Control Policies). `list-accounts` and policy reads generally succeed only from the management account or a delegated administrator.

### Enumerate enabled regions and account-wide settings

```bash
aws ec2 describe-regions --all-regions          # enabled vs. disabled regions
aws iam get-account-summary                      # see above
aws accessanalyzer list-analyzers                # external/unused access analyzers, if any
```

## Misconfigurations & Findings

- **Root user with active access keys.** The root user can perform any action and cannot be constrained by IAM policies or, historically, by Service Control Policies in the same way as other principals. Long-lived root access keys are a critical finding; root should have MFA, no access keys, and be used only for the few tasks that require it.
- **Root user without MFA.** Absence of MFA on the root user (visible indirectly via `get-account-summary` `AccountMFAEnabled`) is a high-severity finding.
- **Weak or absent password policy.** `get-account-password-policy` returning a permissive policy (short minimum length, no rotation, reuse allowed) weakens console identities.
- **Account not enrolled in an organization, or no Service Control Policies.** A standalone account, or an organization without SCPs, lacks a key preventative control layer; a compromised principal faces no organizational guardrails.
- **Over-broad principals.** `get-account-authorization-details` revealing many principals with `*:*` or `Administrator`-equivalent policies expands the blast radius of any single compromise.
- **Permissive account alias / contact leakage.** Descriptive aliases and contact information aid an attacker in targeting and social engineering.
- **Many enabled regions with no workloads.** Unused but enabled regions widen the attack surface and are common blind spots for monitoring, providing quiet locations to operate.
- **Cross-account trust without external ID or condition keys.** Roles trusting other accounts without `sts:ExternalId` or source-account conditions are exploitable; see the IAM trust-policy pages for detail.

## Exploitation

Account-level orientation is rarely an exploit in itself; it is the reconnaissance that selects the exploitation path. The typical sequence is:

1. **Resolve identity and privilege.** Run `get-caller-identity`, then `get-account-authorization-details` (or, if denied, probe individual `iam:Get*`/`List*` calls). Determine whether the current principal is privileged or whether a path to a privileged principal exists.
2. **Map the permission graph offline.** Feed the authorization details into a policy-analysis tool to find principals reachable from the current one via `iam:PassRole`, `sts:AssumeRole`, policy-attachment permissions, or credential-creation permissions. These permission-to-attack-path mappings are covered in depth on the IAM privilege-escalation page.
3. **Identify the root and management account as ultimate targets.** The account root user and the organization management account are the highest-value identities; compromise of the management account can cascade to every member account through cross-account roles such as the default `OrganizationAccountAccessRole`.
4. **Traverse cross-account trust.** Use `describe-organization` and discovered trust policies to identify roles that can be assumed across accounts, then `aws sts assume-role --role-arn <arn> --role-session-name <s>` to pivot.
5. **Operate in low-visibility regions.** Enabled-but-unused regions discovered via `describe-regions` are candidate locations for activity that is less likely to be monitored.

Detailed, permission-by-permission escalation paths live on the IAM pages; this overview provides the map those pages traverse.

## Detection & Logging

- **CloudTrail** is the authoritative record of account activity. Management events capture control-plane API calls (`sts:GetCallerIdentity`, `iam:*`, `organizations:*`, `account:*`); data events capture object-level operations (for example S3 object access) when explicitly enabled. Each event records the principal (`userIdentity`), source IP, user agent, timestamp, and request/response parameters.
- **`GetCallerIdentity` is logged but unauthenticated against IAM**, so a flood of these calls (or calls from unusual IPs/agents) can indicate credential validation by an external party.
- **`GetAccountAuthorizationDetails` and bulk `iam:List*`/`Get*` calls** in a short window are a strong reconnaissance signal; legitimate use is infrequent.
- **`organizations:Describe*`/`List*` from a member account** that does not normally perform org reads is suspicious.
- **Root user activity** should be alerted on unconditionally; CloudTrail records `userIdentity.type` of `Root`. AWS recommends a dedicated metric filter and alarm for any root sign-in or API use.
- **CloudTrail organization trails** centralize logging across all member accounts into the management account, providing a single tamper-resistant view; their absence is itself a finding.
- **GuardDuty** provides managed detections (for example `Recon:IAMUser/*`, `Stealth:IAMUser/CloudTrailLoggingDisabled`, `PenTest:IAMUser/*`, anomalous credential use) derived from CloudTrail, VPC Flow Logs, and DNS logs.
- **Disabling or modifying CloudTrail** (`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`) is a high-fidelity evasion indicator and should be alarmed.

## Remediation & Hardening

- **Lock down the root user.** Enable MFA, remove all root access keys, store the root credentials securely, and use root only for the documented tasks that require it. Consider centralized root management for organization member accounts where available.
- **Use AWS Organizations with Service Control Policies.** Enroll accounts in an organization, enable the `ALL` feature set, and apply SCPs as preventative guardrails (for example denying disabling of CloudTrail/GuardDuty, restricting regions, and protecting security tooling).
- **Apply a strong password policy** and require MFA for all human identities; prefer federated SSO over long-lived IAM user keys.
- **Enforce least privilege.** Replace `*:*` and broad administrative grants with scoped policies; use IAM Access Analyzer to identify unused access and external access, and review `get-account-authorization-details` regularly.
- **Enable organization-wide CloudTrail** with log file validation, delivery to a dedicated logging account, and SSE-KMS encryption; restrict who can modify trails.
- **Disable unused regions** and monitor all enabled regions; deploy GuardDuty across the organization.
- **Set account-level S3 Block Public Access** and other account-wide guardrails to reduce default exposure.
- **Tag and document accounts** with purpose and owner so that anomalous cross-account trust and unexpected resources are easier to spot.

## Tools

- **AWS CLI / SDKs** - native enumeration of identity, IAM, organizations, and account settings.
- **IAM policy graph analyzers** - tools that ingest `get-account-authorization-details` output to map principals and surface privilege-escalation edges.
- **Cloud security posture and enumeration suites** - automated multi-service auditors that report on root usage, MFA, password policy, SCP coverage, and region exposure.
- **IAM Access Analyzer** - native service for identifying external and unused access at the account level.

## References

- [AWS IAM identities and the account model](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS Organizations introduction](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html)
- [STS GetCallerIdentity API reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [AWS account root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)
- [ARNs and AWS service namespaces](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html)
- [CloudTrail concepts](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html)
