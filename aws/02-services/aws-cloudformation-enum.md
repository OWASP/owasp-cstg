---
cstg_id: CSTG-AWS-CLOUDFORMATION-ENUM
title: "AWS Cloudformation - Enumeration"
provider: aws
service: cloudformation
phase: services
required_access: read-only-audit
required_permissions:
  - cloudformation:ListStacks
  - cloudformation:DescribeStacks
  - cloudformation:DescribeStackResources
  - cloudformation:DescribeStackResource
  - cloudformation:ListStackResources
  - cloudformation:GetTemplate
  - cloudformation:GetTemplateSummary
  - cloudformation:ListStackSets
  - cloudformation:DescribeStackSet
  - cloudformation:ListStackInstances
  - cloudformation:DescribeStackEvents
  - cloudformation:ListExports
  - cloudformation:ListImports
  - cloudformation:ListChangeSets
  - cloudformation:DescribeChangeSet
  - cloudformation:DescribeStackDriftDetectionStatus
  - cloudformation:DetectStackDrift
tools:
  - awscli
  - pacu
  - cloudfox
  - prowler
  - scoutsuite
references:
  - "https://docs.aws.amazon.com/cli/latest/reference/cloudformation/"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html"
  - "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html"
  - "https://hackingthe.cloud/aws/enumeration/loot/"
  - "https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/"
license: CC BY-SA 4.0
---

## Summary

AWS CloudFormation is the native infrastructure-as-code (IaC) service for AWS. It provisions and manages collections of resources, called **stacks**, from declarative JSON or YAML **templates**. Because a single template can describe IAM roles, security groups, Lambda functions, databases, networking, and arbitrary other resources, CloudFormation occupies a uniquely powerful position: it is both a comprehensive inventory of how an account is built and a deployment engine that frequently runs with highly privileged credentials.

From an assessment perspective, CloudFormation is one of the most valuable enumeration targets in any AWS account. The objective of the enumeration phase is to:

- Recover the full templates and parameters of every stack to understand the account's architecture and trust relationships.
- Harvest secrets that developers commonly leave in template parameters, outputs, mappings, and resource metadata.
- Identify the **service role** (or "stack role") each stack uses, since that role's permissions become an attack surface for privilege escalation (see [Privilege Escalation](../03-privilege-escalation/aws-cloudformation-privesc.md)).
- Map StackSets and their cross-account deployment trust, which can pivot into other accounts in an organization.
- Discover deployment artifacts, S3 template buckets, and change sets that reveal intended and pending changes.

Templates are effectively a blueprint of the environment. Enumerating them often yields more architectural insight in minutes than weeks of per-service crawling.

## Prerequisites

This page assumes read-only, authenticated access to the target account with at least the CloudFormation describe/get/list permissions listed in the frontmatter. The `ReadOnlyAccess` and `SecurityAudit` AWS managed policies both grant the necessary actions. Note that the most sensitive actions are:

- `cloudformation:GetTemplate` and `cloudformation:GetTemplateSummary` — return the raw template body and parameter definitions.
- `cloudformation:DescribeStacks` — returns parameter **values** and output **values**, which frequently contain secrets.

A principal with only `ListStacks` but not `GetTemplate`/`DescribeStacks` can still build a useful inventory of stack names and statuses. Where the audit role also has `s3:GetObject` on a template-staging bucket, templates that exceed the inline API size limit can be retrieved directly from S3.

## Enumeration

### List and describe stacks

```bash
# Enumerate every stack and its current status, including deleted-but-retained metadata
aws cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE ROLLBACK_COMPLETE UPDATE_ROLLBACK_COMPLETE IMPORT_COMPLETE \
  --region us-east-1

# Full details: parameters, outputs, capabilities, tags, and — critically — RoleARN (the stack service role)
aws cloudformation describe-stacks --region us-east-1

# Target a single stack
aws cloudformation describe-stacks --stack-name prod-iam --region us-east-1
```

`describe-stacks` is the highest-value single call. The `Parameters` and `Outputs` arrays routinely expose database passwords, API keys, AMI IDs, account IDs, and the ARNs of roles the stack created. The `RoleARN` field names the service role used to deploy the stack.

### Retrieve templates

```bash
# Get the original template body (JSON or YAML)
aws cloudformation get-template \
  --stack-name prod-iam \
  --template-stage Original \
  --region us-east-1

# Get the processed template (after transforms/macros are expanded)
aws cloudformation get-template \
  --stack-name prod-iam \
  --template-stage Processed \
  --region us-east-1

# Summarize a template that has not yet been deployed (parameters, capabilities, resource types)
aws cloudformation get-template-summary --stack-name prod-iam --region us-east-1
```

Loop over all stacks to dump every template at once:

```bash
for s in $(aws cloudformation list-stacks \
  --query 'StackSummaries[?StackStatus!=`DELETE_COMPLETE`].StackName' \
  --output text --region us-east-1); do
  echo "===== $s ====="
  aws cloudformation get-template --stack-name "$s" \
    --query 'TemplateBody' --output text --region us-east-1
done
```

### Enumerate resources within stacks

```bash
# List logical-to-physical resource mappings (find the real resource IDs a stack created)
aws cloudformation list-stack-resources --stack-name prod-network --region us-east-1

# Detailed resource info including resource-level metadata
aws cloudformation describe-stack-resources --stack-name prod-network --region us-east-1

# Single resource detail
aws cloudformation describe-stack-resource \
  --stack-name prod-network --logical-resource-id AppSecurityGroup --region us-east-1
```

### Events, change sets, and drift

```bash
# Deployment history and error messages (often leak resource names and reasons)
aws cloudformation describe-stack-events --stack-name prod-iam --region us-east-1

# Pending change sets reveal intended, not-yet-applied changes
aws cloudformation list-change-sets --stack-name prod-iam --region us-east-1
aws cloudformation describe-change-set \
  --change-set-name <name> --stack-name prod-iam --region us-east-1

# Drift detection reveals out-of-band manual changes (and the real current config)
aws cloudformation detect-stack-drift --stack-name prod-iam --region us-east-1
aws cloudformation describe-stack-resource-drifts --stack-name prod-iam --region us-east-1
```

### Exports and cross-stack references

```bash
# Exported values shared between stacks (often ARNs, subnet IDs, role names)
aws cloudformation list-exports --region us-east-1

# Which stacks import a given export
aws cloudformation list-imports --export-name SharedVpcId --region us-east-1
```

### StackSets (cross-account / multi-region)

```bash
# StackSets deploy a template to many accounts/regions; high value for org-wide pivoting
aws cloudformation list-stack-sets --region us-east-1
aws cloudformation describe-stack-set --stack-set-name org-baseline --region us-east-1

# Where (which accounts/regions) the set is deployed
aws cloudformation list-stack-instances --stack-set-name org-baseline --region us-east-1
```

`describe-stack-set` reveals the **permission model** (`SELF_MANAGED` vs `SERVICE_MANAGED`), the administration role, and the execution role name used in target accounts — key facts for cross-account analysis.

### Region sweep

CloudFormation is regional. Always iterate over every enabled region; production stacks are frequently isolated in non-default regions.

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "## region $r"
  aws cloudformation list-stacks --region "$r" \
    --query 'StackSummaries[?StackStatus!=`DELETE_COMPLETE`].[StackName,StackStatus]' \
    --output text
done
```

### Raw API

The underlying calls are standard signed requests to `cloudformation.<region>.amazonaws.com` using the `DescribeStacks`, `GetTemplate`, `ListStackResources`, and `ListStackSets` actions (Query/JSON protocol). Any signed HTTP client can issue these directly when CLI tooling is unavailable.

## Misconfigurations & Findings

- **Secrets in parameters and outputs.** Plaintext passwords, tokens, and keys stored as stack parameters (without `NoEcho`) or surfaced as outputs are readable by anyone with `DescribeStacks`. Even with `NoEcho`, secrets may still appear in the original template defaults, mappings, or `UserData`.
- **Secrets baked into templates.** Hardcoded credentials in `Resources`, `Mappings`, `Metadata`, or EC2 `UserData` blocks are recoverable via `GetTemplate` and persist in the stack indefinitely.
- **Overly permissive service roles.** A `RoleARN` pointing to a role with `AdministratorAccess` (or broad `iam:*`) means anyone able to update or create stacks with that role inherits those permissions. Enumerate the role's policies to confirm.
- **Templates stored in world-readable or loosely-scoped S3 buckets.** Staging buckets for large templates often hold full architecture blueprints and are sometimes public or broadly readable.
- **Cross-account StackSet trust.** A `SERVICE_MANAGED` StackSet or a self-managed set with an execution role assumable from the management account exposes a deployment path into many member accounts.
- **Stale change sets.** Pending change sets can disclose planned credential rotations, new IAM grants, or new resources before they are deployed.
- **`CAPABILITY_NAMED_IAM` / `CAPABILITY_AUTO_EXPAND` stacks.** Their presence indicates the stack creates IAM resources or expands macros — both are privilege-relevant and worth deeper review.
- **Termination protection and deletion policies.** `DeletionPolicy: Retain` resources survive stack deletion; orphaned retained resources (KMS keys, S3 buckets, snapshots) are common loot.

## Exploitation

Enumeration itself is read-only, but the recovered data feeds directly into exploitation:

1. **Harvest credentials.** Parse every template body and `describe-stacks` output for high-entropy strings, `Password`, `Secret`, `Token`, `Key`, and connection-string patterns. Validate any AWS keys found with `aws sts get-caller-identity`.

```bash
aws cloudformation describe-stacks --region us-east-1 \
  --query 'Stacks[].{Name:StackName,Params:Parameters,Outputs:Outputs}' \
  | grep -iE 'pass|secret|token|key|cred'
```

2. **Map the service role.** For each `RoleARN`, enumerate its attached and inline policies; a permissive deploy role is a privilege-escalation primitive covered in [CloudFormation Privilege Escalation](../03-privilege-escalation/aws-cloudformation-privesc.md).

3. **Reconstruct trust paths.** Use recovered IAM resource definitions and `AssumeRole` policy documents in templates to map which principals can pivot where.

4. **Identify pivot resources.** Physical resource IDs from `list-stack-resources` point you to the specific EC2 instances, Lambda functions, RDS databases, and roles to target next.

## Detection & Logging

All CloudFormation control-plane calls are recorded in **CloudTrail** as management events under the `cloudformation.amazonaws.com` event source. Relevant read events include `DescribeStacks`, `GetTemplate`, `GetTemplateSummary`, `ListStacks`, `ListStackResources`, `DescribeStackResources`, `ListStackSets`, and `ListExports`.

- Read-only calls (`Describe*`, `Get*`, `List*`) are logged but, by default, are not data events — they appear in the standard management trail.
- A burst of `GetTemplate` / `DescribeStacks` across many stacks and regions from a single principal in a short window is a strong enumeration signal. Detect via Athena/CloudTrail Lake queries grouping by `userIdentity.arn` and counting distinct `requestParameters.stackName`.
- `sourceIPAddress` outside expected CI/CD ranges, or an unusual `userAgent` (e.g., scripting SDKs versus the deploy pipeline's agent), helps distinguish operators from attackers.
- GuardDuty does not have a CloudFormation-specific finding type, but credential exfiltration that follows (e.g., recovered keys used from a new ASN) can surface as `UnauthorizedAccess`/`CredentialAccess` findings.

Example CloudTrail Lake query to surface mass template reads:

```sql
SELECT userIdentity.arn, COUNT(*) AS calls,
       COUNT(DISTINCT element_at(requestParameters,'stackName')) AS stacks
FROM <event_data_store>
WHERE eventSource = 'cloudformation.amazonaws.com'
  AND eventName IN ('GetTemplate','DescribeStacks','GetTemplateSummary')
  AND eventTime > timestamp '2026-01-01 00:00:00'
GROUP BY userIdentity.arn
ORDER BY stacks DESC;
```

## Remediation & Hardening

- **Never store secrets in templates, parameters, or outputs.** Use AWS Secrets Manager or SSM Parameter Store SecureString and reference them dynamically (`{{resolve:secretsmanager:...}}`); ensure parameters carrying secrets are marked `NoEcho: true` as a defense-in-depth minimum.
- **Scope read access.** Treat `cloudformation:GetTemplate` and `DescribeStacks` as sensitive. Restrict broad audit roles, and consider resource-level conditions limiting which stacks a principal can read.
- **Least-privilege service roles.** Give each stack a dedicated, narrowly scoped service role rather than a shared administrator role; pass it explicitly so stack operations cannot inherit the caller's broad permissions.
- **Lock down template buckets.** Apply Block Public Access, bucket policies, and encryption to S3 buckets used for template staging.
- **Restrict StackSet trust.** Constrain administration/execution roles and the accounts a StackSet may target; prefer `SERVICE_MANAGED` with explicit OUs over broadly assumable self-managed roles.
- **Monitor and alert** on anomalous bulk `GetTemplate`/`DescribeStacks` patterns and on reads of IAM-creating stacks.
- **Enable termination protection** on critical stacks and audit `DeletionPolicy: Retain` resources for orphaned, unmonitored assets.

## Tools

- **awscli** — native enumeration of stacks, templates, resources, exports, and StackSets.
- **pacu** — modules for CloudFormation enumeration and template/secret extraction across regions.
- **cloudfox** — surfaces interesting CloudFormation outputs and resources during account triage.
- **prowler** / **scoutsuite** — flag CloudFormation misconfigurations such as plaintext secrets and permissive roles in audit reports.

## References

- AWS CLI CloudFormation command reference — https://docs.aws.amazon.com/cli/latest/reference/cloudformation/
- AWS CloudFormation User Guide — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html
- CloudFormation service roles — https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html
- hackingthe.cloud — AWS enumeration / loot — https://hackingthe.cloud/aws/enumeration/loot/
- Rhino Security Labs — Cloud Malware: CloudFormation injection — https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/
