---
cstg_id: CSTG-AWS-CODEPIPELINE-ENUM
title: "AWS Codepipeline - Enumeration"
provider: aws
service: codepipeline
phase: services
required_access: read-only-audit
required_permissions:
  - codepipeline:ListPipelines
  - codepipeline:GetPipeline
  - codepipeline:GetPipelineState
  - codepipeline:ListPipelineExecutions
  - codepipeline:GetPipelineExecution
  - codepipeline:ListActionExecutions
  - codepipeline:ListWebhooks
  - codepipeline:ListTagsForResource
  - codepipeline:ListActionTypes
  - codestar-connections:ListConnections
  - codestar-connections:GetConnection
  - codestar-connections:ListHosts
tools:
  - AWS CLI
  - AWS SDK
  - cloud-permission enumeration tooling
references:
  - https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/concepts.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/security-best-practices.html
  - https://docs.aws.amazon.com/dtconsole/latest/userguide/connections.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
license: CC BY-SA 4.0
---

## Summary

AWS CodePipeline is a managed continuous-delivery service that models software
release as a sequence of **stages**, each containing one or more **actions**
(source, build, test, approval, deploy, invoke). Pipelines orchestrate other
services - CodeCommit, GitHub/Bitbucket via CodeStar Connections, S3, CodeBuild,
CodeDeploy, ECS, CloudFormation, Lambda, Step Functions and more - and pass
**artifacts** between stages through an **artifact store** (an S3 bucket,
optionally encrypted with a KMS key).

From a testing perspective, CodePipeline is high value because it sits at the
center of an organization's deployment supply chain:

- Each pipeline assumes a **service role** that frequently carries broad
  permissions (deploy to production, pass roles, write to S3, update
  CloudFormation stacks). The pipeline is therefore a *role-pivot* surface.
- Actions reference **action service roles** and **deploy targets** that may be
  more privileged than any human identity.
- Source actions resolve to repositories and connections that can expose source
  code, secrets, and the trust path back into the cloud account.
- Artifact stores and **action configuration** (environment variables, build
  spec overrides, parameter overrides) routinely leak credentials and
  configuration.

This page covers **read-only enumeration** of CodePipeline: discovering
pipelines, mapping their structure, resolving the roles and targets they
touch, reading their execution history, and harvesting configuration and
artifact references. No state-changing calls are made. Findings here feed the
sibling pages
[AWS CodePipeline - Privilege Escalation](../03-privilege-escalation/aws-codepipeline-privesc.md)
and
[AWS CodePipeline - Persistence](../06-persistence/aws-codepipeline-persistence.md).

## Prerequisites

- Valid credentials for the target account (any principal) with the
  `codepipeline:List*`/`Get*` read actions listed above. Most read enumeration
  is covered by the AWS managed policy `AWSCodePipeline_ReadOnlyAccess` or
  `ReadOnlyAccess`/`SecurityAudit`.
- To resolve third-party source providers, the
  `codestar-connections:*`/`codeconnections:*` read actions are required.
- Region awareness: CodePipeline is **regional**. Pipelines exist independently
  per region and must be enumerated in each region in scope.
- To fully resolve roles, deploy targets, and artifact buckets, complementary
  read access to IAM, S3, KMS, CodeBuild, CloudFormation, and Lambda is useful
  (cross-reference the corresponding service enumeration pages).

## Enumeration

### 1. List pipelines per region

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $region =="
  aws codepipeline list-pipelines --region "$region" \
    --query 'pipelines[].{name:name,version:version,updated:updated}' --output table
done
```

Raw API: `POST /` with `X-Amz-Target: CodePipeline_20150709.ListPipelines`.

### 2. Retrieve the full pipeline definition

`GetPipeline` returns the complete declarative structure: stages, actions,
action `configuration` blocks, the service role ARN, and the artifact store(s).

```bash
aws codepipeline get-pipeline --name <pipeline-name> --region <region> > pipeline.json

# Service role the pipeline assumes
jq -r '.pipeline.roleArn' pipeline.json

# Artifact store(s) - S3 bucket and optional KMS key
jq '.pipeline.artifactStore, .pipeline.artifactStores' pipeline.json

# Every action, its provider, owner, and per-action roleArn (if any)
jq -r '.pipeline.stages[] | .name as $s | .actions[]
  | "\($s)\t\(.actionTypeId.category)\t\(.actionTypeId.owner)/\(.actionTypeId.provider)\t\(.roleArn // "-")"' \
  pipeline.json

# Full action configuration - inspect for inline secrets, project names,
# CloudFormation params, environment variable overrides, repos, branches
jq '.pipeline.stages[].actions[] | {name:.name, provider:.actionTypeId.provider, config:.configuration}' \
  pipeline.json
```

Key fields to record from each action `configuration`:

- **Source actions**: `RepositoryName`/`FullRepositoryId`, `BranchName`,
  `ConnectionArn` (CodeStar/CodeConnections), `S3Bucket`/`S3ObjectKey`,
  `PollForSourceChanges`.
- **CodeBuild actions**: `ProjectName`, `EnvironmentVariables` (often inline,
  including `PLAINTEXT` secrets), `PrimarySource`.
- **CloudFormation actions**: `StackName`, `RoleArn` (deploy role passed to CFN),
  `TemplatePath`, `ParameterOverrides`, `ActionMode` (CREATE_UPDATE,
  REPLACE_ON_FAILURE, etc.), `Capabilities` (notably
  `CAPABILITY_NAMED_IAM`/`CAPABILITY_IAM`).
- **CodeDeploy / ECS / S3 deploy actions**: target application, deployment
  group, cluster/service, destination bucket.
- **Lambda / StepFunctions invoke actions**: `FunctionName`, `UserParameters`,
  `StateMachineArn`.
- **Manual approval actions**: SNS topic, external URL.

### 3. Pipeline state and structure-at-a-glance

```bash
aws codepipeline get-pipeline-state --name <pipeline-name> --region <region>
```

`GetPipelineState` shows the current status of each stage/action, the latest
execution IDs, transition enable/disable state, and inbound execution
information. Disabled transitions and recently failed stages are useful
operational context.

### 4. Execution history

Execution history reveals who triggered runs, what artifacts/revisions flowed
through, and whether sensitive parameters appear in execution metadata.

```bash
aws codepipeline list-pipeline-executions --pipeline-name <name> --region <region>

aws codepipeline get-pipeline-execution \
  --pipeline-name <name> --pipeline-execution-id <id> --region <region>

# Per-action execution detail: inputs/outputs, the entity that started it,
# external execution URLs, and error details
aws codepipeline list-action-executions \
  --pipeline-name <name> --region <region> \
  --query 'actionExecutionDetails[].{stage:stageName,action:actionName,status:status,
           started:startTime,entity:input.actionTypeId.provider}'
```

`list-action-executions` `output`/`input` blocks frequently include S3 artifact
locations, resolved configuration, and commit IDs.

### 5. Webhooks and source triggers

Webhooks expose externally reachable trigger endpoints and, importantly, the
shared secret/auth configuration.

```bash
aws codepipeline list-webhooks --region <region> \
  --query 'webhooks[].{name:definition.name,target:definition.targetPipeline,
           auth:definition.authentication,url:url}'
```

Record the webhook `url`, `authentication` mode (`GITHUB_HMAC`, `IP`,
`UNAUTHENTICATED`), and `authenticationConfiguration` (allowed IP ranges or
secret-token presence). `UNAUTHENTICATED` webhooks are a notable finding.

### 6. CodeStar / CodeConnections source connections

```bash
# Older API namespace
aws codestar-connections list-connections --region <region>
aws codestar-connections get-connection --connection-arn <arn> --region <region>
aws codestar-connections list-hosts --region <region>

# Newer namespace (same backend)
aws codeconnections list-connections --region <region>
```

Record `ProviderType` (GitHub, GitHubEnterprise, Bitbucket, GitLab),
`ConnectionStatus` (`AVAILABLE` connections are live trust into external SCM),
and the host configuration for self-managed providers.

### 7. Tags, custom action types, and notifications

```bash
aws codepipeline list-tags-for-resource --resource-arn <pipeline-arn> --region <region>
aws codepipeline list-action-types --region <region>            # incl. Custom owner actions
aws codestar-notifications list-notification-rules --region <region>
```

Custom action types (`owner: Custom`) point at a job worker / Lambda that polls
for jobs and may run with elevated privileges.

### 8. Resolve the roles and targets

For every `roleArn` discovered (pipeline service role plus per-action and
CloudFormation deploy roles), pull the trust policy and attached permissions:

```bash
aws iam get-role --role-name <role>
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
aws iam get-role-policy --role-name <role> --policy-name <inline>
```

Build a graph: *pipeline -> service role -> {iam:PassRole targets, deploy
targets, artifact bucket, KMS key}*. This graph is the input to the
privilege-escalation analysis.

## Misconfigurations & Findings

- **Over-privileged service role.** Pipeline service roles attached to
  `AdministratorAccess`, broad `iam:PassRole` with `Resource: *`, or wildcard
  CloudFormation/Lambda update rights. Anyone who can influence the pipeline
  inherits this power.
- **Plaintext secrets in action configuration.** CodeBuild
  `EnvironmentVariables` of type `PLAINTEXT`, CloudFormation `ParameterOverrides`,
  or `UserParameters` containing API keys, tokens, or passwords. These are
  returned by unprivileged `GetPipeline`.
- **Unencrypted or shared artifact store.** Artifact S3 bucket with no
  customer-managed KMS key, public/over-broad bucket policy, or cross-account
  access. Artifacts often contain built secrets and source.
- **Unauthenticated or weakly authenticated webhooks** (`UNAUTHENTICATED`, or
  `IP` filter with overly broad CIDR), allowing untrusted parties to trigger
  releases.
- **Stale `AVAILABLE` source connections** to external SCM that are no longer
  used but still grant the pipeline access to repositories.
- **Polling source actions** (`PollForSourceChanges: true`) on mutable branches,
  enabling source-substitution attacks.
- **Permissive `GetPipeline` access** granted broadly, exposing the entire
  deployment topology and embedded configuration to low-privilege principals.
- **Custom action job workers** running with credentials broader than required.
- **CloudFormation actions using `CAPABILITY_NAMED_IAM`** with a deploy role
  that can create arbitrary IAM resources.

## Detection & Logging

CodePipeline management activity is recorded in **CloudTrail** as a management
event source (`codepipeline.amazonaws.com`). Read-only enumeration generates
events such as:

- `ListPipelines`, `GetPipeline`, `GetPipelineState`,
  `ListPipelineExecutions`, `GetPipelineExecution`, `ListActionExecutions`
- `ListWebhooks`, `ListTagsForResource`, `ListActionTypes`
- `codestar-connections` / `codeconnections`: `ListConnections`,
  `GetConnection`, `ListHosts`

These are read events; by default CloudTrail records management read events but
many trails are configured to log write events only. Defenders should ensure
management read events are captured for at least one trail.

Useful detection signals:

- A burst of `GetPipeline` across many pipelines/regions from a single
  principal (topology sweep).
- `GetPipeline` from a principal that never edits or runs pipelines.
- `codestar-connections:GetConnection`/`UseConnection` from unexpected
  identities.

## Remediation & Hardening

- Scope read access: avoid granting `codepipeline:GetPipeline` broadly, since it
  exposes embedded configuration. Use `AWSCodePipeline_ReadOnlyAccess` only
  where needed.
- Never place secrets in action configuration. Reference Secrets Manager / SSM
  Parameter Store and inject via the build environment as `SECRETS_MANAGER` /
  `PARAMETER_STORE` typed variables.
- Encrypt artifact stores with a customer-managed KMS key and apply a least-
  privilege key policy and bucket policy; block public access.
- Apply least privilege to pipeline service roles and per-action roles; scope
  `iam:PassRole` to specific role ARNs with a `PassedToService` condition.
- Authenticate webhooks (`GITHUB_HMAC` with a strong secret, or `IP` filtering
  with tight CIDRs); remove unauthenticated webhooks.
- Audit and remove unused CodeStar/CodeConnections connections.
- Enable CloudTrail management-event logging (read + write) and route
  CodePipeline/CodeConnections events to detection.

## Tools

- **AWS CLI** (`aws codepipeline`, `aws codestar-connections`,
  `aws codeconnections`) and the AWS SDKs.
- General cloud IAM/permission enumeration and graphing tooling for resolving
  roles, `PassRole` edges, and deploy targets.

## References

- AWS CodePipeline API Reference -
  https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
- CodePipeline concepts (stages, actions, artifacts) -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/concepts.html
- CodePipeline IAM and security -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
- CodePipeline security best practices -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/security-best-practices.html
- CodeStar / CodeConnections connections -
  https://docs.aws.amazon.com/dtconsole/latest/userguide/connections.html
- AWS IAM privilege escalation techniques -
  https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
