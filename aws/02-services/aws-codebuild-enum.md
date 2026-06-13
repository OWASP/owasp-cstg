---
cstg_id: CSTG-AWS-CODEBUILD-ENUM
title: "AWS Codebuild - Enumeration"
provider: aws
service: codebuild
phase: services
required_access: read-only-audit
required_permissions:
  - codebuild:ListProjects
  - codebuild:BatchGetProjects
  - codebuild:ListBuilds
  - codebuild:BatchGetBuilds
  - codebuild:ListBuildBatches
  - codebuild:BatchGetBuildBatches
  - codebuild:ListReportGroups
  - codebuild:BatchGetReportGroups
  - codebuild:ListSourceCredentials
  - codebuild:GetResourcePolicy
  - codebuild:ListProjectsForFleet
  - iam:GetRole
  - iam:ListRolePolicies
  - iam:GetRolePolicy
  - logs:GetLogEvents
tools:
  - AWS CLI
  - AWS SDK
  - cloud security posture / IAM enumeration tooling
references:
  - https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
  - https://docs.aws.amazon.com/codebuild/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-iam-identity-based-access-control.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/setting-up.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
license: CC BY-SA 4.0
---

## Summary

AWS CodeBuild is a fully managed continuous integration (CI) service that compiles source code, runs tests, and produces deployment-ready artifacts. Each build runs inside a managed compute container that assumes a **service role** (an IAM role) supplied at project creation time. Builds are driven by a **buildspec** — an inline or repository-resident YAML document — that executes arbitrary shell commands inside the container with the service role's credentials available through the container's instance metadata endpoint.

From an assessment perspective, CodeBuild is a high-value target for three reasons:

1. **Service roles are frequently over-privileged.** Build jobs commonly need to pull source, push artifacts to S3, push images to ECR, deploy via CloudFormation/CDK, and read secrets — so service roles accumulate broad permissions that an attacker who can influence a build inherits.
2. **Builds execute attacker-controllable code.** The buildspec, environment variables, source overrides, and source repository all influence what runs inside the privileged container. Any principal that can start or modify a build effectively obtains code execution as the service role.
3. **Secrets and credentials flow through builds.** Environment variables, Secrets Manager / SSM Parameter Store references, source credentials (GitHub/Bitbucket OAuth or PATs), and build logs frequently expose sensitive material.

This page covers read-only enumeration: discovering projects, fleets, builds, report groups, source credentials, resource policies, the network/VPC configuration, environment variables, and — most importantly — the service roles and their permissions. The goal of enumeration is to map every CodeBuild resource and identify which builds an attacker could influence and what each build's role could do. Privilege-escalation paths are covered in [aws-codebuild-privesc.md](../03-privilege-escalation/aws-codebuild-privesc.md); persistence techniques are covered in [aws-codebuild-persistence.md](../06-persistence/aws-codebuild-persistence.md).

## Prerequisites

- Read-only audit access to the target account, ideally through a role with the AWS managed `SecurityAudit` or `ReadOnlyAccess` policy, or an equivalent custom policy granting the `codebuild:List*`/`codebuild:BatchGet*`/`codebuild:Get*` actions listed in the frontmatter.
- `iam:GetRole`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, and `iam:GetPolicy*` to resolve service-role permissions (covered in depth in the IAM enumeration pages).
- `logs:*` read access to inspect build log output in CloudWatch Logs.
- CodeBuild is regional. Enumerate every enabled region; resources in one region are invisible from another.

## Enumeration

### Identify the calling identity and regions

Establish who you are and which regions to sweep before enumerating resources.

```bash
aws sts get-caller-identity
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

### List and describe projects

`ListProjects` returns project names; `BatchGetProjects` (max 100 names per call) returns the full configuration, including the service role, environment, source, artifacts, VPC, and logging settings.

```bash
# List every project in a region
aws codebuild list-projects --region us-east-1

# Pull full configuration for up to 100 projects at once
aws codebuild batch-get-projects \
  --names project-a project-b project-c \
  --region us-east-1
```

The `projects[]` objects are the richest enumeration target. Inspect each field:

- **`serviceRole`** — the IAM role assumed by builds. Resolve its permissions; this is the privilege an attacker inherits by running a build.
- **`source`** and **`secondarySources`** — `type` (CODECOMMIT, GITHUB, GITHUB_ENTERPRISE, BITBUCKET, S3, CODEPIPELINE, NO_SOURCE), `location`, `buildspec` (inline buildspec or path), and `auth`. Note whether the buildspec is inline (stored in the project) or pulled from the repo (`buildspec.yml`), since that determines who can change build commands.
- **`environment.environmentVariables`** — name/value/type triples. `PLAINTEXT` values may leak secrets directly. `PARAMETER_STORE` and `SECRETS_MANAGER` types reveal the names/ARNs of referenced secrets, which maps the role's required secret access.
- **`environment.privilegedMode`** — when `true`, the build runs Docker-in-Docker with elevated container privileges (commonly enabled to build container images).
- **`environment.image`** and **`imagePullCredentialsType`** — base image and whether a custom ECR image with role-based pull is used.
- **`vpcConfig`** — `vpcId`, `subnets`, `securityGroupIds`. A VPC-attached build can reach internal-only resources (RDS, internal load balancers, instance metadata of peer services).
- **`logsConfig`** — CloudWatch Logs group/stream and/or S3 destination for build logs (a place to read historical secrets).
- **`artifacts`** / **`secondaryArtifacts`** — output S3 location.
- **`fileSystemLocations`** — mounted EFS file systems.
- **`concurrentBuildLimit`**, **`timeoutInMinutes`**, **`queuedTimeoutInMinutes`**.

Extract the high-signal fields across all projects:

```bash
aws codebuild batch-get-projects --names $(aws codebuild list-projects --query 'projects' --output text) \
  --query 'projects[].{name:name,role:serviceRole,priv:environment.privilegedMode,srcType:source.type,buildspec:source.buildspec,vpc:vpcConfig.vpcId}' \
  --output table
```

Flag every `PLAINTEXT` environment variable for secret review:

```bash
aws codebuild batch-get-projects --names $(aws codebuild list-projects --query 'projects' --output text) \
  --query 'projects[].{name:name,env:environment.environmentVariables[?type==`PLAINTEXT`]}'
```

### Resolve service-role permissions

The service role determines blast radius. For each distinct `serviceRole` ARN, enumerate inline and attached policies.

```bash
ROLE=codebuild-myproject-service-role
aws iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument'
aws iam list-role-policies --role-name "$ROLE"
aws iam get-role-policy --role-name "$ROLE" --policy-name <inline-policy>
aws iam list-attached-role-policies --role-name "$ROLE"
aws iam get-policy-version --policy-arn <arn> --version-id <vN>
```

Confirm the trust policy lists `codebuild.amazonaws.com` as the trusted service. Look specifically for actions that enable privilege escalation when reachable from inside a build: `iam:PassRole`, `iam:*`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `s3:*`, `ecr:*`, `cloudformation:*`, `sts:AssumeRole`, `codebuild:UpdateProject`, `codebuild:StartBuild`, `lambda:UpdateFunctionCode`, and broad `*` resources.

### Enumerate builds and build batches

Historical builds reveal what ran, when, by whom, and surface log locations and resolved environment variables.

```bash
# Build IDs for a project (most recent first)
aws codebuild list-builds-for-project --project-name myproject --region us-east-1

# All build IDs in the account/region
aws codebuild list-builds --region us-east-1

# Full detail (env, phases, logs location, initiator, source version, exported env vars)
aws codebuild batch-get-builds --ids "myproject:<uuid>" --region us-east-1

# Batch builds (matrix / parallel builds)
aws codebuild list-build-batches --region us-east-1
aws codebuild batch-get-build-batches --ids <batch-id>
```

In `batch-get-builds` output, review `initiator` (who started the build), `buildBatchArn`, `resolvedSourceVersion`, `environment.environmentVariables`, `exportedEnvironmentVariables`, `logs.deepLink`/`groupName`/`streamName`, and `phases` for failure detail.

### Read build logs

Build logs frequently echo environment variables, `aws sts get-caller-identity` output, package registry tokens, and other secrets.

```bash
aws logs get-log-events \
  --log-group-name /aws/codebuild/myproject \
  --log-stream-name <streamName> \
  --region us-east-1
```

If `logsConfig` points at S3, list and read those objects instead.

### Report groups and reports

Report groups hold test and code-coverage results and may reference S3 export buckets.

```bash
aws codebuild list-report-groups --region us-east-1
aws codebuild batch-get-report-groups --report-group-arns <arn>
aws codebuild list-reports --region us-east-1
aws codebuild batch-get-reports --report-arns <arn>
```

### Source credentials

CodeBuild stores OAuth tokens / personal access tokens / username-password pairs for GitHub, GitHub Enterprise, and Bitbucket as account-level source credentials. The API does not return the secret value, but it confirms which providers are connected and which projects can pull private repositories.

```bash
aws codebuild list-source-credentials --region us-east-1
```

### Resource policies (cross-account sharing)

Report groups and projects can carry a resource-based policy that shares them across accounts. Read it to identify external principals.

```bash
aws codebuild get-resource-policy --resource-arn <project-or-reportgroup-arn>
```

### Compute fleets

Reserved-capacity fleets back projects with dedicated compute. Enumerate fleets and the projects bound to each.

```bash
aws codebuild list-fleets --region us-east-1
aws codebuild batch-get-fleets --names <fleet-name>
aws codebuild list-projects-for-fleet --fleet-arn <fleet-arn>
```

### Webhooks and triggers

If a project's source is GitHub/Bitbucket, a webhook may auto-trigger builds on repository events. Webhook configuration is returned within `batch-get-projects` under `webhook` (filter groups, branch filters, build type). A permissive `filterGroups` (for example, building on pull requests from forks) means external contributors can trigger privileged builds — a critical finding.

## Misconfigurations & Findings

- **Over-privileged service role.** The role grants `*:*`, `iam:*`, `iam:PassRole` with broad resources, or administrative access far beyond the build's needs. Any build-influence primitive becomes account takeover.
- **Repository-resident buildspec on a public/fork-accessible source.** When `source.buildspec` is a path (`buildspec.yml`) rather than inline, anyone who can push to the source branch — or open a fork PR that a webhook builds — controls the commands run as the service role.
- **Webhook builds pull-request events from forks.** A `filterGroups` configuration that builds untrusted external PRs grants unauthenticated attackers code execution as the service role. This is one of the most severe and common CodeBuild findings.
- **Secrets in plaintext environment variables.** `PLAINTEXT` env vars containing tokens, passwords, or keys are visible to anyone with `BatchGetProjects` and are written to build logs.
- **Secrets echoed into build logs.** Buildspecs that print env vars or run with shell tracing leak secrets to CloudWatch Logs / S3, readable by anyone with log access.
- **`privilegedMode` enabled unnecessarily.** Docker-in-Docker increases the container's capability and makes host/credential interaction easier.
- **VPC-attached builds in sensitive subnets.** A build with code execution and a route to internal databases or admin endpoints can pivot into the private network.
- **Cross-account resource policy to untrusted accounts.** `GetResourcePolicy` reveals external principals that may start builds or read reports.
- **Long-lived source credentials.** Stored GitHub/Bitbucket PATs with broad repo scopes that, if extracted via a build, grant access to source control.

## Detection & Logging

All CodeBuild management-plane API calls are recorded by **CloudTrail** as events from `codebuild.amazonaws.com`. Read-only enumeration generates a recognizable burst of:

- `ListProjects`, `BatchGetProjects`, `ListBuilds`, `BatchGetBuilds`, `ListBuildBatches`, `BatchGetBuildBatches`
- `ListReportGroups`, `BatchGetReportGroups`, `ListReports`, `BatchGetReports`
- `ListSourceCredentials`, `GetResourcePolicy`, `ListFleets`, `BatchGetFleets`, `ListProjectsForFleet`
- Associated IAM reads (`GetRole`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`) and `logs:GetLogEvents`

Defenders should alert on a single principal enumerating most CodeBuild read APIs across many regions in a short window, especially from an unusual principal type, source IP, or user agent. `BatchGetProjects` immediately followed by `StartBuild` or `UpdateProject` from the same principal is a strong escalation indicator. Note that `codebuild:BatchGetBuilds` does not expose the contents of `SECRETS_MANAGER`/`PARAMETER_STORE` variables, but `GetLogEvents` against build log groups can expose secrets that builds printed.

## Remediation & Hardening

- Scope each service role to least privilege; never attach `AdministratorAccess` or `*:*`. Constrain `iam:PassRole` to the specific roles the build legitimately passes, with a `iam:PassedToService` condition.
- Store all secrets in Secrets Manager or SSM Parameter Store and reference them via `SECRETS_MANAGER`/`PARAMETER_STORE` env var types; never use `PLAINTEXT` for sensitive values.
- Prefer inline, version-controlled-by-administrators buildspecs over repo-resident buildspecs for high-privilege projects, or pin the source to trusted branches only.
- For webhook-triggered builds, disable building of pull requests from forks, or require manual approval; scope `filterGroups` to trusted branches and actors.
- Disable `privilegedMode` unless Docker builds genuinely require it.
- Restrict who holds `codebuild:StartBuild`, `codebuild:StartBuildBatch`, `codebuild:UpdateProject`, and `codebuild:CreateProject`.
- Encrypt build artifacts and logs with customer-managed KMS keys and restrict read access to log destinations.
- Enable CloudTrail in all regions with log-file validation and centralized, access-controlled storage.
- Periodically audit resource policies and source credentials; rotate stored PATs and scope them minimally.

## Tools

- AWS CLI (`aws codebuild`, `aws iam`, `aws logs`, `aws sts`)
- AWS SDKs for scripted, multi-region collection
- Cloud security posture management and IAM enumeration tooling that maps service-role permissions to attack paths
- CloudTrail / log analytics for reviewing historical build activity and initiators

## References

- AWS CodeBuild User Guide — https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
- AWS CodeBuild API Reference — https://docs.aws.amazon.com/codebuild/latest/APIReference/Welcome.html
- Identity and access management for CodeBuild — https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-iam-identity-based-access-control.html
- Build specification (buildspec) reference — https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
- Setting up CodeBuild — https://docs.aws.amazon.com/codebuild/latest/userguide/setting-up.html
- HackingThe.Cloud — AWS IAM privilege escalation — https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
