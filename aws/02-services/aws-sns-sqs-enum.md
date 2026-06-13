---
cstg_id: CSTG-AWS-SNS-SQS-ENUM
title: "AWS Sns Sqs - Enumeration"
provider: aws
service: sns-sqs
phase: services
required_access: read-only-audit
required_permissions:
  - sns:ListTopics
  - sns:ListSubscriptions
  - sns:ListSubscriptionsByTopic
  - sns:GetTopicAttributes
  - sns:GetSubscriptionAttributes
  - sns:ListTagsForResource
  - sqs:ListQueues
  - sqs:GetQueueUrl
  - sqs:GetQueueAttributes
  - sqs:ListQueueTags
  - sqs:ListDeadLetterSourceQueues
tools:
  - AWS CLI
  - Pacu
  - ScoutSuite
  - Prowler
  - CloudMapper
references:
  - "https://docs.aws.amazon.com/sns/latest/dg/welcome.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/welcome.html"
  - "https://docs.aws.amazon.com/sns/latest/api/welcome.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html"
  - "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-using-identity-based-policies.html"
license: CC BY-SA 4.0
---

## Summary

Amazon Simple Notification Service (SNS) and Amazon Simple Queue Service (SQS) form the backbone of asynchronous, event-driven messaging in AWS. SNS is a publish/subscribe (pub/sub) service in which publishers send messages to a **topic** and the topic fans them out to one or more **subscriptions** (SQS queues, Lambda functions, HTTP/S endpoints, email, SMS, mobile push, Kinesis Data Firehose). SQS is a managed message queue in which producers send messages and consumers poll and delete them; queues come in **Standard** (at-least-once, best-effort ordering) and **FIFO** (exactly-once, strict ordering) flavours. The two services are frequently chained: an SNS topic fans messages out to multiple SQS queues so that several downstream consumers each receive their own copy.

From a testing perspective these services are high value because they carry **application data in transit** and sit at trust boundaries between services and accounts. Both expose **resource-based policies** (topic policies and queue policies) that are a common source of cross-account and public exposure. The attacker objective during enumeration is to inventory every topic, queue, subscription and dead-letter queue; map the message flow graph; identify which topics/queues are readable, writable or subscribable by external principals; and locate the encryption, redrive and access-policy weaknesses that the privilege-escalation and persistence phases will exploit.

This page covers read-only discovery. See [aws-sns-sqs-privesc.md](../03-privilege-escalation/aws-sns-sqs-privesc.md) for abuse paths and [aws-sns-sqs-persistence.md](../06-persistence/aws-sns-sqs-persistence.md) for durable access techniques.

## Prerequisites

- Valid credentials for the target account (an STS session, IAM user access key, or assumed role) with at minimum read/list permissions on SNS and SQS. The permission set in the frontmatter is sufficient for full passive enumeration.
- Knowledge of the regions in use. SNS and SQS are **regional** services; topics and queues created in `eu-west-1` are invisible to API calls targeting `us-east-1`. Enumeration must iterate every enabled region.
- For cross-account reconnaissance, only the target topic/queue ARN and an identity in the source account are required; resource-based policies are evaluated independently of any role in the target account.

If only unauthenticated access is available, public exposure can still sometimes be probed against a guessed or leaked ARN (see Misconfigurations), but full inventory requires the list permissions above.

## Enumeration

### Establish identity and region scope

```bash
aws sts get-caller-identity
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
```

### SNS topics

```bash
# List every topic in a region
aws sns list-topics --region us-east-1

# Iterate all regions
for r in $REGIONS; do
  echo "== $r =="
  aws sns list-topics --region "$r" --query 'Topics[].TopicArn' --output text
done

# Pull the full attribute set for a topic: includes the resource policy,
# delivery policy, effective delivery policy, KMS key, owner, subscription counts
aws sns get-topic-attributes \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --region us-east-1

# Tags often reveal environment, owner, data classification
aws sns list-tags-for-resource \
  --resource-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --region us-east-1
```

Key attributes returned by `get-topic-attributes`:

- `Policy` - the resource-based access policy (JSON). Parse this for cross-account and wildcard principals.
- `KmsMasterKeyId` - present only if server-side encryption (SSE) is enabled. Absence means messages are unencrypted at rest.
- `Owner` - the account ID owning the topic; differs from your account in shared scenarios.
- `SubscriptionsConfirmed`, `SubscriptionsPending`, `SubscriptionsDeleted` - subscription counts.
- `DeliveryPolicy` / `EffectiveDeliveryPolicy`, `FifoTopic`, `ContentBasedDeduplication`.

### SNS subscriptions

```bash
# All subscriptions in the account/region
aws sns list-subscriptions --region us-east-1

# Subscriptions for a single topic (shows endpoints and protocols)
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:111122223333:orders-events \
  --region us-east-1

# Subscription attributes: filter policy, raw delivery, redrive (DLQ),
# delivery retry policy, and the subscribing principal/owner
aws sns get-subscription-attributes \
  --subscription-arn arn:aws:sns:us-east-1:111122223333:orders-events:6b0e71bd-7e97-4d97-80ce-4a0994e55286 \
  --region us-east-1
```

The `Endpoint` and `Protocol` fields on each subscription reveal the message flow graph: which SQS queues, Lambda functions, or external HTTP/S and email endpoints receive copies of every published message. `SubscriptionRoleArn` (for Firehose) and `FilterPolicy` indicate routing logic.

### SQS queues

```bash
# List queues (optionally filter by name prefix)
aws sqs list-queues --region us-east-1
aws sqs list-queues --queue-name-prefix prod- --region us-east-1

# Resolve a queue URL by name, optionally in another account
aws sqs get-queue-url --queue-name orders-worker --region us-east-1
aws sqs get-queue-url --queue-name orders-worker \
  --queue-owner-aws-account-id 111122223333 --region us-east-1

# Full attribute set: policy, KMS key, redrive policy, message counts, ARN
aws sqs get-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --attribute-names All --region us-east-1

# Tags and dead-letter relationships
aws sqs list-queue-tags --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker --region us-east-1
aws sqs list-dead-letter-source-queues --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-dlq --region us-east-1
```

Key attributes from `get-queue-attributes`:

- `Policy` - the queue's resource-based access policy.
- `QueueArn` - needed to correlate with SNS subscription endpoints.
- `KmsMasterKeyId` / `SqsManagedSseEnabled` - encryption state.
- `RedrivePolicy` - JSON pointing at the dead-letter queue ARN and `maxReceiveCount`.
- `RedriveAllowPolicy` - controls which source queues may use this queue as a DLQ.
- `ApproximateNumberOfMessages`, `ApproximateNumberOfMessagesNotVisible`, `ApproximateNumberOfMessagesDelayed` - queue depth; non-zero values mean live data is present.
- `VisibilityTimeout`, `MessageRetentionPeriod`, `FifoQueue`, `ContentBasedDeduplication`.

### Inspecting message content (read-only but data-touching)

Reading messages is more intrusive than listing attributes because the default `ReceiveMessage` makes the message temporarily invisible to legitimate consumers for the visibility-timeout window. To minimise impact, use a short timeout and do not call `DeleteMessage`:

```bash
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/111122223333/orders-worker \
  --max-number-of-messages 1 --visibility-timeout 0 \
  --attribute-names All --message-attribute-names All \
  --region us-east-1
```

Setting `--visibility-timeout 0` returns the message without hiding it from real consumers. Treat captured payloads as evidence and check them for PII, credentials, and internal identifiers.

### Mapping the flow graph

Correlate the data: every SNS subscription whose `Protocol` is `sqs` lists the destination queue ARN as its `Endpoint`. Joining `list-subscriptions-by-topic` against `get-queue-attributes` builds a directed graph of `publisher -> topic -> queue -> consumer`, including any DLQs reached via `RedrivePolicy`. Lambda and HTTP/S subscriptions extend the graph outside the messaging services and frequently cross account or trust boundaries.

## Misconfigurations & Findings

- **Topic/queue policy open to `"Principal": "*"`.** A wildcard principal with no condition keys allows any AWS account (or, for some actions, anonymous callers) to publish, subscribe, send, or receive. This is the single most impactful messaging finding.
- **Cross-account access without a confused-deputy guard.** Policies that grant another account `sns:Publish`, `sns:Subscribe`, `sqs:SendMessage`, or `sqs:ReceiveMessage` but omit `aws:SourceAccount`, `aws:SourceArn`, or `aws:SourceOwner` conditions allow unintended principals to act, and enable confused-deputy abuse where a service in account A is tricked into writing to account B's queue.
- **`SQS:*` or `SNS:*` action wildcards** in resource policies grant management actions (e.g. `sqs:SetQueueAttributes`, `sns:SetTopicAttributes`, `AddPermission`) to external principals - this lets an attacker rewrite the policy itself.
- **Unencrypted at rest.** No `KmsMasterKeyId` and (for SQS) `SqsManagedSseEnabled=false` means messages are stored unencrypted. Sensitive payloads are exposed to anyone who gains read access.
- **Overly broad KMS key policy.** SSE is moot if the backing KMS key grants `kms:Decrypt` to broad principals; readers can decrypt captured payloads.
- **No HTTPS-only enforcement.** Missing `aws:SecureTransport: true` condition allows plaintext access over HTTP.
- **Missing or misconfigured dead-letter queue.** No `RedrivePolicy` means poison messages are lost; a DLQ with a weaker policy than its source queue is a softer target holding the same data.
- **Public subscription confirmation.** Topics that allow arbitrary `sns:Subscribe` let an attacker register their own endpoint and silently receive a copy of every message (see persistence page).
- **HTTP/S and email subscriptions to external domains** indicate data leaving the trust boundary; verify the endpoints are owned by the organisation.
- **Stale subscriptions** (`PendingConfirmation` or pointing at decommissioned endpoints) signal weak lifecycle hygiene.

## Exploitation

Enumeration itself is non-destructive, but several read actions yield immediate intelligence that feeds later phases:

1. **Policy harvesting.** Collect every `Policy` document from topics and queues and statically evaluate them for wildcard principals, missing source conditions, and action wildcards. Any externally usable grant is an entry point documented on the privilege-escalation page.
2. **Cross-account probing.** With only an ARN, attempt `aws sqs get-queue-attributes` or `aws sns get-topic-attributes` using a foreign identity. A successful response confirms the resource policy grants your principal access even though you cannot list the resource.
3. **Data exposure validation.** Where a queue is readable, a single `receive-message --visibility-timeout 0` proves data exposure without disrupting consumers. Capture a redacted sample as evidence.
4. **Flow-graph pivot identification.** Subscriptions that deliver to Lambda or HTTP/S endpoints in other accounts identify trust paths to pivot through after gaining publish access.

## Detection & Logging

- **CloudTrail management events** record control-plane calls: `ListTopics`, `GetTopicAttributes`, `ListSubscriptionsByTopic`, `GetSubscriptionAttributes`, `ListQueues`, `GetQueueAttributes`, `GetQueueUrl`, `ListQueueTags`. These appear in CloudTrail by default. A burst of `Get*`/`List*` across many topics/queues and regions from one principal is a strong enumeration indicator.
- **SQS data events** (`SendMessage`, `ReceiveMessage`, `DeleteMessage`, `PurgeQueue`) are **not** logged by CloudTrail by default; they must be enabled as data events on a trail. Without that, `ReceiveMessage`-based content inspection is invisible in CloudTrail.
- **SNS data events** for `Publish`/`PublishBatch` similarly require explicit data-event logging.
- Detections to build: GuardDuty does not cover SNS/SQS enumeration directly, so rely on CloudTrail-sourced analytics - alert on a single principal issuing `GetQueueAttributes`/`GetTopicAttributes` against an unusually high number of distinct resources, on cross-region listing sprees, and on `GetQueueUrl` calls specifying `--queue-owner-aws-account-id` for a foreign account.
- Correlate the calling `userIdentity`, `sourceIPAddress`, and `userAgent` (CLI/SDK strings) to separate legitimate automation from reconnaissance.

## Remediation & Hardening

- Scope resource-based policies to specific principal ARNs; never use `"Principal": "*"` without restrictive `Condition` keys.
- Add confused-deputy protections (`aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOwner`) to every cross-service and cross-account grant.
- Enable SSE on all topics and queues; prefer customer-managed KMS keys with tightly scoped key policies.
- Enforce `aws:SecureTransport: true` to require HTTPS.
- Enable CloudTrail data events for high-value queues and topics so that message-plane activity is auditable.
- Configure dead-letter queues with the same or stronger access policy as their source queue, and restrict DLQ sources with `RedriveAllowPolicy`.
- Use least-privilege identity policies; avoid granting `sns:List*`/`sqs:List*` broadly to roles that do not need account-wide discovery.
- Tag resources with owner and data classification and review subscriptions periodically for stale or external endpoints.

## Tools

- **AWS CLI** - primary interface for all `sns`/`sqs` list and get operations shown above.
- **Pacu** - the `sns__enum` and `sqs__enum` style modules automate cross-region topic/queue/subscription inventory and policy collection.
- **ScoutSuite** - audits SNS topic and SQS queue policies, flagging public/cross-account exposure and missing encryption.
- **Prowler** - includes checks for SNS/SQS encryption, public access, and policy hygiene mapped to common benchmarks.
- **CloudMapper / cloud graphing utilities** - visualise the topic-to-queue-to-consumer flow graph.

## References

- AWS SNS Developer Guide - https://docs.aws.amazon.com/sns/latest/dg/welcome.html
- AWS SQS Developer Guide - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/welcome.html
- Amazon SNS API Reference - https://docs.aws.amazon.com/sns/latest/api/welcome.html
- Amazon SQS API Reference - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html
- SNS Access Policy Language - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-overview.html
- SQS Identity-Based Policies - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-using-identity-based-policies.html
