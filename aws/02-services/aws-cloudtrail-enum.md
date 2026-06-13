---
cstg_id: CSTG-AWS-CLOUDTRAIL-ENUM
title: "AWS Cloudtrail - Enumeration"
provider: aws
service: cloudtrail
phase: services
required_access: read-only-audit
required_permissions:
  - cloudtrail:DescribeTrails
  - cloudtrail:GetTrailStatus
  - cloudtrail:GetEventSelectors
  - cloudtrail:ListTrails
  - cloudtrail:GetTrail
  - cloudtrail:ListEventDataStores
  - cloudtrail:GetEventDataStore
  - cloudtrail:LookupEvents
  - cloudtrail:GetInsightSelectors
  - s3:GetBucketPolicy
  - s3:GetBucketLogging
  - kms:DescribeKey
  - organizations:DescribeOrganization
tools:
  - awscli
  - pacu
  - ScoutSuite
  - prowler
  - cloudtrail2timesketch
references:
  - "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
  - "https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/"
  - "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-event-data-store.html"
license: CC BY-SA 4.0
---

## Summary

AWS CloudTrail is the account- and organization-level audit log that records management API calls (control-plane), and optionally data events (object-level S3 reads/writes, Lambda invocations, DynamoDB item access) and network activity events. From the assessor's perspective, CloudTrail enumeration is reconnaissance *of the watcher*: before any noisy action is taken, an attacker who can read CloudTrail configuration learns exactly what is being logged, where the logs are written, who can reach them, and — critically — what is **not** being logged. The same enumeration is what a defender or auditor performs to validate that logging coverage is complete, immutable, and monitored.

The attacker objective during this phase is twofold: (1) understand the detection surface so subsequent activity can be confined to blind spots (regions, accounts, or event categories not covered by any trail), and (2) identify the trail's delivery destinations (S3 buckets, CloudWatch Logs groups, EventBridge) and their access controls, which are themselves targets for log tampering or exfiltration. Knowing the gaps in coverage informs every later phase; this page is the prerequisite reconnaissance for [Post-Exploitation](../05-post-exploitation/aws-cloudtrail-post-exploitation.md) and [Persistence](../06-persistence/aws-cloudtrail-persistence.md).

## Prerequisites

- Any valid AWS credential with read access to CloudTrail configuration. The AWS-managed `SecurityAudit` and `ViewOnlyAccess` policies grant the necessary `cloudtrail:Describe*`/`Get*`/`List*` actions.
- To resolve the security posture of log destinations, read access to the destination services is useful: `s3:GetBucketPolicy`/`GetBucketAcl`/`GetBucketLogging` on the log bucket, `kms:DescribeKey` on any encrypting key, and `logs:DescribeLogGroups` for CloudWatch delivery.
- `cloudtrail:LookupEvents` (90-day management-event history) and `cloudtrail:StartQuery` against a CloudTrail Lake event data store let an assessor read historical activity directly, subject to the data being captured.
- Organization-trail context (`organizations:DescribeOrganization`, `cloudtrail:GetTrail`) is relevant when the foothold is in a member account governed by a management-account trail.

## Enumeration

### Inventory trails and their scope

```bash
# Per-region view; some trails are multi-region, so iterate regions or use the
# describe-trails call which (without --trail-name-list) returns trails visible in the region.
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[].{Name:Name,Home:HomeRegion,Multi:IsMultiRegionTrail,Org:IsOrganizationTrail,Bucket:S3BucketName,KMS:KmsKeyId,LogGroup:CloudWatchLogsLogGroupArn}' \
  --output table

# Newer ARN-based listing (includes Lake and cross-region trails)
aws cloudtrail list-trails --output table

# Pull a single trail's full definition
aws cloudtrail get-trail --name <trail-name-or-arn>
```

Iterate every enabled region — a trail that is *not* multi-region only captures events in its home region, so single-region trails are a primary source of blind spots:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="
  aws cloudtrail describe-trails --region "$r" \
    --query 'trailList[].{Name:Name,Multi:IsMultiRegionTrail,Home:HomeRegion}' --output text
done
```

### Confirm each trail is actually logging

A trail can exist but be **stopped**. `IsLogging` is the decisive field:

```bash
aws cloudtrail get-trail-status --name <trail> \
  --query '{Logging:IsLogging,LastDelivery:LatestDeliveryTime,LastDeliveryError:LatestDeliveryError,LastNotificationError:LatestNotificationError}'
```

`LatestDeliveryError` populated with `AccessDenied`/`NoSuchBucket` indicates a trail that is enabled but silently failing to deliver — an existing coverage gap worth noting.

### Determine what categories of events are captured

```bash
# Management events: read-only vs write-only vs all; whether global service events are included
aws cloudtrail get-event-selectors --trail-name <trail>

# Advanced selectors reveal data-event coverage (S3 objects, Lambda, DynamoDB, etc.)
aws cloudtrail get-event-selectors --trail-name <trail> \
  --query 'AdvancedEventSelectors'

# Insights (anomaly detection on API call-rate / error-rate)
aws cloudtrail get-insight-selectors --trail-name <trail>
```

Interpretation:

- `ReadWriteType: WriteOnly` means read/list/describe calls are **not** logged for that category — reconnaissance is invisible.
- Absence of any data-event selector means object-level S3 GETs/PUTs, Lambda invokes, and DynamoDB item access are **not** recorded; only the control plane is.
- `IncludeManagementEvents: false` or no selector at all on a category is a major gap.

### Enumerate CloudTrail Lake event data stores

```bash
aws cloudtrail list-event-data-stores --output table
aws cloudtrail get-event-data-store --event-data-store <arn> \
  --query '{Name:Name,Multi:MultiRegionEnabled,Org:OrganizationEnabled,Retention:RetentionPeriod,Termination:TerminationProtectionEnabled,Selectors:AdvancedEventSelectors}'
```

### Locate and assess the delivery destinations

```bash
# The S3 bucket receiving logs - assess its policy, encryption, versioning, and access
B=$(aws cloudtrail describe-trails --query 'trailList[0].S3BucketName' --output text)
aws s3api get-bucket-policy   --bucket "$B"
aws s3api get-bucket-acl      --bucket "$B"
aws s3api get-bucket-versioning --bucket "$B"
aws s3api get-bucket-logging  --bucket "$B"
aws s3api get-object-lock-configuration --bucket "$B" 2>/dev/null  # WORM/immutability

# Encrypting KMS key - who can decrypt the logs?
K=$(aws cloudtrail get-trail --name <trail> --query 'Trail.KmsKeyId' --output text)
aws kms get-key-policy --key-id "$K" --policy-name default

# CloudWatch Logs delivery (real-time alerting often hangs off this)
aws cloudtrail get-trail --name <trail> --query 'Trail.CloudWatchLogsLogGroupArn'
```

### Read history directly (when permitted)

```bash
# Last 90 days of management events (works even with no S3 access to the trail bucket)
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin

# Query a CloudTrail Lake store with SQL
aws cloudtrail start-query --query-statement \
  "SELECT eventName, userIdentity.arn, sourceIPAddress, eventTime
   FROM <eds-id> WHERE eventName='AssumeRole' ORDER BY eventTime DESC LIMIT 100"
```

### Determine organization context

```bash
# Is this account governed by an org trail defined in the management account?
aws organizations describe-organization 2>/dev/null
# describe-trails in a member account shows the org trail as a "shadow" trail (read-only here)
aws cloudtrail describe-trails --include-shadow-trails \
  --query "trailList[?IsOrganizationTrail==\`true\`]"
```

An org trail that the member account cannot stop or alter is a strong control; confirming its presence tells the assessor that local log-tampering options are limited to the destination layer.

## Misconfigurations & Findings

- **No multi-region trail.** Activity in unmonitored regions is invisible. A single-region trail (or trails covering only "used" regions) leaves every other region as a blind spot.
- **Trail stopped or failing delivery.** `IsLogging: false` or a persistent `LatestDeliveryError` means events are not reaching durable storage.
- **Management events limited to `WriteOnly`** — all enumeration and reconnaissance goes unlogged.
- **No data-event coverage.** Without data-event selectors, S3 object access (data exfiltration), Lambda invocations, and DynamoDB item access are not recorded.
- **Log bucket lacks immutability/versioning.** No S3 Object Lock, no versioning, and no MFA-delete means delivered logs can be deleted or overwritten.
- **Overly permissive log-bucket policy or KMS key policy** — principals outside the security/log-archive account can read (exfiltrate) or delete logs, or decrypt them.
- **Not an organization trail.** Per-account trails can be disabled by a compromised member account; an org trail centrally enforced from the management account cannot.
- **CloudTrail Lake event data store without termination protection** or with a short retention period.
- **No CloudWatch Logs / EventBridge integration**, so there is no real-time alerting path even though logs are archived.
- **Insights not enabled**, removing automated detection of anomalous API call-rate bursts.

## Exploitation

Enumeration itself is non-destructive, but its output is the map that subsequent phases exploit:

1. The set of regions/accounts/event-categories **not** covered defines where later actions can be performed with reduced logging — see [Post-Exploitation](../05-post-exploitation/aws-cloudtrail-post-exploitation.md) for operating within blind spots and for log-tampering paths.
2. The delivery destinations and their access policies define the targets for log deletion, alteration, or exfiltration.
3. The presence/absence of an immutable org trail dictates whether disabling logging is even viable as a persistence/anti-forensics step — see [Persistence](../06-persistence/aws-cloudtrail-persistence.md).

A read of `get-trail-status` and `get-event-selectors` across all regions is the single most valuable pre-action recon step in an AWS engagement, because it converts blind guessing about detection into a concrete coverage matrix.

## Detection & Logging

- **CloudTrail** records its own configuration-read calls (`DescribeTrails`, `GetTrailStatus`, `GetEventSelectors`, `GetInsightSelectors`, `ListEventDataStores`, `GetEventDataStore`) under event source `cloudtrail.amazonaws.com`. A burst of these from a single principal — especially one that has just performed `sts:GetCallerIdentity` — is a recognizable "casing the logging" signature.
- `LookupEvents` and CloudTrail Lake `StartQuery`/`DescribeQuery` calls are logged and indicate a principal reading historical activity.
- Reads of the log bucket policy / KMS key policy (`s3:GetBucketPolicy`, `kms:GetKeyPolicy`) and `s3:GetBucketVersioning`/`GetObjectLockConfiguration` against the known trail bucket are notable when performed by a non-administrative principal.
- Managed detections: **GuardDuty** does not flag pure configuration reads, but the follow-on tampering it does flag (e.g. `Stealth:IAMUser/CloudTrailLoggingDisabled`, `Stealth:S3/ServerAccessLoggingDisabled`) is the reason this recon is performed. **AWS Config** rules (`cloudtrail-enabled`, `multi-region-cloudtrail-enabled`, `cloud-trail-encryption-enabled`, `cloud-trail-log-file-validation-enabled`) continuously assert the very properties the assessor is enumerating.

## Remediation & Hardening

- Deploy a **multi-region, organization-wide trail** managed from a dedicated logging/security account so member accounts cannot stop or modify it.
- Enable **management events (all read/write)** plus **data events** for sensitive S3 buckets, Lambda, and DynamoDB based on risk.
- Send logs to a **dedicated log-archive account** S3 bucket with **versioning, S3 Object Lock (compliance mode), and MFA-delete**, and a restrictive bucket policy denying access outside the security organization.
- Enable **log file integrity validation** (`--enable-log-file-validation`) so tampering with delivered files is detectable via digest files.
- Encrypt logs with a **dedicated KMS key** whose key policy grants decrypt only to authorized log-analysis roles.
- Integrate with **CloudWatch Logs / EventBridge** for real-time alerting, and enable **CloudTrail Insights** for anomaly detection.
- Use **CloudTrail Lake** with **termination protection** and an appropriate retention period.
- Constrain `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`, and `PutEventSelectors` via SCPs so even compromised account admins cannot weaken logging.
- Continuously evaluate the AWS Config rules listed above and alert on drift.

## Tools

- **awscli** — native `cloudtrail`, `s3api`, and `kms` commands for the full enumeration above.
- **prowler** — checks (`cloudtrail_multi_region_enabled`, `cloudtrail_log_file_validation_enabled`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_logs_s3_bucket_*`) that report logging-coverage gaps.
- **ScoutSuite** — surfaces disabled/single-region trails, unencrypted logs, and permissive log-bucket policies in its report.
- **Pacu** — the `detection__enum_services` and `detection__disruption` modules enumerate trails and report coverage.
- **cloudtrail2timesketch / log-parsing utilities** — for reading and timelining downloaded log files when bucket access is available.

## References

- AWS CloudTrail API Reference — https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html
- CloudTrail concepts — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- Logging data events — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
- Querying CloudTrail Lake event data stores — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-event-data-store.html
- hackingthe.cloud — GuardDuty/CloudTrail evasion considerations — https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/
