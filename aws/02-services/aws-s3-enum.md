---
cstg_id: CSTG-AWS-S3-ENUM
title: "AWS S3 - Enumeration"
provider: aws
service: s3
phase: services
required_access: read-only-audit
required_permissions:
  - s3:ListAllMyBuckets
  - s3:GetBucketPolicy
  - s3:GetBucketAcl
  - s3:GetBucketPublicAccessBlock
  - s3:GetEncryptionConfiguration
  - s3:GetBucketVersioning
  - s3:GetBucketLogging
  - s3:ListBucket
tools: [aws-cli, scoutsuite, prowler, cloudfox]
references:
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/s3api/"
license: CC BY-SA 4.0
---

## Summary

Amazon S3 (Simple Storage Service) stores objects in buckets addressed by a globally unique name.
Because the namespace is global and access can be granted through several independent mechanisms
(bucket policies, bucket and object ACLs, IAM identity policies, Access Points, and the
account/bucket-level Block Public Access settings), S3 is one of the most frequent sources of cloud
data exposure. This page covers authenticated enumeration of S3 from a credentialed principal: the
inventory of buckets and the per-bucket configuration that determines exposure. Unauthenticated
discovery of public buckets is covered in [AWS S3 - Unauthenticated Access](../01-unauthenticated-external/aws-s3-unauthenticated.md).

## Prerequisites

A principal with read access to S3 control-plane APIs. A read-only audit role
(`SecurityAudit` / `ViewOnlyAccess`) is sufficient and recommended. Object-level read
(`s3:GetObject`) is only needed to inspect contents, not to assess configuration.

## Enumeration

List buckets owned by the account:

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text
aws s3 ls
```

For each bucket, collect the configuration that governs exposure and durability:

```bash
B=target-bucket
aws s3api get-bucket-location            --bucket "$B"
aws s3api get-bucket-policy              --bucket "$B" --query Policy --output text
aws s3api get-bucket-policy-status       --bucket "$B"      # IsPublic true/false
aws s3api get-bucket-acl                 --bucket "$B"
aws s3api get-public-access-block        --bucket "$B"      # account- and bucket-level BPA
aws s3api get-bucket-encryption          --bucket "$B"      # SSE-S3 / SSE-KMS / none
aws s3api get-bucket-versioning          --bucket "$B"      # Status + MFADelete
aws s3api get-bucket-logging             --bucket "$B"      # server access logging target
aws s3api get-bucket-ownership-controls  --bucket "$B"      # ACLs enabled vs BucketOwnerEnforced
aws s3api get-bucket-lifecycle-configuration --bucket "$B"
aws s3api get-bucket-website             --bucket "$B"      # static website hosting
aws s3api list-objects-v2                --bucket "$B" --max-items 50
```

Also enumerate constructs that grant access outside the bucket policy:

```bash
aws s3control list-access-points --account-id <acct> --bucket "$B"
aws s3control get-public-access-block --account-id <acct>   # account-wide BPA
```

## Misconfigurations & Findings

- **Public access via policy or ACL** - a bucket policy with `Principal: "*"`, or an ACL granting
  the `AllUsers` / `AuthenticatedUsers` groups. `get-bucket-policy-status` returning `IsPublic: true`
  is the quickest signal.
- **Block Public Access disabled** - account- or bucket-level BPA not fully enabled, allowing future
  public grants to take effect.
- **ACLs enabled** - ownership controls not set to `BucketOwnerEnforced`, leaving object-ACL based
  access paths open (and cross-account object ownership issues).
- **No default encryption**, or SSE-S3 where SSE-KMS with a scoped key policy is warranted.
- **Versioning/MFA-Delete off** - no protection against object overwrite or deletion (ransomware,
  tampering, anti-forensics).
- **No server access logging / no CloudTrail data events** - object access is not recorded.
- **Over-broad bucket policy** - wildcard actions (`s3:*`), broad principals, or missing
  `aws:SourceArn` / `aws:SecureTransport` conditions.
- **Sensitive content** - state files (`terraform.tfstate`), backups, `.env`, key material, logs.

## Detection & Logging

Configuration reads above are S3 **control-plane** calls and appear as management events in
**CloudTrail** (`GetBucketPolicy`, `ListBuckets`, etc.). Object-level access (`GetObject`,
`PutObject`) is **not** logged unless **S3 data events** are explicitly enabled on a trail, or
server access logging is configured on the bucket - their absence is itself a finding. **GuardDuty**
S3 protection flags anomalous access patterns and access from anonymous or unusual principals.

## Remediation & Hardening

- Enable **Block Public Access** at the account level and on every bucket unless public serving is a
  deliberate, reviewed requirement.
- Set **Object Ownership = Bucket owner enforced** to disable ACLs and rely on policies/IAM.
- Apply **least-privilege bucket policies** with `aws:SecureTransport`, `aws:SourceArn`/`SourceAccount`
  conditions; avoid wildcard actions and principals.
- Enable **default encryption** (SSE-KMS with a scoped key policy for sensitive data).
- Enable **versioning + MFA Delete** on buckets holding important or stateful data.
- Enable **CloudTrail S3 data events** (at least for sensitive buckets) and/or server access logging.

## Tools

- **aws-cli** - authoritative enumeration via `s3api`/`s3control`.
- **Prowler**, **ScoutSuite** - read-only posture audit covering the findings above.
- **CloudFox** - surfaces interesting/public buckets from an offensive vantage point.

## References

- AWS - S3 Security Best Practices (userguide/security-best-practices)
- AWS - Blocking public access to S3 storage
- AWS - S3 CLI `s3api` command reference
