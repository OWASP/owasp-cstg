---
cstg_id: CSTG-AWS-S3-UNAUTH
title: "AWS S3 - Unauthenticated Access"
provider: aws
service: s3
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [aws-cli, s3scanner, ffuf]
references:
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"
  - "https://hackingthe.cloud/aws/enumeration/enum_s3/"
license: CC BY-SA 4.0
---

## Summary

Because S3 bucket names share one global namespace and buckets can be made readable or writable by
anonymous users, S3 exposure is testable without any credentials. The unauthenticated phase
discovers buckets associated with a target, then determines whether anonymous principals can list,
read, or write objects. This is the only S3 testing possible at the external tier; authenticated
configuration review is covered in [AWS S3 - Enumeration](../02-services/aws-s3-enum.md).

## Prerequisites

None. All checks use anonymous requests. With the AWS CLI, anonymous access is forced with
`--no-sign-request`.

## Enumeration

**Discover candidate bucket names.** Buckets are frequently named after the organisation, product,
or environment. Sources:

- Web/app source, JavaScript, and HTTP responses referencing `s3.amazonaws.com`,
  `s3-<region>.amazonaws.com`, or virtual-hosted `<bucket>.s3.amazonaws.com`.
- CNAME records pointing at S3 website endpoints.
- Permutation/wordlist brute force on `<org>-<word>` patterns (`backup`, `dev`, `prod`, `assets`,
  `logs`, `static`, `media`).

```bash
# Resolve whether a candidate bucket exists (404 = no such bucket, 403 = exists but private,
# 200/listing = exists and readable)
curl -s -o /dev/null -w '%{http_code}\n' "https://<bucket>.s3.amazonaws.com/"

# Automated discovery / permutation
s3scanner scan --bucket-file candidates.txt
ffuf -w wordlist.txt -u "https://FUZZ.s3.amazonaws.com/" -mc 200,403
```

**Test anonymous access on a discovered bucket:**

```bash
B=target-bucket
# Anonymous object listing
aws s3 ls "s3://$B" --no-sign-request
# Anonymous read of an object
aws s3 cp "s3://$B/path/object" - --no-sign-request
# Anonymous write test (in scope only - confirms a writable/world-writable bucket)
echo test | aws s3 cp - "s3://$B/cstg-write-test.txt" --no-sign-request
# Inspect the ACL if readable
aws s3api get-bucket-acl --bucket "$B" --no-sign-request
```

**Region** can be recovered from the `x-amz-bucket-region` response header even when access is
denied:

```bash
curl -sI "https://$B.s3.amazonaws.com/" | grep -i x-amz-bucket-region
```

## Misconfigurations & Findings

- **Anonymous list** - the `AllUsers` group has `s3:ListBucket`; object keys (and often sensitive
  data) are enumerable by anyone.
- **Anonymous read** - `AllUsers` has `s3:GetObject`; object contents are world-readable.
- **Anonymous write** - `AllUsers` has `s3:PutObject`; attackers can plant, overwrite, or deface
  content (including assets a site serves, enabling stored XSS or supply-chain tampering).
- **`AuthenticatedUsers` grants** - access to *any* AWS account holder (a frequent misunderstanding
  of "authenticated"), not just the target's users.
- **Subdomain takeover** - a dangling CNAME to a deleted S3 website bucket whose name can be
  re-registered.

## Detection & Logging

Anonymous access is only recorded if **S3 server access logging** or **CloudTrail S3 data events**
are enabled on the bucket; by default they are not, so anonymous reads commonly leave no trace -
itself a reportable gap. **GuardDuty** S3 protection can flag anonymous/external access patterns.

## Remediation & Hardening

- Enable account- and bucket-level **Block Public Access**; it overrides public policies and ACLs.
- Remove `AllUsers` / `AuthenticatedUsers` ACL grants and public bucket-policy statements.
- Set **Object Ownership = Bucket owner enforced** to disable ACLs.
- Remove dangling DNS records pointing at deleted buckets to prevent takeover.
- Serve genuinely public content through **CloudFront with OAC**, not a public bucket.

## Tools

- **aws-cli** (`--no-sign-request`) - authoritative anonymous probing.
- **s3scanner**, **ffuf** - bucket discovery and access classification at scale.

## References

- AWS - S3 Access Control overview
- hackingthe.cloud - S3 enumeration
