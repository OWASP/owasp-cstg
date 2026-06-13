---
cstg_id: CSTG-AWS-CLOUDFRONT-ENUM
title: "AWS Cloudfront - Enumeration"
provider: aws
service: cloudfront
phase: services
required_access: read-only-audit
required_permissions:
  - cloudfront:ListDistributions
  - cloudfront:GetDistribution
  - cloudfront:GetDistributionConfig
  - cloudfront:ListCachePolicies
  - cloudfront:GetCachePolicy
  - cloudfront:ListOriginRequestPolicies
  - cloudfront:ListResponseHeadersPolicies
  - cloudfront:ListFunctions
  - cloudfront:DescribeFunction
  - cloudfront:GetFunction
  - cloudfront:ListKeyGroups
  - cloudfront:ListPublicKeys
  - cloudfront:GetPublicKey
  - cloudfront:ListFieldLevelEncryptionConfigs
  - cloudfront:ListOriginAccessControls
  - cloudfront:GetOriginAccessControl
  - cloudfront:ListCloudFrontOriginAccessIdentities
  - cloudfront:ListDistributionsByWebACLId
  - cloudfront:ListInvalidations
  - cloudfront:ListTagsForResource
tools:
  - AWS CLI (aws cloudfront)
  - AWS API / SDK
  - Cloud IAM/permission enumeration tooling
references:
  - https://docs.aws.amazon.com/cli/latest/reference/cloudfront/
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awsCLI.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-the-edge.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html
  - https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudfront.html
license: CC BY-SA 4.0
---

## Summary

This page covers credentialed, read-only enumeration of Amazon CloudFront
configuration from within an AWS account (or across accounts with assumed roles).
The objective is to inventory every distribution and its security-relevant
configuration so that misconfigurations, origin-binding gaps, edge-compute code, and
trust relationships can be assessed.

CloudFront is a global service: its API endpoint is `cloudfront.amazonaws.com` and
resources are not regional. Distribution configuration is one of the richest sources
of architecture intelligence in an account because it enumerates origins
(S3 buckets, ALBs, API Gateways, custom HTTP endpoints), the WAF web ACL in front of
them, edge functions (CloudFront Functions and Lambda@Edge) that run on requests,
and the signing key groups used for private content.

For external, unauthenticated assessment of distributions see
[aws-cloudfront-unauthenticated.md](../01-unauthenticated-external/aws-cloudfront-unauthenticated.md).

## Prerequisites

- Valid AWS credentials (an access key/session, or an assumable role) with the
  read-only CloudFront permissions listed in the frontmatter. The describe/list
  actions above are covered by the AWS managed policies
  `CloudFrontReadOnlyAccess`, `ReadOnlyAccess`, and `SecurityAudit`.
- AWS CLI v2 or an SDK configured with the credentials.
- No region is required (`--region us-east-1` is conventional for global services).

## Enumeration

### Inventory distributions

```bash
# List all distributions with the most security-relevant fields summarised
aws cloudfront list-distributions \
  --query 'DistributionList.Items[].{Id:Id,Domain:DomainName,Aliases:Aliases.Items,Enabled:Enabled,WebACL:WebACLId,Origins:Origins.Items[].DomainName}' \
  --output json

# Full configuration for a single distribution (origins, behaviours, restrictions)
aws cloudfront get-distribution --id E1234567890ABC

# Just the mutable config block (useful for diffing / spotting drift)
aws cloudfront get-distribution-config --id E1234567890ABC
```

Key fields to extract per distribution:

- `Origins.Items[]` - origin domains, origin types, and `OriginAccessControlId`
  / `S3OriginConfig.OriginAccessIdentity` (empty string means no OAC/OAI).
- `OriginGroups` - failover origins.
- `DefaultCacheBehavior` and `CacheBehaviors.Items[]` - `ViewerProtocolPolicy`,
  `AllowedMethods`, `TrustedKeyGroups` / `TrustedSigners` (signed URL enforcement),
  `FieldLevelEncryptionId`, `FunctionAssociations`, `LambdaFunctionAssociations`,
  `CachePolicyId`, `OriginRequestPolicyId`, `ResponseHeadersPolicyId`.
- `WebACLId` - associated AWS WAF web ACL (empty means no WAF).
- `Restrictions.GeoRestriction` - geo blocking config.
- `ViewerCertificate` - ACM certificate, `MinimumProtocolVersion`, and whether the
  default `cloudfront.net` certificate is in use.
- `Logging` - whether standard access logging is enabled and the target bucket.
- `Aliases.Items[]` - CNAMEs (cross-reference with Route 53 / external DNS for
  dangling records).

### Enumerate origin access controls and identities

```bash
# OAC (current mechanism for binding S3/Lambda function URL origins to a distribution)
aws cloudfront list-origin-access-controls
aws cloudfront get-origin-access-control --id E2AOAC1234567

# Legacy Origin Access Identities (OAI)
aws cloudfront list-cloud-front-origin-access-identities
```

Correlate each origin in each distribution against the OAC/OAI inventory to find
S3 origins served **without** any origin-binding control.

### Enumerate edge compute

```bash
# CloudFront Functions (viewer request/response, lightweight JS)
aws cloudfront list-functions
aws cloudfront describe-function --name my-func
aws cloudfront get-function --name my-func --stage LIVE function-code.js   # retrieves source

# Lambda@Edge associations appear inside each behaviour's LambdaFunctionAssociations
aws cloudfront get-distribution --id E1234567890ABC \
  --query 'Distribution.DistributionConfig.DefaultCacheBehavior.LambdaFunctionAssociations'
```

Edge function source code frequently contains hard-coded secrets, auth bypass
logic, header rewriting, signed-URL or token validation, and routing decisions -
all of which are valuable for both attack and review. Retrieve and read the source.
Lambda@Edge function code is fetched from Lambda in `us-east-1` using the ARN found
in the association.

### Enumerate signing keys, policies, and field-level encryption

```bash
# Trusted key groups + public keys used for signed URLs / cookies
aws cloudfront list-key-groups
aws cloudfront list-public-keys
aws cloudfront get-public-key --id K2PUBKEY1234

# Reusable policies referenced by behaviours
aws cloudfront list-cache-policies
aws cloudfront get-cache-policy --id <policy-id>
aws cloudfront list-origin-request-policies
aws cloudfront list-response-headers-policies

# Field-level encryption
aws cloudfront list-field-level-encryption-configs
```

### Map WAF, tags, and invalidation history

```bash
# Which distributions are protected by a given web ACL
aws cloudfront list-distributions-by-web-acl-id --web-acl-id <web-acl-arn-or-id>

# Tags (often reveal environment, owner, data classification)
aws cloudfront list-tags-for-resource --resource arn:aws:cloudfront::111122223333:distribution/E1234567890ABC

# Invalidation history (signals deployments / incident response)
aws cloudfront list-invalidations --distribution-id E1234567890ABC
```

### Raw API

Every action above maps to a `cloudfront.amazonaws.com` API call
(`ListDistributions2020_05_31`, `GetDistribution2020_05_31`, `GetFunction`, etc.)
and can be issued via SigV4-signed HTTPS requests or any SDK when the CLI is
unavailable.

## Misconfigurations & Findings

Flag the following during enumeration:

- **S3 origin without OAC/OAI** - `OriginAccessControlId` and
  `S3OriginConfig.OriginAccessIdentity` both empty. The bucket is likely reachable
  directly, enabling edge-control bypass (see the unauthenticated page).
- **No WAF web ACL** (`WebACLId` empty) on a distribution exposing sensitive or
  dynamic content.
- **Weak TLS** - `ViewerCertificate.MinimumProtocolVersion` permitting TLSv1/TLSv1.1,
  or `CloudFrontDefaultCertificate: true` while serving a custom alias.
- **Insecure viewer protocol** - `ViewerProtocolPolicy: allow-all` (HTTP permitted).
- **Custom origin reachable over HTTP** - `CustomOriginConfig.OriginProtocolPolicy:
  http-only`, or `OriginSslProtocols` allowing SSLv3/TLSv1.
- **Missing custom-header origin lockdown** - a custom origin with no secret header
  (compare `Origins.Items[].CustomHeaders` against the WAF rule that should validate
  it) implies the origin can be reached directly.
- **No access logging** (`Logging.Enabled: false`) and/or no real-time logs - reduces
  detection capability.
- **Overly permissive behaviours** - `AllowedMethods` including
  `PUT/POST/PATCH/DELETE` for paths that should be read-only; caching that includes
  cookies/authorization, enabling cache poisoning or deception.
- **Signed-URL/cookie not enforced** - private paths with empty `TrustedKeyGroups`
  and `TrustedSigners`.
- **Disabled geo-restriction** where compliance requires it
  (`Restrictions.GeoRestriction.RestrictionType: none`).
- **Edge function risks** - secrets, auth-bypass logic, or SSRF-enabling rewrites in
  CloudFront Function / Lambda@Edge source.
- **Dangling aliases** - aliases in `Aliases.Items[]` with no matching live DNS, or
  DNS pointing to a deleted distribution (subdomain-takeover precursor).

## Detection & Logging

- **CloudTrail** records all CloudFront management-plane read calls. The
  enumeration above appears as `eventSource: cloudfront.amazonaws.com` with
  `eventName` values such as `ListDistributions`, `GetDistribution`,
  `GetDistributionConfig`, `ListFunctions`, `GetFunction`, `DescribeFunction`,
  `ListKeyGroups`, `ListOriginAccessControls`, and `ListTagsForResource`. Because
  CloudFront is global, these events are delivered in the `us-east-1` region of the
  trail.
- A burst of `List*`/`Get*`/`Describe*` calls across many CloudFront APIs from a
  single principal in a short window is a strong enumeration signal. `GetFunction`
  (which returns source code) and `GetDistributionConfig` across all distributions
  are particularly noteworthy.
- CloudFront access logs and WAF logs cover the data plane, not these management
  calls.
- Detective controls: CloudTrail with an organization trail, GuardDuty (which can
  flag anomalous API usage and credential misuse), and CloudWatch/EventBridge rules
  on the enumeration event names above.

## Remediation & Hardening

- **Least privilege**: grant CloudFront read actions only to roles that need them;
  treat `cloudfront:GetFunction` and `GetDistributionConfig` as sensitive because
  they expose source code and full configuration. Avoid wildcard
  `cloudfront:*`/`cloudfront:Get*`/`cloudfront:List*` on broad roles.
- **Remediate the findings above**: enable OAC and lock down S3 origins; attach WAF;
  enforce TLS 1.2+ and `redirect-to-https`; require signed URLs/cookies on private
  paths; add and validate origin custom-header secrets; enable access/real-time
  logging.
- **Keep secrets out of edge functions**; review CloudFront Function and Lambda@Edge
  code for hard-coded credentials and weak auth logic.
- **Monitor and alert** on the CloudTrail enumeration patterns and on
  configuration-changing calls (`UpdateDistribution`, `CreateInvalidation`,
  `UpdateFunction`).
- **Audit aliases vs DNS** regularly to prevent dangling-record takeover.

## Tools

- AWS CLI (`aws cloudfront ...`) - native enumeration of all configuration objects.
- AWS API / SDK with SigV4 - raw access when the CLI is unavailable.
- Cloud IAM/permission enumeration tooling - to determine which CloudFront read
  actions the current principal can perform before attempting them.
- Cloud security posture / multi-account inventory tooling - to enumerate
  distributions and flag the misconfigurations above at scale.

## References

- AWS CLI CloudFront command reference:
  https://docs.aws.amazon.com/cli/latest/reference/cloudfront/
- Working with distributions via the CLI:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awsCLI.html
- Restricting access to an S3 origin (OAC/OAI):
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
- CloudFront Functions:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html
- Lambda@Edge:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-the-edge.html
- Serving private content with signed URLs and cookies:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html
- Distribution settings reference:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html
- Service Authorization Reference (CloudFront actions):
  https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudfront.html
