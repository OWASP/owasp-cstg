---
cstg_id: CSTG-AWS-CLOUDFRONT-UNAUTH
title: "AWS Cloudfront - Unauthenticated Access"
provider: aws
service: cloudfront
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - DNS resolver / dig
  - HTTP client (curl)
  - TLS certificate transparency search
  - Web content discovery scanner
references:
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-overview.html
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RestrictingAccessToS3.html
  - https://hackingthe.cloud/aws/exploitation/s3-bucket-takeover/
  - https://hackingthe.cloud/aws/general-knowledge/intro_metadata_endpoint/
  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awsCLI.html
license: CC BY-SA 4.0
---

## Summary

Amazon CloudFront is a content delivery network (CDN) that fronts origins such as
Amazon S3 buckets, Application/Network Load Balancers, API Gateway, EC2 instances,
or arbitrary custom HTTP origins. Each distribution is reachable from the public
Internet at a provider-assigned domain of the form `dXXXXXXXXXXXXX.cloudfront.net`
and, optionally, at one or more customer aliases (CNAMEs) such as `cdn.example.com`.

Because CloudFront is by design an unauthenticated, anonymously reachable edge
service, it presents a large external attack surface that can be assessed with no
AWS credentials whatsoever. The most common externally observable weaknesses are:

- **Origin exposure / origin bypass** - the real origin (S3 bucket, ALB DNS name,
  EC2 IP) is discoverable, allowing an attacker to bypass CloudFront-layer controls
  (WAF, geo-restriction, signed URLs, rate limiting) by talking to the origin
  directly.
- **Dangling alias / subdomain takeover** - a CNAME or distribution alias points at
  a CloudFront distribution or origin that no longer exists or is unclaimed, letting
  an attacker register it and serve content under the victim's name.
- **Misconfigured origin access** - an S3 origin that was meant to be served only
  through CloudFront (via Origin Access Control / Origin Access Identity) remains
  publicly listable or readable directly.
- **Information disclosure** - verbose headers, default `*.cloudfront.net` access,
  directory listing, exposed `.git`/backups, or response headers that leak origin
  identity, stack, or internal hostnames.

This page covers what can be enumerated and tested against CloudFront from an
unauthenticated, external position. Credentialed enumeration of distribution
configuration is covered in
[aws-cloudfront-enum.md](../02-services/aws-cloudfront-enum.md).

## Prerequisites

- No AWS credentials are required.
- Network egress to the public Internet (HTTP/HTTPS and DNS).
- A target scope: one or more domain names, an organization name, or known
  `*.cloudfront.net` distribution domains belonging to the target.

## Enumeration

### Identify CloudFront usage for a target

Resolve candidate hostnames and inspect the DNS chain and response headers. A
CNAME terminating in `cloudfront.net`, or the presence of the `X-Amz-Cf-Id` and
`X-Amz-Cf-Pop` response headers, confirms CloudFront fronts the host.

```bash
# DNS: look for a CNAME to *.cloudfront.net
dig +short cdn.example.com
dig +short CNAME cdn.example.com

# Headers that reveal CloudFront and the edge POP serving the request
curl -sSI https://cdn.example.com/ | grep -iE 'x-amz-cf-(id|pop)|via|x-cache|server'
```

Typical CloudFront response headers:

- `Via: 1.1 <hash>.cloudfront.net (CloudFront)`
- `X-Amz-Cf-Pop: SYD1-C1` (edge location code, leaks rough geography of the POP)
- `X-Amz-Cf-Id: <opaque request id>`
- `X-Cache: Hit from cloudfront` / `Miss from cloudfront` / `Error from cloudfront`

### Discover distribution domains and aliases

- **Certificate Transparency** logs frequently reveal aliases attached to ACM
  certificates used by CloudFront. Search CT databases for the target's apex domain
  to enumerate subdomains that may be CloudFront aliases.
- **Passive DNS / DNS history** services can map historical CNAMEs to
  `cloudfront.net` targets, useful for finding dangling aliases.
- **Direct `*.cloudfront.net` probing**: the assigned distribution domain
  (`dXXXX.cloudfront.net`) is publicly resolvable. If discovered (via CT, referrer
  leakage, JavaScript, or response headers), it can be requested directly.

```bash
# Probe the raw distribution domain. If it serves content without a Host match,
# the distribution may accept the default *.cloudfront.net domain.
curl -sSI https://d1111abcdef8.cloudfront.net/

# Compare behaviour when supplying the customer alias as Host
curl -sSI https://d1111abcdef8.cloudfront.net/ -H 'Host: cdn.example.com'
```

### Map the origin

The goal is to determine what sits behind the edge. Indicators of the origin type:

- **S3 origin**: `Server: AmazonS3` on a cache miss, S3-style XML error bodies
  (`<Error><Code>AccessDenied</Code>` / `NoSuchKey`), or `x-amz-*` headers leaking
  through. The origin domain often follows
  `bucket-name.s3.<region>.amazonaws.com` or `bucket-name.s3-website-<region>.amazonaws.com`.
- **ALB/EC2/custom origin**: `Server` header from nginx/Apache/IIS, application
  framework headers (`X-Powered-By`), or load-balancer cookies (`AWSALB`,
  `AWSALBCORS`).
- **API Gateway**: `x-amzn-RequestId`, `x-amz-apigw-id` headers.

```bash
# Force cache misses to observe origin-emitted headers
curl -sSI "https://cdn.example.com/?cb=$RANDOM" | grep -iE 'server|x-powered-by|x-amzn|x-amz|set-cookie'

# Trigger an error to capture an origin error body (S3 returns XML)
curl -sS "https://cdn.example.com/this-key-should-not-exist-$RANDOM"
```

### Content discovery

Run authenticated-equivalent content discovery against the public edge as any
anonymous client would: enumerate common paths, backup files, source control
directories, and admin endpoints. Because CloudFront caches, vary cache-busting
query strings to reach the origin and to avoid serving stale cached errors.

```bash
# Examples of high-signal paths to probe through the edge
for p in .git/config .env backup.zip robots.txt sitemap.xml .well-known/security.txt admin/ ; do
  printf '%s -> ' "$p"; curl -sS -o /dev/null -w '%{http_code}\n' "https://cdn.example.com/$p?cb=$RANDOM"
done
```

## Misconfigurations & Findings

### Origin bypass (CloudFront control bypass)

If the origin's real address (S3 bucket name, ALB DNS name, or EC2 public IP) is
discoverable and the origin accepts connections from any source, an attacker can
reach the origin directly and bypass any control enforced only at the CloudFront
layer:

- AWS WAF web ACL associated with the distribution.
- Geo-restriction (CloudFront geo blocking).
- Signed URLs / signed cookies (private content).
- Field-level encryption, rate limiting, and header injection.

**Test:** once the origin address is known, request the same resource directly and
compare. A successful direct response that the edge would have blocked confirms the
bypass.

```bash
# Direct-to-origin request (S3 example)
curl -sSI "https://target-origin-bucket.s3.amazonaws.com/private/key"

# Direct-to-origin request (custom origin by IP, supplying the expected Host)
curl -sSI "https://203.0.113.10/" -H 'Host: cdn.example.com' --resolve cdn.example.com:443:203.0.113.10
```

The correct hardening is that the origin only accepts traffic that proves it came
through this specific distribution (Origin Access Control for S3; a shared secret
custom header validated by WAF for custom origins; security groups limited to the
CloudFront managed prefix list for ALB/EC2). If a direct request succeeds, that
binding is missing.

### S3 origin publicly readable / listable

An S3 origin intended to be served exclusively through CloudFront (using OAC/OAI)
sometimes remains public. Signs:

- Requesting the bucket REST endpoint returns object content or a listing.
- The bucket name is exposed in CloudFront error XML or in the origin domain.

```bash
# Attempt a direct bucket listing
curl -sS "https://target-origin-bucket.s3.amazonaws.com/?list-type=2"

# Attempt direct object retrieval that should require OAC
curl -sSI "https://target-origin-bucket.s3.<region>.amazonaws.com/index.html"
```

See the S3 unauthenticated guidance for full bucket testing methodology.

### Dangling alias / subdomain takeover

CloudFront distribution takeover occurs when a DNS record (CNAME) still points to a
`*.cloudfront.net` distribution domain (or to an origin) that is no longer claimed.
Two distinct cases:

1. **Dangling CNAME to an unclaimed alias** - the alias is no longer registered to
   any distribution. Requests return a CloudFront error such as
   `The request could not be satisfied ... Bad request` or `403` with
   `X-Cache: Error from cloudfront`. If an attacker can create a distribution and
   add that alias, they can serve content under the victim domain (subject to ACM
   ownership validation, which raises but does not always eliminate the risk).
2. **Dangling origin** - the distribution still exists but its origin (e.g. an S3
   bucket that was deleted, or an S3 website endpoint) is unclaimed; registering the
   missing origin lets an attacker inject content served through the trusted edge.

```bash
# A dangling alias frequently produces a distinctive CloudFront error page
curl -sS https://abandoned.example.com/ | grep -iE 'cloudfront|request could not be satisfied|Bad request'
```

### Information disclosure

- **Origin identity leakage**: `Server: AmazonS3`, bucket names in error XML, ALB
  hostnames in redirects, or internal hostnames in `Location`/`Set-Cookie`.
- **Default domain reachable**: the distribution serves content over the raw
  `dXXXX.cloudfront.net` domain in addition to the intended alias, enabling control
  bypass and host-header confusion.
- **Verbose errors / stack traces** passed through from a misconfigured origin.
- **Cache deception / poisoning surface**: unkeyed headers, overly broad cache
  behaviours, or caching of authenticated responses. Probe whether path traversal
  in the cache key (`/static/..%2f<dynamic>`) or extension confusion
  (`/account.css`) causes sensitive responses to be cached and served to others.

```bash
# Cache key probing - does adding a static-looking suffix change caching/auth?
curl -sSI "https://cdn.example.com/account"          # dynamic, may be MISS/no-store
curl -sSI "https://cdn.example.com/account.css"       # does this get cached?
```

## Detection & Logging

From the operator side, externally originated reconnaissance and abuse of a
distribution are observable through CloudFront's own telemetry rather than
CloudTrail data events:

- **CloudFront standard access logs** (delivered to S3) and **real-time logs**
  (delivered to Kinesis Data Streams) record every viewer request: URI, status,
  edge location, `x-edge-result-type`, viewer IP, user agent, and referrer. High
  rates of 403/404, scanning patterns, and requests to the raw `*.cloudfront.net`
  domain are visible here.
- **AWS WAF logs** (if a web ACL is attached) record blocked/counted requests and
  matched rules.
- **CloudTrail** records the *management-plane* actions an attacker would take after
  gaining credentials (`CreateDistribution`, `UpdateDistribution`,
  `CreateInvalidation`) but does **not** record anonymous viewer requests; rely on
  CloudFront access logs for the data plane.
- **GuardDuty** and Route 53 query logging can surface anomalous DNS resolution and
  some scanning behaviour.

Indicators worth alerting on: spikes in `Error from cloudfront`, direct origin
access that skips the edge (visible in origin/ALB/S3 logs but absent from CloudFront
logs), and requests whose `Host` is the default distribution domain.

## Remediation & Hardening

- **Bind the origin to the distribution.** For S3 origins use Origin Access Control
  (OAC) and make the bucket private. For custom origins (ALB/EC2/HTTP) require a
  secret custom header injected by CloudFront and validated by WAF, and restrict the
  origin's security group / firewall to the `com.amazonaws.global.cloudfront.origin-facing`
  managed prefix list.
- **Eliminate dangling references.** Decommission DNS records before deleting the
  distribution or origin; audit CNAMEs that point to `*.cloudfront.net` for unclaimed
  aliases and origins.
- **Disable / restrict the default domain** where possible by enforcing the expected
  `Host` at the origin and using viewer request logic to reject the raw distribution
  domain, so controls cannot be bypassed by addressing `dXXXX.cloudfront.net`.
- **Suppress origin leakage**: remove `Server`, framework, and internal headers via
  a response headers policy; return generic custom error pages.
- **Enforce WAF, geo-restriction, and signed URLs/cookies at the edge** and make
  sure equivalent controls (or origin lockdown) exist so they cannot be bypassed.
- **Tighten cache keys** to avoid caching authenticated or per-user responses and to
  resist cache poisoning/deception (normalize, include relevant headers/cookies in
  the cache key, do not cache by default for dynamic paths).
- **Enable standard or real-time access logs and WAF logging** and monitor for the
  indicators above.

## Tools

- DNS resolver / `dig` and passive DNS / DNS history services - identify CloudFront
  CNAMEs and dangling records.
- HTTP client (`curl`) - header inspection, cache-key probing, origin-bypass tests.
- Certificate Transparency search - enumerate aliases bound to ACM certificates.
- Web content discovery scanner - path/backup/source-control discovery through the
  edge.
- Subdomain-takeover detection tooling - flag dangling `*.cloudfront.net` aliases.

## References

- Amazon CloudFront Developer Guide - Introduction:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
- Distribution settings and values:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html
- Restricting access to an S3 origin (OAC/OAI):
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
  and https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RestrictingAccessToS3.html
- Distribution overview:
  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-overview.html
- S3 bucket / origin takeover background:
  https://hackingthe.cloud/aws/exploitation/s3-bucket-takeover/
