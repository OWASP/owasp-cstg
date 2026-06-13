---
cstg_id: CSTG-AWS-ROUTE53-ENUM
title: "AWS Route53 - Enumeration"
provider: aws
service: route53
phase: services
required_access: read-only-audit
required_permissions:
  - route53:ListHostedZones
  - route53:ListResourceRecordSets
  - route53:GetHostedZone
  - route53:ListHealthChecks
  - route53:ListQueryLoggingConfigs
  - route53:ListTrafficPolicies
  - route53resolver:ListResolverEndpoints
  - route53resolver:ListResolverRules
  - route53domains:ListDomains
tools:
  - AWS CLI
  - AWS SDK
  - DNS resolver / dig
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html
  - https://hackingthe.cloud/aws/exploitation/route53/
  - https://aws.amazon.com/blogs/security/how-to-automatically-prevent-amazon-s3-bucket-takeover/
license: CC BY-SA 4.0
---

## Summary

Amazon Route 53 is a managed authoritative DNS service, domain registrar, and health-checking platform. From a security-testing perspective it sits at the intersection of identity (who controls DNS records), exposure (what hostnames resolve to what), and trust (DNS is used to validate TLS certificates, route email, and bootstrap service discovery). Enumeration of Route 53 establishes the full DNS surface a principal can observe or influence: public and private hosted zones, every resource record set, resolver endpoints that bridge VPC and on-premises DNS, query-logging configurations, and the registrar-level domain inventory.

Route 53 is global (records are not regionally scoped), although the Resolver service (endpoints, rules, query logging at the VPC level) and DNS Firewall are regional. Read-only enumeration is high value: DNS records frequently reveal internal naming conventions, staging and pre-production environments, third-party SaaS integrations (via `CNAME` and `TXT` records), email security posture (`SPF`/`DKIM`/`DMARC`), and dangling records that point at deprovisioned cloud resources - the precondition for subdomain takeover. This page covers authorized, read-only discovery from the AWS control plane (API/CLI) as well as observational DNS enumeration from the data plane.

## Prerequisites

- Valid AWS credentials for the target account (an access key pair, an STS session, or an assumed role) with at least the `route53:List*`/`route53:Get*` describe permissions, or membership in a managed read-only/audit policy such as `SecurityAudit` or `ViewOnlyAccess`.
- For Resolver and DNS Firewall enumeration, the `route53resolver:List*`/`Get*` permissions in each region under test.
- For registrar enumeration, `route53domains:*List*`/`*Get*` (the Route 53 Domains API endpoint is hosted in `us-east-1`).
- Data-plane (resolver) enumeration requires no AWS credentials at all - any internet-connected resolver can query public hosted zones; private hosted zone records require resolution from inside an associated VPC.

## Enumeration

### Hosted zones

List every hosted zone the principal can see, distinguishing public from private. The `Config.PrivateZone` flag and the `ResourceRecordSetCount` are the most useful fields.

```bash
aws route53 list-hosted-zones \
  --query "HostedZones[].{Id:Id,Name:Name,Private:Config.PrivateZone,Records:ResourceRecordSetCount}" \
  --output table

# Detail for one zone (includes VPC associations for private zones)
aws route53 get-hosted-zone --id Z0123456789ABCDEFGHIJ
```

`get-hosted-zone` on a private zone returns the `VPCs` array - the VPC IDs and regions the zone is associated with. This maps the private DNS namespace to specific network segments and is valuable for understanding internal topology. To enumerate which private zones are visible from a given VPC:

```bash
aws route53 list-hosted-zones-by-vpc --vpc-id vpc-0abc123 --vpc-region us-east-1
```

You can also locate a zone by exact domain name:

```bash
aws route53 list-hosted-zones-by-name --dns-name corp.example.com.
```

### Resource record sets

Dump every record in a zone. This is the core of DNS enumeration - it reveals the full namespace without relying on guessing or brute force.

```bash
aws route53 list-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ \
  --query "ResourceRecordSets[].{Name:Name,Type:Type,TTL:TTL,Values:ResourceRecords[].Value,Alias:AliasTarget.DNSName}" \
  --output table
```

Records to scrutinise:

- **`A` / `AAAA` / `ALIAS` records** pointing at Elastic IPs, CloudFront distributions, ELB/ALB/NLB DNS names, S3 website endpoints, API Gateway, Elastic Beanstalk, or App Runner. Alias records embed the target's hosted-zone ID and resource type. Records whose alias or value points at a resource that no longer exists are candidates for **subdomain takeover** (see CSTG subdomain-takeover material and the Misconfigurations section below).
- **`CNAME` records** pointing at third-party SaaS (e.g. `*.github.io`, `*.herokudns.com`, `*.azurewebsites.net`, `*.cloudfront.net`, custom-domain endpoints for marketing, support, status, or CDN vendors). These reveal the vendor supply chain and are the most common takeover vector.
- **`TXT` records** - SPF (`v=spf1 ...`), DKIM, DMARC (`_dmarc`), domain-verification tokens for SaaS onboarding (Google, Microsoft 365, Atlassian, etc.), and ACME (`_acme-challenge`) records. These disclose which external services are integrated and the email-spoofing posture.
- **`MX` records** - mail routing (e.g. to Google Workspace, Microsoft 365, or a self-hosted gateway).
- **`NS` and `SOA` records** - delegation. Child `NS` records that delegate a subdomain to a different name server are a takeover surface if the delegated zone is deleted but the delegation remains.
- **`SRV` / naming conventions** - internal service-discovery records and host names that leak environment structure (`dev-`, `staging-`, `internal-`, `vpn-`, `jenkins-`, `db-`).

For very large zones the API paginates; iterate with `--starting-token`/`StartRecordName`. Programmatic pagination across all zones:

```bash
for z in $(aws route53 list-hosted-zones --query "HostedZones[].Id" --output text); do
  echo "== zone $z =="
  aws route53 list-resource-record-sets --hosted-zone-id "$z" --output json
done
```

### Health checks, traffic policies, and routing

Health checks reveal monitored endpoints (often the same hostnames as production targets) and the failover topology:

```bash
aws route53 list-health-checks \
  --query "HealthChecks[].{Id:Id,Type:HealthCheckConfig.Type,Target:HealthCheckConfig.FullyQualifiedDomainName,IP:HealthCheckConfig.IPAddress,Port:HealthCheckConfig.Port,Path:HealthCheckConfig.ResourcePath}" \
  --output table

aws route53 list-traffic-policies
aws route53 list-traffic-policy-instances
```

Weighted, latency, geolocation, and failover routing policies appear in the record sets themselves (`Weight`, `Region`, `GeoLocation`, `Failover`, `SetIdentifier` fields) and disclose multi-region and blue/green deployment structure.

### Query logging configuration

Public-zone DNS query logging streams to CloudWatch Logs. Enumerating the configs both tells you which zones are monitored (relevant to detection planning) and where the logs live:

```bash
aws route53 list-query-logging-configs \
  --query "QueryLoggingConfigs[].{Id:Id,Zone:HostedZoneId,Log:CloudWatchLogsLogGroupArn}"
```

### Route 53 Resolver (regional)

Resolver endpoints bridge DNS resolution between VPCs and external/on-premises networks. Inbound endpoints accept DNS from on-prem; outbound endpoints forward VPC queries to external resolvers per resolver rules. They reveal hybrid-network DNS architecture and potential exfiltration paths.

```bash
# Iterate per region
aws route53resolver list-resolver-endpoints --region us-east-1 \
  --query "ResolverEndpoints[].{Id:Id,Name:Name,Direction:Direction,Status:Status,IpCount:IpAddressCount}"

aws route53resolver list-resolver-endpoint-ip-addresses --resolver-endpoint-id rslvr-in-0abc123 --region us-east-1

# Forwarding rules: which domains forward where
aws route53resolver list-resolver-rules --region us-east-1 \
  --query "ResolverRules[].{Id:Id,Name:Name,Domain:DomainName,Type:RuleType,Targets:TargetIps[].Ip}"

aws route53resolver list-resolver-rule-associations --region us-east-1
aws route53resolver list-resolver-query-log-configs --region us-east-1
```

### Route 53 Resolver DNS Firewall (regional)

```bash
aws route53resolver list-firewall-rule-groups --region us-east-1
aws route53resolver list-firewall-domain-lists --region us-east-1
aws route53resolver list-firewall-rule-group-associations --region us-east-1
```

The firewall domain lists and rules disclose which destinations are blocked or allowed - useful for understanding egress controls and existing DNS-tunneling defences.

### Registrar (Route 53 Domains)

If domains are registered through AWS, the registrar API exposes the domain portfolio, expiry, transfer-lock status, auto-renew, and the registrant/admin/tech contact details (often PII).

```bash
aws route53domains list-domains --region us-east-1
aws route53domains get-domain-detail --domain-name example.com --region us-east-1
aws route53domains list-operations --region us-east-1
```

A disabled transfer lock or expiring registration is a domain-hijack risk; contact PII may be in scope for privacy findings.

### Data-plane / observational DNS enumeration (no AWS credentials)

Public hosted zones are queryable by anyone. Without AWS access you can still characterise the namespace:

```bash
# Authoritative name servers and SOA
dig +short NS example.com
dig SOA example.com

# Test for zone transfer (almost always refused on Route 53, but confirm)
dig AXFR example.com @ns-123.awsdns-45.com

# Record types of interest
dig TXT example.com +short
dig MX example.com +short
dig +short CNAME status.example.com
```

Combine with passive sources (certificate transparency logs, passive DNS, public DNS datasets) and controlled subdomain brute-forcing to recover host names that the control-plane API would only reveal with credentials. Cross-reference resolved targets against deprovisioned cloud resources to flag takeover candidates.

## Misconfigurations & Findings

- **Dangling DNS records (subdomain takeover surface).** `CNAME`/`ALIAS`/`A` records pointing at cloud resources (S3 buckets, CloudFront distributions, Elastic Beanstalk, API Gateway custom domains, ELB DNS names, Elastic IPs, App Runner, GitHub Pages, and many SaaS vendors) that have been deleted or released. An attacker who can register/claim the now-unowned target controls the hostname. Enumerate every alias and external `CNAME`, then verify the target still exists and is owned by the same party.
- **Overly broad read access.** Principals or roles with `route53:List*`/`Get*` (or `route53:*`) beyond what their function requires expose the full internal namespace, private-zone topology, and resolver/forwarding architecture.
- **Private hosted zone data leakage.** Internal host names, database endpoints, and service-discovery records in private zones become readable to any principal with Route 53 read access, regardless of network segmentation.
- **Missing query logging.** Public hosted zones without query logging, or VPCs without Resolver query logging, leave DNS abuse (tunneling, exfiltration, takeover validation) unobserved.
- **Weak email-security records.** Missing or permissive SPF (`+all`/`?all`), absent DKIM, or `p=none` DMARC discoverable via `TXT` records indicate spoofable domains.
- **Stale delegations.** Child `NS` records delegating a subdomain to a zone that no longer exists (lame delegation) - a takeover vector.
- **Registrar weaknesses.** Disabled domain transfer lock, disabled auto-renew, or imminent expiry visible via the Domains API.

## Detection & Logging

Route 53 control-plane API calls are recorded by **CloudTrail** as management events (event source `route53.amazonaws.com`, `route53resolver.amazonaws.com`, and `route53domains.amazonaws.com`). Read/enumeration activity surfaces as events such as `ListHostedZones`, `ListResourceRecordSets`, `GetHostedZone`, `ListHealthChecks`, `ListResolverEndpoints`, and `ListResolverRules`. Note that Route 53 is a global service: its CloudTrail events are delivered in `us-east-1`.

Detection guidance:

- Alert on bursts of `ListResourceRecordSets` / `ListHostedZones` from unusual principals, especially newly created access keys or roles assumed from atypical sources - this pattern indicates namespace harvesting.
- Treat `route53domains` API reads (`GetDomainDetail`, `ListDomains`) from non-administrative principals as suspicious.
- DNS query content is not in CloudTrail; enable **Route 53 public DNS query logging** (per hosted zone, to CloudWatch Logs) and **Resolver query logging** (per VPC, to CloudWatch Logs, S3, or Kinesis Firehose) to observe data-plane resolution.

## Remediation & Hardening

- Apply least privilege: scope Route 53 read permissions to the principals and zones that need them; avoid wildcard `route53:*` and broad managed read policies for non-audit identities.
- Separate public and private DNS responsibilities; restrict who can read private hosted zones.
- Enable DNS query logging on public hosted zones and Resolver query logging on VPCs, and ship to a monitored, retention-controlled destination.
- Continuously inventory `CNAME`/`ALIAS`/`A` records and validate that each target still exists and is owned - remove records when the backing resource is deprovisioned. (See the Persistence and Privilege Escalation pages for the takeover and modification angles.)
- Enforce strong email-authentication records (`SPF -all`, DKIM, `DMARC p=reject`).
- Enable the domain transfer lock and auto-renew on registered domains; protect registrant contact PII.

## Tools

- AWS CLI (`aws route53`, `aws route53resolver`, `aws route53domains`) and AWS SDKs for control-plane enumeration.
- General cloud-enumeration frameworks capable of describing Route 53 resources across accounts/regions.
- DNS tooling (`dig`, resolver libraries), certificate-transparency and passive-DNS data sources, and subdomain-takeover detection utilities for data-plane analysis.

## References

- AWS Route 53 API Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html
- AWS Route 53 Developer Guide: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html
- Route 53 DNS failover and health checks: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html
- Hacking the Cloud - Route 53: https://hackingthe.cloud/aws/exploitation/route53/
- How to automatically prevent S3 bucket takeover: https://aws.amazon.com/blogs/security/how-to-automatically-prevent-amazon-s3-bucket-takeover/
