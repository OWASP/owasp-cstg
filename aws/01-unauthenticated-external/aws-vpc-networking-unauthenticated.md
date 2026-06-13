---
cstg_id: CSTG-AWS-VPC-NETWORKING-UNAUTH
title: "AWS Vpc Networking - Unauthenticated Access"
provider: aws
service: vpc-networking
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - nmap
  - masscan
  - dnsx
  - amass
  - shodan
  - censys
  - httpx
  - awsipranges
license: CC BY-SA 4.0
references:
  - "https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html"
  - "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"
  - "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"
  - "https://ip-ranges.amazonaws.com/ip-ranges.json"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html"
  - "https://docs.aws.amazon.com/AmazonVPC/latest/PrivateLink/what-is-privatelink.html"
  - "https://hackingthe.cloud/aws/enumeration/enum_iam_user_role/"
---

## Summary

Amazon Virtual Private Cloud (VPC) is the network isolation boundary for most AWS workloads. Every EC2 instance, container task, load balancer, RDS database, and Lambda ENI lives inside a subnet of a VPC, and its reachability from the public Internet is governed by a layered set of controls: the presence of an Internet Gateway (IGW) on the route table, a public IP or Elastic IP (EIP), security group rules (stateful, instance-level), and network ACLs (stateless, subnet-level).

This page covers what an **unauthenticated** external party can learn and reach without any AWS credentials. The objective at this phase is to map the externally exposed surface of an organisation's VPC networking - public IP ranges in use, internet-facing hosts and ports, exposed management and data-plane services, DNS that reveals internal naming, and misconfigured network controls that leave services reachable that should not be. This builds the target list before any authenticated phase. Cross-reference [aws-vpc-networking-enum.md](../02-services/aws-vpc-networking-enum.md) for the credentialed view of the same network topology.

## Prerequisites

- No AWS credentials of any kind. All techniques here operate against publicly routable IPs, DNS, and AWS's own public metadata (the published IP-range document), or against services the target has chosen to expose.
- A list of seed identifiers for the target: registered domains, brand names, ASN/owned CIDR blocks, known public IPs, and any product/SaaS hostnames.
- Only externally observable behaviour is in scope. No interaction with the AWS control plane (the `ec2`/`elasticloadbalancing` APIs) is possible without credentials.

## Enumeration

### AWS public IP-range correlation

AWS publishes the full list of IP ranges it owns, tagged by region and service. This lets an external party confirm that a given IP belongs to AWS, which region it is in, and which service category (EC2, CLOUDFRONT, ROUTE53_HEALTHCHECKS, S3, EC2_INSTANCE_CONNECT, GLOBALACCELERATOR, etc.) it is allocated to.

```bash
# Pull the authoritative ranges document (no auth, no rate limit of concern)
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o aws-ip-ranges.json

# Which AWS region/service owns a discovered IP?
jq -r '.prefixes[] | select(.ip_prefix=="<cidr>") | "\(.region) \(.service)"' aws-ip-ranges.json

# All EC2 prefixes in a region (candidate space for the target's instances/EIPs)
jq -r '.prefixes[] | select(.region=="ap-southeast-2" and .service=="EC2") | .ip_prefix' aws-ip-ranges.json
```

Tooling such as `awsipranges` wraps this document for fast membership lookups.

### Passive DNS and certificate transparency

Public DNS frequently exposes the structure of a VPC deployment: `ec2-<a-b-c-d>.<region>.compute.amazonaws.com` reverse names reveal the region and the public IP of an instance; `*.elb.<region>.amazonaws.com` and `*.<region>.elb.amazonaws.com` names indicate Elastic Load Balancers; `*.rds.amazonaws.com` indicates a publicly resolvable database endpoint; `*.vpce.amazonaws.com` indicates VPC endpoint (PrivateLink) services.

```bash
# Subdomain discovery from CT logs and passive sources
amass enum -passive -d target.com -o amass.txt
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u

# Resolve and keep only names that point into AWS space
dnsx -l amass.txt -a -resp-only | sort -u > resolved-ips.txt

# Reverse lookups expose AWS-managed hostnames (region + public IP leak)
dnsx -l resolved-ips.txt -ptr -resp-only
```

AWS-managed reverse names directly disclose the instance public IP and region (e.g. `ec2-3-25-10-20.ap-southeast-2.compute.amazonaws.com`), and ELB/RDS names confirm internet-facing managed services.

### Active port and service scanning

Once candidate IPs are identified (resolved from DNS, found via reverse lookups, or attributed via the IP-range document), scan for reachable ports. Reachability here is the net effect of route tables (IGW present), a public IP/EIP, security groups, and network ACLs - none of which are individually visible from outside, only their combined result.

```bash
# Fast sweep of a candidate range
masscan -p1-65535 --rate 1000 -iL resolved-ips.txt -oG masscan.gnmap

# Service/version detail on responding hosts
nmap -sV -sC -Pn -iL responding-hosts.txt -oA nmap-aws

# HTTP(S) probing and tech fingerprint for web tiers behind ELB/ALB
httpx -l resolved-ips.txt -title -tech-detect -status-code -tls-grab
```

### Internet-scan databases (zero-touch)

Shodan and Censys index the IPv4 space continuously; querying them reveals open ports, banners, and TLS certificates of the target's AWS hosts without sending a single packet from the tester.

```bash
shodan search 'ssl.cert.subject.cn:"target.com" org:"Amazon"'
shodan host <public-ip>
# Censys: services.tls.certificates.leaf_data.subject.common_name: target.com and autonomous_system.name: AMAZON
```

## Misconfigurations & Findings

- **Management ports exposed to 0.0.0.0/0** - SSH (22), RDP (3389), WinRM (5985/5986) reachable from the Internet because a security group has an inbound rule for `0.0.0.0/0`. This is the single most common VPC finding and the primary external foothold vector.
- **Data-plane services exposed** - database and cache ports reachable publicly: MySQL/Aurora (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), Memcached (11211), Elasticsearch/OpenSearch (9200/9300), MSSQL (1433). Often the result of a public subnet + permissive SG, or an RDS instance with "Publicly accessible" enabled.
- **Internal/admin web apps internet-facing** - dashboards, CI runners, Kubernetes API (6443), Docker (2375/2376), Kibana, Grafana, Jenkins, etcd (2379) reachable directly or via an internet-facing load balancer with no auth.
- **Overly permissive network ACLs** - a subnet NACL allowing all inbound, masking the intent that only specific SGs should be reachable, or an `ALLOW` rule numbered below a later `DENY`.
- **DNS leakage of internal topology** - internal hostnames, regions, environment names (`dev-`, `uat-`, `internal-`) published in public DNS or CT logs.
- **Orphaned / dangling DNS records** - a CNAME or A record still pointing at a released EIP or a deregistered ELB/CloudFront/S3 endpoint, enabling subdomain takeover when the underlying AWS resource is re-allocated to another tenant.
- **EIP / shared-tenancy reuse** - released Elastic IPs are returned to a regional pool; a record pointing at a now-released EIP may resolve to an unrelated tenant.

## Exploitation

External, unauthenticated exploitation at the network layer is about turning reachability into access. The combined network controls are opaque from outside, so the tester relies on observed open ports and service behaviour.

1. **Direct service compromise.** A reachable service with weak/default credentials or a known CVE (e.g. an exposed Redis with no `requirepass`, an unauthenticated Jenkins, an MSSQL with `sa`/blank) is exploited directly. Compromise of an EC2 host inside the VPC pivots the tester from external-unauthenticated to internal, where the host's IAM instance profile and the VPC's internal reachability come into play - see [aws-vpc-networking-enum.md](../02-services/aws-vpc-networking-enum.md).
2. **Subdomain takeover.** Where a public DNS record dangles to a released AWS resource, claim the underlying resource (re-create an S3 bucket of the dangling name, register an ELB/CloudFront alias, or acquire the released EIP) to serve content under the victim's trusted hostname - usable for phishing, cookie theft, and bypassing same-site trust.
3. **Reachable internal app abuse.** An internet-facing admin panel or API with no authentication is used to read data, trigger actions, or obtain credentials that bridge into the account.
4. **TLS/certificate intelligence.** Certificates harvested during scanning enumerate further internal hostnames (SANs), confirming additional targets to resolve and probe.

No step here uses AWS APIs; all leverage the service exposure created by VPC networking misconfiguration.

## Detection & Logging

- **CloudTrail (control plane):** The unauthenticated external activity above does not appear in CloudTrail because no AWS API is called. CloudTrail will, however, record the *configuration changes* that created the exposure - `AuthorizeSecurityGroupIngress`, `ModifyInstanceAttribute`, `AllocateAddress`/`AssociateAddress`, `CreateRoute`, `ReplaceNetworkAclEntry`, `ModifyDBInstance` (PubliclyAccessible). Reviewing these is how the exposure is attributed after the fact.
- **VPC Flow Logs:** Capture the inbound connection attempts (source IP, port, ACCEPT/REJECT) against ENIs, subnets, or the whole VPC. Scanning and probing show as bursts of REJECT (blocked) and ACCEPT (reachable) records and are the primary network-layer detection signal.
- **GuardDuty:** Managed findings such as `Recon:EC2/PortProbeUnprotectedPort`, `Recon:EC2/Portscan`, and `UnauthorizedAccess:EC2/SSHBruteForce` are generated from Flow Logs/DNS logs when exposed ports are probed or brute-forced.
- **Route 53 Resolver query logs / DNS firewall:** Surface lookups of internal names if the target operates its own resolver logging.
- **ELB / CloudFront / WAF logs:** Record the HTTP probing of internet-facing web tiers.

## Remediation & Hardening

- Default-deny inbound. No security group should allow `0.0.0.0/0` (or `::/0`) to management ports (22/3389/5985/5986) or data ports (3306/5432/6379/27017/9200/1433, etc.). Restrict to specific CIDRs, or remove public ingress entirely and use SSM Session Manager / EC2 Instance Connect / a bastion.
- Keep databases and internal services in private subnets with no route to an IGW; set RDS "Publicly accessible" to false; expose only intended tiers via load balancers.
- Use VPC endpoints (PrivateLink) and private hosted zones so internal service traffic and naming never traverse or leak to the public Internet.
- Prevent dangling DNS: decommission DNS records as part of resource teardown; periodically reconcile Route 53/external DNS against live AWS resources; avoid reusing released EIPs for sensitive records.
- Enforce guardrails: an SCP or AWS Config rule (`vpc-sg-open-only-to-authorized-ports`, `restricted-ssh`, `restricted-common-ports`) and Security Hub controls to flag open SGs automatically; require security groups by default to have no inbound rules.
- Enable VPC Flow Logs and GuardDuty across all regions; alert on inbound ACCEPTs to sensitive ports and on port-scan findings.

## Tools

- `nmap`, `masscan` - port and service discovery against candidate ranges.
- `dnsx`, `amass` - DNS resolution, reverse lookups, subdomain enumeration.
- `httpx` - HTTP probing, title/tech/TLS grabbing of web tiers.
- `shodan`, `censys` - passive Internet-scan databases for ports, banners, certificates.
- `awsipranges` and the published `ip-ranges.json` document - attribute IPs to AWS region/service.

## References

- AWS - What is Amazon VPC: https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html
- AWS - Security groups for your VPC: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
- AWS - Network ACLs: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
- AWS - AWS IP address ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
- AWS - Elastic IP addresses: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html
- AWS - What is AWS PrivateLink: https://docs.aws.amazon.com/AmazonVPC/latest/PrivateLink/what-is-privatelink.html
- Hacking the Cloud - AWS enumeration: https://hackingthe.cloud/aws/enumeration/enum_iam_user_role/
