---
cstg_id: CSTG-AZURE-NETWORKING-UNAUTH
title: "AZURE Networking - Unauthenticated Access"
provider: azure
service: networking
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - dig
  - nslookup
  - nmap
  - masscan
  - httpx
  - subfinder
  - amass
  - dnsx
  - shodan
  - censys
  - whois
references:
  - "https://learn.microsoft.com/en-us/azure/dns/dns-overview"
  - "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
  - "https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-overview"
  - "https://learn.microsoft.com/en-us/azure/firewall/overview"
  - "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"
  - "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
  - "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
  - "https://hackingthe.cloud/azure/recon/"
license: CC BY-SA 4.0
---

## Summary

This page covers what an external party with **no Azure credentials** can discover and reach across the Azure networking surface. Azure exposes resources to the public Internet through public IP addresses, predictable DNS naming conventions on the `*.azure.com`, `*.cloudapp.azure.com`, `*.azurewebsites.net`, `*.azure-api.net` and related zones, and a large set of published service IP ranges. Because much of this surface is enumerable purely from outside, an attacker's first objective is to map an organization's externally reachable Azure footprint: public endpoints, exposed management/data-plane ports, weakly segmented services behind public IPs, and DNS records that point at deprovisioned resources (subdomain takeover).

The attacker objective at this phase is reconnaissance and opportunistic access: build an inventory of Internet-facing Azure assets owned by the target, identify open ports and services that Network Security Groups (NSGs) or Azure Firewall failed to restrict, find dangling DNS records that can be claimed, and locate management-plane exposure (RDP/SSH/WinRM/Kubernetes API/database ports) that should never face the public Internet.

## Prerequisites

- **Access level:** Unauthenticated. No Azure account, subscription, or token is required.
- **Permissions:** None. All techniques rely on publicly resolvable DNS, published Azure IP ranges, and unauthenticated port/banner probing.
- **Inputs that help:** Target domain names, brand/tenant names, known public IPs, and any leaked resource names (storage accounts, web apps, API Management instances) from code, certificates, or prior phases.

## Enumeration

### Discover Azure-owned IP space and service ranges

Microsoft publishes the full set of Azure datacenter and service IP ranges as downloadable JSON ("Azure IP Ranges and Service Tags - Public Cloud", plus separate files for US Gov, China, and Germany clouds). These map CIDR blocks to service tags (e.g., `AzureCloud`, `Storage`, `Sql`, `AppService`, `AzureFrontDoor`) and regions.

```bash
# Service Tag files are versioned; fetch the current download page, then the JSON
# (URL contains a date-stamped filename, e.g. ServiceTags_Public_YYYYMMDD.json)
curl -s -o ServiceTags_Public.json \
  "https://download.microsoft.com/download/.../ServiceTags_Public_YYYYMMDD.json"

# Find which service tag / region a target public IP belongs to
jq -r --arg ip "20.190.128.10" '
  .values[] | select(.properties.addressPrefixes != null) |
  . as $v | $v.properties.addressPrefixes[] |
  select(. | startswith("20.190")) | "\($v.name): \(.)"' ServiceTags_Public.json
```

Confirming a target IP falls in an Azure range (and which service tag) tells you what kind of resource you are likely facing before you send a single probe.

### DNS enumeration of Azure naming conventions

Azure assigns predictable, globally unique DNS names per service. Brute-forcing these against a target's brand name frequently reveals owned resources:

| Suffix | Service |
|---|---|
| `*.cloudapp.azure.com`, `*.<region>.cloudapp.azure.com` | Public IPs / classic VMs / load balancers |
| `*.azurewebsites.net` | App Service / Function Apps |
| `*.scm.azurewebsites.net` | App Service Kudu/SCM site |
| `*.blob.core.windows.net`, `*.file/queue/table.core.windows.net` | Storage accounts |
| `*.database.windows.net` | Azure SQL |
| `*.documents.azure.com` | Cosmos DB |
| `*.vault.azure.net` | Key Vault |
| `*.azure-api.net` | API Management |
| `*.servicebus.windows.net` | Service Bus / Event Hubs |
| `*.azurecontainer.io` | Container Instances |
| `*.azmk8s.io` | AKS API server |
| `*.trafficmanager.net` | Traffic Manager |
| `*.azureedge.net` | Azure CDN / Front Door classic |
| `*.azurefd.net` | Front Door |
| `*.redis.cache.windows.net` | Azure Cache for Redis |

```bash
# Passive subdomain discovery against the target's owned domains
subfinder -d target.com -all -silent | dnsx -silent -a -resp

# Active brute force against Azure naming conventions for a brand keyword
for s in azurewebsites.net blob.core.windows.net database.windows.net \
         vault.azure.net azure-api.net azmk8s.io cloudapp.azure.com; do
  for w in target targetcorp target-prod target-dev targetapi; do
    dig +short "$w.$s"
  done
done

# Resolve CNAME chains to spot Azure backends behind vanity domains
dig +noall +answer www.target.com CNAME
```

### Port and service discovery

Once Azure-owned IPs are confirmed, probe them for exposed ports. NSGs and Azure Firewall are the controls expected to limit this; gaps show up as reachable management/data ports.

```bash
# Fast wide sweep across confirmed Azure CIDRs / hosts
masscan -p1-65535 --rate 2000 -iL azure_targets.txt -oG sweep.gnmap

# Targeted service/version detection on responders
nmap -sV -sC -Pn -p 22,80,443,1433,3306,3389,5432,5985,5986,6379,10250,16443 \
     -iL responders.txt -oA azure_svc

# HTTP probing + tech fingerprint across discovered web endpoints
httpx -l hosts.txt -title -tech-detect -status-code -web-server -tls-probe
```

Common ports that indicate misconfiguration when reachable from the Internet: `3389` (RDP), `22` (SSH), `5985/5986` (WinRM), `1433/3306/5432` (databases), `6379` (Redis), `10250/10255` (kubelet), `2375/2376` (Docker), and `443` against an AKS `*.azmk8s.io` API server.

### Public datasets

Internet-wide scan datasets reveal exposure without your own probes touching the target:

```bash
# Shodan: Azure-hosted services for an org
shodan search 'org:"Microsoft Azure" hostname:target.com'
shodan search 'ssl.cert.subject.cn:target.com'

# Censys: certificates and hosts referencing the target
censys search 'services.tls.certificates.leaf_data.subject.common_name: target.com'
```

TLS certificate transparency logs (`crt.sh`) frequently leak internal hostnames, App Service names, and API Management gateway names before they are otherwise discoverable.

### Subdomain takeover candidates

Enumerate the target's DNS records and flag any CNAME pointing to an Azure resource name that no longer resolves to a live resource:

```bash
# Flag CNAMEs to Azure backends that return NXDOMAIN / SERVFAIL at the backend
for h in $(cat target_subdomains.txt); do
  cname=$(dig +short "$h" CNAME)
  case "$cname" in
    *azurewebsites.net.|*cloudapp.azure.com.|*trafficmanager.net.|\
    *blob.core.windows.net.|*azureedge.net.|*azurefd.net.|*azure-api.net.)
      if ! dig +short "$cname" | grep -q .; then
        echo "DANGLING: $h -> $cname"
      fi ;;
  esac
done
```

## Misconfigurations & Findings

- **Management ports exposed to `0.0.0.0/0`.** RDP (3389), SSH (22), and WinRM (5985/5986) reachable from the public Internet via an NSG rule allowing source `Internet` / `Any`. This is the single most common high-severity Azure network finding and the primary vector for brute force and exploitation.
- **Database/cache data-plane ports public.** Azure SQL (1433), PostgreSQL/MySQL Flexible Server (5432/3306), and Redis (6379) reachable from the Internet because the server firewall has an `Allow Azure services` rule or a `0.0.0.0 - 255.255.255.255` range, or because a VM-hosted database sits behind a public IP with a permissive NSG.
- **AKS API server publicly reachable.** A `*.azmk8s.io` endpoint with no authorized-IP ranges configured exposes the Kubernetes control plane to credential-stuffing and known CVE exploitation.
- **Dangling DNS / subdomain takeover.** A CNAME or A record still points at an Azure resource (App Service, Traffic Manager profile, storage static site, Front Door, public IP) that has been deleted or whose unique name was released. An attacker who recreates a resource with that exact name claims the subdomain, enabling phishing, cookie theft, and content injection under the target's brand.
- **Overly broad public IP assignment.** Internal-only workloads (jump hosts, build agents, admin panels) given Standard public IPs with permissive NSGs instead of being fronted by Azure Bastion, a VPN, or Private Link.
- **Information-leaking banners and error pages.** App Service default pages, Kudu/SCM endpoints (`*.scm.azurewebsites.net`) reachable without authentication enforcement, and verbose server headers disclosing stack and region.
- **No DDoS / WAF in front of public IPs.** Public endpoints directly exposed rather than behind Azure Front Door / Application Gateway with WAF, leaving L7 surface unprotected.

## Exploitation

Unauthenticated exploitation at the network layer is opportunistic; the network-plane misconfiguration is the door, and the service behind it is the target.

- **Exposed RDP/SSH/WinRM:** password spraying and credential stuffing against discovered management ports; reuse of breached credentials; exploitation of unpatched services. A single compromised VM credential becomes the pivot into the VNet, after which lateral movement and credential harvesting (including the Instance Metadata Service at `169.254.169.254` for managed identity tokens) become possible. See [Enumeration phase](../02-services/azure-networking-enum.md) for what that pivot yields once inside.
- **Exposed databases/Redis:** direct authentication attempts against `*.database.windows.net` (1433) or open Redis (6379), which historically accepts unauthenticated commands when `requirepass` is unset, allowing data read and, in some deployments, command execution.
- **Subdomain takeover:** register a new Azure resource using the released unique name the dangling record points to (e.g., create an App Service named `oldapp` so `oldapp.azurewebsites.net` resolves to attacker-controlled content). The target's subdomain then serves attacker content, enabling session-cookie capture for cookies scoped to the parent domain, OAuth redirect abuse, and credible phishing.
- **AKS API server:** anonymous-auth or weak-RBAC clusters reachable over the Internet allow enumeration of the cluster and, where misconfigured, workload and secret access.

## Detection & Logging

- **NSG flow logs / VNet flow logs** record allowed and denied connections (source IP, destination, port, action). Inbound traffic on management ports from unexpected source ranges, or large fan-out scan patterns from a single external IP, indicate reconnaissance.
- **Azure Activity Logs** capture control-plane changes such as NSG rule creation, public IP allocation, and resource creation. A newly created App Service or storage account whose name matches a previously deleted resource can indicate a takeover in progress.
- **Azure Firewall and Application Gateway/WAF logs** record allowed/blocked requests, signature hits, and rate anomalies for L7 surface.
- **Entra ID sign-in logs** surface the downstream effect of exposed endpoints: spikes in failed sign-ins, credential-stuffing patterns, and sign-ins from anomalous IPs following discovery of an exposed management endpoint.
- **Microsoft Defender for Cloud** generates managed alerts for exposed management ports (Just-In-Time recommendations), public-facing databases, network reconnaissance patterns, and possible subdomain takeover (dangling DNS) findings.
- **Azure DNS analytics / DNS query logging** can reveal brute-force resolution attempts against tenant naming conventions.

## Remediation & Hardening

- **Eliminate public management exposure.** Remove inbound NSG rules allowing `Internet`/`Any` to 22/3389/5985/5986. Use Azure Bastion for browser-based RDP/SSH, Just-In-Time VM access in Defender for Cloud, or a VPN/ExpressRoute path. Default-deny inbound and scope allowed sources to known CIDRs.
- **Make data planes private.** Use Private Endpoints / Private Link for PaaS data services (SQL, Storage, Cosmos, Key Vault), disable public network access where possible, and remove the "Allow Azure services" firewall exception unless explicitly required.
- **Restrict the AKS control plane.** Enable API server authorized IP ranges or deploy a private cluster; never leave the API server open to `0.0.0.0/0`.
- **Prevent subdomain takeover.** Remove DNS records before deprovisioning the resource they point to; prefer alias records for Azure resources (which Azure refuses to leave dangling); run continuous dangling-DNS scanning; reserve critical resource names.
- **Front public surface with managed protection.** Place HTTP/S endpoints behind Azure Front Door / Application Gateway with WAF and enable Azure DDoS Protection Standard on public IPs.
- **Minimize public IPs.** Audit and remove unnecessary public IP assignments; default to private addressing with controlled egress via NAT Gateway / Azure Firewall.
- **Suppress information leakage.** Disable default/landing pages, restrict SCM/Kudu access, and strip verbose server and version headers.

## Tools

- **DNS & passive recon:** `dig`, `nslookup`, `subfinder`, `amass`, `dnsx`, certificate-transparency search (`crt.sh`).
- **Port/service discovery:** `nmap`, `masscan`, `httpx`.
- **Internet-wide datasets:** Shodan, Censys.
- **Azure data:** published Azure IP Ranges and Service Tags JSON; `whois` for IP ownership confirmation.
- **Subdomain takeover:** dedicated dangling-DNS scanners that fingerprint Azure backend signatures.

## References

- [Azure DNS overview](https://learn.microsoft.com/en-us/azure/dns/dns-overview)
- [Prevent dangling DNS / subdomain takeover](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)
- [Network Security Groups overview](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Azure Load Balancer overview](https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-overview)
- [Azure Firewall overview](https://learn.microsoft.com/en-us/azure/firewall/overview)
- [Private Endpoint overview](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview)
- [Public IP addresses](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
- [Azure Bastion overview](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)
- [Azure IP Ranges and Service Tags - Public Cloud](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
- [hackingthe.cloud - Azure recon](https://hackingthe.cloud/azure/recon/)
