---
cstg_id: CSTG-AZURE-NETWORKING-ENUM
title: "AZURE Networking - Enumeration"
provider: azure
service: networking
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Network/virtualNetworks/read"
  - "Microsoft.Network/virtualNetworks/subnets/read"
  - "Microsoft.Network/networkSecurityGroups/read"
  - "Microsoft.Network/networkInterfaces/read"
  - "Microsoft.Network/publicIPAddresses/read"
  - "Microsoft.Network/loadBalancers/read"
  - "Microsoft.Network/applicationGateways/read"
  - "Microsoft.Network/azureFirewalls/read"
  - "Microsoft.Network/routeTables/read"
  - "Microsoft.Network/virtualNetworkGateways/read"
  - "Microsoft.Network/connections/read"
  - "Microsoft.Network/privateEndpoints/read"
  - "Microsoft.Network/privateDnsZones/read"
  - "Microsoft.Network/networkWatchers/read"
  - "Microsoft.Network/bastionHosts/read"
  - "Microsoft.Network/dnsZones/read"
tools:
  - az CLI
  - az network nic list-effective-nsg
  - az network watcher
  - Azure Resource Graph
  - PowerZure
  - AzureHound
  - ScoutSuite
  - Stormspotter
references:
  - "https://learn.microsoft.com/en-us/cli/azure/network"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview"
  - "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview"
  - "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-only enumeration of Azure networking resources from inside a tenant or subscription. With a low-privilege role such as **Reader** (or **Network Contributor** scoped to read), an analyst can map the full virtual-network topology: VNets and subnets, Network Security Groups (NSGs) and their effective rules, network interfaces and the resources they attach to, public IP assignments, load balancers, application gateways, Azure Firewall, route tables (UDRs), VNet peerings, VPN/ExpressRoute gateways, private endpoints, private DNS zones, and Bastion hosts.

The objective is to build an accurate model of how the network is segmented and where the trust boundaries actually fall, as opposed to how they are documented. From that model you identify reachability between subnets and tenants (peering and forced tunneling), exposed management/data ports (effective NSG rules), public IPs that should be private, private endpoints that reveal which PaaS services exist, and gateway connections that bridge into on-premises or partner networks. This enumeration directly informs the lateral-movement and reachability analysis used in later phases.

## Prerequisites

- **Access level:** Authenticated, read-only audit. A valid Entra ID identity (user, service principal, or managed identity) with an Azure RBAC role granting `Microsoft.Network/*/read` over the target scope. Built-in **Reader** is sufficient for almost all enumeration below; **Network Watcher** reads and effective-rule queries may require `Microsoft.Network/networkWatchers/*` and `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action`.
- **Permissions:** The `read` actions listed in the frontmatter. Effective NSG/route queries additionally require the corresponding `.../action` data-plane permissions on the NIC.
- **Context:** Subscription ID(s) and resource group names, obtainable via `az account` and Resource Graph.

## Enumeration

### Establish context

```bash
az login            # interactive, or: az login --service-principal -u <appId> -p <secret> --tenant <tid>
az account list -o table
az account show
SUB=$(az account show --query id -o tsv)
```

### Virtual networks, subnets, and peerings

```bash
# All VNets across the subscription, with address space and subnets
az network vnet list -o table
az network vnet list --query \
  "[].{name:name,rg:resourceGroup,space:addressSpace.addressPrefixes,subnets:subnets[].name}"

# Subnet detail incl. associated NSG, route table, delegations, service endpoints
az network vnet subnet list -g <rg> --vnet-name <vnet> \
  --query "[].{name:name,prefix:addressPrefix,nsg:networkSecurityGroup.id,rt:routeTable.id,\
  delegations:delegations[].serviceName,svcEndpoints:serviceEndpoints[].service}"

# VNet peerings reveal cross-VNet (and cross-subscription/cross-tenant) reachability
az network vnet peering list -g <rg> --vnet-name <vnet> \
  --query "[].{name:name,remote:remoteVirtualNetwork.id,state:peeringState,\
  fwd:allowForwardedTraffic,gw:allowGatewayTransit,useGw:useRemoteGateways,\
  access:allowVirtualNetworkAccess}"
```

### Network Security Groups and effective rules

```bash
# All NSGs and their custom security rules
az network nsg list -o table
az network nsg rule list -g <rg> --nsg-name <nsg> \
  --query "[].{name:name,prio:priority,dir:direction,access:access,proto:protocol,\
  src:sourceAddressPrefix,srcPorts:sourcePortRange,dst:destinationAddressPrefix,\
  dstPorts:destinationPortRange}" -o table

# EFFECTIVE rules on a specific NIC (combines subnet + NIC NSGs + default rules)
az network nic list-effective-nsg -g <rg> -n <nic>

# Effective route table on a NIC (reveals UDRs / forced tunneling / next hops)
az network nic show-effective-route-table -g <rg> -n <nic> -o table
```

The effective-rule view is the source of truth: it merges subnet-level and NIC-level NSGs with Azure's default rules and shows what traffic is actually permitted. Hunt for rules with `source = Internet`/`*`/`0.0.0.0/0`/`Any` and `access = Allow` on sensitive destination ports.

### Public IPs, NICs, and what they attach to

```bash
# All public IPs with the resource consuming them
az network public-ip list \
  --query "[].{name:name,ip:ipAddress,alloc:publicIPAllocationMethod,\
  fqdn:dnsSettings.fqdn,attached:ipConfiguration.id}" -o table

# NICs: private/public IP, attached NSG, IP forwarding, and owning VM
az network nic list \
  --query "[].{name:name,vm:virtualMachine.id,nsg:networkSecurityGroup.id,\
  ipfwd:enableIPForwarding,ips:ipConfigurations[].{priv:privateIPAddress,pub:publicIPAddress.id}}"
```

`enableIPForwarding = true` flags a NIC acting as a network virtual appliance / potential pivot.

### Load balancers, gateways, firewall, and routing

```bash
az network lb list -o table
az network application-gateway list \
  --query "[].{name:name,sku:sku.name,waf:webApplicationFirewallConfiguration.enabled}"
az network firewall list -o table
az network route-table list -o table
az network route-table route list -g <rg> --route-table-name <rt> -o table

# VPN / ExpressRoute gateways and their connections (bridges to other networks)
az network vnet-gateway list -o table
az network vpn-connection list -g <rg> -o table
az network express-route list -o table
```

### Private endpoints, private DNS, and Bastion

```bash
# Private endpoints reveal which PaaS resources are wired into the VNet
az network private-endpoint list \
  --query "[].{name:name,subnet:subnet.id,\
  links:privateLinkServiceConnections[].{to:privateLinkServiceId,groups:groupIds}}"

az network private-dns zone list -o table
az network private-dns record-set list -g <rg> -z <zone> -o table

az network bastion list -o table
```

### Bulk topology with Azure Resource Graph

Resource Graph returns the whole estate in one query and is faster than per-resource CLI calls across large tenants:

```bash
# Every NSG rule allowing inbound from the Internet on any port, tenant-wide
az graph query -q "
resources
| where type == 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where rule.properties.direction == 'Inbound'
  and rule.properties.access == 'Allow'
  and (rule.properties.sourceAddressPrefix in ('*','Internet','0.0.0.0/0'))
| project subscriptionId, resourceGroup, nsg=name,
  ruleName=rule.name, ports=rule.properties.destinationPortRange,
  src=rule.properties.sourceAddressPrefix"

# All public IPs in use across all subscriptions
az graph query -q "
resources
| where type == 'microsoft.network/publicipaddresses'
| where isnotempty(properties.ipAddress)
| project name, ip=properties.ipAddress, subscriptionId, resourceGroup"
```

### Topology export with Network Watcher

```bash
az network watcher list -o table
# Generate the resource-level topology of a VNet/subnet
az network watcher show-topology -g <rg> --vnet <vnet>
# IP flow verify: does an effective rule allow a given flow? (control-level reachability test)
az network watcher test-ip-flow -g <rg> --vm <vm> --direction Inbound \
  --protocol TCP --local <vmIP>:3389 --remote 1.2.3.4:* --nic <nic>
```

## Misconfigurations & Findings

- **Permissive inbound NSG rules.** Effective rules allowing `Internet`/`*`/`Any` to management (22/3389/5985/5986), database (1433/3306/5432), Redis (6379), or container/orchestration (10250/2375/6443) ports. The Resource Graph query above surfaces these tenant-wide.
- **Flat networks / weak segmentation.** Subnets with no associated NSG, broad intra-VNet allow rules, or a single VNet hosting workloads of differing trust levels with no microsegmentation.
- **Risky peering configuration.** Peerings with `allowForwardedTraffic` and/or `allowGatewayTransit` enabled create transitive reachability; cross-subscription or cross-tenant peerings extend the blast radius beyond the owning team.
- **IP forwarding enabled on NICs** that are not sanctioned network virtual appliances, enabling traffic interception/pivoting.
- **Unexpected public IPs** attached to workloads that should be private (jump hosts, build agents, internal APIs), and public IPs without DDoS protection or WAF in front.
- **Gateway bridges.** VPN/ExpressRoute connections expose the route into on-premises or partner networks; misconfigured forced tunneling (UDR `0.0.0.0/0 -> next hop`) can route or blackhole egress in unexpected ways.
- **Private endpoint inventory leakage.** Private endpoints enumerate exactly which Storage, SQL, Key Vault, and other PaaS resources back the environment, a high-value target list for an authenticated low-privilege identity.
- **Missing Network Watcher / flow logs.** Absence of flow logging means lateral movement and exfiltration over the network leave little forensic trail.

## Exploitation

This phase is reconnaissance; the enumeration output feeds exploitation in later phases. The high-value outcomes are:

- **Reachability map for lateral movement.** Effective NSG rules plus peering and route tables tell you exactly which hosts a compromised foothold can reach. Combine `test-ip-flow` results with the topology export to plan movement without noisy scanning.
- **Pivot identification.** NICs with IP forwarding, NVAs, Bastion hosts, and VPN gateways are pivot candidates to reach otherwise-isolated subnets and on-premises networks.
- **Target prioritization.** Private endpoints and the public-IP inventory rank the PaaS and VM targets worth attacking after privilege escalation.
- **Foothold relevance.** If the audit identity is also able to reach the Instance Metadata Service from a compromised VM in an enumerated subnet, the network map indicates which subnets host identities worth harvesting. See the [unauthenticated phase](../01-unauthenticated-external/azure-networking-unauthenticated.md) for the external view that this internal map complements.

## Detection & Logging

- **Azure Activity Logs** record all control-plane `read`/`list` operations against networking resources (e.g., `Microsoft.Network/networkSecurityGroups/read`, `.../networkInterfaces/effectiveNetworkSecurityGroups/action`, `.../showTopology`). A burst of broad networking reads from one principal is a strong enumeration signal.
- **Azure Resource Graph queries** are themselves logged via Activity Logs on the resources returned and via the principal's read activity; large cross-subscription graph queries by a non-administrative identity are anomalous.
- **Entra ID sign-in and audit logs** attribute the enumerating identity, its authentication method (interactive vs. service principal vs. managed identity), source IP, and any conditional-access evaluation, helping distinguish sanctioned audit from a compromised credential.
- **Network Watcher NSG/VNet flow logs** capture the network-level activity if enumeration is followed by probing.
- **Microsoft Defender for Cloud / Defender for Resource Manager** flags suspicious enumeration patterns, including unusual invocation of network-mapping and effective-rule operations by an identity.

## Remediation & Hardening

- **Least privilege on read.** Scope Reader and Network Contributor narrowly; avoid tenant-root or subscription-wide read grants to non-administrative identities. Prefer time-bound access via Privileged Identity Management (PIM) for audit roles.
- **Default-deny segmentation.** Associate an NSG with every subnet, default-deny inbound, and use Application Security Groups for intent-based rules. Apply Azure Firewall / NVA for centralized east-west and egress control.
- **Constrain peering trust.** Disable `allowForwardedTraffic` and gateway transit unless required; review cross-subscription/cross-tenant peerings under change control.
- **Eliminate unsanctioned public exposure.** Remove unnecessary public IPs, disable IP forwarding where not needed, and front public HTTP/S with WAF and DDoS Standard.
- **Private connectivity for PaaS.** Use Private Endpoints and disable public network access on data services; keep private DNS zones consistent.
- **Enable flow logging everywhere.** Turn on Network Watcher VNet/NSG flow logs and ship them to a SIEM; alert on enumeration bursts and new permissive-rule creation.
- **Continuous posture checks.** Use Defender for Cloud / Azure Policy to detect and auto-remediate permissive NSG rules, missing flow logs, and public management ports.

## Tools

- **Native:** `az network` CLI (vnet, subnet, nsg, nic, public-ip, lb, application-gateway, firewall, route-table, vnet-gateway, private-endpoint, private-dns, bastion), `az network nic list-effective-nsg`, `az network nic show-effective-route-table`, `az network watcher show-topology` / `test-ip-flow`, and Azure Resource Graph (`az graph query`).
- **Audit frameworks:** ScoutSuite, Stormspotter, AzureHound, PowerZure (all support read-only network mapping and relationship graphing).

## References

- [az network CLI reference](https://learn.microsoft.com/en-us/cli/azure/network)
- [Virtual Network overview](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview)
- [Network Security Groups overview](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [VNet peering overview](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview)
- [Network Watcher overview](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview)
- [Azure Resource Graph overview](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
- [Private Endpoint overview](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview)
- [Default outbound access](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access)
- [hackingthe.cloud - Azure](https://hackingthe.cloud/azure/)
