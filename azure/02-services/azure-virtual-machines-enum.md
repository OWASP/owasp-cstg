---
cstg_id: CSTG-AZURE-VIRTUAL-MACHINES-ENUM
title: "AZURE Virtual Machines - Enumeration"
provider: azure
service: virtual-machines
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Compute/virtualMachines/read"
  - "Microsoft.Compute/virtualMachines/instanceView/read"
  - "Microsoft.Compute/virtualMachineScaleSets/read"
  - "Microsoft.Compute/disks/read"
  - "Microsoft.Compute/snapshots/read"
  - "Microsoft.Network/networkInterfaces/read"
  - "Microsoft.Network/networkSecurityGroups/read"
  - "Microsoft.Network/publicIPAddresses/read"
  - "Microsoft.Compute/virtualMachines/extensions/read"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/read"
tools:
  - azure-cli
  - azure-powershell-az
  - microburst
  - roadrecon
  - azurehound
  - stormspotter
  - prowler
references:
  - "https://learn.microsoft.com/en-us/cli/azure/vm"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated enumeration of Azure Virtual Machines from a read-only or audit credential within a tenant or subscription. The objective is to build a complete inventory of compute resources and the security-relevant properties that determine attack paths: VM identities (system- and user-assigned managed identities), attached disks and snapshots, network exposure (NICs, public IPs, NSG rules), installed extensions, custom data / boot diagnostics, and the RBAC role assignments that govern who can act on each VM. This inventory feeds the privilege-escalation, post-exploitation, and persistence phases.

A read-only role such as **Reader** is sufficient for most control-plane enumeration. Note that Reader does not return secrets (it cannot read disk SAS URLs without `*/action` rights, cannot list storage keys, and cannot read Key Vault secret values), but it reveals the full topology and identity model.

## Prerequisites

- A valid Entra ID credential (user, service principal, or managed-identity token) with at least **Reader** at the subscription, resource-group, or VM scope.
- Azure CLI (`az`), Azure PowerShell (`Az` module), or the ARM REST API.
- For cross-tenant directory enumeration of identities, directory read access in Entra ID is helpful but not required.

## Enumeration

### Establish context

```bash
az login                                   # interactive, or:
az login --service-principal -u <appId> -p <secret> --tenant <tenantId>
az account show                            # current subscription/tenant
az account list -o table                   # all reachable subscriptions
```

### Inventory virtual machines

```bash
# All VMs across the subscription with power state
az vm list -d -o table
az vm list --query "[].{name:name,rg:resourceGroup,size:hardwareProfile.vmSize,os:storageProfile.osDisk.osType}" -o table

# Full detail for one VM (identity, NICs, disks, extensions)
az vm show -g <rg> -n <vm> -d

# Instance view: power state, patch status, agent status
az vm get-instance-view -g <rg> -n <vm>

# Scale sets
az vmss list -o table
az vmss list-instances -g <rg> -n <vmss>
```

REST equivalents (useful when scripting against a raw token):

```bash
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01
GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2023-09-01
```

### Identify managed identities (highest-value finding)

```bash
# System- and user-assigned identities attached to each VM
az vm identity show -g <rg> -n <vm>

# List all VMs that have any identity assigned
az vm list --query "[?identity!=null].{name:name,type:identity.type,principalId:identity.principalId,userAssigned:identity.userAssignedIdentities}" -o json
```

A VM identity's `principalId` can then be pivoted into Entra ID and RBAC to determine what the identity can do (see Misconfigurations and the [Privilege Escalation](../03-privilege-escalation/azure-virtual-machines-privesc.md) page).

### Disks, snapshots, and recoverable data

```bash
az disk list -o table
az snapshot list -o table
az disk list --query "[?diskState=='Attached'].{name:name,vm:managedBy}" -o table
# Disks/snapshots with a network access policy allowing public/SAS export are notable:
az disk list --query "[].{name:name,publicNetworkAccess:publicNetworkAccess,networkAccessPolicy:networkAccessPolicy}" -o table
```

### Network exposure

```bash
az network nic list -o table
az network public-ip list -o table
az network nsg list -o table

# Find NSG rules allowing inbound management ports from the internet
az network nsg list --query "[].{name:name, rules:securityRules[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0')].{port:destinationPortRange,src:sourceAddressPrefix}}" -o json
```

### Extensions, custom data, and boot diagnostics

```bash
# Installed extensions (CustomScript, DSC, AADLogin, etc.)
az vm extension list -g <rg> --vm-name <vm> -o table

# Boot diagnostics serial log / screenshot (can leak console output, creds in cloud-init)
az vm boot-diagnostics get-boot-log -g <rg> -n <vm>
```

### RBAC - who can act on the VM

```bash
# Role assignments scoped at the VM (and inherited from RG/subscription)
az role assignment list --scope \
  /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm> \
  --include-inherited -o table

# Definitions that grant dangerous VM actions (runCommand, extensions, login)
az role definition list --query "[?contains(to_string(permissions[].actions), 'runCommand') || contains(to_string(permissions[].actions), 'extensions')].roleName"
```

## Misconfigurations & Findings

- **Privileged managed identities.** A VM identity holding Contributor/Owner or a custom role with write actions over other resources, Key Vault access, or directory roles - this is the prime escalation pivot.
- **Overly broad RBAC.** Many principals with Virtual Machine Contributor, or Contributor/Owner inherited at subscription scope, granting `runCommand`/extension rights to a wide audience.
- **Disks and snapshots exportable via SAS.** `networkAccessPolicy` allowing export, or public network access, enabling offline data theft of OS/data disks.
- **Secrets in custom data / boot diagnostics.** cloud-init `customData`, scripts, or console output containing credentials.
- **Public IPs and permissive NSGs** (cross-reference [Unauthenticated](../01-unauthenticated-external/azure-virtual-machines-unauthenticated.md)).
- **CustomScript / DSC extensions** referencing scripts in storage that the auditor can also read - revealing bootstrap secrets.
- **No JIT, no Bastion** indicated by always-open management rules.

## Exploitation

Enumeration is read-only by definition; "exploitation" here means turning inventory into a prioritised target list. Key correlations to compute:

1. **VM -> identity -> RBAC**: for each VM with a managed identity, resolve the identity `principalId` and list its role assignments tenant-wide to find escalation paths.
2. **VM -> reachable secrets**: identities or role assignments that grant `Microsoft.KeyVault/.../secrets/read` or storage key listing.
3. **VM -> data**: snapshots/disks that can be copied or exported.
4. **VM -> code execution surface**: who holds `runCommand` or extension-write rights on a VM whose identity is privileged.

Graph tools (AzureHound/BloodHound, Stormspotter) automate these correlations and produce attack paths directly from the read-only data collected above.

## Detection & Logging

- **Azure Activity Logs** record control-plane read operations as `Microsoft.Compute/virtualMachines/read`, `list`, and management-group/subscription `List` calls. High-volume listing across many resource types from one principal is a hallmark of automated enumeration tools.
- **Entra ID audit/sign-in logs** show the principal authenticating and acquiring ARM tokens; service-principal sign-ins to `https://management.azure.com` are recorded.
- **Microsoft Defender for Cloud / Defender for Resource Manager** raises alerts for suspicious ARM enumeration (e.g. "Suspicious management session using an inactive account", "Azure Resource Manager operation from suspicious IP").
- **Microsoft Sentinel** analytics can correlate mass `*/read` and `*/list` operations as reconnaissance.

Read operations are easy to miss because they are voluminous and benign-looking; defenders should baseline per-principal read volume rather than alert on individual reads.

## Remediation & Hardening

- Apply least privilege: avoid blanket Reader at root scope; scope read access to needed resource groups.
- Audit and minimise managed-identity role assignments - prefer user-assigned identities scoped narrowly, and review them with `az role assignment list`.
- Set disks/snapshots `networkAccessPolicy` to `DenyAll` and disable public network access.
- Remove secrets from `customData` and boot diagnostics; use Key Vault references and the VM's managed identity to fetch secrets at runtime.
- Enable Defender for Servers / Defender for Resource Manager and route Activity + flow logs to Sentinel.
- Use Azure Policy to deny public IPs and internet-facing management NSG rules.

## Tools

- **Azure CLI / Az PowerShell** - native control-plane enumeration.
- **MicroBurst** - PowerShell toolkit for dumping VM, disk, and identity information.
- **AzureHound + BloodHound** - graph-based identity and RBAC attack-path discovery.
- **ROADrecon** - Entra ID directory enumeration to resolve identity principals.
- **Stormspotter** - Azure resource and identity graph collection.
- **Prowler / ScoutSuite** - posture assessment including VM exposure and disk export settings.

## References

- az vm command reference - https://learn.microsoft.com/en-us/cli/azure/vm
- Azure Instance Metadata Service - https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- Managed identities overview - https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- Compute VM REST API - https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines
- Azure built-in roles - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- Hacking the Cloud - Azure - https://hackingthe.cloud/azure/
