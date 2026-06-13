---
cstg_id: CSTG-AZURE-KEY-VAULT-ENUM
title: "AZURE Key Vault - Enumeration"
provider: azure
service: key-vault
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.KeyVault/vaults/read"
  - "Microsoft.KeyVault/vaults/secrets/read (RBAC data plane) OR Key Vault access policy: Secret List"
  - "Microsoft.KeyVault/vaults/keys/read"
  - "Microsoft.KeyVault/vaults/accessPolicies/read"
  - "Microsoft.KeyVault/checkNameAvailability/read"
  - "Microsoft.Authorization/roleAssignments/read"
tools:
  - azure-cli
  - az-rest
  - azure-powershell
  - microburst
  - bloodhound-azurehound
  - roadtools-roadrecon
references:
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy"
  - "https://learn.microsoft.com/en-us/rest/api/keyvault/"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure Key Vault is a managed secrets store for three data-plane object types: **secrets** (arbitrary strings such as passwords, connection strings, and API tokens), **keys** (RSA/EC cryptographic keys used for signing, wrapping, and encryption), and **certificates** (X.509 certificates with their private keys). Each vault exposes two distinct access surfaces: a **management plane** (the Azure Resource Manager API, governed by Azure RBAC on `Microsoft.KeyVault/*`) that controls vault configuration, access model, networking, and recovery; and a **data plane** (the `*.vault.azure.net` endpoint) that controls who can read and write the actual secret material.

The enumeration objective is to inventory every vault reachable from the current identity, determine the authorization model in use on each (legacy **access policies** versus **Azure RBAC**), and map which principals can read or write each object type. Because vaults concentrate the credentials that unlock the rest of an environment - database passwords, service principal client secrets, storage SAS tokens, TLS private keys - a complete vault inventory is frequently the single highest-value reconnaissance artifact in an Azure tenant. Enumeration here is non-destructive and assumes only read/audit-level access.

## Prerequisites

- An authenticated identity in the tenant (user, service principal, or managed identity) with at least directory read and a token for the ARM audience (`https://management.azure.com/`).
- For management-plane inventory: `Microsoft.KeyVault/vaults/read` over one or more subscriptions or resource groups (granted by built-in roles such as **Reader**, **Key Vault Reader**, **Key Vault Contributor**, or **Contributor**).
- For data-plane inventory of object *names* and *versions*: either an **access policy** granting the relevant `List` permission, or an Azure RBAC role such as **Key Vault Reader** (metadata) / **Key Vault Secrets User** / **Key Vault Crypto User** scoped to the vault, plus a token for the vault audience (`https://vault.azure.net`).
- Network reachability to the vault data-plane endpoint - a vault with a private endpoint or firewall (`publicNetworkAccess = Disabled`) is not reachable from the public internet regardless of authorization.

## Enumeration

### Management plane (ARM) - vault inventory

List every vault the identity can see across subscriptions:

```bash
# Enumerate subscriptions first
az account list -o table

# All vaults in the current subscription (ARM list)
az keyvault list -o table

# Detailed view of one vault: SKU, access model, network ACLs, soft-delete/purge protection
az keyvault show --name <vault-name> -o json
```

Key fields to capture from `az keyvault show`:

- `properties.enableRbacAuthorization` - `true` means data-plane authorization is via Azure RBAC; `false` (or absent) means **legacy access policies** are in effect.
- `properties.accessPolicies[]` - when RBAC is disabled, the full list of object IDs and their granted permissions (`secrets`, `keys`, `certificates`).
- `properties.networkAcls` - `defaultAction`, `ipRules`, `virtualNetworkRules`, and `bypass`.
- `properties.publicNetworkAccess` - `Enabled` or `Disabled`.
- `properties.enableSoftDelete`, `properties.enablePurgeProtection`, `properties.softDeleteRetentionInDays`.
- `properties.vaultUri` - the data-plane endpoint.

Raw ARM equivalent (useful when the CLI is unavailable or for scripting against a captured bearer token):

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
```

Enumerate the **role assignments** on a vault to understand the RBAC authorization graph:

```bash
az role assignment list --scope \
  "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>" \
  --include-inherited -o table

az keyvault show --name <vault> --query "properties.accessPolicies" -o json   # legacy model
```

PowerShell equivalents:

```powershell
Get-AzKeyVault
Get-AzKeyVault -VaultName <vault>
(Get-AzKeyVault -VaultName <vault>).AccessPolicies
Get-AzRoleAssignment -Scope "/subscriptions/<sub>/.../vaults/<vault>"
```

### Data plane - object inventory

Listing object *names* and *versions* (not values) requires only the `List` permission and is the core data-plane recon step:

```bash
# Secrets, keys, certificates (names + IDs + attributes; values are NOT returned by list)
az keyvault secret list      --vault-name <vault> -o table
az keyvault key list         --vault-name <vault> -o table
az keyvault certificate list --vault-name <vault> -o table

# Version history of a single object (rotation evidence; older versions may still be enabled)
az keyvault secret list-versions --vault-name <vault> --name <secret-name> -o table
```

Raw data-plane REST (against a `vault.azure.net` token):

```bash
az rest --resource "https://vault.azure.net" --method get \
  --url "https://<vault>.vault.azure.net/secrets?api-version=7.4"
az rest --resource "https://vault.azure.net" --method get \
  --url "https://<vault>.vault.azure.net/keys?api-version=7.4"
az rest --resource "https://vault.azure.net" --method get \
  --url "https://<vault>.vault.azure.net/certificates?api-version=7.4"
```

### Name-resolution / existence checks

Vault DNS names are global and predictable, which allows existence checks even without ARM visibility:

```bash
# Global name availability (reveals whether a vault name is already taken in the cloud)
az rest --method post \
  --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2023-07-01" \
  --body '{"name":"<candidate>","type":"Microsoft.KeyVault/vaults"}'

# DNS existence check (no auth required)
nslookup <candidate>.vault.azure.net
```

### Directory-wide graph view

Map which principals hold vault-relevant roles across the tenant using a graph collector (see [Azure IAM enumeration](../02-services/azure-iam-enum.md) where present). Capture: principals with `Key Vault Administrator`, `Key Vault Contributor`, `Key Vault Secrets User`, `Key Vault Crypto User`, and any custom role containing `Microsoft.KeyVault/vaults/secrets/getSecret/action` or `Microsoft.KeyVault/vaults/accessPolicies/write`.

## Misconfigurations & Findings

- **Legacy access-policy model with overly broad grants.** When `enableRbacAuthorization` is `false`, access policies frequently grant `Get`+`List`+`Set`+`Delete` on all object types to many principals. Access policies are not visible in standard RBAC audits, so these grants are routinely missed.
- **Public network access enabled with `defaultAction = Allow`.** A vault reachable from the internet with no firewall is exposed to any identity that obtains a valid data-plane token, including stolen managed-identity tokens.
- **`bypass = AzureServices`.** Trusted-services bypass can be abused if an attacker controls a first-party service path into the vault.
- **Soft-delete or purge protection disabled.** Without purge protection, an attacker with delete rights can permanently destroy keys and secrets (irrecoverable denial of service); without soft-delete, recovery is impossible.
- **Keys without rotation policy / old enabled versions.** Stale, still-enabled key and secret versions widen the window for compromised material.
- **Secrets that are themselves credentials to other systems.** Connection strings, SAS tokens, and service-principal client secrets stored in the vault create lateral-movement chains; their mere presence (by name) is a finding worth flagging during enumeration.
- **Broad inherited RBAC.** Subscription-level **Contributor**/**Owner** or **Key Vault Administrator** inherited onto the vault grants full data-plane control; inherited assignments are easy to overlook.

## Exploitation

Enumeration is non-destructive; the techniques above only read inventory and configuration. The artifacts collected here directly feed the privilege-escalation and post-exploitation phases:

- The access model (`enableRbacAuthorization`) and the per-principal permission map determine which escalation path applies. See [Key Vault privilege escalation](../03-privilege-escalation/azure-key-vault-privesc.md).
- The object inventory (secret/key/certificate names) and network posture determine what can be exfiltrated once data-plane read is obtained. See [Key Vault post-exploitation](../05-post-exploitation/azure-key-vault-post-exploitation.md).

No secret values are retrieved during enumeration - a `list` operation returns metadata only, while value retrieval (`getSecret`) is a separate, higher-privilege and more strongly logged action handled in the post-exploitation page.

## Detection & Logging

- **Azure Activity Logs** record all management-plane operations on the vault resource: `Microsoft.KeyVault/vaults/read`, writes to access policies, network ACL changes, and create/delete. Frequent or broad `vaults/read` and `accessPolicies/read` from an unusual principal is an enumeration signal.
- **Key Vault resource logs (diagnostic setting `AuditEvent`)** record data-plane operations. List operations appear as `SecretList`, `KeyList`, `CertificateList`, and `VaultGet` events with the caller identity, client IP, and result. These logs only exist if a diagnostic setting routes them to a Log Analytics workspace, storage account, or Event Hub - absence of that setting is itself a gap.
- **Entra ID sign-in logs** show token issuance for the `https://vault.azure.net` and `https://management.azure.com` audiences; a sudden first-time vault-audience token for a service principal can indicate token theft.
- **Entra ID audit logs** capture directory-side role and group changes that grant vault access.
- Managed detections: **Microsoft Defender for Key Vault** flags anomalous access patterns (unusual user/application/location accessing a vault, high-volume secret listing, access from a Tor exit node or suspicious IP).

## Remediation & Hardening

- Migrate every vault to the **Azure RBAC** authorization model (`enableRbacAuthorization = true`) and retire legacy access policies, so all grants are auditable through a single mechanism.
- Apply **least privilege**: grant `Key Vault Secrets User` / `Key Vault Crypto User` only at the vault or object scope to the specific workload identities that need it; avoid subscription-level inheritance.
- Set `publicNetworkAccess = Disabled` and use **private endpoints**; where public access is required, set `networkAcls.defaultAction = Deny` with explicit IP/VNet rules and `bypass = None`.
- Enable **soft-delete** (default) and **purge protection** on every vault.
- Enable the **AuditEvent** diagnostic setting on all vaults and forward to a monitored workspace; alert on bulk `SecretList`/`SecretGet` and access-policy/network changes.
- Enable **Microsoft Defender for Key Vault**.

## Tools

- **azure-cli** (`az keyvault`, `az role assignment`, `az rest`) - primary management- and data-plane enumeration.
- **azure-powershell** (`Get-AzKeyVault`, `Get-AzRoleAssignment`) - alternative inventory.
- **microburst** - Azure-focused PowerShell recon including Key Vault discovery and dumping helpers.
- **bloodhound / azurehound** - graph collection of principals holding vault-relevant roles.
- **roadtools / roadrecon** - tenant-wide Entra ID and ARM enumeration for vault access mapping.

## References

- Key Vault security features - https://learn.microsoft.com/en-us/azure/key-vault/general/security-features
- Provide access using Azure RBAC - https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Assign a Key Vault access policy - https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy
- Key Vault REST API - https://learn.microsoft.com/en-us/rest/api/keyvault/
- Key Vault network security - https://learn.microsoft.com/en-us/azure/key-vault/general/network-security
- hackingthe.cloud (Azure) - https://hackingthe.cloud/azure/
