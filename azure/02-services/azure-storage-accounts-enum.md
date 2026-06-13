---
cstg_id: CSTG-AZURE-STORAGE-ACCOUNTS-ENUM
title: "AZURE Storage Accounts - Enumeration"
provider: azure
service: storage-accounts
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.Storage/storageAccounts/read
  - Microsoft.Storage/storageAccounts/listKeys/action
  - Microsoft.Storage/storageAccounts/blobServices/containers/read
  - Microsoft.Storage/storageAccounts/listAccountSas/action
tools: [azure-cli, az-powershell, MicroBurst, ScoutSuite, Storage-Explorer]
references:
  - "https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts"
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage"
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security"
  - "https://hackingthe.cloud/azure/enumeration/get-azure-storage-account-info/"
license: CC BY-SA 4.0
---

## Summary

With read-only audit access to a subscription or resource group, a tester can fully inventory storage
accounts and assess their security posture: network exposure, anonymous-access settings, encryption
and key configuration, key/SAS state, data-plane authorization model, and the RBAC and key-based
principals that can reach data. This phase establishes which accounts are exposed, which contain
sensitive data, and which credentials (account keys, SAS, Entra roles) are in play - feeding the
privilege-escalation and post-exploitation phases. It assumes a legitimate identity rather than the
anonymous probing in
[Azure Storage Accounts - Unauthenticated Access](../01-unauthenticated-external/azure-storage-accounts-unauthenticated.md).

## Prerequisites

A principal with at least `Reader` over the target scope (subscription/resource group) for the
control plane. Listing account keys requires `Microsoft.Storage/storageAccounts/listKeys/action`
(included in `Storage Account Contributor`, `Owner`, `Contributor`); data-plane listing requires a
**Storage Blob/Queue/Table Data** role or an account key/SAS. Distinguish clearly between control-plane
(ARM) and data-plane (blob/file/queue/table) authorization - they are independent.

## Enumeration

**Authenticate and set context.**

```bash
az login                      # interactive, device-code, or service principal
az account list -o table
az account set --subscription <sub-id>
```

**Inventory all storage accounts (control plane).**

```bash
# Every account in the subscription, with key properties
az storage account list -o json \
  --query '[].{name:name,rg:resourceGroup,kind:kind,sku:sku.name,location:location,
              publicAccess:allowBlobPublicAccess,httpsOnly:enableHttpsTrafficOnly,
              minTls:minimumTlsVersion,sharedKey:allowSharedKeyAccess,
              defaultAction:networkRuleSet.defaultAction}'

# Raw ARM for a single account (reveals full property set)
az storage account show --name <acct> --resource-group <rg> -o json
```

**Assess network exposure and firewall rules.**

```bash
az storage account show --name <acct> --resource-group <rg> \
  --query 'networkRuleSet' -o json          # defaultAction, ipRules, virtualNetworkRules
az network private-endpoint-connection list --id \
  $(az storage account show -n <acct> -g <rg> --query id -o tsv) -o table
```

**Identify the authorization model and key/SAS state.**

```bash
# Is shared-key auth allowed? (false => Entra-only, key/SAS attacks are blocked)
az storage account show -n <acct> -g <rg> --query allowSharedKeyAccess

# When were the keys last rotated? (keyCreationTime under keyPolicy)
az storage account show -n <acct> -g <rg> --query 'keyPolicy'

# List the two account keys (requires listKeys permission - high value)
az storage account keys list -n <acct> -g <rg> -o table

# List Kerberos/Entra SAS policy and whether infrastructure encryption is on
az storage account show -n <acct> -g <rg> \
  --query '{encryption:encryption,requireInfraEnc:encryption.requireInfrastructureEncryption}'
```

**Enumerate containers, file shares, queues, and tables (data plane).** Use Entra auth where
possible; fall back to a key only if explicitly in scope.

```bash
# Blob containers (Entra data-plane auth)
az storage container list --account-name <acct> --auth-mode login -o table
# File shares, queues, tables
az storage share list   --account-name <acct> --auth-mode login -o table
az storage queue list   --account-name <acct> --auth-mode login -o table
az storage table list   --account-name <acct> --auth-mode login -o table

# Per-container public access level and immutability/lease state
az storage container show --account-name <acct> --name <ctr> --auth-mode login \
  --query '{publicAccess:properties.publicAccess,hasImmutability:properties.hasImmutabilityPolicy,
            hasLegalHold:properties.hasLegalHold}'
```

**Enumerate who can reach the data (RBAC + key holders).**

```bash
# Role assignments scoped to the account (look for Storage *Data* roles and broad Contributor/Owner)
ACCT_ID=$(az storage account show -n <acct> -g <rg> --query id -o tsv)
az role assignment list --scope "$ACCT_ID" --include-inherited -o table

# Custom roles that grant listKeys or data actions anywhere
az role definition list --custom-role-only true \
  --query "[?contains(to_string(permissions[].actions), 'listKeys') ||
            contains(to_string(permissions[].dataActions), 'blobServices')].roleName"
```

**Check diagnostic/logging posture (for the Detection findings).**

```bash
az monitor diagnostic-settings list --resource "$ACCT_ID" -o table
az security pricing show -n StorageAccounts --query 'pricingTier'   # Defender for Storage on/off
```

## Misconfigurations & Findings

- **`allowBlobPublicAccess = true`** - any container can opt into anonymous access; combined with a
  public container this is full anonymous exposure (see the unauthenticated page).
- **`allowSharedKeyAccess = true` with broad `listKeys`** - account keys are root-equivalent,
  non-expiring, shared secrets that bypass RBAC and most logging context. Wide `listKeys` is a major
  privilege-escalation primitive (see the privesc page).
- **`networkRuleSet.defaultAction = Allow`** - the account is reachable from the entire internet; no
  firewall or private endpoint.
- **`enableHttpsTrafficOnly = false`** or **`minimumTlsVersion < TLS1_2`** - cleartext or weak
  transport.
- **No key rotation policy / very old `keyCreationTime`** - long-lived keys increase blast radius of
  any leak.
- **Over-broad data-plane RBAC** - `Storage Blob Data Owner/Contributor` or subscription-wide
  `Contributor`/`Owner` granted to users, groups, or service principals that do not need it.
- **Diagnostic logging disabled** and **Defender for Storage off** - anonymous and key-based access
  is unauditable.
- **Public static website (`$web`)** and **leaked SAS in code/config** - confirm scope and expiry.

## Detection & Logging

Control-plane enumeration (`storageAccounts/read`, `listKeys`, role-assignment reads) is recorded in
**Azure Activity Logs** under the corresponding `Microsoft.Storage/*` and
`Microsoft.Authorization/roleAssignments/read` operations, and the calling identity appears in
**Entra ID sign-in logs**. `listKeys` is a particularly noteworthy event and should be alerted on.
Data-plane listing/reads are recorded only when **diagnostic logging** (StorageRead/Write/Delete) is
enabled for the relevant service. **Microsoft Defender for Storage** surfaces unusual enumeration and
access patterns. Note that requests authorised by an **account key or SAS carry no Entra identity**,
so the actor in data-plane logs is the storage key, not a user - a key reason to disable shared-key
access.

## Remediation & Hardening

- Set **`allowSharedKeyAccess = false`** and authorise the data plane exclusively through **Entra ID
  RBAC**; this removes the entire account-key/SAS attack surface.
- Set **`allowBlobPublicAccess = false`** and every container to `Private`.
- Set **`networkRuleSet.defaultAction = Deny`** with **private endpoints** or explicit IP/VNet rules.
- Enforce **`enableHttpsTrafficOnly = true`** and **`minimumTlsVersion = TLS1_2`**.
- Apply **least-privilege RBAC**; restrict `listKeys` to a narrow admin role and audit all holders.
- Enable a **key rotation policy** (`keyPolicy.keyExpirationPeriodInDays`) and rotate regularly; use
  **customer-managed keys** in Key Vault where required.
- Enable **diagnostic settings** for all data-plane categories and **Defender for Storage**.

## Tools

- **azure-cli (`az storage`, `az role assignment`)** / **az-powershell (`Get-AzStorageAccount`)** -
  authoritative control- and data-plane enumeration.
- **MicroBurst** - subscription-wide storage discovery, key dumping, and SAS enumeration.
- **ScoutSuite** - automated posture report flagging public access, network rules, and key state.
- **Azure Storage Explorer** - interactive browse of containers, shares, queues, and tables.

## References

- Microsoft Learn - Storage Resource Provider REST API (storage accounts)
- Microsoft Learn - Manage account access keys
- Microsoft Learn - Azure built-in roles (Storage)
- Microsoft Learn - Configure Azure Storage firewalls and virtual networks
- hackingthe.cloud - Enumerate Azure storage account information
