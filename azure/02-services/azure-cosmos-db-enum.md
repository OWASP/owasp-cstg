---
cstg_id: CSTG-AZURE-COSMOS-DB-ENUM
title: "AZURE Cosmos Db - Enumeration"
provider: azure
service: cosmos-db
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.DocumentDB/databaseAccounts/read
  - Microsoft.DocumentDB/databaseAccounts/listKeys/action
  - Microsoft.DocumentDB/databaseAccounts/readonlykeys/action
  - Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read
  - Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read
  - Microsoft.Authorization/roleAssignments/read
tools:
  - Azure CLI (az cosmosdb)
  - Azure Resource Manager REST API
  - Cosmos DB data-plane SDKs / REST API
  - Azure Resource Graph
  - PowerShell (Az.CosmosDB)
references:
  - https://learn.microsoft.com/en-us/azure/cosmos-db/
  - https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control
  - https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac
  - https://learn.microsoft.com/en-us/rest/api/cosmos-db/
  - https://learn.microsoft.com/en-us/rest/api/cosmos-db-resource-provider/database-accounts
  - https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-restrict-user-data
  - https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall
  - https://hackingthe.cloud/azure/
license: CC BY-SA 4.0
---

## Summary

Azure Cosmos DB is a globally distributed, multi-model database service exposing several wire-compatible APIs over a single underlying resource type (`Microsoft.DocumentDB/databaseAccounts`): the Core (SQL/NoSQL) API, MongoDB API, Cassandra API, Gremlin (graph) API, and Table API. Each account is reachable at a public endpoint of the form `https://<account>.documents.azure.com:443/` (Core), `https://<account>.mongo.cosmos.azure.com/` (MongoDB), and similar per-API hostnames.

Enumeration of Cosmos DB matters because the service combines two distinct authorization planes that are frequently misunderstood:

- **Control plane** — Azure Resource Manager (ARM) operations governed by Azure RBAC roles (e.g. `Microsoft.DocumentDB/*`). This is where account metadata, networking, backup, and *key-listing* permissions live.
- **Data plane** — access to the documents/items themselves. Historically this is governed by **primary/secondary account keys** and **resource tokens**, and more recently by **Cosmos DB data-plane RBAC** (a separate role system distinct from Azure RBAC, using `Microsoft.DocumentDB/databaseAccounts/sqlAccounts/.../...` data actions) for the Core API and **local authentication (key)** for the others.

The central enumeration objective is to determine, for each account: which authentication modes are enabled, who/what can read the account keys (the most common privilege-escalation pivot), how the account is network-exposed (public endpoint, IP firewall, VNet rules, private endpoint), and whether sensitive data is reachable. This page covers read-only enumeration; exploitation of discovered keys and access is covered in [Cosmos DB Post-Exploitation](../05-post-exploitation/azure-cosmos-db-post-exploitation.md).

## Prerequisites

- Read access to the subscription(s) or resource group(s) in scope, sufficient to list resources and read `Microsoft.DocumentDB/databaseAccounts`.
- For key enumeration: `Microsoft.DocumentDB/databaseAccounts/listKeys/action` and/or `.../readonlykeys/action`. Note these are **action** permissions granted by control-plane roles such as `DocumentDB Account Contributor`, `Contributor`, and `Owner`.
- For data-plane RBAC inspection: ability to read Cosmos DB SQL role definitions and assignments (`Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/read`, `.../sqlRoleAssignments/read`).
- Tooling: Azure CLI with the account-set context, or a valid ARM bearer token for the REST API. For data-plane reads, either an account key, a resource token, or a data-plane RBAC role assignment scoped to the calling identity.

## Enumeration

### 1. Discover database accounts across the tenant

List every Cosmos DB account in scope and capture the properties that drive the rest of the assessment.

```bash
# All accounts in a subscription
az cosmosdb list -o table

# Full property dump for one account
az cosmosdb show \
  --name <account> \
  --resource-group <rg> \
  -o json
```

Azure Resource Graph is the fastest way to inventory at tenant scale and to surface security-relevant flags in one query:

```bash
az graph query -q "
resources
| where type == 'microsoft.documentdb/databaseaccounts'
| project name, resourceGroup, subscriptionId, location,
          kind,
          apis = properties.capabilities,
          publicNetworkAccess = properties.publicNetworkAccess,
          disableKeyBasedMetadataWriteAccess = properties.disableKeyBasedMetadataWriteAccess,
          disableLocalAuth = properties.disableLocalAuth,
          ipRules = properties.ipRules,
          isVirtualNetworkFilterEnabled = properties.isVirtualNetworkFilterEnabled,
          virtualNetworkRules = properties.virtualNetworkRules,
          privateEndpoints = properties.privateEndpointConnections,
          backupPolicy = properties.backupPolicy
"
```

Equivalent ARM REST call:

```
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2024-11-15
Authorization: Bearer <arm-token>
```

Key properties to record from `az cosmosdb show`:

- `kind` and `capabilities` — identifies the API surface (`EnableCassandra`, `EnableGremlin`, `EnableTable`, `EnableMongo`, or default Core/SQL). The exposed hostname and the relevant auth model both follow from this.
- `disableLocalAuth` — when `true`, account-key and resource-token (local) authentication is **disabled** and only Entra ID / data-plane RBAC works. When `false` or absent, keys are accepted.
- `disableKeyBasedMetadataWriteAccess` — when `true`, account keys cannot perform metadata (control-plane-like) writes via the data plane.
- `publicNetworkAccess` — `Enabled` / `Disabled`. `Disabled` means only private endpoints reach the account.
- `ipRules`, `isVirtualNetworkFilterEnabled`, `virtualNetworkRules`, `privateEndpointConnections` — the network exposure surface.
- `consistencyPolicy`, `locations`/`readLocations`/`writeLocations` — global distribution; each replica region has its own regional endpoint that inherits the same auth and may be reachable independently.
- `backupPolicy` — `Periodic` vs `Continuous`; continuous backup enables point-in-time restore, which is a data-recovery / exfiltration vector during post-exploitation.

### 2. Enumerate connection strings and keys (privilege check)

The single most impactful enumeration step is determining whether the calling identity can read account keys. A key grants **full data-plane access** (and, unless `disableKeyBasedMetadataWriteAccess` is set, metadata writes) regardless of data-plane RBAC.

```bash
# Read-write primary/secondary keys (requires listKeys/action)
az cosmosdb keys list \
  --name <account> --resource-group <rg> \
  --type keys

# Read-only keys (requires readonlykeys/action)
az cosmosdb keys list \
  --name <account> --resource-group <rg> \
  --type read-only-keys

# Full connection strings (host + key combined, ready for SDKs)
az cosmosdb keys list \
  --name <account> --resource-group <rg> \
  --type connection-strings
```

REST equivalents (POST operations — note these are *write-classified actions* and are audited in the Activity Log):

```
POST .../databaseAccounts/{account}/listKeys?api-version=2024-11-15
POST .../databaseAccounts/{account}/readonlykeys?api-version=2024-11-15
POST .../databaseAccounts/{account}/listConnectionStrings?api-version=2024-11-15
```

If these calls succeed, treat the account as fully compromised from the caller's position and record it as a finding. If they fail with authorization errors but the account has `disableLocalAuth: false`, the keys still exist and are usable by anyone who *can* list them — enumerate who that is in the next step.

### 3. Enumerate the control-plane RBAC that grants key access

Identify every principal that can list keys, because key-listing is the dominant escalation path. The relevant permission is `Microsoft.DocumentDB/databaseAccounts/listKeys/action`, held by built-in roles `Owner`, `Contributor`, and `DocumentDB Account Contributor`, and by any custom role that includes it or a `Microsoft.DocumentDB/*` wildcard.

```bash
acct=$(az cosmosdb show -n <account> -g <rg> --query id -o tsv)

# Direct assignments on the account scope
az role assignment list --scope "$acct" -o table

# Include assignments inherited from RG/subscription/management group
az role assignment list --scope "$acct" --include-inherited -o table

# Inspect custom roles that may contain the listKeys action
az role definition list --custom-role-only true \
  --query "[?contains(to_string(permissions[].actions), 'DocumentDB')]" -o json
```

Watch for: broad `Contributor`/`Owner` at subscription scope, service principals with `DocumentDB Account Contributor`, and custom roles using `Microsoft.DocumentDB/*` or `*/listKeys/action`.

### 4. Enumerate Cosmos DB data-plane RBAC (Core/SQL API)

Cosmos DB has its **own** data-plane role system, separate from Azure RBAC, for the Core API. Role definitions and assignments are control-plane resources but govern *item-level* access. Enumerate them to map who can read/write data via Entra ID without keys.

```bash
# Data-plane role definitions (built-in + custom)
az cosmosdb sql role definition list \
  --account-name <account> --resource-group <rg> -o json

# Data-plane role assignments (principalId -> roleDefinition -> scope)
az cosmosdb sql role assignment list \
  --account-name <account> --resource-group <rg> -o json
```

The two built-in data-plane roles are `Cosmos DB Built-in Data Reader` (`00000000-0000-0000-0000-000000000001`) and `Cosmos DB Built-in Data Contributor` (`...0002`). Custom data roles enumerate granular data actions such as `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read` and `.../executeQuery`. Resolve each `principalId` against Entra ID to identify the human or workload identity behind the assignment.

### 5. Enumerate databases, containers, and schema (data plane)

With a key, a resource token, or a data-plane RBAC assignment, enumerate the logical hierarchy. This is metadata enumeration — it reveals naming, partition keys, throughput, and indexing without necessarily reading documents.

Control-plane listing (works with reader RBAC, no key needed):

```bash
# SQL/Core API
az cosmosdb sql database list --account-name <account> -g <rg> -o table
az cosmosdb sql container list --account-name <account> -g <rg> \
  --database-name <db> -o table

# Other APIs
az cosmosdb mongodb database list   --account-name <account> -g <rg> -o table
az cosmosdb cassandra keyspace list --account-name <account> -g <rg> -o table
az cosmosdb gremlin database list   --account-name <account> -g <rg> -o table
az cosmosdb table list              --account-name <account> -g <rg> -o table
```

Data-plane listing via the Core REST API (requires the `authorization` header derived from a key or token):

```
GET https://<account>.documents.azure.com/dbs
GET https://<account>.documents.azure.com/dbs/<db>/colls
```

Record container names, `partitionKey` paths, indexing policy, unique-key policy, and provisioned/autoscale throughput. Sensitive container names (e.g. `users`, `tokens`, `secrets`, `audit`, `pii`) are themselves a finding and guide the sampling done during post-exploitation.

### 6. Probe the public endpoint and network exposure (low-touch)

Determine reachability without authenticating. The data endpoint responds to unauthenticated requests with characteristic errors, confirming the account exists and is publicly routable:

```bash
# Existence / reachability probe (expect 401 Unauthorized if reachable & key-auth enabled)
curl -s -o /dev/null -w "%{http_code}\n" \
  https://<account>.documents.azure.com/

# MongoDB API endpoint resolves on its own hostname
nslookup <account>.mongo.cosmos.azure.com
```

Cross-reference with the network config gathered in step 1: an account with `publicNetworkAccess: Enabled`, no `ipRules`, and `disableLocalAuth: false` is internet-reachable and key-only — the highest-risk posture. Confirm whether the IP firewall includes the "Accept connections from within Azure datacenters" allowance (the `0.0.0.0` single-IP rule), which effectively permits any Azure-hosted resource.

## Misconfigurations & Findings

- **Local (key) auth enabled (`disableLocalAuth: false`)** while keys are broadly readable — any principal with `listKeys/action` obtains full data access. The most common Cosmos DB finding.
- **Over-broad key-listing rights** — `Contributor`/`Owner` at subscription scope, or service principals/automation accounts holding `DocumentDB Account Contributor`, granting key access far beyond need.
- **Metadata write via key not disabled (`disableKeyBasedMetadataWriteAccess: false`)** — key holders can create/drop databases and containers, not just read data.
- **Public network access enabled with no IP/VNet restrictions** — `publicNetworkAccess: Enabled` and empty `ipRules`, exposing the endpoint to the internet (subject only to key/token possession).
- **"Allow access from Azure" firewall rule** present — the `0.0.0.0` allowance trusts the entire Azure backbone, a weak boundary.
- **No private endpoint** for an account holding sensitive data despite VNet availability.
- **Data-plane RBAC not adopted** — reliance on shared keys instead of per-identity Entra-backed roles, preventing attribution and least privilege.
- **Resource tokens with broad scope / long lifetime** in use, or token-broker patterns that mint over-permissioned tokens.
- **Continuous backup or frequent periodic backups** combined with weak restore-permission controls — a data-recovery exfiltration path.
- **Keys never rotated** — secondary keys present in code/config and never cycled, so a leaked key remains valid indefinitely.

## Detection & Logging

Enumeration of Cosmos DB is observable across two log sources:

- **Azure Activity Log** records all control-plane operations against the account, including the key-listing actions `listKeys`, `readonlykeys`, and `listConnectionStrings`. A spike of `List Keys` operations, or such operations from an unexpected principal/IP, is a strong enumeration signal. Role-assignment reads/writes (`Microsoft.Authorization/roleAssignments`) and data-plane role definition/assignment changes also surface here.
- **Entra ID sign-in and audit logs** attribute the ARM token used for the above operations to a user, service principal, or managed identity, including the source IP, application, and conditional-access result. Correlate the `listKeys` Activity Log entry with the Entra sign-in to identify the actor.

For data-plane visibility, enable **Cosmos DB diagnostic settings** and route the `DataPlaneRequests` (and `ControlPlaneRequests`) categories to a Log Analytics workspace or storage. `DataPlaneRequests` records each item/query operation with the operation type, status code, partition, and the authorization type (`PrimaryMasterKey`, `SecondaryReadonlyMasterKey`, `ResourceToken`, `AAD`), making key-based versus identity-based access distinguishable and enabling detection of bulk reads/queries.

Detection guidance for assessors: note whether diagnostic settings exist and which categories are enabled, since absent `DataPlaneRequests` logging means data exfiltration would be invisible.

## Remediation & Hardening

- Set **`disableLocalAuth: true`** to eliminate account-key and resource-token auth where workloads can use Entra ID, removing the key-listing escalation path entirely.
- Adopt **Cosmos DB data-plane RBAC** with `Cosmos DB Built-in Data Reader`/`Data Contributor` or least-privilege custom data roles assigned per identity, scoped to specific databases/containers where possible.
- Restrict control-plane **`listKeys` rights** to a minimal set of break-glass principals; avoid subscription-scope `Contributor`/`Owner` for application identities.
- Set **`disableKeyBasedMetadataWriteAccess: true`** so any residual key cannot mutate the resource topology.
- Set **`publicNetworkAccess: Disabled`** and use **private endpoints**; where public access is required, apply tight **IP firewall** and **VNet service-endpoint** rules and remove the broad "Allow access from Azure" rule.
- **Rotate** primary/secondary keys regularly and after any suspected exposure; rotating a key invalidates connection strings derived from it.
- Enable **diagnostic settings** for `DataPlaneRequests`/`ControlPlaneRequests` and alert on anomalous `listKeys` and bulk-read patterns.
- Use **resource tokens** with the narrowest permission mode and shortest viable validity when key-based delegation is unavoidable; never embed primary keys in client applications.

## Tools

- **Azure CLI** (`az cosmosdb`, `az role assignment`, `az graph query`) — primary control-plane enumeration.
- **Azure Resource Manager REST API** — direct ARM calls for accounts, keys, and role resources.
- **Cosmos DB data-plane REST API / SDKs** — listing databases/containers and sampling items.
- **PowerShell `Az.CosmosDB`** — equivalent control-plane cmdlets.
- **Azure Resource Graph** — tenant-scale inventory and misconfiguration sweeps.

## References

- Azure Cosmos DB documentation — https://learn.microsoft.com/en-us/azure/cosmos-db/
- Configure role-based access control (data plane) — https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac
- Security / RBAC overview — https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control
- Cosmos DB Resource Provider REST API (database accounts) — https://learn.microsoft.com/en-us/rest/api/cosmos-db-resource-provider/database-accounts
- Cosmos DB data-plane REST API — https://learn.microsoft.com/en-us/rest/api/cosmos-db/
- Restrict user access with resource tokens — https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-restrict-user-data
- Configure IP firewall — https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall
- hacking the cloud — Azure — https://hackingthe.cloud/azure/
