---
cstg_id: CSTG-AZURE-SQL-DATABASE-ENUM
title: "AZURE Sql Database - Enumeration"
provider: azure
service: sql-database
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.Sql/servers/read
  - Microsoft.Sql/servers/databases/read
  - Microsoft.Sql/servers/firewallRules/read
  - Microsoft.Sql/servers/administrators/read
  - Microsoft.Sql/servers/azureADOnlyAuthentications/read
  - Microsoft.Sql/servers/auditingSettings/read
  - Microsoft.Sql/servers/securityAlertPolicies/read
  - Microsoft.Sql/servers/encryptionProtector/read
  - Microsoft.Sql/servers/privateEndpointConnections/read
  - Microsoft.Sql/servers/databases/transparentDataEncryption/read
  - Microsoft.Sql/servers/databases/dataMaskingPolicies/read
  - Microsoft.Sql/servers/connectionPolicies/read
tools:
  - cloud provider CLI
  - cloud provider REST API client
  - infrastructure resource graph query tools
  - SQL client libraries / command-line query tools
references:
  - https://learn.microsoft.com/en-us/cli/azure/sql/server
  - https://learn.microsoft.com/en-us/cli/azure/sql/db
  - https://learn.microsoft.com/en-us/rest/api/sql/
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
  - https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
license: CC BY-SA 4.0
---

## Summary

This page covers enumeration of Azure SQL Database from an authenticated read-only position on the management (ARM) plane and, where reachable, the data plane. The goal is to build a complete inventory of logical servers and databases, map their network exposure and authentication configuration, identify the principals that hold control- and data-plane authority, and surface security-relevant settings (auditing, threat protection, encryption, data masking) that affect both risk and the attacker's ability to operate undetected.

Two distinct planes must be enumerated separately:

- **Control plane (Azure Resource Manager):** server/database resources, firewall rules, Entra admin assignment, auditing, Defender for SQL, encryption protector, and Private Endpoint connections. Governed by Azure RBAC.
- **Data plane (TDS, port 1433):** schemas, tables, logins/users, role memberships, and stored objects. Governed by SQL/Entra authentication and database-level permissions, independent of RBAC.

A common privilege-escalation pivot is that control-plane authority (for example a role that can write firewall rules and reset the Entra admin) can be leveraged to gain data-plane access even without an existing database login - see [azure-sql-database-post-exploitation.md](../05-post-exploitation/azure-sql-database-post-exploitation.md).

## Prerequisites

- A valid Entra ID principal (user, service principal, or managed identity) with at least Reader on the target scope for control-plane enumeration. The permissions listed in the frontmatter are the read actions that yield a complete picture; `Reader` includes all of them.
- For data-plane enumeration, a network path to TCP 1433 (see [azure-sql-database-unauthenticated.md](../01-unauthenticated-external/azure-sql-database-unauthenticated.md)) and either a SQL login or an Entra principal mapped to a database user.

## Enumeration

### Inventory logical servers and databases

```bash
# All logical SQL servers visible to the principal, across subscriptions
az sql server list -o table

# Databases on a given server (excludes the 'master' system DB in output naming)
az sql db list --resource-group <rg> --server <server> -o table

# Full server properties: admin login, version, public network access, minimal TLS, state
az sql server show --resource-group <rg> --name <server> -o json
```

For broad, cross-subscription inventory, Azure Resource Graph is far faster than iterating per-subscription:

```bash
# Enumerate every SQL server and its public-network-access / TLS posture tenant-wide
az graph query -q "resources
| where type =~ 'microsoft.sql/servers'
| project name, resourceGroup, subscriptionId,
          publicNetworkAccess = properties.publicNetworkAccess,
          minimalTlsVersion = properties.minimalTlsVersion,
          adminLogin = properties.administratorLogin,
          location"

# Enumerate all databases
az graph query -q "resources
| where type =~ 'microsoft.sql/servers/databases'
| project name, resourceGroup, subscriptionId"
```

### Map network exposure

```bash
# Server-level IP firewall rules. Watch for 0.0.0.0/0.0.0.0 (Allow Azure services)
# and 0.0.0.0/255.255.255.255 (allow all).
az sql server firewall-rule list --resource-group <rg> --server <server> -o table

# Virtual network rules (subnet-scoped access)
az sql server vnet-rule list --resource-group <rg> --server <server> -o table

# Private Endpoint connections - presence suggests public access should be disabled
az sql server private-endpoint-connection list --resource-group <rg> --server <server> -o json

# Connection policy (Default / Proxy / Redirect)
az sql server conn-policy show --resource-group <rg> --server <server> -o json
```

A firewall rule named `AllowAllWindowsAzureIps` with start and end IP `0.0.0.0` indicates the "Allow Azure services and resources to access this server" toggle is on.

### Enumerate authentication configuration

```bash
# Microsoft Entra admin assigned to the server (a high-value target principal)
az sql server ad-admin list --resource-group <rg> --server <server> -o json

# Is Entra-only authentication enforced? If 'false', SQL logins are still accepted.
az sql server ad-only-auth get --resource-group <rg> --server <server> -o json
```

`administratorLogin` from `az sql server show` is the SQL admin account name; combined with `ad-only-auth` being disabled, it indicates SQL authentication is a live vector.

### Enumerate security and audit posture

These settings determine both residual risk and how visible subsequent activity will be.

```bash
# SQL Auditing (server-level): is it enabled, and where do logs go?
az sql server audit-policy show --resource-group <rg> --name <server> -o json

# Microsoft Defender for SQL (advanced threat protection)
az sql server threat-policy show --resource-group <rg> --server <server> -o json 2>/dev/null
az security pricing show -n SqlServers -o json

# Transparent Data Encryption protector (service-managed vs customer-managed key)
az sql server tde-key show --resource-group <rg> --server <server> -o json

# Per-database TDE state
az sql db tde show --resource-group <rg> --server <server> --database <db> -o json
```

### Raw REST API enumeration

When the CLI is unavailable or to confirm exact field values, the same data is available via the ARM REST API with a management-scoped bearer token:

```bash
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
SUB=<subscription-id>; RG=<rg>; SRV=<server>
API=2023-08-01-preview

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Sql/servers/$SRV/firewallRules?api-version=$API"

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Sql/servers/$SRV/administrators?api-version=$API"
```

### Data-plane enumeration

Once a login is available and the network path is open, enumerate inside the database. An Entra principal can obtain a database access token without a stored password:

```bash
# Acquire an Entra access token scoped to the SQL data plane
az account get-access-token --resource https://database.windows.net --query accessToken -o tsv
```

Use the token or a SQL login with a client to inventory principals, permissions, and objects:

```sql
-- Logins and users
SELECT name, type_desc, is_disabled FROM sys.sql_logins;
SELECT name, type_desc, authentication_type_desc FROM sys.database_principals
WHERE type IN ('S','U','G','E','X');

-- Role memberships (who is in db_owner / db_securityadmin / etc.)
SELECT dp.name AS member, rp.name AS role
FROM sys.database_role_members drm
JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id
JOIN sys.database_principals rp ON drm.role_principal_id = rp.principal_id;

-- Server-level role membership (when connected to master)
SELECT * FROM sys.server_role_members;

-- Effective permissions of the current principal
SELECT * FROM sys.fn_my_permissions(NULL, 'DATABASE');

-- Schema and table inventory
SELECT s.name AS schema_name, t.name AS table_name
FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id;

-- Stored procedures, functions, and views (potential for embedded credentials/logic)
SELECT name, type_desc FROM sys.objects WHERE type IN ('P','FN','V','TR');
```

## Misconfigurations & Findings

- **`publicNetworkAccess = Enabled`** on servers that also have Private Endpoints, or that have no business need for public exposure.
- **Firewall rules permitting `0.0.0.0`-`255.255.255.255`** or the `AllowAllWindowsAzureIps` (`0.0.0.0`/`0.0.0.0`) rule.
- **`minimalTlsVersion` below 1.2**, or unset (defaulting to permit legacy TLS).
- **Entra-only authentication disabled** (`azureADOnlyAuthentication = false`), leaving SQL logins active.
- **No SQL Auditing**, or auditing routed to a destination the principal can also write to (enabling log tampering).
- **Microsoft Defender for SQL not enabled** at the server or subscription tier.
- **Service-managed TDE only**, where customer-managed keys (CMK) with separation of duties are required by policy.
- **Overly broad Azure RBAC**: principals holding `SQL Server Contributor`, `Contributor`, or custom roles with `Microsoft.Sql/servers/firewallRules/write` and `Microsoft.Sql/servers/administrators/write`, which together enable a data-plane takeover.
- **Data masking misconfigured or absent** on columns containing sensitive data.

## Detection & Logging

- **Azure Activity Logs** record all read and write operations against `Microsoft.Sql/*` resources, including the listing of firewall rules and administrators. High-volume read enumeration across many servers in a short window is a detectable reconnaissance pattern.
- **Microsoft Entra ID sign-in logs** show the token acquisitions used for both ARM (`https://management.azure.com`) and data-plane (`https://database.windows.net`) access, including the application and source IP.
- **Microsoft Entra ID audit logs** record changes to the SQL server's Entra admin assignment.
- **SQL Auditing**, when enabled, captures data-plane queries against `sys.*` catalog views and other enumeration activity.
- **Microsoft Defender for SQL** can flag "Suspected database enumeration" and "Access from an unusual location" patterns.

## Remediation & Hardening

- Apply least-privilege Azure RBAC; avoid broad Contributor-class grants on SQL scopes. Audit any custom role carrying `firewallRules/write` or `administrators/write`.
- Disable public network access and use Private Endpoints; where public access is required, restrict firewall rules to known IPs and disable "Allow Azure services".
- Enforce Entra-only authentication and minimum TLS 1.2.
- Enable SQL Auditing to an append-only/immutable destination and enable Microsoft Defender for SQL across all servers.
- Inside the database, apply least-privilege role membership; review `db_owner`, `db_securityadmin`, and `CONTROL` grants.
- Use dynamic data masking and column-level encryption for sensitive data, and customer-managed keys for TDE where policy requires.

## Tools

- Cloud provider CLI (server/database/firewall/admin/audit enumeration).
- Cloud provider REST API client (exact field retrieval, automation).
- Infrastructure resource graph query tools (tenant-wide inventory and posture queries).
- SQL client libraries and command-line query tools (data-plane principal, permission, and schema enumeration).

## References

- CLI reference: sql server - https://learn.microsoft.com/en-us/cli/azure/sql/server
- CLI reference: sql db - https://learn.microsoft.com/en-us/cli/azure/sql/db
- Azure SQL REST API - https://learn.microsoft.com/en-us/rest/api/sql/
- Microsoft Entra authentication overview - https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview
- Configure firewall rules - https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure
- Transparent Data Encryption overview - https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview
- SQL Auditing overview - https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
- Azure Resource Graph overview - https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
