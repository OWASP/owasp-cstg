---
cstg_id: CSTG-AZURE-APP-SERVICE-FUNCTIONS-ENUM
title: "AZURE App Service Functions - Enumeration"
provider: azure
service: app-service-functions
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Web/sites/read"
  - "Microsoft.Web/sites/config/read"
  - "Microsoft.Web/sites/config/list/action"
  - "Microsoft.Web/sites/functions/read"
  - "Microsoft.Web/sites/functions/listkeys/action"
  - "Microsoft.Web/sites/host/listkeys/action"
  - "Microsoft.Web/sites/publishxml/action"
  - "Microsoft.Web/sites/slots/read"
  - "Microsoft.Web/serverfarms/read"
  - "Microsoft.Web/sites/basicPublishingCredentialsPolicies/read"
tools:
  - azure-cli
  - az-rest
  - azure-powershell
  - microburst
  - roadrecon
references:
  - "https://learn.microsoft.com/en-us/cli/azure/webapp"
  - "https://learn.microsoft.com/en-us/cli/azure/functionapp"
  - "https://learn.microsoft.com/en-us/rest/api/appservice/web-apps"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger"
  - "https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity"
  - "https://learn.microsoft.com/en-us/azure/app-service/reference-app-settings"
  - "https://github.com/NetSPI/MicroBurst"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-oriented enumeration of Azure App Service web apps and Azure Function Apps from a foothold that has at least directory/subscription read access. The goal is to inventory every app and slot, read its configuration and app settings, identify attached managed identities, enumerate functions and their authorization levels, recover function/host/master keys and publish profiles, and locate the connection strings and secrets these apps hold. The output of this phase feeds privilege-escalation and persistence work: a function's managed identity, a recovered master key, or a connection string in app settings is frequently the most direct route to broader access.

App Service and Functions share the same `Microsoft.Web` resource provider. Both expose a control plane (ARM management API / `az`) and a data/management plane (the Kudu SCM site and the Functions admin/key APIs). Enumeration spans both planes.

## Prerequisites

- An authenticated principal (user, service principal, or managed identity) with read access to the target scope.
- Reader-level RBAC (`Microsoft.Web/sites/read`, `.../config/read`) is enough to inventory apps and most configuration. Recovering secrets additionally requires the `list`/`listkeys` POST actions and `publishxml/action`, which the built-in **Reader** role does **not** grant but **Contributor**, **Website Contributor**, and custom roles often do.
- Azure CLI, Azure PowerShell (`Az` module), or a token for `https://management.azure.com`.

## Enumeration

### Inventory apps, function apps, and slots

```bash
# All web apps and function apps in scope
az webapp list -o table
az functionapp list -o table

# Deployment slots are distinct deploy targets and hostnames
az webapp deployment slot list -g <rg> -n <app> -o table

# App Service plans (SKU, OS, whether it is Linux/containerized)
az appservice plan list -o table

# Raw ARM listing (works for any management-plane token)
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Web/sites?api-version=2023-12-01"
```

### Read configuration, app settings, and connection strings

App settings and connection strings frequently contain the most valuable secrets (storage keys, SQL/Cosmos connection strings, downstream API keys, service principal credentials).

```bash
# Site configuration (runtime, network, scm settings, identity hints)
az webapp config show -g <rg> -n <app>

# App settings (environment variables) - often contains secrets in cleartext
az webapp config appsettings list -g <rg> -n <app> -o json
az functionapp config appsettings list -g <rg> -n <app> -o json

# Connection strings
az webapp config connection-string list -g <rg> -n <app>

# Whether the app references Key Vault for its settings (look for @Microsoft.KeyVault references)
az webapp config appsettings list -g <rg> -n <app> \
  --query "[?contains(value,'KeyVault')]"
```

### Enumerate identities (the privesc pivot)

```bash
# System-assigned and user-assigned managed identities
az webapp identity show -g <rg> -n <app>
az functionapp identity show -g <rg> -n <app>

# Resolve what the identity can reach
az role assignment list --assignee <identity-principal-id> --all -o table
```

A managed identity attached to an app is the single most important enumeration finding: any code or console access on the app can mint tokens for that identity. See [the privilege-escalation page](../03-privilege-escalation/azure-app-service-functions-privesc.md).

### Enumerate functions and authorization levels

```bash
# List functions in a Function App
az functionapp function list -g <rg> -n <app> -o table

# Per-function definition reveals authLevel (anonymous/function/admin) and bindings
az functionapp function show -g <rg> -n <app> --function-name <fn>

# Raw config.bindings via ARM
az rest --method get --url \
 "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/functions/<fn>?api-version=2023-12-01"
```

### Recover keys, master key, and publish profiles

```bash
# Per-function keys
az functionapp function keys list -g <rg> -n <app> --function-name <fn>

# Host keys + the master key (master = full admin over the Functions runtime)
az functionapp keys list -g <rg> -n <app>
az rest --method post --url \
 "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/host/default/listkeys?api-version=2023-12-01"

# Publish profile = SCM/FTP credentials for deploy + Kudu console
az webapp deployment list-publishing-profiles -g <rg> -n <app> --xml

# SCM publishing credentials (basic-auth user/pass for Kudu)
az rest --method post --url \
 "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/config/publishingcredentials/list?api-version=2023-12-01"

# Are basic-auth deployment credentials enabled? (persistence/footprint check)
az resource show --ids \
 "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/basicPublishingCredentialsPolicies/scm" \
 --api-version 2023-12-01
```

### Inspect the SCM/Kudu data plane

With publish credentials or an Entra token scoped to the SCM site:

```bash
# Environment variables (incl. all app settings) as the runtime sees them
curl -s -u '<user>:<pass>' https://<app>.scm.azurewebsites.net/api/settings

# File system browse / download
curl -s -u '<user>:<pass>' https://<app>.scm.azurewebsites.net/api/vfs/site/wwwroot/

# Deployment history (source repo URLs, commit authors)
curl -s -u '<user>:<pass>' https://<app>.scm.azurewebsites.net/api/deployments
```

### Network and exposure posture

```bash
az webapp config access-restriction show -g <rg> -n <app>
az webapp vnet-integration list -g <rg> -n <app>
az webapp config show -g <rg> -n <app> --query "{https:httpsOnly,minTls:minTlsVersion,ftps:ftpsState,scmIp:scmIpSecurityRestrictions}"
```

## Misconfigurations & Findings

- **Secrets in app settings/connection strings in cleartext** rather than Key Vault references - directly readable by anyone with config-list rights.
- **Highly privileged managed identity** (Owner/Contributor at subscription, Key Vault access policy, or write access to other resources) attached to an app, turning app-level access into tenant-level access.
- **Master/host key obtainable** by the foothold principal - the master key is full admin over the Functions runtime and individual function keys.
- **Publish profile / SCM basic auth enabled** - recoverable credentials grant Kudu console (RCE) and FTP deploy without an Entra identity.
- **No access restrictions on the main or SCM site** - management plane reachable from anywhere.
- **`anonymous` functions** discovered in the inventory.
- **HTTPS not enforced**, weak `minTlsVersion`, or FTP/FTPS enabled.
- **Source control integration to attacker-influenceable repos** or deployment from public packages.

## Exploitation

Enumeration is read-focused, but the recovered material is immediately actionable:

- Use connection strings / storage keys found in app settings to access the backing data stores.
- Use a recovered **master key** to invoke any function (including `admin`-level) and to call the Functions admin API.
- Use a recovered **publish profile** to log into Kudu and run commands (`POST /api/command`) - effectively RCE in the app context, with access to the app's managed-identity token endpoint.
- Use the managed-identity token endpoint from inside the app to obtain ARM/Graph/Key Vault tokens (detailed in the privilege-escalation page).

## Detection & Logging

- **Azure Activity Logs** record the control-plane reads/POSTs used here, notably `Microsoft.Web/sites/config/list/action`, `.../host/listkeys/action`, `.../functions/listkeys/action`, and `.../publishxml/action` (and `publishingcredentials/list`). A burst of `listkeys`/`publishxml` calls across many apps is a strong enumeration/secret-harvest signal.
- **Entra ID sign-in logs** show the principal authenticating to ARM and to the SCM site.
- **App Service diagnostic logs** (`AppServiceAuditLogs`, `AppServiceConsoleLogs`, `AppServiceHTTPLogs`) capture Kudu/SCM access and `api/settings`, `api/vfs`, `api/command` calls.
- Reads of `basicPublishingCredentialsPolicies` and access-restriction config indicate posture mapping ahead of persistence.

## Remediation & Hardening

- Store secrets in **Key Vault** and reference them with `@Microsoft.KeyVault(...)` app settings; never place raw secrets in app settings or connection strings.
- Scope managed identities with least privilege; avoid Owner/Contributor on app identities and prefer resource-scoped role assignments.
- Restrict who holds the `list`/`listkeys`/`publishxml` actions - the built-in **Reader** role intentionally excludes them; review **Contributor**/**Website Contributor** assignments.
- Disable SCM/FTP **basic publishing credentials** and require Entra ID for SCM.
- Apply access restrictions/private endpoints to the main and SCM sites; enforce HTTPS and `minTlsVersion 1.2`+, disable FTP.
- Prefer `function`/`admin` authorization for functions and rotate host/function keys regularly.
- Stream all diagnostic categories to Log Analytics and alert on `listkeys`/`publishxml` bursts.

## Tools

- **Azure CLI** (`az webapp`, `az functionapp`) and `az rest` - primary management-plane enumeration.
- **Azure PowerShell** (`Az.Websites`) - equivalent cmdlets.
- **MicroBurst** - automated App Service / Function App and key/credential discovery across a subscription.
- **ROADrecon** - Entra ID enumeration to resolve identities and role assignments tied to apps.

## References

- [az webapp reference](https://learn.microsoft.com/en-us/cli/azure/webapp)
- [az functionapp reference](https://learn.microsoft.com/en-us/cli/azure/functionapp)
- [App Service Web Apps REST API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps)
- [Managed identities for App Service and Functions](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
- [App Service app settings reference](https://learn.microsoft.com/en-us/azure/app-service/reference-app-settings)
- [NetSPI MicroBurst](https://github.com/NetSPI/MicroBurst)
