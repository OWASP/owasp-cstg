---
cstg_id: CSTG-AZURE-LOGIC-APPS-ENUM
title: "AZURE Logic Apps - Enumeration"
provider: azure
service: logic-apps
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.Logic/workflows/read
  - Microsoft.Logic/workflows/triggers/read
  - Microsoft.Logic/workflows/runs/read
  - Microsoft.Logic/workflows/versions/read
  - Microsoft.Web/connections/read
  - Microsoft.Web/sites/read
  - Microsoft.Authorization/roleAssignments/read
tools:
  - Azure CLI (az)
  - Azure PowerShell (Az.LogicApp)
  - Azure REST API
  - MicroBurst
  - ScoutSuite
  - AzureHound / BloodHound
references:
  - "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview"
  - "https://learn.microsoft.com/en-us/rest/api/logic/"
  - "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app"
  - "https://learn.microsoft.com/en-us/azure/connectors/managed"
  - "https://learn.microsoft.com/en-us/azure/logic-apps/single-tenant-overview-compare"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure Logic Apps is a workflow-orchestration and integration service. A workflow is a sequence of a trigger (what starts the run) and one or more actions (HTTP calls, connector operations, control-flow steps) defined in a JSON document using the Workflow Definition Language. Logic Apps come in two hosting models: **Consumption** (multi-tenant, one workflow per Logic App resource, `Microsoft.Logic/workflows`) and **Standard** (single-tenant, runs on an App Service plan as a `Microsoft.Web/sites` of kind `functionapp,workflowapp`, hosting multiple workflows). Both connect to other systems through **connections** — managed API connections (`Microsoft.Web/connections`) that store authorization to a connector (Office 365, SQL, Key Vault, Service Bus, storage, third-party SaaS) and, in many cases, cached OAuth tokens or credentials.

From an offensive perspective Logic Apps are valuable because they combine three exposed assets: **trigger URLs** (HTTP-request triggers carry an inline Shared Access Signature in the callback URL, granting anyone with the URL the ability to invoke the workflow), **stored connections** (a workflow can reach mailboxes, databases, storage, and SaaS tenants through pre-authorized connections), and a **managed identity** that the workflow can use to authenticate to Azure Resource Manager and Key Vault. Run history additionally exposes the inputs and outputs of every action — frequently including secrets, tokens, and sensitive business data in cleartext.

This page covers read-only discovery and inventory of Logic Apps, their definitions, triggers, connections, identities, and run history. Exploitation of those findings is covered in [Logic Apps - Privilege Escalation](../03-privilege-escalation/azure-logic-apps-privesc.md).

## Prerequisites

- An authenticated principal (user, service principal, or managed identity) with at least read access to the target subscription or resource group.
- Reader on the Logic App / resource group is sufficient for most inventory operations. `Microsoft.Logic/workflows/read` returns the workflow and its full definition; `.../runs/read` and `.../triggers/read` return run history and trigger metadata. Reading Standard workflows additionally uses `Microsoft.Web/sites/read` against the hosting site.
- The **trigger callback URL with its SAS signature** is returned by the `listCallbackUrl` action, which Reader-level roles can call — this is the key enumeration nuance: read access yields an invocable URL.
- Connection *metadata* (connector type, target, display name) is readable; the cached secret/token inside a connection is not returned by read operations.
- Azure CLI, Azure PowerShell `Az.LogicApp`, or direct REST calls with a bearer token for `https://management.azure.com`.

## Enumeration

### Locate Logic Apps in scope

```bash
# Consumption Logic Apps visible to the caller
az logic workflow list -o table
az logic workflow list --resource-group <rg> -o table

# Resource Graph is fastest at scale and surfaces both hosting models
az graph query -q "Resources | where type =~ 'microsoft.logic/workflows' | project name, resourceGroup, subscriptionId, location, identity, properties.state"

# Standard Logic Apps appear as Web sites of a workflow kind
az graph query -q "Resources | where type =~ 'microsoft.web/sites' and kind contains 'workflowapp' | project name, resourceGroup, location, identity"
```

```powershell
Get-AzLogicApp | Format-Table Name, Location, State
```

Raw REST:

```bash
TOKEN=$(az account get-access-token --query accessToken -o tsv)
SUB=$(az account show --query id -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
```

### Retrieve the workflow definition

The workflow definition is the single most informative artifact: it contains the trigger configuration, every action, embedded URLs and hostnames, references to connections, and frequently inline secrets or parameter defaults.

```bash
az logic workflow show -g <rg> -n <workflow> --query definition

# Save the full definition for offline review
az logic workflow show -g <rg> -n <workflow> -o json > <workflow>.json
```

```bash
TOKEN=$(az account get-access-token --query accessToken -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>?api-version=2019-05-01"
```

For Standard Logic Apps, workflow definitions live as `workflow.json` files inside the host site and are retrievable through the App Service file API or the workflow management API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Web/sites/<site>/hostruntime/runtime/webhooks/workflow/api/management/workflows?api-version=2018-11-01"
```

Review every definition for: hardcoded API keys, basic-auth headers, connection strings in `HTTP` actions, internal hostnames/URLs, `parameters` blocks with secret defaults, and which connections each action references.

### Triggers and callback URLs (high value)

HTTP-request triggers expose a callback URL containing an inline SAS signature. Reading it yields a directly invocable endpoint.

```bash
# List triggers on the workflow
az logic workflow trigger list -g <rg> -n <workflow> -o table

# Retrieve the callback URL (includes the SAS sig query parameters)
az rest --method post \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/triggers/<trigger>/listCallbackUrl?api-version=2019-05-01"
```

The returned `value` is the full HTTPS endpoint with `sp`, `sv`, and `sig` query parameters — anyone holding it can invoke the workflow without further Azure authentication. Catalog every callback URL discovered.

### Run history (inputs and outputs)

Run history records the inputs and outputs of every action across past executions and is a rich source of leaked secrets and data.

```bash
# List runs
az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/runs?api-version=2019-05-01"

# List actions of a specific run, then read each action's input/output links
az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/runs/<runId>/actions?api-version=2019-05-01"
```

Action inputs/outputs are exposed via `inputsLink` and `outputsLink` URIs returned in the action object; follow those links (they carry their own SAS) to read the cleartext payloads, which commonly include bearer tokens, passwords submitted to HTTP actions, query results, and email contents.

### Connections

```bash
# Managed API connections in the resource group
az resource list --resource-group <rg> --resource-type "Microsoft.Web/connections" -o table

# Detail of a connection: connector type, target API, auth status
az resource show --ids "/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Web/connections/<conn>" --api-version 2016-06-01
```

A connection's `api.id` and `displayName` reveal what system it reaches (e.g. `office365`, `sql`, `keyvault`, `azureblob`, `servicebus`). Connections in a `Connected` state hold a usable authorization; the cached token/secret is not returned by reads but is usable at workflow runtime.

### Identity of the workflow

Determine what Azure RBAC and Graph permissions a workflow inherits at runtime.

```bash
# Consumption
az logic workflow show -g <rg> -n <workflow> --query identity

# Standard (App Service-hosted)
az webapp identity show -g <rg> -n <site>

# Resolve role assignments held by that principal
PRINCIPAL=$(az logic workflow show -g <rg> -n <workflow> --query identity.principalId -o tsv)
az role assignment list --assignee "$PRINCIPAL" --all -o table
```

### Access control and IP restrictions

```bash
# accessControl shows IP allow-lists for trigger/contents/actions (often empty = open)
az logic workflow show -g <rg> -n <workflow> --query accessControl
```

## Misconfigurations & Findings

- **Open HTTP-trigger callback URL.** The trigger SAS URL has no IP restriction (`accessControl.triggers.allowedCallerIpAddresses` empty); a leaked or enumerated URL allows anonymous invocation. This is the most common Logic Apps exposure.
- **Over-privileged managed identity.** The workflow's identity holds Contributor, Owner, User Access Administrator, or Key Vault data-plane roles; anyone who can edit/run the workflow inherits that privilege. Severe finding.
- **Secrets in the definition.** Hardcoded API keys, basic-auth headers, and connection strings embedded directly in `HTTP` actions or `parameters` defaults, readable with `workflows/read`.
- **Secrets in run history.** Inputs/outputs persisted in cleartext expose tokens, passwords, and sensitive data to anyone with `runs/read`.
- **Highly-privileged stored connections.** A `Connected` connection to Office 365, SQL, Key Vault, or storage grants reachable access to those systems through the workflow without separate authentication.
- **No secure-inputs/secure-outputs flag.** Actions handling secrets are not marked `secureInputs`/`secureOutputs`, so sensitive data is logged in run history.
- **Run-history contents readable without `accessControl.contents` restriction.** The `contents` access control is unset, so input/output links are retrievable by any reader.
- **Diagnostic logging disabled.** Workflow runtime and trigger diagnostics not forwarded to Log Analytics, leaving execution unmonitored.

## Exploitation

Enumeration itself is non-destructive. The inventory produced here feeds downstream activity:

1. **Workflow invocation and code-path abuse** — a discovered open callback URL can be invoked with crafted input; if the workflow performs privileged actions (writes to storage, sends mail, calls ARM as its identity), the caller drives those actions. See [Logic Apps - Privilege Escalation](../03-privilege-escalation/azure-logic-apps-privesc.md).
2. **Privilege escalation via the managed identity** — if the workflow identity is over-privileged, a principal able to edit the definition or trigger a run executes actions as that identity. See the privilege-escalation page.
3. **Lateral movement through connections** — a `Connected` connection is a pre-authorized path into the connected system.

Prioritise workflows whose identity has broad role assignments, whose callback URLs are unrestricted, and whose connections reach high-value systems.

## Detection & Logging

- **Azure Activity Logs** record control-plane reads such as `Microsoft.Logic/workflows/read`, `.../runs/read`, and the `.../triggers/listCallbackUrl/action` call (retrieving the SAS-bearing URL). A `listCallbackUrl` call followed by external invocation of that URL is a notable chain.
- **Entra ID sign-in and audit logs** attribute the calling identity. A service principal or user enumerating Logic App definitions and run history outside its baseline is a useful signal.
- Reading run-history inputs/outputs is a control-plane operation logged in Activity Logs; bulk retrieval of action input/output links by one principal in a short window indicates secret harvesting.
- Microsoft Defender for Cloud surfaces alerts for anomalous Logic Apps activity when the resource is onboarded; route workflow runtime diagnostics to Log Analytics for run-level visibility.

## Remediation & Hardening

- Restrict HTTP-trigger access with `accessControl.triggers.allowedCallerIpAddresses` (an IP allow-list) and prefer connector or Entra-authenticated triggers over open SAS callback URLs; regenerate trigger access keys periodically.
- Apply least privilege to the workflow's managed identity; grant only the specific roles and scopes its actions require, never subscription Contributor/Owner by default.
- Mark actions that handle secrets with `secureInputs` and `secureOutputs` so values are redacted from run history; reference secrets from Key Vault at runtime rather than embedding them in the definition.
- Set `accessControl.contents` and `accessControl.actions` IP restrictions to limit who can read run input/output payloads.
- Scope and review managed API connections; remove unused `Connected` connections and prefer connections that use the workflow's managed identity over stored credentials.
- Forward Logic Apps diagnostic logs (WorkflowRuntime, trigger/action events) to Log Analytics and enable alerting on anomalous invocation.

## Tools

- **Azure CLI (az)** with the `logic` extension — primary enumeration interface for Consumption workflows; `az webapp` / `az resource` for Standard and connections.
- **Azure PowerShell (Az.LogicApp)** — `Get-AzLogicApp`, `Get-AzLogicAppTrigger`, `Get-AzLogicAppRunHistory`, `Get-AzLogicAppTriggerCallbackUrl`.
- **Azure REST API** — direct calls to `management.azure.com` for run actions, callback URLs, and Standard workflow definitions.
- **MicroBurst** — PowerShell toolkit with Azure resource enumeration and secret-hunting helpers applicable to Logic Apps definitions and run history.
- **ScoutSuite** — multi-cloud auditing that reports Logic Apps posture.
- **AzureHound / BloodHound** — graph the workflow identity's role assignments and reachable targets.

## References

- Logic Apps overview — https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview
- Logic Apps REST API — https://learn.microsoft.com/en-us/rest/api/logic/
- Securing a Logic App — https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app
- Managed connectors — https://learn.microsoft.com/en-us/azure/connectors/managed
- Single-tenant vs multi-tenant comparison — https://learn.microsoft.com/en-us/azure/logic-apps/single-tenant-overview-compare
- hackingthe.cloud Azure section — https://hackingthe.cloud/azure/
