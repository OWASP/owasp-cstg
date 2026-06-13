---
cstg_id: CSTG-AZURE-AUTOMATION-ACCOUNTS-ENUM
title: "AZURE Automation Accounts - Enumeration"
provider: azure
service: automation-accounts
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.Automation/automationAccounts/read
  - Microsoft.Automation/automationAccounts/runbooks/read
  - Microsoft.Automation/automationAccounts/credentials/read
  - Microsoft.Automation/automationAccounts/variables/read
  - Microsoft.Automation/automationAccounts/connections/read
  - Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/read
  - Microsoft.Authorization/roleAssignments/read
tools:
  - Azure CLI (az)
  - Azure PowerShell (Az.Automation)
  - Azure REST API
  - MicroBurst
  - ScoutSuite
  - PowerZure
references:
  - "https://learn.microsoft.com/en-us/azure/automation/overview"
  - "https://learn.microsoft.com/en-us/rest/api/automation/"
  - "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview"
  - "https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure Automation Accounts are a control-plane service for orchestrating operational tasks across Azure and hybrid environments. An Automation Account hosts runbooks (PowerShell, PowerShell Workflow, Python 2/3, and graphical), schedules, webhooks, shared resources (variables, credentials, certificates, connections), DSC configurations, Update Management, and Hybrid Runbook Worker groups that execute jobs on machines outside Azure. Each account can hold one or more identities: a system-assigned managed identity, user-assigned managed identities, and (in legacy deployments) a "Run As" account backed by a service principal and a self-signed certificate.

From an offensive perspective the service is a high-value target because it combines **stored secrets** (credential and certificate assets, connection strings, variables marked encrypted) with a **code-execution surface** (runbooks) and a set of **privileged identities** that frequently hold Contributor or broader roles over a subscription. Enumerating an Automation Account establishes which jobs run where, which secrets are reachable, what identity a runbook will execute as, and whether external trigger paths (webhooks, schedules, Hybrid Workers) exist.

This page covers read-only discovery and inventory of Automation Accounts and their components. Exploitation of those findings is covered in [Automation Accounts - Privilege Escalation](../03-privilege-escalation/azure-automation-accounts-privesc.md) and [Automation Accounts - Persistence](../06-persistence/azure-automation-accounts-persistence.md).

## Prerequisites

- An authenticated principal (user, service principal, or managed identity) with at least read access to the target subscription or resource group.
- Reader on the Automation Account (or the broader scope) is sufficient for most inventory operations. The `Microsoft.Automation/automationAccounts/read` permission lists the account; reading child objects (runbooks, variables, connections, hybrid worker groups) requires the corresponding `*/read` data actions, which Reader grants.
- Note that the **plaintext value** of an encrypted variable and the **secret** of a credential or certificate asset are *not* returned by read operations — retrieving those requires job execution and is covered in the privilege-escalation page. Enumeration reveals their existence and metadata only.
- Azure CLI with the automation extension, or Azure PowerShell `Az.Automation`, or direct REST calls with a bearer token for `https://management.azure.com`.

## Enumeration

### Locate Automation Accounts in scope

```bash
# All Automation Accounts visible to the caller
az automation account list -o table

# Within a specific resource group
az automation account list --resource-group <rg> -o table

# Resource Graph is fastest at tenant/subscription scale
az graph query -q "Resources | where type =~ 'microsoft.automation/automationaccounts' | project name, resourceGroup, subscriptionId, location, identity"
```

```powershell
Get-AzAutomationAccount | Format-Table AutomationAccountName, ResourceGroupName, Location
```

Raw REST:

```bash
TOKEN=$(az account get-access-token --query accessToken -o tsv)
SUB=$(az account show --query id -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01"
```

### Identity of the account

Determining what a runbook will run as is the single most important enumeration step. Check both managed identities and any legacy Run As account.

```bash
# System- and user-assigned managed identity principalIds
az automation account show -g <rg> -n <account> --query identity

# Resolve the role assignments held by that principal across the tenant
PRINCIPAL=$(az automation account show -g <rg> -n <account> --query identity.principalId -o tsv)
az role assignment list --assignee "$PRINCIPAL" --all -o table
```

Legacy Run As accounts surface as a service principal and a connection asset named `AzureRunAsConnection` plus a certificate asset `AzureRunAsCertificate`:

```bash
az automation connection list -g <rg> --automation-account-name <account> -o table
az automation certificate list -g <rg> --automation-account-name <account> -o table
```

### Runbooks

```bash
# List runbooks, type, state, and last-modified
az automation runbook list -g <rg> --automation-account-name <account> -o table

# Retrieve the source of a published runbook (often contains secrets or logic)
az automation runbook show -g <rg> --automation-account-name <account> -n <runbook> --query "{name:name, runbookType:runbookType, state:state}"
```

```powershell
Get-AzAutomationRunbook -ResourceGroupName <rg> -AutomationAccountName <account>
# Export the draft or published content to disk for review
Export-AzAutomationRunbook -ResourceGroupName <rg> -AutomationAccountName <account> -Name <runbook> -OutputFolder ./runbooks -Slot Published
```

Runbook content frequently embeds hardcoded credentials, connection strings, internal hostnames, storage account keys, and references to credential/variable assets. Review every exported runbook.

### Shared resource assets

```bash
# Variables (note isEncrypted; encrypted values are NOT returned)
az automation variable list -g <rg> --automation-account-name <account> -o table

# Credential assets (username is shown, password is not)
az automation credential list -g <rg> --automation-account-name <account> -o table

# Certificates and connections
az automation certificate list -g <rg> --automation-account-name <account> -o table
az automation connection list -g <rg> --automation-account-name <account> -o table
```

Connections of type `AzureServicePrincipal` reveal an Application (client) ID and tenant; the certificate thumbprint links back to a certificate asset. This identifies a service principal the account can authenticate as.

### Triggers: webhooks, schedules, jobs

```bash
# Schedules and links to runbooks
az automation schedule list -g <rg> --automation-account-name <account> -o table

# Job history reveals what has run, when, and its status
az automation job list -g <rg> --automation-account-name <account> -o table
```

Webhooks expose an unauthenticated HTTPS trigger URL. The full URL with token is only returned at creation time, but webhook *metadata* (name, expiry, enabled state, linked runbook) is enumerable:

```bash
TOKEN=$(az account get-access-token --query accessToken -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Automation/automationAccounts/<account>/webhooks?api-version=2015-10-31"
```

### Hybrid Runbook Worker groups

Hybrid Workers extend job execution to on-premises or other-cloud machines. They are a pivot point from Azure into a corporate network.

```bash
az automation hrwg list -g <rg> --automation-account-name <account> -o table
# Workers within a group
az automation hrwg hrw list -g <rg> --automation-account-name <account> --hybrid-runbook-worker-group-name <group> -o table
```

### State configuration (DSC)

```bash
az automation configuration list -g <rg> --automation-account-name <account> -o table
# DSC node configurations and registered nodes
TOKEN=$(az account get-access-token --query accessToken -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Automation/automationAccounts/<account>/nodes?api-version=2020-01-13-preview"
```

## Misconfigurations & Findings

- **Over-privileged managed identity / Run As account.** The account identity holds Owner, Contributor, or User Access Administrator at subscription scope. Any principal who can create or edit a runbook inherits that privilege at execution time. This is the most common and most severe finding.
- **Legacy Run As certificate.** Run As accounts (deprecated, retired for new creation) store a service principal certificate as an asset. The certificate is exportable through runbook execution and can be reused for offline authentication.
- **Secrets in runbook source.** Hardcoded passwords, storage keys, SAS tokens, and API keys committed into runbook bodies, recoverable by anyone with `runbooks/read`.
- **Webhooks without IP restriction.** Automation webhooks have no built-in source-IP allowlist and no per-call authentication beyond the URL token; a leaked URL grants anonymous runbook execution until expiry.
- **Source Control integration with stored PAT.** Accounts wired to a Git repo store a token used to sync runbooks; the integration metadata can expose the repository and sync identity.
- **Verbose logging disabled.** Job logs and diagnostic settings not forwarded to Log Analytics, leaving execution unmonitored.
- **Reader-readable account with credential/variable assets present.** The mere existence of `credentials`/`certificates`/encrypted `variables` signals reachable secrets to anyone who can later obtain job-execution rights.

## Exploitation

Enumeration itself is non-destructive. The inventory produced here feeds two downstream activities:

1. **Secret extraction and privilege escalation** — if the account identity is over-privileged or holds reachable assets, a principal able to create/edit/start runbooks can run code as that identity and dump assets. See [Automation Accounts - Privilege Escalation](../03-privilege-escalation/azure-automation-accounts-privesc.md).
2. **Persistence** — webhooks, schedules, hidden runbooks, and Hybrid Workers provide durable footholds. See [Automation Accounts - Persistence](../06-persistence/azure-automation-accounts-persistence.md).

Prioritise accounts whose identity has broad role assignments (the `az role assignment list --assignee <principalId>` output above) and whose asset inventory is non-empty.

## Detection & Logging

- **Azure Activity Logs** record control-plane reads such as `Microsoft.Automation/automationAccounts/read`, `.../runbooks/read`, and listing of assets. Bulk enumeration of multiple accounts/assets by a single principal in a short window is a useful signal.
- **Entra ID sign-in and audit logs** attribute the calling identity. Correlate the principal performing enumeration with its normal behaviour baseline; service principals suddenly listing Automation resources are notable.
- Read operations against assets do not return secret values, so they do not by themselves indicate compromise — but a read sweep immediately followed by a runbook create/start (see privesc page) is a high-confidence chain.
- Microsoft Defender for Cloud surfaces alerts for anomalous Automation activity when the resource is onboarded.

## Remediation & Hardening

- Apply least privilege to the account's managed identity; grant only the specific roles and scopes the runbooks need, never subscription Owner/Contributor by default.
- Migrate off legacy Run As accounts to managed identities and delete the residual Run As certificate and connection assets.
- Restrict who holds `Microsoft.Automation/automationAccounts/*/write` and `.../runbooks/*` — these enable code execution as the identity.
- Store secrets in Azure Key Vault referenced at runtime rather than in credential/variable assets or runbook source; scan runbook content for embedded secrets.
- Forward Automation diagnostic logs (JobLogs, JobStreams, DscNodeStatus) to Log Analytics and enable alerting.
- Set short expiry on webhooks, regenerate them on a schedule, and front them with a gateway that enforces source restrictions where feasible.

## Tools

- **Azure CLI (az)** with the `automation` extension — primary enumeration interface.
- **Azure PowerShell (Az.Automation)** — `Get-AzAutomationAccount`, `Get-AzAutomationRunbook`, `Export-AzAutomationRunbook`, `Get-AzAutomationVariable`, etc.
- **Azure REST API** — direct calls to `management.azure.com` for objects the CLI does not surface (webhooks, DSC nodes).
- **MicroBurst** — PowerShell toolkit with Automation-focused enumeration and asset-dump helpers.
- **PowerZure** — Azure offensive toolkit covering Automation runbook and asset operations.
- **ScoutSuite** — multi-cloud auditing that reports Automation Account posture.

## References

- Azure Automation overview — https://learn.microsoft.com/en-us/azure/automation/overview
- Automation REST API — https://learn.microsoft.com/en-us/rest/api/automation/
- Automation security overview — https://learn.microsoft.com/en-us/azure/automation/automation-security-overview
- Hybrid Runbook Worker — https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker
- hackingthe.cloud Azure section — https://hackingthe.cloud/azure/
