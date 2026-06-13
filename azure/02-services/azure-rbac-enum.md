---
cstg_id: CSTG-AZURE-RBAC-ENUM
title: "AZURE Rbac - Enumeration"
provider: azure
service: rbac
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Authorization/roleAssignments/read"
  - "Microsoft.Authorization/roleDefinitions/read"
  - "Microsoft.Authorization/denyAssignments/read"
  - "Microsoft.Authorization/classicAdministrators/read"
  - "Microsoft.Management/managementGroups/read"
  - "Microsoft.Resources/subscriptions/read"
  - "Microsoft.Resources/subscriptions/resourceGroups/read"
  - "directory readers (Entra ID) for principal resolution"
tools:
  - azure-cli
  - azure-powershell
  - azure-resource-graph
  - microsoft-graph-api
  - rbac-enumeration-mapper
  - directory-enumeration-tooling
references:
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview"
  - "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure Role-Based Access Control (RBAC) is the authorization system that governs access to Azure *resources* (the control plane managed by Azure Resource Manager, ARM). It is distinct from, but layered on top of, Microsoft Entra ID (formerly Azure AD), which governs identities and directory-level roles. RBAC answers the question "which security principal may perform which action against which resource scope?"

This page covers enumeration of the Azure RBAC model: discovering scopes (management groups, subscriptions, resource groups, individual resources), reading role definitions (built-in and custom), mapping role assignments to principals (users, groups, service principals, managed identities), and identifying deny assignments and classic administrators. The objective of an assessor is to build a complete, scope-aware picture of *who can do what*, which is the prerequisite for the privilege-escalation analysis described in [azure-rbac-privesc.md](../03-privilege-escalation/azure-rbac-privesc.md).

Accurate RBAC enumeration is the single highest-value reconnaissance activity in an Azure environment because almost every lateral movement and escalation path ultimately reduces to an over-broad, mis-scoped, or transitively granted role assignment.

## Prerequisites

The techniques below assume an authenticated principal with read-only visibility into the authorization plane. Concretely, the principal should hold (directly or transitively) the data actions `Microsoft.Authorization/*/read` at the scope being assessed, which is satisfied by the built-in **Reader** role at the subscription level plus the ability to resolve principals in the directory. The dedicated built-in role **Reader** combined with a directory read capability, or the **Security Reader** / **Global Reader** Entra roles for directory-side resolution, is sufficient for a full read-only audit.

Key facts that shape enumeration:

- RBAC is **additive and inheritable**: an assignment at a parent scope (management group → subscription → resource group → resource) is inherited by all child scopes. The effective permission set of a principal at a resource is the union of all role assignments at that resource and every ancestor scope.
- A **deny assignment** explicitly blocks actions and *takes precedence* over allow role assignments. Deny assignments are created by Azure-managed services (for example Blueprints, managed apps) and cannot be created directly by users, but they materially change the effective access picture and must be enumerated.
- Permissions are expressed as `Actions` / `NotActions` (control-plane) and `DataActions` / `NotDataActions` (data-plane). A wildcard `*` in `Actions` is the canonical owner-equivalent grant.
- Resolving the *principal* behind a `principalId` (a GUID) requires Entra ID / Microsoft Graph access; without it, assignments appear as opaque object IDs.

## Enumeration

### Establish identity and accessible scopes

```bash
# Who am I, and what tenant/subscription am I in?
az account show
az ad signed-in-user show          # if a user principal
az account list --all -o table     # all subscriptions the principal can see

# Management group hierarchy (top of the scope tree)
az account management-group list -o table
az account management-group show --name <mgGroupId> --expand --recurse

# Resource groups within the current subscription
az group list -o table
```

### Read role definitions (what each role can do)

```bash
# All role definitions visible at a scope (built-in + custom)
az role definition list --scope /subscriptions/<subId> -o json

# Custom roles only (these are where mis-scoped grants frequently hide)
az role definition list --custom-role-only true -o json

# Inspect a single role's Actions / NotActions / DataActions
az role definition list --name "Contributor" \
  --query "[].{name:roleName, actions:permissions[].actions, notActions:permissions[].notActions}"
```

Raw ARM REST (useful when the CLI is unavailable or for API-level fidelity):

```http
GET https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01
Authorization: Bearer <ARM token>
```

### Read role assignments (who holds which role, where)

```bash
# All assignments at and below a scope, including inherited ones
az role assignment list --scope /subscriptions/<subId> --include-inherited --all -o json

# Assignments for a specific principal across the subscription
az role assignment list --assignee <objectId-or-upn> --all -o json

# Assignments granting a specific high-value role
az role assignment list --role "Owner" --scope /subscriptions/<subId> --all
az role assignment list --role "User Access Administrator" --all
```

Raw ARM REST:

```http
GET https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()
```

### Enumerate deny assignments and classic administrators

```bash
# Deny assignments (override allow grants)
az rest --method get --url \
  "https://management.azure.com/subscriptions/<subId>/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01"

# Classic co-administrators / service administrators (legacy, full control)
az role assignment list --include-classic-administrators true --scope /subscriptions/<subId>
```

### Resolve principals via Microsoft Graph

Assignment objects reference principals only by GUID; resolution turns GUIDs into actionable identities and reveals group-based (transitive) grants.

```bash
# Resolve a principal object
az ad user show --id <objectId>
az ad sp show --id <objectId>
az ad group show --group <objectId>

# Transitive group membership for a user (reveals indirect role grants)
az rest --method get --url \
  "https://graph.microsoft.com/v1.0/users/<objectId>/transitiveMemberOf"

# Service principals tied to managed identities (assignment-of-identity targets)
az identity list -o json
```

### Scale with Azure Resource Graph

Resource Graph queries authorization data across many subscriptions in one call, which is far more efficient than iterating per subscription:

```bash
az graph query -q "authorizationresources
| where type == 'microsoft.authorization/roleassignments'
| extend roleDefId = tostring(properties.roleDefinitionId),
         principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType),
         scope = tostring(properties.scope)
| project roleDefId, principalId, principalType, scope"
```

A complete enumeration produces a join of: principal → (direct or group-transitive) → role assignment → role definition (Actions/DataActions) → scope, with deny assignments subtracted. This effective-access graph is the artifact the privilege-escalation phase consumes.

## Misconfigurations & Findings

- **Over-broad scope inheritance.** Owner or Contributor assigned at the management-group or subscription scope when only a single resource group needs it. The grant silently flows to every current and future child resource.
- **Wildcard custom roles.** Custom role definitions containing `Microsoft.Authorization/*/write` or a bare `*` Action that were intended to be narrow. These are owner-equivalent or User-Access-Administrator-equivalent and are easy to overlook because the role *name* sounds benign.
- **`Microsoft.Authorization/roleAssignments/write` granted outside Owner/UAA.** Any principal with this action can grant itself any role — a direct escalation primitive. Flag every holder.
- **Group-based grants hiding privilege.** A user appears low-privileged by direct assignment but inherits Owner through nested group membership. Always evaluate transitive membership.
- **Service principals and managed identities with standing high privilege.** Non-interactive identities (CI/CD service principals, VM/Function managed identities) holding Contributor/Owner. These lack MFA and are frequent pivot targets.
- **Lingering classic administrators.** Classic co-administrators retain subscription-wide control outside the RBAC model and are commonly forgotten.
- **Stale / orphaned assignments.** Assignments whose `principalId` no longer resolves (deleted principal) clutter the model and can be re-bound if the GUID is reused.
- **No Privileged Identity Management (PIM).** High-value roles assigned as permanent ("active") rather than eligible/just-in-time, maximizing the standing attack surface.

## Exploitation

Enumeration is itself reconnaissance rather than exploitation, but the assembled effective-access graph directly drives exploitation in the privilege-escalation phase. The assessor should, at this stage, identify and prioritize:

1. Principals holding `Microsoft.Authorization/roleAssignments/write` (self-elevation).
2. Principals holding `Microsoft.Authorization/roleDefinitions/write` (craft a privileged custom role, then assign it).
3. Principals who can act on identities (`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, `Microsoft.Compute/virtualMachines/write`, run-command, etc.) to borrow a more privileged managed identity.
4. Any path from the currently held principal to an Owner/UAA assignment, whether direct, group-transitive, or via a controllable service principal credential.

Each concrete path and the commands to execute it are detailed in [azure-rbac-privesc.md](../03-privilege-escalation/azure-rbac-privesc.md).

## Detection & Logging

- **Azure Activity Logs** record control-plane reads and writes against `Microsoft.Authorization`. Listing role assignments/definitions appears as read operations on `Microsoft.Authorization/roleAssignments/read` and `Microsoft.Authorization/roleDefinitions/read`. High-volume or broad-scope enumeration (for example a single principal reading authorization data across many subscriptions, or repeated `denyAssignments` reads) is an anomaly worth alerting on.
- **Microsoft Entra ID audit logs** capture directory reads/queries that resolve principals and enumerate group membership; **sign-in logs** show the authentication that preceded the activity (principal, IP, app/client, conditional-access result).
- **Microsoft Graph activity logs** capture `transitiveMemberOf` and directory-object lookups used to resolve assignments.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** analytics rules can flag mass enumeration of authorization resources and unusual Resource Graph query volume. Resource Graph reads do not appear in Activity Logs the same way per-subscription ARM calls do, so correlate Graph query telemetry where available.

## Remediation & Hardening

- Apply **least privilege and least scope**: assign roles at the narrowest scope (resource group or resource), never at management-group/subscription level "for convenience".
- Prefer **built-in roles**; audit every **custom role** for wildcard `Actions`/`DataActions` and for `Microsoft.Authorization/*/write`.
- Restrict `Microsoft.Authorization/roleAssignments/write` and `roleDefinitions/write` to a small, audited set of Owner/User Access Administrator principals.
- Adopt **Entra ID Privileged Identity Management (PIM)** for just-in-time, time-bound, approval-gated activation of high-value roles; eliminate standing Owner/UAA.
- Use **groups** for assignment and govern membership with access reviews; run periodic **Entra ID Access Reviews** to remove stale grants.
- Eliminate **classic administrators**; migrate to RBAC.
- Give workload identities (service principals, managed identities) **scoped, minimal** roles; rotate and protect their credentials; prefer managed identities over long-lived secrets.
- Enable diagnostic settings to export Activity, Entra audit, and sign-in logs to a monitored Log Analytics workspace / Sentinel.

## Tools

- **Azure CLI** (`az role`, `az ad`, `az account management-group`, `az graph`) for assignment, definition, and scope enumeration.
- **Azure PowerShell** (`Get-AzRoleAssignment`, `Get-AzRoleDefinition`, `Get-AzManagementGroup`) as an alternative control-plane client.
- **Azure Resource Graph** for cross-subscription authorization queries at scale.
- **Microsoft Graph API** for principal resolution and transitive group-membership expansion.
- **RBAC enumeration / mapping utilities** that build an effective-access graph (principal → role → scope, minus deny assignments) and highlight escalation primitives.
- **Directory enumeration tooling** for breadth-first discovery of users, groups, service principals, and their interrelationships.

## References

- Azure RBAC overview — https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
- Role definitions — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions
- Role assignments — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- Deny assignments — https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments
- Built-in roles — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- Scope overview — https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- Role Assignments REST API — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments
- Azure Resource Graph — https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
