---
cstg_id: CSTG-AZURE-SUBSCRIPTIONS-ENUM
title: "AZURE Subscriptions - Enumeration"
provider: azure
service: subscriptions
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Resources/subscriptions/read"
  - "Microsoft.Resources/subscriptions/resourceGroups/read"
  - "Microsoft.Resources/subscriptions/resources/read"
  - "Microsoft.Management/managementGroups/read"
  - "Microsoft.Authorization/roleAssignments/read"
  - "Microsoft.Authorization/roleDefinitions/read"
  - "Microsoft.Authorization/policyAssignments/read"
  - "Microsoft.Resources/deployments/read"
  - "Microsoft.Resources/tags/read"
  - "directory readers (Entra ID) for tenant/principal resolution"
tools:
  - azure-cli
  - azure-powershell
  - azure-resource-graph
  - microsoft-graph-api
  - arm-rest-client
  - subscription-mapping-tooling
references:
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview"
  - "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview"
  - "https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list"
  - "https://learn.microsoft.com/en-us/rest/api/managedapplications/applications"
  - "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/understand-vat-charges"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

In Azure, a **subscription** is the primary unit of billing, quota, and access-control isolation, and it is the scope at which most resources are deployed. Subscriptions sit inside the scope hierarchy that flows **tenant (Microsoft Entra ID directory) → management groups → subscriptions → resource groups → resources**. A single Entra tenant can contain many subscriptions, and management groups aggregate subscriptions so that RBAC role assignments and Azure Policy can be applied to many subscriptions at once through inheritance.

This page covers enumeration of the subscription layer: discovering which subscriptions a principal can reach, mapping the management-group hierarchy above them, inventorying the resource groups and resources within each subscription, reading the policy and lock configuration that constrains them, and identifying the tenant(s) and cross-tenant relationships the subscriptions are associated with. The goal of an assessor is a complete map of the subscription estate and the access boundaries between its members — the foundation for the privilege-escalation, lateral-movement, and persistence phases.

Because the subscription is where blast radius is defined, an accurate inventory at this layer determines how far a single compromised principal can reach. Role assignments and the resource-level enumeration that subscriptions contain are covered in depth in [azure-rbac-enum.md](azure-rbac-enum.md); this page focuses on the subscription and management-group fabric itself.

## Prerequisites

An authenticated principal with read-only visibility into Azure Resource Manager (ARM). The minimum useful grant is the built-in **Reader** role at one subscription or management-group scope. A holder of Reader at a management group can enumerate every subscription beneath it through inheritance. Directory-side resolution (resolving tenant IDs, principal GUIDs, and cross-tenant guests) additionally benefits from **Global Reader** / **Directory Readers** in Entra ID.

Key facts that shape enumeration:

- The set of subscriptions a principal can *see* equals the set where it (directly or transitively, including via management-group inheritance) holds at least a read role. A principal may have access to subscriptions in **multiple tenants** — `az account list` enumerates across all tenants the principal can authenticate to.
- **Management groups** form the scope above subscriptions; the root management group's ID equals the tenant ID. Role assignments and policy at the management-group level inherit to all child subscriptions, so the hierarchy is essential to understanding effective access.
- A subscription has a **state** (`Enabled`, `Disabled`, `Warned`, `PastDue`, `Deleted`) and an associated **tenant** and **billing account**. Disabled or warned subscriptions still hold resources and assignments.
- **Resource locks** (`CanNotDelete`, `ReadOnly`) and **Azure Policy** assignments constrain what can be done in a subscription regardless of RBAC and must be enumerated to predict which exploitation paths are viable.

## Enumeration

### Establish identity, tenants, and reachable subscriptions

```bash
# Current context: account, tenant, subscription
az account show -o json

# Every subscription the principal can reach, across all tenants
az account list --all -o table
az account list --all --query "[].{name:name, id:id, state:state, tenant:tenantId}" -o json

# Tenants the principal can authenticate into (cross-tenant reach)
az account tenant list -o table

# Signed-in user (if a user principal) and its directory object
az ad signed-in-user show
```

Raw ARM REST (API-level fidelity, or when the CLI is unavailable):

```http
GET https://management.azure.com/subscriptions?api-version=2022-12-01
Authorization: Bearer <ARM token>

GET https://management.azure.com/tenants?api-version=2022-12-01
Authorization: Bearer <ARM token>
```

### Map the management-group hierarchy (scope above subscriptions)

```bash
# Top-level management groups visible to the principal
az account management-group list -o table

# Full recursive tree, including child management groups and subscriptions
az account management-group show --name <mgGroupId> --expand --recurse -o json

# The root management group ID equals the tenant ID
az account management-group show --name <tenantId> --expand --recurse
```

```http
GET https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2021-04-01
GET https://management.azure.com/providers/Microsoft.Management/managementGroups/{groupId}?$expand=children&$recurse=true&api-version=2021-04-01
```

### Inventory resource groups and resources per subscription

```bash
az account set --subscription <subId>

# Resource groups (with location and tags)
az group list --query "[].{name:name, location:location, tags:tags}" -o json

# Every resource in the subscription (the full inventory)
az resource list --query "[].{name:name, type:type, rg:resourceGroup, location:location}" -o json

# Subscription-level providers/services in use
az provider list --query "[?registrationState=='Registered'].namespace" -o tsv
```

### Read governance: policy, locks, deployments, tags

```bash
# Azure Policy assignments at subscription scope (and inherited from MG)
az policy assignment list --scope /subscriptions/<subId> -o json

# Resource locks that would block delete/modify (CanNotDelete / ReadOnly)
az lock list --query "[].{name:name, level:level, scope:id}" -o json

# Deployment history (often leaks parameters, names, and architecture)
az deployment sub list --query "[].{name:name, state:properties.provisioningState, ts:properties.timestamp}" -o json
az deployment group list --resource-group <rg> -o json

# Tag taxonomy across the subscription (env, owner, data-classification)
az tag list -o json
```

### Cross-subscription enumeration at scale with Resource Graph

Resource Graph queries all reachable subscriptions in one call, which is far more efficient than iterating per subscription and is the preferred technique for large estates:

```bash
# Subscription inventory
az graph query -q "resourcecontainers
| where type == 'microsoft.resources/subscriptions'
| project subscriptionId, name, tenantId, state = tostring(properties.state)"

# All resource groups across all reachable subscriptions
az graph query -q "resourcecontainers
| where type == 'microsoft.resources/subscriptions/resourcegroups'
| project subscriptionId, resourceGroup = name, location, tags"

# Full resource count by type and subscription (footprint heat-map)
az graph query -q "resources
| summarize count() by subscriptionId, type
| order by count_ desc"
```

### Managed applications and delegated (Lighthouse) access

```bash
# Managed applications (managed-app resource group is provider-controlled)
az managedapp list -o json

# Azure Lighthouse delegations — registrations that grant an EXTERNAL
# managing tenant standing access into this subscription
az rest --method get --url \
  "https://management.azure.com/subscriptions/<subId>/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&\$expand=registrationDefinition"
```

A complete enumeration produces: tenant(s) → management-group tree → subscriptions (with state, billing, policy, locks) → resource groups → resources, annotated with the principal's effective access at each scope. This map is the artifact every later phase consumes.

## Misconfigurations & Findings

- **Sprawling subscription estate without management-group structure.** Subscriptions parked directly under the root group, so policy and guardrails cannot be applied consistently and one over-broad management-group assignment grants the whole tenant.
- **Cross-tenant reach by a single principal.** A user or service principal that can `az account list` subscriptions in multiple tenants — a high-value finding because compromise spans organizational boundaries.
- **Azure Lighthouse delegations to unexpected managing tenants.** Standing cross-tenant RBAC grants to an external partner tenant; if that partner is compromised, the subscription is too. Frequently forgotten after an engagement ends.
- **Management-group-scoped Owner/Contributor.** Privilege assigned at a management group inherits to every current and future child subscription — maximal blast radius hidden one level above where defenders usually look.
- **Disabled / warned / past-due subscriptions still holding resources and assignments.** Often unmonitored yet still reachable and still carrying credentials, managed identities, and role assignments.
- **Absent or audit-only policy.** Azure Policy assignments in `Audit`/`Disabled` effect rather than `Deny`, so the guardrail records violations but does not prevent the actions an attacker would take.
- **Resource locks missing on critical resources**, or conversely, knowledge of `CanNotDelete`/`ReadOnly` locks that an attacker will remove (`Microsoft.Authorization/locks/delete`) before destructive actions.
- **Deployment history leakage.** Subscription/resource-group deployments retaining parameters that embedded secrets, admin usernames, or sensitive architecture detail.

## Detection & Logging

- **Azure Activity Logs** record control-plane reads/writes per subscription. Subscription, management-group, resource, policy, and lock listing appear as read operations (for example `Microsoft.Resources/subscriptions/read`, `Microsoft.Management/managementGroups/read`, `Microsoft.Authorization/policyAssignments/read`). Broad, fast enumeration — one principal listing resources across many subscriptions, or walking the entire management-group tree — is an anomaly worth alerting on.
- **Microsoft Entra ID sign-in logs** show the authentication that preceded the activity, including which tenant(s) a principal signed into; cross-tenant sign-ins by one identity are notable. **Entra audit logs** capture directory reads that resolve tenants and principals.
- **Azure Resource Graph** reads are not surfaced in per-subscription Activity Logs the same way ARM calls are; correlate Graph query telemetry where the platform exposes it, and treat high-volume cross-subscription Graph queries as reconnaissance.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** provide analytics for mass enumeration and for unusual access to many subscriptions by a single principal.

## Remediation & Hardening

- Impose a deliberate **management-group hierarchy** (for example a landing-zone design) and apply guardrails — Azure Policy in **Deny** effect, not merely Audit — at the management-group level so they inherit consistently.
- Assign roles at the **narrowest scope**; avoid management-group/subscription Owner/Contributor "for convenience". Use [Azure RBAC least-privilege practices](azure-rbac-enum.md).
- Inventory and **review Azure Lighthouse delegations** regularly; remove standing cross-tenant access for partners that no longer need it; require justification and expiry.
- Periodically reconcile the subscription estate: cancel or clean up **disabled/past-due subscriptions**, remove orphaned resources, and ensure every subscription is monitored.
- Apply **resource locks** to critical resources and protect the `Microsoft.Authorization/locks/*` permission; alert on lock deletion.
- Scrub **deployment history** of sensitive parameters; mark secrets `secureString` and pass them via Key Vault references rather than plaintext parameters.
- Export **Activity, Entra audit, and sign-in logs** from every subscription via diagnostic settings to a central, monitored Log Analytics workspace / Sentinel; do not leave any subscription unlogged.

## Tools

- **Azure CLI** (`az account`, `az account management-group`, `az group`, `az resource`, `az policy`, `az lock`, `az deployment`) for subscription and governance enumeration.
- **Azure PowerShell** (`Get-AzSubscription`, `Get-AzManagementGroup`, `Get-AzResourceGroup`, `Get-AzPolicyAssignment`, `Get-AzResourceLock`) as an alternative ARM client.
- **Azure Resource Graph** for cross-subscription inventory at scale.
- **Microsoft Graph API** for tenant and principal resolution and cross-tenant guest enumeration.
- **ARM REST clients** for API-level fidelity and access to providers the CLI does not surface (managed services / Lighthouse registrations).
- **Subscription-mapping utilities** that join tenant → management group → subscription → resource group → resource with the principal's effective access at each scope.

## References

- Azure Resource Manager overview — https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview
- Management groups overview — https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- RBAC scope overview — https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- Azure Resource Graph — https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- Subscriptions List REST API — https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list
- Managed applications REST API — https://learn.microsoft.com/en-us/rest/api/managedapplications/applications
- Azure Lighthouse — https://learn.microsoft.com/en-us/azure/lighthouse/overview
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
