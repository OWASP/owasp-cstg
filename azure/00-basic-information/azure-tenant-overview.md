---
cstg_id: CSTG-AZURE-TENANT-OVERVIEW
title: "AZURE Tenant - Overview"
provider: azure
service: tenant
phase: basic-information
required_access: read-only-audit
required_permissions:
  - "Any authenticated principal can read most directory objects by default (member users, guests, service principals, managed identities)"
  - "Global Reader or Directory Readers directory role for complete identity-plane visibility"
  - "Reader RBAC role at the management-group, subscription, or resource-group scope for resource-plane visibility"
  - "Microsoft Graph read scopes (Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory) for full programmatic enumeration"
tools: [az cli, Azure PowerShell (Az module), Microsoft Graph PowerShell SDK, ROADtools, AzureHound, ScubaGear, Stormspotter, MicroBurst]
references:
  - "https://learn.microsoft.com/en-us/entra/fundamentals/whatis"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/developer-glossary"
  - "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/overview"
  - "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens"
  - "https://learn.microsoft.com/en-us/graph/api/overview"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"
  - "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins"
license: CC BY-SA 4.0
---

## Summary

An Azure **tenant** is the top-level security and administrative boundary of the Microsoft cloud estate. The tenant *is* a single instance of **Microsoft Entra ID** (formerly Azure Active Directory), identified by a globally unique GUID and one or more DNS domains (for example `contoso.onmicrosoft.com` plus any verified custom domains). Every identity (user, group, application, service principal, managed identity, device), every Microsoft 365 workload, and every Azure resource subscription is anchored to exactly one tenant. Understanding the tenant model is the foundation for all Azure security testing because it defines two distinct but linked control planes — the **identity plane** (Entra ID) and the **resource plane** (Azure Resource Manager) — and the trust edges between them.

This overview page establishes the mental model a tester or defender needs before drilling into individual services: how identities are represented and authenticated, how authorization is split between Entra directory roles and Azure RBAC, how the management-group / subscription / resource-group / resource hierarchy is organized, and which tokens and endpoints mediate access. The objective during reconnaissance is to determine *which tenant* a target belongs to, *what relationship* the current principal has to it, and *where power concentrates* — which roles, which subscriptions, which trust relationships — so that subsequent enumeration ([Entra ID](../02-services/azure-entra-id-enum.md), [RBAC](../02-services/azure-rbac-enum.md), [managed identities](../02-services/azure-managed-identities-enum.md)) can be targeted.

## Prerequisites

- For unauthenticated tenant reconnaissance (tenant discovery, domain-to-tenant mapping, OpenID configuration), no credentials are required — see [Entra ID unauthenticated](../01-unauthenticated-external/azure-entra-id-unauthenticated.md).
- For authenticated identity-plane enumeration, any principal in the tenant suffices for default directory reads. The **Global Reader** or **Directory Readers** role, or Microsoft Graph read scopes such as `Directory.Read.All`, `Policy.Read.All`, and `RoleManagement.Read.Directory`, provide complete coverage.
- For resource-plane enumeration, an Azure RBAC role with read actions (the built-in **Reader** role, or `Microsoft.Resources/subscriptions/read` and `*/read` data actions) at the relevant management-group, subscription, or resource-group scope.
- Tooling: `az` CLI, Azure PowerShell, the Microsoft Graph PowerShell SDK, or any OAuth2 client capable of acquiring tokens for `https://graph.microsoft.com` (Entra/identity plane) and `https://management.azure.com` (ARM/resource plane).

## Tenant identity and resource model

### What the tenant contains

A tenant is the container for two stacked planes that share the same Entra ID directory for authentication but use different authorization systems:

- **Identity plane — Microsoft Entra ID.** Holds all directory objects and the Entra **directory roles** that govern them. Authorization here is evaluated by Entra ID and Microsoft Graph.
- **Resource plane — Azure Resource Manager (ARM).** Holds the subscription/resource hierarchy and the **Azure RBAC** role assignments that govern Azure resources. Authorization here is evaluated by ARM.

A single tenant can own zero, one, or many Azure subscriptions, and can simultaneously back Microsoft 365, Dynamics 365, Power Platform, and Intune. A subscription trusts exactly one tenant for authentication at any time but can be transferred between tenants. Identities (especially guests and multi-tenant service principals) can have relationships spanning multiple tenants.

### Directory object types

| Object | Description | Security relevance |
|---|---|---|
| **User** | Member or guest (B2B) account. | Primary human principal; guests inherit broad default read access. |
| **Group** | Security or Microsoft 365 group; static, dynamic, or role-assignable. | Group membership grants RBAC, app access, and (for role-assignable groups) directory roles. |
| **Application (app registration)** | The global definition / blueprint of an application, with its own app ID. | Holds credentials and requested API permissions; owners can add credentials. |
| **Service principal (enterprise application)** | The local instance of an application within a tenant. | The actual principal that authenticates and holds role assignments and consented Graph permissions. |
| **Managed identity** | A special, credential-less service principal tied to an Azure resource. | Bridges the resource plane to the identity plane; common privilege-escalation pivot — see [managed identities](../02-services/azure-managed-identities-enum.md). |
| **Device** | Registered, hybrid-joined, or Entra-joined endpoint. | Conditional Access input; can hold Primary Refresh Tokens. |
| **Administrative Unit** | A scoping container that delegates role administration over a subset of objects. | Restricts/grants delegated admin; can hide or expose privileged scope. |

### Authorization: two role systems

Testers must keep the two systems distinct because a principal can be powerful in one and powerless in the other:

- **Entra directory roles** (e.g. *Global Administrator*, *Privileged Role Administrator*, *Application Administrator*, *User Administrator*, *Privileged Authentication Administrator*, *Global Reader*) govern the directory itself — users, groups, app registrations, policies. *Global Administrator* can elevate itself to control all Azure subscriptions via the **User Access Administrator** elevation (the "Access management for Azure resources" toggle), making the identity plane the ultimate authority.
- **Azure RBAC roles** (e.g. *Owner*, *Contributor*, *Reader*, *User Access Administrator*, plus thousands of resource-specific roles) govern Azure resources and are assigned at a scope in the resource hierarchy. RBAC is additive and inherited down the hierarchy; a deny assignment can override an allow.

See [RBAC enumeration](../02-services/azure-rbac-enum.md) and [Entra ID privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md) for how these systems are abused.

### Resource hierarchy

Azure resources are organized in a strict, inheriting hierarchy. Role assignments and Azure Policy applied at a higher scope flow downward:

```
Tenant Root Management Group
  └─ Management Group(s)            (organizational grouping of subscriptions)
      └─ Subscription(s)            (billing + RBAC + policy boundary)
          └─ Resource Group(s)      (lifecycle/management container)
              └─ Resource(s)        (VM, storage account, key vault, etc.)
```

A privileged assignment at the Tenant Root or an intermediate management group is high-impact because it is inherited by every subscription beneath it.

## Authentication and tokens

Entra ID is an OpenID Connect / OAuth 2.0 identity provider. Access to both planes is mediated by bearer tokens issued by the tenant's token endpoints:

- **Authority/token endpoints:** `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` and `.../oauth2/v2.0/token`, where `{tenant}` is the tenant GUID, a verified domain, or `common`/`organizations`/`consumers`.
- **Audiences (resources) of interest:** `https://graph.microsoft.com` (Microsoft Graph / identity plane), `https://management.azure.com` (ARM / resource plane), `https://vault.azure.net` (Key Vault data plane), `https://storage.azure.com` (Storage data plane), and many more — each is a separate token audience.

Common credential and grant types a tester encounters:

- **Interactive / device-code / auth-code flows** — human sign-in producing delegated tokens scoped to the user's permissions and consented app scopes.
- **Client credentials (app-only)** — a service principal authenticating with a client secret or certificate, producing app tokens scoped to its granted application permissions. Stolen secrets/certs enable non-interactive, MFA-immune access.
- **Managed identity** — system- or user-assigned identity that obtains tokens from the local Instance Metadata Service (IMDS) endpoint (`http://169.254.169.254/metadata/identity/oauth2/token`) or the App Service identity endpoint, with no stored secret. See [managed identities lateral movement](../04-lateral-movement/azure-managed-identities-lateral.md).
- **Refresh tokens / Primary Refresh Tokens (PRTs)** — long-lived artifacts that can mint new access tokens across resources; high-value for persistence.

Token contents (decoded JWT claims such as `tid`, `oid`, `appid`, `scp`/`roles`, `aud`) reveal the tenant, the principal, and the authorization a captured token confers — a key triage step after credential capture.

## Reconnaissance

### Identify the tenant (often unauthenticated)

```bash
# Resolve a domain to its tenant GUID via the OpenID configuration
curl -s https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration | jq -r '.issuer'

# Tenant-realm / login metadata for a domain (federation, namespace type)
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.com&xml=1"

# Autodiscover-style tenant + verified domains enumeration via Graph (anonymous endpoint)
curl -s -X POST https://login.microsoftonline.com/common/userrealm/ -d "..."
```

(See [Entra ID unauthenticated](../01-unauthenticated-external/azure-entra-id-unauthenticated.md) for full tenant-discovery technique coverage.)

### Establish authenticated context

```bash
# CLI sign-in and current-context inspection
az login
az account show                      # current subscription + tenantId + signed-in user
az account list --all -o table       # every subscription the principal can see
az account tenant list -o table      # tenants the principal has access to

# Acquire raw tokens for each plane
az account get-access-token --resource https://graph.microsoft.com
az account get-access-token --resource https://management.azure.com
```

```powershell
# Azure PowerShell context
Connect-AzAccount
Get-AzContext
Get-AzTenant
Get-AzSubscription

# Microsoft Graph context
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgContext
(Get-MgOrganization).Id            # tenant GUID
Get-MgOrganization | Select-Object DisplayName, VerifiedDomains
```

### Map the identity plane

```bash
# Tenant/organization details and verified domains via Graph
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" https://graph.microsoft.com/v1.0/organization
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" https://graph.microsoft.com/v1.0/domains

# Who holds directory roles (concentration of power)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/directoryRoles?\$expand=members"
```

Deep identity enumeration (users, groups, apps, service principals, Conditional Access, role members) is covered in [Entra ID enumeration](../02-services/azure-entra-id-enum.md).

### Map the resource plane

```bash
# Management-group hierarchy (requires read at the management group)
az account management-group list -o table
az account management-group show --name <mg-id> --expand --recurse

# Subscriptions, resource groups, and resources
az account list -o table
az group list -o table
az resource list -o table

# Effective role assignments for the current principal across a subscription
az role assignment list --all --assignee <objectId-or-upn> -o table
```

A combined identity-and-resource graph can be collected and analyzed with tools such as AzureHound/BloodHound or ROADtools to surface attack paths automatically.

## Misconfigurations & Findings

- **Permissive default directory reads.** By default any member (and frequently any guest) can enumerate most users, groups, applications, and role assignments, exposing the full power map of the tenant to any foothold. Restricting member/guest read access is rarely configured.
- **Tenant Root / management-group over-assignment.** Owner or User Access Administrator at the Tenant Root Management Group or an intermediate group is inherited by every subscription, turning one assignment into estate-wide control.
- **Global Administrator with Azure elevation available.** A Global Admin can flip the "Access management for Azure resources" toggle to gain User Access Administrator at root, bridging full directory control into full resource control.
- **Cross-plane blind spots.** Defenders monitoring one plane (e.g. ARM Activity Logs) while ignoring the other (Entra audit logs) miss identity-plane attacks such as app-credential addition or role assignment.
- **Multi-tenant trust and guest sprawl.** Guests, multi-tenant app registrations, and cross-tenant access settings widen the boundary; an attacker controlling a partner tenant or a consented multi-tenant app may pivot inward.
- **Unmanaged subscription-to-tenant relationships.** Subscriptions transferred between tenants, or "shadow" subscriptions associated with the directory, may fall outside governance and monitoring.

## Exploitation

This is an overview page; concrete attack paths live in the phase-specific guides. The tenant model nonetheless frames the principal exploitation pivots:

- **Identity-plane to resource-plane bridge.** Control of a high-privilege directory role (Global Administrator) is escalated into Azure resource control via the Azure-resource access elevation, then User Access Administrator / Owner assignments. See [Entra ID privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md) and [RBAC privilege escalation](../03-privilege-escalation/azure-rbac-privesc.md).
- **Resource-plane to identity-plane bridge.** A compromised resource (VM, Function, Automation runbook, AKS pod) yields a managed-identity token from IMDS, which may carry directory or RBAC permissions allowing escalation back into the directory. See [managed identities privilege escalation](../03-privilege-escalation/azure-managed-identities-privesc.md).
- **Credential and token abuse.** App secrets/certificates, refresh tokens, and PRTs harvested from a foothold mint tokens for any audience the principal is authorized for, crossing service boundaries. See [Key Vault](../02-services/azure-key-vault-enum.md) and [post-exploitation](../05-post-exploitation/azure-entra-id-post-exploitation.md).

## Detection & Logging

- **Microsoft Entra ID sign-in logs** record every interactive and non-interactive token issuance, including the application, resource, IP, device, and Conditional Access result — the primary source for spotting anomalous token acquisition, service-principal sign-ins, and managed-identity usage.
- **Microsoft Entra ID audit logs** record directory changes: role assignments, application/credential additions, consent grants, group membership changes, policy edits. Cross-plane attacks surface here even when ARM logs are clean.
- **Azure Activity Log** records resource-plane control operations per subscription: role assignment writes (`Microsoft.Authorization/roleAssignments/write`), resource deployments, and management-plane changes. The "Access management for Azure resources" elevation is observable as an administrative operation.
- **Managed detections.** Microsoft Defender for Cloud and Microsoft Entra ID Protection raise alerts for risky sign-ins, impossible travel, and suspicious directory operations; route both Activity Logs and Entra logs to a Log Analytics workspace / SIEM for correlation across the two planes.
- High-fidelity tenant-level signals include directory role grants, new app credentials, the Azure-resource elevation toggle, and creation of new subscriptions or management-group moves.

## Remediation & Hardening

- **Restrict default read access.** Limit what member and guest users can read in the directory; tighten external collaboration / cross-tenant access settings and guest invitation controls.
- **Minimize standing privilege.** Use Privileged Identity Management (PIM) for just-in-time, time-bound, approval-gated activation of both Entra directory roles and Azure RBAC roles; keep zero standing Global Administrators where feasible (target a small, monitored break-glass set).
- **Govern the hierarchy.** Assign RBAC at the narrowest scope; avoid Owner/User Access Administrator at the Tenant Root or management groups; apply Azure Policy to enforce guardrails inherited down the tree.
- **Protect the identity-resource bridge.** Audit and constrain the Global Admin Azure-elevation toggle; review managed-identity role assignments so a compromised resource cannot escalate into the directory.
- **Enforce strong authentication.** Require phishing-resistant MFA via Conditional Access for all privileged roles and management-plane operations; restrict legacy authentication.
- **Monitor both planes together.** Centralize Entra sign-in/audit logs and Azure Activity Logs in a SIEM and alert on cross-plane privilege operations; baseline assessment with ScubaGear or equivalent CIS/Microsoft secure-score tooling.

## Tools

- **az CLI / Azure PowerShell (Az module)** — interactive and scripted enumeration of subscriptions, resources, and RBAC; token acquisition for any audience.
- **Microsoft Graph PowerShell SDK** — directory-object and policy enumeration on the identity plane.
- **ROADtools (roadrecon)** — offline collection and graph analysis of an Entra tenant.
- **AzureHound / BloodHound** — collects identity and resource edges to surface attack paths across both planes.
- **ScubaGear** — automated tenant security baseline assessment against published configuration guidance.
- **Stormspotter / MicroBurst** — additional enumeration and attack-surface mapping toolkits for Azure tenants and services.

## References

- [Microsoft Entra ID — what is it](https://learn.microsoft.com/en-us/entra/fundamentals/whatis)
- [Microsoft identity platform glossary (tenant, app, service principal)](https://learn.microsoft.com/en-us/entra/identity-platform/developer-glossary)
- [Management groups overview](https://learn.microsoft.com/en-us/azure/governance/management-groups/overview)
- [Azure RBAC overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
- [Entra ID built-in roles reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft identity platform access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Microsoft Graph API overview](https://learn.microsoft.com/en-us/graph/api/overview)
- [Managed identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Entra ID sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
