---
cstg_id: CSTG-AZURE-ENTRA-ID-ENUM
title: "AZURE Entra Id - Enumeration"
provider: azure
service: entra-id
phase: services
required_access: read-only-audit
required_permissions:
  - "Directory Readers (or Global Reader) directory role"
  - "Microsoft Graph delegated/application scopes: User.Read.All, Group.Read.All, Application.Read.All, RoleManagement.Read.Directory, Policy.Read.All, Directory.Read.All"
tools: [ROADtools (roadrecon), AzureHound, Microsoft Graph PowerShell SDK, az cli, AADInternals, Stormspotter, ScubaGear]
references:
  - "https://learn.microsoft.com/en-us/graph/api/overview"
  - "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference"
  - "https://learn.microsoft.com/en-us/graph/api/resources/directoryrole"
  - "https://github.com/dirkjanm/ROADtools"
  - "https://bloodhound.specterops.io/"
  - "https://learn.microsoft.com/en-us/powershell/microsoftgraph/"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/application-rollup"
license: CC BY-SA 4.0
---

## Summary

Once any authenticated principal (a low-privileged user, a guest, a service principal, or a managed identity) exists in or has been invited to an Entra ID tenant, an enormous amount of directory data becomes readable. By default every member user can read most users, groups, applications, service principals, devices, and the directory role assignment graph. This page covers **authenticated directory enumeration** — mapping users, groups, roles, applications/service principals, devices, Conditional Access posture, and tenant settings — to understand who has power, where trust is delegated, and which paths lead to privilege escalation or lateral movement.

The attacker objective is to build a complete picture of the identity graph: identify privileged role members (Global Administrator, Privileged Role Administrator, Application Administrator, etc.), discover applications and service principals with dangerous Graph permissions or owner relationships, map group-based access (including dynamic and role-assignable groups), enumerate Conditional Access gaps, and locate credentials and ownership edges that can be abused. This is the reconnaissance backbone for [privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md) and [lateral movement](../04-lateral-movement/azure-entra-id-lateral.md).

## Prerequisites

- Any authenticated identity in the tenant (member user, guest, service principal, or workload managed identity). The default directory read access available to members is sufficient for most enumeration.
- For complete coverage, read scopes such as `Directory.Read.All`, `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, and `Policy.Read.All`, or the **Directory Readers** / **Global Reader** roles.
- A Microsoft Graph access token (delegated or app-only), or the ability to interactively sign in.

## Enumeration

### Acquire context and tokens

```bash
# Who am I and which tenant/subscriptions
az login
az account show
az ad signed-in-user show

# Acquire a Microsoft Graph token for raw API calls
az account get-access-token --resource-type ms-graph --query accessToken -o tsv
```

```powershell
# Microsoft Graph PowerShell SDK
Connect-MgGraph -Scopes "Directory.Read.All","RoleManagement.Read.Directory","Application.Read.All"
Get-MgContext
Get-MgOrganization | Select-Object DisplayName,Id,VerifiedDomains
```

### Users, guests, and credentials

```powershell
# All users with key attributes; flag guests, sync status, and onPremises identities
Get-MgUser -All -Property Id,UserPrincipalName,UserType,AccountEnabled,OnPremisesSyncEnabled,CreatedDateTime,LastPasswordChangeDateTime |
  Select-Object UserPrincipalName,UserType,AccountEnabled,OnPremisesSyncEnabled

# Guests specifically (B2B external principals)
Get-MgUser -Filter "userType eq 'Guest'" -All
```

```bash
# Raw Graph
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,userType,accountEnabled" | jq .
```

### Directory roles and assignments (the power map)

```powershell
# Active role assignments
Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal |
  Select-Object @{n='Role';e={$_.RoleDefinitionId}}, @{n='Principal';e={$_.Principal.AdditionalProperties.displayName}}

# Eligible (PIM) assignments — often missed but grant standing escalation paths
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All

# Members of Global Administrator
Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" |
  ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id }
```

### Groups, dynamic membership, and role-assignable groups

```powershell
# Role-assignable (privileged) groups — control of these = control of attached roles
Get-MgGroup -Filter "isAssignableToRole eq true" -All

# Dynamic groups — membership rules may be abusable to self-add via attribute manipulation
Get-MgGroup -All -Property Id,DisplayName,GroupTypes,MembershipRule |
  Where-Object { $_.GroupTypes -contains 'DynamicMembership' }
```

### Applications and service principals (the largest attack surface)

```powershell
# App registrations and their credentials (secrets/certs) and reply URLs
Get-MgApplication -All -Property AppId,DisplayName,KeyCredentials,PasswordCredentials,RequiredResourceAccess

# Service principals — enumerate granted app roles (application permissions) on Microsoft Graph
Get-MgServicePrincipal -All |
  ForEach-Object { Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id }

# OAuth2 delegated grants (user/admin consent)
Get-MgOauth2PermissionGrant -All
```

```bash
# High-value: find every SP holding RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All,
# Application.ReadWrite.All, Directory.ReadWrite.All on the Graph SP
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/<graph-sp-id>/appRoleAssignedTo" | jq '.value[]'
```

### Conditional Access, tenant policies, and PIM

```powershell
# Conditional Access policies — look for exclusions, report-only gaps, missing MFA
Get-MgIdentityConditionalAccessPolicy -All |
  Select-Object DisplayName,State,@{n='Excluded';e={$_.Conditions.Users.ExcludeUsers}}

# Authorization policy: can users register apps? consent to apps? invite guests?
Get-MgPolicyAuthorizationPolicy | Select-Object DefaultUserRolePermissions,AllowedToCreateApps
```

### Devices and graph collection at scale

```bash
# Devices (joined/registered) — pivot to hybrid identities and PRT abuse
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/devices" | jq '.value[].displayName'
```

```bash
# ROADtools — dump the entire directory to a local SQLite db for offline graph analysis
roadrecon auth -u user@contoso.com -p '<password>'   # or --device-code / --as-app
roadrecon gather
roadrecon plugin policies
# AzureHound — collect into BloodHound for attack-path graphing
azurehound -u user@contoso.com -p '<password>' -t contoso.onmicrosoft.com list -o output.json
```

## Misconfigurations & Findings

- **Default directory read for all members/guests.** Guests and low-priv users can enumerate the full identity graph, exposing privileged users, group structure, and app permissions — a recon goldmine.
- **Excessive standing privileged role assignments.** Many permanent Global Administrators / Privileged Role Administrators instead of PIM-eligible, just-in-time assignments.
- **Service principals with tenant-wide Graph application permissions** (`RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All`) — each is a latent escalation to Global Admin.
- **App registrations with long-lived secrets/certificates** readable by owners; multiple credentials hint at credential sprawl.
- **Role-assignable and dynamic groups** whose ownership/membership rules can be manipulated to grant roles.
- **Conditional Access gaps** — break-glass-style exclusions applied broadly, report-only policies never enforced, or no MFA on privileged roles.
- **Permissive authorization policy** — users allowed to register applications (`AllowedToCreateApps = true`) and to consent to apps, enabling consent-phishing and app-based persistence.
- **Stale/over-privileged guests** retaining access after engagements end.

## Exploitation

Enumeration itself is non-destructive, but the data directly seeds escalation. Practical pivots discovered here:

1. **Identify the shortest path to Global Admin.** Cross-reference role members, group owners, and app-owner edges (AzureHound/BloodHound `MATCH` queries such as paths to the `Global Admin` node) to find a chain from the current principal.
2. **Locate owned applications/service principals.** If the current user owns an app or SP that holds a powerful Graph app role, ownership permits adding credentials and authenticating as that SP — see [privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md).
3. **Spot Conditional Access blind spots** (legacy auth allowed, device-code permitted, excluded users) to choose an authentication path that avoids MFA.
4. **Map cross-tenant and Azure RBAC reach** to plan [lateral movement](../04-lateral-movement/azure-entra-id-lateral.md) from the directory plane into subscriptions.

## Detection & Logging

- Microsoft Graph reads do **not** appear in Entra ID **audit logs** (which record writes/changes) and only authentication appears in **sign-in logs**. Bulk read enumeration is therefore low-signal, but the **initial sign-in** of the enumerating principal is logged with application, IP, and device details.
- Use **MS Graph activity logs** (where enabled) and **sign-in logs** to spot a single principal authenticating to data-collection apps (e.g., unfamiliar client app IDs used by ROADtools/AzureHound) or generating anomalous request volumes.
- Repeated `Get-Mg*` / Graph queries from an SDK client app ID from a new IP/ASN, especially with the `Microsoft Graph PowerShell` or unfamiliar first-party app IDs, are an enumeration indicator.
- **Entra ID Protection** may raise `unfamiliarFeatures`/`anonymousIPAddress` on the sign-in.
- Azure **Activity Logs** capture only ARM-plane reads, not Graph directory reads — relevant only when enumeration touches subscriptions.

## Remediation & Hardening

- Set **"Restrict access to Entra admin/portal"** and, where feasible, restrict default member/guest directory read via the authorization policy (`guestUserRoleId` to the most-restrictive guest role; consider restricting member enumeration).
- Apply **Microsoft Entra PIM**: make privileged roles eligible (just-in-time) rather than permanent, with approval and justification.
- Inventory and minimise **service principal Graph application permissions**; remove unused tenant-wide grants and prefer least-privilege scopes.
- Rotate and shorten **app credentials**; alert on new secret/certificate additions.
- Lock down the **authorization policy**: set `AllowedToCreateApps = false`, restrict user consent to verified publishers / low-risk delegated permissions, and limit who can invite guests.
- Enforce **Conditional Access** MFA on all users (especially admins), block legacy authentication, and remove broad exclusions.
- Periodically run **ScubaGear** or equivalent baselines to detect drift.
- Review and expire **guest accounts** with access reviews.

## Tools

- **ROADtools (roadrecon)** — authenticated full-directory collection to SQLite, offline analysis, GUI.
- **AzureHound + BloodHound** — collects the identity graph and computes shortest attack paths.
- **Microsoft Graph PowerShell SDK** — native cmdlets for all read operations above.
- **az cli** — token acquisition and `az ad` enumeration.
- **AADInternals** — directory and tenant configuration enumeration with an access token.
- **Stormspotter** — graph visualisation of Azure/Entra objects.
- **ScubaGear** — CISA M365 configuration baseline assessment (read-only).

## References

- Microsoft Graph API overview and reference
- Microsoft Entra built-in roles and permissions reference
- Microsoft Graph `directoryRole` resource type
- ROADtools project documentation (dirkjanm)
- BloodhHound / AzureHound documentation (SpecterOps)
- Microsoft Graph PowerShell SDK documentation
- Microsoft Entra managed identities overview
