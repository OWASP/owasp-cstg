---
cstg_id: CSTG-AZURE-SQL-DATABASE-UNAUTH
title: "AZURE Sql Database - Unauthenticated Access"
provider: azure
service: sql-database
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - cloud provider CLI
  - DNS resolution utilities
  - SQL client libraries / command-line query tools
  - TLS/certificate inspection utilities
  - network port scanners
references:
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings
  - https://learn.microsoft.com/en-us/azure/azure-sql/database/security-best-practice
  - https://hackingthe.cloud/azure/
license: CC BY-SA 4.0
---

## Summary

Azure SQL Database is a fully managed relational database service (PaaS). Logical SQL servers are exposed on the public DNS suffix `*.database.windows.net` and, by default, are reachable over the public internet on TCP port 1433. Access is gated by two independent control planes that are frequently misconfigured: a server-level/database-level **IP firewall** and an authentication layer that may accept either SQL logins (username/password) or Microsoft Entra ID principals.

From an unauthenticated, external position the testing objective is to (1) confirm that a logical server exists and resolves, (2) determine whether the network controls permit a connection at all, and (3) determine whether authentication can be reached, weakened, or bypassed. The most common high-impact unauthenticated finding is a logical server whose firewall contains the **"Allow Azure services and resources to access this server"** rule (the `0.0.0.0` start/end firewall entry) combined with a SQL login protected only by a weak or default credential, leaving the database one password guess away from compromise.

This page covers only what is observable and reachable without valid credentials. Authenticated enumeration is covered in [azure-sql-database-enum.md](../02-services/azure-sql-database-enum.md); actions following a successful login are covered in [azure-sql-database-post-exploitation.md](../05-post-exploitation/azure-sql-database-post-exploitation.md).

## Prerequisites

- No credentials to the target tenant or subscription.
- Outbound network access to TCP 1433 (and, for the Redirect connection policy, the dynamic backend range 11000-11999). Some corporate egress filters block 1433; a connection failure may be an egress artifact rather than a target control.
- A candidate logical server name or hostname. Server hostnames follow the pattern `<server-name>.database.windows.net`. Names are globally unique within this namespace, which makes them enumerable by guessing or by harvesting from other artifacts.

## Enumeration

### Discover candidate server hostnames

Logical server names live in a single global DNS namespace, so existence can be tested purely by name resolution without ever contacting the target organization directly. Candidate names are commonly derived from the organization's naming conventions (`<org>-sql-prod`, `<app>db`, `<env>-sqlsrv`), and harvested from:

- Public DNS / certificate transparency logs (CNAMEs pointing at `database.windows.net`).
- Source code, CI/CD configuration, mobile app bundles, and `web.config` / `appsettings.json` files leaked in public repositories or client downloads, where connection strings frequently appear in full.
- Subdomain and asset inventories from prior reconnaissance phases.

Confirm a guessed server resolves:

```bash
# A resolving CNAME chain to a regional gateway confirms the server exists
nslookup contoso-sql-prod.database.windows.net
dig +short contoso-sql-prod.database.windows.net
```

A live logical server resolves through a CNAME to a regional gateway such as `<region>.database.windows.net` and ultimately to a cloudapp.azure.com gateway address. A non-existent server name returns NXDOMAIN.

### Probe network reachability

```bash
# Is the SQL TDS port reachable from this position?
nmap -Pn -p 1433 contoso-sql-prod.database.windows.net

# Quick connectivity check without a scanner
nc -zv contoso-sql-prod.database.windows.net 1433
```

An open 1433 indicates the firewall permits the source IP (or a broad rule is present). A filtered/closed result indicates either a restrictive firewall, that Public Network Access is disabled (Private Endpoint only), or upstream egress filtering.

### Inspect the connection policy and certificate

The regional gateway presents a TLS certificate during the pre-login handshake. Inspecting it confirms the endpoint is genuinely an Azure SQL gateway and reveals the negotiated connection policy behaviour (Redirect vs Proxy).

```bash
# Inspect the gateway TLS certificate (subject/SAN confirms *.database.windows.net)
openssl s_client -connect contoso-sql-prod.database.windows.net:1433 -starttls mssql 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

### Test whether authentication can be reached

If the network layer permits a connection, attempt only a benign, low-volume login probe to confirm that the authentication layer is reachable. The objective at this stage is to distinguish "blocked by firewall" from "reachable, awaiting credentials" - not to brute force.

```bash
# Reachability probe only. The expected result is an explicit auth failure (login failed),
# which proves the network layer is open and the server is accepting logins.
sqlcmd -S contoso-sql-prod.database.windows.net -U probe -P 'invalid' -l 5 -Q "SELECT 1"
```

A response of `Login failed for user 'probe'` confirms reachability and that SQL authentication is enabled. A timeout or `Cannot open server ... requested by the login. Client with IP address ... is not allowed to access the server` reveals the firewall is blocking the source IP - and notably, that error message also discloses the server exists and the caller's own public IP.

## Misconfigurations & Findings

- **Overly broad IP firewall rules.** A server-level firewall rule spanning `0.0.0.0`-`255.255.255.255` (or any large public CIDR) exposes the TDS endpoint to the entire internet. Test by connecting from an arbitrary source IP.
- **"Allow Azure services and resources to access this server" enabled.** This creates a firewall entry with start and end IP `0.0.0.0`, permitting connections from *any* Azure resource in *any* tenant, not just the owner's. An attacker with any Azure compute resource gains a network path to the server, leaving only authentication between them and the data.
- **Public Network Access left enabled when a Private Endpoint exists.** When a Private Endpoint is provisioned, the public endpoint should be disabled; leaving `Public Network Access = Enabled` defeats the purpose of the private link.
- **SQL authentication enabled with weak/default credentials.** Mixed-mode servers accept SQL logins. Common findings include reused administrator passwords, credentials matching the server name, or leaked credentials from public connection strings.
- **Leaked connection strings.** Full connection strings (server, database, user, password) recovered from public repositories, client binaries, or misconfigured storage. These typically grant immediate authenticated access; treat as a direct breach path.
- **`Encrypt=false` / `TrustServerCertificate=true` in client configurations.** Indicates clients accept downgraded or unverified TLS, exposing credentials to network interception on untrusted paths.
- **Minimum TLS version not enforced.** A server permitting TLS 1.0/1.1 exposes connections to known transport weaknesses.

## Exploitation

Unauthenticated exploitation against Azure SQL Database centres on reaching the authentication layer through a permissive firewall and then obtaining a valid credential. Authorisation for any credential testing must be explicit and in scope, and probing should be rate-limited to avoid lockouts and denial of service.

- **Connect from an in-scope Azure resource** when "Allow Azure services" is enabled but the public IP firewall is otherwise restrictive. A connection sourced from any Azure IP is treated as permitted by that rule.
- **Authenticate with recovered credentials.** Use connection strings or credential pairs harvested during reconnaissance directly against the reachable server. A successful login transitions the engagement to the authenticated phase - see [azure-sql-database-post-exploitation.md](../05-post-exploitation/azure-sql-database-post-exploitation.md).
- **Constrained credential testing** against SQL logins should be performed only with explicit authorisation, at low volume, and with awareness that SQL authentication does not enforce Entra ID account lockout - making it both a viable and a noisy vector.

A successful login at this stage usually reflects a network-control failure (the endpoint should not have been reachable) compounded by a credential failure.

## Detection & Logging

- **Azure Activity Logs** record control-plane changes to the logical server, including creation and modification of firewall rules (`Microsoft.Sql/servers/firewallRules/write`) and changes to connection settings. A sudden broadening of firewall rules to `0.0.0.0` or `0.0.0.0/0` is a high-value alert.
- **Microsoft Entra ID sign-in logs** record interactive and non-interactive sign-ins for Entra-based database authentication, including source IP, conditional access result, and failure reason. Repeated failures from unexpected geographies indicate credential probing against Entra-backed logins.
- **Microsoft Entra ID audit logs** record directory-side changes relevant to database access, such as the assignment of the Entra admin for the SQL server.
- **SQL Auditing** (server- or database-level), when enabled and routed to a Log Analytics workspace, Storage account, or Event Hub, captures successful and failed login events (`BATCH_COMPLETED`, `DATABASE_AUTHENTICATION_FAILED_GROUP`, `FAILED_DATABASE_AUTHENTICATION_GROUP`), source IP, and principal. This is the primary record of unauthenticated login attempts reaching the server.
- **Microsoft Defender for SQL** generates alerts for anomalous patterns such as brute-force attempts, logins from unfamiliar locations, and access from a potentially harmful application.

## Remediation & Hardening

- Disable **Public Network Access** and require **Private Endpoints** for all access where feasible; this removes the public TDS endpoint entirely.
- Where public access is required, scope server- and database-level firewall rules to the smallest possible set of known source IPs. Never use `0.0.0.0`-`255.255.255.255` or broad public CIDRs.
- Disable the **"Allow Azure services and resources to access this server"** option unless a specific, justified requirement exists; prefer explicit per-resource access via managed identity and Private Link.
- Prefer **Microsoft Entra ID authentication** and disable SQL authentication (Entra-only authentication) so that access is governed by conditional access, MFA, and centralised lifecycle management.
- Where SQL logins must remain, enforce strong, unique passwords, rotate them, and never embed them in source code, client binaries, or unencrypted configuration.
- Enforce a **minimum TLS version of 1.2** and require encryption (`Encrypt=true`) with certificate validation on all clients.
- Enable **SQL Auditing** to an immutable destination and **Microsoft Defender for SQL** for anomaly detection.

## Tools

- Cloud provider CLI (for confirming control-plane state once any access is obtained).
- DNS resolution utilities (name-existence confirmation via the global `database.windows.net` namespace).
- Network port scanners and connectivity utilities (TCP 1433 reachability).
- TLS/certificate inspection utilities (gateway identity and connection-policy confirmation).
- SQL client libraries and command-line query tools (authentication-reachability probing).

## References

- Azure SQL Database network access controls overview - https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview
- Configure firewall rules - https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure
- Connectivity architecture (gateways, Redirect vs Proxy, ports) - https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture
- Microsoft Entra authentication overview - https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview
- Connectivity settings (TLS, public network access) - https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings
- Security best practices - https://learn.microsoft.com/en-us/azure/azure-sql/database/security-best-practice
- Hacking the Cloud - Azure - https://hackingthe.cloud/azure/
