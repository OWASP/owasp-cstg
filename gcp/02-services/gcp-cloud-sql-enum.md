---
cstg_id: CSTG-GCP-CLOUD-SQL-ENUM
title: "GCP Cloud Sql - Enumeration"
provider: gcp
service: cloud-sql
phase: services
required_access: read-only-audit
required_permissions:
  - cloudsql.instances.list
  - cloudsql.instances.get
  - cloudsql.databases.list
  - cloudsql.users.list
  - cloudsql.backupRuns.list
  - cloudsql.sslCerts.list
  - resourcemanager.projects.get
  - monitoring.timeSeries.list
tools:
  - gcloud
  - Cloud SQL Admin API
  - ScoutSuite
  - Prowler
  - PMapper
  - gcloud asset inventory
references:
  - "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
  - "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/databases"
  - "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users"
  - "https://cloud.google.com/sql/docs/mysql/instance-settings"
  - "https://cloud.google.com/sql/docs/mysql/iam-roles"
  - "https://cloud.google.com/sql/docs/mysql/iam-authentication"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-oriented enumeration of Cloud SQL using the Cloud SQL Admin API and IAM, from the perspective of a principal that already holds valid credentials in the target project (for example, a viewer/auditor role or a compromised service account). The objective is to build a complete inventory of Cloud SQL instances and their security posture — network exposure, TLS enforcement, encryption, backups, database users, flags, and the IAM bindings that govern them — without yet authenticating to any database engine.

The Cloud SQL **control plane** (the Admin API, reached through `gcloud sql` or REST) is entirely separate from the **data plane** (the SQL engine reached over 3306/5432/1433). Control-plane enumeration reveals configuration and metadata; it also reveals the capabilities a principal would have to *change* configuration, set passwords, or trigger exports — which is the bridge into privilege escalation and post-exploitation.

## Prerequisites

- Valid credentials for a principal in the target project: a user, or a service-account key / impersonable service account / metadata-derived token.
- Read access to the Cloud SQL Admin API. The predefined `roles/cloudsql.viewer` grants the `cloudsql.instances.get/list`, `cloudsql.databases.list`, `cloudsql.users.list`, `cloudsql.backupRuns.list`, and `cloudsql.sslCerts.list` permissions used below. `roles/viewer` at project level is also sufficient for read enumeration.
- `gcloud` configured with the credentials, or the ability to call the REST endpoint with a bearer token.

```bash
# Confirm identity and active project
gcloud config list
gcloud auth list
gcloud projects describe "$(gcloud config get-value project)"
```

## Enumeration

### Instance inventory

```bash
# List all instances in the active project
gcloud sql instances list

# Across projects you can read
for p in $(gcloud projects list --format='value(projectId)'); do
  echo "== $p =="
  gcloud sql instances list --project "$p" 2>/dev/null
done

# Full configuration of one instance (the key artifact)
gcloud sql instances describe <instance> --format=json
```

Raw Admin API equivalent:

```bash
TOKEN=$(gcloud auth print-access-token)
PROJECT=$(gcloud config get-value project)

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://sqladmin.googleapis.com/v1/projects/$PROJECT/instances" | jq .

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://sqladmin.googleapis.com/v1/projects/$PROJECT/instances/<instance>" | jq .
```

### Extract the security-relevant fields

From `instances.get`/`describe`, pull the fields that determine exposure and data protection:

```bash
gcloud sql instances describe <instance> --format=json | jq '{
  name, databaseVersion, region,
  publicIp: .ipAddresses,
  authorizedNetworks: .settings.ipConfiguration.authorizedNetworks,
  ipv4Enabled: .settings.ipConfiguration.ipv4Enabled,
  privateNetwork: .settings.ipConfiguration.privateNetwork,
  requireSsl: .settings.ipConfiguration.requireSsl,
  sslMode: .settings.ipConfiguration.sslMode,
  backupEnabled: .settings.backupConfiguration.enabled,
  pitr: .settings.backupConfiguration.pointInTimeRecoveryEnabled,
  deletionProtection: .settings.deletionProtectionEnabled,
  diskEncryption: .diskEncryptionConfiguration,
  databaseFlags: .settings.databaseFlags
}'
```

### Databases, users, certificates, backups

```bash
# Databases (schemas) on the instance
gcloud sql databases list --instance=<instance>

# Database users (built-in and IAM users)
gcloud sql users list --instance=<instance>

# Client SSL certificates issued for the instance
gcloud sql ssl-certs list --instance=<instance>

# Server CA chain (also confirms TLS posture)
gcloud sql ssl server-ca-certs list --instance=<instance>

# Backups available (potential data-exfil source via restore/export)
gcloud sql backups list --instance=<instance>

# Operations history (recent admin actions on the instance)
gcloud sql operations list --instance=<instance>
```

### Database flags worth noting

Database flags often re-enable risky engine features. Capture them during enumeration:

```bash
gcloud sql instances describe <instance> \
  --format='value(settings.databaseFlags)'
```

Flags to flag: MySQL `local_infile=on` (enables `LOAD DATA LOCAL`), PostgreSQL `cloudsql.enable_pg_cron`, logging flags turned off (`log_connections`/`log_disconnections=off`, `general_log=off`), and `skip_show_database=off`.

### IAM bindings over Cloud SQL

Determine which principals can read, modify, or connect to instances — this defines the escalation surface.

```bash
# Project-level bindings, filtered to SQL-relevant roles
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.role | test("cloudsql|owner|editor"))'

# What can the current identity do? (testIamPermissions)
gcloud projects test-iam-permissions "$PROJECT" \
  --permissions=cloudsql.instances.update,cloudsql.users.update,cloudsql.instances.connect,cloudsql.instances.export
```

### IAM database authentication users

If IAM database authentication is enabled, the principal may be able to obtain a short-lived login token rather than a static password:

```bash
# IAM users appear with type CLOUD_IAM_USER / CLOUD_IAM_SERVICE_ACCOUNT
gcloud sql users list --instance=<instance>

# Obtain an OAuth token usable as the DB password for an IAM DB user
gcloud sql generate-login-token
```

### Cross-project discovery via Asset Inventory

```bash
# Org-wide search for all Cloud SQL instances (needs cloudasset.assets.* read)
gcloud asset search-all-resources \
  --scope=organizations/<org-id> \
  --asset-types=sqladmin.googleapis.com/Instance \
  --format='table(name,assetType,project)'
```

## Misconfigurations & Findings

- **`ipConfiguration.authorizedNetworks` containing `0.0.0.0/0`** alongside `ipv4Enabled=true` — public exposure of the data-plane listener (see the unauthenticated page).
- **`requireSsl=false` / `sslMode=ALLOW_UNENCRYPTED_AND_ENCRYPTED`** — cleartext connections permitted.
- **No customer-managed encryption** where required by policy (`diskEncryptionConfiguration` absent means Google-managed keys; not a finding by itself, but relevant to data-governance scope).
- **Backups disabled or PITR disabled** — recoverability gap; conversely, *enabled* backups are an exfiltration avenue for a principal with restore/export rights.
- **`deletionProtectionEnabled=false`** — destructive actions are unguarded.
- **Risky database flags** (`local_infile=on`, audit/logging flags off) reducing detection and widening engine attack surface.
- **Over-broad IAM**: principals with `roles/cloudsql.admin`, `roles/cloudsql.editor`, `roles/editor`, or `roles/owner` can set user passwords, change network config, and export data. Service accounts with these roles whose keys are exposed are high-value.
- **Stale client SSL certs** that were never revoked.

Why it matters: control-plane enumeration produces the exact list of instances, their reachability, their built-in/IAM users, and the principals who can manipulate them — turning a single credential into a targeted plan for data access without guessing.

## Exploitation

Read-only enumeration is not itself exploitation, but it directly seeds it:

1. **Map a path to a database session.** If the enumerated instance has a public IP and the current principal holds `cloudsql.users.update`, the principal can set a known password on a built-in user and then connect (covered in post-exploitation). If IAM DB auth is enabled and the principal is (or can impersonate) an IAM DB user, `gcloud sql generate-login-token` yields immediate access.

2. **Identify export/backup-based exfiltration.** Instances with `cloudsql.instances.export` available to the principal and a writable Cloud Storage bucket allow whole-database dumps without ever authenticating to the engine.

3. **Identify impersonation chains.** Cross-reference IAM bindings with service accounts the principal can impersonate (`iam.serviceAccounts.getAccessToken`) to reach a more privileged Cloud SQL admin identity.

```bash
# Quick triage: which readable instances are public AND non-SSL?
for i in $(gcloud sql instances list --format='value(name)'); do
  gcloud sql instances describe "$i" --format=json | jq -r \
    'select(.settings.ipConfiguration.ipv4Enabled==true) |
     "\(.name) public=\(.settings.ipConfiguration.ipv4Enabled) ssl=\(.settings.ipConfiguration.requireSsl) nets=\(.settings.ipConfiguration.authorizedNetworks)"'
done
```

For the follow-on actions see [Cloud SQL - Post-Exploitation](../05-post-exploitation/gcp-cloud-sql-post-exploitation.md). For the external view of the same exposure see [Cloud SQL - Unauthenticated Access](../01-unauthenticated-external/gcp-cloud-sql-unauthenticated.md).

## Detection & Logging

- **Cloud Audit Logs — Data Access logs** record control-plane *reads*: `cloudsql.instances.list`, `cloudsql.instances.get`, `cloudsql.databases.list`, `cloudsql.users.list`, etc. Data Access logging for Cloud SQL Admin API must be explicitly enabled; if it is off, read enumeration is invisible in audit logs.
- `testIamPermissions` and `getIamPolicy` calls also appear in Data Access logs when enabled, and broad permission probing is a useful detection signal.
- `gcloud sql generate-login-token` and IAM-token minting (`iam.serviceAccounts.getAccessToken`) appear in audit logs and indicate an attempt to obtain database access via IAM.
- High-volume enumeration from a single principal across many projects (especially via Asset Inventory) is anomalous and detectable through audit-log aggregation.

Recommended detections:
- Enable Data Access audit logs for the Cloud SQL Admin API and alert on enumeration bursts.
- Alert on `generate-login-token` / `getAccessToken` for SQL-relevant service accounts outside expected workloads.

## Remediation & Hardening

- **Apply least privilege.** Grant `roles/cloudsql.viewer` only where genuine read access is needed; avoid `roles/editor`/`roles/owner` for routine database operators. Use `roles/cloudsql.client` (connect-only) for application service accounts rather than admin roles.
- **Enable Data Access audit logs** for Cloud SQL so read enumeration is recorded.
- **Use IAM database authentication** to eliminate static passwords and bind database access to auditable IAM identities.
- **Enforce Organization Policies** (`constraints/sql.restrictPublicIp`, `constraints/sql.restrictAuthorizedNetworks`, `constraints/sql.disableDefaultUserPassword`) to keep enumerated misconfigurations from existing.
- **Restrict who can impersonate** Cloud SQL admin service accounts; avoid downloadable service-account keys.
- **Review and revoke stale client SSL certificates** surfaced by `ssl-certs list`.

## Tools

- **gcloud / Cloud SQL Admin API** — primary enumeration interface for instances, databases, users, certs, backups, operations.
- **gcloud asset search-all-resources** — org-wide Cloud SQL discovery across many projects from one query.
- **ScoutSuite / Prowler** — automated GCP posture assessment that flags public IP, missing SSL enforcement, disabled backups, and broad IAM on Cloud SQL.
- **PMapper** — models IAM relationships to find principals and impersonation chains that reach Cloud SQL admin capabilities.

## References

- Cloud SQL Admin API — instances: https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances
- Cloud SQL Admin API — databases: https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/databases
- Cloud SQL Admin API — users: https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users
- Instance settings reference: https://cloud.google.com/sql/docs/mysql/instance-settings
- Cloud SQL IAM roles: https://cloud.google.com/sql/docs/mysql/iam-roles
- IAM database authentication: https://cloud.google.com/sql/docs/mysql/iam-authentication
