---
cstg_id: CSTG-GCP-BIGQUERY-ENUM
title: "GCP Bigquery - Enumeration"
provider: gcp
service: bigquery
phase: services
required_access: read-only-audit
required_permissions:
  - bigquery.datasets.get
  - bigquery.datasets.getIamPolicy
  - bigquery.tables.list
  - bigquery.tables.get
  - bigquery.tables.getIamPolicy
  - bigquery.models.list
  - bigquery.routines.list
  - bigquery.jobs.list
  - bigquery.jobs.create
  - bigquery.capacityCommitments.list
  - bigquery.reservations.list
  - bigquery.transfers.get
  - bigquery.connections.list
  - resourcemanager.projects.get
tools:
  - "Cloud SDK CLI (bq, gcloud)"
  - "BigQuery REST API client"
  - "BigQuery Data Transfer Service API client"
references:
  - https://cloud.google.com/bigquery/docs/reference/rest
  - https://cloud.google.com/bigquery/docs/information-schema-intro
  - https://cloud.google.com/bigquery/docs/access-control
  - https://cloud.google.com/bigquery/docs/access-control-basic-roles
  - https://cloud.google.com/bigquery/docs/control-access-to-resources-iam
  - https://cloud.google.com/bigquery/docs/reference/bq-cli-reference
  - https://cloud.google.com/bigquery/docs/authorized-views
  - https://cloud.google.com/bigquery/docs/reference/data-transfer/rest
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

BigQuery is Google Cloud's serverless, multi-tenant analytics data warehouse. Because it is frequently the destination for analytics pipelines, application telemetry, billing exports, and ad-hoc data dumps, a single BigQuery project often concentrates an organization's most sensitive structured data: customer PII, payment records, authentication logs, exported secrets, and copies of operational databases. The service is organized as a hierarchy of `project -> dataset -> table/view/model/routine`, with access controllable at the organization, project, dataset, table, column, and row level.

Enumeration of BigQuery focuses on discovering which projects expose datasets, mapping the access controls applied at each level of the hierarchy, identifying tables and views that contain sensitive content, and recognizing structural features (authorized views, authorized datasets, external connections, scheduled transfers, and user-defined routines) that can be abused later. Much of this can be performed entirely through metadata APIs and the `INFORMATION_SCHEMA` views without reading a single row of table data, which makes it low-noise relative to running full data queries.

This page covers read-only and audit-level enumeration. Exploitation of discovered weaknesses (data exfiltration, lateral movement via service-account-backed connections, privilege escalation through routines) is covered in [GCP BigQuery - Post-Exploitation](../05-post-exploitation/gcp-bigquery-post-exploitation.md).

## Prerequisites

- A principal (user, service account, or federated identity) with at least metadata-read access to one or more BigQuery resources. Useful baseline roles include `roles/bigquery.metadataViewer` (metadata only, no data), `roles/bigquery.dataViewer` (metadata + data), and `roles/bigquery.user` (run jobs and create datasets). The basic role `roles/viewer` also grants broad BigQuery read access.
- Knowledge of, or ability to enumerate, the target project IDs. BigQuery resources are always scoped to a project; cross-project enumeration requires the relevant identity to be granted access in each project.
- A configured Cloud SDK environment or a valid OAuth 2.0 / service-account credential able to call `bigquery.googleapis.com` and `bigquerydatatransfer.googleapis.com`.

> Note on permission granularity: listing datasets requires `bigquery.datasets.get` against the project; listing tables requires `bigquery.tables.list` on the dataset; reading table schema requires `bigquery.tables.get`. The `*.getIamPolicy` permissions are needed to read access bindings and are commonly overlooked when scoping least-privilege audit roles.

## Enumeration

### Establish identity and reachable projects

Before enumerating BigQuery, confirm which identity is active and which projects it can see. Cross-reference with project-level IAM enumeration.

```bash
# Active identity and token scopes
gcloud auth list
gcloud config list

# Projects the identity can resolve
gcloud projects list
gcloud asset search-all-resources \
  --scope="organizations/ORG_ID" \
  --asset-types="bigquery.googleapis.com/Dataset,bigquery.googleapis.com/Table"
```

`gcloud asset search-all-resources` (Cloud Asset Inventory) is the most efficient way to discover BigQuery resources across an entire organization or folder when the identity holds `cloudasset.assets.searchAllResources`, and it surfaces datasets/tables that the identity may not be able to list project-by-project.

### List datasets

```bash
# CLI
bq ls --project_id=PROJECT_ID
bq ls --all --project_id=PROJECT_ID          # include hidden/anonymous datasets
bq ls --datasets --max_results=1000 --project_id=PROJECT_ID
```

```http
GET https://bigquery.googleapis.com/bigquery/v2/projects/PROJECT_ID/datasets?all=true
```

The `all=true` parameter returns hidden datasets, including the per-user anonymous `_xxxx` datasets that hold cached query results. Cached result datasets can contain materialized copies of sensitive query output and are frequently forgotten by data owners.

### Inspect dataset metadata and access controls

```bash
bq show --format=prettyjson PROJECT_ID:DATASET
```

```http
GET https://bigquery.googleapis.com/bigquery/v2/projects/PROJECT_ID/datasets/DATASET
```

The dataset resource contains an `access` array that is BigQuery's primary access-control mechanism. Each entry maps a role (`OWNER`, `WRITER`, `READER`, or a fine-grained IAM role) to a grantee. Grantees can be:

- `userByEmail` / `groupByEmail` — individual or group principals
- `specialGroup` — `projectOwners`, `projectWriters`, `projectReaders`, or **`allAuthenticatedUsers`** (any Google-authenticated principal anywhere)
- `iamMember` — IAM members including `allUsers` (fully public) in some configurations
- `view` — an **authorized view** in another dataset that is permitted to query this dataset on a caller's behalf
- `dataset` — an **authorized dataset** granted blanket read access
- `routine` — an **authorized routine** permitted to read this dataset

Pay particular attention to `allUsers`, `allAuthenticatedUsers`, and broad `domain` grants, which expose data beyond the intended audience.

### Read IAM policies at dataset and table level

In addition to the legacy `access` list, BigQuery supports resource-level IAM policies on datasets and tables.

```bash
bq get-iam-policy PROJECT_ID:DATASET
bq get-iam-policy --table PROJECT_ID:DATASET.TABLE
```

```http
POST https://bigquery.googleapis.com/bigquery/v2/projects/PROJECT_ID/datasets/DATASET:getIamPolicy
POST https://bigquery.googleapis.com/bigquery/v2/projects/PROJECT_ID/datasets/DATASET/tables/TABLE:getIamPolicy
```

Compare the IAM policy with the `access` list — both grant access, and an audit that examines only one of the two will miss exposures. Look for conditional role bindings, which BigQuery supports and which may scope access by resource name or time.

### List and inspect tables, views, models, and routines

```bash
bq ls --max_results=10000 PROJECT_ID:DATASET           # tables and views
bq ls --models PROJECT_ID:DATASET                       # BigQuery ML models
bq ls --routines PROJECT_ID:DATASET                     # functions and stored procedures
bq ls --transfer_config --transfer_location=US          # scheduled data transfers
```

```bash
# Full schema, type (TABLE / VIEW / MATERIALIZED_VIEW / EXTERNAL), row count, size
bq show --format=prettyjson PROJECT_ID:DATASET.TABLE
```

For each object capture: `type`, `numRows`, `numBytes`, `schema.fields` (column names and types — often self-describing, e.g. `ssn`, `password_hash`, `card_number`), `expirationTime`, `labels`, and for views the embedded SQL `query`. The view definition reveals which underlying datasets/tables it reads, which is essential for finding authorized-view trust relationships.

### Use INFORMATION_SCHEMA for bulk metadata harvesting

`INFORMATION_SCHEMA` views allow metadata enumeration in a single query and only require `bigquery.jobs.create` plus metadata read on the target dataset.

```sql
-- Every column across a dataset, with types
SELECT table_catalog, table_schema, table_name, column_name, data_type
FROM `PROJECT_ID`.`DATASET`.INFORMATION_SCHEMA.COLUMNS
ORDER BY table_name, ordinal_position;

-- Table inventory with sizes and row counts (region-scoped)
SELECT table_schema, table_name, total_rows, total_logical_bytes, creation_time
FROM `PROJECT_ID`.`region-us`.INFORMATION_SCHEMA.TABLE_STORAGE
ORDER BY total_logical_bytes DESC;

-- View definitions (reveals authorized-view source tables)
SELECT table_schema, table_name, view_definition
FROM `PROJECT_ID`.`DATASET`.INFORMATION_SCHEMA.VIEWS;

-- Routine (UDF / stored procedure) bodies
SELECT routine_schema, routine_name, routine_type, security_type, routine_definition
FROM `PROJECT_ID`.`DATASET`.INFORMATION_SCHEMA.ROUTINES;

-- Object-level access grants
SELECT * FROM `PROJECT_ID`.`DATASET`.INFORMATION_SCHEMA.OBJECT_PRIVILEGES;
```

The `region-*` and `region-eu`/`region-us` scoping for storage and job views means an enumeration must be repeated per region where data may reside.

### Enumerate jobs, reservations, and transfers

```bash
# Recent jobs (queries) run in the project - reveals query patterns and other principals
bq ls --jobs --all --max_results=1000 PROJECT_ID
bq show --format=prettyjson --job JOB_ID
```

```sql
-- Query history with the principal, statement text, and bytes processed
SELECT creation_time, user_email, job_type, statement_type, total_bytes_processed, query
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
ORDER BY creation_time DESC;
```

Job history is a rich source of intelligence: it exposes the literal SQL other principals run (which can leak filter values, table names in other projects, and embedded credentials), the service accounts that operate pipelines, and the volume of data movement that constitutes a "normal" baseline.

### Enumerate external connections and transfer configurations

```bash
# External connections (Cloud SQL, Spanner, AWS/Azure federation, Vertex AI)
bq ls --connection --project_id=PROJECT_ID --location=US

# Scheduled query / data transfer configs
bq ls --transfer_config --transfer_location=US --project_id=PROJECT_ID
```

```http
GET https://bigquerydatatransfer.googleapis.com/v1/projects/PROJECT_ID/locations/-/transferConfigs
GET https://bigqueryconnection.googleapis.com/v1/projects/PROJECT_ID/locations/-/connections
```

Each connection and each scheduled transfer runs under a service account. Note the `serviceAccountName` field — these are high-value identities because they typically hold standing permissions on external data sources and can be a pivot target.

## Misconfigurations & Findings

- **Public or all-authenticated datasets** — an `access` entry or IAM binding for `allUsers` or `allAuthenticatedUsers` exposes data to the internet or to any Google account. This is the single most impactful BigQuery misconfiguration.
- **Overbroad basic roles** — `roles/editor`/`roles/viewer` at the project level grant data access to every dataset, defeating per-dataset controls.
- **Authorized views/datasets over-scoped** — an authorized view that reads a sensitive source but exposes too many columns/rows acts as a controlled bypass that is broader than intended.
- **`DEFINER`-rights routines** — stored procedures and UDFs with `security_type = DEFINER` execute with the creator's privileges, enabling callers to read data they otherwise cannot.
- **Sensitive data in cached/anonymous datasets** — the per-user `_xxxx` result-cache datasets retain materialized query output without the original access controls.
- **Service-account-backed connections and transfers with standing external access** — connections to Cloud SQL, Spanner, or cross-cloud sources concentrate credentials in a service account that may be assumable.
- **Missing column-level / row-level security** — sensitive columns (`ssn`, `dob`, `card_pan`) lacking policy tags or row-access policies are fully readable by anyone with table read access.
- **Long or absent table expiration** — forgotten exports and snapshots accumulate sensitive data indefinitely.
- **Verbose query history exposure** — broad `bigquery.jobs.list` access lets a principal read other users' query text, leaking secrets and schema of other systems.

## Detection & Logging

BigQuery activity is recorded in Cloud Audit Logs.

- **Admin Activity** logs (always on) record metadata-mutating operations and IAM changes: `google.cloud.bigquery.v2.DatasetService.UpdateDataset`, `SetIamPolicy`, dataset/table creation and deletion.
- **Data Access** logs (must be explicitly enabled for `DATA_READ`/`DATA_WRITE` on the BigQuery service) record `jobservice.jobcompleted`, `tabledataservice.list`, and query execution including the principal and statement.
- Enumeration that uses only metadata APIs (`datasets.get`, `tables.get`, `getIamPolicy`) generates `DATA_READ`/metadata entries that are often *not* logged unless Data Access logging is enabled, making metadata enumeration comparatively quiet.

Representative queries against the audit log sink:

```sql
-- Metadata enumeration and IAM reads
protoPayload.methodName="google.iam.v1.IAMPolicy.GetIamPolicy"
resource.type="bigquery_dataset"

-- Listing of datasets/tables
protoPayload.methodName=("google.cloud.bigquery.v2.DatasetService.ListDatasets"
  OR "google.cloud.bigquery.v2.TableService.ListTables")

-- Query jobs (requires Data Access logging)
resource.type="bigquery_resource"
protoPayload.methodName="jobservice.jobcompleted"
```

Defenders should ensure Data Access logging is enabled for BigQuery, alert on `INFORMATION_SCHEMA.JOBS*` queries by unexpected principals, and monitor for `SetIamPolicy`/dataset `access` changes that introduce `allUsers`/`allAuthenticatedUsers`.

## Remediation & Hardening

- Disable basic roles in favor of predefined BigQuery roles; never grant `roles/bigquery.dataViewer` at project scope when dataset scope suffices.
- Remove `allUsers` and `allAuthenticatedUsers` from dataset `access` lists and IAM policies; audit with Policy Analyzer / Cloud Asset Inventory.
- Apply column-level security with policy tags (Data Catalog / Dataplex) and row-level security policies on sensitive tables.
- Set table/partition expiration to bound data retention; disable result caching for sensitive workloads.
- Enable Data Access audit logging for BigQuery and route to a tamper-resistant sink.
- Restrict `bigquery.jobs.list`/job metadata visibility so principals cannot read others' query text.
- Use authorized views/datasets/routines deliberately and review their column/row exposure; prefer `INVOKER`-rights routines unless `DEFINER` is required.
- Scope and rotate the service accounts behind connections and transfer configs; grant them least privilege on external sources.
- Enforce VPC Service Controls perimeters around BigQuery to limit data egress to untrusted networks.

## Tools

- Cloud SDK CLI (`bq`, `gcloud`) for dataset/table/job/connection enumeration.
- BigQuery REST API and `INFORMATION_SCHEMA` views for bulk metadata harvesting.
- Cloud Asset Inventory (`gcloud asset search-all-resources`) for org-wide resource discovery.
- BigQuery Data Transfer Service and Connection Service APIs for transfer/connection enumeration.
- IAM Policy Analyzer for resolving effective access.

## References

- BigQuery REST API reference — https://cloud.google.com/bigquery/docs/reference/rest
- INFORMATION_SCHEMA introduction — https://cloud.google.com/bigquery/docs/information-schema-intro
- BigQuery access control overview — https://cloud.google.com/bigquery/docs/access-control
- Basic roles and permissions — https://cloud.google.com/bigquery/docs/access-control-basic-roles
- Control access to resources with IAM — https://cloud.google.com/bigquery/docs/control-access-to-resources-iam
- Authorized views — https://cloud.google.com/bigquery/docs/authorized-views
- `bq` command-line reference — https://cloud.google.com/bigquery/docs/reference/bq-cli-reference
- Data Transfer Service REST API — https://cloud.google.com/bigquery/docs/reference/data-transfer/rest
- hackingthe.cloud (GCP) — https://hackingthe.cloud/gcp/
