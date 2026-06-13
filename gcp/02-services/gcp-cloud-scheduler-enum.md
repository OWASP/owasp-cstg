---
cstg_id: CSTG-GCP-CLOUD-SCHEDULER-ENUM
title: "GCP Cloud Scheduler - Enumeration"
provider: gcp
service: cloud-scheduler
phase: services
required_access: read-only-audit
required_permissions:
  - cloudscheduler.jobs.list
  - cloudscheduler.jobs.get
  - cloudscheduler.locations.list
  - resourcemanager.projects.get
tools:
  - gcloud CLI
  - Cloud Scheduler REST API
  - Cloud Asset Inventory
references:
  - https://cloud.google.com/scheduler/docs
  - https://cloud.google.com/scheduler/docs/reference/rest
  - https://cloud.google.com/scheduler/docs/creating
  - https://cloud.google.com/scheduler/docs/http-target-auth
  - https://cloud.google.com/iam/docs/understanding-roles#cloudscheduler-roles
license: CC BY-SA 4.0
---

## Summary

Cloud Scheduler is Google Cloud's fully managed cron-job service. A scheduler job fires on a cron-style schedule and delivers a target invocation to one of three destinations: an HTTP/HTTPS endpoint (`httpTarget`), a Pub/Sub topic (`pubsubTarget`), or an App Engine HTTP request (`appEngineHttpTarget`). Each job optionally carries an OAuth or OIDC identity (a service account) used to authenticate to the target, and HTTP targets can embed arbitrary headers and a request body.

From a testing perspective, Cloud Scheduler is high-value reconnaissance because a single `jobs.get` reveals: which service accounts are wired to fire automation, which internal and external URLs are invoked on a schedule, what bearer-style headers or bodies are baked into the job definition, and which Pub/Sub topics drive downstream processing. This information maps the project's automation surface and frequently exposes secrets stored in headers or bodies. Enumeration here is read-only and is a prerequisite for the privilege-escalation and persistence techniques documented in the sibling pages.

## Prerequisites

- Valid credentials for the target project (user, service account key, workload identity, or an active `gcloud`/metadata-server session).
- The Cloud Scheduler API (`cloudscheduler.googleapis.com`) enabled on the project. Disabled APIs return `403 SERVICE_DISABLED` and indicate no jobs exist.
- Read permissions. The predefined role `roles/cloudscheduler.viewer` grants the minimal set:
  - `cloudscheduler.jobs.list`
  - `cloudscheduler.jobs.get`
  - `cloudscheduler.locations.list`
- Broader roles that include these: `roles/cloudscheduler.admin`, `roles/editor`, `roles/viewer`, `roles/owner`.

## Enumeration

### Identify enabled APIs and available locations

Cloud Scheduler is regional. Jobs live under a parent of the form `projects/PROJECT/locations/LOCATION`, where the location is an App Engine region (for example `us-central1`, `europe-west1`). Confirm the API is enabled and list the locations that host jobs.

```bash
# Is the API enabled?
gcloud services list --enabled --project "$PROJECT" \
  --filter="config.name:cloudscheduler.googleapis.com"

# List locations that can host scheduler jobs
gcloud scheduler locations list --project "$PROJECT"
```

Raw REST equivalent:

```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudscheduler.googleapis.com/v1/projects/$PROJECT/locations"
```

### List jobs in each location

```bash
for LOC in us-central1 us-east1 europe-west1 asia-northeast1; do
  echo "== $LOC =="
  gcloud scheduler jobs list --location "$LOC" --project "$PROJECT"
done
```

REST:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudscheduler.googleapis.com/v1/projects/$PROJECT/locations/$LOC/jobs"
```

### Describe each job in full

The list response is summarised; the `get` call returns the complete job definition including the target, the attached service account, headers, and the body. This is the most valuable single call.

```bash
gcloud scheduler jobs describe "$JOB_NAME" \
  --location "$LOC" --project "$PROJECT" --format=json
```

REST:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudscheduler.googleapis.com/v1/projects/$PROJECT/locations/$LOC/jobs/$JOB_NAME"
```

Fields worth extracting from each job:

- `schedule` and `timeZone` - cron expression and timezone (when automation fires).
- `httpTarget.uri` / `httpTarget.httpMethod` - destination URL and verb. Note internal URLs (Cloud Run, Cloud Functions, internal load balancers, private endpoints, `*.run.app`, `*.cloudfunctions.net`) versus external hosts.
- `httpTarget.headers` - custom headers. Frequently contains `Authorization: Bearer <token>`, API keys, `X-Api-Key`, webhook signing secrets, or basic-auth credentials in cleartext.
- `httpTarget.body` - base64-encoded request payload, which may include credentials, IDs, or command parameters.
- `httpTarget.oauthToken.serviceAccountEmail` - the SA whose OAuth token is sent to Google APIs (audience is the target host).
- `httpTarget.oidcToken.serviceAccountEmail` and `.audience` - the SA minting an OIDC identity token, used to invoke Cloud Run/Functions and other OIDC-validating services.
- `pubsubTarget.topicName` / `.data` / `.attributes` - the topic that is published to and the static payload.
- `appEngineHttpTarget` - the App Engine service/version/relative URI invoked.
- `state` - `ENABLED`, `PAUSED`, or `DISABLED`.
- `attemptDeadline`, `retryConfig` - delivery behaviour.

### Decode embedded bodies and inspect identities

```bash
# Decode the base64 body of an HTTP job
gcloud scheduler jobs describe "$JOB_NAME" --location "$LOC" \
  --project "$PROJECT" --format="value(httpTarget.body)" | base64 -d

# List the service accounts referenced across all jobs (privilege-mapping seed)
for LOC in $(gcloud scheduler locations list --project "$PROJECT" --format="value(locationId)"); do
  gcloud scheduler jobs list --location "$LOC" --project "$PROJECT" --format=json
done | jq -r '.[] | (.httpTarget.oauthToken.serviceAccountEmail // empty),
                    (.httpTarget.oidcToken.serviceAccountEmail // empty)' | sort -u
```

Each discovered service account should be cross-referenced against IAM bindings (see [GCP IAM enumeration](../02-services/gcp-iam-enum.md) where present) to understand what privileges an attacker would gain by causing a job to act as that identity.

### Bulk discovery via Cloud Asset Inventory

When `cloudasset.assets.searchAllResources` is available, Cloud Scheduler jobs can be enumerated across an entire organization or folder in a single query, without iterating regions or projects.

```bash
gcloud asset search-all-resources \
  --scope="organizations/$ORG_ID" \
  --asset-types="cloudscheduler.googleapis.com/Job" \
  --format=json
```

### Read-only test of execution behaviour

`jobs.run` triggers a job immediately on demand. It is **not** read-only - it causes the target to be invoked with the job's identity and payload - and is therefore documented under the privilege-escalation page rather than here. During pure enumeration, do not invoke `jobs.run`.

## Misconfigurations & Findings

- **Secrets in headers or body.** Long-lived bearer tokens, API keys, signing secrets, or basic-auth credentials stored in `httpTarget.headers`/`httpTarget.body`. These are readable by any principal with `cloudscheduler.jobs.get` and are not redacted by the API.
- **Over-privileged attached service account.** A job configured to act as a highly privileged SA (for example one with `roles/editor`, `roles/owner`, or token-creation rights). Any principal who can update or run the job inherits that identity's reach.
- **Unauthenticated HTTP targets.** Jobs hitting endpoints with no `oauthToken`/`oidcToken`, implying the target relies on network position or has no authentication - a target worth probing directly.
- **Internal endpoints exposed by definition.** Job URIs revealing internal Cloud Run/Functions/ILB hostnames and request shapes that would otherwise be undiscoverable externally.
- **Broad edit access.** Principals holding `cloudscheduler.jobs.update`/`create`/`run` beyond the automation owners, enabling the privilege-escalation and persistence paths.
- **Stale or paused jobs.** `PAUSED`/`DISABLED` jobs still hold credentials and SA bindings and can be re-enabled.

## Detection & Logging

Cloud Scheduler enumeration is captured by Cloud Audit Logs.

- `cloudscheduler.jobs.list` and `cloudscheduler.jobs.get` are **Data Access** audit logs (`DATA_READ`). They are **not** recorded unless Data Access audit logging is explicitly enabled for the Cloud Scheduler service in the project/folder/org IAM audit configuration. Many environments leave `DATA_READ` off, so read enumeration is often invisible - defenders should enable it.
- Administrative changes (`jobs.create`, `jobs.update`, `jobs.delete`, `jobs.pause`, `jobs.resume`, `jobs.run`) are **Admin Activity** logs and are always on.

Sample query (Logs Explorer):

```
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.serviceName="cloudscheduler.googleapis.com"
protoPayload.methodName=("google.cloud.scheduler.v1.CloudScheduler.ListJobs" OR
  "google.cloud.scheduler.v1.CloudScheduler.GetJob")
```

Indicators of reconnaissance: a single principal issuing `GetJob` across many or all jobs and locations in a short window, or `ListJobs` calls from unusual source IPs / principals that do not own the automation.

## Remediation & Hardening

- Enable Data Access (`DATA_READ`) audit logging for `cloudscheduler.googleapis.com` so enumeration is recorded.
- Never store secrets in job headers or bodies. Reference Secret Manager from the target instead, and have the target resolve the secret at runtime using its own identity.
- Grant `roles/cloudscheduler.viewer`/`admin` narrowly; avoid project-wide `viewer`/`editor` for principals that do not need scheduler access.
- Attach least-privilege, single-purpose service accounts to jobs - one SA per job, scoped to exactly the target it invokes.
- Prefer OIDC tokens with a specific `audience` over static `Authorization` headers so no long-lived secret lives in the job.
- Periodically review jobs across all regions via Cloud Asset Inventory and remove stale or paused jobs.

## Tools

- `gcloud scheduler` CLI (`locations list`, `jobs list`, `jobs describe`).
- Cloud Scheduler REST API (`v1`).
- Cloud Asset Inventory (`gcloud asset search-all-resources`) for org-wide discovery.
- `jq` / `base64` for parsing job definitions and decoding bodies.

## References

- https://cloud.google.com/scheduler/docs
- https://cloud.google.com/scheduler/docs/reference/rest
- https://cloud.google.com/scheduler/docs/creating
- https://cloud.google.com/scheduler/docs/http-target-auth
- https://cloud.google.com/iam/docs/understanding-roles#cloudscheduler-roles
- https://cloud.google.com/logging/docs/audit
