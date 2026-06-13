---
cstg_id: CSTG-GCP-CLOUD-FUNCTIONS-ENUM
title: "GCP Cloud Functions - Enumeration"
provider: gcp
service: cloud-functions
phase: services
required_access: read-only-audit
required_permissions: [cloudfunctions.functions.list, cloudfunctions.functions.get, cloudfunctions.functions.getIamPolicy, cloudfunctions.functions.sourceCodeGet, run.services.list, run.services.get, run.services.getIamPolicy, iam.serviceAccounts.list]
tools: [gcloud, gsutil, curl, ScoutSuite, gcp_enum]
references: ["https://cloud.google.com/functions/docs/reference/rest", "https://cloud.google.com/functions/docs/securing/managing-access-iam", "https://cloud.google.com/functions/docs/concepts/version-comparison", "https://cloud.google.com/run/docs/reference/rest", "https://hackingthe.cloud/gcp/"]
license: CC BY-SA 4.0
---

## Summary

Google Cloud Functions is a serverless, event-driven compute platform that runs single-purpose handlers in response to HTTP requests, Pub/Sub messages, Cloud Storage object changes, Firestore events, and other triggers. It exists in two generations: 1st gen, the original product built on a Google-managed infrastructure layer, and 2nd gen, which is built directly on Cloud Run and Eventarc and is increasingly the default. Because a 2nd gen function is also a Cloud Run service under the hood, enumeration of Cloud Functions overlaps heavily with [Cloud Run enumeration](./gcp-cloud-run-enum.md).

From a testing perspective, Cloud Functions are high-value targets for three reasons: each function executes with an attached service account whose identity and token are reachable from inside the runtime; function source code frequently contains hardcoded secrets, connection strings, and internal endpoints; and HTTP-triggered functions are often exposed to `allUsers` (unauthenticated) either intentionally or by accident. The objective of this enumeration phase is to inventory every function in scope, recover its runtime configuration, identity, trigger surface, IAM bindings, environment variables, and source code, so that misconfigurations and privilege-escalation paths can be assessed.

## Prerequisites

Enumeration assumes read-only credentials with visibility into the Cloud Functions and (for 2nd gen) Cloud Run APIs. The most useful permissions are:

- `cloudfunctions.functions.list` and `cloudfunctions.functions.get` — list functions and read their full configuration.
- `cloudfunctions.functions.getIamPolicy` — read the per-function invoker IAM policy (who can call it).
- `cloudfunctions.functions.sourceCodeGet` — obtain a signed URL to download the deployed source archive.
- `run.services.list`, `run.services.get`, `run.services.getIamPolicy` — equivalents for 2nd gen functions surfaced as Cloud Run services.
- `iam.serviceAccounts.list` and `iam.serviceAccounts.get` — map function identities to service accounts.

The `roles/cloudfunctions.viewer`, `roles/run.viewer`, and `roles/iam.securityReviewer` predefined roles together cover almost all read paths. Many environments grant `roles/viewer` (basic Viewer) broadly, which also includes function metadata read access. Enumeration should be performed against every project the principal can see; use `gcloud projects list` and `gcloud resource-manager folders list` to establish the project inventory first.

## Enumeration

### Establish identity and project scope

```bash
gcloud auth list
gcloud config get-value project
gcloud projects list --format="value(projectId)"
```

### List functions (both generations)

```bash
# All functions across all regions, both generations (gcloud >= 2nd gen aware)
gcloud functions list --project "$PROJECT" --format=json

# Force a generation if needed
gcloud functions list --project "$PROJECT" --gen2 --format=json
gcloud functions list --project "$PROJECT" --no-gen2 --format=json
```

Raw REST equivalents (useful when the CLI is unavailable or to confirm the API surface directly):

```bash
TOKEN=$(gcloud auth print-access-token)

# 1st gen + 2nd gen via the v2 API (use '-' as location to list all regions)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudfunctions.googleapis.com/v2/projects/$PROJECT/locations/-/functions"

# Legacy v1 API (1st gen only)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudfunctions.googleapis.com/v1/projects/$PROJECT/locations/-/functions"
```

### Read full configuration of a function

```bash
gcloud functions describe "$FN" --region "$REGION" --project "$PROJECT" --format=json
```

Pay attention to these fields in the returned object:

- `serviceConfig.serviceAccountEmail` (v2) / `serviceAccountEmail` (v1) — the runtime identity. This is the credential an attacker inherits on code execution.
- `serviceConfig.environmentVariables` and `buildConfig.environmentVariables` — plaintext environment variables, a common secret-leak location.
- `serviceConfig.secretEnvironmentVariables` / `secretVolumes` — references into Secret Manager (the values are not returned, but the secret names and the fact the function can read them are).
- `serviceConfig.ingressSettings` — `ALLOW_ALL`, `ALLOW_INTERNAL_ONLY`, or `ALLOW_INTERNAL_AND_GCLB`.
- `serviceConfig.vpcConnector` / `vpcConnectorEgressSettings` — network reachability into a VPC.
- `eventTrigger` vs `httpsTrigger` / `url` — the trigger type and, for HTTP, the invocation URL.
- `buildConfig.source` — the Cloud Storage or Source Repository location of the deployed source.

### Determine who can invoke a function (IAM)

For HTTP-triggered functions, invocation is controlled by the `cloudfunctions.invoker` (1st gen) or `run.invoker` (2nd gen / Cloud Run) permission. Read the policy:

```bash
# 1st gen
gcloud functions get-iam-policy "$FN" --region "$REGION" --project "$PROJECT" --format=json

# 2nd gen — read the underlying Cloud Run service policy too
gcloud run services get-iam-policy "$FN" --region "$REGION" --project "$PROJECT" --format=json
```

A binding granting `roles/cloudfunctions.invoker` or `roles/run.invoker` to `allUsers` means the function is callable by anyone on the internet; `allAuthenticatedUsers` means any Google account.

### Retrieve source code

The deployed source archive can be downloaded via a short-lived signed URL:

```bash
# v1
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudfunctions.googleapis.com/v1/projects/$PROJECT/locations/$REGION/functions/$FN:generateDownloadUrl" \
  -X POST -d '{}' -H "Content-Type: application/json"
```

For 2nd gen functions, the `buildConfig.source.storageSource` object names a Cloud Storage bucket and object holding the source zip; if the calling principal has `storage.objects.get` on that bucket, the archive can be pulled directly:

```bash
gsutil cp "gs://$SOURCE_BUCKET/$SOURCE_OBJECT" ./source.zip
unzip -o source.zip -d ./source && grep -RniE "password|secret|api[_-]?key|token|bearer|conn" ./source
```

### Map identities

```bash
# Inventory service accounts so function identities can be resolved
gcloud iam service-accounts list --project "$PROJECT" --format="table(email,disabled)"
```

Correlate each function's `serviceAccountEmail` against this list. A function running as the **default compute service account** (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`), which historically holds the broad `roles/editor`, is a strong lead for later phases.

## Misconfigurations & Findings

- **Unauthenticated invocation (`allUsers`/`allAuthenticatedUsers` invoker).** The single most common finding. An HTTP function exposed to `allUsers` is an internet-facing endpoint executing with a privileged service account; reachability plus any code weakness becomes a direct path to that identity.
- **Over-privileged runtime service account.** Functions running as the default compute service account or as a custom account with `roles/editor`, `roles/owner`, or token-creation rights provide a large blast radius on execution.
- **Secrets in environment variables or source.** Plaintext `environmentVariables` and credentials committed into the source archive are readable by anyone with describe/source access and are exfiltratable from inside the runtime.
- **Permissive ingress.** `ingressSettings: ALLOW_ALL` on a function intended to be internal exposes it beyond the VPC.
- **Public source bucket.** The Cloud Storage bucket holding the source zip being world-readable leaks the full application code without any Cloud Functions permission.
- **VPC connector reachability.** A function with a VPC connector can reach internal databases, metadata endpoints, and private services; combined with code execution this becomes a network pivot.
- **Stale / forgotten functions.** Old functions left deployed often run outdated dependencies and over-broad identities while no longer being monitored.

## Exploitation

Enumeration itself is read-only, but its output directly seeds exploitation. The decision tree:

1. If an HTTP function is bound to `allUsers`/`allAuthenticatedUsers`, note the `url` and test it (see [privilege escalation](../03-privilege-escalation/gcp-cloud-functions-privesc.md)).
2. If the runtime service account is privileged, the function becomes a target for code injection or deployment-based takeover.
3. If source or env vars contain credentials, harvest them for lateral movement.

A quick triage one-liner to flag publicly invocable functions:

```bash
for fn in $(gcloud functions list --project "$PROJECT" --format="value(name)"); do
  region=$(gcloud functions describe "$fn" --project "$PROJECT" --format="value(region)" 2>/dev/null)
  pol=$(gcloud functions get-iam-policy "$fn" --region "$region" --project "$PROJECT" --format=json 2>/dev/null)
  echo "$pol" | grep -q "allUsers\|allAuthenticatedUsers" && echo "PUBLIC: $fn ($region)"
done
```

## Detection & Logging

All enumeration activity is recorded in **Cloud Audit Logs** as Admin Activity and Data Access entries (the latter must be explicitly enabled for Data Access logs on the Cloud Functions and Cloud Run services).

- `cloudfunctions.googleapis.com/data_access` and `...ListFunctions`, `GetFunction`, `GetIamPolicy`, `GenerateDownloadUrl` method names appear in the `protoPayload.methodName` field.
- 2nd gen reads surface under `run.googleapis.com` with `ListServices`, `GetService`, `GetIamPolicy`.
- Source downloads via `generateDownloadUrl` and subsequent `storage.objects.get` on the source bucket are visible in Storage Data Access logs.
- The `protoPayload.authenticationInfo.principalEmail` field identifies the enumerating principal; `requestMetadata.callerIp` gives source IP.

Defenders should alert on broad `ListFunctions`/`GetIamPolicy` sweeps from a single principal across many regions in a short window, and on any `GenerateDownloadUrl` calls outside of CI/CD identities.

## Remediation & Hardening

- Enable Data Access audit logs for `cloudfunctions.googleapis.com` and `run.googleapis.com` so reads are visible.
- Restrict who holds `cloudfunctions.viewer`, `run.viewer`, and `iam.securityReviewer`; treat `sourceCodeGet` as sensitive.
- Apply an organization policy (`constraints/iam.allowedPolicyMemberDomains`) and the Domain Restricted Sharing constraint to block `allUsers`/`allAuthenticatedUsers` bindings outright.
- Set `ingressSettings` to `ALLOW_INTERNAL_ONLY` or `ALLOW_INTERNAL_AND_GCLB` unless public access is required.
- Keep source buckets private and lifecycle-expire old source archives.

## Tools

- `gcloud functions` / `gcloud run` — first-party enumeration of both generations.
- `gsutil` — pulling source archives from Cloud Storage.
- `curl` — direct REST access to the v1/v2 APIs for confirmation and scripting.
- ScoutSuite and similar multi-cloud auditors — automated detection of public invokers and over-privileged identities.
- General GCP enumeration toolkits — bulk inventory across projects and regions.

## References

- Cloud Functions REST API reference — https://cloud.google.com/functions/docs/reference/rest
- Managing access with IAM (Cloud Functions) — https://cloud.google.com/functions/docs/securing/managing-access-iam
- 1st gen vs 2nd gen comparison — https://cloud.google.com/functions/docs/concepts/version-comparison
- Cloud Run REST API reference — https://cloud.google.com/run/docs/reference/rest
- hackingthe.cloud GCP techniques — https://hackingthe.cloud/gcp/
