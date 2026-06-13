---
cstg_id: CSTG-GCP-CLOUD-RUN-ENUM
title: "GCP Cloud Run - Enumeration"
provider: gcp
service: cloud-run
phase: services
required_access: read-only-audit
required_permissions:
  - run.services.list
  - run.services.get
  - run.services.getIamPolicy
  - run.revisions.list
  - run.revisions.get
  - run.jobs.list
  - run.jobs.get
  - run.executions.list
  - run.configurations.get
  - run.routes.get
  - artifactregistry.repositories.list
  - artifactregistry.dockerimages.list
  - cloudbuild.builds.list
  - resourcemanager.projects.getIamPolicy
tools:
  - gcloud CLI
  - Google Cloud REST API (run.googleapis.com)
  - curl / HTTP client
  - ScoutSuite
  - Prowler
references:
  - "https://cloud.google.com/run/docs/reference/rest"
  - "https://cloud.google.com/run/docs/securing/managing-access"
  - "https://cloud.google.com/run/docs/securing/service-identity"
  - "https://cloud.google.com/run/docs/authenticating/public"
  - "https://cloud.google.com/run/docs/configuring/services/environment-variables"
  - "https://cloud.google.com/run/docs/triggering/https-request"
  - "https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/"
license: CC BY-SA 4.0
---

## Summary

Cloud Run is Google Cloud's fully managed serverless container platform. It runs stateless containers exposed as HTTPS endpoints. The platform has two surfaces: the **Cloud Run Admin API** (`run.googleapis.com`), used to deploy, configure, and read services/jobs, and the **data plane** — the public or internal HTTPS URL where each service is served (`*.run.app` or a custom domain). Two resource kinds matter: **services** (long-running request-driven containers, exposed via a URL and managed as immutable **revisions** behind a **route**) and **jobs** (run-to-completion containers invoked as **executions**).

Cloud Run is a high-value enumeration target for several reasons. Each service runs as a **runtime service account** whose identity tokens are reachable from inside the container's metadata server, so any code-execution foothold inside a Cloud Run container inherits that service account's IAM permissions. Service **revisions expose their full deployment specification** — container image, environment variables (which frequently embed secrets), mounted secret references, ingress and authentication settings, VPC connectors, and the runtime service account — to any principal who can read the service. And the data-plane **invoker policy** (`run.routes.invoke` / `roles/run.invoker`) governs whether the endpoint is reachable by `allUsers` (public) or restricted, frequently misconfigured to public.

The objective of this phase is to catalogue, without changing state, every Cloud Run service and job in scope; resolve each one's runtime identity, image source, configuration, secrets exposure, ingress posture, and invoker bindings; and identify which endpoints are publicly invokable. This produces the inputs for both data-plane attacks (reaching exposed endpoints) and identity-based escalation (abusing the runtime service account), handed to the [Privilege Escalation](../03-privilege-escalation/gcp-cloud-run-privesc.md) phase.

## Prerequisites

This phase assumes a read-only audit identity scoped to one or more projects. Useful permissions include:

- `run.services.list` / `run.services.get` — list and describe Cloud Run services and their full revision spec.
- `run.services.getIamPolicy` — read the per-service invoker (allow) policy that decides who can call the endpoint.
- `run.revisions.list` / `run.revisions.get`, `run.configurations.get`, `run.routes.get` — read the immutable revision history, the configuration template, and the traffic-splitting route.
- `run.jobs.list` / `run.jobs.get`, `run.executions.list` — enumerate Cloud Run jobs and their executions.
- `artifactregistry.repositories.list`, `artifactregistry.dockerimages.list`, `cloudbuild.builds.list` — resolve and inspect the container images and build provenance referenced by services.
- `resourcemanager.projects.getIamPolicy` and `iam.serviceAccounts.getIamPolicy` — correlate which principals can deploy services or impersonate the runtime service accounts (see [Service Accounts Enumeration](gcp-service-accounts-enum.md)).

The predefined roles `roles/run.viewer`, `roles/viewer`, and `roles/iam.securityReviewer` grant most of the above. The data-plane reachability of a service can be assessed with **no GCP credentials at all** when the invoker policy includes `allUsers`; unauthenticated discovery is covered below and overlaps with the [unauthenticated external](../01-unauthenticated-external/) phase.

## Enumeration

### Identify the active identity and reachable projects

```bash
gcloud auth list
gcloud config list
gcloud projects list --format="table(projectId,projectNumber,name)"

# Confirm the Cloud Run API is enabled in the target project
gcloud services list --enabled --project="$PROJECT" \
  --filter="config.name:run.googleapis.com"
```

### List services and jobs across regions

Cloud Run is regional; services in different regions are listed independently. Enumerate all regions, not just the configured default.

```bash
PROJECT=target-project-id

# All services in all regions (managed platform)
gcloud run services list --project="$PROJECT" --platform=managed \
  --format="table(metadata.name, region, status.url, status.latestReadyRevisionName)"

# Per-region listing if the aggregate view is restricted
for R in us-central1 us-east1 europe-west1 asia-east1; do
  gcloud run services list --project="$PROJECT" --region="$R" \
    --format="value(metadata.name, status.url)"
done

# Cloud Run jobs and their executions
gcloud run jobs list --project="$PROJECT" --region="$R" \
  --format="table(metadata.name, status.latestCreatedExecution.name)"
gcloud run jobs executions list --job=JOB --region="$R" --project="$PROJECT"
```

### Describe a service: identity, image, env, ingress, secrets

The full service object is the richest single artifact in this phase. `describe` (or the REST `GET`) returns the container spec including environment variables and the runtime service account.

```bash
SVC=target-service
REGION=us-central1

gcloud run services describe "$SVC" --region="$REGION" --project="$PROJECT" \
  --format=yaml

# Targeted high-value fields
gcloud run services describe "$SVC" --region="$REGION" --project="$PROJECT" \
  --format="yaml(
    spec.template.spec.serviceAccountName,
    spec.template.spec.containers[].image,
    spec.template.spec.containers[].env,
    spec.template.metadata.annotations,
    metadata.annotations)"
```

Key fields to extract:

- `spec.template.spec.serviceAccountName` — the **runtime service account**. If empty, the service runs as the **Compute Engine default service account** (`PROJECTNUMBER-compute@developer.gserviceaccount.com`), historically `roles/editor`.
- `spec.template.spec.containers[].image` — the container image (Artifact Registry / GCR / external).
- `spec.template.spec.containers[].env` — inline environment variables; routinely contain API keys, database passwords, and tokens in plaintext.
- `spec.template.spec.containers[].env[].valueFrom.secretKeyRef` and `volumeMounts` — references to **Secret Manager** secrets mounted as env vars or files; reveals which secrets this identity can read.
- `metadata.annotations["run.googleapis.com/ingress"]` — `all`, `internal`, or `internal-and-cloud-load-balancing`.
- `spec.template.metadata.annotations["run.googleapis.com/vpc-access-connector"]` — VPC connector granting reachability into private networks.
- `run.googleapis.com/launch-stage`, `cloudsql-instances`, and `cpu-throttling` annotations — additional attack-surface hints (e.g. attached Cloud SQL instances).

### Read the raw REST API

```bash
TOKEN=$(gcloud auth print-access-token)

# Knative-style v1 API (services live under namespaces/<project>)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://$REGION-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/$PROJECT/services"

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://$REGION-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/$PROJECT/services/$SVC"

# Cloud Run Admin API v2 (services / jobs)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/services"
```

### Enumerate revisions and traffic split

```bash
# Revision history - older revisions may carry secrets/config removed from latest
gcloud run revisions list --service="$SVC" --region="$REGION" --project="$PROJECT" \
  --format="table(metadata.name, status.imageDigest, spec.serviceAccountName)"

gcloud run revisions describe REVISION --region="$REGION" --project="$PROJECT" \
  --format=yaml

# Traffic split across revisions (a tag URL may serve a non-default revision)
gcloud run services describe "$SVC" --region="$REGION" --project="$PROJECT" \
  --format="yaml(status.traffic)"
```

Revision-tagged URLs (`https://TAG---SVC-HASH-REGION.a.run.app`) can route to a specific revision regardless of the main traffic split — a way to reach old or staging code paths.

### Read the per-service invoker (data-plane) policy

```bash
# Who may invoke the endpoint? Look for allUsers / allAuthenticatedUsers
gcloud run services get-iam-policy "$SVC" --region="$REGION" --project="$PROJECT" \
  --format=json

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://$REGION-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/$PROJECT/services/$SVC?resource=$SVC" \
  -X POST # (use the getIamPolicy method for the v2 API)
```

A binding of `roles/run.invoker` to `allUsers` means the endpoint is fully public; `allAuthenticatedUsers` means any Google account (not just the org) can invoke it.

### Resolve the container image and build provenance

```bash
# What images back the services, and where do they come from?
gcloud artifacts repositories list --project="$PROJECT" \
  --format="table(name, format, mode)"
gcloud artifacts docker images list \
  "$REGION-docker.pkg.dev/$PROJECT/REPO" --include-tags

# Build history can reveal source repos, substitutions (sometimes secrets), and triggers
gcloud builds list --project="$PROJECT" --limit=20 \
  --format="table(id, status, source.repoSource.repoName, images)"
```

### Map who can deploy or impersonate

```bash
# Project policy: who can deploy/update services (run.developer/run.admin) and actAs SAs?
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.role|test("run\\.|iam.serviceAccountUser|editor|owner"))'

# Resource policy on the runtime SA: who can mint its tokens?
gcloud iam service-accounts get-iam-policy \
  RUNTIME_SA@"$PROJECT".iam.gserviceaccount.com --format=json
```

### Unauthenticated / external discovery

Cloud Run URLs follow predictable patterns (`https://SVC-HASH-REGION.a.run.app` or `https://SVC-PROJECTNUMBER.REGION.run.app`). With no credentials:

```bash
# Probe a known/guessed URL - 403 vs 200 distinguishes auth-required from public
curl -s -o /dev/null -w "%{http_code}\n" "https://$SVC-$HASH-uc.a.run.app/"

# A response served by Google front end with "Your client does not have permission"
# indicates the service exists but requires an Authorization bearer token.
```

Public Cloud Run services are also discoverable via passive sources (certificate transparency logs for `*.run.app`, search-engine indexing, and the target's own DNS/custom domains). See the [unauthenticated external](../01-unauthenticated-external/) phase.

## Misconfigurations & Findings

- **Publicly invokable services (`allUsers`).** `roles/run.invoker` bound to `allUsers` exposes the endpoint to the entire internet. If the container performs no in-app authentication, the application and any backend it can reach (Cloud SQL, internal APIs via VPC connector) are exposed.
- **Secrets in plaintext environment variables.** API keys, DB credentials, and tokens placed in `env` (rather than `secretKeyRef`) are readable by anyone with `run.services.get` and are written into deployment specs and audit logs.
- **Default Compute Engine service account as runtime identity.** Services with no explicit `serviceAccountName` run as the default SA with `roles/editor`; a single code-execution bug then yields project-editor-equivalent tokens.
- **Over-privileged runtime service accounts.** Runtime SAs holding `roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator`, `roles/secretmanager.secretAccessor` for many secrets, or `roles/resourcemanager.projectIamAdmin` make any SSRF/RCE in the container a full compromise.
- **Ingress set to `all` on internal services.** Services intended for internal traffic but left at ingress `all` are reachable from the internet.
- **Broad deploy permissions.** Wide assignment of `roles/run.developer`/`roles/run.admin` combined with `roles/iam.serviceAccountUser` on privileged SAs creates a deploy-to-escalate path (see Privilege Escalation).
- **Stale / tagged revisions** serving outdated code or carrying secrets removed from the latest revision but still describable.
- **VPC connector to a sensitive network** turning a public service into an internet-to-internal-network bridge, often combined with attached Cloud SQL instances.
- **External / untrusted container images** or images with no build provenance, indicating supply-chain risk.

## Exploitation

Enumeration is non-destructive but seeds two distinct attack tracks:

1. **Data-plane track.** For each service with `allUsers` (or guessable URL + weak in-app auth), record the URL, ingress, and any attached backends (VPC connector, Cloud SQL). These feed application-layer testing and SSRF probing — an SSRF in a public Cloud Run container can reach the metadata server at `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` and exfiltrate the runtime SA token.
2. **Identity track.** For each service, connect: runtime service account → its effective IAM roles → reachable resources/secrets. A service whose runtime SA is the default editor SA, or holds token-creator/secret-accessor, is a high-value escalation target. Also record principals who can `run.services.create`/`update` while holding `iam.serviceAccountUser` over a privileged SA — they can deploy a container that impersonates it.

Concretely, list every (service URL, ingress, invoker policy, runtime SA, runtime SA roles, mounted secrets) tuple and rank by runtime-SA privilege and public reachability. Hand the highest-value entries to [Cloud Run Privilege Escalation](../03-privilege-escalation/gcp-cloud-run-privesc.md).

## Detection & Logging

- **Cloud Audit Logs — Admin Activity** capture writes such as `google.cloud.run.v2.Services.CreateService`, `UpdateService`, `DeleteService`, `SetIamPolicy`, and job `RunJob`/`CreateExecution`. These are always on and are the primary signal for deploy-based attacks.
- **Read-only enumeration** (`GetService`, `ListServices`, `GetIamPolicy`, `ListRevisions`) is logged only when **Data Access audit logs** (`DATA_READ`) are explicitly enabled for the Cloud Run API. Without that, the discovery in this phase is largely invisible in audit logs.
- **Request logs and access logs** for each service record incoming HTTP requests (method, path, status, caller IP, and — for authenticated calls — the authenticated principal). High-volume probing or unexpected source IPs on an `internal`-intended service is visible here.
- Metadata-server token retrieval from inside a Cloud Run container is **not** recorded in Cloud Audit Logs; the *use* of the resulting token against other APIs is logged under those services, so correlate token issuance time with anomalous downstream API calls by the runtime SA.
- **Security Command Center** surfaces relevant posture findings such as public Cloud Run services and over-privileged or default runtime service accounts.

## Remediation & Hardening

- Require authentication on services: avoid binding `roles/run.invoker` to `allUsers`/`allAuthenticatedUsers`; front public services with IAP or Cloud Load Balancing + Cloud Armor where exposure is intended. Enforce the `iam.allowedPolicyMemberDomains` org policy to block public principals.
- Store secrets in **Secret Manager** and reference them via `secretKeyRef`/volume mounts with least-privilege `secretmanager.secretAccessor` scoped to specific secrets — never inline secrets in `env`.
- Assign each service a **dedicated least-privilege runtime service account**; never rely on the default Compute Engine SA. Disable automatic editor grants via `iam.automaticIamGrantsForDefaultServiceAccounts`.
- Set `ingress` to `internal` or `internal-and-cloud-load-balancing` for non-public services.
- Separate deploy permissions (`roles/run.developer`) from the ability to act as privileged service accounts; grant `iam.serviceAccountUser` only on the specific low-privilege runtime SA.
- Enable Data Access audit logs for the Cloud Run, IAM, and Secret Manager APIs so enumeration and secret access are observable.
- Use Binary Authorization and trusted Artifact Registry repositories to control which images can be deployed.

## Tools

- **gcloud CLI** — `gcloud run services/jobs/revisions`, `get-iam-policy`, `gcloud artifacts`, `gcloud builds`.
- **Google Cloud REST API** — `run.googleapis.com` (v2 Admin API and the Knative `serving.knative.dev/v1` surface).
- **curl / generic HTTP client** — data-plane probing of `*.run.app` endpoints and metadata-server access from a foothold.
- **ScoutSuite / Prowler** — posture scanners that flag public Cloud Run services, default/over-privileged runtime SAs, and plaintext-secret exposure.
- **IAM graphing utilities** — correlate runtime SAs with their effective roles and impersonation paths.

## References

- Cloud Run Admin API reference — https://cloud.google.com/run/docs/reference/rest
- Managing access / invoker permissions — https://cloud.google.com/run/docs/securing/managing-access
- Service identity (runtime service account) — https://cloud.google.com/run/docs/securing/service-identity
- Allowing public (unauthenticated) access — https://cloud.google.com/run/docs/authenticating/public
- Configuring environment variables and secrets — https://cloud.google.com/run/docs/configuring/services/environment-variables
- Triggering services with HTTPS requests — https://cloud.google.com/run/docs/triggering/https-request
- Default service accounts (hackingthe.cloud) — https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/
