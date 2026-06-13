---
cstg_id: CSTG-GCP-APP-ENGINE-ENUM
title: "GCP App Engine - Enumeration"
provider: gcp
service: app-engine
phase: services
required_access: read-only-audit
required_permissions:
  - appengine.applications.get
  - appengine.services.list
  - appengine.versions.list
  - appengine.versions.get
  - appengine.instances.list
  - appengine.operations.list
  - iam.serviceAccounts.list
  - iam.serviceAccounts.getIamPolicy
  - resourcemanager.projects.getIamPolicy
tools:
  - Provider CLI (gcloud)
  - Provider REST API client (Admin API)
  - Cloud asset inventory client
  - Generic HTTP client
references:
  - https://cloud.google.com/appengine/docs/admin-api
  - https://cloud.google.com/appengine/docs/standard/reference/app-yaml
  - https://cloud.google.com/appengine/docs/legacy/standard/python/appidentity
  - https://cloud.google.com/iam/docs/service-account-overview
  - https://cloud.google.com/sdk/gcloud/reference/app
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

Google App Engine (GAE) is a fully managed Platform-as-a-Service for deploying web
applications and APIs. It exists in two execution environments - the **standard
environment** (sandboxed runtimes such as Python, Java, Go, Node.js, PHP, Ruby) and the
**flexible environment** (application code packaged into Docker containers running on
managed Compute Engine VMs). A project may contain at most one App Engine *application*,
which is partitioned into one or more *services* (formerly "modules"), each of which has
one or more deployed *versions*, each of which runs on one or more *instances*.

From a security-testing perspective App Engine is interesting for three reasons:

1. **A default service account with broad rights.** Every App Engine application is
   associated with a service account, conventionally `PROJECT_ID@appspot.gserviceaccount.com`.
   By default this identity is granted the legacy **Editor** role on the project, making
   it one of the most powerful identities in the project. Any code running on App Engine
   - including code an attacker can deploy or influence - executes as this identity unless
   a per-version service account override is configured.
2. **Source and configuration disclosure.** Deployment artifacts, `app.yaml`/`appengine-web.xml`
   configuration, environment variables, and (for standard runtimes) application source can
   often be retrieved through the Admin API, the source-code download endpoint, or the
   deployment bucket in Cloud Storage. These frequently contain secrets.
3. **A public attack surface.** Each version is reachable over HTTPS at predictable
   `*.appspot.com` and `*.<region>.r.appspot.com` hostnames, and traffic-split / version
   routing can expose pre-production or forgotten versions.

This page covers passive and active **enumeration** of App Engine. Turning the
discovered access into elevated privilege is covered in
[GCP App Engine - Privilege Escalation](../03-privilege-escalation/gcp-app-engine-privesc.md).

## Prerequisites

- A principal able to read App Engine resources in the target project. The minimum useful
  permission set is the **App Engine Viewer** role (`roles/appengine.appViewer`) or the
  individual `appengine.*.get`/`appengine.*.list` permissions, plus
  `resourcemanager.projects.getIamPolicy` and `iam.serviceAccounts.list` to map the
  associated identities.
- For unauthenticated surface mapping (public endpoints, version hostnames), no project
  permissions are required - only network reachability to the public `appspot.com`
  domains.
- The provider CLI and/or a REST client capable of calling the App Engine Admin API
  (`appengine.googleapis.com`).

The App Engine Admin API must be enabled on the project for most administrative reads to
succeed; if it is disabled, only the runtime HTTP surface and the Cloud Storage
deployment bucket are observable.

## Enumeration

### Confirm the application exists and read its top-level configuration

```bash
# Top-level application object: location, default hostname, default service account,
# default bucket, IAP/SSL settings, dispatch rules.
gcloud app describe --project "$PROJECT_ID"

# Raw Admin API equivalent
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://appengine.googleapis.com/v1/apps/${PROJECT_ID}"
```

Key fields to capture from the application object:

- `defaultHostname` - the canonical `*.appspot.com` host.
- `serviceAccount` - the **application-level** service account. If absent, the default
  `PROJECT_ID@appspot.gserviceaccount.com` is in use. This is the identity to investigate
  for privilege escalation.
- `defaultBucket` / `codeBucket` - the Cloud Storage buckets holding staged code and
  default object storage (`staging.PROJECT_ID.appspot.com`, `PROJECT_ID.appspot.com`).
- `locationId` - the region; App Engine location is immutable once set.
- `iap` - whether Identity-Aware Proxy is enabled, and the OAuth2 client configuration.

### Enumerate services, versions, and instances

```bash
# Services (modules)
gcloud app services list --project "$PROJECT_ID"

# Versions for each service, including traffic split and serving status
gcloud app versions list --project "$PROJECT_ID"

# Detailed version object - contains env vars, entrypoint, runtime, scaling,
# inbound services, VPC connector, and the per-version service account override
gcloud app versions describe "$VERSION_ID" \
  --service "$SERVICE_ID" --project "$PROJECT_ID"

# Running instances (flexible env exposes VM names usable for SSH pivoting)
gcloud app instances list --service "$SERVICE_ID" --project "$PROJECT_ID"
```

Raw API traversal:

```bash
BASE="https://appengine.googleapis.com/v1/apps/${PROJECT_ID}"
TOK="$(gcloud auth print-access-token)"

curl -s -H "Authorization: Bearer $TOK" "$BASE/services"
curl -s -H "Authorization: Bearer $TOK" "$BASE/services/${SERVICE_ID}/versions?view=FULL"
curl -s -H "Authorization: Bearer $TOK" "$BASE/services/${SERVICE_ID}/versions/${VERSION_ID}/instances"
```

The `view=FULL` parameter is important: the default `BASIC` view omits the environment
variables, handlers, and service-account fields. Always request `FULL` when hunting for
secrets and identity overrides.

### Extract environment variables and per-version configuration

The version object frequently embeds plaintext configuration:

- `envVariables` - key/value pairs set in `app.yaml` `env_variables:` or
  `appengine-web.xml`. Commonly holds database passwords, API keys, third-party tokens,
  and signing secrets.
- `betaSettings` / `vpcAccessConnector` - VPC connector reveals which internal networks
  the app can reach (useful for understanding lateral-movement potential).
- `serviceAccount` - per-version identity override. If this differs from the application
  default, each version may run as a *different* identity with different blast radius.
- `entrypoint` / `runtime` - reveals the language and start command.
- `inboundServices` (e.g. `INBOUND_SERVICE_WARMUP`, mail, task-queue) - additional
  internal entry points.

```bash
gcloud app versions describe "$VERSION_ID" --service "$SERVICE_ID" \
  --project "$PROJECT_ID" --format='yaml(envVariables, serviceAccount, vpcAccessConnector, runtime, entrypoint)'
```

### Identify the associated service accounts and their privileges

```bash
# List service accounts; the App Engine default is PROJECT_ID@appspot.gserviceaccount.com
gcloud iam service-accounts list --project "$PROJECT_ID"

# Project IAM policy - find every binding that includes the appspot SA or any
# per-version override SA
gcloud projects get-iam-policy "$PROJECT_ID" --format=json \
  | jq '.bindings[] | select(.members[] | test("appspot.gserviceaccount.com"))'

# Roles the App Engine identity itself can grant or impersonate (key privesc signal)
gcloud iam service-accounts get-iam-policy \
  "${PROJECT_ID}@appspot.gserviceaccount.com" --project "$PROJECT_ID"
```

A default-Editor `appspot` service account combined with any ability to deploy or modify a
version is a direct privilege-escalation path - see the privesc page.

### Retrieve staged source and deployment artifacts from Cloud Storage

Deployed code is staged in project-owned buckets. With Storage read access these can be
downloaded and inspected for hardcoded secrets, internal hostnames, and additional
credentials:

```bash
gsutil ls "gs://staging.${PROJECT_ID}.appspot.com/"
gsutil ls "gs://${PROJECT_ID}.appspot.com/"
gsutil -m cp -r "gs://staging.${PROJECT_ID}.appspot.com/" ./gae-staging/
```

For legacy standard-environment applications, source can sometimes be retrieved through the
source download tooling if the deployer enabled source upload, and via the
`apps.services.versions` resource which references the staged files.

### Map the public HTTP surface (works without project access)

App Engine hostnames are predictable, enabling discovery and version targeting from the
outside:

```
https://PROJECT_ID.REGION_ID.r.appspot.com           # default service, region-qualified
https://PROJECT_ID.appspot.com                        # default service, legacy host
https://SERVICE-dot-PROJECT_ID.REGION_ID.r.appspot.com
https://VERSION-dot-SERVICE-dot-PROJECT_ID.REGION_ID.r.appspot.com   # explicit version
```

The `VERSION-dot-SERVICE-dot-PROJECT` pattern lets a tester reach a *specific* version
directly, bypassing traffic splitting. This routinely exposes:

- Old versions that still serve traffic but were forgotten and never patched.
- Staging/debug versions deployed alongside production.
- Versions with different (weaker) IAP or authentication configuration.

```bash
# Probe an explicit version that is not receiving split traffic
curl -sI "https://${VERSION_ID}-dot-${SERVICE_ID}-dot-${PROJECT_ID}.${REGION_ID}.r.appspot.com/"

# Enumerate dispatch routing and any default redirects
gcloud app describe --format='value(dispatchRules)' --project "$PROJECT_ID"
```

Also test for the App Engine metadata/identity endpoints from inside a running instance
(if code execution is later obtained): the standard environment exposes an App Identity
service and, in flexible, the standard Compute Engine metadata server
(`http://metadata.google.internal/computeMetadata/v1/`) yields tokens for the running
service account.

### Cloud Asset Inventory cross-check

Where `cloudasset.assets.searchAllResources` is available, App Engine resources can be
inventoried project- or org-wide without enabling the Admin API on each project:

```bash
gcloud asset search-all-resources \
  --scope="projects/${PROJECT_ID}" \
  --asset-types="appengine.googleapis.com/Application,appengine.googleapis.com/Service,appengine.googleapis.com/Version"
```

## Misconfigurations & Findings

- **Default Editor on the appspot service account.** The application runs as
  `PROJECT_ID@appspot.gserviceaccount.com`, which by default holds `roles/editor`. Any
  deploy or version mutation primitive becomes project-wide Editor execution.
- **Secrets in `envVariables`.** Database credentials, API keys, and signing secrets stored
  in plaintext environment variables, readable to anyone with `appengine.versions.get`
  (FULL view).
- **No per-version service account override.** All services/versions share the
  over-privileged default identity instead of a least-privilege per-service account.
- **Forgotten/over-served versions.** Old versions still in `SERVING` status, reachable via
  `VERSION-dot-...` hostnames, containing unpatched code or weaker auth.
- **Missing IAP / app-level authentication.** Internal or admin services exposed publicly on
  `appspot.com` with no Identity-Aware Proxy or application-layer auth.
- **World-readable deployment buckets.** `staging.PROJECT_ID.appspot.com` /
  `PROJECT_ID.appspot.com` buckets with permissive IAM exposing source and artifacts.
- **Overly broad VPC connector.** A version attached to a VPC connector that grants reach
  into sensitive internal subnets, expanding lateral-movement options.
- **`login: admin` handlers relying on legacy users API.** Handlers protected only by the
  legacy `login: admin` directive, which may behave unexpectedly behind IAP or with
  service-to-service calls.

## Detection & Logging

App Engine administrative and access activity is recorded in **Cloud Audit Logs**:

- **Admin Activity logs** (always on, non-disableable) record writes:
  `google.appengine.v1.Versions.CreateVersion`, `UpdateVersion`, `DeleteVersion`,
  `google.appengine.v1.Services.UpdateService` (traffic splits),
  `google.appengine.v1.Applications.UpdateApplication`,
  `google.appengine.v1.Instances.DeleteInstance`.
- **Data Access logs** (must be explicitly enabled for App Engine) record reads such as
  `GetApplication`, `ListServices`, `ListVersions`, and `GetVersion`. Enumeration of
  configuration and environment variables is only visible if Data Access logging is turned
  on - defenders should enable `DATA_READ`/`ADMIN_READ` on `appengine.googleapis.com`.
- **Request logs** capture inbound HTTP requests per version, useful for spotting probing of
  explicit `VERSION-dot-...` hostnames.

Useful queries (Logs Explorer / `gcloud logging read`):

```bash
# Version creation / mutation (potential deploy-based privesc)
gcloud logging read \
  'protoPayload.serviceName="appengine.googleapis.com"
   AND protoPayload.methodName=("google.appengine.v1.Versions.CreateVersion"
                               OR "google.appengine.v1.Versions.UpdateVersion")' \
  --project "$PROJECT_ID" --freshness=7d

# Traffic-split changes (re-routing to attacker-controlled version)
gcloud logging read \
  'protoPayload.methodName="google.appengine.v1.Services.UpdateService"' \
  --project "$PROJECT_ID" --freshness=7d
```

Detection signals worth alerting on: version creation by an identity that does not normally
deploy; a new version whose `serviceAccount` is the default appspot SA when policy requires
overrides; traffic shifted to a freshly created version; and reads of version FULL views by
unexpected principals.

## Remediation & Hardening

- **Replace the default appspot identity privileges.** Do not leave `roles/editor` bound to
  `PROJECT_ID@appspot.gserviceaccount.com`. Assign a dedicated, least-privilege service
  account per service via the per-version `serviceAccount` field and grant only the roles
  the workload needs.
- **Never store secrets in environment variables.** Use a secrets manager and fetch at
  runtime; keep `app.yaml`/`appengine-web.xml` free of credentials.
- **Restrict who can deploy.** Limit `roles/appengine.deployer`,
  `roles/appengine.serviceAdmin`, and `roles/cloudbuild.builds.editor`. Treat deploy rights
  as equivalent to "run code as the App Engine identity".
- **Enable Data Access audit logging** for `appengine.googleapis.com` so configuration and
  environment reads are recorded.
- **Front internal/admin services with IAP** and remove reliance on the legacy
  `login: admin` directive for sensitive endpoints.
- **Prune old versions** and stop/delete non-serving versions to shrink the public attack
  surface and remove unpatched code reachable via explicit version hostnames.
- **Lock down deployment buckets.** Ensure `staging.PROJECT_ID.appspot.com` and
  `PROJECT_ID.appspot.com` use uniform bucket-level access with least-privilege IAM.
- **Scope VPC connectors** to the minimum required subnets and firewall internal reachability.

## Tools

- Provider CLI (`gcloud app`, `gcloud iam`, `gsutil`) for application, service, version,
  instance, and identity enumeration.
- Provider REST API client against the App Engine Admin API
  (`appengine.googleapis.com/v1`) for `view=FULL` configuration retrieval.
- Cloud Asset Inventory client for cross-project resource discovery.
- Generic HTTP client for unauthenticated public-surface and explicit-version probing on
  `*.appspot.com` / `*.r.appspot.com`.

## References

- App Engine Admin API: https://cloud.google.com/appengine/docs/admin-api
- `app.yaml` reference (env variables, handlers, login directives): https://cloud.google.com/appengine/docs/standard/reference/app-yaml
- App Identity service: https://cloud.google.com/appengine/docs/legacy/standard/python/appidentity
- Service account overview: https://cloud.google.com/iam/docs/service-account-overview
- `gcloud app` command reference: https://cloud.google.com/sdk/gcloud/reference/app
- Hacking the Cloud - GCP: https://hackingthe.cloud/gcp/
