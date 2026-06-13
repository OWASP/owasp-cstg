---
cstg_id: CSTG-GCP-CLOUD-STORAGE-ENUM
title: "GCP Cloud Storage - Enumeration"
provider: gcp
service: cloud-storage
phase: services
required_access: read-only-audit
required_permissions:
  - storage.buckets.list
  - storage.buckets.get
  - storage.buckets.getIamPolicy
  - storage.objects.list
  - storage.objects.get
  - storage.objects.getIamPolicy
  - resourcemanager.projects.get
tools: ["gcloud storage", "gsutil", "GCP JSON API", "ScoutSuite", "Prowler", "PMapper"]
references:
  - "https://cloud.google.com/storage/docs/listing-buckets"
  - "https://cloud.google.com/storage/docs/listing-objects"
  - "https://cloud.google.com/storage/docs/access-control/iam-roles"
  - "https://cloud.google.com/storage/docs/access-control/iam-permissions"
  - "https://cloud.google.com/storage/docs/uniform-bucket-level-access"
  - "https://cloud.google.com/storage/docs/public-access-prevention"
  - "https://cloud.google.com/storage/docs/object-versioning"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated enumeration of Cloud Storage from a read-only
("audit") vantage point: an identity that holds viewer-level permissions across
one or more projects. The objective is to build a complete inventory of buckets
and their security posture - access-control mode, public exposure, IAM bindings,
encryption, retention/versioning, and the sensitivity of stored objects - so
that exploitable misconfigurations and privilege-escalation paths can be
identified.

Enumeration is the foundation for the
[Privilege Escalation](../03-privilege-escalation/gcp-cloud-storage-privesc.md)
and [Post-Exploitation](../05-post-exploitation/gcp-cloud-storage-post-exploitation.md)
phases: knowing which buckets exist, who can read/write them, and what they
contain determines every subsequent attack path.

## Prerequisites

- A valid Google identity (user account or service account) with at least
  read/viewer permissions on the target project(s). Minimal useful set:
  `storage.buckets.list`, `storage.buckets.get`, `storage.objects.list`,
  `storage.objects.get`, plus the `*.getIamPolicy` variants to read access
  control. `roles/storage.objectViewer` + `roles/storage.legacyBucketReader`,
  or simply `roles/viewer`, satisfies most enumeration.
- The target project ID(s). `resourcemanager.projects.get` /
  `resourcemanager.projects.list` help discover them.
- A configured `gcloud` / `gsutil` environment, or a token for direct JSON API
  calls.

## Enumeration

### Establish identity and project scope

```bash
# Who am I and what is active?
gcloud auth list
gcloud config get-value project
gcloud auth print-access-token            # raw OAuth token for API calls

# What projects can this identity see?
gcloud projects list
gcloud resource-manager org-policies list --project=<PROJECT_ID>
```

### List buckets

```bash
# All buckets in a project
gcloud storage buckets list --project=<PROJECT_ID>
gsutil ls -p <PROJECT_ID>

# JSON API
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://storage.googleapis.com/storage/v1/b?project=<PROJECT_ID>"
```

### Describe bucket configuration and posture

```bash
# Full metadata: location, storage class, access mode, retention, versioning
gcloud storage buckets describe gs://<BUCKET> --format=json
gsutil ls -L -b gs://<BUCKET>

# Is Uniform Bucket-Level Access on? (off => object ACLs in play)
gcloud storage buckets describe gs://<BUCKET> \
  --format="value(uniform_bucket_level_access)"

# Public Access Prevention state
gcloud storage buckets describe gs://<BUCKET> \
  --format="value(public_access_prevention)"
```

Key fields to capture for each bucket: `location`, `storageClass`,
`iamConfiguration.uniformBucketLevelAccess.enabled`,
`iamConfiguration.publicAccessPrevention`, `versioning.enabled`,
`retentionPolicy`, `encryption.defaultKmsKeyName`, `logging`, and
`softDeletePolicy`.

### Read access-control bindings

```bash
# Bucket-level IAM policy - look for allUsers / allAuthenticatedUsers
gcloud storage buckets get-iam-policy gs://<BUCKET> --format=json
gsutil iam get gs://<BUCKET>

# Object-level ACLs (only relevant when uniform access is OFF)
gsutil acl get gs://<BUCKET>/<OBJECT>
gsutil defacl get gs://<BUCKET>     # default ACL applied to new objects
```

### List and triage objects

```bash
# Recursive object listing with sizes and timestamps
gcloud storage ls -r gs://<BUCKET>/**
gsutil ls -r gs://<BUCKET>/**

# Long listing (size, time, storage class, generation)
gsutil ls -l gs://<BUCKET>/**

# Include non-current versions (object versioning)
gsutil ls -a gs://<BUCKET>/**
```

Triage object keys for high-value content:

```
*.sql *.dump *.bak           database backups
*.tfstate *.tfstate.backup   Terraform state (often contains secrets)
.env *.env *.ini *.cfg       configuration / credentials
*.pem *.key *.p12 *.json     keys / service-account credentials
.git/ .svn/                  source-control metadata
*.log                        logs that may leak tokens
id_rsa* *.ppk                SSH keys
backup* dump* export*        bulk data exports
```

### Map cross-project and identity reach

```bash
# What roles does my identity hold on this project?
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)" \
  --format="table(bindings.role)"

# Buckets reachable across multiple projects (loop)
for p in $(gcloud projects list --format="value(projectId)"); do
  echo "== $p =="; gcloud storage buckets list --project="$p" 2>/dev/null
done
```

## Misconfigurations & Findings

- **Public exposure:** any bucket IAM binding or object ACL referencing
  `allUsers` / `allAuthenticatedUsers` (cross-reference
  [Unauthenticated Access](../01-unauthenticated-external/gcp-cloud-storage-unauthenticated.md)).
- **Fine-grained access still enabled:** Uniform Bucket-Level Access OFF means
  per-object ACLs exist and must be audited individually - a common hiding place
  for stray public grants.
- **Public Access Prevention not enforced:** `inherited` rather than `enforced`
  leaves the bucket one binding away from being public.
- **Overly broad principals:** `roles/storage.admin` or
  `roles/storage.objectAdmin` bound to broad groups, `roles/editor`/`owner`
  primitive roles, or domain-wide (`domain:example.com`) bindings.
- **Versioning + no lifecycle:** old generations persist and may hold secrets
  removed from the live object; readable by anyone with `storage.objects.get`
  and a generation number.
- **No default CMEK / no encryption policy:** buckets using Google-managed keys
  only, where org policy requires CMEK.
- **Logging disabled:** no access/usage logs and Data Access audit logging off,
  reducing detectability of exfiltration.
- **Sensitive data classes** identified in object triage (PII, backups,
  credentials, source).

### Programmatic posture scan

```bash
# ScoutSuite - multi-service posture incl. GCS public/IAM findings
scout gcp --user-account --report-dir ./scout

# Prowler for GCP - storage checks
prowler gcp --project-ids <PROJECT_ID> --service gcs
```

## Detection & Logging

- **Cloud Audit Logs - Admin Activity** (always on) records bucket
  create/update/delete and `SetIamPolicy`. Read-only enumeration of
  configuration (`storage.buckets.get`, `getIamPolicy`) is logged in
  **Data Access** logs **only when Data Access logging is enabled**.
- **Object reads** (`storage.objects.get`, `storage.objects.list`) are Data
  Access events; mass listing/triage produces a recognizable burst of
  `storage.objects.list` calls from one principal - detectable if Data Access
  logging is enabled.
- **`gcloud auth print-access-token` usage** is not itself logged, but the
  resulting API calls carry the caller identity in
  `protoPayload.authenticationInfo.principalEmail`.
- **Security Command Center / Event Threat Detection** can surface anomalous
  data-access volumes and public-resource findings.
- Enumeration tooling (ScoutSuite/Prowler) generates large volumes of
  `*.get`/`*.list` calls in a short window - a useful detection signal.

## Remediation & Hardening

- Enable **Data Access audit logging** for `storage.googleapis.com` (DATA_READ
  and DATA_WRITE) so enumeration and exfiltration are visible.
- Enforce **Uniform Bucket-Level Access** and **Public Access Prevention**
  (`enforced`) org-wide via org policy constraints.
- Apply **least privilege**: prefer `roles/storage.objectViewer` scoped to
  specific buckets over project-wide `roles/viewer`; avoid primitive
  `editor`/`owner`.
- Use **VPC Service Controls** perimeters to constrain which networks/identities
  can read storage, blocking blanket enumeration from outside the perimeter.
- Set **lifecycle rules** to expire non-current object versions and reduce the
  blast radius of versioned secrets.
- Regularly run posture tooling and alert on any new `allUsers` /
  `allAuthenticatedUsers` bindings.

## Tools

- **gcloud storage / gsutil** - native enumeration of buckets, objects, IAM,
  ACLs, and metadata.
- **GCP JSON API** - scriptable enumeration with a bearer token.
- **ScoutSuite** - cross-service posture assessment with GCS public/IAM checks.
- **Prowler** - check-based GCP auditing including storage controls.
- **PMapper** - models IAM relationships to find who can reach which buckets.

## References

- Listing buckets: https://cloud.google.com/storage/docs/listing-buckets
- Listing objects: https://cloud.google.com/storage/docs/listing-objects
- IAM roles for Cloud Storage: https://cloud.google.com/storage/docs/access-control/iam-roles
- IAM permissions: https://cloud.google.com/storage/docs/access-control/iam-permissions
- Uniform bucket-level access: https://cloud.google.com/storage/docs/uniform-bucket-level-access
- Public access prevention: https://cloud.google.com/storage/docs/public-access-prevention
- Object versioning: https://cloud.google.com/storage/docs/object-versioning
