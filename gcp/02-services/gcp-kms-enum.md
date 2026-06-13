---
cstg_id: CSTG-GCP-KMS-ENUM
title: "GCP Kms - Enumeration"
provider: gcp
service: kms
phase: services
required_access: read-only-audit
required_permissions:
  - cloudkms.keyRings.list
  - cloudkms.cryptoKeys.list
  - cloudkms.cryptoKeyVersions.list
  - cloudkms.keyRings.getIamPolicy
  - cloudkms.cryptoKeys.getIamPolicy
  - cloudkms.locations.list
  - resourcemanager.projects.get
tools:
  - gcloud CLI
  - Cloud KMS REST/RPC API
  - ScoutSuite
  - Prowler
references:
  - "https://cloud.google.com/kms/docs/reference/rest"
  - "https://cloud.google.com/kms/docs/resource-hierarchy"
  - "https://cloud.google.com/kms/docs/reference/permissions-and-roles"
  - "https://cloud.google.com/kms/docs/separation-of-duties"
  - "https://cloud.google.com/kms/docs/audit-logging"
license: CC BY-SA 4.0
---

## Summary

Google Cloud Key Management Service (Cloud KMS) is the managed cryptographic key store
used across a GCP organization to protect data at rest and to perform signing, MAC, and
asymmetric operations. Keys are organized into a four-level hierarchy
(project -> location -> key ring -> crypto key -> crypto key version) and are referenced by
nearly every other GCP service: customer-managed encryption keys (CMEK) for Cloud Storage,
BigQuery, Persistent Disk, Pub/Sub, Secret Manager, Spanner, and more.

The enumeration objective is to build a complete inventory of key rings, keys, key versions,
their protection level (software, `HSM`, `EXTERNAL`, `EXTERNAL_VPC`), purpose
(`ENCRYPT_DECRYPT`, `ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, `MAC`), rotation state, and -
most importantly - the IAM policy bound to each resource. Because KMS resources are the
control point for confidentiality across the environment, an over-permissive KMS IAM binding
(for example `roles/cloudkms.cryptoKeyEncrypterDecrypter` granted to a broad principal, or a
principal that can both administer keys and use them) collapses the separation of duties that
KMS is meant to enforce. Enumeration maps which principals can use, manage, or destroy each
key, and which services and resources depend on those keys, so that a tester or defender can
identify the highest-value cryptographic dependencies and the paths to abuse them.

## Prerequisites

- Read-only/audit access to the target project(s) with at least:
  - `cloudkms.keyRings.list`, `cloudkms.cryptoKeys.list`,
    `cloudkms.cryptoKeyVersions.list`, `cloudkms.importJobs.list` to list resources.
  - `cloudkms.cryptoKeys.get`, `cloudkms.keyRings.get`,
    `cloudkms.cryptoKeyVersions.get` to read configuration detail.
  - `cloudkms.keyRings.getIamPolicy` and `cloudkms.cryptoKeys.getIamPolicy` to read the
    resource-level IAM bindings (the most security-relevant data).
  - `cloudkms.locations.list` to discover the regions/locations a key ring may exist in
    (key rings are location-scoped and cannot be listed without the location).
- The predefined role `roles/cloudkms.viewer` grants the get/list permissions but does **not**
  grant `getIamPolicy`; `roles/cloudkms.admin` or a custom role is required to read KMS IAM
  policies. Project-level `roles/viewer` does not include KMS resource read by default.
- KMS data is regional. There is no single global list call; you must iterate every location.
  Enumerate locations first, then key rings per location.

## Enumeration

### Discover locations and projects

```bash
# Confirm the active project and identity
gcloud config get-value project
gcloud auth list

# List all KMS locations the API will accept
gcloud kms locations list --project "$PROJECT"
# Equivalent REST call
# GET https://cloudkms.googleapis.com/v1/projects/$PROJECT/locations
```

### List key rings, keys, and versions

```bash
PROJECT="target-project"

# For every location, list key rings
for LOC in $(gcloud kms locations list --project "$PROJECT" --format='value(locationId)'); do
  echo "== location: $LOC =="
  gcloud kms keyrings list --location "$LOC" --project "$PROJECT" \
    --format='value(name)'
done

# List crypto keys in a key ring (note purpose, protection level, rotation)
gcloud kms keys list \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --format='table(name, purpose, primary.state, versionTemplate.protectionLevel, rotationPeriod, nextRotationTime)'

# List versions for a specific key
gcloud kms keys versions list \
  --key "$KEY" --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --format='table(name, state, protectionLevel, algorithm, generateTime, destroyTime)'

# Inspect a single key in detail
gcloud kms keys describe "$KEY" \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT"
```

Raw REST equivalents (useful when only an access token is available, e.g. from a token leak):

```bash
TOKEN=$(gcloud auth print-access-token)
BASE="https://cloudkms.googleapis.com/v1"

curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings"

curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings/$KEYRING/cryptoKeys"

curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings/$KEYRING/cryptoKeys/$KEY/cryptoKeyVersions"
```

### Read the IAM policy on each KMS resource

The IAM binding is the single most important artifact. Policies can be set at the key-ring
level (inherited by all keys) or per crypto key.

```bash
# Key-ring level
gcloud kms keyrings get-iam-policy "$KEYRING" \
  --location "$LOC" --project "$PROJECT" --format=json

# Crypto-key level
gcloud kms keys get-iam-policy "$KEY" \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" --format=json
```

```bash
# REST
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings/$KEYRING:getIamPolicy"

curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings/$KEYRING/cryptoKeys/$KEY:getIamPolicy"
```

Also fold in project-, folder-, and organization-level IAM bindings, since roles such as
`roles/cloudkms.admin`, `roles/cloudkms.cryptoKeyEncrypterDecrypter`, `roles/owner`, and
`roles/editor` granted higher in the hierarchy are inherited by every key:

```bash
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.role | test("cloudkms|owner|editor"))'
```

### Test your own effective permissions

`testIamPermissions` reveals what the current credential can actually do against a key without
needing read access to the policy itself:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$BASE/projects/$PROJECT/locations/$LOC/keyRings/$KEYRING/cryptoKeys/$KEY:testIamPermissions" \
  -d '{"permissions":[
        "cloudkms.cryptoKeyVersions.useToEncrypt",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToSign",
        "cloudkms.cryptoKeys.setIamPolicy",
        "cloudkms.cryptoKeyVersions.destroy",
        "cloudkms.cryptoKeys.update"]}'
```

### Map key dependencies (who uses these keys)

A key's blast radius is defined by the resources encrypted with it. Cross-reference each key
name against CMEK-consuming services:

```bash
# Storage buckets using a CMEK
gcloud storage buckets list --format='value(name, default_kms_key)' \
  | grep -i "cryptoKeys"

# Compute disks with CMEK
gcloud compute disks list --format='value(name, diskEncryptionKey.kmsKeyName)'

# BigQuery dataset default CMEK
bq show --format=prettyjson "$PROJECT:$DATASET" | jq '.defaultEncryptionConfiguration'

# Secret Manager CMEK
gcloud secrets describe "$SECRET" --format='value(replication)'

# Pub/Sub topic CMEK
gcloud pubsub topics describe "$TOPIC" --format='value(kmsKeyName)'
```

### Tooling-assisted sweep

`ScoutSuite` (`gcp` provider) and `Prowler` (`-p gcp`) both inventory KMS key rings, keys,
rotation periods, and flag overly permissive bindings and `allUsers`/`allAuthenticatedUsers`
exposure automatically across all locations.

## Misconfigurations & Findings

- **Public or broad key access.** `allUsers` or `allAuthenticatedUsers` in a key or key-ring
  IAM policy, or a binding to a whole domain/`projectEditor`/`projectOwner` convenience group,
  exposes encrypt/decrypt to far more principals than intended.
- **Separation of duties violation.** A single principal holding both `roles/cloudkms.admin`
  (manage/destroy keys, set IAM) and `roles/cloudkms.cryptoKeyEncrypterDecrypter` (use keys).
  Google's recommended model keeps the key administrator distinct from the key user.
- **`roles/cloudkms.cryptoKeyEncrypterDecrypter` or `...Encrypter`/`...Decrypter` granted at
  project/folder/org level**, silently applying to every current and future key.
- **`cloudkms.cryptoKeys.setIamPolicy` reachable** by a non-admin principal - a direct
  self-grant path (see the privilege-escalation page).
- **No rotation.** `ENCRYPT_DECRYPT` keys with no `rotationPeriod`/`nextRotationTime` set, or
  unusually long rotation periods, leaving a single key version protecting data indefinitely.
- **Destroy/`destroyScheduledDuration` too short**, or principals with
  `cloudkms.cryptoKeyVersions.destroy`, enabling denial-of-service by rendering CMEK-protected
  data permanently unrecoverable.
- **Software protection level where HSM/External was required** by policy for sensitive data.
- **Imported key material** (`importJobs`) without controls, or keys whose material origin is
  unknown.
- **Orphaned/over-broad bindings** to deleted principals or default service agents that no
  longer need key access.
- **CMEK pointing at a key in a different project** with a weaker IAM policy than the data,
  effectively downgrading protection to the weakest key policy.

## Exploitation

Enumeration itself is read-only, but its output directly seeds exploitation:

- A key with `cryptoKeyEncrypterDecrypter` reachable by the current principal allows decrypt
  of every CMEK-protected object that uses it. Map the dependent buckets/disks/datasets found
  above, then decrypt their contents using the key.
- A key (or key ring) where the current principal has `setIamPolicy` allows self-granting any
  KMS role - the privilege-escalation primitive detailed in
  [GCP KMS - Privilege Escalation](../03-privilege-escalation/gcp-kms-privesc.md).
- `cloudkms.cryptoKeyVersions.destroy` on a key protecting production data is a ransom/DoS
  primitive: scheduling all versions for destruction makes the dependent data unreadable.

Use the inventory to prioritize keys by the sensitivity and quantity of data they protect.

## Detection & Logging

- **Cloud Audit Logs** record KMS activity. Admin Activity logs (always on, no opt-in) capture
  configuration changes such as `CreateCryptoKey`, `UpdateCryptoKey`,
  `SetIamPolicy`, `CreateKeyRing`, `DestroyCryptoKeyVersion`, and `UpdateCryptoKeyVersion`.
- **Data Access logs** (must be explicitly enabled for the Cloud KMS API in the IAM audit
  config) capture `GetIamPolicy`, `ListCryptoKeys`, `ListKeyRings`, and crucially the
  cryptographic data-plane operations `Encrypt`, `Decrypt`, `AsymmetricSign`,
  `AsymmetricDecrypt`, and `GenerateRandomBytes`. Without Data Access logging enabled,
  enumeration of policies and use of keys is largely invisible.
- Enumeration footprint: a burst of `ListKeyRings`/`ListCryptoKeys`/`GetIamPolicy` across many
  locations from a single principal, and `testIamPermissions` probing, are detectable signals.
- Sample query:

```
resource.type="cloudkms_cryptokey"
protoPayload.methodName=("GetIamPolicy" OR "ListCryptoKeys" OR
  "google.cloud.kms.v1.KeyManagementService.Encrypt" OR
  "google.cloud.kms.v1.KeyManagementService.Decrypt")
```

- Cloud KMS exposes monitoring metrics; alert on anomalous request volume per key.

## Remediation & Hardening

- Enforce least privilege at the key or key-ring level, never at project/folder/org level for
  KMS use roles. Prefer granular `cryptoKeyEncrypter`/`cryptoKeyDecrypter` over the combined
  `cryptoKeyEncrypterDecrypter` where only one direction is needed.
- Enforce separation of duties: distinct principals for key administration
  (`roles/cloudkms.admin`) and key usage. Never grant `setIamPolicy` to key users.
- Remove `allUsers`/`allAuthenticatedUsers` and domain-wide bindings from KMS resources.
- Enable Data Access audit logging for the Cloud KMS API so that `Encrypt`/`Decrypt`/`Sign`
  and `GetIamPolicy` are recorded.
- Configure automatic rotation (`--rotation-period`, `--next-rotation-time`) for symmetric
  `ENCRYPT_DECRYPT` keys.
- Use Organization Policy constraints (for example to require HSM protection level, or to
  restrict CMEK key locations) and IAM Conditions to scope key access.
- Set an appropriate `destroyScheduledDuration` and restrict `cryptoKeyVersions.destroy`.

## Tools

- **gcloud CLI** (`gcloud kms ...`) - native enumeration of locations, key rings, keys,
  versions, and IAM policies.
- **Cloud KMS REST/RPC API** - direct enumeration when only a bearer token is available.
- **ScoutSuite** - multi-location KMS inventory and misconfiguration flags.
- **Prowler** (`-p gcp`) - KMS rotation, public access, and separation-of-duties checks.

## References

- Cloud KMS REST API reference - https://cloud.google.com/kms/docs/reference/rest
- Cloud KMS resource hierarchy - https://cloud.google.com/kms/docs/resource-hierarchy
- Cloud KMS permissions and roles - https://cloud.google.com/kms/docs/reference/permissions-and-roles
- Separation of duties for Cloud KMS - https://cloud.google.com/kms/docs/separation-of-duties
- Cloud KMS audit logging - https://cloud.google.com/kms/docs/audit-logging
