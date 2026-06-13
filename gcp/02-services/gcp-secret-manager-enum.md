---
cstg_id: CSTG-GCP-SECRET-MANAGER-ENUM
title: "GCP Secret Manager - Enumeration"
provider: gcp
service: secret-manager
phase: services
required_access: read-only-audit
required_permissions:
  - secretmanager.secrets.list
  - secretmanager.secrets.get
  - secretmanager.secrets.getIamPolicy
  - secretmanager.versions.list
  - secretmanager.versions.get
  - secretmanager.locations.list
  - resourcemanager.projects.get
tools: ["gcloud secrets", "GCP Secret Manager REST API", "ScoutSuite", "Prowler", "PMapper", "GCP IAM analysis tooling"]
references:
  - "https://cloud.google.com/secret-manager/docs/overview"
  - "https://cloud.google.com/secret-manager/docs/access-control"
  - "https://cloud.google.com/secret-manager/docs/reference/rest"
  - "https://cloud.google.com/secret-manager/docs/managing-secrets"
  - "https://cloud.google.com/secret-manager/docs/managing-secret-versions"
  - "https://cloud.google.com/secret-manager/docs/manage-access-to-secrets"
  - "https://cloud.google.com/secret-manager/docs/audit-logging"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated enumeration of Google Cloud Secret Manager from
a read-only ("audit") vantage point: an identity holding viewer-level
permissions across one or more projects. Secret Manager stores API keys,
database passwords, TLS private keys, service-account JSON, OAuth client
secrets, and other credential material as versioned `secret` resources, each
with its own resource-level IAM policy. The objective of enumeration is to build
a complete inventory of secrets, their versions, replication/CMEK
configuration, and - most importantly - **who can read them**, so that
exploitable access paths can be identified before they are exercised.

Distinguish two capability tiers during enumeration. *Metadata* permissions
(`secretmanager.secrets.list`, `secretmanager.secrets.get`,
`secretmanager.versions.list`) reveal that a secret exists and how it is
configured but do **not** disclose the secret value. The *payload* permission
`secretmanager.versions.access` is what actually returns plaintext and is the
crown jewel; this page treats reaching that permission as the goal, while
[Privilege Escalation](../03-privilege-escalation/gcp-secret-manager-privesc.md)
and
[Post-Exploitation](../05-post-exploitation/gcp-secret-manager-post-exploitation.md)
cover obtaining and weaponizing it.

## Prerequisites

- A valid Google identity (user account or service account) with at least
  viewer-level permissions on the target project(s). A minimal useful metadata
  set is `secretmanager.secrets.list`, `secretmanager.secrets.get`,
  `secretmanager.versions.list`, and `secretmanager.secrets.getIamPolicy`.
  `roles/secretmanager.viewer` grants metadata + IAM visibility without payload
  access; `roles/viewer` (primitive) also grants metadata across the project.
- The target project ID(s). `resourcemanager.projects.get` /
  `resourcemanager.projects.list` help discover them. Secret Manager is a
  global service but secrets may be regionally pinned, so
  `secretmanager.locations.list` is useful.
- A configured `gcloud` environment, or an OAuth access token for direct REST
  API calls.

## Enumeration

### Establish identity and project scope

```bash
gcloud auth list
gcloud config get-value project
gcloud auth print-access-token            # raw OAuth token for API calls

# Projects this identity can see
gcloud projects list --format="value(projectId)"

# Confirm the Secret Manager API is enabled on a project
gcloud services list --enabled --project=<PROJECT_ID> \
  --filter="config.name=secretmanager.googleapis.com"
```

### List secrets

```bash
# All secrets in a project (metadata only)
gcloud secrets list --project=<PROJECT_ID>

# REST API
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets"

# Regional (regionalized) secrets, if any locations are in use
for L in $(gcloud secrets locations list 2>/dev/null); do :; done
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.<LOCATION>.rep.googleapis.com/v1/projects/<PROJECT_ID>/locations/<LOCATION>/secrets"
```

### Describe secret configuration and posture

```bash
# Full metadata: replication, CMEK, labels, rotation, expiry, annotations
gcloud secrets describe <SECRET> --project=<PROJECT_ID> --format=json

# REST equivalent
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>"
```

Capture for each secret: `replication` (automatic vs. user-managed and which
regions), `replication.*.customerManagedEncryption.kmsKeyName` (CMEK key, if
any), `rotation`, `expireTime`/`ttl`, `topics` (Pub/Sub notifications),
`labels`, and `annotations` - labels and secret *names* frequently leak the
secret's purpose (e.g. `prod-db-password`, `stripe-live-key`).

### Enumerate versions

```bash
# List versions and their state (ENABLED / DISABLED / DESTROYED)
gcloud secrets versions list <SECRET> --project=<PROJECT_ID>

# Describe a specific version (metadata, not payload)
gcloud secrets versions describe <VERSION> --secret=<SECRET> --project=<PROJECT_ID>

# REST
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>/versions"
```

Note: listing/describing versions returns state and create time but **not** the
payload. Plaintext requires the `access` operation
(`projects/.../versions/<n>:access`), which depends on
`secretmanager.versions.access` - see Exploitation.

### Read access-control bindings (the critical step)

Each secret carries its own IAM policy; project-level viewers may not have
payload access, while a narrow per-secret binding might grant it to a different,
reachable principal.

```bash
# Per-secret IAM policy
gcloud secrets get-iam-policy <SECRET> --project=<PROJECT_ID> --format=json

# REST
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>:getIamPolicy"

# Project-level bindings that confer secret access (inherited by all secrets)
gcloud projects get-iam-policy <PROJECT_ID> --format=json \
  | grep -E "secretmanager|roles/(owner|editor)"
```

Look specifically for principals bound to `roles/secretmanager.secretAccessor`
(or `admin`) at the project level or on individual secrets, and for IAM
Conditions that scope access by `resource.name`.

### Test whether the current identity can read payloads

```bash
# Ask the API directly which permissions the caller holds on a secret
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["secretmanager.versions.access","secretmanager.versions.get","secretmanager.secrets.setIamPolicy"]}' \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>:testIamPermissions"
```

### Sweep across all reachable projects

```bash
for P in $(gcloud projects list --format="value(projectId)"); do
  echo "== $P =="
  gcloud secrets list --project="$P" --format="value(name,createTime)" 2>/dev/null
done
```

## Misconfigurations & Findings

- **Broad payload access:** `roles/secretmanager.secretAccessor` or
  `roles/secretmanager.admin` bound to large groups, `allAuthenticatedUsers`,
  `domain:<domain>`, or to primitive `roles/editor`/`roles/owner` holders -
  every such principal can read plaintext.
- **Primitive roles confer secret access:** `roles/owner` and `roles/editor`
  include `secretmanager.versions.access`; any editor/owner on the project can
  read every secret, often unintentionally.
- **Default service accounts with secret access:** the Compute Engine default SA
  (Editor) or other broadly-attached SAs holding accessor on secrets, reachable
  via any workload running as them (see
  [Compute Engine enumeration](gcp-compute-engine-enum.md)).
- **Missing IAM Conditions:** accessor granted project-wide rather than scoped
  to specific secret names, so one binding exposes all current and future
  secrets.
- **No CMEK where policy requires it:** secrets encrypted only with
  Google-managed keys, removing the KMS-key access checkpoint and any
  customer-controlled key audit/disable lever.
- **Sensitive secret names/labels** that reveal purpose and increase targeting
  value (production credentials, signing keys, third-party API keys).
- **Old enabled versions:** superseded but still `ENABLED` versions that may
  contain rotated-out credentials still valid downstream.
- **Data Access logging disabled:** `AccessSecretVersion` is a Data Access event
  and is **not logged by default**, so payload reads are invisible.

### Programmatic posture scan

```bash
# ScoutSuite - surfaces Secret Manager IAM exposure among other findings
scout gcp --user-account --report-dir ./scout

# Prowler for GCP
prowler gcp --project-ids <PROJECT_ID>
```

## Detection & Logging

- **Cloud Audit Logs - Admin Activity** (always on, cannot be disabled) records
  `CreateSecret`, `UpdateSecret`, `DeleteSecret`, `AddSecretVersion`,
  `DestroySecretVersion`, `SetIamPolicy`, and metadata reads are partly here.
- **Data Access logs** capture `GetSecret`, `ListSecrets`, `ListSecretVersions`,
  `GetSecretVersion`, and crucially `AccessSecretVersion` - but **only when Data
  Access logging is enabled** for `secretmanager.googleapis.com`. Without it,
  enumeration and payload reads leave no trace.
- The caller identity appears in
  `protoPayload.authenticationInfo.principalEmail`; the secret and version are
  in `protoPayload.resourceName`.
- **Security Command Center / Event Threat Detection** can surface anomalous
  access volumes and over-permissive IAM findings on secrets.
- Posture tooling (ScoutSuite/Prowler) generates a recognizable burst of
  `*.get`/`*.list`/`getIamPolicy` calls from one principal.

```bash
gcloud logging read \
  'protoPayload.serviceName="secretmanager.googleapis.com" AND
   protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"' \
  --project=<PROJECT_ID> --freshness=7d
```

## Remediation & Hardening

- Enable **Data Access audit logging** (DATA_READ) for
  `secretmanager.googleapis.com` so version access and enumeration are visible.
- Grant `roles/secretmanager.secretAccessor` **per secret**, not project-wide,
  and use **IAM Conditions** scoping by `resource.name` where multiple secrets
  share a project.
- Avoid primitive `roles/editor`/`roles/owner` on projects holding sensitive
  secrets; these silently confer payload access.
- Use **CMEK** so access additionally depends on a KMS key you can audit and
  disable, and so key-usage logs provide a second signal.
- Set **rotation** schedules and **disable/destroy** superseded versions so old
  credentials cannot be read.
- Constrain access with **VPC Service Controls** perimeters to limit which
  networks/identities can call the Secret Manager API.
- Regularly review per-secret IAM policies and alert on new `secretAccessor`
  bindings, especially to broad principals.

## Tools

- **gcloud secrets** - native enumeration of secrets, versions, metadata, and
  IAM policies.
- **GCP Secret Manager REST API** - scriptable enumeration with a bearer token,
  including `testIamPermissions`.
- **ScoutSuite** - cross-service posture assessment surfacing Secret Manager IAM
  exposure.
- **Prowler** - check-based GCP auditing.
- **PMapper / IAM analysis tooling** - models which principals can reach
  `secretmanager.versions.access` on which secrets, directly or via
  impersonation.

## References

- Secret Manager overview - https://cloud.google.com/secret-manager/docs/overview
- Access control - https://cloud.google.com/secret-manager/docs/access-control
- REST reference - https://cloud.google.com/secret-manager/docs/reference/rest
- Managing secrets - https://cloud.google.com/secret-manager/docs/managing-secrets
- Managing secret versions - https://cloud.google.com/secret-manager/docs/managing-secret-versions
- Manage access to secrets - https://cloud.google.com/secret-manager/docs/manage-access-to-secrets
- Audit logging - https://cloud.google.com/secret-manager/docs/audit-logging
</content>
</invoke>
