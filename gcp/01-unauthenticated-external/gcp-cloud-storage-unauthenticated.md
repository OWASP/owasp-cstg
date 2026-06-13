---
cstg_id: CSTG-GCP-CLOUD-STORAGE-UNAUTH
title: "GCP Cloud Storage - Unauthenticated Access"
provider: gcp
service: cloud-storage
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: ["gsutil", "gcloud storage", "curl", "GCPBucketBrute", "cloud_enum"]
references:
  - "https://cloud.google.com/storage/docs/access-control/lists"
  - "https://cloud.google.com/storage/docs/access-control/iam-permissions"
  - "https://cloud.google.com/storage/docs/json_api/v1/objects/list"
  - "https://cloud.google.com/storage/docs/request-endpoints"
  - "https://cloud.google.com/storage/docs/access-control/making-data-public"
  - "https://hackingthe.cloud/gcp/general-knowledge/default_cloud_storage_naming/"
  - "https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/"
license: CC BY-SA 4.0
---

## Summary

Google Cloud Storage organizes data into globally namespaced **buckets** that
contain **objects** (blobs). Because the bucket namespace is global and flat,
any bucket name can be probed from the public Internet without credentials.
Buckets and objects can be exposed to anonymous principals through two distinct
access-control systems: **IAM policies** (binding roles to the special members
`allUsers` and `allAuthenticatedUsers`) and legacy **Access Control Lists
(ACLs)** that grant permissions to the `AllUsers` / `AllAuthenticatedUsers`
scopes. Either path can leak object contents, object listings, or even write
access to anyone on the Internet.

The unauthenticated objective is to discover the existence of buckets belonging
to a target, determine whether anonymous read or list access is allowed, and
extract any data or metadata reachable without authentication. A misconfigured
bucket frequently yields source code, database backups, configuration files,
secrets, customer data, or static-site assets that disclose internal structure.

## Prerequisites

- No credentials. All techniques here operate over the public XML and JSON HTTP
  endpoints or via tooling configured for anonymous access.
- Network egress to `storage.googleapis.com` and the per-bucket virtual-hosted
  endpoints (`<bucket>.storage.googleapis.com`).
- A candidate list of organization names, product names, project IDs, and
  domains to seed bucket-name guessing.

## Enumeration

### Public request endpoints

Cloud Storage exposes several equivalent unauthenticated HTTP endpoints. A
single object or bucket can be reached through any of them:

```
# Virtual-hosted style (XML API)
https://<BUCKET>.storage.googleapis.com/<OBJECT>

# Path style (XML API)
https://storage.googleapis.com/<BUCKET>/<OBJECT>

# JSON API
https://www.googleapis.com/storage/v1/b/<BUCKET>/o/<OBJECT>

# Legacy / alternate host
https://commondatastorage.googleapis.com/<BUCKET>/<OBJECT>
```

### Distinguishing existence from access

The HTTP status code returned for an anonymous request reveals the bucket's
state without any credentials:

```bash
# Does the bucket exist, and is it publicly listable?
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://storage.googleapis.com/storage/v1/b/<BUCKET>/o"
```

| Response | Interpretation |
|----------|----------------|
| `200` + object list | Bucket exists and **anonymous listing is allowed** |
| `403` (`AccessDenied`) | Bucket **exists** but listing is denied (name confirmed) |
| `404` (`NoSuchBucket`) | Bucket does not exist (name available) |

This existence oracle means an attacker can confirm bucket names even when no
data is readable, which fuels further targeted guessing.

### Reading and listing with tooling

```bash
# Anonymous listing of a bucket's objects (no project / no creds)
gsutil ls gs://<BUCKET>/
gcloud storage ls gs://<BUCKET>/ --no-user-output-enabled

# XML API object listing (no auth header)
curl -s "https://storage.googleapis.com/<BUCKET>?list-type=2"
curl -s "https://<BUCKET>.storage.googleapis.com/"

# Fetch a specific object
curl -s "https://storage.googleapis.com/<BUCKET>/<OBJECT>" -o loot.bin
```

### Name guessing and brute force

Bucket names commonly follow predictable patterns. Seed wordlists with the
target's name plus separators and suffixes:

```
<org>           <org>-backup        <org>-assets       <org>-prod
<org>-dev       <org>-staging       <org>-data         <org>-logs
<org>-static    <org>-media         <org>-terraform    <org>-tf-state
<org>.<domain>  <org>_backups       <project-id>-temp  <project-id>.appspot.com
```

Automated discovery:

```bash
# GCPBucketBrute - permutes a keyword and tests existence/permissions
python3 gcpbucketbrute.py -k <KEYWORD> -u   # -u = unauthenticated mode

# cloud_enum - multi-cloud, includes GCS bucket discovery
cloud_enum -k <KEYWORD> --quickscan
```

### App Engine and Firebase default buckets

Projects that use App Engine or Firebase receive automatic default buckets whose
names derive from the project ID:

```
<PROJECT_ID>.appspot.com
staging.<PROJECT_ID>.appspot.com
<PROJECT_ID>.firebasestorage.app
```

Guessing the project ID therefore directly yields candidate bucket names that
may contain deployed application artifacts.

## Misconfigurations & Findings

- **`allUsers` granted a read or viewer role.** An IAM binding of
  `roles/storage.objectViewer` or `roles/storage.legacyObjectReader` to
  `allUsers` makes every object readable by anyone. `roles/storage.objectAdmin`
  or `roles/storage.legacyBucketWriter` additionally allow anonymous **writes**.
- **`allUsers` granted `roles/storage.legacyBucketReader` or
  `roles/storage.admin`.** This permits anonymous **listing** of object keys,
  exposing the full inventory even where individual object names are not
  guessable.
- **`allAuthenticatedUsers` bindings.** This member matches **any Google
  account on the Internet**, not just the target's organization. It is not a
  meaningful access restriction and should be treated as public.
- **Legacy ACLs with `AllUsers` / `AllAuthenticatedUsers` scope.** Even when the
  bucket-level IAM policy is clean, individual objects may carry public ACL
  entries (common for objects copied with `-a public-read`).
- **Uniform vs. fine-grained access.** Buckets with fine-grained (ACL-enabled)
  access can have per-object public grants that are easy to overlook; uniform
  bucket-level access disables object ACLs and is the safer default.
- **Sensitive content in "static asset" buckets.** Static-site or CDN buckets
  intentionally made public frequently also contain `.env`, `.git/`, backups,
  source maps, or admin tooling that was never meant to be served.
- **Existence disclosure via `403`.** Even a locked-down bucket confirms a
  naming convention, aiding reconnaissance of related buckets.

## Exploitation

1. **Confirm the target bucket exists** using the status-code oracle above.
2. **Test anonymous listing.** If `GET /storage/v1/b/<BUCKET>/o` returns `200`,
   enumerate every object key and triage by extension (`.sql`, `.bak`, `.zip`,
   `.env`, `.pem`, `.json`, `.tfstate`, `.log`).
3. **Test anonymous object read** even when listing is denied: fetch objects by
   guessed/known names (`backup.sql`, `.env`, `config.json`,
   `terraform.tfstate`). Listing denied does not imply reads denied.
4. **Test anonymous write.** Attempt to upload an object; success indicates a
   writable public bucket that can be abused for hosting, defacement, or
   tampering with assets consumed by the application:
   ```bash
   echo test > poc.txt
   gsutil cp poc.txt gs://<BUCKET>/poc.txt
   curl -X PUT --data-binary @poc.txt \
     "https://storage.googleapis.com/<BUCKET>/poc.txt"
   ```
5. **Pivot on contents.** Extract credentials, service-account keys, or
   `tfstate` files that contain long-lived secrets, then use them for
   authenticated access (see
   [GCP Cloud Storage - Privilege Escalation](../03-privilege-escalation/gcp-cloud-storage-privesc.md)).
6. **Map version history.** If object versioning is enabled and public, older
   object generations may still be readable even after the live object was
   "deleted":
   ```bash
   gsutil ls -a gs://<BUCKET>/<OBJECT>     # shows generation numbers
   curl "https://storage.googleapis.com/<BUCKET>/<OBJECT>?generation=<GEN>"
   ```

## Detection & Logging

- **Cloud Audit Logs - Data Access:** Anonymous object reads/writes appear in
  `storage.googleapis.com` Data Access logs **only if Data Access audit logging
  is explicitly enabled** for the project (it is off by default for reads). The
  principal is recorded as unauthenticated/anonymous.
- **Cloud Audit Logs - Admin Activity:** The act of adding an `allUsers` /
  `allAuthenticatedUsers` IAM binding or a public ACL is recorded in
  Admin Activity logs (`SetIamPolicy`, `storage.setIamPermissions`,
  `storage.objects.update` with ACL change) and is always on.
- **Usage logs / access logs:** Optional Cloud Storage usage and storage logs
  written to a log bucket capture per-request `cs_method`, `cs_uri`, and
  requester identity, useful for spotting anonymous traffic.
- **Server access logs at the network layer:** If served through Cloud CDN or a
  load balancer, request logs there reveal mass enumeration patterns
  (sequential `404`/`403` bursts).
- **Security Command Center** flags `PUBLIC_BUCKET_ACL` and
  `PUBLIC_LOG_BUCKET` style findings for buckets exposed to `allUsers` /
  `allAuthenticatedUsers`.

## Remediation & Hardening

- **Enable Uniform Bucket-Level Access** to disable object ACLs and centralize
  control in IAM.
- **Enable Public Access Prevention** at the bucket or organization level. The
  organization policy constraint
  `constraints/storage.publicAccessPrevention` blocks any binding to `allUsers`
  / `allAuthenticatedUsers` and overrides existing public grants.
- **Audit existing public exposure:**
  ```bash
  gsutil iam get gs://<BUCKET> | grep -E "allUsers|allAuthenticatedUsers"
  gcloud storage buckets get-iam-policy gs://<BUCKET> --format=json
  ```
- **Never use `allAuthenticatedUsers`** as an access restriction; it is
  effectively public.
- **Serve genuinely public content through Cloud CDN / signed URLs** rather than
  marking source buckets public; keep build artifacts, backups, and state files
  in private buckets.
- **Disable Data Access reads-as-public** and turn on Data Access audit logging
  to gain visibility into anonymous reads.
- **Use VPC Service Controls** to place sensitive buckets inside a service
  perimeter so data exfiltration from anonymous or stolen credentials is
  blocked at the perimeter.

## Tools

- **gsutil / gcloud storage** - native CLI; both operate anonymously when no
  credentials are configured.
- **curl** - direct XML/JSON endpoint probing and the existence oracle.
- **GCPBucketBrute** - keyword-driven bucket name permutation and
  permission testing (authenticated and unauthenticated modes).
- **cloud_enum** - multi-cloud public-resource discovery including GCS.

## References

- Cloud Storage access control - ACLs: https://cloud.google.com/storage/docs/access-control/lists
- Cloud Storage IAM permissions: https://cloud.google.com/storage/docs/access-control/iam-permissions
- Objects: list (JSON API): https://cloud.google.com/storage/docs/json_api/v1/objects/list
- Request endpoints: https://cloud.google.com/storage/docs/request-endpoints
- Making data public: https://cloud.google.com/storage/docs/access-control/making-data-public
- Default Cloud Storage naming (hackingthe.cloud): https://hackingthe.cloud/gcp/general-knowledge/default_cloud_storage_naming/
- GCP bucket enumeration (Rhino Security Labs): https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/
