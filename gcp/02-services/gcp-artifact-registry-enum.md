---
cstg_id: CSTG-GCP-ARTIFACT-REGISTRY-ENUM
title: "GCP Artifact Registry - Enumeration"
provider: gcp
service: artifact-registry
phase: services
required_access: read-only-audit
required_permissions:
  - artifactregistry.repositories.list
  - artifactregistry.repositories.get
  - artifactregistry.locations.list
  - artifactregistry.repositories.getIamPolicy
  - artifactregistry.packages.list
  - artifactregistry.versions.list
  - artifactregistry.tags.list
  - artifactregistry.dockerimages.list
  - resourcemanager.projects.get
tools:
  - gcloud CLI
  - Artifact Registry REST API
  - Docker CLI / OCI client
  - crane / skopeo
  - curl
references:
  - https://cloud.google.com/artifact-registry/docs/reference/rest
  - https://cloud.google.com/artifact-registry/docs/access-control
  - https://cloud.google.com/sdk/gcloud/reference/artifacts
  - https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
  - https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
license: CC BY-SA 4.0
---

## Summary

Artifact Registry is Google Cloud's managed service for storing and distributing build artifacts: container images (Docker/OCI), language packages (Maven, npm, Python/PyPI, Go, Apt, Yum/RPM), generic files, and Kubeflow Pipelines templates. It is the successor to Container Registry (GCR / `gcr.io`), and many environments run both side by side during migration.

From a testing perspective, Artifact Registry is a high-value enumeration target because it sits at the centre of the software supply chain. Repositories frequently leak sensitive data in two ways: through their *contents* (hardcoded credentials, service-account keys, internal source code, and configuration baked into image layers or package archives) and through their *access policy* (overly broad IAM bindings, public `allUsers`/`allAuthenticatedUsers` grants, and remote/virtual repositories that proxy or cache upstream content). Identifying who can read, write, and administer each repository establishes both the data-exposure risk and the foundations for later privilege-escalation and persistence analysis (see [Privilege Escalation](../03-privilege-escalation/gcp-artifact-registry-privesc.md) and [Persistence](../06-persistence/gcp-artifact-registry-persistence.md)).

This page covers read-only discovery: locating repositories across all regions, inventorying packages and image versions, pulling manifests and layers for content inspection, and reviewing IAM and repository configuration for misconfiguration.

## Prerequisites

- A principal (user, service account, or federated identity) with at least read access to the target project, or a credential obtained earlier in the engagement.
- For full inventory, the permissions listed in `required_permissions`. Many are bundled in the predefined roles `roles/artifactregistry.reader` (read repositories and contents), `roles/artifactregistry.repoAdmin`, `roles/artifactregistry.admin`, and `roles/viewer`.
- For image/package download, network reachability to the regional endpoints (`<location>-docker.pkg.dev`, `<location>-maven.pkg.dev`, `<location>-npm.pkg.dev`, `<location>-python.pkg.dev`, etc.).
- The active project ID. If unknown, enumerate with `gcloud projects list` or `resourcemanager.projects.get`.

> Note: read access to repository *contents* (pulling an image) is governed by `artifactregistry.repositories.downloadArtifacts`, which is separate from the metadata permissions used to *list* repositories. A principal may be able to enumerate names without being able to pull, or vice versa.

## Enumeration

### Locations and repositories

Artifact Registry repositories are regional (or multi-regional) resources. Always enumerate across all locations, because operators commonly create repositories in non-default regions that a single-region scan misses.

```bash
# Supported locations
gcloud artifacts locations list

# List all repositories in a project (across locations)
gcloud artifacts repositories list --project=<PROJECT_ID>

# Detailed view of one repository (format, mode, cleanup policies, KMS key, etc.)
gcloud artifacts repositories describe <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID>
```

Raw REST equivalent (useful when the CLI is unavailable or to script across many projects):

```bash
TOKEN=$(gcloud auth print-access-token)

# Iterate locations, then list repositories per location
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://artifactregistry.googleapis.com/v1/projects/<PROJECT_ID>/locations/<LOCATION>/repositories"
```

Key fields in each repository object:

- `format` — `DOCKER`, `MAVEN`, `NPM`, `PYTHON`, `APT`, `YUM`, `GO`, `KFP`, `GENERIC`.
- `mode` — `STANDARD_REPOSITORY`, `REMOTE_REPOSITORY` (proxies/caches an upstream such as Docker Hub or PyPI), or `VIRTUAL_REPOSITORY` (aggregates several upstreams behind one endpoint). Remote and virtual repositories carry their own risk profile (see Misconfigurations).
- `kmsKeyName` — presence indicates CMEK encryption.
- `cleanupPolicies` / `cleanupPolicyDryRun` — retention rules; dry-run mode means policies are evaluated but not enforced, so stale/vulnerable versions may persist.
- `remoteRepositoryConfig` — upstream URI and, for remote repos, the upstream credential reference.

### Packages, versions, and tags

Once a repository is identified, enumerate its contents:

```bash
# Container images in a Docker-format repository
gcloud artifacts docker images list \
  <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO> \
  --include-tags --project=<PROJECT_ID>

# Generic package listing (works for any format)
gcloud artifacts packages list \
  --repository=<REPO> --location=<LOCATION> --project=<PROJECT_ID>

# Versions of a package
gcloud artifacts versions list \
  --package=<PACKAGE> --repository=<REPO> \
  --location=<LOCATION> --project=<PROJECT_ID>

# Tags mapped to versions
gcloud artifacts tags list \
  --package=<PACKAGE> --repository=<REPO> \
  --location=<LOCATION> --project=<PROJECT_ID>
```

### Pulling and inspecting image content

For Docker/OCI repositories, the registry speaks the standard OCI Distribution / Docker Registry v2 protocol. Authenticate Docker to the endpoint and then use standard tooling. The username `oauth2accesstoken` with a gcloud access token, or `_json_key`/`_json_key_base64` with a service-account key, are both accepted.

```bash
# Configure Docker credential helper for the endpoint
gcloud auth configure-docker <LOCATION>-docker.pkg.dev

# Or authenticate ad hoc with a raw token (no helper)
echo "$(gcloud auth print-access-token)" | \
  docker login -u oauth2accesstoken --password-stdin https://<LOCATION>-docker.pkg.dev

docker pull <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:<TAG>
```

`crane` and `skopeo` allow manifest, config, and layer inspection without a full Docker daemon — useful for scanning many images quickly:

```bash
crane auth login <LOCATION>-docker.pkg.dev -u oauth2accesstoken -p "$(gcloud auth print-access-token)"
crane catalog <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>
crane manifest <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:<TAG>
crane config   <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:<TAG>   # ENV, ENTRYPOINT, history

skopeo inspect docker://<LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:<TAG>
```

The image config (`crane config`) frequently exposes build-time environment variables, embedded tokens, and the layer history including `RUN` commands. Each layer is a tarball that can be unpacked and scanned for secrets, private keys, `.npmrc`/`.pypirc`/`.git` directories, and credential files left behind during the build.

### Raw registry API (anonymous / token probing)

The OCI endpoints can be queried directly to test for anonymous read access or to enumerate repository catalogs without the gcloud helper:

```bash
# Token endpoint (returns a bearer scoped to a repository)
curl -s "https://<LOCATION>-docker.pkg.dev/v2/token?scope=repository:<PROJECT_ID>/<REPO>/<IMAGE>:pull"

# Catalog and tag listing against the v2 API
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://<LOCATION>-docker.pkg.dev/v2/_catalog"
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://<LOCATION>-docker.pkg.dev/v2/<PROJECT_ID>/<REPO>/<IMAGE>/tags/list"
```

### Language-package repositories

Non-container formats expose HTTP endpoints with their ecosystem's native protocol. Indexes and archives reveal internal package names (which themselves can hint at dependency-confusion exposure) and may contain secrets:

```bash
# Python (PyPI-style simple index)
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://<LOCATION>-python.pkg.dev/<PROJECT_ID>/<REPO>/simple/"

# npm
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://<LOCATION>-npm.pkg.dev/<PROJECT_ID>/<REPO>/<PACKAGE>"

# Maven (browse the layout directly)
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://<LOCATION>-maven.pkg.dev/<PROJECT_ID>/<REPO>/<group/path>/maven-metadata.xml"
```

### Legacy Container Registry (gcr.io)

If GCR is still in use, the backing Cloud Storage buckets (`artifacts.<PROJECT_ID>.appspot.com`, `<region>.artifacts.<PROJECT_ID>.appspot.com`, or `<host>_artifacts`) and the `gcr.io`/`<region>.gcr.io` endpoints should be enumerated with the same OCI tooling. GCR access is governed by the storage IAM of those buckets, so a public-readable artifacts bucket exposes every image.

## Misconfigurations & Findings

- **Public repositories (`allUsers` / `allAuthenticatedIdentities`):** an IAM binding granting `roles/artifactregistry.reader` (or stronger) to `allUsers` exposes every artifact to the internet; `allAuthenticatedUsers`/`allAuthenticatedIdentities` exposes it to any Google account. Inspect with `getIamPolicy` (below).
- **Secrets baked into images/packages:** service-account JSON keys, cloud credentials, API tokens, and private SSH/TLS keys embedded in layers, `ENV` instructions, or package archives. These often grant a foothold far beyond the registry itself.
- **Overly broad write/admin bindings:** principals with `roles/artifactregistry.writer`, `repoAdmin`, or `admin` who do not need them create supply-chain tampering and persistence opportunities.
- **Remote repositories with embedded upstream credentials:** `REMOTE_REPOSITORY` mode can store credentials (via Secret Manager) for authenticated upstreams; readers of the repo config plus the referenced secret may recover them.
- **Virtual repositories with priority ordering:** a `VIRTUAL_REPOSITORY` aggregating an internal standard repo and an external remote repo can be vulnerable to dependency confusion if upstream priority lets a public package shadow an internal name.
- **Disabled or dry-run cleanup policies:** stale versions with known CVEs persist and remain pullable.
- **No CMEK / no VPC Service Controls:** absence of `kmsKeyName` and absence of a VPC-SC perimeter means data is reachable from any network with valid IAM.

### Reviewing the IAM policy

```bash
gcloud artifacts repositories get-iam-policy <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> --format=json
```

```bash
curl -s -X POST -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "https://artifactregistry.googleapis.com/v1/projects/<PROJECT_ID>/locations/<LOCATION>/repositories/<REPO>:getIamPolicy"
```

Flag any binding to `allUsers` or `allAuthenticatedUsers`, and any member outside the expected set. Remember that project-level and folder/org-level bindings also apply — a `roles/artifactregistry.reader` at the project level grants access to every repository in the project, so enumerate ancestor policies too.

## Detection & Logging

Enumeration of Artifact Registry is recorded in **Cloud Audit Logs**:

- **Admin Activity** logs (always on, non-disableable) capture configuration reads/writes such as `GetRepository`, `GetIamPolicy`, `SetIamPolicy`, `CreateRepository`, and `DeleteRepository` under the service name `artifactregistry.googleapis.com`.
- **Data Access** logs (must be explicitly enabled per service or org-wide) capture `ListRepositories`, `ListPackages`, `ListVersions`, and artifact downloads/uploads (`DownloadArtifacts`, image pulls). Without Data Access logging enabled, bulk content enumeration and image pulls are largely invisible.

Defenders should watch for:

- A single principal calling `getIamPolicy`/`ListRepositories` across many repositories or projects in a short window.
- Image pulls from unusual principals, source IPs, or geographies (`DownloadArtifacts` data-access events).
- Anonymous or `allAuthenticatedUsers` access appearing in logs, indicating a public binding is being exercised.

Sample query (Logs Explorer):

```
resource.type="audited_resource"
protoPayload.serviceName="artifactregistry.googleapis.com"
protoPayload.methodName=~"(GetIamPolicy|ListRepositories|DownloadArtifacts)"
```

## Remediation & Hardening

- Remove all `allUsers` / `allAuthenticatedUsers` bindings unless a repository is intentionally public; prefer per-team groups over individuals.
- Apply least privilege: grant `roles/artifactregistry.reader` only where pulls are required, and reserve `writer`/`repoAdmin`/`admin` for CI/CD service accounts and platform owners.
- Enable **Data Access audit logs** for `artifactregistry.googleapis.com` so reads and pulls are recorded.
- Place repositories inside a **VPC Service Controls** perimeter to prevent exfiltration to untrusted networks even with valid IAM.
- Enforce **CMEK** for sensitive repositories and enforce active (non-dry-run) cleanup policies.
- Scan images and packages for embedded secrets in CI before publishing; never bake service-account keys into images — use Workload Identity instead.
- For virtual/remote repositories, set internal upstreams at higher priority than public ones and restrict which principals may configure them.

## Tools

- **gcloud CLI** (`gcloud artifacts ...`) — repository, package, version, tag, and IAM enumeration.
- **Artifact Registry REST API** — scriptable enumeration across projects/locations.
- **Docker CLI**, **crane**, **skopeo** — pull and inspect image manifests, configs, and layers.
- **Secret scanners** (e.g. trufflehog, gitleaks against unpacked layers) — locate credentials in artifacts.
- **curl** — direct OCI v2 / language-ecosystem API probing and anonymous-access testing.

## References

- Artifact Registry REST API reference — https://cloud.google.com/artifact-registry/docs/reference/rest
- Artifact Registry access control and roles — https://cloud.google.com/artifact-registry/docs/access-control
- gcloud artifacts command reference — https://cloud.google.com/sdk/gcloud/reference/artifacts
- Remote and virtual repositories — https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
- Predefined IAM roles for Artifact Registry — https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
