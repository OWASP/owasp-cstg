---
cstg_id: CSTG-GCP-COMPUTE-ENGINE-ENUM
title: "GCP Compute Engine - Enumeration"
provider: gcp
service: compute-engine
phase: services
required_access: read-only-audit
required_permissions:
  - compute.instances.list
  - compute.instances.get
  - compute.disks.list
  - compute.images.list
  - compute.snapshots.list
  - compute.networks.list
  - compute.subnetworks.list
  - compute.firewalls.list
  - compute.addresses.list
  - compute.instances.getSerialPortOutput
  - compute.projects.get
  - iam.serviceAccounts.list
tools: [gcloud, gcp-rest-api, ScoutSuite, prowler, gcp_enum, curl, jq]
references:
  - "https://cloud.google.com/compute/docs/reference/rest/v1/instances/list"
  - "https://cloud.google.com/sdk/gcloud/reference/compute/instances/list"
  - "https://cloud.google.com/compute/docs/metadata/overview"
  - "https://cloud.google.com/compute/docs/access/service-accounts"
  - "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts"
  - "https://cloud.google.com/compute/docs/instances/viewing-and-applying-os-patch-data"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-oriented enumeration of Google Compute Engine once any valid credential is held - a stolen service-account token, leaked user credentials, or an authorized read-only audit identity. The objective is to build a complete inventory of the compute footprint and to surface the data that drives later phases: which instances exist, what service accounts they run as and with what scopes, which disks/snapshots/images contain data, how the network and firewalls are shaped, and what secrets sit in instance and project metadata.

Enumeration is deliberately low-impact and read-only; every command below maps to a `*.list` or `*.get` permission. Findings here feed directly into [privilege escalation](../03-privilege-escalation/gcp-compute-engine-privesc.md) and [post-exploitation](../05-post-exploitation/gcp-compute-engine-post-exploitation.md).

## Prerequisites

- Any authenticated principal with Compute read permissions (for example the `roles/compute.viewer` role or an attached service account whose token was obtained via SSRF/metadata - see the [unauthenticated page](../01-unauthenticated-external/gcp-compute-engine-unauthenticated.md)).
- `gcloud` configured, or a raw OAuth bearer token for direct REST calls.

Validate the active identity and its reach first:

```bash
gcloud auth list
gcloud config get-value project
gcloud projects list                       # cross-project visibility?
curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$(gcloud auth print-access-token)"
```

## Enumeration

### Instances

```bash
# All instances across all zones
gcloud compute instances list

# Full detail (service accounts, scopes, metadata, networking, disks)
gcloud compute instances list --format=json
gcloud compute instances describe <NAME> --zone <ZONE> --format=json

# Raw REST equivalent (aggregated across zones)
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://compute.googleapis.com/compute/v1/projects/<PROJECT>/aggregated/instances"
```

Key fields to extract from each instance: `serviceAccounts[].email` and `serviceAccounts[].scopes`, `metadata.items` (startup scripts, SSH keys), `networkInterfaces[].accessConfigs` (external IPs), `disks[].source`, `shieldedInstanceConfig`, and `tags` (which firewall rules apply).

### Service accounts and scopes

The service account attached to an instance plus its OAuth scopes defines the blast radius of that VM. Enumerate both:

```bash
# Service accounts in the project
gcloud iam service-accounts list

# What an instance runs as (per-instance default identity + scopes)
gcloud compute instances describe <NAME> --zone <ZONE> \
  --format="yaml(serviceAccounts)"
```

A service account bound with `https://www.googleapis.com/auth/cloud-platform` scope and broad IAM roles is the prime escalation target.

### Disks, snapshots, and images

```bash
gcloud compute disks list
gcloud compute snapshots list
gcloud compute images list --no-standard-images          # custom images only
gcloud compute images list --format="table(name,family,licenses)"

# Check for publicly shared images/snapshots (allUsers/allAuthenticatedUsers)
gcloud compute images get-iam-policy <IMAGE>
gcloud compute snapshots get-iam-policy <SNAPSHOT>
```

### Networking and firewalls

```bash
gcloud compute networks list
gcloud compute networks subnets list
gcloud compute firewall-rules list --format="table(name,network,direction,sourceRanges.list(),allowed[].map().firewall_rule().list(),targetTags.list())"
gcloud compute addresses list                 # reserved static IPs
gcloud compute routers list
```

Flag firewall rules with `sourceRanges=0.0.0.0/0` allowing 22, 3389, or database ports, and target tags that map them to specific instances.

### Metadata - the high-value target

Project-level metadata applies to every instance; instance metadata is per-VM. Both frequently hold SSH keys, startup scripts, and embedded secrets.

```bash
# Project-wide metadata (SSH keys often live here)
gcloud compute project-info describe --format="yaml(commonInstanceMetadata)"

# Per-instance metadata, including startup/shutdown scripts
gcloud compute instances describe <NAME> --zone <ZONE> \
  --format="yaml(metadata)"
```

From inside a compromised VM, the metadata server reveals identity and tokens directly:

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
```

### Serial port output

Serial console logs often contain boot diagnostics, cloud-init output, and occasionally leaked secrets or tokens:

```bash
gcloud compute instances get-serial-port-output <NAME> --zone <ZONE> --port 1
```

### Bulk automated enumeration

```bash
# ScoutSuite produces a full multi-service GCP posture report
scout gcp --user-account            # or --service-account-key key.json

# Prowler GCP checks (CIS-aligned findings, including compute)
prowler gcp --project-ids <PROJECT>
```

## Misconfigurations & Findings

- **Default service account with broad scope.** Instances running as the Compute Engine default service account (`<projectnumber>-compute@developer.gserviceaccount.com`) with `cloud-platform` scope and the default Editor role - a direct escalation primitive.
- **Secrets in metadata / startup scripts.** API keys, database passwords, and tokens embedded in `startup-script` or custom metadata keys.
- **Project-level SSH keys.** Keys in project metadata grant login to every instance that does not block project keys.
- **Publicly shared images/snapshots** (`allUsers`/`allAuthenticatedUsers` IAM bindings).
- **Shielded VM / Secure Boot disabled**, and **OS Login disabled** in favor of metadata SSH keys.
- **Overly broad firewall rules** mapped to instances via target tags.
- **No serial-port logging restriction**, allowing secrets to leak through serial output.

## Detection & Logging

- **Cloud Audit Logs - Admin Activity** always records write operations; read operations such as `compute.instances.list`, `compute.instances.get`, and `compute.instances.getSerialPortOutput` are recorded under **Data Access** logs only when Data Access audit logging is explicitly enabled for the Compute Engine API. Enabling Data Access logging is what makes recon visible.
- High-volume `*.list` calls across many resource types from a single identity in a short window is a recon signature; correlate by `protoPayload.authenticationInfo.principalEmail`.
- `getSerialPortOutput` and `getIamPolicy` calls on images/snapshots are notable when issued by an identity that does not normally perform them.
- **Security Command Center** flags public images/snapshots, default service account usage, and overly permissive firewall findings.

## Remediation & Hardening

- Enable Data Access audit logs for Compute Engine so read enumeration is captured.
- Replace the default service account on instances with a least-privilege, purpose-built service account; restrict scopes and avoid `cloud-platform` where narrower scopes suffice.
- Remove secrets from metadata and startup scripts; use Secret Manager with workload-scoped access instead.
- Enforce OS Login (`enable-oslogin=true`) and disable project-wide SSH keys; enable Shielded VM and Secure Boot.
- Audit and remove public IAM bindings on images and snapshots.
- Apply least privilege to read roles; `roles/compute.viewer` should be granted only where genuinely required.

## Tools

- Cloud CLI and raw REST for targeted, scriptable enumeration.
- Posture scanners (ScoutSuite, Prowler) for broad CIS-aligned inventory and misconfiguration findings.
- JSON processors for extracting service-account, scope, and metadata fields at scale.

## References

- Instances list API: https://cloud.google.com/compute/docs/reference/rest/v1/instances/list
- gcloud compute instances list: https://cloud.google.com/sdk/gcloud/reference/compute/instances/list
- Metadata overview: https://cloud.google.com/compute/docs/metadata/overview
- Service accounts on instances: https://cloud.google.com/compute/docs/access/service-accounts
- IAM service accounts API: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
- Viewing OS patch / instance data: https://cloud.google.com/compute/docs/instances/viewing-and-applying-os-patch-data
