---
cstg_id: CSTG-GCP-GKE-ENUM
title: "GCP Gke - Enumeration"
provider: gcp
service: gke
phase: services
required_access: read-only-audit
required_permissions:
  - container.clusters.list
  - container.clusters.get
  - container.clusters.getCredentials
  - container.operations.list
  - container.nodePools.list
  - compute.instances.list
  - compute.instanceGroupManagers.list
  - iam.serviceAccounts.list
  - resourcemanager.projects.get
  - serviceusage.services.list
tools:
  - gcloud CLI
  - kubectl
  - Google Kubernetes Engine REST API
  - ScoutSuite
  - Prowler
  - kube-hunter
  - kubeaudit
  - rbac-lookup / rbac-tool
references:
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview"
  - "https://cloud.google.com/kubernetes-engine/docs/reference/rest"
  - "https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/access-scopes"
  - "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
  - "https://hackingthe.cloud/gcp/"
  - "https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/"
license: CC BY-SA 4.0
---

## Summary

Google Kubernetes Engine (GKE) is Google Cloud's managed Kubernetes service. A
GKE cluster is a hybrid security domain: it sits inside a GCP project and
inherits that project's IAM, networking, and service-account model, while also
running its own Kubernetes control plane with a completely separate
authorization layer (Kubernetes RBAC), its own identities (ServiceAccounts,
nodes, users), and its own secret store (etcd). Effective access to a workload
is therefore the *intersection and union* of two distinct authorization
systems, and an assessment that only enumerates one of them will miss most of
the real attack surface.

The objective of this enumeration phase is to map both planes completely: the
GCP-side view (which clusters exist, their node pools, the node and workload
service accounts, access scopes, network exposure, and the GCP IAM principals
who can reach the API server) and the in-cluster view (namespaces, RBAC roles
and bindings, ServiceAccounts and their tokens, Workload Identity mappings,
secrets, pod security posture, and exposed services). This dual map feeds the
privilege-escalation analysis
([gcp-gke-privesc.md](../03-privilege-escalation/gcp-gke-privesc.md)) and the
lateral-movement analysis
([gcp-gke-lateral.md](../04-lateral-movement/gcp-gke-lateral.md)): a node's
attached service account, a pod's Workload Identity binding, or an overly broad
RBAC role each becomes a bridge between Kubernetes and the wider GCP project.

## Prerequisites

Authenticated access to the target GCP project with at least read-only
visibility into GKE and (ideally) the cluster API. On the GCP side, the
predefined `roles/container.viewer` plus `roles/viewer` grant the
`container.clusters.list/get` and `compute.instances.list` permissions used
below. Reaching the Kubernetes API additionally requires
`container.clusters.getCredentials` (to fetch a kubeconfig) and at least one
RBAC binding inside the cluster - note that `getCredentials` only retrieves
connection credentials; what those credentials can *do* is governed by
Kubernetes RBAC, which must be enumerated separately.

Establish the active identity and accessible scope first:

```bash
gcloud auth list
gcloud config get-value project
gcloud config get-value account

# Which GKE-related APIs are enabled in scope?
gcloud services list --enabled --project <PROJECT_ID> | grep -Ei 'container|gke'
```

## Enumeration

### GCP-side cluster inventory

```bash
# All clusters in the project, across all locations
gcloud container clusters list --project <PROJECT_ID> \
  --format="table(name,location,currentMasterVersion,currentNodeVersion,status,endpoint)"

# Full cluster manifest - the single richest artifact for posture review
gcloud container clusters describe <CLUSTER> \
  --location <LOC> --project <PROJECT_ID> --format=json
```

The describe output exposes the entire security posture. Inspect in particular:

- `privateClusterConfig` - whether the control-plane endpoint is private,
  and the `masterIpv4CidrBlock`.
- `masterAuthorizedNetworksConfig` - the CIDR allowlist for API access (absent
  or `0.0.0.0/0` means the public endpoint is reachable from anywhere).
- `masterAuth` - presence of `clientCertificate` / `clusterCaCertificate`;
  legacy basic-auth (`username`/`password`) and client-cert issuance should be
  empty on modern clusters.
- `networkConfig.datapathProvider`, `networkPolicy` - whether network policy /
  Dataplane V2 is enforced.
- `legacyAbac.enabled` - legacy ABAC must be `false`.
- `nodeConfig.serviceAccount` and `nodeConfig.oauthScopes` - the node identity
  and its access scopes (see below).
- `workloadIdentityConfig.workloadPool` - whether Workload Identity is enabled.
- `shieldedNodes`, `binaryAuthorization`, `databaseEncryption` (etcd
  application-layer encryption), `releaseChannel`, and `loggingConfig` /
  `monitoringConfig`.

### Node pools, nodes, and node identity

```bash
gcloud container node-pools list --cluster <CLUSTER> \
  --location <LOC> --project <PROJECT_ID>

gcloud container node-pools describe <POOL> --cluster <CLUSTER> \
  --location <LOC> --project <PROJECT_ID> \
  --format="value(config.serviceAccount, config.oauthScopes, config.metadata)"

# Underlying GCE VMs backing the nodes (these are normal Compute instances)
gcloud compute instances list --project <PROJECT_ID> \
  --filter="name~gke-${CLUSTER}" \
  --format="table(name,zone,serviceAccounts[].email,serviceAccounts[].scopes)"
```

Two node-level findings matter most. First, the **node service account**: if a
node pool runs as the *default Compute Engine service account*
(`<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`), every pod that can
reach the node metadata server can mint tokens for an identity that is granted
`roles/editor` by default. Second, the **OAuth access scopes**: a node created
with `https://www.googleapis.com/auth/cloud-platform` exposes the full API
surface of the node SA to any pod that reads metadata, regardless of how
narrowly that SA's IAM is scoped.

### Raw GKE REST API

```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://container.googleapis.com/v1/projects/<PROJECT_ID>/locations/-/clusters"
```

### Obtaining cluster credentials

```bash
gcloud container clusters get-credentials <CLUSTER> \
  --location <LOC> --project <PROJECT_ID>
# Writes a kubeconfig context using the gke-gcloud-auth-plugin for token exchange.
```

If the cluster endpoint is private and not reachable directly, enumeration of
the control plane may require a foothold inside the VPC (a bastion, a Cloud
Shell with a peering, or a compromised node) - see the lateral-movement page.

### In-cluster discovery (Kubernetes plane)

Once a kubeconfig is active, enumerate the Kubernetes authorization model. Begin
by establishing what the current identity is allowed to do:

```bash
kubectl auth whoami
kubectl auth can-i --list                          # current namespace
kubectl auth can-i --list --all-namespaces 2>/dev/null
kubectl auth can-i '*' '*' --all-namespaces        # cluster-admin check
```

Then map the cluster's structure and RBAC:

```bash
kubectl get namespaces
kubectl get nodes -o wide
kubectl get pods --all-namespaces -o wide
kubectl get serviceaccounts --all-namespaces

# RBAC: roles, cluster roles, and the bindings that grant them
kubectl get clusterroles
kubectl get clusterrolebindings -o wide
kubectl get roles --all-namespaces
kubectl get rolebindings --all-namespaces -o wide

# Expand a specific role to its rules
kubectl get clusterrole cluster-admin -o yaml
kubectl describe clusterrolebinding <BINDING>
```

### Secrets, config, and Workload Identity mappings

```bash
# Secrets are the highest-value in-cluster target (SA tokens, registry creds, app keys)
kubectl get secrets --all-namespaces
kubectl get secret <NAME> -n <NS> -o jsonpath='{.data}' | base64 -d 2>/dev/null

# ConfigMaps frequently leak endpoints, connection strings, and tokens
kubectl get configmaps --all-namespaces -o yaml

# Workload Identity: which KSA is bound to which GCP SA?
kubectl get serviceaccount <KSA> -n <NS> -o yaml   # look for the
#   iam.gke.io/gcp-service-account annotation
```

A Kubernetes ServiceAccount carrying the
`iam.gke.io/gcp-service-account: <GSA_EMAIL>` annotation is the explicit bridge
from a pod to a GCP identity; correlate each such mapping with that GSA's IAM
roles (enumerated per [gcp-iam-enum.md](gcp-iam-enum.md)) to score the blast
radius of compromising a pod in that namespace.

### Exposed services and ingress

```bash
kubectl get services --all-namespaces -o wide       # LoadBalancer / NodePort externals
kubectl get ingress --all-namespaces
kubectl get endpoints --all-namespaces
```

## Misconfigurations & Findings

- **Public control-plane endpoint without Master Authorized Networks.** A
  public API server endpoint with no CIDR allowlist (or `0.0.0.0/0`) is
  internet-reachable; combined with any token leak it is directly exploitable.
- **Node pool using the default Compute service account with broad scopes.**
  The default SA holds `roles/editor`; nodes created with the
  `cloud-platform` scope expose that to every pod via the metadata server.
- **Workload Identity disabled.** Without Workload Identity, pods fall back to
  the node SA, collapsing per-workload least privilege into a single node-wide
  identity.
- **Legacy ABAC or legacy metadata endpoints enabled.** `legacyAbac.enabled`
  true, or the legacy (`v1beta1`) metadata API / unprotected metadata, allow
  pods to read node credentials and bypass Workload Identity.
- **Overly broad RBAC.** `cluster-admin` bound to broad groups,
  `system:authenticated`, or default ServiceAccounts; wildcard verbs/resources
  in custom roles; `bind`, `escalate`, or `impersonate` granted.
- **Default ServiceAccount auto-mounting tokens** into pods that do not need API
  access (`automountServiceAccountToken` not disabled).
- **Secrets unencrypted at the application layer** (no `databaseEncryption`
  with a Cloud KMS key) and broadly readable via RBAC.
- **No Pod Security Standards / admission control**, permitting privileged
  pods, `hostPath`, host namespaces, and `hostNetwork`.
- **Shielded GKE nodes / Binary Authorization disabled**, weakening node
  integrity and image provenance guarantees.

## Detection & Logging

GKE produces audit data on both planes, all surfaced through **Cloud Audit
Logs**:

- **GCP control-plane operations** (`google.container.v1.ClusterManager.*`:
  CreateCluster, GetCluster, GetJSONWebKeys, SetNodePoolManagement, etc.) appear
  as Admin Activity logs and are always on.
  `container.clusters.getCredentials` invocations are visible here and are a
  reliable signal that someone is preparing to talk to the API server.
- **Kubernetes API server audit logs** are exported to Cloud Logging under the
  `k8s.io` / `k8s_cluster` resource type. `get`/`list` of secrets,
  `can-i`-style `SelfSubjectAccessReview` and `SelfSubjectRulesReview`
  creations, and RBAC reads are recorded here, including the requesting user and
  source IP.

```bash
# GCP-side: who fetched cluster credentials?
gcloud logging read \
  'protoPayload.methodName="google.container.v1.ClusterManager.GetCluster"
   OR protoPayload.methodName:"getCredentials"' \
  --project=<PROJECT_ID> --freshness=7d

# Kubernetes-side: secret reads and access reviews
gcloud logging read \
  'resource.type="k8s_cluster"
   AND (protoPayload.methodName="io.k8s.core.v1.secrets.get"
        OR protoPayload.methodName="io.k8s.authorization.v1.selfsubjectrulesreviews.create")' \
  --project=<PROJECT_ID> --freshness=7d --format=json
```

- High-volume `can-i`/access-review activity, broad secret listing, or `kubectl
  get ... --all-namespaces` sweeps are strong reconnaissance indicators.
- Security Command Center, GKE Security Posture, and Event Threat Detection
  surface anomalous Kubernetes activity, public endpoint exposure, and known
  attacker behaviours.

## Remediation & Hardening

- Make the control plane **private** and restrict the API endpoint with
  **Master Authorized Networks**.
- Run node pools with a **dedicated, minimally scoped service account**, never
  the default Compute SA, and avoid the `cloud-platform` access scope.
- Enable **Workload Identity** cluster-wide and bind each KSA to a least-
  privilege GSA; disable token auto-mount where not required.
- Enforce **RBAC least privilege**; remove `cluster-admin` from broad subjects;
  forbid wildcard rules and `bind`/`escalate`/`impersonate` except where
  essential.
- Enable **application-layer secret encryption** with a Cloud KMS key.
- Enforce **Pod Security Standards** (or a policy admission controller),
  **Shielded GKE Nodes**, and **Binary Authorization**.
- Disable legacy ABAC and legacy/unprotected metadata; keep clusters on a
  **release channel** for timely patching.
- Ensure Kubernetes API server audit logs are exported and retained.

## Tools

- **gcloud CLI** and the **GKE REST API** for GCP-side inventory.
- **kubectl** with `auth can-i`/`whoami` for in-cluster authorization mapping.
- **ScoutSuite** and **Prowler** for automated GKE posture and exposure audits.
- **kube-hunter** for control-plane and node exposure discovery.
- **kubeaudit** and **rbac-lookup / rbac-tool** for RBAC and pod-security review.

## References

- GKE overview - https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview
- GKE REST reference - https://cloud.google.com/kubernetes-engine/docs/reference/rest
- Cluster access for kubectl - https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl
- Workload Identity - https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- Node access scopes - https://cloud.google.com/kubernetes-engine/docs/concepts/access-scopes
- Kubernetes RBAC - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Hacking the Cloud (GCP) - https://hackingthe.cloud/gcp/
- Rhino Security Labs - Kubernetes privilege escalation - https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/
