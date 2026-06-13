---
cstg_id: CSTG-AZURE-AKS-ENUM
title: "AZURE Aks - Enumeration"
provider: azure
service: aks
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.ContainerService/managedClusters/read"
  - "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
  - "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
  - "Microsoft.ContainerService/managedClusters/agentPools/read"
  - "Microsoft.Authorization/roleAssignments/read"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/read"
  - "Microsoft.Network/loadBalancers/read"
  - "Kubernetes RBAC: get/list on pods, secrets, serviceaccounts, configmaps, roles, rolebindings, clusterroles, clusterrolebindings, nodes"
tools:
  - az cli (azure-cli)
  - az aks
  - kubectl
  - Azure REST API
  - Azure Resource Graph
  - kubelet/kube-apiserver
  - MicroBurst
  - Peirates
  - kubeletctl
  - AzureHound
references:
  - "https://learn.microsoft.com/en-us/azure/aks/concepts-clusters-workloads"
  - "https://learn.microsoft.com/en-us/azure/aks/concepts-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/cluster-configuration"
  - "https://learn.microsoft.com/en-us/cli/azure/aks"
  - "https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters"
  - "https://learn.microsoft.com/en-us/azure/aks/use-managed-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview"
  - "https://hackingthe.cloud/azure/"
  - "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
  - "https://github.com/NetSPI/MicroBurst"
license: CC BY-SA 4.0
---

## Summary

Azure Kubernetes Service (AKS) is Microsoft's managed Kubernetes offering. Each cluster is an Azure Resource Manager (ARM) resource of type `Microsoft.ContainerService/managedClusters`, but it also exposes a full Kubernetes control plane (the API server) and a set of worker nodes (agent pools) that are Azure Virtual Machine Scale Sets living in an auto-generated **node resource group** (named `MC_<rg>_<cluster>_<region>` by default). This dual nature — an Azure resource on the outside, a Kubernetes cluster on the inside — means an AKS engagement spans two distinct authorization planes: **Azure RBAC** (who can manage the cluster object, pull credentials, and reach the node resource group) and **Kubernetes RBAC** (who can act inside the cluster once credentials are obtained).

The attacker objective during enumeration is to inventory every AKS cluster in scope; determine its network exposure (public vs. private API server, authorized IP ranges); identify the identities the cluster and its kubelet/nodes run as; map who can pull `clusterUser`/`clusterAdmin` credentials; and, once inside, enumerate Kubernetes namespaces, service accounts, RBAC bindings, secrets, and mounted cloud credentials. This inventory feeds the [privilege escalation](../03-privilege-escalation/azure-aks-privesc.md) and [lateral movement](../04-lateral-movement/azure-aks-lateral.md) phases — the value of a cluster is defined by the managed identities and Kubernetes permissions reachable from a foothold inside it.

## Prerequisites

- Read access to the subscription/resource group to list clusters and their configuration: built-in **Reader** at the relevant scope gives `Microsoft.ContainerService/managedClusters/read`, `.../agentPools/read`, and `Microsoft.Authorization/roleAssignments/read`.
- To retrieve a kubeconfig: the `listClusterUserCredential` action (granted by the **Azure Kubernetes Service Cluster User Role**) or `listClusterAdminCredential` (granted by the **Azure Kubernetes Service Cluster Admin Role**). With local accounts disabled and Entra integration enabled, the user credential yields a kubeconfig whose tokens are still gated by Entra + Azure/Kubernetes RBAC.
- For in-cluster enumeration: Kubernetes RBAC `get`/`list` verbs on the objects of interest. A namespaced **Reader** equivalent (`view` ClusterRole) covers most read operations; cluster-wide reconnaissance of nodes, clusterroles, and all-namespace secrets needs broader read (e.g. the built-in `view` ClusterRole bound cluster-wide, or `cluster-admin`).
- An authenticated Azure context (CLI/PowerShell session, service principal, or a managed-identity token). Pure unauthenticated enumeration is limited to externally exposed API servers and ingress (see Misconfigurations).

## Enumeration

### List clusters and read configuration (Azure plane)

```bash
# All AKS clusters in the current subscription
az aks list -o table

# Across every accessible subscription
for s in $(az account list --query "[].id" -o tsv); do
  az aks list --subscription "$s" \
    --query "[].{name:name, rg:resourceGroup, version:kubernetesVersion, fqdn:fqdn, privateFqdn:privateFqdn, rbac:enableRbac}" -o table
done

# Full detail for one cluster
az aks show -g <resource-group> -n <cluster> -o json
```

Resource Graph gives a tenant-wide sweep in one query:

```bash
az graph query -q "Resources
| where type =~ 'microsoft.containerservice/managedclusters'
| project name, resourceGroup, subscriptionId, location,
          fqdn=properties.fqdn, privateFqdn=properties.privateFQDN,
          apiServerAccess=properties.apiServerAccessProfile,
          aadProfile=properties.aadProfile, identity=identity,
          nodeRG=properties.nodeResourceGroup, localAccounts=properties.disableLocalAccounts"
```

Raw ARM REST:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.ContainerService/managedClusters?api-version=2024-02-01"
```

Key fields to capture from `az aks show`:

- `apiServerAccessProfile.enablePrivateCluster` — true = private API server (reachable only from the VNet/peered networks/private DNS).
- `apiServerAccessProfile.authorizedIpRanges` — IP allow-list on a public API server; empty means the API server is reachable from any IP.
- `aadProfile` — Entra integration (`managed: true`), Azure RBAC for Kubernetes (`enableAzureRbac: true`), and admin group object IDs.
- `disableLocalAccounts` — whether the static `clusterAdmin` (local) kubeconfig is disabled.
- `identity` (cluster control-plane identity) and `identityProfile.kubeletidentity` (the **kubelet identity** used to pull images and that nodes can reach via IMDS).
- `addonProfiles` — managed add-ons (e.g. `azureKeyvaultSecretsProvider`, `omsagent`/monitoring, `azurePolicy`, `ingressApplicationGateway`) each of which may have its own identity.
- `networkProfile` — CNI plugin, network policy engine, outbound type.
- `nodeResourceGroup` — the `MC_*` resource group containing the node VMSS, NICs, and load balancers.

### Enumerate agent pools and the node resource group

```bash
az aks nodepool list -g <rg> --cluster-name <cluster> -o table

# Node VM scale sets, NICs and load balancers live in the node resource group
NODE_RG=$(az aks show -g <rg> -n <cluster> --query nodeResourceGroup -o tsv)
az vmss list -g "$NODE_RG" -o table
az network lb list -g "$NODE_RG" -o table
az network public-ip list -g "$NODE_RG" -o table
```

### Identify the cluster, kubelet, and add-on identities

```bash
# Control-plane (cluster) managed identity and the kubelet identity
az aks show -g <rg> -n <cluster> \
  --query "{clusterIdentity:identity, kubelet:identityProfile.kubeletidentity, addons:addonProfiles}" -o json
```

Resolve each `clientId`/`objectId` to its role assignments to gauge blast radius (see [managed identities enumeration](../02-services/azure-aks-enum.md) techniques and the managed-identity page):

```bash
az role assignment list --assignee <kubelet-objectId> --all -o table
az role assignment list --assignee <cluster-identity-objectId> --all -o table
```

The kubelet identity is the most security-relevant: it is reachable from any pod that can reach the node's Instance Metadata Service (IMDS) endpoint, so any role it holds is exposed to in-cluster workloads.

### Determine who can pull credentials (Azure plane)

```bash
# Who has the actions that mint kubeconfigs for this cluster
CLUSTER_ID=$(az aks show -g <rg> -n <cluster> --query id -o tsv)
az role assignment list --scope "$CLUSTER_ID" --all -o table

# Look specifically for the credential-listing actions / roles:
#   Microsoft.ContainerService/managedClusters/listClusterUserCredential/action
#   Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action
#   Azure Kubernetes Service Cluster Admin Role / Cluster User Role / RBAC Cluster Admin
```

### Obtain a kubeconfig

```bash
# User credential (subject to Entra + Azure/K8s RBAC if integrated)
az aks get-credentials -g <rg> -n <cluster>

# Admin (local) credential — bypasses Entra, fails only if disableLocalAccounts=true
az aks get-credentials -g <rg> -n <cluster> --admin

# Non-interactive Entra login for the cluster (when integrated)
kubelogin convert-kubeconfig -l azurecli
```

### In-cluster Kubernetes enumeration

Once a kubeconfig is loaded, enumerate the Kubernetes plane:

```bash
# What can the current identity do? (self subject access review)
kubectl auth can-i --list
kubectl auth can-i --list --namespace kube-system

# Cluster topology
kubectl get nodes -o wide
kubectl get namespaces
kubectl get pods -A -o wide

# RBAC: roles, bindings, and what is bound to whom
kubectl get clusterroles,clusterrolebindings -o wide
kubectl get roles,rolebindings -A -o wide

# Service accounts and their tokens / automounting
kubectl get serviceaccounts -A
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}'

# Secrets (often the highest-value objects in the cluster)
kubectl get secrets -A
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' | base64 -d  # per key

# ConfigMaps frequently leak endpoints, connection strings, feature flags
kubectl get configmaps -A -o yaml
```

### Workload identity and pod-mounted credentials

```bash
# Service accounts federated to Entra (Azure Workload Identity) carry these annotations/labels
kubectl get serviceaccounts -A -o json | \
  jq '.items[] | select(.metadata.annotations["azure.workload.identity/client-id"]) |
      {ns:.metadata.namespace, name:.metadata.name,
       clientId:.metadata.annotations["azure.workload.identity/client-id"],
       tenant:.metadata.annotations["azure.workload.identity/tenant-id"]}'

# Pods opted into workload identity carry the azure.workload.identity/use=true label
kubectl get pods -A -l azure.workload.identity/use=true -o wide

# SecretProviderClass objects (CSI Key Vault driver) reveal which Key Vault secrets are mounted
kubectl get secretproviderclasses -A -o yaml
```

### Externally observable enumeration

For a public cluster the API server FQDN (`<name>-<hash>.hcp.<region>.azmk8s.io`) is internet-reachable; an unauthenticated probe reveals the Kubernetes version and whether anonymous access is allowed:

```bash
FQDN=$(az aks show -g <rg> -n <cluster> --query fqdn -o tsv)
curl -sk "https://${FQDN}:443/version"
curl -sk "https://${FQDN}:443/api"   # 401/403 expected; 200 indicates anonymous access
```

Ingress/load-balancer public IPs in the node resource group, and any `LoadBalancer`-type services, expose application surface that is enumerable without cluster credentials.

## Misconfigurations & Findings

- **Public API server with no authorized IP ranges.** The Kubernetes API server is reachable from any source IP, exposing the auth surface to the internet. Worse if combined with anonymous-auth enabled.
- **Local accounts not disabled.** With `disableLocalAccounts=false`, anyone holding the cluster admin action can pull a static `clusterAdmin` kubeconfig that bypasses Entra and Conditional Access entirely.
- **Azure RBAC for Kubernetes not enabled / legacy `aadProfile` admin groups overly broad.** Large Entra groups mapped to `cluster-admin`, or reliance on Kubernetes RBAC only, makes access review difficult.
- **Over-privileged kubelet identity.** The kubelet/node identity holds Contributor, AcrPush, Key Vault, Storage, or other broad roles. Because every pod can reach IMDS on the node, this identity is effectively shared with all workloads.
- **`hostNetwork`/`hostPID`/privileged pods and permissive Pod Security.** Pods allowed to run privileged, mount the host filesystem, or share host namespaces enable node takeover and IMDS access from arbitrary code.
- **Automounted default service-account tokens with real permissions.** `automountServiceAccountToken` left on, plus RBAC bound to `system:serviceaccounts` or to default SAs, gives any pod usable API credentials.
- **Secrets stored as plain Kubernetes Secrets.** Base64-only secrets readable by broad RBAC, no encryption-at-rest with a customer-managed key, and connection strings/tokens in ConfigMaps.
- **Workload identity / pod-identity over-grant.** Federated service accounts mapped to identities with broad Azure roles, or wildcard federation subjects (see federated-credential findings on the managed-identity page).
- **Wide outbound and no network policy.** No `NetworkPolicy` enforcement means a compromised pod can reach the API server, IMDS, other namespaces, and Azure data-plane endpoints freely.
- **Old Kubernetes version / unpatched node images** with known control-plane or container-escape CVEs.

## Detection & Logging

- **Azure Activity Logs** record control-plane operations on the cluster resource: `Microsoft.ContainerService/managedClusters/read`, `.../write`, `.../listClusterUserCredential/action`, and `.../listClusterAdminCredential/action`. Credential-listing actions are the key signal that someone is pulling a kubeconfig; bulk `read` against many clusters from one principal indicates reconnaissance.
- **AKS diagnostic settings / control-plane logs** (when enabled) export the Kubernetes audit log (`kube-audit`, `kube-audit-admin`), `kube-apiserver`, `kube-controller-manager`, and `guard` (Entra authz webhook) categories to Log Analytics/Event Hub/Storage. The Kubernetes audit log is where in-cluster enumeration (`list`/`get` on secrets, serviceaccounts, RBAC) is visible — but only if diagnostic settings are configured; by default no Kubernetes audit log is retained.
- **Entra ID sign-in logs** record interactive and service-principal/managed-identity token acquisitions used for `get-credentials` and for Entra-integrated cluster logins (filter on the cluster/kubelet `appId`). **Entra ID audit logs** record changes to the cluster's service principal and app-role assignments.
- **Microsoft Defender for Containers** provides managed detections for AKS: anomalous `kubectl` activity, sensitive secret access, exposed dashboards, crypto-mining, and IMDS access from pods; it ingests both the Kubernetes audit log and node runtime signals.
- Unauthenticated probing of the public API server FQDN appears in API-server logs (when audit logging is on) as anonymous/`401` requests.

## Remediation & Hardening

- Make API servers private (`--enable-private-cluster`) or apply tight `--api-server-authorized-ip-ranges`; never leave a public API server with an empty allow-list.
- Disable local accounts (`--disable-local-accounts`) and enable Entra integration with **Azure RBAC for Kubernetes**, so all access flows through Entra + Conditional Access + Azure RBAC and is auditable.
- Apply least privilege to the cluster and kubelet identities; never grant them Contributor/Owner. Use a dedicated user-assigned kubelet identity scoped only to required ACR/Key Vault/Storage.
- Enforce Pod Security (restricted profile) / Azure Policy for AKS to block privileged, `hostNetwork`, `hostPID`, and host-path pods; restrict who can create such pods.
- Disable `automountServiceAccountToken` by default; bind RBAC narrowly and never to `system:authenticated`/`system:serviceaccounts`.
- Use Azure Key Vault (CSI secrets store) or encryption-at-rest with a customer-managed key instead of plain Kubernetes Secrets; keep secrets out of ConfigMaps.
- Constrain Workload Identity federation subjects to exact service accounts; map federated identities to narrowly scoped Azure roles.
- Enforce default-deny `NetworkPolicy`; block pod egress to IMDS (169.254.169.254) where not required.
- Enable AKS diagnostic settings (kube-audit categories) and Microsoft Defender for Containers; export logs to a SIEM. Keep Kubernetes and node images patched.

## Tools

- **az cli / az aks** — list clusters, read configuration, enumerate node pools, pull kubeconfigs.
- **kubectl** — in-cluster enumeration of namespaces, RBAC, service accounts, secrets, pods; `auth can-i --list` for effective-permission discovery.
- **kubelogin** — convert kubeconfig for non-interactive Entra-integrated logins.
- **Azure Resource Graph** — single-query, tenant-wide cluster inventory.
- **Azure REST API / Microsoft Graph** — raw cluster and identity/role-assignment queries.
- **MicroBurst** — Azure enumeration toolkit including AKS-related discovery.
- **kubeletctl / Peirates** — enumerate and interact with the kubelet API and Kubernetes from a pod foothold.
- **AzureHound** — graph collection of Azure/Entra relationships including cluster and identity edges.

## References

- AKS clusters and workloads concepts — Microsoft Learn
- AKS identity and access concepts — Microsoft Learn
- AKS cluster configuration — Microsoft Learn
- `az aks` command reference — Microsoft Learn
- Managed clusters REST API — Microsoft Learn
- Use a managed identity in AKS — Microsoft Learn
- Azure Workload Identity overview — Microsoft Learn
- Kubernetes RBAC — kubernetes.io
- Azure cloud techniques — hackingthe.cloud
- MicroBurst — NetSPI (GitHub)
