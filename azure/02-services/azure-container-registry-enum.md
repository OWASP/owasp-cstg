---
cstg_id: CSTG-AZURE-CONTAINER-REGISTRY-ENUM
title: "AZURE Container Registry - Enumeration"
provider: azure
service: container-registry
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.ContainerRegistry/registries/read
  - Microsoft.ContainerRegistry/registries/listCredentials/action
  - Microsoft.ContainerRegistry/registries/metadata/read
  - Microsoft.ContainerRegistry/registries/pull/read
tools:
  - Azure CLI (az acr)
  - Azure REST API / ARM API
  - Docker / OCI client
  - ORAS (OCI Registry As Storage) client
  - crane / skopeo
references:
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-roles
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
  - https://learn.microsoft.com/en-us/rest/api/containerregistry/
  - https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
  - https://hackingthe.cloud/azure/
license: CC BY-SA 4.0
---

## Summary

Azure Container Registry (ACR) is a managed OCI-compliant registry for storing
and distributing container images, Helm charts, and other OCI artifacts. A single
registry is identified by a login server in the form `<name>.azurecr.io` and is
backed by Azure-managed storage. ACR is a high-value target because container
images frequently embed secrets (cloud credentials, API keys, connection strings,
private keys), because images pulled by ACR consumers run in privileged contexts
(AKS nodes, Container Instances, App Service, Functions), and because the registry
control plane exposes credential-issuing operations that can be abused for lateral
movement and persistence.

Enumeration of ACR spans two distinct planes:

- **Control plane (Azure Resource Manager / Entra ID):** registry resources,
  SKU/tier, network rules, admin-user state, replication, webhooks, scope maps,
  tokens, role assignments, and managed-identity bindings. Reached via ARM
  (`management.azure.com`) and authenticated with Entra ID tokens.
- **Data plane (the registry endpoint):** repositories, tags, manifests, image
  layers, artifact metadata, and the contents of the images themselves. Reached
  via the registry login server (`<name>.azurecr.io`) using the OCI Distribution
  and ACR-specific `/acr/v1/` APIs.

This page covers read-only enumeration of both planes. The goal is to inventory
registries, identify weak authentication and network posture, and discover
secrets and sensitive material exposed inside images and registry configuration,
without modifying any resource.

## Prerequisites

- Valid Entra ID principal (user, service principal, or managed identity) with at
  least `Reader` on the subscription, resource group, or registry for control-plane
  enumeration; or
- Data-plane credentials: an Entra ID token with `AcrPull`/`Reader`, an ACR token
  (scope-map based), the registry **admin** username/password, or a credential
  harvested from a CI/CD pipeline, Kubernetes pull secret, or container host.
- Tooling: Azure CLI (`az acr`), a Docker/OCI client, and optionally `oras`,
  `crane`, or `skopeo` for direct registry interaction. The ARM REST API can be
  driven with any HTTP client carrying a bearer token.

Note that data-plane access does not require control-plane permissions, and vice
versa. A pull secret recovered from a workload may permit full image enumeration
even where the principal cannot see the registry resource in ARM.

## Enumeration

### Control plane: discover registries

List all registries visible to the current principal across subscriptions:

```bash
az account list --query "[].id" -o tsv | while read SUB; do
  az acr list --subscription "$SUB" \
    -o table 2>/dev/null
done

# Detail for one registry (login server, SKU, admin-user state, identity)
az acr show -n <registry> -o json
```

Equivalent ARM REST calls:

```http
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01
GET https://management.azure.com/{registryId}?api-version=2023-07-01
```

Key fields to record from the registry resource:

- `properties.loginServer` — the data-plane endpoint.
- `properties.adminUserEnabled` — `true` indicates a static admin
  username/password pair exists (see Misconfigurations).
- `sku.name` — `Basic`/`Standard`/`Premium`. Only `Premium` supports private
  endpoints, network rules, scope maps/tokens, customer-managed keys, content
  trust, and geo-replication; lower tiers cannot be network-restricted.
- `identity` — system- or user-assigned managed identities attached to the
  registry (used by ACR Tasks and for pulling base images).
- `properties.networkRuleSet`, `properties.publicNetworkAccess`,
  `properties.networkRuleBypassOptions` — network exposure.
- `properties.policies.exportPolicy`, `properties.policies.quarantinePolicy`,
  `properties.policies.trustPolicy`, `properties.anonymousPullEnabled`,
  `properties.zoneRedundancy`.

### Control plane: credentials, tokens, scope maps, and identities

```bash
# Admin credentials (only if adminUserEnabled == true)
az acr credential show -n <registry> -o json

# Scope maps (Premium) - define repository/action grants
az acr scope-map list -r <registry> -o table
az acr scope-map show -r <registry> -n <scopeMap> -o json

# Tokens bound to scope maps
az acr token list -r <registry> -o table
az acr token show -r <registry> -n <token> -o json

# Role assignments on the registry (who has AcrPull/AcrPush/Owner/etc.)
az role assignment list --scope $(az acr show -n <registry> --query id -o tsv) -o table
```

The built-in ACR data roles to look for in assignments:

| Role | Data-plane effect |
| --- | --- |
| `AcrPull` | Pull images/artifacts |
| `AcrPush` | Pull and push |
| `AcrDelete` | Delete images/artifacts |
| `AcrImageSigner` | Sign images (content trust) |
| `Owner` / `Contributor` | Full control incl. listing credentials, enabling admin user |
| `AcrQuarantineReader` / `AcrQuarantineWriter` | Quarantine workflow |

### Control plane: webhooks, replications, tasks

```bash
# Webhooks - reveal downstream endpoints and may leak secrets in custom headers
az acr webhook list -r <registry> -o table
az acr webhook show  -r <registry> -n <webhook> -o json
az acr webhook get-headers -r <registry> -n <webhook>   # custom headers/secrets

# Geo-replications (Premium)
az acr replication list -r <registry> -o table

# ACR Tasks - build/automation definitions, often reference identities & secrets
az acr task list -r <registry> -o table
az acr task show -r <registry> -n <task> -o json
az acr task list-runs -r <registry> -o table
```

ACR Tasks are particularly valuable: a task definition can reference a managed
identity, source repositories, and inline/keyvault-backed secrets, and task run
logs may contain build-time secrets.

### Data plane: authenticate to the registry endpoint

Data-plane enumeration requires exchanging an Entra ID token for an ACR refresh
token, or using admin/token credentials directly:

```bash
# Entra ID -> ACR token exchange handled transparently by the CLI
az acr login -n <registry>

# Obtain only the access token (no docker daemon needed)
az acr login -n <registry> --expose-token

# Direct credential login (admin user or scope-map token)
docker login <registry>.azurecr.io -u <user> -p <password_or_token>
```

The raw token exchange (useful for tooling that talks to the API directly):

```http
POST https://<registry>.azurecr.io/oauth2/exchange
  grant_type=access_token&service=<registry>.azurecr.io&access_token=<AAD_token>
# returns an ACR refresh token

POST https://<registry>.azurecr.io/oauth2/token
  grant_type=refresh_token&service=<registry>.azurecr.io&scope=repository:*:*&refresh_token=<rt>
# returns a scoped access token for the Distribution API
```

### Data plane: repositories, tags, manifests

```bash
# List repositories
az acr repository list -n <registry> -o table

# List tags and their detail (timestamps, digests, signed state)
az acr repository show-tags -n <registry> --repository <repo> --detail -o json

# Show manifests for a repository (digests, architecture, last-updated)
az acr manifest list-metadata -r <registry> -n <repo> -o json

# Inspect a specific image/tag
az acr repository show -n <registry> --image <repo>:<tag> -o json
```

Direct OCI Distribution / ACR `/acr/v1/` API:

```http
GET https://<registry>.azurecr.io/v2/_catalog
GET https://<registry>.azurecr.io/acr/v1/<repo>/_tags
GET https://<registry>.azurecr.io/v2/<repo>/tags/list
GET https://<registry>.azurecr.io/v2/<repo>/manifests/<tag>
   Accept: application/vnd.docker.distribution.manifest.v2+json
```

With `crane`/`skopeo`:

```bash
crane catalog <registry>.azurecr.io
crane ls <registry>.azurecr.io/<repo>
skopeo list-tags docker://<registry>.azurecr.io/<repo>
skopeo inspect docker://<registry>.azurecr.io/<repo>:<tag>
```

### Data plane: inspect image contents for secrets

The most impactful enumeration step is reading what is inside the images.
Pull and dissect filesystem layers and image configuration:

```bash
# Pull without running
crane pull <registry>.azurecr.io/<repo>:<tag> image.tar
# or: skopeo copy docker://<registry>.azurecr.io/<repo>:<tag> oci:./image

# Image config exposes ENV vars, ENTRYPOINT, CMD, build history
crane config <registry>.azurecr.io/<repo>:<tag> | jq '.config.Env, .history'
docker history <registry>.azurecr.io/<repo>:<tag> --no-trunc
```

Targets inside images and their metadata:

- Build-time `ARG`/`ENV` values and `RUN` commands captured in image history
  (e.g. cloud keys passed as build args, `curl` of secrets).
- Files under `/root/.aws/`, `/root/.azure/`, `/home/*/.config/`, `~/.docker/config.json`,
  `~/.kube/config`, `.npmrc`, `.git-credentials`, `.netrc`.
- Application config: `appsettings*.json`, `.env`, `web.config`, `application.properties`.
- Embedded private keys, certificates, JWTs, and connection strings.
- Cached package-manager credentials and CI tokens.
- Non-distributable / referrer artifacts (signatures, SBOMs, provenance) via the
  OCI Referrers API: `GET /v2/<repo>/referrers/<digest>`.

### Anonymous and unauthenticated checks

If `properties.anonymousPullEnabled` is `true`, the Distribution API may be
queried without credentials. Always probe:

```bash
curl -s https://<registry>.azurecr.io/v2/                # 200 vs 401
curl -s https://<registry>.azurecr.io/v2/_catalog
```

A `200` (rather than `401 Www-Authenticate`) on `/v2/` indicates anonymous pull
is enabled and the registry is effectively public.

## Misconfigurations & Findings

- **Admin user enabled (`adminUserEnabled: true`).** Creates a static, shared,
  long-lived username/password with full push/pull. These credentials are not
  tied to an identity, bypass Entra ID conditional access, and are routinely
  copied into pipelines and pull secrets. Flag any registry with the admin user
  enabled.
- **Anonymous pull enabled.** Exposes all repositories and image contents to the
  internet with no authentication, leaking any embedded secrets.
- **Public network access unrestricted.** Basic/Standard SKUs cannot be network
  restricted at all; Premium registries with `publicNetworkAccess: Enabled` and
  no `networkRuleSet` are reachable from anywhere.
- **Secrets baked into images.** Credentials in ENV/ARG, config files, or layer
  history. The single highest-impact ACR finding.
- **Over-broad role assignments.** `AcrPush`/`Contributor`/`Owner` granted to
  broad groups, or `AcrPull` granted at subscription scope.
- **Scope-map tokens that are over-scoped or never expire.** Tokens with
  `repositories/*` content/write actions, or with no password expiry.
- **Webhooks with secrets in custom headers**, or pointing at attacker-reachable
  endpoints.
- **Export policy enabled / no quarantine / content trust disabled**, permitting
  unrestricted image export and unsigned-image promotion.
- **Managed identity attached to the registry with broad Azure RBAC**, reachable
  via ACR Tasks (see the privilege-escalation page).

## Detection & Logging

Enumeration of ACR is observable in:

- **Azure Activity Logs** — control-plane operations such as
  `Microsoft.ContainerRegistry/registries/read`,
  `.../listCredentials/action`, `.../tokens/read`, `.../scopeMaps/read`,
  `.../webhooks/getCallbackConfig/action`, `.../generateCredentials/action`.
  Listing admin credentials is a notable signal.
- **ACR diagnostic logs** (`ContainerRegistryLoginEvents`,
  `ContainerRegistryRepositoryEvents`) sent to Log Analytics / Event Hub /
  storage — record login, pull, push, and delete events on the data plane,
  including source IP and the authenticated identity/token.
- **Entra ID sign-in and audit logs** — token issuance, the
  `oauth2/exchange` flow surfaces as a sign-in to the registry resource, and
  failed authentication attempts.

Note that data-plane pulls are only logged if ACR diagnostic settings are
configured; absence of diagnostic settings is itself a gap.

## Remediation & Hardening

- Disable the admin user (`az acr update -n <r> --admin-enabled false`); use
  Entra ID identities or short-lived scope-map tokens instead.
- Disable anonymous pull unless the registry is intentionally public.
- Use the Premium SKU with private endpoints and `networkRuleSet` default-deny;
  set `publicNetworkAccess: Disabled`.
- Apply least-privilege RBAC: grant `AcrPull` only, scoped to the registry, and
  reserve `AcrPush`/delete for pipelines using workload identity federation.
- Use scope maps/tokens with narrow repository scopes and short expiries.
- Keep secrets out of images: use build secrets that are not persisted, scan
  images in CI, and rotate any credential found in a layer.
- Enable diagnostic settings to capture login/repository events centrally.
- Enable content trust/quarantine and restrict export where supported.

## Tools

- Azure CLI (`az acr`) — control- and data-plane enumeration.
- Azure REST / ARM API — scripted enumeration with bearer tokens.
- Docker / OCI clients — login and pull.
- ORAS — enumerate and pull arbitrary OCI artifacts.
- `crane` / `skopeo` — catalog, list-tags, inspect, and pull without a daemon.
- Image/secret scanners — inspect pulled layers for credentials.

## References

- Azure Container Registry overview — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro
- ACR roles and permissions — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-roles
- ACR authentication options — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
- ACR REST API reference — https://learn.microsoft.com/en-us/rest/api/containerregistry/
- ACR Tasks overview — https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/

See also: [Container Registry - Privilege Escalation](../03-privilege-escalation/azure-container-registry-privesc.md) and [Container Registry - Persistence](../06-persistence/azure-container-registry-persistence.md).
