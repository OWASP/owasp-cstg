---
cstg_id: CSTG-AZURE-DEVOPS-ENUM
title: "AZURE Devops - Enumeration"
provider: azure
service: devops
phase: services
required_access: read-only-audit
required_permissions:
  - "vso.profile (read profile via PAT/OAuth)"
  - "vso.project (read projects and teams)"
  - "vso.build (read build definitions and logs)"
  - "vso.release (read release definitions)"
  - "vso.code (read repositories and source)"
  - "vso.serviceendpoint (read service connections)"
  - "vso.variablegroups_read (read variable groups)"
  - "vso.agentpools (read agent pools)"
  - "Project Reader / Project Collection Valid Users (UI role)"
tools:
  - "Azure DevOps REST API"
  - "Azure CLI (az devops extension)"
  - "Git CLI"
  - "HTTP client"
references:
  - "https://learn.microsoft.com/en-us/rest/api/azure/devops/"
  - "https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth"
  - "https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables"
  - "https://www.hackingthe.cloud/azure/"
  - "https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-personal-access-tokens-via-api"
license: CC BY-SA 4.0
---

## Summary

Azure DevOps (ADO) is a hosted application lifecycle platform comprising Repos (Git/TFVC), Pipelines (build and release automation), Boards, Artifacts (package feeds), and Test Plans. An organization is the top-level tenant boundary (`https://dev.azure.com/{organization}`), containing one or more **projects**, each holding repositories, pipelines, service connections, variable groups, and agent pools.

From an attacker or assessor perspective, Azure DevOps is one of the highest-value targets in a cloud estate because it sits at the intersection of source code, secrets, and deployment identity. Pipelines frequently hold **service connections** that federate into Azure subscriptions (often as Owner/Contributor), AWS, container registries, and package feeds. Variable groups and pipeline variables hold long-lived secrets. Service principals and managed identities used by pipelines are often over-privileged. As a result, read access to a single project frequently reveals a path to cloud control-plane compromise.

This page covers enumeration of the organization, projects, identities, repositories, pipelines, service connections, secrets storage, agent pools, and the various authentication artifacts (PATs, OAuth tokens, SSH keys, pipeline tokens) that an actor may discover. Enumeration here is intentionally read-only; privilege escalation paths that build on these findings are covered in [azure-devops-privesc.md](../03-privilege-escalation/azure-devops-privesc.md) and persistence in [azure-devops-persistence.md](../06-persistence/azure-devops-persistence.md).

## Prerequisites

- A credential that authenticates to the organization. This can be:
  - A **Personal Access Token (PAT)** supplied as HTTP Basic auth (username blank or arbitrary, password = PAT).
  - An **OAuth 2.0 / Entra ID access token** scoped to `499b84ac-1321-427f-aa17-267ca6975798` (the Azure DevOps resource app ID).
  - Interactive Entra ID session via the web UI.
  - The pipeline-injected **`System.AccessToken`** (the project build service identity) available inside a running pipeline.
- The target organization name and, ideally, at least one project name. Organizations may be discovered via `https://app.vssps.visualstudio.com/_apis/accounts?memberId={userId}`.
- Network egress to `dev.azure.com`, `*.visualstudio.com`, `vssps.dev.azure.com`, and `vsrm.dev.azure.com`.

The REST API base for most resources is `https://dev.azure.com/{org}/{project}/_apis/...`, profile/identity APIs live under `https://vssps.dev.azure.com`, and release endpoints under `https://vsrm.dev.azure.com`. Most calls take `?api-version=7.1`.

## Enumeration

### Identify the authenticated principal and its organizations

```bash
# Who am I (profile)
curl -s -u :$ADO_PAT \
  "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1"

# Organizations the principal can access (memberId from the profile 'id')
curl -s -u :$ADO_PAT \
  "https://app.vssps.visualstudio.com/_apis/accounts?memberId={publicAlias}&api-version=7.1"
```

With the Azure CLI DevOps extension:

```bash
az extension add --name azure-devops
az devops configure --defaults organization=https://dev.azure.com/$ORG
echo $ADO_PAT | az devops login --organization https://dev.azure.com/$ORG
az devops user list --org https://dev.azure.com/$ORG --top 1000
```

### Enumerate projects, teams, and members

```bash
# Projects in the organization
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/projects?api-version=7.1"

az devops project list --org https://dev.azure.com/$ORG

# Teams and members per project
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/teams?api-version=7.1-preview.3"
```

### Enumerate identities, groups, and permissions

User and group membership reveals who holds **Project Collection Administrators**, **Project Administrators**, **Build Administrators**, and **Endpoint Administrators** roles — the high-value targets.

```bash
# Graph: users, groups, service principals, service identities
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/users?api-version=7.1-preview.1"
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/groups?api-version=7.1-preview.1"
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/serviceprincipals?api-version=7.1-preview.1"

# Membership of a specific group descriptor
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/Memberships/{subjectDescriptor}?direction=down&api-version=7.1-preview.1"
```

Permissions are expressed through **security namespaces** and access control lists. Enumerate namespaces (Git Repositories, Build, ServiceEndpoints, Project, etc.) and the ACLs to see who has explicit Allow/Deny on critical tokens:

```bash
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/securitynamespaces?api-version=7.1"
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/accesscontrollists/{namespaceId}?api-version=7.1"
```

### Enumerate repositories and source content

Source code itself is a primary target: hardcoded secrets, `.env` files, deployment scripts, IaC (Terraform/Bicep/ARM), and pipeline YAML referencing secret variables.

```bash
# Repos in a project
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories?api-version=7.1"

# Clone via Git using the PAT as the password
git clone "https://anything:$ADO_PAT@dev.azure.com/$ORG/$PROJECT/_git/$REPO"

# Search across repos for secrets (Code Search extension API)
curl -s -u :$ADO_PAT -H "Content-Type: application/json" \
  "https://almsearch.dev.azure.com/$ORG/_apis/search/codesearchresults?api-version=7.1" \
  -d '{"searchText":"password OR secret OR connectionString OR client_secret","$top":1000}'

# Branches, commit history, and deleted/old branches may retain secrets
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$REPO/refs?api-version=7.1"
```

Review pipeline definition files (`azure-pipelines.yml`, `.azure/`, `templates/`) for referenced variable groups, secure files, and service connection names.

### Enumerate pipelines, builds, and logs

Build and release logs are frequently the richest source of leaked secrets, environment variables, and resource identifiers because logging is verbose and secret masking is imperfect (values echoed indirectly, base64-encoded, or split are not redacted).

```bash
# Build/YAML pipeline definitions
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/build/definitions?api-version=7.1"

# Recent build runs
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/build/builds?api-version=7.1&\$top=200"

# Logs for a build (download every log; grep for tokens, AKV references, IPs)
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/build/builds/{buildId}/logs?api-version=7.1"
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/build/builds/{buildId}/logs/{logId}?api-version=7.1"

# Classic release pipelines (note the vsrm host)
curl -s -u :$ADO_PAT \
  "https://vsrm.dev.azure.com/$ORG/$PROJECT/_apis/release/definitions?api-version=7.1&\$expand=environments"
```

### Enumerate service connections (service endpoints)

Service connections are the bridge from CI/CD into cloud accounts. Each connection's type, authorization scheme, and (critically) whether it is shared across pipelines or grants broad cloud roles should be recorded.

```bash
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
```

Key fields to capture:
- `type`: `azurerm` (Azure Resource Manager), `aws`, `dockerregistry`, `github`, `kubernetes`, `generic`, etc.
- `authorization.scheme`: `ServicePrincipal` (app registration + client secret/cert), `WorkloadIdentityFederation` (OIDC, no stored secret), `ManagedServiceIdentity`, `UsernamePassword`, `Token`.
- `data.subscriptionId` / `scopeLevel` / `serviceprincipalid`: identifies the Entra ID app and the Azure scope it can act on.
- `isShared` / `isReady` and the project references.

Secret material is not returned by this API (it is write-only), but the **identity** (service principal app ID, subscription, scope) is fully enumerable, which directly informs the privesc page.

### Enumerate variable groups, secure files, and secrets storage

```bash
# Variable groups (secret values are masked but names and Key Vault links show)
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/variablegroups?api-version=7.1"

# Secure files (certs, .pfx, keystores stored for pipelines)
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/securefiles?api-version=7.1-preview.1"
```

Variable groups of type `AzureKeyVault` reveal the linked Key Vault and the service connection used to read it — another pivot into Azure.

### Enumerate agent pools and deployment groups

Self-hosted agents run on machines you may be able to reach or that hold cached credentials. Pool and agent enumeration shows the runtime environment for pipelines.

```bash
# Organization-level agent pools
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/distributedtask/pools?api-version=7.1"

# Agents in a pool (OS, version, capabilities, online status)
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/_apis/distributedtask/pools/{poolId}/agents?api-version=7.1&includeCapabilities=true"

# Environments and Kubernetes/VM resources
curl -s -u :$ADO_PAT \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/environments?api-version=7.1-preview.1"
```

### Enumerate feeds and artifacts

```bash
curl -s -u :$ADO_PAT \
  "https://feeds.dev.azure.com/$ORG/_apis/packaging/feeds?api-version=7.1-preview.1"
```

Feeds may allow package overwrite/upstream poisoning and often contain internal packages whose source reveals secrets.

### Enumerate existing access tokens and authorizations

```bash
# PATs owned by the authenticated user (tokenadministration / token API)
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/tokens/pats?api-version=7.1-preview.1"

# OAuth authorizations / SSH public keys on the profile
curl -s -u :$ADO_PAT \
  "https://vssps.dev.azure.com/$ORG/_apis/token/sshpublickeys?api-version=7.1-preview.1"
```

## Misconfigurations & Findings

- **Over-privileged service connections.** `azurerm` connections scoped to a full subscription with Owner/Contributor, reusable across all pipelines (`Grant access permission to all pipelines` enabled), let any pipeline author obtain cloud control-plane access.
- **Secrets in plaintext.** Non-secret pipeline variables, repo files, and build logs containing credentials, connection strings, or PATs. Secret masking gaps where values are transformed before logging.
- **Public or anonymous-readable projects.** Organization setting allowing public projects or anonymous access exposes source and pipelines without authentication.
- **PAT sprawl and over-scoped PATs.** Full-scope PATs (`vso.*` all), long or no expiry, and organization-wide PATs. Lack of PAT lifecycle policy.
- **Weak pipeline authorization controls.** Service connections, variable groups, and agent pools left as "open" (no pipeline approval/checks), allowing untrusted forks/branches to consume privileged resources.
- **Self-hosted agents with ambient credentials.** Agents running on VMs with managed identities, az CLI cached logins, or Docker socket access that pipelines can abuse.
- **Inactive guest/external accounts** retaining Contributor/Project Admin membership.
- **Classic release pipelines** with stored secrets and weaker isolation than YAML pipelines.
- **Key Vault-backed variable groups** whose service connection reads more secrets than the pipeline needs.

## Detection & Logging

Reading these resources generates auditable events. Defenders should monitor:

- **Azure DevOps Auditing** (`https://dev.azure.com/{org}/_settings/audit`, and the Audit REST API `https://auditservice.dev.azure.com/{org}/_apis/audit/auditlog`). Relevant action IDs include `Token.PatCreateEvent`, `Project.AccessGranted`, `Library.ServiceConnectionExecuteAuthorized`, `Git.RepositoryCreated`, and `Pipelines.*`. Enumeration shows up as high-volume read patterns and Code Search queries.
- **Entra ID sign-in logs** for OAuth tokens issued to the Azure DevOps resource (`499b84ac-1321-427f-aa17-267ca6975798`), and conditional-access evaluation for the principal.
- **Entra ID audit logs** for service principal usage tied to `azurerm` connections.
- **Azure Activity Logs** in the *target subscriptions* will show downstream actions performed via service-connection service principals (read events such as `Microsoft.Resources/subscriptions/resourceGroups/read`).
- Bursts of API calls from a single PAT across many projects, especially against `serviceendpoint`, `variablegroups`, `securefiles`, and `build/logs`, are strong enumeration indicators.

## Remediation & Hardening

- Disable public projects and anonymous access at the organization policy level unless explicitly required.
- Enforce **PAT lifecycle policy**: short max lifetime, full-scope PATs disabled, scoped PATs only, and automated revocation of inactive tokens. Restrict PAT creation to specific groups.
- Scope every service connection to the least Azure RBAC role and the narrowest resource scope (resource group, not subscription). Prefer **Workload Identity Federation (OIDC)** over stored service principal secrets.
- Turn off "Grant access permission to all pipelines" for connections, variable groups, secure files, and agent pools; require explicit pipeline authorization plus approvals/checks (branch control, protected resources).
- Store secrets only in Azure Key Vault referenced via least-privileged variable groups; never as plaintext variables or in repos. Enable secret/credential scanning on repos and pipelines.
- Apply Conditional Access (require compliant device / MFA) to the Azure DevOps resource and restrict org access to a single Entra tenant.
- Use Microsoft-hosted agents where possible; for self-hosted, run least-privilege, ephemeral agents without ambient cloud identities.
- Restrict membership of Project Collection Administrators, Project Administrators, Endpoint Administrators, and Build Administrators; review regularly.

## Tools

- Azure DevOps REST API (`dev.azure.com`, `vssps.dev.azure.com`, `vsrm.dev.azure.com`, `feeds.dev.azure.com`, `almsearch.dev.azure.com`)
- Azure CLI with the `azure-devops` extension
- Git CLI (clone over HTTPS using a PAT)
- Generic HTTP client for raw API enumeration

## References

- Azure DevOps REST API reference — https://learn.microsoft.com/en-us/rest/api/azure/devops/
- Azure DevOps OAuth and authentication — https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth
- Permissions and security namespaces — https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions
- Service connections / service endpoints — https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints
- Pipeline variables and secrets — https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables
- Manage PATs via API — https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-personal-access-tokens-via-api
- hackingthe.cloud (Azure) — https://www.hackingthe.cloud/azure/
