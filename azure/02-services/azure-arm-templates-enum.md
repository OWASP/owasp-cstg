---
cstg_id: CSTG-AZURE-ARM-TEMPLATES-ENUM
title: "AZURE Arm Templates - Enumeration"
provider: azure
service: arm-templates
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.Resources/subscriptions/resourceGroups/read"
  - "Microsoft.Resources/deployments/read"
  - "Microsoft.Resources/deployments/operations/read"
  - "Microsoft.Resources/deployments/exportTemplate/action"
  - "Microsoft.Resources/templateSpecs/read"
  - "Microsoft.Resources/templateSpecs/versions/read"
  - "Microsoft.Storage/storageAccounts/listKeys/action (where templates are staged in blobs)"
tools:
  - azure-cli
  - azure-powershell
  - arm-rest-api
  - bicep-cli
  - microburst
  - roadrecon
references:
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/overview"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-history"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-specs"
  - "https://learn.microsoft.com/en-us/rest/api/resources/deployments"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/secure-template-outputs"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Azure Resource Manager (ARM) templates are declarative JSON (or Bicep, which transpiles to JSON) documents that describe the desired state of Azure resources. They are submitted to the Resource Manager control plane as *deployments*, which are first-class resources scoped to a subscription, resource group, management group, or tenant. Every deployment is recorded in **deployment history** and its full request body — including the template, the parameters that were supplied, and the outputs that were produced — is retained and retrievable through the control plane.

This makes ARM templates and their deployment history a high-value enumeration target. A reader with read access to the control plane can reconstruct exactly how an environment was built, recover hardcoded secrets and connection strings left in template parameters or outputs, learn naming conventions and resource topology, identify the identities used to perform deployments, and discover reusable artifacts (Template Specs, linked/nested templates staged in storage) that can later be abused. Because deployment history persists even after the deployed resources are deleted or rotated, it frequently exposes credentials that the operator believes are no longer reachable.

The attacker objective in this phase is reconnaissance: harvest configuration, secrets, identity references, and reusable infrastructure-as-code artifacts from deployment history and template repositories without modifying anything.

## Prerequisites

- Valid credentials for the tenant (user, service principal, or managed identity) with at least read access to one or more subscriptions/resource groups.
- Role assignment granting the deployment-read actions listed in `required_permissions`. The built-in **Reader** role already grants `Microsoft.Resources/deployments/read` and `.../operations/read`, which is sufficient to read deployment history and recover inline secrets. **Contributor** additionally grants `exportTemplate/action`.
- For templates staged as linked/nested artifacts in blob storage, read access (or `listKeys`) to the relevant storage account, or a still-valid SAS token embedded in a deployment.
- Tooling: `az`/`Azure PowerShell`, or any HTTP client able to call the ARM REST API at `https://management.azure.com`.

## Enumeration

### 1. Establish context and list scopes

```bash
az account show -o jsonc
az account list --all -o table
az group list --query "[].{name:name, location:location}" -o table
```

### 2. List deployments at every scope

Deployments exist at subscription, resource group, management group, and tenant scope. Enumerate all four.

```bash
# Resource-group scope
az deployment group list -g <rg> -o table

# Subscription scope
az deployment sub list -o table

# Management-group scope
az deployment mg list --management-group-id <mg> -o table

# Tenant scope
az deployment tenant list -o table
```

Raw REST equivalent (resource-group scope):

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.Resources/deployments?api-version=2021-04-01"
```

### 3. Recover the template, parameters, and outputs of each deployment

The single most valuable call. The deployment's `properties` contains `parameters`, `outputs`, `templateLink`, `dependencies`, and the resolved provider state.

```bash
az deployment group show -g <rg> -n <deployment-name> -o jsonc

# Export the exact template that was deployed (Contributor)
az deployment group export -g <rg> -n <deployment-name> -o json > deploy.json
```

Inspect parameters and outputs directly for plaintext secrets:

```bash
az deployment group show -g <rg> -n <deployment-name> \
  --query "properties.parameters" -o jsonc

az deployment group show -g <rg> -n <deployment-name> \
  --query "properties.outputs" -o jsonc
```

### 4. Read per-resource deployment operations

Operations expose the request/response for each resource in the deployment, including the identity that performed the action and provider-returned values.

```bash
az deployment operation group list -g <rg> -n <deployment-name> -o jsonc
```

REST:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.Resources/deployments/<name>/operations?api-version=2021-04-01"
```

### 5. Export the live template for resources or whole resource groups

Even with no useful deployment history, the current state can be exported as a template (Contributor / `exportTemplate/action`):

```bash
az group export -g <rg> --skip-all-params -o json > rg-current.json
az resource list -g <rg> -o table
```

### 6. Enumerate Template Specs (reusable, versioned templates)

```bash
az ts list -o table
az ts list -g <rg> -o table
az ts show -g <rg> -n <spec-name> --version <ver> -o jsonc
```

REST:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Resources/templateSpecs?api-version=2022-02-01"
```

### 7. Locate linked / nested templates and their staging artifacts

`templateLink.uri` and `parametersLink.uri` in deployment properties frequently point to blob storage URLs that include SAS tokens. Harvest them.

```bash
az deployment group show -g <rg> -n <name> \
  --query "properties.templateLink" -o jsonc

# If a SAS-bearing URI is present, fetch it directly:
curl -s "https://<account>.blob.core.windows.net/<container>/template.json?<sas>"
```

Enumerate storage accounts that may hold staged IaC artifacts:

```bash
az storage account list -o table
az storage blob list --account-name <acct> -c <container> --auth-mode login -o table
```

### 8. Bicep source and pipeline references

If exported templates reference Bicep modules, registry paths (`br:`), or deployment-script resources, note them — they point to source repositories, container registries, or `Microsoft.Resources/deploymentScripts` that execute arbitrary code under an identity.

## Misconfigurations & Findings

- **Plaintext secrets in template parameters.** Passwords, API keys, connection strings, and SAS tokens passed as ordinary `string` parameters instead of `securestring`. These are stored verbatim in deployment history and retrievable for the retention life of the deployment.
- **Secrets in deployment outputs.** Outputs are *never* masked unless the template explicitly references a Key Vault via `secureOutput`/secure output handling. Plaintext keys in `properties.outputs` are a common finding.
- **Persistent history exposure.** Deployment history survives deletion of the deployed resources and rotation of credentials elsewhere, so a secret "removed" from a running resource may still be live in history.
- **SAS tokens in `templateLink`/`parametersLink`.** Long-lived account SAS tokens embedded in linked-template URIs grant continued read (and sometimes write) access to the staging storage account.
- **Public or anonymously readable staging containers** holding linked/nested templates and parameter files.
- **Over-broad role assignments** discoverable via the identity recorded in deployment operations (e.g., a service principal performing deployments turns out to be Owner/Contributor at subscription scope).
- **Template Specs containing embedded secrets or backdoor-friendly defaults** readable by anyone with Reader on the hosting resource group.
- **`deploymentScripts` and `customScriptExtension`** definitions revealing executed commands, downloaded payloads, and the managed identity they run under.
- **Hardcoded principal/object IDs and role-assignment definitions** in templates, revealing the trust topology and candidate escalation targets.

## Exploitation

This page is enumeration-focused; the techniques below are read-only collection that feed later phases.

1. **Harvest secrets from history.** For every deployment at every scope, pull `properties.parameters` and `properties.outputs` and grep recovered JSON for `password`, `key`, `connectionString`, `secret`, `sig=`, `AccountKey`, `SharedAccessKey`, and PEM/JWT patterns.
2. **Reuse SAS tokens.** Any `?sv=...&sig=...` URI found in `templateLink`/`parametersLink` or outputs can be used directly against blob storage to download further artifacts or, if write-capable, to tamper with templates referenced by future deployments.
3. **Map identities.** Read deployment operations to learn which user/service principal/managed identity performs deployments; this is the identity to target for privilege escalation and for the persistence techniques in [ARM Templates - Persistence](../06-persistence/azure-arm-templates-persistence.md).
4. **Recover topology for lateral movement.** Exported templates give exact resource names, private IPs, subnet layout, Key Vault names, storage account names, and dependency graphs — a complete blueprint of the environment.
5. **Stage reusable artifacts.** Catalog Template Specs and linked templates; a writable one becomes a persistence/escalation vector covered in the persistence page.

## Detection & Logging

- **Azure Activity Logs** record control-plane reads against `Microsoft.Resources/deployments` operations. High-volume `deployments/read`, `deployments/operations/read`, `deployments/exportTemplate/action`, and `resourceGroups/exportTemplate/action` from a single principal — especially across many resource groups or subscriptions in a short window — is a strong reconnaissance signal.
- `Microsoft.Resources/templateSpecs/read` enumeration spikes likewise indicate IaC artifact harvesting.
- **Entra ID sign-in logs** correlate the ARM activity to a principal, source IP, device, and conditional-access posture; look for service principals or managed identities performing broad read sweeps outside their normal pattern.
- Storage **diagnostic logs** (`StorageRead`) capture blob GETs against staging containers, including SAS-authenticated requests — useful for catching SAS-token reuse harvested from `templateLink`.
- Managed detections: Microsoft Defender for Cloud and Microsoft Sentinel analytics rules can flag anomalous mass enumeration of deployment history and template exports; correlate Activity Log `read`/`exportTemplate` events with sign-in anomalies.

## Remediation & Hardening

- **Never pass secrets as plaintext parameters.** Use `securestring`/`secureObject`, and source secrets at deploy time from Key Vault via `reference` to a Key Vault secret rather than inlining values.
- **Do not emit secrets as outputs.** If an output must carry a secret, use a Key Vault reference so the value is not stored in history.
- **Purge or restrict deployment history** that contains legacy plaintext secrets; treat any secret ever present in history as compromised and rotate it.
- **Avoid SAS tokens in `templateLink`.** Prefer user-delegation SAS with short lifetimes, private endpoints, or managed-identity-authenticated linked templates; never commit account-key SAS to history.
- **Scope roles tightly.** Grant Reader/Contributor at the narrowest scope; audit who holds `exportTemplate/action`.
- **Lock down staging storage:** disable anonymous blob access, restrict network access, and rotate account keys that have leaked into history.
- **Scan IaC in CI** for hardcoded secrets before deployment so they never reach Resource Manager.

## Tools

- **azure-cli** (`az deployment ... show/export`, `az ts`, `az group export`) — primary enumeration interface.
- **azure-powershell** (`Get-AzResourceGroupDeployment`, `Get-AzResourceGroupDeploymentOperation`, `Export-AzResourceGroup`) — equivalent cmdlets.
- **arm-rest-api** — raw `management.azure.com` calls for scripted, paginated harvesting.
- **bicep-cli** — decompile exported JSON to readable Bicep for analysis.
- **microburst** — Azure-focused PowerShell toolkit for enumerating subscriptions, storage, and exposed artifacts.
- **roadrecon** — Entra ID reconnaissance to correlate deployment identities with directory roles.

## References

- Azure Resource Manager templates overview — Microsoft Learn
- Deployment history and `Get`/`exportTemplate` operations — Microsoft Learn
- Template Specs — Microsoft Learn
- Deployments REST API reference — Microsoft Learn
- Secure handling of template parameters and outputs — Microsoft Learn
- hackingthe.cloud — Azure techniques index
