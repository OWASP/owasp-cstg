---
cstg_id: CSTG-AZURE-MANAGED-IDENTITIES-ENUM
title: "AZURE Managed Identities - Enumeration"
provider: azure
service: managed-identities
phase: services
required_access: read-only-audit
required_permissions:
  - "Microsoft.ManagedIdentity/userAssignedIdentities/read"
  - "Microsoft.Authorization/roleAssignments/read"
  - "Microsoft.Compute/virtualMachines/read"
  - "Microsoft.Web/sites/read"
  - "Microsoft.ContainerService/managedClusters/read"
  - "Directory Readers (Entra ID) for service principal lookup"
tools:
  - az cli (azure-cli)
  - Azure REST API
  - Microsoft Graph API
  - MicroBurst
  - ROADtools (roadrecon)
  - AzureHound
  - ScubaGear
references:
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-managed-identities-work-vm"
  - "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-view-managed-identity-service-principal-portal"
  - "https://learn.microsoft.com/en-us/rest/api/managedidentity/user-assigned-identities"
  - "https://hackingthe.cloud/azure/abusing-managed-identities/"
  - "https://github.com/NetSPI/MicroBurst"
  - "https://github.com/dirkjanm/ROADtools"
license: CC BY-SA 4.0
---

## Summary

Azure managed identities are service principals automatically managed by the Azure platform that let a resource (a virtual machine, App Service web app, Function App, Logic App, Automation Account, Azure Kubernetes Service cluster, Container Instance, Data Factory, etc.) obtain Microsoft Entra ID (formerly Azure AD) access tokens without any developer-managed secret. There are two kinds:

- **System-assigned managed identity** — created with, tied to the lifecycle of, and deleted with a single resource. It has a 1:1 relationship with that resource.
- **User-assigned managed identity (UAMI)** — a standalone Azure resource (`Microsoft.ManagedIdentity/userAssignedIdentities`) that can be assigned to one or many resources, surviving independently of any consumer.

Both are backed by an Entra service principal with an `appId` (client ID), an object ID (principal ID), and zero or more Azure RBAC role assignments and/or Entra directory roles and Graph API permissions. The attacker objective during enumeration is to build a complete inventory of every managed identity in scope, map each one to the resources that can request its tokens, and resolve the exact RBAC role assignments, scopes, and directory permissions each identity holds. This inventory directly drives the [privilege escalation](../03-privilege-escalation/azure-managed-identities-privesc.md) and [lateral movement](../04-lateral-movement/azure-managed-identities-lateral.md) phases: a token-granting resource that an operator can reach is only valuable if the identity behind it is over-privileged, and that can only be known by enumerating its assignments.

## Prerequisites

- Read-only access sufficient to list resources and role assignments. The least-privilege read footprint is the built-in **Reader** role at the relevant scope (subscription, resource group, or management group) plus the **Directory Readers** Entra role (or any account that can read the directory) to resolve service principals.
- For a complete picture of an identity's effective permissions, the ability to read role assignments (`Microsoft.Authorization/roleAssignments/read`, included in Reader) and to query Microsoft Graph for the identity's `appRoleAssignments` (Graph application/directory permissions) and Entra directory role memberships.
- An authenticated context: an Azure CLI/PowerShell session, a service principal, or a token already obtained from a managed-identity endpoint (see the lateral-movement page). Pure unauthenticated enumeration of managed identities is not possible.

## Enumeration

### List user-assigned managed identities

User-assigned identities are first-class resources and are listed directly:

```bash
# All UAMIs in the current subscription
az identity list -o table

# Full detail (clientId, principalId, tenantId, resource id) for a single UAMI
az identity show -g <resource-group> -n <identity-name>

# Across all accessible subscriptions
for s in $(az account list --query "[].id" -o tsv); do
  az identity list --subscription "$s" \
    --query "[].{name:name, rg:resourceGroup, clientId:clientId, principalId:principalId}" -o table
done
```

Raw Resource Manager (ARM) REST equivalent:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
```

### Discover system-assigned identities and identity-to-resource bindings

System-assigned identities are not listed by `az identity`; they live inside the `identity` block of each consuming resource. Enumerate per resource type and look for an `identity` property:

```bash
# Virtual machines (both system- and user-assigned)
az vm list --query "[?identity!=null].{name:name, rg:resourceGroup, type:identity.type, principalId:identity.principalId, uami:identity.userAssignedIdentities}" -o json

# VM scale sets
az vmss list --query "[?identity!=null].{name:name, rg:resourceGroup, identity:identity}" -o json

# App Service / Function Apps
az webapp list  --query "[?identity!=null].{name:name, identity:identity}" -o json
az functionapp list --query "[?identity!=null].{name:name, identity:identity}" -o json

# Logic Apps, Automation Accounts, Data Factory, Container Instances, AKS
az logic workflow list --query "[?identity!=null]" -o json 2>/dev/null
az automation account list --query "[?identity!=null]" -o json 2>/dev/null
az datafactory list --query "[?identity!=null]" -o json 2>/dev/null
az container list --query "[?identity!=null]" -o json 2>/dev/null
az aks list --query "[?identity!=null || servicePrincipalProfile!=null].{name:name, identity:identity, kubeletIdentity:identityProfile}" -o json
```

A generic sweep across every resource type using Azure Resource Graph is the most reliable way to find all identity-bearing resources at once:

```bash
az graph query -q "Resources
| where isnotnull(identity)
| project name, type, location, resourceGroup, subscriptionId, identityType=identity.type, principalId=identity.principalId, userAssigned=identity.userAssignedIdentities"
```

For UAMIs, find every resource a given identity is attached to (the "blast radius" of one identity):

```bash
az graph query -q "Resources
| where identity.userAssignedIdentities has '<uami-resource-id>'
| project name, type, resourceGroup"
```

### Resolve the backing service principal

Each managed identity maps to an Entra service principal of type `ManagedIdentity`. Resolve by client ID or list all of them:

```bash
# By client (app) ID returned from az identity show
az ad sp show --id <clientId>

# All managed-identity service principals in the tenant
az ad sp list --all --query "[?servicePrincipalType=='ManagedIdentity'].{displayName:displayName, appId:appId, id:id}" -o table
```

Microsoft Graph raw query:

```bash
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=servicePrincipalType eq 'ManagedIdentity'&\$select=id,appId,displayName"
```

### Enumerate effective permissions of each identity

The value of an identity is its permissions. Enumerate both Azure RBAC (control- and data-plane on resources) and Entra/Graph (directory) permissions.

**Azure RBAC role assignments** (use the identity's `principalId`):

```bash
# All role assignments granted to the identity, across scopes
az role assignment list --assignee <principalId> --all -o table

# Resolve each role's actual actions for over-privilege analysis
az role definition list --name "<RoleName>" \
  --query "[].{name:roleName, actions:permissions[0].actions, dataActions:permissions[0].dataActions}" -o json
```

**Entra directory roles and Graph application permissions** (the high-impact ones):

```bash
# App-role (Graph) permissions granted to the identity's service principal,
# e.g. RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, Directory.ReadWrite.All
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/appRoleAssignments"

# Entra directory role memberships (e.g. Global Administrator, Privileged Role Administrator)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/transitiveMemberOf"
```

### Inspect federated identity credentials

User-assigned identities can be configured with **federated identity credentials** (workload identity federation), allowing external OIDC issuers (GitHub Actions, AKS workload identity, other clouds) to obtain tokens for the identity. Enumerating these reveals trust relationships that extend the identity's reachability outside Azure:

```bash
az identity federated-credential list --identity-name <name> -g <resource-group> -o json
# Raw:
az rest --method get \
  --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<name>/federatedIdentityCredentials?api-version=2023-01-31"
```

## Misconfigurations & Findings

- **Over-privileged identities.** Identities assigned **Owner**, **Contributor**, **User Access Administrator**, or **Role Based Access Control Administrator** at subscription or management-group scope. Contributor and Owner on a resource that runs arbitrary code (VM, Function, Automation) is effectively a path to that identity's full power for anyone who can reach the resource. User Access Administrator / RBAC Administrator allow self-escalation by granting new role assignments.
- **High-impact Graph permissions on a managed identity.** App-role grants such as `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`, or `GroupMember.ReadWrite.All` turn a single compromised resource into a tenant-takeover primitive.
- **Shared user-assigned identity.** One UAMI attached to many resources of differing trust levels (e.g. a build agent VM and a production database host) means compromise of the lowest-trust resource yields the identity's full privilege everywhere.
- **Identity scope mismatch.** A system-assigned identity that needs read on one storage account but holds Contributor on the whole resource group or subscription.
- **Orphaned / dangling federated credentials.** Federated identity credentials whose subject/issuer points at a deleted repo, branch, or external workload that an attacker can recreate, allowing token issuance for the identity from outside Azure.
- **Wildcard or overly broad federation subjects.** Federated credentials with permissive `subject` matching (e.g. any branch of a public fork) granting token access too broadly.
- **Identities with no role assignments but high directory roles.** An identity that appears harmless on the RBAC plane but is a member of a privileged Entra role.

## Detection & Logging

- **Azure Activity Logs** record control-plane reads and writes against `Microsoft.ManagedIdentity/*` and against the `identity` block of resources (e.g. `Microsoft.Compute/virtualMachines/write` that assigns an identity). Listing operations are largely read events; bulk read/enumeration patterns (many `list`/`read` operations from one principal in a short window) are visible.
- **Entra ID audit logs** record creation/modification of service principals, app-role assignment changes, and directory role membership changes for managed identities.
- **Entra ID sign-in logs** record managed-identity token acquisitions as service-principal sign-ins (filter on the identity's `appId`/service principal); this is more relevant to the token-use phases but baselining normal sign-in patterns here aids later detection.
- **Microsoft Defender for Cloud** and **Microsoft Entra Permissions Management** surface over-privileged identities and unused permissions; **ScubaGear** and Azure RBAC review tooling flag broad assignments.
- Enumeration via Graph (`/servicePrincipals`, `/appRoleAssignments`) appears in Entra audit/sign-in logs attributed to the calling principal.

## Remediation & Hardening

- Apply least privilege: scope every managed-identity role assignment to the narrowest resource/scope required, and prefer purpose-built built-in roles over Contributor/Owner.
- Avoid granting managed identities high-impact Graph application permissions; where unavoidable, isolate them and monitor closely.
- Prefer one identity per workload/trust boundary; do not share a single UAMI across resources of differing sensitivity.
- Regularly review and remove unused identities, unused role assignments, and stale federated identity credentials. Constrain federation `subject`/`issuer` to exact repos/branches/workloads.
- Use Azure Policy to deny or alert on assignment of Owner/User Access Administrator to managed identities and to require identities on resources rather than embedded secrets.
- Enable Microsoft Defender for Cloud and periodic access reviews; export Activity and Entra logs to a SIEM for retention and correlation.

## Tools

- **az cli** / **Azure REST API** — list identities, role assignments, resource `identity` blocks, federated credentials.
- **Microsoft Graph API** — resolve service principals, app-role (Graph) permissions, directory role membership.
- **Azure Resource Graph** — single-query sweep for all identity-bearing resources tenant-wide.
- **MicroBurst** — PowerShell toolkit for Azure service and identity enumeration.
- **ROADtools (roadrecon)** — offline Entra directory enumeration including service principals and app-role assignments.
- **AzureHound** — graph-based collection of Azure/Entra relationships including managed identities and their assignments.
- **ScubaGear** / **Defender for Cloud** — configuration and over-privilege assessment.

## References

- Managed identities for Azure resources overview — Microsoft Learn
- How managed identities work with Azure VMs — Microsoft Learn
- View the managed-identity service principal — Microsoft Learn
- User-assigned identities REST API — Microsoft Learn
- Abusing managed identities — hackingthe.cloud
- MicroBurst — NetSPI (GitHub)
- ROADtools — dirkjanm (GitHub)
