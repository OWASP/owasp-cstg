---
cstg_id: CSTG-GCP-ORG-POLICY-ENUM
title: "GCP Org Policy - Enumeration"
provider: gcp
service: org-policy
phase: services
required_access: read-only-audit
required_permissions:
  - orgpolicy.policy.get
  - orgpolicy.policies.list
  - orgpolicy.constraints.list
  - resourcemanager.organizations.get
  - resourcemanager.projects.get
tools:
  - gcloud CLI
  - Cloud Asset Inventory
  - Org Policy API (orgpolicy.googleapis.com)
  - Resource Manager API
references:
  - https://cloud.google.com/resource-manager/docs/organization-policy/overview
  - https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
  - https://cloud.google.com/resource-manager/docs/organization-policy/creating-managing-custom-constraints
  - https://cloud.google.com/sdk/gcloud/reference/org-policies
  - https://cloud.google.com/asset-inventory/docs/overview
  - https://cloud.google.com/iam/docs/understanding-roles#orgpolicy-roles
license: CC BY-SA 4.0
---

## Summary

The Google Cloud **Organization Policy Service** lets administrators apply centralized, programmatic restrictions ("constraints") across an entire resource hierarchy — organization, folders, and projects. Unlike IAM, which governs *who* can act on a resource, Organization Policy governs *what configurations are allowed* on resources, regardless of the identity performing the action. Examples include restricting which external IPs a VM may have, disabling service account key creation, restricting the locations resources can be deployed to, and enforcing uniform bucket-level access on Cloud Storage.

Org policies are inherited down the hierarchy and can be evaluated, overridden, or merged at each node. Because these policies are the backbone of many compensating and preventive cloud security controls, enumerating them is a high-value early step: their presence, absence, or misconfiguration directly tells an assessor which guardrails exist and which attack paths remain open (for example, whether `iam.disableServiceAccountKeyCreation` is enforced, or whether `compute.requireShieldedVm` is set).

This page covers discovering the constraints catalog, reading effective and node-level policies across the hierarchy, identifying custom constraints, and inferring the overall guardrail posture. Exploitation of weak or modifiable policies is covered in [GCP Org Policy - Privilege Escalation](../03-privilege-escalation/gcp-org-policy-privesc.md).

## Prerequisites

- An authenticated principal (user, service account, or workload identity) with at least read access to Organization Policy and Resource Manager.
- Knowledge of, or the ability to discover, the resource hierarchy identifiers (organization ID, folder IDs, project IDs). See [GCP Resource Hierarchy enumeration] for hierarchy discovery; org policy queries must target a specific node.
- Relevant read permissions:
  - `orgpolicy.policy.get` / `orgpolicy.policies.list` — read policies set on a node.
  - `orgpolicy.constraints.list` — list the catalog of available (built-in and custom) constraints applicable to a node.
  - `resourcemanager.organizations.get`, `resourcemanager.folders.get`, `resourcemanager.projects.get` — resolve hierarchy nodes.
  - `cloudasset.assets.searchAllResources` / `cloudasset.assets.analyzeOrgPolicies` (optional) — bulk discovery via Cloud Asset Inventory.
- The predefined role `roles/orgpolicy.policyViewer` grants the policy/constraint read permissions; `roles/orgpolicy.policyAdmin` grants read and write.

> Note: A principal that lacks any org-policy read permission can still **infer** policy state indirectly by observing which actions succeed or fail (e.g., attempting to create a service account key and receiving a constraint-violation error). Indirect inference is described under Misconfigurations & Findings.

## Enumeration

### Identify the catalog of available constraints

The list of constraints that *can* be applied to a node (built-in plus any custom constraints visible to the caller):

```bash
# List all constraints available for an organization node
gcloud org-policies list-custom-constraints --organization=ORG_ID
gcloud resource-manager org-policies list-available-constraints --organization=ORG_ID   # legacy v1 command

# v2 / current: describe a specific constraint definition
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
  --organization=ORG_ID --effective
```

Raw API equivalent (Org Policy v2):

```bash
ACCESS_TOKEN=$(gcloud auth print-access-token)

# List custom constraints defined at the org
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://orgpolicy.googleapis.com/v2/organizations/ORG_ID/customConstraints"
```

### List policies set on a specific node

Org policies are always read relative to a node. Enumerate every node you can reach.

```bash
# Policies explicitly set on a project, folder, or organization
gcloud org-policies list --project=PROJECT_ID
gcloud org-policies list --folder=FOLDER_ID
gcloud org-policies list --organization=ORG_ID
```

API equivalent:

```bash
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://orgpolicy.googleapis.com/v2/projects/PROJECT_ID/policies"
```

### Read a specific policy and its effective (inherited) value

The *effective* policy is the result after inheritance and merge logic is applied down the hierarchy — this is what actually governs the resource.

```bash
# Value set directly on the node
gcloud org-policies describe constraints/compute.vmExternalIpAccess --project=PROJECT_ID

# Effective value after inheritance from parent folders/org
gcloud org-policies describe constraints/compute.vmExternalIpAccess --project=PROJECT_ID --effective
```

API:

```bash
# getEffectivePolicy returns the inherited+merged result
curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://orgpolicy.googleapis.com/v2/projects/PROJECT_ID/policies/compute.vmExternalIpAccess:getEffectivePolicy"
```

### Bulk enumeration with Cloud Asset Inventory

When `cloudasset` permissions are available, Asset Inventory analyzes effective org policies across the hierarchy in a single call, avoiding per-node iteration:

```bash
# Analyze the effective org policies for a constraint across a scope
gcloud asset analyze-org-policies \
  --scope=organizations/ORG_ID \
  --constraint=constraints/iam.disableServiceAccountKeyCreation

# Analyze governed containers/assets and the policies that apply to them
gcloud asset analyze-org-policy-governed-assets \
  --scope=organizations/ORG_ID \
  --constraint=constraints/compute.vmExternalIpAccess

# Search all policy assets via the asset feed
gcloud asset search-all-resources \
  --scope=organizations/ORG_ID \
  --asset-types=orgpolicy.googleapis.com/Policy
```

### Build a posture map

For an efficient sweep, query the effective value of the highest-impact security constraints across each reachable project. Constraints whose presence/absence most directly affects attack paths include:

| Constraint | Security effect when enforced |
|---|---|
| `iam.disableServiceAccountKeyCreation` | Blocks creation of long-lived SA keys |
| `iam.disableServiceAccountKeyUpload` | Blocks uploading externally generated keys |
| `iam.automaticIamGrantsForDefaultServiceAccounts` | Stops default SAs from receiving Editor on projects |
| `iam.allowedPolicyMemberDomains` | Domain-restricted sharing; blocks `allUsers`/external grants |
| `iam.disableServiceAccountCreation` | Prevents creating new service accounts |
| `compute.vmExternalIpAccess` | Restricts which VMs may have external IPs |
| `compute.requireShieldedVm` | Forces Shielded VM (secure/measured boot) |
| `compute.requireOsLogin` | Forces OS Login (SSH key central control) |
| `compute.disableSerialPortAccess` | Blocks interactive serial console |
| `compute.vmCanIpForward` | Restricts IP forwarding (pivot/routing abuse) |
| `compute.restrictXpnProjectLienRemoval` | Protects Shared VPC host liens |
| `storage.uniformBucketLevelAccess` | Disables legacy bucket/object ACLs |
| `storage.publicAccessPrevention` | Blocks public bucket exposure |
| `sql.restrictPublicIp` | Blocks public IPs on Cloud SQL |
| `gcp.resourceLocations` | Restricts deployment regions (data residency) |
| `gcp.restrictServiceUsage` | Allow/deny-lists which APIs may be enabled |
| `essentialcontacts.allowedContactDomains` | Restricts notification contact domains |
| `constraints/cloudfunctions.allowedIngressSettings` | Restricts function ingress exposure |

## Misconfigurations & Findings

- **No org-level guardrails set.** When `gcloud org-policies list --organization=ORG_ID` returns an empty set, every project relies on default (permissive) behavior. Notably, key-creation, default-SA-grants, and public-access constraints are *not* enforced by default.
- **Enforcement only at project level / gaps in folders.** Policies set on individual projects but not at the org or folder level mean newly created projects inherit no protection. Look for hierarchy nodes where the effective policy reverts to the permissive default.
- **`enforced: false` overrides on boolean constraints.** A child node can set `enforce: false` to *disable* a guardrail inherited from a parent (subject to the `inheritFromParent` and merge rules). Enumerate child overrides that weaken parent enforcement.
- **List constraints with `allowAll` or overly broad `allowedValues`.** For list constraints (e.g., `compute.vmExternalIpAccess`, `gcp.restrictServiceUsage`), an `allowAll: true` or wildcard rule negates the control.
- **`allowedPolicyMemberDomains` not enforced.** Without it, IAM bindings to `allUsers`, `allAuthenticatedUsers`, or external Google identities are permitted across the hierarchy — a common data-exposure precursor.
- **Default service account auto-grants enabled.** Absence of `iam.automaticIamGrantsForDefaultServiceAccounts` enforcement means default Compute/App Engine SAs may hold `roles/editor`, a frequent privilege-escalation pivot.
- **Custom constraints with weak conditions.** Custom constraints (`organizations/ORG_ID/customConstraints/...`) use CEL conditions; an overly narrow `condition` or a `methodType` that omits `UPDATE`/`CREATE` leaves enforcement gaps. Review each custom constraint's condition, resource types, and method types.
- **Indirect inference (no read permission).** If org-policy read is denied, a constraint's enforcement can still be inferred from error messages: a denied action returns a `FAILED_PRECONDITION`/`constraint ... violated` error citing the constraint name, while a permitted action succeeds. This reveals enforcement state without `orgpolicy.policy.get`.
- **Dry-run vs live divergence.** Org Policy supports dry-run (`liveState` vs `dryRunSpec`). A constraint configured only as dry-run logs violations but does **not** block them; treat dry-run-only constraints as not enforced.

## Detection & Logging

- Org Policy administrative reads and writes are captured in **Cloud Audit Logs** under the `orgpolicy.googleapis.com` service. Policy modifications appear as **Admin Activity** logs (always on, no opt-in); policy reads such as `GetPolicy`/`GetEffectivePolicy`/`ListPolicies` appear as **Data Access** logs (must be explicitly enabled per service/principal).
- Cloud Asset Inventory `analyzeOrgPolicies`, `analyzeOrgPolicyGovernedAssets`, and `searchAllResources` calls against `cloudasset.googleapis.com` likewise surface in Data Access logs when enabled.
- Defenders should monitor for `methodName` values such as `google.cloud.orgpolicy.v2.OrgPolicy.GetPolicy`, `ListPolicies`, `ListConstraints`, and the asset-inventory analyze methods, especially bursts of effective-policy reads spanning many projects (posture-mapping behavior).
- Enumeration that relies solely on observing constraint-violation errors leaves no org-policy read trail — only the failed *target* action (e.g., `CreateServiceAccountKey`) is logged. Correlate repeated `PERMISSION_DENIED`/`FAILED_PRECONDITION` errors as a signal.

## Remediation & Hardening

- Set high-impact constraints at the **organization** node so all current and future projects inherit them; reserve project-level overrides for documented exceptions.
- Enable **Data Access audit logs** for `orgpolicy.googleapis.com` and `cloudasset.googleapis.com` to gain visibility into policy reads.
- Restrict `roles/orgpolicy.policyViewer` and especially `roles/orgpolicy.policyAdmin` to a minimal set of platform administrators; do not bundle them into broadly assigned custom roles.
- Periodically reconcile the *effective* policy of each project against a baseline (using `analyze-org-policies`) to detect child overrides that weaken inherited guardrails.
- Promote dry-run constraints to enforced once validated; do not leave security-relevant constraints in dry-run indefinitely.

## Tools

- **gcloud CLI** — `gcloud org-policies`, `gcloud resource-manager org-policies`, `gcloud asset analyze-org-policies`.
- **Org Policy API v2** (`orgpolicy.googleapis.com`) — direct REST enumeration of policies and custom constraints.
- **Cloud Asset Inventory** (`cloudasset.googleapis.com`) — hierarchy-wide effective-policy analysis.
- **Resource Manager API** — hierarchy node discovery to scope queries.

## References

- Organization Policy Service overview — https://cloud.google.com/resource-manager/docs/organization-policy/overview
- Organization policy constraints catalog — https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- Creating and managing custom constraints — https://cloud.google.com/resource-manager/docs/organization-policy/creating-managing-custom-constraints
- `gcloud org-policies` reference — https://cloud.google.com/sdk/gcloud/reference/org-policies
- Cloud Asset Inventory overview — https://cloud.google.com/asset-inventory/docs/overview
- Org Policy IAM roles — https://cloud.google.com/iam/docs/understanding-roles#orgpolicy-roles
