---
cstg_id: CSTG-GCP-IAM-ENUM
title: "GCP Iam - Enumeration"
provider: gcp
service: iam
phase: services
required_access: read-only-audit
required_permissions:
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.organizations.getIamPolicy
  - resourcemanager.folders.getIamPolicy
  - iam.serviceAccounts.list
  - iam.roles.list
  - iam.serviceAccountKeys.list
  - resourcemanager.projects.get
  - serviceusage.services.list
tools:
  - gcloud CLI
  - Google Cloud REST/RPC API
  - ScoutSuite
  - Prowler
  - enumerate-iam style policy auditors
  - PMapper / GCP IAM graph tooling
references:
  - "https://cloud.google.com/iam/docs/overview"
  - "https://cloud.google.com/iam/docs/understanding-roles"
  - "https://cloud.google.com/iam/docs/reference/rest"
  - "https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy"
  - "https://cloud.google.com/iam/docs/service-account-overview"
  - "https://hackingthe.cloud/gcp/"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
license: CC BY-SA 4.0
---

## Summary

Google Cloud's Identity and Access Management (IAM) is the authorization layer
that governs **who** (identity) can perform **what action** (role/permission)
on **which resource** (project, folder, organization, or individual service
object). Enumeration of IAM is the foundational reconnaissance step for any
cloud assessment: before a path to a sensitive bucket, key, or workload can be
found, the full set of principals, the roles bound to them, and the resource
hierarchy in which those bindings sit must be mapped.

The objective of this phase is to build a complete, accurate picture of the
effective permissions of the assessed credential and of every other principal
reachable from it. This includes user accounts, groups, service accounts (SAs),
service account keys, custom and predefined roles, allow/deny policies, IAM
Conditions, and the inherited bindings flowing down the
organization -> folder -> project -> resource hierarchy. Accurate enumeration
directly feeds the privilege-escalation analysis (see
[gcp-iam-privesc.md](../03-privilege-escalation/gcp-iam-privesc.md)): an attack
path is only an escalation if a principal *actually holds* the permission that
enables it.

## Prerequisites

Authenticated access to the target environment with at least read-only
visibility into IAM. A minimal audit-grade credential typically holds the
predefined `roles/iam.securityReviewer` and `roles/viewer` (or
`roles/browser`), which grant the `*.getIamPolicy`, `*.list`, and `*.get`
permissions used below. Enumeration is possible with far less - even a single
permission such as `iam.serviceAccounts.list` reveals useful structure - and a
key goal of this phase is to determine *exactly* what the credential can see
rather than assuming a particular role.

Establish the active identity and accessible resource scope first:

```bash
# Who am I (active credential)?
gcloud auth list
gcloud config list account --format="value(core.account)"

# What projects can this identity see?
gcloud projects list
gcloud organizations list
gcloud resource-manager folders list --organization=<ORG_ID>

# Raw token introspection (works for OAuth user/SA access tokens)
TOKEN=$(gcloud auth print-access-token)
curl -s "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${TOKEN}"
```

## Enumeration

### Resource hierarchy and project metadata

```bash
gcloud organizations list --format="table(displayName,name,owner.directoryCustomerId)"
gcloud resource-manager folders list --organization=<ORG_ID>
gcloud projects list --format="table(projectId,projectNumber,name,lifecycleState)"
gcloud projects describe <PROJECT_ID>

# Enabled APIs - narrows the in-scope service attack surface
gcloud services list --enabled --project <PROJECT_ID>
```

### IAM policy bindings at every level

The allow-policy is the central artifact. Pull it at organization, folder, and
project scope, and remember that bindings **inherit downward** - an
organization-level `roles/owner` applies to every child project.

```bash
gcloud organizations get-iam-policy <ORG_ID> --format=json
gcloud resource-manager folders get-iam-policy <FOLDER_ID> --format=json
gcloud projects get-iam-policy <PROJECT_ID> --format=json

# Raw API equivalent (requestedPolicyVersion=3 returns Conditions)
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"options":{"requestedPolicyVersion":3}}' \
  "https://cloudresourcemanager.googleapis.com/v3/projects/<PROJECT_ID>:getIamPolicy"
```

> Always request `policyVersion 3`. The default version 1 silently strips
> conditional bindings, hiding access that is granted only when an IAM
> Condition is satisfied.

### Filtering bindings for a specific principal

`gcloud asset` and the `--flatten` trick reveal every role a single principal
holds across a project, including via inheritance:

```bash
# All bindings for the current user
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.members:user:alice@example.com" \
  --format="table(bindings.role)"

# Org-wide search for any binding referencing a principal (Asset Inventory)
gcloud asset search-all-iam-policies \
  --scope=organizations/<ORG_ID> \
  --query="policy:alice@example.com"

# Find every resource where a given role is granted
gcloud asset search-all-iam-policies \
  --scope=organizations/<ORG_ID> \
  --query="policy.role.permissions:resourcemanager.projects.setIamPolicy"
```

### Service accounts and keys

Service accounts are the most valuable IAM targets - they are non-human,
frequently over-privileged, and can be impersonated or have keys minted.

```bash
gcloud iam service-accounts list --project <PROJECT_ID>

# Per-SA: who can use/impersonate this SA (its own resource IAM policy)?
gcloud iam service-accounts get-iam-policy <SA_EMAIL> --project <PROJECT_ID>

# User-managed keys on each SA (KEY_TYPE=USER_MANAGED indicates an exportable key)
gcloud iam service-accounts keys list \
  --iam-account=<SA_EMAIL> \
  --managed-by=user --format="table(name,validAfterTime,validBeforeTime,keyType)"
```

The SA *resource* policy is critical: a principal granted
`roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` on a
specific SA can act as that SA even without holding the SA's project-level
roles. Enumerate these per-SA policies, not just the project policy.

### Roles and permission expansion

```bash
# Predefined and custom roles available
gcloud iam roles list                      # curated/predefined
gcloud iam roles list --project <PROJECT_ID>   # custom, project-scoped
gcloud iam roles list --organization <ORG_ID>  # custom, org-scoped

# Expand a role into its concrete permission set
gcloud iam roles describe roles/editor
gcloud iam roles describe <CUSTOM_ROLE_ID> --project <PROJECT_ID>
```

Always expand roles to permissions. A custom role named innocuously may include
`iam.serviceAccounts.getAccessToken` or `resourcemanager.projects.setIamPolicy`,
which are the primitives behind most escalation paths.

### Testable-permission probing

When the policy itself is not readable, `testIamPermissions` reveals which
specific permissions the caller holds against a resource without requiring
`getIamPolicy`:

```bash
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccounts.getAccessToken","iam.roles.create"]}' \
  "https://cloudresourcemanager.googleapis.com/v3/projects/<PROJECT_ID>:testIamPermissions"
```

### Deny policies and organization policies

Modern environments layer IAM **deny policies** and **organization policy
constraints** on top of allow bindings. Both can override an otherwise-granted
permission and must be enumerated to avoid false-positive findings.

```bash
gcloud iam policies list-deny \
  --attachment-point="cloudresourcemanager.googleapis.com/projects/<PROJECT_ID>" \
  --page-size=100

gcloud org-policies list --project=<PROJECT_ID>
gcloud org-policies describe iam.disableServiceAccountKeyCreation --project=<PROJECT_ID>
```

### Workload Identity and external identities

```bash
# Workload Identity Pools / federated identities (often grant SA impersonation)
gcloud iam workload-identity-pools list --location=global --project=<PROJECT_ID>
gcloud iam workload-identity-pools providers list \
  --workload-identity-pool=<POOL_ID> --location=global --project=<PROJECT_ID>

# Workforce identity pools (org-level SSO federation)
gcloud iam workforce-pools list --organization=<ORG_ID> --location=global
```

## Misconfigurations & Findings

- **Primitive roles in use.** `roles/owner`, `roles/editor`, and `roles/viewer`
  granted to users, groups, or SAs. `editor`/`owner` confer broad write/IAM
  control and are a frequent root cause of escalation.
- **`allUsers` / `allAuthenticatedUsers` bindings.** Any binding to these
  pseudo-principals exposes the resource publicly (storage buckets, SAs, Cloud
  Functions, Pub/Sub). This is a high-severity finding regardless of the role.
- **Over-privileged service accounts.** SAs with `editor`/`owner`, or with
  IAM-mutating permissions (`*.setIamPolicy`, `iam.roles.create`,
  `iam.serviceAccounts.*`), especially the default Compute/App Engine SAs which
  receive `roles/editor` automatically.
- **Exportable user-managed SA keys.** Any `USER_MANAGED` key is a long-lived,
  non-rotating credential that can be exfiltrated; old keys indicate weak
  hygiene.
- **Impersonation grants.** `roles/iam.serviceAccountTokenCreator` or
  `serviceAccountUser` bound broadly, allowing principals to act as more
  privileged SAs.
- **Custom roles hiding sensitive permissions.** Innocuously named roles that
  expand to escalation primitives.
- **policyVersion-1 blind spots.** Reviewers who only read version-1 policies
  miss conditional bindings that grant access.
- **Stale / external principals.** Bindings to deleted accounts
  (`deleted:`), personal Gmail accounts, or external organization domains.
- **Broad Workload Identity provider mappings** that allow external OIDC
  subjects to impersonate SAs with weak attribute conditions.

## Detection & Logging

IAM read operations are recorded in **Cloud Audit Logs**:

- `getIamPolicy`, `serviceAccounts.list`, `roles.list`, `testIamPermissions`,
  and key listing are **Data Access** audit logs (`ADMIN_READ` /
  `DATA_READ`). These are **not enabled by default** for most services and must
  be turned on per service in the IAM audit configuration. Where disabled, this
  enumeration is invisible.
- Query example:

```bash
gcloud logging read \
  'protoPayload.methodName=("GetIamPolicy" OR "google.iam.admin.v1.ListServiceAccounts")' \
  --project=<PROJECT_ID> --freshness=7d --format=json
```

- High-volume `testIamPermissions` or sequential `getIamPolicy` across many
  resources is a strong reconnaissance indicator. Security Command Center and
  managed detections (e.g., Event Threat Detection) can flag anomalous IAM
  enumeration patterns and access from anonymizing infrastructure.
- The `protoPayload.authenticationInfo.principalEmail` and
  `requestMetadata.callerIp` fields identify the enumerating principal and
  source.

## Remediation & Hardening

- Enable Data Access audit logs (`ADMIN_READ`/`DATA_READ`) for IAM and
  Resource Manager so enumeration is observable.
- Eliminate primitive roles; replace with least-privilege predefined or custom
  roles. Use the IAM Recommender to right-size grants based on actual usage.
- Forbid `allUsers`/`allAuthenticatedUsers` via the
  `iam.allowedPolicyMemberDomains` (Domain Restricted Sharing) org policy.
- Disable user-managed SA keys with
  `iam.disableServiceAccountKeyCreation`; prefer Workload Identity Federation /
  attached service accounts and short-lived tokens.
- Apply IAM Conditions and deny policies to constrain sensitive permissions.
- Periodically review SA resource policies for unexpected impersonation grants.

## Tools

- **gcloud CLI** and the **Cloud REST/RPC API** for native enumeration.
- **ScoutSuite** and **Prowler** for automated, multi-account IAM posture
  audits and public-exposure flags.
- **Cloud Asset Inventory** (`gcloud asset search-all-iam-policies`) for
  org-wide binding search.
- **IAM permission auditors** that brute-test `testIamPermissions` to map the
  effective rights of a captured credential.
- **Privilege-mapping graph tools** that ingest IAM policies and SA bindings to
  surface reachable escalation paths.

## References

- Google Cloud IAM overview - https://cloud.google.com/iam/docs/overview
- Understanding roles - https://cloud.google.com/iam/docs/understanding-roles
- IAM REST reference - https://cloud.google.com/iam/docs/reference/rest
- Resource Manager getIamPolicy - https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
- Service account overview - https://cloud.google.com/iam/docs/service-account-overview
- Hacking the Cloud (GCP) - https://hackingthe.cloud/gcp/
- Rhino Security Labs - GCP privilege escalation - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
