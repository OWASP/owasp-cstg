---
cstg_id: CSTG-GCP-SERVICE-ACCOUNTS-ENUM
title: "GCP Service Accounts - Enumeration"
provider: gcp
service: service-accounts
phase: services
required_access: read-only-audit
required_permissions:
  - iam.serviceAccounts.list
  - iam.serviceAccounts.get
  - iam.serviceAccountKeys.list
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.organizations.getIamPolicy
  - iam.roles.list
  - iam.roles.get
tools:
  - gcloud CLI
  - Google Cloud REST/RPC API
  - ScoutSuite
  - Prowler
  - enumerate-iam style policy parsers
references:
  - "https://cloud.google.com/iam/docs/service-account-overview"
  - "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts"
  - "https://cloud.google.com/iam/docs/keys-list-get"
  - "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
  - "https://cloud.google.com/iam/docs/service-account-types"
  - "https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/"
license: CC BY-SA 4.0
---

## Summary

Google Cloud service accounts (SAs) are a special type of identity (`principal`) used by workloads — virtual machines, functions, containers, and external applications — rather than by humans. Each service account is identified by an email of the form `name@project-id.iam.gserviceaccount.com` (user-managed), `project-number-compute@developer.gserviceaccount.com` / `project-id@appspot.gserviceaccount.com` (default), or `service-project-number@gcp-sa-<service>.iam.gserviceaccount.com` (Google-managed). A service account is simultaneously a *resource* (something on which IAM policy can be set, granting other principals the ability to use or manage it) and an *identity* (something that itself holds IAM roles on projects, folders, and the organization).

This duality is what makes service accounts the single most important enumeration target in GCP. Mapping which service accounts exist, which roles they hold, which principals can act as them, and which keys exist for them produces the complete graph of privilege escalation and lateral movement paths in the environment. The objective of this phase is to build that graph without altering state: catalogue every service account, its granted permissions, the IAM policies that govern who can impersonate or manage it, and any associated long-lived key material or workload bindings.

## Prerequisites

This phase assumes a read-only audit identity. Useful permissions include:

- `iam.serviceAccounts.list` and `iam.serviceAccounts.get` — list and describe service accounts in a project.
- `iam.serviceAccountKeys.list` — list key metadata (key IDs, types, validity windows) for a service account.
- `resourcemanager.projects.getIamPolicy`, `resourcemanager.folders.getIamPolicy`, `resourcemanager.organizations.getIamPolicy` — read the IAM allow policies at each level of the resource hierarchy.
- `iam.roles.list` / `iam.roles.get` — resolve custom role definitions to their underlying permissions.
- Read access to consuming services (`compute.instances.get`, `container.clusters.get`, `cloudfunctions.functions.get`, `run.services.get`) — to map which workloads run as which service account.

The predefined roles `roles/iam.securityReviewer`, `roles/iam.serviceAccountViewer`, and `roles/viewer` grant most of the above. Even without dedicated IAM-read permission, an attacker who has compromised a workload identity can enumerate self-permissions (see [Privilege Escalation](../03-privilege-escalation/gcp-service-accounts-privesc.md)).

## Enumeration

### Identify the active identity and reachable projects

```bash
# Who am I, and which projects/credentials are configured?
gcloud auth list
gcloud config list
gcloud projects list --format="table(projectId,projectNumber,name)"

# From a compromised VM/metadata context, identify the attached SA and its scopes
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

### List and describe service accounts

```bash
PROJECT=target-project-id

# List all user-managed and default service accounts
gcloud iam service-accounts list --project="$PROJECT" \
  --format="table(email,displayName,disabled,uniqueId)"

# Describe a single SA (includes oauth2ClientId, uniqueId, disabled state)
gcloud iam service-accounts describe \
  app-runner@"$PROJECT".iam.gserviceaccount.com

# Raw REST equivalent
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iam.googleapis.com/v1/projects/$PROJECT/serviceAccounts"
```

### Enumerate keys for each service account

```bash
SA=app-runner@"$PROJECT".iam.gserviceaccount.com

# Key metadata only - distinguishes USER_MANAGED vs SYSTEM_MANAGED keys
gcloud iam service-accounts keys list --iam-account="$SA" \
  --managed-by=user \
  --format="table(name,validAfterTime,validBeforeTime,keyType)"

curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iam.googleapis.com/v1/projects/$PROJECT/serviceAccounts/$SA/keys?keyTypes=USER_MANAGED"
```

The presence of `USER_MANAGED` keys is significant: these are long-lived JSON credentials that, if exfiltrated, grant durable access independent of org policy or session controls. `SYSTEM_MANAGED` keys are rotated by Google and not exportable.

### Read who can use / manage each service account (resource-level policy)

```bash
# IAM allow policy ON the service account itself - reveals impersonation grants
gcloud iam service-accounts get-iam-policy "$SA" --format=json
```

Look in this policy for bindings granting other principals:

- `roles/iam.serviceAccountTokenCreator` — can mint access tokens / sign as the SA.
- `roles/iam.serviceAccountUser` — can attach the SA to new workloads (VMs, functions, jobs).
- `roles/iam.serviceAccountKeyAdmin` — can create exportable keys.
- `roles/iam.workloadIdentityUser` — can impersonate the SA from a federated external/Kubernetes identity.
- `roles/owner` / `roles/editor` / `roles/iam.serviceAccountAdmin` — full control.

### Read what each service account can do (project/folder/org policies)

```bash
# Project-level allow policy
gcloud projects get-iam-policy "$PROJECT" --format=json

# Filter all bindings that mention service accounts
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.members[] | contains("serviceAccount:"))'

# Folder and organization policies (hierarchy inheritance matters)
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
gcloud organizations get-iam-policy ORG_ID --format=json
```

A service account's effective permissions are the union of every role bound to it at the project, every parent folder, and the organization. Always resolve the full hierarchy — a benign-looking project binding may be overshadowed by a broad org-level grant.

### Programmatic effective-access analysis

```bash
# Policy Analyzer: "what can this SA access across the org?"
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --identity="serviceAccount:$SA"

# Reverse: "who can impersonate this SA?"
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --full-resource-name="//iam.googleapis.com/projects/$PROJECT/serviceAccounts/$SA"

# Org-wide IAM snapshot for offline graphing
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID \
  --query="memberTypes:serviceAccount"
```

### Resolve custom roles

```bash
# Custom roles can hide sensitive permissions behind innocuous names
gcloud iam roles list --project="$PROJECT" --format="table(name,title)"
gcloud iam roles describe ROLE_ID --project="$PROJECT" \
  --format="yaml(includedPermissions)"
gcloud iam roles describe roles/editor --format="yaml(includedPermissions)"
```

### Map workloads to service accounts

```bash
# Compute Engine instances and their attached SA + scopes
gcloud compute instances list \
  --format="table(name,zone,serviceAccounts[].email,serviceAccounts[].scopes)"

# Cloud Functions
gcloud functions list --format="table(name,serviceAccountEmail)"

# Cloud Run
gcloud run services list --format="table(metadata.name,spec.template.spec.serviceAccountName)"

# GKE node pool default SA + Workload Identity bindings
gcloud container clusters describe CLUSTER --zone ZONE \
  --format="value(nodeConfig.serviceAccount,workloadIdentityConfig.workloadPool)"
```

## Misconfigurations & Findings

- **Default service accounts in use.** The Compute Engine default SA (`PROJECTNUMBER-compute@developer.gserviceaccount.com`) historically receives the `roles/editor` role on the project. Any workload running with this identity and broad `cloud-platform` scope is effectively project-editor. Flag every VM/function/job still using a default SA.
- **`roles/editor` or `roles/owner` granted to service accounts.** Primitive roles bound to non-human identities are an oversized blast radius and a common privilege-escalation pivot.
- **User-managed keys present.** Each exportable JSON key is a standing credential outside session and MFA controls; count them, note their age, and flag keys with no `validBeforeTime` (non-expiring).
- **Broad impersonation grants.** `serviceAccountTokenCreator` or `serviceAccountUser` granted to large groups, `allUsers`/`allAuthenticatedUsers`, or low-privilege identities creates impersonation chains.
- **Cross-project / cross-org bindings.** A service account from project A granted roles in project B (or referenced in B's allow policy) is a lateral-movement bridge.
- **Workload Identity Federation pools** allowing external IdP subjects to impersonate an SA with insufficiently scoped attribute conditions.
- **Service accounts with `disabled: false` but no associated workload** — orphaned identities that retain privileges and keys.
- **Custom roles aggregating sensitive permissions** (e.g. `iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs`, `iam.roles.update`) under benign titles.

## Exploitation

Pure enumeration is non-destructive, but the artifacts gathered here directly seed later phases. The practical output is an *impersonation and privilege graph*:

1. For each service account, record its effective roles (project + folder + org).
2. For each service account, record the principals that can `actAs`, `getAccessToken`, `signJwt`, `signBlob`, or create keys for it.
3. Connect edges: principal → (can impersonate) → SA → (holds role) → resource. A path from the compromised identity to a high-privilege SA is an escalation path; a path that crosses a project boundary is lateral movement.

Identify the highest-value target — typically the default SA with `roles/editor`, or any SA holding `roles/owner`, `roles/iam.securityAdmin`, `roles/resourcemanager.projectIamAdmin`, or `roles/iam.serviceAccountAdmin`. Hand these targets to the [Privilege Escalation](../03-privilege-escalation/gcp-service-accounts-privesc.md) and [Lateral Movement](../04-lateral-movement/gcp-service-accounts-lateral.md) phases.

## Detection & Logging

- **Cloud Audit Logs — Admin Activity** record administrative reads such as `SetIamPolicy` but *not* most `getIamPolicy`/`list` calls by default. To capture enumeration, **Data Access audit logs** must be explicitly enabled for the IAM and Resource Manager APIs (`DATA_READ` log type). Without this, read-only enumeration is largely invisible.
- When Data Access logging is enabled, look for high-volume `google.iam.admin.v1.ListServiceAccounts`, `ListServiceAccountKeys`, `GetIamPolicy`, and `cloudasset.googleapis.com` `AnalyzeIamPolicy` / `SearchAllIamPolicies` calls from a single principal in a short window.
- Metadata-server queries from a compromised VM (`/instance/service-accounts/...`) are not logged in Cloud Audit Logs; detect them at the host/network layer.
- Security Command Center surfaces some IAM posture findings (primitive roles, default SA usage, exportable keys) that mirror this enumeration.

## Remediation & Hardening

- Enable Data Access audit logs for IAM and Resource Manager so read-only reconnaissance is observable.
- Enforce the organization policies `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` to eliminate exportable keys; prefer short-lived credentials and Workload Identity Federation.
- Replace default service accounts: set `iam.automaticIamGrantsForDefaultServiceAccounts` to disable automatic `roles/editor`, and attach purpose-built least-privilege SAs to each workload.
- Apply least privilege — never bind primitive roles (`owner`/`editor`/`viewer`) to service accounts; use granular predefined or custom roles.
- Periodically run Policy Analyzer / recommender to identify and prune over-granted and unused service accounts and roles.
- Restrict who holds `serviceAccountTokenCreator`, `serviceAccountUser`, and `serviceAccountKeyAdmin`, and scope grants to individual SAs rather than the whole project.

## Tools

- **gcloud CLI** — `iam service-accounts`, `projects get-iam-policy`, `asset analyze-iam-policy` commands.
- **Google Cloud REST/RPC API** — `iam.googleapis.com`, `cloudresourcemanager.googleapis.com`, `cloudasset.googleapis.com`.
- **ScoutSuite / Prowler** — multi-account posture scanners that enumerate SAs, keys, and risky IAM bindings.
- **IAM policy graphing utilities** — parse `getIamPolicy` output into principal→role→resource edges.

## References

- Service account overview — https://cloud.google.com/iam/docs/service-account-overview
- Service account types (default, user-managed, Google-managed) — https://cloud.google.com/iam/docs/service-account-types
- `projects.serviceAccounts` REST reference — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
- Listing and getting service account keys — https://cloud.google.com/iam/docs/keys-list-get
- `getIamPolicy` reference — https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy
- Default service accounts (hackingthe.cloud) — https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/
