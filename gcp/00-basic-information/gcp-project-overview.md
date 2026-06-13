---
cstg_id: CSTG-GCP-PROJECT-OVERVIEW
title: "GCP Project - Overview"
provider: gcp
service: project
phase: basic-information
required_access: read-only-audit
required_permissions:
  - resourcemanager.projects.get
  - resourcemanager.projects.list
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.organizations.get
  - resourcemanager.folders.list
  - serviceusage.services.list
tools:
  - gcloud CLI
  - Cloud Asset Inventory API
  - Cloud Resource Manager API
references:
  - "https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy"
  - "https://cloud.google.com/docs/overview"
  - "https://cloud.google.com/iam/docs/overview"
  - "https://cloud.google.com/resource-manager/docs/access-control-proj"
  - "https://cloud.google.com/iam/docs/service-account-overview"
  - "https://cloud.google.com/resource-manager/reference/rest"
license: CC BY-SA 4.0
---

## Summary

The **project** is the fundamental organizing and trust boundary of Google Cloud Platform (GCP). Almost every GCP resource - virtual machines, storage buckets, databases, service accounts, networks, API keys - is created inside, billed to, and access-controlled by a project. A project groups a set of related resources, enables a set of APIs, attaches a billing account, and anchors an IAM policy that governs who can do what to the resources it contains.

Understanding the project is the entry point for assessing any GCP environment. The project is where the **resource hierarchy** (organization -> folders -> projects -> resources) terminates and where most concrete permissions take effect. It is also where the most common privilege-escalation and lateral-movement primitives live: default service accounts, API enablement, IAM policy bindings, and the metadata server that exposes credentials to compute workloads.

For a tester, the project answers the central reconnaissance questions: *Which projects can these credentials see? What is enabled in each? Who has access, and through which identities? Where does access in this project lead - other projects, the folder, or the entire organization?* For a defender, the project is the unit at which IAM hygiene, API surface reduction, logging, and organization-policy enforcement are applied.

This page covers the GCP identity/access/resource model as it relates to the project: the hierarchy, project identifiers, the IAM model, principal types, authentication methods, and how to enumerate and evaluate a project's posture from read-only audit access.

## Prerequisites

The enumeration described here assumes a principal (user, service account, or federated identity) with **read-only audit-level access** to one or more projects. The most useful viewer-grade permissions are:

- `resourcemanager.projects.get` / `resourcemanager.projects.list` - read project metadata and list visible projects.
- `resourcemanager.projects.getIamPolicy` - read the project's IAM policy (who has access).
- `resourcemanager.folders.list` / `resourcemanager.folders.getIamPolicy` - walk the hierarchy upward.
- `resourcemanager.organizations.get` / `resourcemanager.organizations.getIamPolicy` - read organization context.
- `serviceusage.services.list` - see which APIs are enabled.
- `cloudasset.assets.*` (via `roles/cloudasset.viewer`) - enumerate resources at scale.

These are bundled in roles such as `roles/viewer` (basic), `roles/iam.securityReviewer`, `roles/cloudasset.viewer`, and `roles/resourcemanager.organizationViewer`. Note that even an identity with *no* explicit project role may still see projects where it holds resource-level grants, and that the `gcloud projects list` result reflects only projects where the caller has at least `resourcemanager.projects.get`.

A credential of any kind is required to authenticate (see [Authentication Methods](#authentication-methods) below). Unauthenticated callers cannot enumerate projects.

## The Resource Hierarchy

GCP arranges resources in a strict parent-child tree. IAM policies set at any node are **inherited downward** and are additive - a principal's effective permissions on a resource are the union of all policies from the organization down to the resource itself.

```
Organization (the root node; tied to a Cloud Identity / Workspace domain)
   |
   +-- Folder (optional; can nest multiple levels)
   |      |
   |      +-- Folder
   |      |      +-- Project
   |      |             +-- Resource (VM, bucket, dataset, service account, ...)
   |      +-- Project
   |
   +-- Project   (projects may also sit directly under the org or have no org)
```

Key consequences for testing:

- **Inheritance is one-directional and additive.** A grant of `roles/owner` at the organization or folder level cascades to every project beneath it. There is no "deny by inheritance" except via explicit IAM **deny policies** or **organization policies**, which are evaluated separately.
- **An owner/editor on a parent is an owner/editor on the child.** Compromising a folder-level binding is often more valuable than any single project.
- **Projects can be orphaned.** A project created without an organization (common for personal accounts or quick experiments) has no parent governance; its IAM policy is the only control.
- **The organization node is the security anchor.** Organization policies, VPC Service Controls perimeters, and the audit-log sink that captures Admin Activity are typically set here.

## Project Identifiers

Every project has three distinct identifiers; confusing them is a frequent source of errors during testing:

| Identifier | Example | Mutable? | Notes |
|---|---|---|---|
| **Project ID** | `acme-prod-1a2b` | No (permanent) | Globally unique, user-chosen at creation, used in almost all CLI/API calls. |
| **Project number** | `849302156471` | No | Auto-assigned, globally unique, used in resource names like service-account emails and metadata. |
| **Display name** | `ACME Production` | Yes | Human-friendly label, not unique. |

Many resource identifiers embed the project number rather than the ID - for example, the **default Compute Engine service account** is `<project-number>-compute@developer.gserviceaccount.com`, and the **App Engine / default service** identities follow similar patterns. When reading IAM policies you will encounter both forms; resolve numbers to IDs with `gcloud projects describe`.

## The IAM Model

GCP IAM answers "who (principal) can do what (role) on which resource". A policy is a collection of **bindings**, each binding pairing one role with a list of members and an optional condition.

**Principals (members).** Referenced in policies by typed strings:

- `user:alice@example.com` - a human Google/Workspace account.
- `serviceAccount:svc@<project>.iam.gserviceaccount.com` - a non-human identity (the most security-relevant principal in GCP).
- `group:eng@example.com` - a Google Group; membership is managed outside the project.
- `domain:example.com` - everyone in a Workspace domain.
- `principal://...` / `principalSet://...` - **Workload Identity Federation** and Workforce Identity principals from external IdPs (OIDC/SAML/AWS).
- `allUsers` / `allAuthenticatedUsers` - public and any-Google-account, respectively. Bindings to these on a project or resource are a high-severity finding.

**Roles.** Three categories:

- **Basic roles** - `roles/owner`, `roles/editor`, `roles/viewer`. Coarse, broadly over-privileged, and discouraged. `owner` includes the ability to modify the IAM policy itself.
- **Predefined roles** - service-scoped, e.g. `roles/compute.admin`, `roles/storage.objectViewer`, `roles/iam.serviceAccountTokenCreator`. Hundreds exist.
- **Custom roles** - defined per org or per project with a hand-picked permission set.

**Permissions** take the form `service.resource.verb` (e.g. `compute.instances.list`, `iam.serviceAccounts.actAs`). A principal cannot be granted a bare permission - only roles that contain it.

**Conditions, deny policies, and organization policies** add evaluation layers: IAM Conditions gate a binding on request attributes (time, resource name, IP); IAM **deny policies** explicitly block permissions and override allow grants; **organization policy constraints** (e.g. `iam.disableServiceAccountKeyCreation`, `compute.requireOsLogin`, `iam.allowedPolicyMemberDomains`) constrain configuration regardless of IAM. All three are worth reading during an assessment because they change what an otherwise-permissive binding can actually do.

## Service Accounts and the Project

Service accounts are both principals (they appear in IAM policy bindings) and resources (they live inside a project and have their own IAM policy controlling who can use them). They are the connective tissue of GCP lateral movement:

- **Default service accounts** - the Compute Engine default SA (`<project-number>-compute@developer.gserviceaccount.com`) and others are created automatically and historically granted the broad `roles/editor` on the project. Workloads running as these accounts inherit that power.
- **`iam.serviceAccounts.actAs` / `getAccessToken` / `signJwt` / `getOpenIdToken`** - permissions that let a principal *impersonate* a service account, assuming its identity and permissions. This is the single most important escalation pattern to map at the project level.
- **`iam.serviceAccountKeys.create`** - lets a principal mint long-lived JSON key files for a service account, producing portable credentials.
- **Attached service accounts** - a VM, Cloud Function, Cloud Run service, or GKE workload runs *as* a service account; whoever can deploy or modify that workload effectively gains the SA's permissions.

These paths are covered in depth on the service-account and privilege-escalation pages; at the overview level the point is that *enumerating which service accounts exist in a project and who can act as them is core reconnaissance.*

## Authentication Methods

GCP credentials a tester or defender will encounter:

- **User credentials (OAuth 2.0).** Interactive sign-in via `gcloud auth login`, stored as Application Default Credentials (ADC). Tied to a human Google/Workspace identity.
- **Service-account keys.** Long-lived JSON key files containing a private key. Highly portable, often leaked in source code, CI systems, or buckets. Activate with `gcloud auth activate-service-account --key-file=key.json`.
- **Short-lived tokens.** OAuth access tokens (typically ~1 hour) minted via impersonation (`--impersonate-service-account`) or the metadata server. The preferred, auditable alternative to keys.
- **Metadata server.** On Compute Engine, GKE, Cloud Run, and Cloud Functions, the link-local endpoint `http://metadata.google.internal/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`) returns the attached service account's access token and project metadata. SSRF or code execution against such a workload yields cloud credentials.
- **Workload Identity Federation.** External workloads (AWS, Azure, GitHub Actions, any OIDC IdP) exchange a native token for short-lived GCP credentials without a key file. Misconfigured provider attribute conditions (overly broad audience or subject matching) are a notable finding.
- **API keys.** Bearer strings for unauthenticated-style access to certain APIs; they identify a project, not a principal, and provide no IAM authorization on their own.

## Enumeration

All commands assume an authenticated `gcloud` session or a token in `$TOKEN`.

**Identify the active identity and visible projects:**

```bash
# Who am I and what is the active config?
gcloud auth list
gcloud config list

# All projects the caller can see
gcloud projects list --format="table(projectId,projectNumber,name,lifecycleState)"

# Detail on one project (resolves ID <-> number, shows parent)
gcloud projects describe acme-prod-1a2b
```

**Walk the hierarchy:**

```bash
# Organizations visible to the caller
gcloud organizations list

# Folders under an org or folder
gcloud resource-manager folders list --organization=ORG_ID
gcloud resource-manager folders list --folder=FOLDER_ID

# Ancestry of a project (org/folder chain) - useful to find the governance root
gcloud projects get-ancestors acme-prod-1a2b
```

**Read IAM at each level (who has access):**

```bash
gcloud projects   get-iam-policy acme-prod-1a2b --format=json
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
gcloud organizations get-iam-policy ORG_ID --format=json

# Find every role granted to a specific principal across the hierarchy
gcloud projects get-iam-policy acme-prod-1a2b \
  --flatten="bindings[].members" \
  --filter="bindings.members:user:alice@example.com" \
  --format="table(bindings.role)"
```

**Enumerate enabled APIs (attack surface) and quotas:**

```bash
gcloud services list --enabled --project=acme-prod-1a2b
gcloud services list --available --project=acme-prod-1a2b   # what could be turned on
```

**Enumerate service accounts and who can use them:**

```bash
gcloud iam service-accounts list --project=acme-prod-1a2b
gcloud iam service-accounts get-iam-policy \
  <SA>@acme-prod-1a2b.iam.gserviceaccount.com --format=json
```

**Bulk inventory via Cloud Asset Inventory** (fastest way to map an org):

```bash
# Every resource and IAM policy under an org, in one export
gcloud asset search-all-resources --scope=organizations/ORG_ID
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers"
```

**Raw REST equivalents** (when only a token is available):

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/acme-prod-1a2b:getIamPolicy"
```

**From a compromised workload, query the metadata server:**

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Test access without prior knowledge of permissions** using `testIamPermissions`, which returns only the permissions the caller actually holds (no error if denied):

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d \
  '{"permissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccounts.actAs","serviceusage.services.enable"]}' \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/acme-prod-1a2b:testIamPermissions"
```

## Misconfigurations & Findings

Project-level conditions that warrant findings:

- **Basic roles in use.** `roles/owner` or `roles/editor` granted broadly (especially to groups, large domains, or service accounts) instead of least-privilege predefined roles. `editor` alone permits creating resources and modifying many configurations; `owner` additionally permits rewriting the IAM policy.
- **`allUsers` / `allAuthenticatedUsers` in the project or resource IAM policy.** Public access to a project or any resource within it.
- **Default service account with `roles/editor`.** The Compute Engine default SA retaining its automatic editor grant means any VM (and any SSRF/RCE on a VM) yields project-wide write access.
- **Service-account impersonation chains.** Principals holding `iam.serviceAccounts.actAs`, `...getAccessToken`, `...getOpenIdToken`, `...signBlob`, or `...signJwt` on more-privileged service accounts - a direct escalation primitive.
- **`iam.serviceAccountKeys.create` without an org-policy block.** Allows minting long-lived, exfiltratable keys.
- **Permission to modify IAM policy** (`resourcemanager.projects.setIamPolicy`, `iam.roles.update` on a granted custom role) held by lower-trust principals - self-escalation.
- **Permission to enable APIs** (`serviceusage.services.enable`) - lets a principal expand the attack surface (e.g. turn on an API whose default SA is over-privileged).
- **No organization / orphaned project.** No inherited governance, organization policies, or central audit sink.
- **Cross-project trust sprawl.** A service account from project A bound into project B's policy creates a lateral path; widespread cross-project bindings expand blast radius.
- **Weak Workload Identity Federation conditions.** Provider attribute mappings that accept any subject/repository/audience from an external IdP, enabling external actors to obtain GCP credentials.
- **Audit logging disabled or Data Access logs off.** Reduces detectability of the activity below (see Detection).

## Exploitation

The project overview surfaces the *starting points*; detailed step-by-step paths live on the service-specific and privilege-escalation pages. The recurring project-scoped patterns are:

1. **Credential acquisition -> project enumeration.** From a leaked key, an OAuth token, or a metadata-server token on a compromised workload, run the Enumeration steps to map visible projects, the active identity's roles, enabled APIs, and reachable service accounts.

2. **Default-SA inheritance.** If the active or attached identity is a default service account with `roles/editor`, the attacker already holds broad project write access; pivot to creating resources, reading storage, or attaching the SA to new compute they control.

3. **Service-account impersonation.** If the identity holds `iam.serviceAccounts.getAccessToken` (or `actAs`) on a higher-privileged SA, mint a token for it and re-run enumeration as that identity:
   ```bash
   gcloud projects list --impersonate-service-account=\
     privileged@acme-prod-1a2b.iam.gserviceaccount.com
   ```

4. **IAM self-escalation.** If the identity can call `setIamPolicy` on the project (or holds `owner`), it can grant itself any role:
   ```bash
   gcloud projects add-iam-policy-binding acme-prod-1a2b \
     --member="user:attacker@example.com" --role="roles/owner"
   ```

5. **API enablement -> new surface.** With `serviceusage.services.enable`, turn on a service whose default identity or default config is exploitable, then leverage it.

6. **Hierarchy escalation.** If a project binding reveals access to a folder or organization (or a service account that has it), the same techniques applied one level up grant control of every child project.

See the GCP IAM privilege-escalation pages for the full per-permission breakdown of each path.

## Detection & Logging

GCP records administrative and data activity in **Cloud Audit Logs**, surfaced in Cloud Logging and routable to sinks (BigQuery, Pub/Sub, Cloud Storage). Relevant log streams:

- **Admin Activity logs** - always on, not configurable off. Capture configuration and policy writes: `SetIamPolicy` on projects/folders/orgs, `CreateServiceAccount`, `CreateServiceAccountKey`, `services.enable`, project create/delete. These reveal IAM self-escalation, key minting, and API enablement.
- **Data Access logs** - off by default for most services (except some always-on entries); when enabled they record reads such as `GetIamPolicy`, `projects.get`, and resource listing. Enumeration activity is largely invisible unless Data Access logging is turned on.
- **System Event logs** - GCP-initiated changes.
- **Policy Denied logs** - requests blocked by VPC Service Controls or IAM, useful for spotting probing.

High-value signals to alert on:

- `protoPayload.methodName="SetIamPolicy"` adding `roles/owner`/`roles/editor`, `allUsers`, or external domains.
- `google.iam.admin.v1.CreateServiceAccountKey` - long-lived key creation.
- `GenerateAccessToken` / `SignJwt` / `SignBlob` calls, especially cross-project impersonation.
- `serviceusage.services.enable` for sensitive or unexpected APIs.
- Access-token use from the metadata server originating from unexpected source IPs (when ADC keys appear off-instance).

Managed detections in **Security Command Center** (e.g. Event Threat Detection findings such as *Persistence: IAM Anomalous Grant*, *Privilege Escalation: Impersonation*, and *Service Account Self-Investigation*) correlate these audit events automatically.

## Remediation & Hardening

- **Eliminate basic roles.** Replace `owner`/`editor`/`viewer` with least-privilege predefined or custom roles. Use IAM Recommender to right-size grants.
- **Disable or restrict default service accounts.** Apply the org policies `iam.automaticIamGrantsForDefaultServiceAccounts` (prevents the automatic `editor` grant) and `compute.disableDefaultServiceAccount`, or strip the default SA's editor role and assign minimal roles.
- **Block long-lived keys.** Enforce `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload`; prefer Workload Identity Federation and short-lived impersonation tokens.
- **Constrain principals.** Set `iam.allowedPolicyMemberDomains` to prevent external identities (and `allUsers`/`allAuthenticatedUsers` where supported) from appearing in policies.
- **Use IAM Conditions and deny policies** to scope sensitive permissions by resource, time, or attribute, and to hard-block dangerous permissions for low-trust principals.
- **Govern the hierarchy.** Place every project under an organization and appropriate folders; apply organization policies at the org/folder level so they inherit.
- **Lock down impersonation.** Grant `serviceAccountTokenCreator`/`actAs` narrowly and audit existing holders.
- **Reduce API surface.** Disable unused APIs; restrict `serviceusage.services.enable` to administrators.
- **Tighten Workload Identity Federation** provider conditions to exact subjects/audiences/repositories.
- **Enable Data Access audit logs** for sensitive services, route logs to an immutable sink in a separate security project, and enable Security Command Center.
- **Protect against exfiltration** with VPC Service Controls perimeters around projects holding sensitive data.

## Tools

- **gcloud CLI / Cloud SDK** - primary interface for project, IAM, and service enumeration and configuration.
- **Cloud Asset Inventory API** - bulk export of resources and IAM policies across an org/folder/project.
- **Cloud Resource Manager API** - programmatic access to projects, folders, organizations, and their IAM policies.
- **Security Command Center** - managed posture management and threat detection at the project/org level.
- **Open-source GCP enumeration and audit toolkits** (e.g. multi-cloud auditors and GCP-focused enumeration utilities) automate the read-only checks above and visualize permission/attack-path relationships.

## References

- Google Cloud - Resource hierarchy: https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy
- Google Cloud - Platform overview: https://cloud.google.com/docs/overview
- Google Cloud - IAM overview: https://cloud.google.com/iam/docs/overview
- Google Cloud - Access control for projects with IAM: https://cloud.google.com/resource-manager/docs/access-control-proj
- Google Cloud - Service accounts overview: https://cloud.google.com/iam/docs/service-account-overview
- Google Cloud - Resource Manager REST reference: https://cloud.google.com/resource-manager/reference/rest
- Google Cloud - Cloud Audit Logs overview: https://cloud.google.com/logging/docs/audit
- Google Cloud - Organization policy constraints: https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
