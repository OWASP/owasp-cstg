---
cstg_id: CSTG-GCP-CLOUD-BUILD-ENUM
title: "GCP Cloud Build - Enumeration"
provider: gcp
service: cloud-build
phase: services
required_access: read-only-audit
required_permissions:
  - cloudbuild.builds.list
  - cloudbuild.builds.get
  - resourcemanager.projects.getIamPolicy
  - iam.serviceAccounts.list
tools: [gcloud, scoutsuite, prowler]
references:
  - "https://cloud.google.com/build/docs/securing-builds/configure-access-control"
  - "https://cloud.google.com/build/docs/cloud-build-service-account"
license: CC BY-SA 4.0
---

## Summary

Cloud Build executes build and deployment pipelines. Each build runs as a **service account** -
historically the default Cloud Build service account
(`<project-number>@cloudbuild.gserviceaccount.com`), which has been granted broad project roles in
many environments. Because anyone who can submit a build can run code as that service account, Cloud
Build is a high-value enumeration target: its identity and the triggers that invoke it define a
significant slice of a project's effective privilege. This page covers read-only enumeration of
builds, triggers, and the build identity.

## Prerequisites

A principal with read access to Cloud Build and IAM (`Viewer` / `Security Reviewer` is sufficient).

## Enumeration

```bash
gcloud config set project <project>
# Build history and trigger inventory
gcloud builds list --limit=50
gcloud builds triggers list
gcloud builds triggers describe <trigger> --region=<region>
# Which identity do builds run as, and what can it do?
gcloud projects get-iam-policy <project> \
  --flatten='bindings[].members' \
  --filter='bindings.members:cloudbuild.gserviceaccount.com' \
  --format='table(bindings.role)'
gcloud iam service-accounts list
```

Inspect trigger definitions and inline `cloudbuild.yaml` for the connected source repository, the
substitution variables, and any referenced secrets (Secret Manager mounts, encrypted env).

## Misconfigurations & Findings

- **Over-privileged build service account** - the Cloud Build SA holding broad roles (e.g.
  `roles/editor`, or `iam.serviceAccountUser`/`serviceAccountTokenCreator` over powerful accounts),
  so any build inherits that power.
- **Broad ability to submit builds** - `cloudbuild.builds.create` granted widely, turning build
  submission into code execution as the build SA.
- **Triggers on untrusted sources** - triggers that build on push/PR from repositories or forks that
  external contributors can influence.
- **Secrets exposed in build config** - plaintext credentials in `cloudbuild.yaml` or substitutions
  instead of Secret Manager.
- **Custom worker pools with broad network reach** into private resources.

## Detection & Logging

Cloud Build activity is recorded in **Cloud Audit Logs**: Admin Activity logs capture
`google.devtools.cloudbuild.v1.CloudBuild.CreateBuild` / `CreateBuildTrigger` and record the calling
principal. Builds also emit logs to Cloud Logging / the build's log bucket. Alert on build creation
by unexpected principals and on new or modified triggers.

## Remediation & Hardening

- Run builds as a **dedicated, least-privilege user-managed service account**, not the default SA;
  grant only the roles each pipeline needs.
- Restrict `cloudbuild.builds.create` and trigger-management permissions to CI/CD administrators.
- Use **Secret Manager** for build secrets; never inline credentials.
- Gate triggers from untrusted sources (require approval for external contributors).
- Review the default Cloud Build SA's role grants and remove unnecessary breadth.

## Tools

- **gcloud** - authoritative enumeration of builds, triggers, and IAM bindings.
- **Prowler**, **ScoutSuite** - flag over-privileged build identities and broad access.

## References

- Google Cloud - Configure access control for Cloud Build
- Google Cloud - Cloud Build service account
