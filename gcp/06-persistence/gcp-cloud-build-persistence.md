---
cstg_id: CSTG-GCP-CLOUD-BUILD-PERSIST
title: "GCP Cloud Build - Persistence"
provider: gcp
service: cloud-build
phase: persistence
required_access: assumed-breach
required_permissions:
  - cloudbuild.builds.create
  - cloudbuild.builds.update
  - source.repos.update
tools: [gcloud]
references:
  - "https://cloud.google.com/build/docs/automating-builds/create-manage-triggers"
  - "https://cloud.google.com/build/docs/cloud-build-service-account"
license: CC BY-SA 4.0
---

## Summary

Because Cloud Build triggers run automatically in response to source events and execute as a
service account, a build trigger is a durable mechanism for regaining privileged execution. An
attacker who can create or modify triggers - or modify the build configuration a trigger consumes -
establishes recurring code execution as the build identity without retaining their original
credentials.

## Prerequisites

Permission to create or modify build triggers (`cloudbuild.builds.update` /
trigger-management permissions) or write access to the source repository or `cloudbuild.yaml` that a
trigger builds.

## Exploitation

### Malicious or modified build trigger

Create a trigger that fires on a common event (push to a branch, tag, or on a schedule) and runs
attacker-controlled steps as the build service account.

```bash
gcloud builds triggers create manual \
  --name=ci-housekeeping \
  --repo=<repo> --branch-pattern='^main$' \
  --build-config=cloudbuild.yaml
```

Blend in by naming the trigger like existing CI jobs and reusing a legitimate-looking build config
that also performs the attacker action (e.g. re-granting a role, refreshing an external token).

### Build-config tampering

Where triggers build a `cloudbuild.yaml` from a source repository, modifying that file (via
`source.repos.update` or upstream VCS access) injects steps that execute on every subsequent build -
persistence that lives in the pipeline definition rather than in IAM.

### Scheduled execution

A Cloud Scheduler job or a time-based trigger that periodically submits a build provides
attacker-controlled execution on a cadence, surviving credential rotation.

## Misconfigurations & Findings

- Trigger creation/modification permissions granted beyond CI/CD administrators.
- Triggers building configs from branches that many principals can write to.
- No review or change control on `cloudbuild.yaml` in the source repository.

## Detection & Logging

`CreateBuildTrigger` / `UpdateBuildTrigger` and each `CreateBuild` are recorded in **Cloud Audit
Logs** Admin Activity with the calling principal. Alert on trigger creation/modification outside
change windows, on triggers referencing unexpected repos or branches, and on builds running steps
that call IAM or token APIs. Review trigger inventory against an approved baseline.

## Remediation & Hardening

- Restrict trigger management to CI/CD administrators; require change control for trigger changes.
- Protect the branches that triggers build (branch protection, required review).
- Run builds as a least-privilege SA so a hijacked trigger inherits minimal power.
- Periodically reconcile the trigger inventory and `cloudbuild.yaml` against source control.

## Tools

- **gcloud** - enumerate and manage triggers for review and detection.

## References

- Google Cloud - Create and manage build triggers
- Google Cloud - Cloud Build service account
