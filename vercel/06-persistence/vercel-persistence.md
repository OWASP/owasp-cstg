---
cstg_id: CSTG-VERCEL-PERSIST
title: "Vercel - Persistence"
provider: vercel
service: platform
phase: persistence
required_access: assumed-breach
required_permissions: []
tools: [curl, jq, vercel-cli]
references:
  - "https://vercel.com/docs/rest-api"
  - "https://vercel.com/docs/deployments/deploy-hooks"
  - "https://vercel.com/docs/git"
license: CC BY-SA 4.0
---

## Summary

Persistence on Vercel means retaining control-plane access or code execution after the initial
credential is gone. Because access is token- and integration-based, durable footholds are new
tokens, added team members, deploy hooks, Git-integration backdoors, and malicious code committed
into the deployment pipeline.

## Prerequisites

A token or role permitting token creation, member management, or deployment configuration.

## Exploitation

### New access token / team member

Create an additional access token, or invite an attacker-controlled account (ideally a high role),
so access survives rotation of the original credential:

```bash
T="<token>"; H="Authorization: Bearer $T"
curl -s -X POST "https://api.vercel.com/v3/user/tokens" -H "$H" -H 'Content-Type: application/json' \
  -d '{"name":"ci-maintenance"}'        # returns a new bearer token
```

Name it to blend with legitimate automation.

### Deploy hooks

A deploy hook is an unauthenticated URL that triggers a build of a branch. Creating one provides a
durable, credential-free way to trigger deployments (and thus run pipeline code) on demand:

```bash
curl -s -X POST "https://api.vercel.com/v1/projects/<id>/deploy-hooks?teamId=<team>" -H "$H" \
  -H 'Content-Type: application/json' -d '{"name":"refresh","ref":"main"}'
```

### Git-integration / pipeline backdoor

Committing malicious code, a build script, or a serverless function into the connected repository
means every future deployment re-establishes the foothold - persistence that lives in source rather
than in Vercel config. Modifying build/install commands in project settings achieves the same.

### Malicious function or middleware

A deployed function or edge middleware that proxies requests or beacons out provides durable remote
access at the application's own domain, surviving credential changes.

## Misconfigurations & Findings

- Access tokens or team members created outside normal provisioning.
- Deploy hooks not tied to a known automation.
- Build/install command or repository changes outside review.
- Functions/middleware not present in the reviewed source.

## Detection & Logging

Token creation, member invites, deploy-hook creation, and project-setting changes are recorded in
the team **Audit Log**; deployments and function activity in deployment/function logs. Reconcile
tokens, members, deploy hooks, and project build settings against an approved baseline; require code
review on the connected repository. Alert on token/member/deploy-hook creation outside change
windows.

## Remediation & Hardening

- Inventory and rotate access tokens; remove unrecognised tokens, members, and deploy hooks.
- Require review/branch protection on the connected repository; lock build/install command changes.
- Enforce SSO/SAML and least-privilege roles; review the Audit Log regularly.
- Treat any post-incident environment as compromised until tokens, hooks, and pipeline code are
  verified against source control.

## Tools

- **curl / jq**, **vercel-cli** - enumerate and manage tokens, members, deploy hooks for review.

## References

- Vercel - REST API, Deploy hooks, Git integration
