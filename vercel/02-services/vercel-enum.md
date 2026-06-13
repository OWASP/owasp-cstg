---
cstg_id: CSTG-VERCEL-ENUM
title: "Vercel - Enumeration"
provider: vercel
service: platform
phase: services
required_access: assumed-breach
required_permissions: []
tools: [curl, jq, vercel-cli]
references:
  - "https://vercel.com/docs/rest-api"
  - "https://vercel.com/docs/rest-api/endpoints"
license: CC BY-SA 4.0
---

## Summary

With a Vercel **access token** (assumed-breach: a leaked or issued token), the control plane is
enumerable via the REST API at `https://api.vercel.com`. The objective is to inventory projects,
environment variables, deployments, domains, and team members, and to understand the token's scope
and the actor's role.

## Prerequisites

A valid access token (`Authorization: Bearer <token>`). For team resources, the relevant `teamId` /
slug. Reading decrypted secret values depends on the token's scope and the API endpoint used.

## Enumeration

```bash
T="<vercel-token>"; H="Authorization: Bearer $T"
# Who/what does this token represent, and which teams?
curl -s https://api.vercel.com/v2/user -H "$H" | jq '.user.username,.user.email'
curl -s https://api.vercel.com/v2/teams -H "$H" | jq '.teams[].slug'
# Projects (optionally scoped to a team)
curl -s "https://api.vercel.com/v9/projects?teamId=<team>" -H "$H" | jq '.projects[].name'
# Environment variables for a project (config; secret values per scope/endpoint)
curl -s "https://api.vercel.com/v9/projects/<project>/env?teamId=<team>" -H "$H" | jq
# Deployments (URLs incl. preview)
curl -s "https://api.vercel.com/v6/deployments?projectId=<id>&teamId=<team>" -H "$H" | jq '.deployments[].url'
# Domains and team members
curl -s "https://api.vercel.com/v5/domains?teamId=<team>" -H "$H" | jq '.domains[].name'
curl -s "https://api.vercel.com/v2/teams/<team>/members" -H "$H" | jq '.members[] | {username,role}'
```

## Misconfigurations & Findings

- **Over-scoped access tokens** - a personal/full-access token where a narrowly scoped one would do;
  a token granting team-wide control.
- **Secrets retrievable via the API** - environment variables (including production secrets)
  readable with the token.
- **Excessive team membership/roles** - too many Owners, external collaborators with broad roles.
- **Long-lived tokens without expiry**, or tokens committed to source/CI.
- **Sensitive values in env vars** that should be in a dedicated secrets manager.

## Detection & Logging

Team **Audit Logs** (available on paid plans) record control-plane actions and token usage; the
dashboard shows token last-used. API enumeration shows as a burst of read calls from one token,
often from a new IP. Alert on token use from unfamiliar locations and on first-seen tokens.

## Remediation & Hardening

- Issue **least-scope, expiring** access tokens; prefer team-scoped tokens limited to what
  automation needs; rotate regularly.
- Restrict who can create tokens; review the token inventory.
- Apply least-privilege **team roles**; minimise Owners and external members.
- Keep secrets in env vars scoped correctly (not Preview if production-only) and review the Audit
  Log.

## Tools

- **curl / jq**, **vercel-cli** - enumerate projects, env, deployments, domains, and members.

## References

- Vercel - REST API and endpoint reference
