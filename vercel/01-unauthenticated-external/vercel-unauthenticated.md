---
cstg_id: CSTG-VERCEL-UNAUTH
title: "Vercel - Unauthenticated Access"
provider: vercel
service: platform
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [curl, jq]
references:
  - "https://vercel.com/docs/security/deployment-protection"
  - "https://vercel.com/docs/projects/environment-variables"
license: CC BY-SA 4.0
---

## Summary

Without any credentials, the testable surface is what a Vercel deployment serves to the internet:
the production site, any reachable preview deployments, client bundles (which may inline secrets),
source maps, and the serverless/edge function endpoints. The recurring external weaknesses are
client-exposed secrets, unprotected preview deployments, and function-level flaws such as SSRF.

## Enumeration

**Client-exposed secrets and config.** Any variable inlined at build time (e.g. `NEXT_PUBLIC_*`) is
in the shipped JavaScript:

```bash
# Pull and scan bundles/source maps for secrets and backend URLs
curl -s https://<app>/_next/static/chunks/ -o - 2>/dev/null
# Source maps, if deployed, reveal original source
curl -s https://<app>/_next/static/chunks/<file>.js.map | jq '.sources[]' 2>/dev/null
```

Grep recovered assets for `apikey`, `secret`, `token`, `service_role`, and backend hostnames.

**Preview deployment exposure.** Preview URLs follow predictable patterns
(`https://<project>-<hash>-<team>.vercel.app`) and may serve unreleased code without protection:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "https://<project>-git-<branch>-<team>.vercel.app/"
```

**Function endpoints.** Enumerate API routes (`/api/*`, edge middleware) and test them unauthenticated:

```bash
curl -s "https://<app>/api/<route>" -H 'Content-Type: application/json' -d '{}'
```

**Deployment protection state.** A 401/redirect to Vercel SSO indicates protection is enabled; a
200 on a preview/production URL that should be gated is a finding.

## Misconfigurations & Findings

- **Secrets inlined into client bundles** - API keys, tokens, or a Supabase `service_role` key in
  `NEXT_PUBLIC_*` or hardcoded, recoverable by anyone.
- **Source maps deployed to production**, exposing original source and embedded constants.
- **Unprotected preview deployments** - unreleased features/code reachable at guessable URLs;
  Deployment Protection not enabled for Preview.
- **Deployment Protection bypass** - misconfigured protection bypass for automation, or
  `x-vercel-protection-bypass` tokens leaked, allowing gated deployments to be reached.
- **SSRF / unauth function logic** - serverless/edge functions that fetch attacker-controlled URLs
  or act without authentication, sometimes reaching internal/metadata endpoints of a backing cloud.
- **Permissive CORS** on function responses.
- **Missing security headers** (CSP, HSTS, frame protection).

## Detection & Logging

Production and function requests appear in Vercel's deployment and function **logs** (and log
drains, if configured). Anomalous hits on preview URLs, repeated requests probing `/api/*`, or use
of a protection-bypass header are the external signals. Without log drains, retention is limited.

## Remediation & Hardening

- Never inline secrets into client bundles; only truly public values belong in `NEXT_PUBLIC_*`.
- Disable production source maps, or restrict their exposure.
- Enable **Deployment Protection** (Vercel Authentication) for Preview (and Production where
  appropriate); protect or rotate protection-bypass tokens.
- Enforce authentication and strict CORS in functions; validate/allowlist any outbound URL to
  prevent SSRF.
- Set security headers via `vercel.json` / framework config (CSP, HSTS, `X-Frame-Options`).

## Tools

- **curl / jq** - retrieve and analyse bundles, source maps, preview URLs, and function endpoints.

## References

- Vercel - Deployment protection
- Vercel - Environment variables
