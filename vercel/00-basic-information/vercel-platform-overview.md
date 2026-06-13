---
cstg_id: CSTG-VERCEL-OVERVIEW
title: "Vercel - Platform Overview"
provider: vercel
service: platform
phase: basic-information
required_access: unauthenticated
required_permissions: []
tools: [curl, vercel-cli]
references:
  - "https://vercel.com/docs/rest-api"
  - "https://vercel.com/docs/projects/environment-variables"
  - "https://vercel.com/docs/security/deployment-protection"
license: CC BY-SA 4.0
---

## Summary

Vercel is a deployment platform for frontend and serverless applications. Its security model centres
on **access tokens** and **team roles** for the control plane, **environment variables** as the
secret store, **deployments** (production and preview) as the exposed surface, and **serverless /
edge functions** as the executable surface. Unlike IaaS, there is no resource-level IAM; access is
governed by token scope, team membership/role, and per-deployment protection settings.

## Platform anatomy

- **Account / Team** - resources belong to a personal account or a Team; members hold roles (Owner,
  Member, Developer, Billing, Viewer, Contributor) that determine control-plane access.
- **Projects** - a project maps to a repository and holds configuration, env vars, and domains.
- **Deployments** - every push produces an immutable deployment with a unique URL. **Production**
  deployments serve the assigned domains; **Preview** deployments serve branch/PR builds at
  generated URLs.
- **Environment variables** - secrets and config scoped to Development / Preview / Production (and
  optionally per-branch). The secret store for the app.
- **Functions** - Serverless and Edge Functions execute backend code; they read env vars and can
  reach the network and connected backends.
- **Access tokens** - bearer tokens for the Vercel REST API (`https://api.vercel.com`), scoped to a
  user or team.

## Identities and access

| Identity | Used for | Scope |
| --- | --- | --- |
| **Access token** | REST API automation/CLI | User- or team-scoped; inherits the actor's role |
| **Team role** | Dashboard/control-plane actions | Owner > Member/Developer > Viewer, etc. |
| **Deployment protection** | Who can view a deployment | Public, Vercel Authentication, password, trusted IPs |

## How exposure is determined

- **Deployment Protection** settings decide whether production/preview URLs are public or gated
  (Vercel Authentication, password, or trusted IPs). Misconfiguration here is the main external risk.
- **Environment variable scope** decides which deployments receive which secrets; a secret scoped to
  Preview is present in every preview build.
- **`NEXT_PUBLIC_` / build-time inlining** - any variable inlined into client bundles is public by
  design; secrets placed there are exposed.
- **Function code** determines server-side trust: SSRF, missing auth, and permissive CORS are code
  issues that the platform does not prevent.

## References

- Vercel - REST API
- Vercel - Environment variables
- Vercel - Deployment protection
