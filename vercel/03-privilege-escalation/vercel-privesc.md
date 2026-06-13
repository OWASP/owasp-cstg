---
cstg_id: CSTG-VERCEL-PRIVESC
title: "Vercel - Privilege Escalation"
provider: vercel
service: platform
phase: privilege-escalation
required_access: assumed-breach
required_permissions: []
tools: [curl, jq, vercel-cli]
references:
  - "https://vercel.com/docs/rest-api"
  - "https://vercel.com/docs/projects/environment-variables"
  - "https://vercel.com/docs/teams-and-accounts/team-members-and-roles"
license: CC BY-SA 4.0
---

## Summary

Vercel has no resource-level IAM to escalate through; escalation is about **widening the blast
radius of an access token or team role** and, most importantly, **extracting the environment-variable
secrets** that unlock backing systems. The highest-impact path is usually not deeper Vercel access
but the secrets Vercel holds - database URLs, cloud keys, third-party tokens - which pivot the
attacker out of Vercel entirely.

## Prerequisites

A Vercel access token or a team role, identified during enumeration along with the projects whose
env vars are reachable.

## Exploitation

### Environment-variable secret extraction (primary path)

Project env vars routinely hold the application's most sensitive credentials. With a sufficiently
scoped token, read them via the API or by triggering a deployment/build that echoes them:

```bash
T="<token>"; H="Authorization: Bearer $T"
curl -s "https://api.vercel.com/v9/projects/<project>/env?teamId=<team>&decrypt=true" -H "$H" | jq
```

Recovered values - database connection strings, cloud provider keys, Supabase `service_role`,
payment/email tokens - are then used directly against those systems, which is the real escalation.

### Function-based secret disclosure

Where the API won't return decrypted values but the token can deploy, deploying or modifying a
function that reads `process.env` and returns it exposes the secrets at runtime:

```js
export default function handler(req, res) { res.json(process.env) }  // illustrative
```

This is an authorization finding: the ability to deploy is the ability to read every secret scoped
to that environment.

### Token scope abuse

A broadly scoped token (full account/team) performs any action the actor could: create deployments,
change env vars, add domains, or invite members. Use enumeration to confirm scope, then exercise the
minimum action that proves impact.

### Team-role escalation

An over-privileged member (or a token for one) can invite new members, promote roles, or transfer
project access. Adding an Owner or a new full-scope token is durable escalation (see persistence).

## Misconfigurations & Findings

- Tokens able to read decrypted production secrets.
- Deploy permission granted broadly (deploy = read all env secrets at runtime).
- Members with Owner/admin roles beyond need; external collaborators with deploy rights.
- Secrets in Vercel env that grant powerful access to other systems (least-privilege not applied at
  the secret itself).

## Detection & Logging

Env-var reads, deployments, member invites, and role changes appear in the team **Audit Log**.
A deployment that reads broadly from `process.env`, or env access immediately after a token is first
seen, are signals. Alert on role/membership changes and on production env access outside CI.

## Remediation & Hardening

- Scope tokens minimally and set expiry; separate read vs deploy automation.
- Treat "can deploy" as "can read all env secrets" - restrict deploy rights accordingly.
- Apply least privilege to the secrets themselves (scoped DB users, limited cloud keys) so a leak
  has bounded impact.
- Minimise Owners; review member roles and external collaborators; require SSO/SAML where available.

## Tools

- **curl / jq**, **vercel-cli** - read env, deploy, and manage members to demonstrate impact.

## References

- Vercel - REST API, Environment variables, Team roles
