---
cstg_id: CSTG-SUPABASE-OVERVIEW
title: "Supabase - Platform Overview"
provider: supabase
service: platform
phase: basic-information
required_access: unauthenticated
required_permissions: []
tools: [curl, supabase-cli, psql]
references:
  - "https://supabase.com/docs/guides/api"
  - "https://supabase.com/docs/guides/database/postgres/row-level-security"
  - "https://supabase.com/docs/guides/api/api-keys"
license: CC BY-SA 4.0
---

## Summary

Supabase is a backend-as-a-service built around a managed **PostgreSQL** database. The same database
is exposed through several always-on interfaces, which is what makes its security model distinctive:
a project's tables are automatically published as a REST API, and access is controlled less by
platform IAM than by **database Row Level Security (RLS)** and the API key presented. Understanding
the key model and RLS is the prerequisite for testing any Supabase project.

## Project anatomy

A project is identified by a **project ref** and reached at `https://<project-ref>.supabase.co`. Its
interfaces:

- **REST API (PostgREST)** at `/rest/v1/` - every table and view in an exposed schema (default
  `public`) becomes an endpoint automatically.
- **Auth (GoTrue)** at `/auth/v1/` - signup, login, JWT issuance, password/OTP flows.
- **Storage** at `/storage/v1/` - S3-like object buckets with their own access policies.
- **Realtime** at `/realtime/v1/` - websocket subscriptions to database changes.
- **Edge Functions** at `/functions/v1/` - Deno serverless functions.

## Keys and identities

| Key | Sent as | Bypasses RLS? | Where it belongs |
| --- | --- | --- | --- |
| **anon (publishable) key** | `apikey` header / `Authorization: Bearer` | No | Frontend - identifies the project, not a secret |
| **service_role (secret) key** | same headers | **Yes - full bypass** | Backend only - never in client code |
| **User JWT** | `Authorization: Bearer` | No (subject to RLS as that user) | Issued by Auth after login |

Both API keys are JWTs whose `role` claim (`anon` or `service_role`) Postgres maps to a database
role. The `service_role` key runs as a role that bypasses RLS entirely, so its exposure is
equivalent to full database compromise.

## Row Level Security (RLS)

RLS is the access-control boundary for the REST API. With RLS **enabled** on a table, every request
is filtered by policies evaluated against the caller's JWT claims (`auth.uid()`, `auth.role()`).
With RLS **disabled** on a table in an exposed schema, the anon key can read (and depending on grants
write) every row. The single most important question when testing a Supabase project is therefore:
*which exposed tables do not have RLS enabled, and are the policies that exist actually restrictive?*

## How access is scoped

- Schema exposure (the Data API "exposed schemas" setting) determines which tables are reachable via
  PostgREST at all.
- RLS policies determine row visibility per role/user.
- Table/role `GRANT`s underlie the policies.
- Storage buckets are public or private, with their own RLS-style policies on `storage.objects`.

## References

- Supabase - Auto-generated REST API
- Supabase - Row Level Security
- Supabase - API keys (anon vs service_role)
