---
cstg_id: CSTG-SUPABASE-UNAUTH
title: "Supabase - Unauthenticated Access"
provider: supabase
service: platform
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [curl, jq, ffuf]
references:
  - "https://supabase.com/docs/guides/api"
  - "https://supabase.com/docs/guides/storage/security/access-control"
license: CC BY-SA 4.0
---

## Summary

The anon (publishable) key is designed to ship in client code, so it is recoverable from almost any
Supabase-backed application and grants the `anon` role against the project's public interfaces. With
nothing more than that key, a tester can exercise the REST API, Auth, and Storage exactly as the
`anon` role - which is harmless if RLS and bucket policies are correct, and a full data breach if
they are not. This phase needs no issued credentials beyond the publicly shipped anon key.

## Enumeration

**Recover the project ref and anon key** from the target application: inspect JavaScript bundles,
network requests, or environment-config endpoints for `https://<ref>.supabase.co` and the
`SUPABASE_ANON_KEY` / `apikey` value.

```bash
URL="https://<ref>.supabase.co"; ANON="<anon-key>"
# PostgREST advertises the exposed schema via OpenAPI - lists every reachable table/view
curl -s "$URL/rest/v1/" -H "apikey: $ANON" | jq 'keys'
```

**Dump the full schema via GraphQL introspection.** Supabase enables the `pg_graphql` extension by
default, exposing a GraphQL endpoint at `/graphql/v1`. With only the anon key, a standard
introspection query returns the entire type system - every table, column, type, and relationship in
the exposed schema - which frequently reveals more structure than the PostgREST OpenAPI, and does so
even where RLS prevents reading the underlying rows:

```bash
# Compact introspection - enumerate all GraphQL types (tables surface as <Table>Collection types)
curl -s "$URL/graphql/v1" -H "apikey: $ANON" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}' | jq

# Then query a discovered collection directly (returns data if RLS allows)
curl -s "$URL/graphql/v1" -H "apikey: $ANON" -H "Content-Type: application/json" \
  -d '{"query":"{ <table>Collection(first: 5) { edges { node { id } } } }"}' | jq
```

Introspection mapping the schema is a disclosure finding in its own right (it exposes table and
column names, hinting at sensitive data) even when RLS correctly blocks the row data.

**Test each table for anonymous readability** (RLS off or permissive policy returns rows):

```bash
curl -s "$URL/rest/v1/<table>?select=*&limit=5" -H "apikey: $ANON"
# Anonymous write test (in scope only)
curl -s "$URL/rest/v1/<table>" -H "apikey: $ANON" -H "Content-Type: application/json" \
  -d '{"note":"cstg-write-test"}'
```

**Auth surface** - check whether open signup is enabled and what it grants:

```bash
curl -s "$URL/auth/v1/signup" -H "apikey: $ANON" -H "Content-Type: application/json" \
  -d '{"email":"t@example.com","password":"Passw0rd!cstg"}'
```

**Storage** - list buckets and probe public objects:

```bash
curl -s "$URL/storage/v1/bucket" -H "apikey: $ANON"
curl -s "$URL/storage/v1/object/list/<bucket>" -H "apikey: $ANON" -H "Content-Type: application/json" -d '{}'
```

## Misconfigurations & Findings

- **Tables without RLS in an exposed schema** - anonymous read of all rows via `/rest/v1/<table>`.
  This is the most common and most severe Supabase finding.
- **Permissive RLS policies** - `USING (true)` or policies that don't reference `auth.uid()`,
  effectively public.
- **Anonymous insert/update/delete** - write grants to `anon` with no restricting policy.
- **Public storage buckets** holding private objects, or object policies that permit anonymous read.
- **Open signup enabling privileged flows** - self-registration that lands users in a role or table
  with excessive access.
- **Sensitive views** (joining `auth.users`, internal tables) exposed through the API.
- **GraphQL introspection enabled** at `/graphql/v1` - the anon key can dump the full schema (table
  and column names, relationships), aiding targeting even when RLS blocks the data.

## Detection & Logging

Supabase records API, Auth, and Postgres activity in the project's **Logs** (and log drains, if
configured). Anonymous reads appear as `anon`-role requests in the API/Postgres logs; a spike of
`anon` requests enumerating many tables or `/rest/v1/` is the signal. Absence of log drains means
this history is retention-limited - itself worth flagging.

## Remediation & Hardening

- **Enable RLS on every table in an exposed schema** and write least-privilege policies that
  reference `auth.uid()`/`auth.role()`. Pre-deploy check:
  `select tablename from pg_tables where schemaname='public' and not rowsecurity;`
- Remove `anon` write grants unless explicitly intended.
- Make buckets private by default; scope `storage.objects` policies to the owning user.
- Restrict the Data API exposed schemas, or disable the Data API and use Edge Functions / direct
  connections where a public API is not required.
- Disable open signup if not needed, or constrain what a newly signed-up user can reach.
- If GraphQL is unused, disable the `pg_graphql` endpoint (drop/disable the extension or remove the
  `graphql_public` schema from the exposed schemas); RLS still governs row data, but limiting schema
  introspection reduces reconnaissance value.

## Tools

- **curl / jq** - exercise the REST, Auth, and Storage APIs with the anon key.
- **ffuf** - enumerate table/endpoint names where the OpenAPI listing is restricted.

## References

- Supabase - Auto-generated REST API
- Supabase - GraphQL (pg_graphql) and the `/graphql/v1` endpoint
- Supabase - Storage access control
