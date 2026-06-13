---
cstg_id: CSTG-SUPABASE-PRIVESC
title: "Supabase - Privilege Escalation"
provider: supabase
service: platform
phase: privilege-escalation
required_access: assumed-breach
required_permissions: []
tools: [curl, jq, psql]
references:
  - "https://supabase.com/docs/guides/api/api-keys"
  - "https://supabase.com/docs/guides/database/postgres/row-level-security"
  - "https://supabase.com/docs/guides/database/secure-data"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in Supabase is about crossing from the `anon` role or a single user's data to
broader, or total, access. The dominant paths are: obtaining the `service_role` key (which bypasses
RLS entirely), exploiting weak or missing RLS to read or modify other users' rows, and abusing
flawed policy logic or insecure views. Each path is keyed below by the weakness that enables it.

## Prerequisites

A starting position of anon key or a low-privilege user JWT, and an enumeration pass identifying
tables without RLS, weak policies, or exposed keys (see
[Supabase - Enumeration](../02-services/supabase-enum.md)).

## Exploitation

### Exposed `service_role` key (full RLS bypass)

The service_role key runs as a role that bypasses all RLS. It is frequently leaked into client
bundles, mobile apps, public repos, CI logs, or `NEXT_PUBLIC_`-prefixed env vars. With it, every
table is fully readable and writable regardless of policy:

```bash
URL="https://<ref>.supabase.co"; SRK="<service_role-key>"
curl -s "$URL/rest/v1/<any-table>?select=*" -H "apikey: $SRK" -H "Authorization: Bearer $SRK"
```

This is equivalent to full database compromise and should be treated as the highest-severity
finding.

### Missing RLS on an exposed table

A table in the `public` schema with RLS disabled is readable/writable by `anon` and every user. Read
all rows, or modify records belonging to others:

```bash
curl -s "$URL/rest/v1/<table>?select=*" -H "apikey: $ANON"
curl -s "$URL/rest/v1/<table>?id=eq.<other-users-id>" -X PATCH -H "apikey: $ANON" \
  -H "Content-Type: application/json" -d '{"role":"admin"}'
```

### Weak RLS policy logic

Policies that don't bind rows to the caller allow horizontal escalation (reading/altering other
users' rows). Common flaws: `USING (true)`, filtering only on `auth.role()` not `auth.uid()`, trust
of a client-supplied identifier, or a write policy missing `WITH CHECK` so a user can set fields
(e.g. `role`, `is_admin`, `tenant_id`) they shouldn't control - vertical escalation within the app.

### Insecure views and `SECURITY DEFINER` functions

A view over a sensitive base table can return rows the base table's RLS would deny (views run with
the view owner's rights unless `security_invoker` is set). Likewise, a `SECURITY DEFINER` function
callable via RPC (`/rest/v1/rpc/<fn>`) that performs privileged actions without internal
authorization checks can be abused for escalation.

### Role/JWT abuse

If the application mints or accepts JWTs with insufficient validation, manipulating claims
(`role`, custom `app_metadata`) may grant elevated access. The signing secret must never be exposed;
where it is, arbitrary `service_role` JWTs can be forged.

## Misconfigurations & Findings

- service_role key present in any client-reachable location.
- Public-schema tables without RLS, or policies using `USING (true)` / no `WITH CHECK`.
- Views/RPC functions that bypass RLS.
- Client-controlled columns governing authorization (`role`, `is_admin`).

## Detection & Logging

service_role usage appears as `service_role` requests in API/Postgres logs - any such request from
outside the backend is anomalous. Horizontal-escalation attempts show as one user accessing many
distinct `auth.uid()` rows. Alert on service_role calls from unexpected sources and on broad
cross-user reads.

## Remediation & Hardening

- Treat the service_role key as a top-tier secret: backend-only, in a secrets manager, never in
  `NEXT_PUBLIC_`/client builds; rotate immediately if exposed.
- Enable RLS on all exposed tables; bind policies to `auth.uid()`; always set `WITH CHECK` on writes.
- Set `security_invoker=true` on views over sensitive data; add authorization checks inside
  `SECURITY DEFINER` functions.
- Never trust client-supplied identity columns; derive them from `auth.uid()` server-side.

## Tools

- **curl / jq** - exercise key- and policy-based access paths.
- **psql** - confirm policy logic and grants with database access.

## References

- Supabase - API keys, Row Level Security, Securing your data
