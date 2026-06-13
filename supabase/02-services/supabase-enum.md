---
cstg_id: CSTG-SUPABASE-ENUM
title: "Supabase - Enumeration"
provider: supabase
service: platform
phase: services
required_access: assumed-breach
required_permissions: []
tools: [curl, jq, supabase-cli, psql]
references:
  - "https://supabase.com/docs/guides/api"
  - "https://supabase.com/docs/guides/auth"
  - "https://supabase.com/docs/guides/database/postgres/row-level-security"
license: CC BY-SA 4.0
---

## Summary

With an authenticated user JWT (an account on the target application) or a recovered key, a tester
enumerates the project's schema, auth users, storage, edge functions, and the RLS policies that
gate them. The objective is to map what each role can reach and to identify policies that can be
subverted. "Assumed breach" here means holding at least a valid low-privilege user session or an
anon key.

## Prerequisites

A valid user JWT (from registering/logging into the application) or the anon key. Reading RLS policy
definitions and full schema requires database access (a `service_role` key or direct Postgres
connection); without it, infer policies behaviorally from API responses.

## Enumeration

```bash
URL="https://<ref>.supabase.co"; ANON="<anon-key>"; JWT="<user-jwt>"
# Schema / endpoint inventory
curl -s "$URL/rest/v1/" -H "apikey: $ANON" | jq 'keys'
# What this user can see vs the anon role (diff the two)
curl -s "$URL/rest/v1/<table>?select=*" -H "apikey: $ANON"                              # anon
curl -s "$URL/rest/v1/<table>?select=*" -H "apikey: $ANON" -H "Authorization: Bearer $JWT"  # user
# Auth: current user + claims
curl -s "$URL/auth/v1/user" -H "apikey: $ANON" -H "Authorization: Bearer $JWT" | jq
# Storage buckets and objects visible to this identity
curl -s "$URL/storage/v1/bucket" -H "apikey: $ANON" -H "Authorization: Bearer $JWT"
```

With direct database access (service_role / Postgres), enumerate RLS posture authoritatively:

```sql
-- tables in public lacking RLS
select tablename from pg_tables where schemaname='public' and not rowsecurity;
-- all policies and their USING/WITH CHECK expressions
select schemaname, tablename, policyname, cmd, qual, with_check from pg_policies;
-- role grants
select grantee, table_name, privilege_type from information_schema.role_table_grants
  where table_schema='public';
```

## Misconfigurations & Findings

- **Tables/views readable by the authenticated user beyond their own rows** - policies that filter on
  role but not on `auth.uid()`, so any logged-in user reads everyone's data.
- **RLS enabled but policy logic flawed** - `USING (true)`, comparisons to client-supplied values,
  or `WITH CHECK` missing on writes.
- **Exposed views over sensitive base tables** that sidestep the base table's RLS.
- **Edge Functions** that accept user input and call the database with the service_role key.
- **Overbroad storage policies** letting a user list/read other users' objects.

## Detection & Logging

Authenticated API calls are attributed to the user (JWT `sub`) in the project's API/Postgres logs.
Enumeration shows as one identity reading across many tables or many users' rows. Configure **log
drains** to retain this for investigation.

## Remediation & Hardening

- Write policies that scope rows to the user: `USING (auth.uid() = user_id)`, and always pair write
  policies with `WITH CHECK`.
- Audit views for RLS bypass; apply `security_invoker` where appropriate.
- Have Edge Functions enforce authorization explicitly rather than relying on the service_role key
  to "just work".
- Scope storage policies on `storage.objects` to `owner = auth.uid()`.

## Tools

- **curl / jq** - behavioral enumeration via the REST/Auth/Storage APIs.
- **psql / supabase-cli** - authoritative schema, policy, and grant enumeration with DB access.

## References

- Supabase - REST API, Auth, and Row Level Security
