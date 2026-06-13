---
cstg_id: CSTG-SUPABASE-PERSIST
title: "Supabase - Persistence"
provider: supabase
service: platform
phase: persistence
required_access: assumed-breach
required_permissions: []
tools: [curl, psql]
references:
  - "https://supabase.com/docs/guides/database/functions"
  - "https://supabase.com/docs/guides/functions"
license: CC BY-SA 4.0
---

## Summary

With database-level access (service_role or direct Postgres), an attacker can establish durable
access that survives credential rotation by planting it inside the database or the project's
functions. Persistence in Supabase lives in Postgres roles, triggers/functions, auth records, and
edge functions rather than in cloud IAM.

## Prerequisites

service_role key or a privileged Postgres connection.

## Exploitation

### Database roles and backdoor accounts

Create a new database role or a privileged application user that the operators are unlikely to
notice:

```sql
create role cstg_persist login password 'redacted';
grant postgres to cstg_persist;   -- or a role that bypasses RLS
```

### Trigger / function implants

A trigger or `SECURITY DEFINER` function re-establishes access or exfiltrates on normal activity
(e.g. on insert into a busy table), running with the definer's rights:

```sql
create function public._audit() returns trigger as $$ begin
  -- attacker logic runs on each row event
  return new; end; $$ language plpgsql security definer;
create trigger _audit after insert on public.<busy_table>
  for each row execute function public._audit();
```

### Auth-layer persistence

Insert or elevate an account in `auth.users` (with service_role admin access), or add a federated
identity, to retain an application login independent of any single credential.

### Edge function backdoor

Deploy or modify an Edge Function to act as an authenticated proxy into the database using the
service_role key, providing durable remote access at `/functions/v1/<name>`.

### Persistent API keys / JWT

Where the JWT signing secret is known, valid `service_role` JWTs can be minted offline at will until
the secret is rotated - persistence without storing anything in the project.

## Misconfigurations & Findings

- Unexpected database roles with broad grants.
- `SECURITY DEFINER` functions / triggers not present in source control.
- `auth.users` entries or identities not created through the application.
- Edge Functions outside the deployment pipeline.

## Detection & Logging

`CREATE ROLE/FUNCTION/TRIGGER` and Admin Auth changes appear in Postgres/API logs; function
deploys appear in project logs. Reconcile roles, functions, triggers, and deployed functions against
source control and an approved baseline. Alert on DDL outside migrations and on out-of-band auth
changes.

## Remediation & Hardening

- Rotate the service_role key and database password; review and drop unknown roles.
- Manage all schema/functions/triggers through migrations under source control; diff against the
  live database.
- Restrict who/what can deploy Edge Functions; review function inventory.
- Rotate the JWT secret if exposure is suspected (invalidates forged tokens).

## Tools

- **psql** - inspect and remove roles, functions, and triggers.
- **curl** - review deployed edge functions.

## References

- Supabase - Database functions and Edge Functions
