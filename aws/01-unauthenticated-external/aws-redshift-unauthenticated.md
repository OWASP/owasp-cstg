---
cstg_id: CSTG-AWS-REDSHIFT-UNAUTH
title: "AWS Redshift - Unauthenticated Access"
provider: aws
service: redshift
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - aws-cli
  - psql
  - nmap
  - redshift-jdbc/odbc-client
  - masscan
  - cloud-asset-search-engines
references:
  - https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/security-network-isolation.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/managing-cluster-considerations.html
  - https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-authentication-access-control.html
  - https://docs.aws.amazon.com/redshift/latest/dg/c_intro_to_qsqls.html
  - https://hackingthe.cloud/aws/exploitation/
license: CC BY-SA 4.0
---

## Summary

Amazon Redshift is a managed, petabyte-scale data warehouse. Clusters (provisioned) and workgroups (Redshift Serverless) expose a PostgreSQL-compatible wire protocol on TCP port 5439 by default. When a cluster is launched with **public accessibility** enabled and its associated VPC security group permits inbound traffic from the internet, the database endpoint becomes reachable from anywhere. Because Redshift stores aggregated, often highly sensitive analytical data (consolidated PII, financial records, telemetry, logs), an exposed endpoint is a high-value target.

From an unauthenticated, external perspective the goal of this phase is to determine whether a Redshift endpoint exists, whether it is internet-reachable, and whether it can be reached without valid credentials through misconfiguration (open security groups, weak/default/guessable credentials, leaked credentials, or unauthenticated data-access features such as Redshift Data API misuse via leaked tokens). No AWS API access is assumed here; discovery relies on DNS, network scanning, certificate metadata, and public data exposure.

## Prerequisites

- Network egress to the target's public IP ranges / endpoints (TCP 5439 by default, though operators may relocate the listener to another port).
- No AWS credentials are required for this phase. Where leaked material (connection strings, credentials, snapshots shared publicly) is in scope, those artifacts substitute for live credentials.
- A PostgreSQL-protocol client capable of speaking to Redshift (e.g. `psql`, JDBC/ODBC drivers).

## Enumeration

### Identify candidate endpoints

Provisioned Redshift cluster endpoints follow predictable DNS patterns:

```
<cluster-identifier>.<random>.<region>.redshift.amazonaws.com
```

Redshift Serverless endpoints follow:

```
<workgroup>.<account-id>.<region>.redshift-serverless.amazonaws.com
```

Discovery vectors that do not require AWS access:

- **Passive DNS / certificate transparency.** Search CT logs and passive DNS datasets for `*.redshift.amazonaws.com` and `*.redshift-serverless.amazonaws.com` hostnames attributable to the target. The cluster identifier and (for serverless) the AWS account ID are frequently disclosed in these hostnames.
- **Subdomain and CNAME records.** Organisations commonly publish friendly CNAMEs (e.g. `warehouse.example.com` -> `prod-cluster.abc123.us-east-1.redshift.amazonaws.com`). Enumerate the target's DNS for records pointing at Redshift endpoints.
- **Source-code and document leaks.** Search public repositories, paste sites, CI logs, mobile apps, and JS bundles for endpoint hostnames, JDBC/ODBC connection strings (`jdbc:redshift://host:5439/dev`), and embedded credentials.
- **Internet-wide scan data.** Query cloud asset / internet scan engines for hosts answering on 5439 within AWS-attributed IP space.

### Confirm reachability

```bash
# TCP reachability to the default Redshift port
nmap -Pn -p 5439 <cluster-endpoint>

# Large-scale sweep of candidate ranges
masscan -p5439 <cidr> --rate 1000
```

A Redshift listener completes the TCP handshake and will negotiate the PostgreSQL startup/SSL handshake. Banner/protocol fingerprinting:

```bash
# Probe the startup handshake; Redshift advertises PostgreSQL-compatible behaviour
psql "host=<endpoint> port=5439 dbname=dev user=probe sslmode=prefer connect_timeout=5"
```

### TLS metadata

The TLS certificate presented on 5439 often confirms the endpoint is Redshift and may leak the cluster identifier / region in the SAN/CN. Capture it:

```bash
openssl s_client -connect <endpoint>:5439 -starttls postgres 2>/dev/null | openssl x509 -noout -text
```

## Misconfigurations & Findings

- **Publicly accessible cluster.** `PubliclyAccessible = true` combined with an internet-routable elastic IP / public subnet means the endpoint resolves to a public address.
- **Permissive security group.** Inbound rule allowing `0.0.0.0/0` (or broad CIDRs) to TCP 5439. This is the single most common path to an exposed warehouse. See [security group exposure](../02-services/aws-ec2-security-groups-enum.md) for the broader pattern.
- **Default / weak master credentials.** The cluster admin username (often left as `awsuser` or `admin`) combined with a weak, reused, or leaked master password allows direct login.
- **Leaked credentials in code or config.** Connection strings with embedded passwords committed to source control, embedded in client apps, or present in unsecured backups.
- **`require_ssl` disabled.** Cleartext authentication and query traffic over the internet, enabling credential interception on-path.
- **Publicly shared snapshots.** A cluster snapshot shared with `all` (public) lets any AWS account restore a full copy of the warehouse. See the post-exploitation page for the snapshot-sharing technique; from an external view, publicly shared snapshots are an unauthenticated data-exposure finding.
- **Quicksight / BI proxies and unauthenticated front-ends** that connect to Redshift with embedded service credentials and expose query functionality without authentication.

## Exploitation

> Only test endpoints and accounts you are explicitly authorised to assess. Connecting to a database constitutes access; treat scope and rules of engagement strictly.

### Direct authentication with discovered/guessed credentials

If credentials were recovered (leak, default, or weak-password guess against the master user), authenticate directly:

```bash
psql "host=<endpoint> port=5439 dbname=dev user=<user> sslmode=require" 
# or with password in the connection string (avoid in shared shells / history)
psql "host=<endpoint> port=5439 dbname=dev user=<user> password=<pw> sslmode=require"
```

On success, immediate low-impact confirmation queries:

```sql
SELECT current_user, current_database(), version();
SELECT datname FROM pg_database;
SELECT usename, usesuper FROM pg_user;
```

### Credential spraying

Where a valid username is known (e.g. `awsuser`/`admin` or one disclosed in a leak), a low-rate, lockout-aware spray of a small list of likely passwords may succeed. Redshift master passwords are operator-set and are a frequent reuse point. Keep attempts minimal and within engagement constraints.

### Restoring a publicly shared snapshot

If a cluster snapshot is shared publicly, any AWS account can restore it into its own VPC and read the entire dataset offline, bypassing the source cluster's network controls. This crosses into authenticated-tenant activity and is detailed in [post-exploitation](../05-post-exploitation/aws-redshift-post-exploitation.md#exfiltration-via-snapshot-sharing).

## Detection & Logging

- **CloudTrail (management events).** `CreateCluster`, `ModifyCluster`, and `RestoreFromClusterSnapshot` calls reveal when a cluster became publicly accessible or had its security group changed. `AuthorizeClusterSecurityGroupIngress` / EC2 `AuthorizeSecurityGroupIngress` show the rule that opened 5439.
- **Redshift connection and user-activity logs.** Audit logging (`enable_user_activity_logging` / cluster audit logging to S3 or CloudWatch) records `connectionlog`, `userlog`, and `useractivitylog` entries: source IP, username, authentication outcome, SSL usage, and executed SQL. Repeated failed authentications from external IPs indicate spraying.
- **VPC Flow Logs.** Inbound connections to the ENI on port 5439 from internet sources.
- **GuardDuty.** Anomalous access patterns and connections from known-malicious IPs to RDS/Redshift-style endpoints.

Indicators: authentication failures from many source IPs, successful logins from previously unseen geographies/ASNs, non-SSL connections when SSL is expected, and `RestoreFromClusterSnapshot` in unexpected accounts referencing a shared snapshot.

## Remediation & Hardening

- **Disable public accessibility.** Set `PubliclyAccessible = false`; place clusters/workgroups in private subnets and reach them via VPN, Direct Connect, PrivateLink, or a bastion.
- **Restrict security groups.** Remove `0.0.0.0/0` on 5439; allow only specific trusted CIDRs / security-group references.
- **Enforce SSL.** Set the `require_ssl` parameter to `true` so all connections are encrypted and cleartext auth is rejected.
- **Strong, unique master credentials.** Rotate from any default username; use a long random master password stored in Secrets Manager; prefer IAM-based authentication (`GetClusterCredentials` / IAM identity center) and short-lived credentials over static passwords.
- **Never share snapshots publicly.** Audit snapshot share lists; restrict sharing to specific, known account IDs.
- **Enable audit logging** (connection, user, and user-activity logs) and monitor for failed-auth bursts and unexpected source IPs.
- **Disclose nothing in DNS/source.** Avoid descriptive CNAMEs and remove connection strings/credentials from code, client apps, and CI artifacts.

## Tools

- `aws-cli` (Redshift / Redshift Serverless APIs - for the authorised tenant view)
- `psql` and JDBC/ODBC Redshift drivers (PostgreSQL-protocol clients)
- `nmap`, `masscan` (port discovery)
- `openssl` (TLS certificate inspection)
- Certificate-transparency, passive-DNS, and internet-scan search engines
- Secret-scanning tooling for leaked connection strings/credentials

## References

- AWS - Managing clusters in a VPC: https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html
- AWS - Network isolation and security: https://docs.aws.amazon.com/redshift/latest/mgmt/security-network-isolation.html
- AWS - Cluster considerations (public accessibility): https://docs.aws.amazon.com/redshift/latest/mgmt/managing-cluster-considerations.html
- AWS - IAM authentication and access control for Redshift: https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-authentication-access-control.html
- AWS - Connecting with the query editor / clients: https://docs.aws.amazon.com/redshift/latest/dg/c_intro_to_qsqls.html
- Hacking the Cloud - AWS exploitation techniques: https://hackingthe.cloud/aws/exploitation/
