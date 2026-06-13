[![Creative Commons License](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/OWASP/owasp-cstg)

# OWASP Cloud Security Testing Guide

The **Cloud Security Testing Guide (CSTG)** is a comprehensive, vendor-neutral manual for testing
the security of cloud environments. It is written for penetration testers, cloud and platform
engineers, security architects, detection engineers, and auditors - anyone who needs to assess, or
defend, infrastructure running on a major cloud provider.

Cloud providers release and change services faster than any single team can track, and each new
managed service brings its own identity model, network exposure, and abuse paths. Traditional
network and application testing methodologies do not capture these provider-specific risks: an S3
bucket policy, an over-permissioned IAM role, a managed identity attached to a virtual machine, or a
writable deployment bucket are not findings a port scan or a web proxy will surface. CSTG exists to
fill that gap with a structured, repeatable, provider-specific testing methodology.

## What makes CSTG different

- **Offensive *and* defensive.** Every technique page documents not only how to enumerate and
  exploit a weakness, but the **detection** footprint it leaves in the provider's logs and the
  concrete **remediation** that closes it. The guide is as useful to a blue team hardening an estate
  as to a tester attacking it.
- **Access-aware.** Cloud assessments are gated by the access the tester is given - from an
  anonymous external position, a single leaked credential, a read-only audit role, or an elevated
  principal. Each page declares the access it assumes, so an engagement can be scoped to what is
  actually testable with the credentials available.
- **Atomic and structured.** Content is organised as a **phase × service matrix** per provider, with
  one self-describing page per service and testing phase. This makes the guide easy to navigate, to
  contribute to, and to consume programmatically.
- **Comprehensive.** The goal is to document the full, real-world technique set for each service -
  the enumeration commands, the misconfigurations that matter, and the privilege-escalation,
  lateral-movement, post-exploitation, and persistence paths that follow.

## How the guide is organised

Each provider is divided into testing **phases**, and within each phase the atomic unit is a single
**service** page:

| Phase | Question it answers |
| --- | --- |
| **Basic Information** | How does this provider's identity, access, and resource model work? |
| **Unauthenticated / External** | What is exposed to an attacker with no credentials? |
| **Services (Enumeration)** | With valid credentials, what is deployed and how is it configured? |
| **Privilege Escalation** | How can a low-privilege principal gain more access? |
| **Lateral Movement** | How does access move between services, accounts, or to on-premises? |
| **Post-Exploitation** | What can an attacker do with the access obtained? |
| **Persistence** | How is durable access established and hidden? |

The sharpest boundary in the guide is **unauthenticated vs authenticated** testing, reflecting the
single most important question in any cloud engagement: *what access do we have to begin with?*

Each page follows a fixed structure - Summary, Prerequisites, Enumeration, Misconfigurations &
Findings, Exploitation, Detection & Logging, Remediation & Hardening, Tools, References - and carries
machine-readable frontmatter (provider, service, phase, required access, required permissions). See
[STRUCTURE.md](STRUCTURE.md) for the authoring format and the access-tier definitions.

## Provider guides

### Amazon Web Services (AWS)
Identity (IAM/STS), storage (S3, EBS), compute (EC2, Lambda, ECS/EKS, ECR), data (RDS, DynamoDB),
application and integration (API Gateway, SNS/SQS, Cognito), infrastructure-as-code (CloudFormation),
secrets and keys (Secrets Manager, SSM, KMS), and logging/monitoring (CloudTrail).

### Microsoft Azure
Identity (Entra ID, RBAC, Managed Identities), storage (Storage Accounts), compute (Virtual
Machines, AKS), application (App Service, Functions, Logic Apps), automation (Automation Accounts,
ARM templates), secrets and keys (Key Vault), and networking.

### Google Cloud Platform (GCP)
Identity (IAM, Service Accounts), storage (Cloud Storage), compute (Compute Engine, GKE, Cloud Run,
Cloud Functions), data (Cloud SQL), build and integration (Cloud Build, Pub/Sub), secrets and keys
(Secret Manager, KMS), and Workspace pivoting.

### Managed application platforms (PaaS / BaaS)
Platform services whose security model is based on API keys, tokens, and application-layer controls
rather than infrastructure IAM. Their phases are adapted accordingly.

- **Supabase** - the anon vs `service_role` key model, the auto-generated PostgREST API, and
  PostgreSQL Row Level Security (RLS), plus Auth, Storage, and Edge Functions.
- **Vercel** - access tokens and team roles, environment-variable secrets, deployment protection
  and preview deployments, and serverless / edge functions.

## Using the guide

1. Establish the **access** available for the engagement (provider, credential form, privilege
   level, scope) - this determines which phases and pages are in play.
2. Work the phases in order: understand the platform, test the external surface, then (with
   credentials) enumerate, escalate, move laterally, and assess post-exploitation and persistence.
3. For each finding, use the **Detection & Logging** and **Remediation & Hardening** sections to give
   the asset owner actionable, defensive output - not just an attack narrative.

> **Authorisation and rules of engagement.** Testing cloud environments is subject to each
> provider's acceptable-use and penetration-testing policies. Denial-of-service and destructive
> actions are prohibited by default across AWS, Azure, and GCP without prior approval. Always test
> only environments you are explicitly authorised to assess, within the agreed scope.

## Contributing

CSTG is community-driven. New service pages, additional techniques, corrections, and provider
coverage are all welcome - see [STRUCTURE.md](STRUCTURE.md) for the page format and the issue
templates under `.github/ISSUE_TEMPLATE/`. All contributions are licensed under CC BY-SA 4.0.

## Project Leaders
- [Stefano Di Paola](https://github.com/wisec)
- [Jamieson O'Reilly](https://github.com/orlyjamie)

## License
This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
