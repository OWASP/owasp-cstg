---
cstg_id: CSTG-AWS-SES-ENUM
title: "AWS Ses - Enumeration"
provider: aws
service: ses
phase: services
required_access: read-only-audit
required_permissions:
  - ses:GetAccount
  - ses:ListIdentities
  - ses:GetIdentityVerificationAttributes
  - ses:GetIdentityDkimAttributes
  - ses:GetIdentityMailFromDomainAttributes
  - ses:GetIdentityPolicies
  - ses:ListIdentityPolicies
  - ses:DescribeConfigurationSet
  - ses:ListConfigurationSets
  - ses:GetSendQuota
  - ses:GetSendStatistics
  - ses:ListReceiptRuleSets
  - ses:DescribeActiveReceiptRuleSet
  - ses:ListEmailIdentities
  - ses:GetEmailIdentity
  - ses:ListEmailTemplates
  - ses:ListContactLists
references:
  - https://docs.aws.amazon.com/ses/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html
  - https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
  - https://docs.aws.amazon.com/ses/latest/dg/receiving-email.html
  - https://hackingthe.cloud/aws/enumeration/loot/
  - https://aws.permissions.cloud/iam/ses
license: CC BY-SA 4.0
---

## Summary

Amazon Simple Email Service (SES) is a managed bulk and transactional email platform. From a security-testing perspective it is a high-value target for two reasons: it provides a trusted, deliverable email channel that can be abused for phishing and spoofing of an organization's own verified domains, and (when inbound receiving is configured) it can be coupled to S3, SNS, and Lambda to intercept or exfiltrate mail. SES exposes two API generations — the original API (`ses:*`, AWS SDK/CLI `aws ses`) and SES v2 (`ses:*` actions under the v2 namespace, CLI `aws sesv2`) — which share an underlying resource model but use different verbs.

Enumeration of SES establishes:

- Which **identities** (domains and email addresses) are verified and therefore usable as `From` addresses.
- Whether the account is in the **sandbox** or has **production** sending access, and the current **sending quota** (24-hour cap and max send rate).
- Whether **DKIM**, **SPF**/custom MAIL FROM, and **DMARC** are configured — both a deliverability signal and a spoofing-resistance signal.
- **Identity (authorization) policies** that may allow cross-account `SendEmail`/`SendRawEmail` (delegated sending).
- **Configuration sets** and their event-publishing destinations (CloudWatch, SNS, Kinesis Firehose) which can leak recipient data.
- **Inbound receipt rule sets** that deliver mail to S3/SNS/Lambda/WorkMail — a powerful interception primitive.
- Stored **email templates** and **contact lists** which frequently contain PII and reusable phishing content.

This page covers read-only discovery. Active abuse (sending, interception, suppression tampering) is covered in [aws-ses-post-exploitation.md](../05-post-exploitation/aws-ses-post-exploitation.md), and durable footholds in [aws-ses-persistence.md](../06-persistence/aws-ses-persistence.md).

## Prerequisites

- Valid credentials (IAM user, role session, or federated session) for the target account.
- For full read coverage, the read-only permissions listed in the frontmatter. The AWS managed policies `AmazonSESReadOnlyAccess`, `ReadOnlyAccess`, and `SecurityAudit` grant most of these.
- SES is **regional**. Identities, configuration sets, receipt rule sets, quotas, and templates are scoped per Region. Inbound email receiving is only available in a subset of Regions. Enumerate every Region the organization uses; do not assume `us-east-1`.
- Note the API split: classic actions use `aws ses ...`; newer features (email identities with granular DKIM signing attributes, contact lists, suppression list, dedicated IP pools, virtual deliverability manager) use `aws sesv2 ...`. Enumerate with both where available, because IAM policies often grant one namespace and not the other.

## Enumeration

### Account-level sending posture

Determine whether the account can send to arbitrary recipients (production) or only to verified addresses (sandbox), and the volume ceiling:

```bash
# Classic API
aws ses get-send-quota --region us-east-1
aws ses get-account-sending-enabled --region us-east-1

# SES v2 — richer account object (sandbox status, enforcement, suppression config)
aws sesv2 get-account --region us-east-1
```

`get-account` returns `ProductionAccessEnabled` (false = sandbox), `SendingEnabled`, `EnforcementStatus`, the `SendQuota` (`Max24HourSend`, `MaxSendRate`, `SentLast24Hours`), and the account-level `SuppressionAttributes`. A production account with a high `Max24HourSend` and many verified domains is a strong phishing platform.

### Identities (the spoofable surface)

```bash
# Classic — both domains and email addresses
aws ses list-identities --region us-east-1
aws ses list-identities --identity-type Domain --region us-east-1
aws ses list-identities --identity-type EmailAddress --region us-east-1

# Verification + DKIM + custom MAIL FROM status (batch up to 100 identities)
aws ses get-identity-verification-attributes \
  --identities example.com user@example.com --region us-east-1
aws ses get-identity-dkim-attributes \
  --identities example.com --region us-east-1
aws ses get-identity-mail-from-domain-attributes \
  --identities example.com --region us-east-1

# SES v2 equivalent — per-identity detail in one call
aws sesv2 list-email-identities --region us-east-1
aws sesv2 get-email-identity --email-identity example.com --region us-east-1
```

For each identity capture: `VerificationStatus` (only `Success` identities can be used as senders), `DkimEnabled`/`DkimVerificationStatus`, `SigningEnabled`, and the MAIL FROM domain. A **verified domain** is more dangerous than a verified address — it allows sending as *any* mailbox `@example.com`, including executives, no-reply, finance, etc.

### Identity authorization (sending) policies

These resource policies on an identity authorize *other principals/accounts* to send as it (delegated sending). They are a common cross-account escalation and abuse vector:

```bash
aws ses list-identity-policies --identity example.com --region us-east-1
aws ses get-identity-policies --identity example.com \
  --policy-names PolicyName1 --region us-east-1
```

Flag any policy whose `Principal` includes `*`, a wildcard `AWS:*`, an external account ID, or a broad `aws:PrincipalOrgID` without tight conditions, especially when paired with `ses:SendEmail`/`ses:SendRawEmail`.

### Configuration sets and event destinations

Configuration sets group sending and attach event destinations. Those destinations can stream recipient addresses, message metadata, bounces, and complaints to logging sinks an attacker may already read:

```bash
aws ses list-configuration-sets --region us-east-1
aws ses describe-configuration-set \
  --configuration-set-name MyConfigSet \
  --configuration-set-attribute-names eventDestinations trackingOptions \
    deliveryOptions reputationOptions --region us-east-1

# SES v2
aws sesv2 list-configuration-sets --region us-east-1
aws sesv2 get-configuration-set --configuration-set-name MyConfigSet --region us-east-1
aws sesv2 get-configuration-set-event-destinations \
  --configuration-set-name MyConfigSet --region us-east-1
```

Note SNS topics, Kinesis Firehose streams, and CloudWatch dimensions used as event sinks — they may expose recipient lists and message subjects. Also note `TrackingOptions` custom redirect domains, which reveal recipient interaction with links.

### Inbound email receiving (interception surface)

Only relevant in Regions that support SES inbound receiving (e.g. `us-east-1`, `us-west-2`, `eu-west-1`). Receipt rules can write inbound mail to S3 or invoke Lambda/SNS:

```bash
aws ses list-receipt-rule-sets --region us-east-1
aws ses describe-active-receipt-rule-set --region us-east-1
aws ses describe-receipt-rule-set --rule-set-name MyRuleSet --region us-east-1
```

For each rule record the `Recipients` it matches, and the ordered `Actions` (`S3Action` bucket/prefix, `LambdaAction` function ARN, `SNSAction` topic, `WorkmailAction`, `BounceAction`, `StopAction`). An S3Action target bucket frequently contains the full raw content of received emails — review S3 access separately.

### Templates, contact lists, and suppression

```bash
# Classic templates
aws ses list-templates --region us-east-1
aws ses get-template --template-name WelcomeEmail --region us-east-1

# SES v2 templates, contact lists, contacts
aws sesv2 list-email-templates --region us-east-1
aws sesv2 get-email-template --template-name WelcomeEmail --region us-east-1
aws sesv2 list-contact-lists --region us-east-1
aws sesv2 list-contacts --contact-list-name Newsletter --region us-east-1

# Account + configuration-set suppression lists (recipient addresses)
aws sesv2 list-suppressed-destinations --region us-east-1
```

Templates and contact lists are a rich source of recipient PII, internal subdomains, and ready-made, brand-consistent message bodies that lower the effort to craft convincing phishing.

### Cross-Region sweep

Because everything above is regional, script the sweep across all enabled Regions:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="
  aws sesv2 get-account --region "$r" 2>/dev/null \
    --query '{Prod:ProductionAccessEnabled,Send:SendingEnabled,Quota:SendQuota.Max24HourSend}'
  aws ses list-identities --region "$r" --output text 2>/dev/null
done
```

## Misconfigurations & Findings

- **Verified domain identities** that allow sending as any local-part, with weak or absent **DMARC** (`p=none`) at the DNS layer — internal/external spoofing is fully deliverable and DKIM-signed by the org.
- **Production access with a large 24-hour quota** combined with broad `ses:SendEmail`/`SendRawEmail` grants to many principals.
- **Identity authorization policies** allowing external accounts or wildcards to send as a verified identity.
- **DKIM disabled** or `Easy DKIM` not verified on otherwise-verified domains.
- **No custom MAIL FROM domain**, so SPF aligns to `amazonses.com` rather than the org domain — weakens DMARC alignment and is an indicator of loose configuration.
- **Event destinations** pointing to SNS/Firehose/CloudWatch that expose recipient addresses and subjects to readers of those services.
- **Inbound receipt rules** delivering mail to S3 buckets/Lambda — review for overbroad bucket policies and for catch-all recipient matches (`Recipients` empty = matches all).
- **Contact lists and templates** containing PII or credentials in template variables/defaults.
- Overly permissive IAM allowing `ses:*` to roles that only need to send via a single identity.

## Detection & Logging

All SES management-plane calls are recorded in **CloudTrail** as events from `ses.amazonaws.com` (covers both classic and v2; v2 calls appear with their v2 event names). Read-only enumeration generates a recognizable burst of `Get*`/`List*`/`Describe*` events:

- `GetAccount`, `GetSendQuota`, `GetAccountSendingEnabled`
- `ListIdentities`, `GetIdentityVerificationAttributes`, `GetIdentityDkimAttributes`, `GetIdentityPolicies`, `ListIdentityPolicies`
- `ListConfigurationSets`, `DescribeConfigurationSet`, `GetConfigurationSetEventDestinations`
- `ListReceiptRuleSets`, `DescribeActiveReceiptRuleSet`, `DescribeReceiptRuleSet`
- `ListTemplates`, `ListEmailTemplates`, `ListContactLists`, `ListSuppressedDestinations`

Detection signals: a single principal enumerating SES across many Regions in a short window; SES read activity from a principal or role with no prior SES history; SES API calls from unusual source IPs, user agents (SDK vs CLI), or assumed-role sessions tied to compute that does not normally touch SES. Note that **data-plane sending** (`SendEmail`, `SendRawEmail`, `SendBulkEmail`) is *not* logged in CloudTrail by default — rely on SES sending event publishing and CloudWatch sending metrics for that visibility, which is why event-destination enumeration above matters.

## Remediation & Hardening

- Scope IAM to the minimum needed: prefer `ses:SendEmail`/`SendRawEmail` constrained by `ses:FromAddress`/`ses:Recipients` conditions and a specific identity ARN resource, rather than `ses:*`.
- Enforce **DKIM** on all verified domains and configure a **custom MAIL FROM** domain for SPF alignment; publish DMARC at the DNS layer with `p=quarantine`/`p=reject`.
- Remove or tightly condition cross-account identity authorization policies; never use `Principal: "*"`.
- Restrict who can create/modify configuration sets, event destinations, and receipt rule sets; review event-destination targets for least-exposure.
- Lock down S3 buckets used by inbound `S3Action` and the Lambda functions invoked by receipt rules.
- Enable SES event publishing to a controlled destination and forward to a SIEM so data-plane sending is observable; alert on sending-rate anomalies and on bounce/complaint spikes.
- Keep accounts in the sandbox unless production sending is genuinely required; right-size the sending quota.

## Tools

- AWS CLI (`aws ses`, `aws sesv2`) and AWS SDKs.
- Multi-service cloud enumeration frameworks that include SES identity, policy, and receipt-rule collection.
- IAM permission reference and policy-evaluation tooling to map which principals can send as which identity.
- CloudTrail / Athena for reviewing historical SES management activity.

## References

- AWS SES API Reference (classic): https://docs.aws.amazon.com/ses/latest/APIReference/Welcome.html
- AWS SES API Reference (v2): https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html
- Monitoring your Amazon SES sending activity: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
- Receiving email with Amazon SES: https://docs.aws.amazon.com/ses/latest/dg/receiving-email.html
- hackingthe.cloud — enumeration / loot: https://hackingthe.cloud/aws/enumeration/loot/
- SES IAM actions reference: https://aws.permissions.cloud/iam/ses
