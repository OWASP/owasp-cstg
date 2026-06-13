---
cstg_id: CSTG-GCP-PUB-SUB-ENUM
title: "GCP Pub/Sub - Enumeration"
provider: gcp
service: pub-sub
phase: services
required_access: read-only-audit
required_permissions:
  - pubsub.topics.list
  - pubsub.topics.getIamPolicy
  - pubsub.subscriptions.list
  - pubsub.subscriptions.getIamPolicy
tools: [gcloud, scoutsuite, prowler]
references:
  - "https://cloud.google.com/pubsub/docs/access-control"
  - "https://cloud.google.com/pubsub/docs/admin"
license: CC BY-SA 4.0
---

## Summary

Pub/Sub is a managed messaging service: publishers send messages to **topics**, and
**subscriptions** deliver them to consumers. Access is governed by IAM policies set at the
topic and subscription level (in addition to project-level roles). Because messages frequently carry
sensitive event data, and because subscriptions can be attached by anyone with the right
permission, Pub/Sub IAM exposure is a meaningful confidentiality and integrity risk. This page
covers read-only enumeration of topics, subscriptions, and their access policies.

## Prerequisites

A principal with read access to Pub/Sub and IAM (`Viewer` / `Security Reviewer`).

## Enumeration

```bash
gcloud config set project <project>
gcloud pubsub topics list
gcloud pubsub subscriptions list
# Access policy per resource
gcloud pubsub topics get-iam-policy <topic>
gcloud pubsub subscriptions get-iam-policy <subscription>
# Subscription detail: which topic it drains, push endpoint, retention
gcloud pubsub subscriptions describe <subscription>
gcloud pubsub schemas list
```

`describe` on a push subscription reveals the **push endpoint** (and any attached service-account
identity used to authenticate the push), useful for understanding where messages flow.

## Misconfigurations & Findings

- **Overly broad IAM bindings** - `roles/pubsub.editor`/`admin`, or `allUsers`/`allAuthenticatedUsers`
  on a topic or subscription, exposing message data or allowing arbitrary publishing.
- **Cross-project / external principals** granted subscribe or publish on sensitive topics.
- **Push subscriptions to untrusted endpoints**, or push identities with excessive permissions.
- **No encryption with a customer-managed key (CMEK)** where message content is sensitive.
- **Schemas absent** where message integrity/validation is expected.

## Detection & Logging

Pub/Sub admin operations (`CreateTopic`, `SetIamPolicy`, `CreateSubscription`) are recorded in
**Cloud Audit Logs** Admin Activity. Data-plane operations (publish/pull) are logged only when Data
Access audit logs are enabled for Pub/Sub - their absence limits visibility into who consumed
messages. Alert on `SetIamPolicy` changes and new subscriptions on sensitive topics.

## Remediation & Hardening

- Apply **least-privilege IAM** at the topic/subscription level; never grant `allUsers` /
  `allAuthenticatedUsers`.
- Restrict who can create subscriptions on sensitive topics.
- Use **CMEK** for sensitive message data and validate with **schemas**.
- Authenticate push subscriptions with a dedicated, least-privilege service account; vet endpoints.
- Enable **Data Access audit logs** for Pub/Sub on sensitive projects.

## Tools

- **gcloud** - authoritative enumeration of topics, subscriptions, and IAM policies.
- **Prowler**, **ScoutSuite** - flag public or broad Pub/Sub bindings in a posture audit.

## References

- Google Cloud - Pub/Sub access control
- Google Cloud - Managing topics and subscriptions
