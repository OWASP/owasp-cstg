---
cstg_id: CSTG-AZURE-SERVICE-BUS-ENUM
title: "AZURE Service Bus - Enumeration"
provider: azure
service: service-bus
phase: services
required_access: read-only-audit
required_permissions:
  - Microsoft.ServiceBus/namespaces/read
  - Microsoft.ServiceBus/namespaces/queues/read
  - Microsoft.ServiceBus/namespaces/topics/read
  - Microsoft.ServiceBus/namespaces/authorizationRules/read
  - Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action
  - Microsoft.ServiceBus/namespaces/networkRuleSets/read
  - Microsoft.ServiceBus/namespaces/privateEndpointConnections/read
  - Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/read
tools:
  - Azure CLI
  - Azure PowerShell (Az module)
  - Azure REST API
  - Azure Resource Graph
  - Service Bus AMQP/HTTP client libraries
references:
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-messaging-overview
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity
  - https://learn.microsoft.com/en-us/rest/api/servicebus/
  - https://learn.microsoft.com/en-us/cli/azure/servicebus
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#integration
  - https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security
license: CC BY-SA 4.0
---

## Summary

Azure Service Bus is a fully managed enterprise message broker providing queues
(point-to-point), topics with subscriptions (publish/subscribe), and advanced
messaging features such as sessions, dead-letter queues, scheduled delivery, and
transactions. Service Bus frequently sits at the centre of an organisation's
integration fabric: order processing, financial transactions, command-and-control
for backend workers, event fan-out, and cross-service decoupling. Messages in
transit therefore commonly contain personally identifiable information, payment
data, internal API payloads, credentials, and business-critical commands.

From a security-testing perspective, Service Bus is a high-value target for two
reasons. First, **Shared Access Signature (SAS) keys** grant long-lived,
namespace- or entity-scoped access to send and receive messages, and these keys
are routinely embedded in application configuration, key vaults, CI/CD pipelines,
and connection strings. Second, the **data plane and the management plane are
governed by different authorisation systems**: Azure RBAC (`Microsoft.ServiceBus/*`)
controls the management plane (creating namespaces, reading authorization rules,
listing keys), while data-plane operations (send/receive/peek) are governed either
by SAS tokens or by Azure RBAC data actions backed by Microsoft Entra ID. A reader
who can enumerate a namespace's authorization rules and list its keys effectively
holds the data-plane keys to every queue and topic in that namespace.

This page covers enumeration only: discovering namespaces, entities, authorization
rules, key material, network exposure, and identity configuration. Active key
abuse, role-assignment abuse, and message interception are covered in
[Service Bus - Privilege Escalation](../03-privilege-escalation/azure-service-bus-privesc.md).

## Prerequisites

- An authenticated principal (user, service principal, or managed identity) with
  at least read access to the target subscription or resource group, or a Reader
  role at namespace scope.
- For management-plane enumeration: directory/subscription read access plus the
  `Microsoft.ServiceBus/namespaces/read` action.
- For key extraction: `Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action`
  (or the entity-level equivalent). The built-in **Contributor** and **Azure Service
  Bus Data Owner** roles, and any custom role granting `listKeys`, satisfy this.
- For data-plane enumeration over AMQP/HTTP: either a valid SAS connection string,
  or an Entra ID token for a principal holding `Azure Service Bus Data Receiver`,
  `Azure Service Bus Data Sender`, or `Azure Service Bus Data Owner` at namespace
  or entity scope.
- Tooling: Azure CLI with the `servicebus` extension or built-in commands, Azure
  PowerShell, or any AMQP 1.0 / HTTP client. Azure Resource Graph access is
  helpful for fleet-wide discovery.

## Enumeration

### Tenant- and subscription-wide discovery (management plane)

Identify every Service Bus namespace across the accessible estate. Azure Resource
Graph is the fastest path and returns SKU, location, and resource ID in one query.

```bash
# List all Service Bus namespaces across all accessible subscriptions
az graph query -q "
  Resources
  | where type =~ 'microsoft.servicebus/namespaces'
  | project name, resourceGroup, subscriptionId, location,
            sku = tostring(sku.name), id, tags
" --first 1000 -o table

# Equivalent ARM list call, per subscription
az servicebus namespace list -o table

# Raw REST
az rest --method get \
  --url "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.ServiceBus/namespaces?api-version=2022-10-01-preview"
```

PowerShell equivalent:

```powershell
Get-AzServiceBusNamespace | Select-Object Name, ResourceGroupName, Location, SkuName
```

The SKU (`Basic`, `Standard`, `Premium`) is security-relevant: only **Premium**
supports VNet integration, private endpoints, and customer-managed keys. `Basic`
and `Standard` namespaces are reachable from the public internet by default and
support topics only on `Standard`+.

### Namespace detail and configuration

```bash
az servicebus namespace show \
  --resource-group <RG> --name <NAMESPACE> -o json
```

Inspect the returned object for:

- `serviceBusEndpoint` / `properties.serviceBusEndpoint` — the public FQDN
  (`<namespace>.servicebus.windows.net`).
- `properties.minimumTlsVersion` — flag anything below `1.2`.
- `properties.disableLocalAuth` — when `false` (the default), SAS key auth is
  enabled. When `true`, only Entra ID auth is accepted; this materially changes
  the attack surface.
- `properties.zoneRedundant`, `sku.name`, `sku.tier`.
- `identity` — presence of a system-assigned or user-assigned managed identity,
  and its `principalId`. A namespace identity is used for customer-managed key
  access and is a pivot target.
- `properties.encryption` — customer-managed key (CMK) configuration and the
  referenced Key Vault.

### Entity enumeration: queues, topics, subscriptions, rules

```bash
# Queues
az servicebus queue list --resource-group <RG> --namespace-name <NAMESPACE> -o table

# Per-queue detail (message counts reveal live traffic and backlog)
az servicebus queue show --resource-group <RG> --namespace-name <NAMESPACE> \
  --name <QUEUE> -o json

# Topics
az servicebus topic list --resource-group <RG> --namespace-name <NAMESPACE> -o table

# Subscriptions under a topic
az servicebus topic subscription list --resource-group <RG> \
  --namespace-name <NAMESPACE> --topic-name <TOPIC> -o table

# Subscription rules / filters (reveal routing logic and data classification)
az servicebus topic subscription rule list --resource-group <RG> \
  --namespace-name <NAMESPACE> --topic-name <TOPIC> --subscription-name <SUB> -o json
```

The `countDetails` and `messageCount` fields on queues and subscriptions are
valuable reconnaissance: a non-zero `activeMessageCount` indicates live data
present for the taking, while a growing `deadLetterMessageCount` often indicates
poison messages that may contain sensitive payloads no consumer successfully
processed. Entity names themselves frequently leak business context
(`prod-payments-settlement`, `pii-export-queue`, `admin-commands`).

### Authorization rules and SAS key discovery

This is the core of Service Bus enumeration. Authorization rules exist at two
scopes: **namespace** and **entity** (per-queue / per-topic). Each rule carries a
set of rights (`Listen`, `Send`, `Manage`) and two named keys.

```bash
# Namespace-scoped authorization rules (RootManageSharedAccessKey is the default,
# and grants Listen+Send+Manage over the ENTIRE namespace)
az servicebus namespace authorization-rule list \
  --resource-group <RG> --namespace-name <NAMESPACE> -o table

# Entity-scoped rules
az servicebus queue authorization-rule list \
  --resource-group <RG> --namespace-name <NAMESPACE> --queue-name <QUEUE> -o table
az servicebus topic authorization-rule list \
  --resource-group <RG> --namespace-name <NAMESPACE> --topic-name <TOPIC> -o table
```

If the caller holds `listKeys`, the live key material and connection strings can
be retrieved directly. Treat any output of the following as a credential of the
highest sensitivity:

```bash
az servicebus namespace authorization-rule keys list \
  --resource-group <RG> --namespace-name <NAMESPACE> \
  --name RootManageSharedAccessKey -o json
```

The response contains `primaryKey`, `secondaryKey`, `primaryConnectionString`,
and `secondaryConnectionString`. A connection string of the form
`Endpoint=sb://<ns>.servicebus.windows.net/;SharedAccessKeyName=<rule>;SharedAccessKey=<key>`
is immediately usable from any internet-connected client unless network rules
restrict it. Note the `Rights` array on the rule: a `Manage` rule can itself
create further authorization rules and read keys, making it a persistence and
escalation primitive (see the privilege-escalation page).

REST equivalent for the key listing:

```bash
az rest --method post \
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.ServiceBus/namespaces/<NAMESPACE>/authorizationRules/RootManageSharedAccessKey/listKeys?api-version=2022-10-01-preview"
```

### Data-plane enumeration over AMQP/HTTP

With a SAS connection string or an Entra ID token, the broker itself can be
queried without touching the ARM management plane. The Service Bus runtime FQDN
is `<namespace>.servicebus.windows.net` over AMQP 1.0 (5671/TLS) and HTTPS (443).
Reading runtime properties and **peeking** messages is non-destructive — peek does
not lock or remove messages — and is the safest way to confirm the presence and
nature of in-flight data during an authorised assessment.

```python
# Non-destructive peek using an Entra ID credential (no SAS key required)
from azure.servicebus import ServiceBusClient
from azure.identity import DefaultAzureCredential

ns = "<namespace>.servicebus.windows.net"
client = ServiceBusClient(ns, credential=DefaultAzureCredential())

with client.get_queue_receiver("<queue>") as receiver:
    for msg in receiver.peek_messages(max_message_count=5):
        print(msg.message_id, msg.sequence_number, str(msg))
```

```python
# Runtime properties (active/dead-letter counts) via SAS connection string
from azure.servicebus.management import ServiceBusAdministrationClient
admin = ServiceBusAdministrationClient.from_connection_string("<CONN_STRING>")
for q in admin.list_queues_runtime_properties():
    print(q.name, q.active_message_count, q.dead_letter_message_count)
```

Peeking the dead-letter sub-queue (`<queue>/$DeadLetterQueue`) often surfaces the
richest data, since failed messages accumulate there indefinitely.

### Network and access-control posture

```bash
# Network rule set: default action, IP allow-lists, VNet rules, public access flag
az servicebus namespace network-rule-set show \
  --resource-group <RG> --namespace-name <NAMESPACE> -o json

# Private endpoint connections
az servicebus namespace private-endpoint-connection list \
  --resource-group <RG> --namespace-name <NAMESPACE> -o json

# Geo-disaster-recovery pairing (alias namespaces extend the trust boundary)
az servicebus georecovery-alias list \
  --resource-group <RG> --namespace-name <NAMESPACE> -o table
```

Record `defaultAction` (`Allow` vs `Deny`), `publicNetworkAccess`, and the
presence of `ipRules` / `virtualNetworkRules`. A namespace with
`defaultAction: Allow` and no private endpoint is reachable from anywhere a valid
SAS key or token is presented.

### RBAC and identity enumeration

Map who holds management- and data-plane authority over each namespace.

```bash
# All role assignments scoped at or below the namespace
az role assignment list --all \
  --scope "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.ServiceBus/namespaces/<NAMESPACE>" \
  -o table
```

Catalogue principals holding the data-plane roles **Azure Service Bus Data Owner**
(`090c5cfd-751d-490a-894a-3ce6f1109419`), **Azure Service Bus Data Sender**, and
**Azure Service Bus Data Receiver**, as well as management roles (Contributor,
Owner) that can list keys. Cross-reference managed identities discovered in the
namespace `identity` block and in consuming applications (App Service, Functions,
AKS, VMs) — these identities are the realistic pivot when local auth is disabled.

## Misconfigurations & Findings

- **`RootManageSharedAccessKey` in active use.** The default namespace rule grants
  Listen+Send+Manage over the whole namespace; its presence in application config
  is a single point of total compromise.
- **`disableLocalAuth = false` with broad SAS distribution.** SAS keys are
  long-lived bearer credentials with no built-in expiry; once leaked they remain
  valid until manually regenerated.
- **`Manage`-rights rules handed to applications.** Applications rarely need
  Manage; granting it lets a compromised app mint new keys.
- **Public network access enabled (`defaultAction: Allow`, no private endpoint).**
  Combined with a leaked key, this allows data-plane access from the open internet.
- **`minimumTlsVersion` below 1.2** or TLS not enforced.
- **Over-broad data-plane RBAC** — Data Owner assigned where Receiver/Sender
  suffices, or assignments at subscription/RG scope inherited by all namespaces.
- **Connection strings in source control, pipeline variables, ARM/Bicep outputs,
  or App Settings** retrievable by lower-privileged readers.
- **Dead-letter backlogs** retaining sensitive payloads indefinitely.
- **Geo-DR alias namespaces** that silently extend the data trust boundary to a
  second region/namespace.

## Detection & Logging

Enumeration of Service Bus leaves traces across two log sources:

- **Azure Activity Log** records management-plane operations. The key signal is
  `Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action` —
  enumeration of SAS keys. Also watch
  `.../authorizationRules/read`, `namespaces/read`, and `queues/read` bursts that
  indicate fleet sweeps. Query example:

```bash
az monitor activity-log list --resource-group <RG> \
  --offset 7d \
  --query "[?contains(operationName.value, 'authorizationRules/listKeys')]" -o table
```

- **Microsoft Entra ID sign-in and audit logs** capture token issuance for the
  service principals/managed identities performing the enumeration, including the
  resource `https://servicebus.azure.net`. Correlate sign-ins from unexpected IPs
  or principals against the Activity Log key-listing events.
- **Diagnostic settings** on the namespace (when enabled) emit `OperationalLogs`
  and runtime audit logs to Log Analytics; absence of a diagnostic setting is
  itself a finding because data-plane access then goes largely unrecorded.

Note that pure data-plane peek/receive over AMQP is **not** captured by the
Activity Log; it appears only if namespace diagnostic logging is configured. This
gap is precisely why key listing (a loud management-plane event) and subsequent
quiet data-plane abuse should be correlated.

## Remediation & Hardening

- Set `disableLocalAuth = true` to enforce Entra ID-only authentication and
  eliminate long-lived SAS bearer keys where applications support it.
- Where SAS is required, delete the default `RootManageSharedAccessKey` from
  application use, issue per-entity rules scoped to the minimum rights
  (`Listen` OR `Send`, never `Manage`), and rotate keys on a schedule using the
  primary/secondary pattern.
- Prefer per-entity authorization over namespace-wide rules.
- Use Premium SKU with private endpoints and `defaultAction: Deny`; restrict
  `publicNetworkAccess`.
- Assign data-plane RBAC at the narrowest scope and the least role (Receiver or
  Sender, not Owner). Avoid subscription/RG-level data-role inheritance.
- Enforce `minimumTlsVersion: 1.2`.
- Enable namespace diagnostic settings to Log Analytics so data-plane operations
  are auditable; alert on `listKeys` events.
- Store any connection strings only in Key Vault with tight access policies; never
  in source control or plaintext app settings.

## Tools

- **Azure CLI** (`az servicebus`, `az rest`, `az graph`, `az monitor`) — primary
  management-plane enumeration.
- **Azure PowerShell (Az.ServiceBus)** — equivalent cmdlets.
- **Azure Resource Graph** — fast cross-subscription namespace discovery.
- **Azure Service Bus client libraries** (.NET, Java, Python, JavaScript) — AMQP/HTTP
  data-plane peek and runtime-property reads.
- **Azure REST API** — direct ARM and runtime calls where CLI coverage is thin.

## References

- Service Bus messaging overview — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-messaging-overview
- Service Bus SAS authentication — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
- Authentication and authorization — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization
- Managed identities with Service Bus — https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity
- Service Bus REST API — https://learn.microsoft.com/en-us/rest/api/servicebus/
- az servicebus CLI reference — https://learn.microsoft.com/en-us/cli/azure/servicebus
- Built-in roles (Integration) — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#integration
- Service Bus network security — https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security
