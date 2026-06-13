---
cstg_id: CSTG-AWS-APPSYNC-ENUM
title: "AWS Appsync - Enumeration"
provider: aws
service: appsync
phase: services
required_access: read-only-audit
required_permissions:
  - appsync:ListGraphqlApis
  - appsync:GetGraphqlApi
  - appsync:ListApiKeys
  - appsync:GetSchemaCreationStatus
  - appsync:GetIntrospectionSchema
  - appsync:ListTypes
  - appsync:ListResolvers
  - appsync:GetResolver
  - appsync:ListDataSources
  - appsync:GetDataSource
  - appsync:ListFunctions
  - appsync:GetFunction
  - appsync:ListTagsForResource
references:
  - https://docs.aws.amazon.com/appsync/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/cli/latest/reference/appsync/index.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/resolver-mapping-template-reference-overview.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_service-with-iam.html
license: CC BY-SA 4.0
---

## Summary

This page covers credentialed, read-only enumeration of AWS AppSync from the control plane —
inventorying GraphQL APIs, their authorization configuration, API keys, schemas, resolvers,
data sources, pipeline functions, caching, logging, and the IAM roles AppSync assumes to reach
backing services. The goal is to build a complete map of each API's attack surface and to
identify the misconfigurations that the unauthenticated
([AWS AppSync - Unauthenticated Access](../01-unauthenticated-external/aws-appsync-unauthenticated.md))
and privilege-escalation
([AWS AppSync - Privilege Escalation](../03-privilege-escalation/aws-appsync-privesc.md))
phases exploit.

The control-plane reveals the things the data plane hides: which authorization modes are
enabled, every API key and its expiry, the exact resolver mapping templates (and therefore the
DynamoDB/SQL/HTTP operations they perform), every data source and its backing resource, and the
**service role ARNs** AppSync uses — each of which is a potential privilege-escalation pivot.

## Prerequisites

- Read/audit credentials in the target account (e.g. a role with `SecurityAudit` or equivalent
  `appsync:Get*`/`appsync:List*` permissions).
- AWS CLI v2 or SDK configured for the relevant region(s). AppSync is regional; iterate over
  all regions.

## Enumeration

### Inventory APIs

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $region =="
  aws appsync list-graphql-apis --region "$region" \
    --query 'graphqlApis[].{name:name,apiId:apiId,auth:authenticationType,uris:uris}' --output table
done
```

`list-graphql-apis` returns, per API: `apiId`, `name`, `authenticationType`,
`additionalAuthenticationProviders`, `uris` (GRAPHQL and REALTIME endpoints), `logConfig`,
`xrayEnabled`, `wafWebAclArn`, `tags`, and `apiType` (GRAPHQL or MERGED).

Pull the full detail for each API:

```bash
aws appsync get-graphql-api --region "$region" --api-id "$API_ID" --query 'graphqlApi'
```

Record for each API:

- **`authenticationType`** and **`additionalAuthenticationProviders`** — the full set of
  enabled modes (API_KEY, AWS_IAM, AMAZON_COGNITO_USER_POOLS, OPENID_CONNECT, AWS_LAMBDA).
  Any API with API_KEY enabled is a candidate for unauthenticated access.
- **`userPoolConfig.defaultAction`** — `ALLOW` means unauthenticated/unmatched requests are
  permitted by default (a common over-permissive setting).
- **`logConfig`** — whether request logging is enabled, the level, and whether verbose
  content is logged.
- **`wafWebAclArn`** — whether a WAF is attached (absence = no rate limiting / introspection
  blocking).
- **`xrayEnabled`**, **`additionalAuthenticationProviders[].openIDConnectConfig`** and
  **`lambdaAuthorizerConfig`** (the authorizer Lambda ARN).

### API keys

```bash
aws appsync list-api-keys --region "$region" --api-id "$API_ID" \
  --query 'apiKeys[].{id:id,expires:expires,description:description}' --output table
```

Each entry shows the key `id` (the `da2-...` value), `description`, and `expires` (epoch).
Flag: keys with very distant expiries (near the 365-day max), keys with descriptions implying
production use, and the mere existence of keys on a sensitive API.

### Schema and introspection

```bash
# Schema build status
aws appsync get-schema-creation-status --region "$region" --api-id "$API_ID"

# Retrieve the introspection schema (SDL or JSON) from the control plane
aws appsync get-introspection-schema --region "$region" --api-id "$API_ID" \
  --format SDL /tmp/$API_ID.graphql
cat /tmp/$API_ID.graphql

# Enumerate types directly
aws appsync list-types --region "$region" --api-id "$API_ID" --format SDL \
  --query 'types[].{name:name,definition:definition}'
```

The control-plane `get-introspection-schema` works even when data-plane introspection is
effectively blocked, giving the auditor the complete SDL including auth directives
(`@aws_api_key`, `@aws_cognito_user_pools`, `@aws_iam`, `@aws_oidc`, `@aws_auth`,
`@aws_subscribe`). Map every field to its required authorization mode.

### Resolvers, functions, and mapping templates

Resolvers are where authorization logic and data-store operations live. Enumerate them per
type and read the mapping templates / code:

```bash
# Resolvers attached to each type (Query, Mutation, Subscription, plus object types)
for t in Query Mutation Subscription; do
  aws appsync list-resolvers --region "$region" --api-id "$API_ID" --type-name "$t" \
    --query 'resolvers[].{field:fieldName,kind:kind,ds:dataSourceName,fn:functions}'
done

# Full resolver detail incl. request/response mapping templates or APPSYNC_JS code
aws appsync get-resolver --region "$region" --api-id "$API_ID" \
  --type-name Query --field-name listUsers

# Pipeline functions (shared resolver logic)
aws appsync list-functions --region "$region" --api-id "$API_ID" \
  --query 'functions[].{id:functionId,name:name,ds:dataSourceName}'
aws appsync get-function --region "$region" --api-id "$API_ID" --function-id "$FN_ID"
```

In `requestMappingTemplate`/`responseMappingTemplate` (VTL) or `code` (APPSYNC_JS) look for:

- **Unscoped operations** — DynamoDB `Scan`, `Query`/`GetItem` keyed on client-supplied input,
  SQL with concatenated parameters, HTTP requests built from raw arguments.
- **Missing identity checks** — templates that ignore `$context.identity` and trust
  client-supplied owner IDs (IDOR).
- **Injection sinks** — raw interpolation of `$context.args` into DynamoDB conditions, SQL, or
  outbound HTTP (NoSQL/SQL injection, SSRF).
- **Verbose error handling** that surfaces data-source internals.

### Data sources and the roles AppSync assumes

Data sources tie the API to backing services and carry the **service role** AppSync uses:

```bash
aws appsync list-data-sources --region "$region" --api-id "$API_ID" \
  --query 'dataSources[].{name:name,type:type,role:serviceRoleArn}' --output table

aws appsync get-data-source --region "$region" --api-id "$API_ID" --name "$DS_NAME"
```

Data source `type` values and what to record:

- **AMAZON_DYNAMODB** — `dynamodbConfig` (table name, region, `useCallerCredentials`,
  `versioned`, `deltaSyncConfig`) and `serviceRoleArn`.
- **AMAZON_OPENSEARCH_SERVICE / AMAZON_ELASTICSEARCH** — domain endpoint + role.
- **AWS_LAMBDA** — `lambdaConfig.lambdaFunctionArn` + role.
- **RELATIONAL_DATABASE** — `relationalDatabaseConfig` (RDS cluster ARN, secret ARN, database
  name) + role.
- **HTTP** — `httpConfig.endpoint` (potential SSRF/internal target) and any auth config.
- **AMAZON_EVENTBRIDGE** — event bus ARN + role.
- **NONE** — local resolver (no backend).

For every `serviceRoleArn`, inspect the attached policies — these define what the API can do to
the backing store and are the basis for the privilege-escalation phase:

```bash
ROLE=$(aws appsync get-data-source --region "$region" --api-id "$API_ID" --name "$DS_NAME" \
  --query 'dataSource.serviceRoleArn' --output text)
ROLE_NAME=${ROLE##*/}
aws iam list-attached-role-policies --role-name "$ROLE_NAME"
aws iam list-role-policies --role-name "$ROLE_NAME"
aws iam get-role --role-name "$ROLE_NAME" --query 'Role.AssumeRolePolicyDocument'
```

`useCallerCredentials: true` on a DynamoDB source means the *caller's* IAM identity is used
(IAM auth mode); `false`/absent means the AppSync service role's broad permissions are used for
all callers — a frequent over-permission.

### Caching, domains, and tags

```bash
aws appsync get-api-cache --region "$region" --api-id "$API_ID" 2>/dev/null
aws appsync list-domain-names --region "$region" 2>/dev/null
aws appsync list-tags-for-resource --region "$region" --resource-arn "$API_ARN"
```

A configured API cache may serve cached responses across callers; note `apiCachingBehavior`
(FULL_REQUEST_CACHING can leak data between principals if cache keys omit identity).

## Misconfigurations & Findings

- **API_KEY enabled** (especially as the default mode) on sensitive APIs — public-by-key data.
- **`userPoolConfig.defaultAction = ALLOW`** — unmatched requests permitted by default.
- **Field-level auth gaps** — sensitive queries/mutations lacking restrictive directives, or
  annotated `@aws_api_key`.
- **Over-permissive service roles** — `dynamodb:*`, `lambda:InvokeFunction` on broad ARNs,
  `rds-data:*`, `iam:PassRole`/`sts:AssumeRole`, or wildcard resources on the role AppSync
  assumes.
- **`useCallerCredentials: false`** on DynamoDB sources, so all callers share the role's broad
  access.
- **Unscoped resolver templates** — `Scan`, client-keyed lookups, raw SQL/HTTP interpolation.
- **HTTP data sources pointing at internal endpoints** — SSRF/pivot potential.
- **No WAF attached**, **logging disabled**, **X-Ray disabled** — limited detection and
  rate-limiting.
- **Long-lived API keys** approaching the 365-day maximum.
- **Cache configured without identity in the cache key** — cross-principal data exposure.

## Detection & Logging

- **CloudTrail** records the control-plane reads performed here (`ListGraphqlApis`,
  `GetGraphqlApi`, `ListApiKeys`, `GetIntrospectionSchema`, `ListResolvers`, `GetResolver`,
  `ListDataSources`, `GetDataSource`, etc.). A burst of `appsync:List*`/`Get*` from one
  principal across many regions is a strong enumeration signal.
- Note that `get-introspection-schema` and resolver reads expose the full schema and logic to
  any principal with audit permissions; alert on unusual readers.
- Data-plane queries are **not** in CloudTrail; correlate with AppSync CloudWatch request logs
  and WAF logs for runtime activity.

## Remediation & Hardening

- Restrict `appsync:Get*`/`List*` (and especially `GetIntrospectionSchema`, `GetResolver`,
  `ListApiKeys`) to roles that genuinely need them.
- Remove unused API keys; shorten expiries; avoid API_KEY for sensitive data.
- Set `userPoolConfig.defaultAction` to `DENY`.
- Apply least privilege to AppSync service roles; scope DynamoDB/Lambda/RDS/HTTP permissions to
  exact resources; remove `iam:PassRole`/wildcards.
- Prefer `useCallerCredentials: true` with IAM auth so per-caller IAM controls apply.
- Enable request logging, WAF, and X-Ray; include identity in cache keys or disable response
  caching for per-user data.
- Add restrictive field-level auth directives across the schema.

## Tools

- AWS CLI (`aws appsync ...`, `aws iam ...`) and AWS SDKs.
- IAM policy/role analysis tooling for evaluating service-role permissions.
- Multi-account/multi-region cloud inventory collectors.
- GraphQL SDL viewers for analysing the retrieved introspection schema.

## References

- AWS AppSync API Reference: https://docs.aws.amazon.com/appsync/latest/APIReference/Welcome.html
- AWS CLI — appsync command reference: https://docs.aws.amazon.com/cli/latest/reference/appsync/index.html
- AWS AppSync — Authorization and authentication: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
- AWS AppSync — Resolver mapping template reference: https://docs.aws.amazon.com/appsync/latest/devguide/resolver-mapping-template-reference-overview.html
- AWS AppSync — How AppSync works with IAM: https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_service-with-iam.html
