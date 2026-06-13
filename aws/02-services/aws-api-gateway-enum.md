---
cstg_id: CSTG-AWS-API-GATEWAY-ENUM
title: "AWS Api Gateway - Enumeration"
provider: aws
service: api-gateway
phase: services
required_access: read-only-audit
required_permissions:
  - apigateway:GET
  - lambda:GetPolicy
  - lambda:GetFunction
  - iam:GetRole
  - iam:GetRolePolicy
  - iam:ListRolePolicies
  - iam:ListAttachedRolePolicies
  - wafv2:GetWebACLForResource
  - logs:DescribeLogGroups
tools:
  - aws-cli
  - boto3
  - pmapper
  - cloudmapper
  - ScoutSuite
  - Prowler
references:
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html"
  - "https://docs.aws.amazon.com/apigateway/latest/api/Welcome.html"
  - "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/api-reference.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-resource-policies.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html"
  - "https://hackingthe.cloud/aws/enumeration/account_enumeration/"
license: CC BY-SA 4.0
---

## Summary

This page covers authenticated, read-oriented enumeration of Amazon API Gateway from inside an AWS account, using credentials that have audit/read access. The goal is to build a complete inventory of REST APIs (API Gateway v1), HTTP and WebSocket APIs (API Gateway v2), their stages, routes, integrations, authorizers, resource policies, API keys, usage plans, and the IAM roles the gateway assumes - and from that inventory identify the weak points (missing authorizers, permissive resource policies, dangerous integration roles) that the unauthenticated ([unauthenticated access](../01-unauthenticated-external/aws-api-gateway-unauthenticated.md)) and privilege-escalation ([privilege escalation](../03-privilege-escalation/aws-api-gateway-privesc.md)) phases build on.

API Gateway has two control-plane APIs:

- **`apigateway` (v1):** REST APIs (`restapis`), plus edge config. CLI: `aws apigateway ...`.
- **`apigatewayv2` (v2):** HTTP and WebSocket APIs. CLI: `aws apigatewayv2 ...`.

Both are gated almost entirely by the single coarse action **`apigateway:GET`** on `arn:aws:apigateway:{region}::/*` resources.

## Prerequisites

- Read access to the API Gateway control plane: `apigateway:GET` (covers all `GET` operations across v1 and v2).
- Helpful adjacent read permissions to follow the data flow: `lambda:GetPolicy`/`lambda:GetFunction` (integration targets and resource policies), `iam:GetRole`/`iam:GetRolePolicy`/`iam:ListAttachedRolePolicies` (gateway execution and authorizer/credentials roles), `wafv2:GetWebACLForResource` (associated Web ACLs), `logs:DescribeLogGroups` (access/execution logging status).

## Enumeration

### Inventory REST APIs (v1)

```bash
REGION=us-east-1

# List all REST APIs
aws apigateway get-rest-apis --region $REGION

# For a given API, enumerate its full structure
API=abc123xyz
aws apigateway get-resources --rest-api-id $API --region $REGION \
  --embed methods                       # resources + per-method config
aws apigateway get-stages   --rest-api-id $API --region $REGION
aws apigateway get-authorizers --rest-api-id $API --region $REGION
aws apigateway get-rest-api  --rest-api-id $API --region $REGION   # includes 'policy' (resource policy)
aws apigateway get-deployments --rest-api-id $API --region $REGION
```

Pull each method's authorization and integration in detail:

```bash
# For resource RES and method GET
RES=a1b2c3
aws apigateway get-method \
  --rest-api-id $API --resource-id $RES --http-method GET --region $REGION
# returns authorizationType, authorizerId, apiKeyRequired, methodIntegration

aws apigateway get-integration \
  --rest-api-id $API --resource-id $RES --http-method GET --region $REGION
# returns type (AWS/AWS_PROXY/HTTP/HTTP_PROXY/MOCK), uri, credentials (role ARN), connectionId
```

### Inventory HTTP and WebSocket APIs (v2)

```bash
aws apigatewayv2 get-apis --region $REGION

APIID=def456
aws apigatewayv2 get-routes      --api-id $APIID --region $REGION
aws apigatewayv2 get-integrations --api-id $APIID --region $REGION
aws apigatewayv2 get-authorizers  --api-id $APIID --region $REGION
aws apigatewayv2 get-stages       --api-id $APIID --region $REGION
```

### API keys, usage plans, custom domains, models

```bash
aws apigateway get-api-keys --include-values --region $REGION    # secret values if permitted
aws apigateway get-usage-plans --region $REGION
aws apigateway get-usage-plan-keys --usage-plan-id $UP --region $REGION
aws apigateway get-domain-names --region $REGION
aws apigateway get-base-path-mappings --domain-name api.example.com --region $REGION
aws apigateway get-vpc-links --region $REGION
aws apigatewayv2 get-vpc-links --region $REGION
```

`--include-values` on `get-api-keys` returns the raw key material - a high-value target on its own.

### Follow integrations to their backends and roles

```bash
# Lambda integration target: resolve the function and its resource policy
aws lambda get-policy --function-name myBackendFn --region $REGION
aws lambda get-function --function-name myBackendFn --region $REGION

# The role API Gateway uses for an AWS/AWS_PROXY integration (the 'credentials' field)
aws iam get-role --role-name apigw-integration-role
aws iam list-attached-role-policies --role-name apigw-integration-role
aws iam list-role-policies --role-name apigw-integration-role
aws iam get-role-policy --role-name apigw-integration-role --policy-name inline
```

### Logging, WAF, and account context

```bash
aws apigateway get-account --region $REGION                 # CloudWatch logging role
aws wafv2 get-web-acl-for-resource \
  --resource-arn "arn:aws:apigateway:$REGION::/restapis/$API/stages/prod" \
  --scope REGIONAL --region $REGION
aws logs describe-log-groups --log-group-name-prefix "API-Gateway-Execution-Logs_$API" --region $REGION
```

Iterate over all regions; API Gateway is regional and APIs are often scattered across regions.

## Misconfigurations & Findings

- **Methods/routes with `authorizationType: NONE` and `apiKeyRequired: false`** - publicly invokable. Cross-reference with the resource policy to confirm reachability.
- **Resource policy with `Principal: "*"`** lacking `aws:SourceVpce`, `aws:SourceIp`, or account/org conditions - a "private" API that is effectively open.
- **`AWS`/`AWS_PROXY`/`HTTP_PROXY` integrations with a powerful `credentials` role** - the gateway assumes this role on every invocation; an unauthenticated caller indirectly exercises its permissions (see Exploitation in the privesc page).
- **API keys retrievable in plaintext** via `get-api-keys --include-values`, or keys with no associated throttling.
- **No access logging / execution logging enabled** on stages - blind spot for incident response.
- **No associated WAF Web ACL** and **no usage-plan throttling**.
- **Lambda authorizers with caching** (`authorizerResultTtlInSeconds > 0`) keyed on attacker-controllable identity sources.
- **MOCK integrations** returning canned data that may leak structure, or **`{proxy+}` greedy routes** forwarding everything to a backend.
- **`disableExecuteApiEndpoint: false`** while a custom domain exists - the default endpoint remains reachable as a bypass.

## Exploitation

Enumeration is largely read-only, but the inventory directly seeds exploitation:

1. **Build the route-to-auth matrix.** From `get-resources --embed methods` (v1) and `get-routes` (v2), produce a table of every route x method with its `authorizationType`, `authorizerId`, and `apiKeyRequired`. Any `NONE`/`false` combination on a sensitive resource is an immediate unauthenticated target - hand it to the [unauthenticated phase](../01-unauthenticated-external/aws-api-gateway-unauthenticated.md).

2. **Resolve effective reachability.** Combine the route matrix with the resource policy and `disableExecuteApiEndpoint` to determine which endpoint URLs are actually callable from outside.

3. **Harvest secrets.** `get-api-keys --include-values` may yield live keys; `get-stages` `variables` and exported Swagger/OpenAPI (`get-export`) may embed backend URLs, tokens, or internal hostnames.

```bash
aws apigateway get-export \
  --rest-api-id $API --stage-name prod \
  --export-type oas30 /tmp/openapi.json --region $REGION
```

4. **Map the integration roles** for the privilege-escalation analysis (next phase): record every integration `credentials` role ARN and its attached policies.

## Detection & Logging

- **CloudTrail (management events):** All enumeration calls are read APIs logged as management events: `GetRestApis`, `GetResources`, `GetMethod`, `GetIntegration`, `GetAuthorizers`, `GetApiKeys`, `GetStages`, `GetExport`, plus the v2 equivalents (`GetApis`, `GetRoutes`, `GetIntegrations`). `eventSource` is `apigateway.amazonaws.com`.
- **High-signal events to alert on:** `GetApiKeys` with `includeValues=true`, `GetExport`, and a single principal sweeping `GetRestApis`/`GetResources`/`GetMethod` across many APIs and regions in a short window (classic post-compromise reconnaissance).
- **GuardDuty:** May raise findings such as anomalous API usage or recon behaviour tied to the calling principal.
- Note that **read enumeration does not appear in API Gateway access logs** (those record data-plane invocations); it is visible only in CloudTrail.

## Remediation & Hardening

- Scope `apigateway:GET` tightly; it is coarse and grants visibility into resource policies, stage variables, and (with values) API keys. Restrict `get-api-keys --include-values` via least privilege; prefer not granting it broadly.
- Avoid storing secrets in stage variables or exported specs; use Secrets Manager / Parameter Store referenced at runtime.
- Detect drift: alert on methods set to `authorizationType: NONE` on production APIs and on resource policies containing `Principal: "*"` without conditions.
- Enable access logging and execution logging on all stages so that subsequent invocation activity is captured.
- Tightly scope integration `credentials` roles to the single backend action they require.
- Rotate API keys and enforce throttling via usage plans; associate a WAF Web ACL.

## Tools

- **aws-cli / boto3** - the enumeration commands above; scriptable across regions and accounts.
- **ScoutSuite / Prowler** - automated multi-service audit that flags open resource policies, missing authorizers, and missing logging on API Gateway.
- **pmapper / cloudmapper** - graph the IAM roles attached to integrations and authorizers to spot escalation paths.

## References

- [Amazon API Gateway Developer Guide](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)
- [API Gateway REST API (v1) control-plane reference](https://docs.aws.amazon.com/apigateway/latest/api/Welcome.html)
- [API Gateway v2 (HTTP/WebSocket) API reference](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/api-reference.html)
- [API Gateway resource policies](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-resource-policies.html)
- [API Gateway permissions reference](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [hackingthe.cloud - Account enumeration](https://hackingthe.cloud/aws/enumeration/account_enumeration/)
