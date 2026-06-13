---
cstg_id: CSTG-AWS-API-GATEWAY-UNAUTH
title: "AWS Api Gateway - Unauthenticated Access"
provider: aws
service: api-gateway
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools:
  - curl
  - httpx
  - ffuf
  - amass
  - nuclei
references:
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-call-api.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-resource-policies.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-using-iam-policies-to-invoke-api.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html"
  - "https://hackingthe.cloud/aws/general-knowledge/intro_aws_attacking/"
license: CC BY-SA 4.0
---

## Summary

Amazon API Gateway is a managed service for publishing HTTP, REST, and WebSocket APIs that front Lambda functions, HTTP backends, AWS service integrations, and VPC resources. Because the gateway is internet-facing by default and its endpoints are not inherently secret, it is one of the most common externally reachable AWS surfaces.

This page covers what an unauthenticated party - someone holding no AWS credentials - can discover and exploit against an API Gateway deployment from the public internet. The attacker objective is to (1) discover live API endpoints and their structure, (2) identify routes or methods that lack authentication or are misconfigured, and (3) invoke backend functionality, leak data, or pivot toward the integrated backend (Lambda, internal HTTP services, other AWS services) without ever authenticating to AWS.

Two URL shapes are in scope:

- **Default execute-api endpoint:** `https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/{resource}`
- **Custom domain mapping:** `https://api.example.com/...` mapped to one or more APIs/stages via a base path mapping. The custom domain hides the API ID and region but the underlying behaviour is identical.

## Prerequisites

- No AWS credentials. All techniques rely only on the API being reachable over the public internet (the default for edge-optimized and regional REST APIs and for HTTP APIs).
- Knowledge or discovery of at least one API ID, custom domain, or stage name. These are recoverable through DNS, certificate transparency, JavaScript/mobile-app reverse engineering, or brute force.

## Enumeration

### Discover endpoints from the outside

API IDs and custom domains leak through the artifacts that consume them. Useful sources:

- **Client-side code:** Search JavaScript bundles, SPA config files, and mobile app binaries for `execute-api.<region>.amazonaws.com`, stage names, and `x-api-key` literals.
- **Certificate transparency / subdomain enumeration:** Custom API domains often appear in CT logs.

```bash
# Subdomain and CT enumeration for custom API domains
amass enum -passive -d example.com
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Probe for live API hosts and grab status/title/tech
httpx -l hosts.txt -status-code -title -tech-detect -follow-redirects
```

The default endpoint format reveals two facts immediately: the **region** (e.g. `us-east-1`) and the **API ID**. The API ID is a random string and is not brute-forceable in practice, but the **stage** and **resource path** segments often are.

### Probe stages and routes

```bash
BASE="https://abc123xyz.execute-api.us-east-1.amazonaws.com"

# Common stage names
for s in prod production dev development stage staging test qa v1 v2 api default; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$s/")
  echo "$code  $BASE/$s/"
done

# Brute-force resources within a discovered stage
ffuf -u "$BASE/prod/FUZZ" -w /path/to/api-wordlist.txt -mc all -fc 403 -t 50
```

Notes on interpreting responses:

- `{"message":"Missing Authentication Token"}` with HTTP 403 is the **default API Gateway response for a route/method that does not exist**, not necessarily an auth wall. It is the single most useful enumeration signal: a different response means a real route exists.
- `{"message":"Forbidden"}` typically indicates a **resource policy** or WAF denial.
- `{"message":"Unauthorized"}` indicates an attached **authorizer** (IAM, Cognito, Lambda, or JWT) is rejecting the request.

### Enumerate HTTP methods per resource

```bash
for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "== $m =="
  curl -s -X "$m" -o /dev/null -w "%{http_code}\n" "$BASE/prod/users"
done

# OPTIONS frequently reveals allowed methods and CORS configuration
curl -s -i -X OPTIONS "$BASE/prod/users" \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST"
```

### Recover structure via SDK/docs artifacts

If the team published a Swagger/OpenAPI file, an exported SDK, or API documentation, the full route map, parameters, and required headers may be available. Search the target's web assets, S3 buckets, and public repositories for `swagger.json`, `openapi.yaml`, and generated SDK packages.

## Misconfigurations & Findings

- **Routes/methods with no authorizer (`authorizationType: NONE`)** that expose sensitive functionality. The most common high-impact finding: a route meant for internal or authenticated use is publicly invokable.
- **Permissive resource policy** - a REST API resource policy with `Principal: "*"` and no `aws:SourceVpce`, `aws:SourceIp`, or account condition, leaving a "private" API effectively public.
- **API keys treated as a security boundary.** API keys are for usage plans/throttling, not authentication. Keys embedded in client code grant whatever the route allows.
- **Overly broad CORS** (`Access-Control-Allow-Origin: *` combined with credentialed or sensitive endpoints) enabling cross-site data theft from a victim browser.
- **Verbose error responses / stack traces** from the backend leaking through the integration response, revealing Lambda function names, ARNs, internal hostnames, or library versions.
- **Mock or test stages left enabled** (`dev`, `test`, `debug`) with weaker auth than `prod`.
- **No WAF and no throttling**, enabling brute force, enumeration, and cost-amplification / denial-of-wallet against pay-per-invoke backends.
- **Greedy proxy integrations** (`{proxy+}` / `ANY`) that forward arbitrary paths and methods to a backend, widening the attack surface and exposing path-traversal-style routing to backend resources.
- **SSRF-prone integrations** where user-controlled input reaches an HTTP or AWS-service integration that can be redirected to internal endpoints.

## Exploitation

### Invoke an unauthenticated route

When a route returns anything other than the default "Missing Authentication Token" message, it exists and is reachable. Drive it with realistic payloads:

```bash
# Unauthenticated data read
curl -s "$BASE/prod/users?limit=1000"

# Unauthenticated write to a Lambda/proxy backend
curl -s -X POST "$BASE/prod/orders" \
  -H "Content-Type: application/json" \
  -d '{"item":"x","qty":1}'
```

### Bypass an authorizer via method/route gaps

Authorization is configured **per method per resource**. A `GET` may require an authorizer while `POST`, `PUT`, or `OPTIONS` on the same resource was left as `NONE`. Enumerate every method (above) and look for the gap. Likewise a child resource (`/admin/users`) may be unprotected even when the parent appears locked.

### Abuse greedy proxy routing

For `ANY /{proxy+}` integrations, manipulate the trailing path and method to reach backend handlers that the developers did not expect to be externally addressable:

```bash
curl -s "$BASE/prod/internal/healthcheck"
curl -s "$BASE/prod/../prod/admin"          # routing/normalization quirks
curl -s -X DELETE "$BASE/prod/{proxy}/cache"
```

### Exploit weak custom-authorizer logic

Lambda (token/request) authorizers are custom code and frequently contain logic flaws: accepting empty/`null` tokens, caching an allow decision keyed only on a header attacker controls, or failing open on exceptions. Probe with malformed, empty, and structurally-valid-but-unsigned tokens, and test cache poisoning by reusing identity-bearing headers.

### CORS-based data theft

If a sensitive endpoint reflects the request `Origin` into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`, a malicious site can read responses from a victim's authenticated browser session. Confirm by sending an attacker `Origin` and checking the reflected ACAO header.

### Denial-of-wallet / throttling abuse

Where no usage plan, key requirement, or WAF rate limit is present, repeated invocation of a pay-per-use backend (Lambda, DynamoDB, downstream APIs) inflates cost and can exhaust concurrency, degrading availability for legitimate users.

## Detection & Logging

- **CloudTrail (management events):** Configuration of APIs themselves (`CreateDeployment`, `UpdateRestApiPolicy`, `CreateAuthorizer`, `UpdateStage`) is logged, but **API invocations (the data plane) are not in standard CloudTrail.** External invocation of an endpoint is not visible in CloudTrail alone.
- **API Gateway access logs:** Must be explicitly enabled per stage; they capture source IP, route, status, latency, and `$context` variables (including authorizer principal). This is the primary record of unauthenticated invocation attempts.
- **CloudWatch execution logs and metrics:** `4XXError`/`5XXError`, `Count`, and `Latency` metrics; a spike in 403/401 responses indicates enumeration or auth probing.
- **AWS WAF logs:** If a Web ACL is associated, blocked and counted requests are logged with matched rules.
- **VPC Flow Logs / backend logs:** For private APIs and HTTP integrations, downstream invocation appears in backend service logs even when gateway access logging is off.

Indicators of unauthenticated probing: bursts of 403 with "Missing Authentication Token", systematic path/method fanning from a single source, OPTIONS-heavy traffic, and requests with unusual `Origin` headers.

## Remediation & Hardening

- Require authorization on **every method of every resource**; never leave `authorizationType: NONE` on sensitive routes. Audit the `OPTIONS`, `PUT`, and proxy methods specifically.
- Use IAM authorization, a Cognito user pool authorizer, a JWT authorizer (HTTP APIs), or a hardened Lambda authorizer. Ensure custom authorizers fail closed and do not cache on attacker-controlled keys.
- Do not treat API keys as authentication; use them only for usage plans and throttling, and never embed long-lived secrets in client code.
- For private/internal APIs, use **private API endpoints** with a resource policy restricting `aws:SourceVpce`, plus interface VPC endpoints; avoid `Principal: "*"` without strong conditions.
- Attach **AWS WAF** with managed rule groups and rate-based rules; configure usage plans / throttling to limit brute force and denial-of-wallet.
- Restrict CORS to explicit allowed origins; never reflect arbitrary `Origin` with credentials.
- Suppress backend error detail in integration/gateway responses; return generic errors externally.
- Disable or lock down non-production stages; remove unused stages and routes.
- Map custom domains and disable the default `execute-api` endpoint (`disableExecuteApiEndpoint`) when only the custom domain should be reachable.

## Tools

- **curl / httpx** - manual and bulk endpoint probing, method enumeration, header inspection.
- **ffuf** - resource and stage path brute forcing.
- **amass / crt.sh** - custom-domain and certificate-transparency discovery.
- **nuclei** - templated detection of exposed API Gateway misconfigurations, CORS issues, and default responses.

## References

- [Amazon API Gateway Developer Guide](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)
- [How to call an API](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-call-api.html)
- [Controlling and managing access to a REST API](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html)
- [API Gateway resource policies](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-resource-policies.html)
- [Control access using IAM policies to invoke an API](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-using-iam-policies-to-invoke-api.html)
- [JWT authorizers for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
- [hackingthe.cloud - Attacking AWS](https://hackingthe.cloud/aws/general-knowledge/intro_aws_attacking/)
