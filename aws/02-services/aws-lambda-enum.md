---
cstg_id: CSTG-AWS-LAMBDA-ENUM
title: "AWS Lambda - Enumeration"
provider: aws
service: lambda
phase: services
required_access: read-only-audit
required_permissions:
  - lambda:ListFunctions
  - lambda:GetFunction
  - lambda:GetFunctionConfiguration
  - lambda:GetPolicy
  - lambda:ListVersionsByFunction
  - lambda:ListAliases
  - lambda:ListEventSourceMappings
  - lambda:ListLayers
  - lambda:GetLayerVersion
  - lambda:ListFunctionUrlConfigs
  - lambda:GetFunctionUrlConfig
  - iam:GetRole
  - iam:ListRolePolicies
  - iam:ListAttachedRolePolicies
tools: [aws-cli, scoutsuite, prowler, cloudfox, pmapper]
references:
  - "https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/lambda/"
  - "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
  - "https://hackingthe.cloud/aws/exploitation/lambda-steal-iam-credentials/"
license: CC BY-SA 4.0
---

## Summary

AWS Lambda runs code on demand under an **execution role** (an IAM role) and is invoked by a wide
range of event sources - API Gateway, Function URLs, S3, DynamoDB streams, SQS, SNS, EventBridge,
Kinesis, ALB, and others. From a testing perspective Lambda is interesting for three reasons: the
function's code and configuration frequently contain secrets and connection strings; the execution
role is a credential the function holds and may grant far more than the function needs; and any
principal able to read or modify functions, layers, or resource policies can pivot toward code
execution under that role. This page covers authenticated, read-only enumeration of Lambda from a
credentialed principal: the inventory of functions, their configuration and code, the roles they
assume, how they can be invoked, and the supporting constructs (layers, event source mappings,
Function URLs, resource policies) that determine exposure.

Privilege escalation paths are covered in
[AWS Lambda - Privilege Escalation](../03-privilege-escalation/aws-lambda-privesc.md); use of a
compromised function for further access is covered in
[AWS Lambda - Post-Exploitation](../05-post-exploitation/aws-lambda-post-exploitation.md).

## Prerequisites

A principal with read access to the Lambda control plane and, ideally, IAM read access to resolve
execution roles. A read-only audit role (`SecurityAudit` / `ViewOnlyAccess`) is sufficient and
recommended. Reading function code requires `lambda:GetFunction` (which returns a pre-signed URL to
the deployment package); inspecting environment variables requires `lambda:GetFunctionConfiguration`
or `GetFunction`.

## Enumeration

Establish identity and region, then inventory functions (Lambda is regional - repeat per region):

```bash
aws sts get-caller-identity
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $R =="
  aws lambda list-functions --region "$R" \
    --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Role:Role,Handler:Handler}' \
    --output table
done
```

For each function collect configuration, role, environment, layers, and code location:

```bash
F=target-function
aws lambda get-function                --function-name "$F"          # config + code Location URL
aws lambda get-function-configuration  --function-name "$F" \
  --query '{Role:Role,Env:Environment.Variables,Vpc:VpcConfig,Layers:Layers[].Arn,Handler:Handler,Runtime:Runtime,Timeout:Timeout}'
aws lambda list-versions-by-function   --function-name "$F"
aws lambda list-aliases                --function-name "$F"
```

Environment variables are the most common quick win - they routinely hold database credentials, API
keys, and tokens in plaintext:

```bash
aws lambda get-function-configuration --function-name "$F" \
  --query 'Environment.Variables' --output json
```

Download and inspect the deployment package (the `Code.Location` field is a short-lived pre-signed
URL; no `s3:GetObject` permission is required):

```bash
URL=$(aws lambda get-function --function-name "$F" --query 'Code.Location' --output text)
curl -s "$URL" -o "$F.zip" && unzip -o "$F.zip" -d "$F" && grep -rIE \
  'AKIA|aws_secret|password|api[_-]?key|token|BEGIN .*PRIVATE KEY' "$F"
```

Enumerate how the function can be invoked. Resource-based policies, Function URLs, and event source
mappings each create an invocation surface:

```bash
aws lambda get-policy            --function-name "$F" --query Policy --output text   # resource policy
aws lambda list-function-url-configs --function-name "$F"                            # public/IAM URL
aws lambda get-function-url-config   --function-name "$F"                            # AuthType: NONE?
aws lambda list-event-source-mappings --function-name "$F"                           # SQS/DDB/Kinesis
```

Enumerate layers (shared code/dependencies that run in the function's context) and their access
policies, account-wide:

```bash
aws lambda list-layers
aws lambda list-layer-versions --layer-name <layer>
aws lambda get-layer-version-policy --layer-name <layer> --version-number <n>
```

Resolve the execution role to understand the blast radius of the function and any downstream privesc:

```bash
ROLE=$(aws lambda get-function-configuration --function-name "$F" --query Role --output text)
RN=${ROLE##*/}
aws iam get-role --role-name "$RN" --query 'Role.AssumeRolePolicyDocument'
aws iam list-attached-role-policies --role-name "$RN"
aws iam list-role-policies          --role-name "$RN"
```

## Misconfigurations & Findings

- **Secrets in environment variables** - credentials, API keys, or tokens stored in plaintext env
  vars instead of Secrets Manager / SSM Parameter Store; visible to anyone with
  `lambda:GetFunctionConfiguration`.
- **Secrets or sensitive logic in the deployment package** - hard-coded keys, private keys, internal
  hostnames, or `.env` files readable via the pre-signed `Code.Location` URL.
- **Function URL with `AuthType: NONE`** - the function is invocable unauthenticated over the
  internet; combined with an over-privileged role this is a direct exposure.
- **Over-permissive resource policy** - a `lambda:InvokeFunction` grant to `Principal: "*"`, a wide
  `Service` principal, or a foreign account without `SourceArn`/`SourceAccount` conditions.
- **Over-privileged execution role** - the role carries `*:*`, `iam:*`, `AdministratorAccess`, or
  data-store wildcards far beyond what the function needs; this is the value of a Lambda compromise.
- **Cross-account layer or function policies** - layers shared to other accounts, or invoke rights
  granted cross-account, expanding trust beyond the boundary.
- **No reserved concurrency / no dead-letter or destination config** - operational, but also relevant
  to abuse (uncapped invocation, lost evidence).
- **Functions in a VPC with broad security groups** - the role plus network position can reach
  internal data stores.

## Detection & Logging

The enumeration calls above are Lambda **control-plane** management events recorded in **CloudTrail**
(`ListFunctions`, `GetFunction`, `GetFunctionConfiguration`, `GetPolicy`, `ListEventSourceMappings`,
`GetFunctionUrlConfig`, `GetLayerVersionPolicy`). A burst of `GetFunction`/`GetFunctionConfiguration`
across many functions and regions from one principal is a strong reconnaissance signal. Note that
`GetFunction` returns a pre-signed S3 URL whose subsequent download is **not** a Lambda or CloudTrail
event - code exfiltration via that URL is invisible at the Lambda layer. Function **invocation** is an
`Invoke` data event, logged only if Lambda data events are enabled on the trail. **GuardDuty** and
IAM Access Analyzer surface resource policies that grant external access.

## Remediation & Hardening

- Store secrets in **Secrets Manager** or **SSM Parameter Store** and fetch at runtime; keep them out
  of environment variables and the deployment package.
- Apply **least-privilege execution roles** - one role per function, scoped to the exact resources and
  actions needed; never reuse a broad shared role.
- Avoid `AuthType: NONE` Function URLs; use `AWS_IAM` auth or front the function with API Gateway and
  an authorizer.
- Constrain resource-based policies with `SourceArn`/`SourceAccount` and specific principals; review
  cross-account grants with IAM Access Analyzer.
- Encrypt environment variables with a customer-managed KMS key and restrict `kms:Decrypt`.
- Enable **CloudTrail Lambda data events** for sensitive functions and alert on configuration changes.

## Tools

- **aws-cli** - authoritative enumeration via the `lambda` and `iam` commands.
- **Prowler**, **ScoutSuite** - read-only posture checks for public Function URLs, permissive
  policies, plaintext secrets, and over-privileged roles.
- **CloudFox** - surfaces functions, their roles, env vars, and reachable secrets from an offensive
  vantage point.
- **PMapper** - models the execution role into the account's IAM graph to reveal escalation paths.

## References

- AWS - Lambda security (developer guide)
- AWS - Lambda CLI command reference
- AWS - Using resource-based policies for Lambda
- hackingthe.cloud - Steal IAM credentials from a Lambda function
