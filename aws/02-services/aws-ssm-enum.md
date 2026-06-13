---
cstg_id: CSTG-AWS-SSM-ENUM
title: "AWS Ssm - Enumeration"
provider: aws
service: ssm
phase: services
required_access: read-only-audit
required_permissions:
  - ssm:DescribeInstanceInformation
  - ssm:ListDocuments
  - ssm:GetDocument
  - ssm:DescribeParameters
  - ssm:GetParameters
  - ssm:GetParametersByPath
  - ssm:ListCommands
  - ssm:ListCommandInvocations
  - ssm:DescribeSessions
  - ssm:DescribeAssociations
  - ssm:DescribeMaintenanceWindows
  - ssm:DescribePatchBaselines
  - ssm:ListInventoryEntries
  - ssm:GetInventory
tools:
  - aws-cli
  - boto3
  - cloud-iam-enumeration-tooling
references:
  - "https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/cli/latest/reference/ssm/index.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html"
  - "https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/"
license: CC BY-SA 4.0
---

## Summary

AWS Systems Manager (SSM) is a management and operations service that provides remote command execution, interactive shell access (Session Manager), configuration management (State Manager and associations), patching, inventory collection, and a hierarchical secrets/configuration store (Parameter Store). Because SSM can execute arbitrary commands as root/SYSTEM on every managed node, and because Parameter Store frequently holds credentials, connection strings, and API keys, SSM is one of the highest-value services to enumerate in an AWS environment.

This page covers read-only enumeration of SSM: discovering which instances are managed (the SSM agent is installed and reporting), what documents (runbooks) exist, what is stored in Parameter Store, what commands and sessions have run historically, and what associations, maintenance windows, and inventory data reveal about the environment. The attacker objective is to map the blast radius of SSM permissions, locate stored secrets, and identify managed nodes that can be reached without ever touching SSH, RDP, or a network path.

## Prerequisites

- Valid AWS credentials (IAM user, role, or temporary STS session) with read/describe permissions on SSM.
- The List/Describe/Get permissions enumerated in `required_permissions`. Note that `ssm:GetParameters` and `ssm:GetParameter` return secret values; `ssm:DescribeParameters` returns only metadata (names, types) and is the minimum needed to find parameters.
- For decrypting `SecureString` parameters, the caller also needs `kms:Decrypt` on the KMS key that encrypts the parameter (the AWS-managed `alias/aws/ssm` key by default, or a customer-managed key).
- No network access to the managed instances is required - all enumeration is via the AWS control plane.

## Enumeration

### Identify managed nodes

The single most important call is `DescribeInstanceInformation`, which lists every node the SSM agent reports for (EC2 instances, on-premises/hybrid-activated machines, and edge devices). A managed node with an online ping status is a potential remote-execution target.

```bash
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,Platform:PlatformType,Name:PlatformName,Ver:PlatformVersion,Agent:AgentVersion,IP:IPAddress,Computer:ComputerName}' \
  --output table
```

Filter for only online nodes (the ones you can act on right now):

```bash
aws ssm describe-instance-information \
  --filters "Key=PingStatus,Values=Online" \
  --query 'InstanceInformationList[].InstanceId' --output text
```

Hybrid/on-prem activations (managed nodes whose IDs start with `mi-`) indicate machines outside EC2 that SSM can reach - often a path into a corporate network:

```bash
aws ssm describe-activations \
  --query 'ActivationList[].{Id:ActivationId,Reg:RegistrationsCount,Limit:RegistrationLimit,Role:IamRole,Expired:Expired}'
```

### Enumerate documents (runbooks)

SSM documents define what commands run on nodes. Enumerate both AWS-owned and self-owned/shared documents:

```bash
# All documents visible to this account
aws ssm list-documents --query 'DocumentIdentifiers[].{Name:Name,Owner:Owner,Type:DocumentType,Format:DocumentFormat}' --output table

# Only documents this account owns (custom runbooks, may contain logic/secrets)
aws ssm list-documents --filters "Key=Owner,Values=Self" --output table

# Read a specific document's content
aws ssm get-document --name "MyCustomRunbook" --document-version '$LATEST'

# Who is a document shared with (cross-account exposure)?
aws ssm describe-document-permission --name "MyCustomRunbook" --permission-type Share
```

Custom documents often embed inline scripts, internal hostnames, parameter references, and occasionally hardcoded credentials.

### Enumerate Parameter Store

Parameter Store is a primary secrets target. List all parameter metadata first (no decrypt permission needed):

```bash
aws ssm describe-parameters \
  --query 'Parameters[].{Name:Name,Type:Type,Tier:Tier,KeyId:KeyId,User:LastModifiedUser}' --output table
```

Retrieve values by path hierarchy, decrypting `SecureString` values where permitted:

```bash
# Recursively pull every parameter under a path, with decryption
aws ssm get-parameters-by-path \
  --path "/" --recursive --with-decryption \
  --query 'Parameters[].{Name:Name,Value:Value}' --output json

# Targeted retrieval of specific parameters
aws ssm get-parameters --names "/prod/db/password" "/prod/api/key" --with-decryption
```

Also inspect parameter history, which can reveal previously stored secret values that are still readable:

```bash
aws ssm get-parameter-history --name "/prod/db/password" --with-decryption
```

### Enumerate command and session history

Past commands and sessions reveal operational patterns, target instances, and sometimes sensitive output:

```bash
# Recent Run Command executions
aws ssm list-commands --query 'Commands[].{Id:CommandId,Doc:DocumentName,Status:Status,Targets:Targets,Requester:RequesterServiceRole}'

# Per-invocation detail including command output (if comment/output retained)
aws ssm list-command-invocations --command-id <id> --details

# Active and historical Session Manager sessions
aws ssm describe-sessions --state History --query 'Sessions[].{Id:SessionId,Owner:Owner,Target:Target,Doc:DocumentName,Start:StartDate}'
aws ssm describe-sessions --state Active
```

### Enumerate associations, inventory, patch, and maintenance windows

```bash
# State Manager associations (recurring document executions against targets)
aws ssm list-associations --query 'Associations[].{Name:Name,Id:AssociationId,Targets:Targets,Schedule:ScheduleExpression}'
aws ssm describe-association --association-id <id>

# Maintenance windows and their registered tasks (often run privileged docs on a schedule)
aws ssm describe-maintenance-windows
aws ssm describe-maintenance-window-tasks --window-id <id>

# Inventory: installed software, network config, custom inventory on each node
aws ssm get-inventory
aws ssm list-inventory-entries --instance-id <id> --type-name "AWS:Application"

# Patch baselines and compliance (find unpatched nodes)
aws ssm describe-patch-baselines
aws ssm describe-instance-patch-states --instance-ids <id>
```

## Misconfigurations & Findings

- **Plaintext secrets in `String` parameters.** Credentials stored as `String` rather than `SecureString` are returned to anyone with `ssm:GetParameter`/`GetParametersByPath` and require no KMS decrypt permission. This is one of the most common and impactful findings.
- **Overly broad parameter read scope.** Identities granted `ssm:GetParametersByPath` on `/` or `ssm:GetParameters` on `arn:aws:ssm:*:*:parameter/*` can read every secret in the account, regardless of naming hierarchy intent.
- **`kms:Decrypt` on the SSM key granted too widely.** When a role can both read `SecureString` metadata and decrypt with the encrypting KMS key, the "secure" string is effectively plaintext to that role.
- **Custom documents containing embedded secrets or internal data.** `aws:runShellScript`/`aws:runPowerShellScript` content stored in a document is readable by anyone with `ssm:GetDocument`/`ssm:ListDocuments`.
- **Documents shared cross-account or publicly.** `describe-document-permission` showing `All` or external account IDs is a data-exposure and potential supply-chain finding.
- **Stale/orphaned managed nodes and hybrid activations.** Long-lived activations with high registration limits, or instances whose IAM role is more privileged than needed, expand the SSM attack surface.
- **Sensitive command output retained.** `list-command-invocations --details` and S3/CloudWatch output destinations may persist command stdout containing secrets.

## Exploitation

Enumeration itself is non-destructive, but it directly feeds later phases:

- Plaintext or decryptable Parameter Store values yield credentials used immediately (database access, third-party API keys, additional AWS access keys). See [Privilege Escalation](../03-privilege-escalation/aws-ssm-privesc.md).
- The list of Online managed nodes from `DescribeInstanceInformation` is the target set for Run Command and Session Manager execution. See [Lateral Movement](../04-lateral-movement/aws-ssm-lateral.md).
- Custom document contents and command history map operational workflows and reveal which instances run privileged automation.

## Detection & Logging

- **CloudTrail** records SSM read APIs as management events: `DescribeInstanceInformation`, `ListDocuments`, `GetDocument`, `DescribeParameters`, `GetParameters`, `GetParametersByPath`, `GetParameterHistory`, `DescribeSessions`, `ListCommands`, `ListCommandInvocations`, `DescribeActivations`, `GetInventory`. Note that `GetParameter`/`GetParameters` log the parameter `name` in `requestParameters` but never the value.
- High-volume `GetParametersByPath --recursive` from a single principal, or enumeration immediately following first use of a credential, is a strong indicator of credential harvesting or reconnaissance.
- `kms:Decrypt` events on the SSM key correlated with `GetParameters` calls reveal `SecureString` access.
- GuardDuty surfaces anomalous SSM/credential-exfiltration behavior (for example, account credentials used from an unexpected location), and `Discovery:*` findings can correlate with broad enumeration.
- Enable CloudTrail data/management logging across all regions; SSM enumeration is often performed region-by-region to evade single-region monitoring.

## Remediation & Hardening

- Store all secrets as `SecureString` with a **customer-managed KMS key**, and scope `kms:Decrypt` narrowly via key policy so only the workloads that need a secret can decrypt it.
- Apply least privilege to SSM parameter reads: grant `ssm:GetParameter*` on specific path prefixes (`/team/app/*`), never `*`.
- Avoid storing static secrets in Parameter Store where Secrets Manager rotation or short-lived role credentials are viable.
- Restrict `ssm:GetDocument`/`ssm:ListDocuments` and audit custom documents for embedded secrets; move logic-bearing data out of document content.
- Review `describe-document-permission` output; remove `All` (public) sharing and unintended cross-account shares.
- Inventory and expire unused hybrid activations and de-register orphaned managed nodes.
- Use SCPs and IAM permission boundaries to prevent broad `ssm:Get*`/`ssm:Describe*` grants outside designated operational roles.

## Tools

- **aws-cli** - native `aws ssm` subcommands for all enumeration above.
- **boto3 / cloud SDKs** - scripted multi-region sweeps of parameters, documents, and managed nodes.
- **Cloud IAM enumeration tooling** - identifies which SSM permissions a given principal holds, mapping enumeration capability before any call is made.

## References

- AWS Systems Manager API Reference - https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html
- AWS CLI `ssm` command reference - https://docs.aws.amazon.com/cli/latest/reference/ssm/index.html
- AWS Systems Manager Parameter Store - https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
- Hacking the Cloud - Run shell commands on EC2 via SSM - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
