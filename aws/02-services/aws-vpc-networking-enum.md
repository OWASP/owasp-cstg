---
cstg_id: CSTG-AWS-VPC-NETWORKING-ENUM
title: "AWS Vpc Networking - Enumeration"
provider: aws
service: vpc-networking
phase: services
required_access: read-only-audit
required_permissions:
  - ec2:DescribeVpcs
  - ec2:DescribeSubnets
  - ec2:DescribeRouteTables
  - ec2:DescribeInternetGateways
  - ec2:DescribeNatGateways
  - ec2:DescribeSecurityGroups
  - ec2:DescribeSecurityGroupRules
  - ec2:DescribeNetworkAcls
  - ec2:DescribeNetworkInterfaces
  - ec2:DescribeAddresses
  - ec2:DescribeInstances
  - ec2:DescribeVpcPeeringConnections
  - ec2:DescribeVpcEndpoints
  - ec2:DescribeVpcEndpointServiceConfigurations
  - ec2:DescribeTransitGateways
  - ec2:DescribeTransitGatewayAttachments
  - ec2:DescribeFlowLogs
  - ec2:DescribePrefixLists
  - ec2:DescribeManagedPrefixLists
  - elasticloadbalancing:DescribeLoadBalancers
  - elasticloadbalancing:DescribeTargetGroups
  - rds:DescribeDBInstances
tools:
  - aws-cli
  - pmapper
  - cloudmapper
  - prowler
  - scoutsuite
  - aws-network-firewall-analyzer
license: CC BY-SA 4.0
references:
  - "https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html"
  - "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
  - "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"
  - "https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html"
  - "https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html"
  - "https://docs.aws.amazon.com/vpc/latest/privatelink/concepts.html"
  - "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
  - "https://hackingthe.cloud/aws/enumeration/account_enumeration/"
---

## Summary

This page covers credentialed, read-only enumeration of an AWS account's VPC networking from the control plane. With audit-level access, the entire network topology is observable: VPCs and their CIDRs, subnets (public vs private), route tables, Internet/NAT gateways, security groups and their rules, network ACLs, elastic network interfaces (ENIs) and the resources behind them, Elastic IPs, VPC peering, Transit Gateways, VPC endpoints (PrivateLink), prefix lists, and Flow Log configuration.

The objective is to build a precise model of how traffic can flow - what is internet-facing, which subnets are public, which security groups are over-permissive, where cross-VPC and cross-account paths exist (peering, TGW, endpoint services), and where the absence of Flow Logs creates a monitoring blind spot. This model drives lateral-movement and exposure analysis and complements the external view in [aws-vpc-networking-unauthenticated.md](../01-unauthenticated-external/aws-vpc-networking-unauthenticated.md).

## Prerequisites

- Read-only/audit credentials in the account (for example a principal with the AWS managed `ReadOnlyAccess` or `SecurityAudit` policy, or the granular `ec2:Describe*` / `elasticloadbalancing:Describe*` permissions listed in the frontmatter).
- All `Describe*` calls below are read-only and produce no configuration change. They must be run per region; iterate every enabled region because VPC resources are regional.
- For network-reachability reasoning (`ec2:DescribeNetworkInsightsAnalysis` via VPC Reachability Analyzer) some additional permissions are required; the core enumeration here needs only describe access.

## Enumeration

### VPCs, subnets, and routing

```bash
# All VPCs with CIDRs and default flag
aws ec2 describe-vpcs --region "$R" \
  --query 'Vpcs[].{Id:VpcId,Cidr:CidrBlock,Default:IsDefault,Tags:Tags}'

# Subnets: map to VPC, AZ, auto-assign-public-IP, available IPs
aws ec2 describe-subnets --region "$R" \
  --query 'Subnets[].{Id:SubnetId,Vpc:VpcId,Az:AvailabilityZone,Cidr:CidrBlock,MapPublicIp:MapPublicIpOnLaunch}'

# Route tables - a subnet is "public" if its route table has a 0.0.0.0/0 route to an igw-*
aws ec2 describe-route-tables --region "$R" \
  --query 'RouteTables[].{Id:RouteTableId,Vpc:VpcId,Assoc:Associations[].SubnetId,Routes:Routes[].{Dest:DestinationCidrBlock,Gw:GatewayId,Nat:NatGatewayId,Pcx:VpcPeeringConnectionId,Tgw:TransitGatewayId}}'

# Internet and NAT gateways
aws ec2 describe-internet-gateways --region "$R"
aws ec2 describe-nat-gateways --region "$R"
```

A subnet with a `0.0.0.0/0 -> igw-*` route is public. Cross-reference subnet IDs against the route tables to label every subnet public or private.

### Security groups and network ACLs

```bash
# Security groups (stateful, instance/ENI level) - the highest-value object here
aws ec2 describe-security-groups --region "$R" \
  --query 'SecurityGroups[].{Id:GroupId,Vpc:VpcId,Name:GroupName,Ingress:IpPermissions,Egress:IpPermissionsEgress}'

# Flatten ingress rules to spot 0.0.0.0/0 exposures
aws ec2 describe-security-group-rules --region "$R" \
  --query "SecurityGroupRules[?IsEgress==\`false\`].{Sg:GroupId,From:FromPort,To:ToPort,Proto:IpProtocol,Cidr:CidrIpv4,RefSg:ReferencedGroupInfo.GroupId}"

# Network ACLs (stateless, subnet level) - ordered allow/deny entries
aws ec2 describe-network-acls --region "$R" \
  --query 'NetworkAcls[].{Id:NetworkAclId,Vpc:VpcId,Subnets:Associations[].SubnetId,Entries:Entries}'
```

### ENIs, instances, and public addressing

ENIs are the truth source for what is actually attached to the network and whether it has a public address.

```bash
# Every ENI: attachment, private/public IP, owning service, attached SGs
aws ec2 describe-network-interfaces --region "$R" \
  --query 'NetworkInterfaces[].{Eni:NetworkInterfaceId,Subnet:SubnetId,PrivIp:PrivateIpAddress,PubIp:Association.PublicIp,Type:InterfaceType,Desc:Description,Sgs:Groups[].GroupId,Status:Status}'

# Instances with their network placement and IAM instance profile (pivot target)
aws ec2 describe-instances --region "$R" \
  --query 'Reservations[].Instances[].{Id:InstanceId,Subnet:SubnetId,PrivIp:PrivateIpAddress,PubIp:PublicIpAddress,Sgs:SecurityGroups[].GroupId,Profile:IamInstanceProfile.Arn}'

# Elastic IPs and what they are associated with
aws ec2 describe-addresses --region "$R" \
  --query 'Addresses[].{Eip:PublicIp,Assoc:AssociationId,Eni:NetworkInterfaceId,Instance:InstanceId}'
```

The `InterfaceType` / `Description` of an ENI reveals managed services in the VPC (e.g. `interface` with a `ELB app/...` description = load balancer, `Amazon RDS` = database, `aws-lambda` = Lambda ENI, `vpc_endpoint` = PrivateLink).

### Cross-VPC and cross-account connectivity

```bash
# VPC peering (intra- and inter-account)
aws ec2 describe-vpc-peering-connections --region "$R" \
  --query 'VpcPeeringConnections[].{Id:VpcPeeringConnectionId,Req:RequesterVpcInfo,Acc:AccepterVpcInfo,Status:Status.Code}'

# Transit Gateways and their attachments (hub-and-spoke, often multi-account)
aws ec2 describe-transit-gateways --region "$R"
aws ec2 describe-transit-gateway-attachments --region "$R" \
  --query 'TransitGatewayAttachments[].{Tgw:TransitGatewayId,Resource:ResourceType,ResourceId:ResourceId,OwnerId:ResourceOwnerId,State:State}'

# VPC endpoints (consuming PrivateLink) and endpoint *services* this account publishes
aws ec2 describe-vpc-endpoints --region "$R" \
  --query 'VpcEndpoints[].{Id:VpcEndpointId,Svc:ServiceName,Vpc:VpcId,Type:VpcEndpointType,Policy:PolicyDocument}'
aws ec2 describe-vpc-endpoint-service-configurations --region "$R" \
  --query 'ServiceConfigurations[].{Id:ServiceId,Name:ServiceName,AcceptanceRequired:AcceptanceRequired,Allowed:NetworkLoadBalancerArns}'

# Managed prefix lists (referenced inside SG rules - expand to see real CIDRs)
aws ec2 describe-managed-prefix-lists --region "$R"
aws ec2 get-managed-prefix-list-entries --region "$R" --prefix-list-id <pl-id>
```

### Internet-facing managed services and Flow Logs

```bash
# Internet-facing load balancers
aws elbv2 describe-load-balancers --region "$R" \
  --query 'LoadBalancers[?Scheme==`internet-facing`].{Name:LoadBalancerName,Dns:DNSName,Vpc:VpcId,Sgs:SecurityGroups}'

# Publicly accessible RDS
aws rds describe-db-instances --region "$R" \
  --query 'DBInstances[?PubliclyAccessible==`true`].{Id:DBInstanceIdentifier,Endpoint:Endpoint.Address,Vpc:DBSubnetGroup.VpcId,Sgs:VpcSecurityGroups}'

# Flow Log coverage (which VPCs/subnets/ENIs are logged - and which are NOT)
aws ec2 describe-flow-logs --region "$R" \
  --query 'FlowLogs[].{Id:FlowLogId,Resource:ResourceId,Dest:LogDestination,TrafficType:TrafficType,Status:FlowLogStatus}'
```

## Misconfigurations & Findings

- **Security groups open to 0.0.0.0/0 on sensitive ports** - any ingress rule with `CidrIpv4: 0.0.0.0/0` (or `CidrIpv6: ::/0`) covering 22, 3389, 5985/5986, 3306, 5432, 6379, 27017, 9200, 1433, or a wide range (`0-65535`). Correlate with public subnets and ENIs that have a public IP to confirm true exposure.
- **Public subnets hosting data-tier resources** - RDS, ElastiCache, or sensitive instances in a subnet whose route table has an IGW route.
- **`PubliclyAccessible: true` RDS / internet-facing ELBs** fronting internal apps without auth or WAF.
- **Over-broad NACLs** - `ALLOW` for `0.0.0.0/0` on all protocols, or allow rules with lower numbers than the intended denies (NACLs evaluate in ascending rule-number order, first match wins).
- **Default VPC / default security group in use** - the default SG allows all traffic between members; default VPC subnets are public by design.
- **Permissive cross-account paths** - VPC peering or TGW attachments to accounts outside the trust boundary; endpoint *service configurations* with `AcceptanceRequired: false` and broad allow-principals, exposing an internal NLB to other accounts.
- **VPC endpoint policies set to `Allow *`** - a gateway/interface endpoint with a wide-open policy can be used to reach S3/other services without the intended restriction.
- **Missing or partial Flow Logs** - VPCs/subnets/ENIs with no flow log = network-layer blind spot for both defenders and any post-incident analysis.
- **SG rules referencing prefix lists** that expand to far broader CIDRs than expected.

## Exploitation

Read-only enumeration is not itself exploitation, but it directly enables it by exposing the reachable paths. Typical uses of this model:

1. **Target selection for external attack.** SGs open to `0.0.0.0/0` on management/data ports, joined with ENIs that have a public IP in a public subnet, produce the exact internet-reachable host:port list to attack from outside (see the unauthenticated page).
2. **Lateral movement mapping.** After compromising one host (e.g. via its instance profile - see EC2/IAM pages), the SG-to-SG references and the route tables reveal which other internal hosts that host can reach. SG rules that reference *another security group* mean any member of the source SG can reach the destination port on members of the destination SG.
3. **Cross-account pivot discovery.** Peering connections, TGW attachments, and self-published endpoint services with loose acceptance/allow-principals reveal paths into or out of other accounts - candidate routes for expanding access across an organisation.
4. **Blind-spot exploitation.** Subnets/ENIs without Flow Logs are chosen for noisy activity (scanning, exfil staging) because the network-layer record will be absent.
5. **Defence-evasion route planning.** VPC endpoints to S3/STS let traffic leave via PrivateLink rather than an IGW, which may bypass egress filtering and NAT-based monitoring assumptions.

No state-changing API is required for the analysis; the leverage comes from understanding reachability precisely.

## Detection & Logging

- **CloudTrail (control plane):** Every `Describe*` and `Get*` call above is logged as a read event (e.g. `DescribeSecurityGroups`, `DescribeNetworkInterfaces`, `DescribeVpcPeeringConnections`). A burst of broad VPC/EC2 `Describe*` from one principal in a short window - especially across many regions - is a strong reconnaissance signal. GuardDuty surfaces this as `Recon:IAMUser/...` style findings when the principal/behaviour is anomalous.
- **CloudTrail (config changes that created the exposure):** When attributing a finding, pivot to the write events that produced it - `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `CreateRoute`, `CreateInternetGateway`/`AttachInternetGateway`, `ReplaceNetworkAclEntry`, `CreateVpcPeeringConnection`, `CreateTransitGatewayVpcAttachment`, `CreateVpcEndpoint`, `ModifyVpcEndpointServicePermissions`, `DeleteFlowLogs`.
- **VPC Flow Logs:** Show the resulting traffic; their *absence* (visible via `DescribeFlowLogs` returning nothing for a resource) is itself a finding.
- **AWS Config:** Records configuration history and can flag drift via managed rules such as `vpc-sg-open-only-to-authorized-ports`, `restricted-ssh`, `restricted-common-ports`, `vpc-flow-logs-enabled`, `subnet-auto-assign-public-ip-disabled`.
- **Security Hub:** Aggregates the above into CIS/Foundational findings for open SGs and missing flow logs.

## Remediation & Hardening

- Eliminate `0.0.0.0/0` ingress to management and data ports; prefer SG-to-SG references over CIDRs so rules describe identity-based reachability, not address ranges.
- Place data-tier resources only in private subnets; set RDS `PubliclyAccessible` to false; use internal load balancers for internal apps.
- Scope NACLs as a coarse backstop only; rely on least-privilege security groups as the primary control and review rule ordering for allow-before-deny mistakes.
- Avoid the default VPC and default security group for workloads; ensure the default SG has no rules.
- Review every peering connection, TGW attachment, and endpoint service for cross-account scope; set `AcceptanceRequired: true` and explicit allow-principals on published endpoint services; scope VPC endpoint policies tightly.
- Enable VPC Flow Logs for all VPCs (or at the account/Org level) to a central, access-controlled destination; alert on `DeleteFlowLogs`.
- Enforce guardrails with SCPs/Config/Security Hub; require new security groups to have no inbound rules by default and review changes via CloudTrail-driven alerting.
- Use VPC Reachability Analyzer to validate intended vs actual reachability between resources.

## Tools

- `aws-cli` - the `ec2 describe-*`, `elbv2 describe-*`, `rds describe-*` calls above.
- `prowler`, `scoutsuite` - automated checks for open SGs, public subnets, missing flow logs, public RDS.
- `cloudmapper` - builds a visual network diagram of VPCs, subnets, SGs, and exposure from describe data.
- `pmapper` - models identity-to-resource paths that pair with the network paths found here.
- `aws-network-firewall-analyzer` / VPC Reachability Analyzer - validate effective reachability.

## References

- AWS - What is Amazon VPC: https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html
- AWS - DescribeSecurityGroups API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
- AWS - Network ACLs: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
- AWS - What is VPC peering: https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html
- AWS - What is a transit gateway: https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html
- AWS - AWS PrivateLink concepts: https://docs.aws.amazon.com/vpc/latest/privatelink/concepts.html
- AWS - VPC Flow Logs: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- Hacking the Cloud - account enumeration: https://hackingthe.cloud/aws/enumeration/account_enumeration/
