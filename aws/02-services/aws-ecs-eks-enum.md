---
cstg_id: CSTG-AWS-ECS-EKS-ENUM
title: "AWS Ecs Eks - Enumeration"
provider: aws
service: ecs-eks
phase: services
required_access: read-only-audit
required_permissions:
  - ecs:ListClusters
  - ecs:DescribeClusters
  - ecs:ListServices
  - ecs:DescribeServices
  - ecs:ListTaskDefinitions
  - ecs:DescribeTaskDefinition
  - ecs:ListTasks
  - ecs:DescribeTasks
  - ecs:ListContainerInstances
  - ecs:DescribeContainerInstances
  - eks:ListClusters
  - eks:DescribeCluster
  - eks:ListNodegroups
  - eks:DescribeNodegroup
  - eks:ListFargateProfiles
  - eks:ListAddons
  - eks:DescribeAddon
  - eks:ListAccessEntries
  - eks:ListIdentityProviderConfigs
  - ecr:DescribeRepositories
  - ecr:GetRepositoryPolicy
tools:
  - aws-cli
  - kubectl
  - eksctl
  - ScoutSuite
  - Prowler
  - Pacu
  - cloudmapper
references:
  - "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/eks/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/cluster-auth.html"
  - "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
  - "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
  - "https://hackingthe.cloud/aws/general-knowledge/intro-to-ecs/"
license: CC BY-SA 4.0
---

## Summary

Amazon Elastic Container Service (ECS) and Amazon Elastic Kubernetes Service (EKS) are AWS's two managed container orchestration platforms. ECS is AWS-native and schedules *tasks* (one or more containers) onto either EC2 instances the account owns or onto serverless *Fargate* capacity. EKS runs upstream Kubernetes with an AWS-managed control plane and worker capacity provided by EC2 node groups, self-managed nodes, or Fargate.

Both services are dense intersections of AWS IAM and the container runtime, which makes them high-value targets. The objective of enumeration is to map the full container estate: clusters, services, task/pod definitions, the IAM roles attached to running workloads (task roles, task execution roles, node instance roles, IRSA/Pod Identity service accounts), the container images and their registries (ECR), network exposure, and the Kubernetes-layer authorization model (the `aws-auth` ConfigMap or EKS access entries, plus RBAC). The information gathered here feeds directly into the privilege-escalation, lateral-movement, and post-exploitation pages for this service.

A reader performing this phase wants answers to: *Which workloads run with which IAM roles? Which task definitions embed secrets or over-broad permissions? Which container images can be pulled or pushed? Who can reach the Kubernetes API, and with what RBAC rights? Where are the trust boundaries between the container, the node, and the AWS control plane?*

## Prerequisites

- Read-only AWS credentials with the ECS, EKS, and ECR describe/list permissions listed above. The managed `ReadOnlyAccess` or `SecurityAudit` policies grant the AWS-side calls.
- For the Kubernetes layer of EKS, the principal must additionally be mapped inside the cluster: either an entry in the `aws-auth` ConfigMap (legacy) or an EKS *access entry* (current), or a Kubernetes RBAC binding reachable through an OIDC/identity-provider association. Without an in-cluster mapping, `eks:DescribeCluster` still reveals control-plane metadata but `kubectl` calls return `403 Forbidden`.
- Network reachability to the EKS API server endpoint. Endpoints may be `public`, `private`, or both; a private-only endpoint requires being inside the VPC or a peered/transit-connected network.

## Enumeration

### ECS clusters, services, and tasks

```bash
# Clusters
aws ecs list-clusters
aws ecs describe-clusters --clusters <cluster-arn> \
  --include ATTACHMENTS SETTINGS STATISTICS TAGS

# Services in a cluster
aws ecs list-services --cluster <cluster>
aws ecs describe-services --cluster <cluster> --services <svc-1> <svc-2>

# Running and stopped tasks
aws ecs list-tasks --cluster <cluster> --desired-status RUNNING
aws ecs list-tasks --cluster <cluster> --desired-status STOPPED
aws ecs describe-tasks --cluster <cluster> --tasks <task-arn>
```

### ECS task definitions (the richest source of intelligence)

```bash
aws ecs list-task-definitions --status ACTIVE
aws ecs describe-task-definition --task-definition <family:revision> \
  --include TAGS
```

The `describe-task-definition` response is the primary loot target. Inspect:
- `taskRoleArn` — the IAM role the *application* inside the container assumes (its credentials are exposed via the task metadata endpoint, see the post-exploitation page).
- `executionRoleArn` — the role ECS uses to pull images and inject secrets/logs.
- `containerDefinitions[].environment` — plaintext environment variables, frequently containing credentials, connection strings, and API keys.
- `containerDefinitions[].secrets` — references to Secrets Manager / SSM Parameter Store values injected at runtime (names reveal what secrets exist).
- `containerDefinitions[].image` — ECR or third-party registry image references.
- `volumes`, `networkMode` (`awsvpc`, `bridge`, `host`), and `privileged`/`linuxParameters` — container escape and host-access indicators.

### ECS container instances (EC2 launch type)

```bash
aws ecs list-container-instances --cluster <cluster>
aws ecs describe-container-instances --cluster <cluster> \
  --container-instances <ci-arn>
```

This maps tasks to the underlying EC2 hosts and their instance profile roles — relevant where a task on the EC2 launch type can reach the host's IMDS.

### ECR registries and images

```bash
aws ecr describe-repositories
aws ecr list-images --repository-name <repo>
aws ecr describe-images --repository-name <repo>
aws ecr get-repository-policy --repository-name <repo>      # resource policy
aws ecr get-registry-policy                                  # registry-wide policy
# Pull an image's auth token (and thus the ability to docker pull)
aws ecr get-login-password --region <region>
```

Registry and repository policies expose cross-account pull/push grants — a common path for supply-chain abuse covered in lateral movement.

### EKS clusters and control-plane metadata

```bash
aws eks list-clusters
aws eks describe-cluster --name <cluster>
```

From `describe-cluster`, record:
- `endpoint`, `resourcesVpcConfig.endpointPublicAccess`, `endpointPrivateAccess`, and `publicAccessCidrs` — API server exposure.
- `roleArn` — the cluster IAM role.
- `identity.oidc.issuer` — the OIDC provider URL backing IRSA.
- `accessConfig.authenticationMode` — `CONFIG_MAP`, `API`, or `API_AND_CONFIG_MAP`.
- `logging` — whether control-plane audit logging is enabled (see Detection).
- `encryptionConfig` — whether Kubernetes secrets are envelope-encrypted with KMS.

### EKS node groups, Fargate profiles, add-ons, and access model

```bash
aws eks list-nodegroups --cluster-name <cluster>
aws eks describe-nodegroup --cluster-name <cluster> --nodegroup-name <ng>
aws eks list-fargate-profiles --cluster-name <cluster>
aws eks list-addons --cluster-name <cluster>
aws eks describe-addon --cluster-name <cluster> --addon-name <addon>

# Access entries (the modern, IAM-side authorization map)
aws eks list-access-entries --cluster-name <cluster>
aws eks describe-access-entry --cluster-name <cluster> --principal-arn <arn>
aws eks list-associated-access-policies --cluster-name <cluster> --principal-arn <arn>

# Federated/OIDC identity provider configs
aws eks list-identity-provider-configs --cluster-name <cluster>
```

`describe-nodegroup` reveals `nodeRole` (the node instance profile), `remoteAccess` (SSH key/security groups), and launch template references.

### Kubernetes layer (EKS)

```bash
# Generate kubeconfig using the current AWS identity
aws eks update-kubeconfig --name <cluster> --region <region>

# Test and enumerate authorization
kubectl auth whoami
kubectl auth can-i --list
kubectl auth can-i --list --namespace <ns>

# The legacy IAM<->RBAC bridge
kubectl get configmap aws-auth -n kube-system -o yaml

# RBAC graph
kubectl get clusterroles,clusterrolebindings -o wide
kubectl get roles,rolebindings -A -o wide

# Workloads, service accounts, secrets, and IRSA annotations
kubectl get pods -A -o wide
kubectl get sa -A -o yaml | grep -i "eks.amazonaws.com/role-arn"
kubectl get secrets -A
kubectl get nodes -o wide
```

The IRSA annotation `eks.amazonaws.com/role-arn` on a ServiceAccount, and the EKS Pod Identity association, are the bridge from a Kubernetes pod to an AWS IAM role — they are the focal point of EKS privilege escalation.

## Misconfigurations & Findings

- **Plaintext secrets in task definition environment variables.** Credentials in `environment[]` are visible to anyone with `ecs:DescribeTaskDefinition` and are written to CloudTrail-adjacent metadata; they should be `secrets[]` references instead.
- **Over-privileged task roles.** A task role with `*:*`, `iam:PassRole`, `sts:AssumeRole`, or broad data-plane access turns any application compromise into an account-wide foothold.
- **Public EKS API server endpoint with `0.0.0.0/0` in `publicAccessCidrs`.** Exposes the Kubernetes control plane to the internet; combined with weak RBAC this is critical.
- **Permissive `aws-auth` mappings** — e.g. mapping a broad role to `system:masters`, or `mapRoles` granting cluster-admin to the node role.
- **`system:masters` or cluster-admin bound to service accounts or wide groups** in RBAC, or `automountServiceAccountToken` left enabled on privileged accounts.
- **Privileged / host-mode tasks and pods** (`privileged: true`, `hostNetwork`, `hostPID`, `hostPath` mounts, `securityContext` allowing capability `SYS_ADMIN`) — direct container-escape primitives.
- **Public or cross-account ECR repository policies** allowing untrusted principals to pull (data exposure) or push (image poisoning).
- **Control-plane audit logging disabled** (`logging.clusterLogging` types `audit`, `authenticator` off), blinding defenders.
- **EKS secrets not envelope-encrypted with KMS**, leaving them base64-only in etcd.
- **Node IMDS reachable from pods** (no IMDSv2 hop-limit enforcement / no network policy), exposing the node instance role.

## Exploitation

Enumeration is non-destructive, but the artifacts it surfaces are the launch points for later phases. From this phase, a reader can already:

- Read secrets directly out of `describe-task-definition` `environment[]` blocks.
- Identify which `taskRoleArn`/IRSA roles to harvest once a container is reached (see [privilege escalation](../03-privilege-escalation/aws-ecs-eks-privesc.md)).
- Determine whether the EKS API is internet-reachable and whether the current identity already has `kubectl` rights (`auth can-i --list`).
- Map cross-account ECR trust to plan supply-chain pivots (see [lateral movement](../04-lateral-movement/aws-ecs-eks-lateral.md)).

Confirm reachable Kubernetes verbs without modifying anything:

```bash
kubectl auth can-i create pods -A
kubectl auth can-i create pods/exec -A
kubectl auth can-i get secrets -A
kubectl auth can-i '*' '*' -A
```

## Detection & Logging

- **CloudTrail (management events):** ECS `Describe*`/`List*`, EKS `DescribeCluster`/`ListClusters`, ECR `GetAuthorizationToken`, `GetRepositoryPolicy`, and `eks:ListAccessEntries` all emit management events. A burst of `Describe*`/`List*` across ECS, EKS, and ECR from one principal is a reconnaissance signature.
- **EKS authenticator & audit logs (CloudWatch Logs):** when control-plane logging is enabled, `aws eks update-kubeconfig` followed by `kubectl` calls produce `authenticator` log entries (mapping the IAM principal to a Kubernetes user) and `audit` entries for every API verb, including `auth can-i`/SelfSubjectRulesReview probes.
- **GuardDuty:** EKS Protection and the broader recon findings (`Recon:EKS/*`, `Discovery:*`) flag anomalous Kubernetes API enumeration and suspicious calls from container workloads.
- **ECR pulls** (`BatchGetImage`, `GetDownloadUrlForLayer`) are logged as data/management events and reveal which images an identity is reading.

## Remediation & Hardening

- Replace plaintext `environment` secrets with `secrets[]` references to Secrets Manager / SSM, encrypted with KMS.
- Scope task roles, execution roles, and node roles to least privilege; never grant `iam:PassRole`/`*:*` to a task role.
- Set EKS `authenticationMode` to `API`, migrate off `aws-auth`, and grant access via narrowly scoped access entries and access policies.
- Make the EKS endpoint private, or restrict `publicAccessCidrs` to known administrative ranges.
- Enforce least-privilege RBAC; avoid binding `cluster-admin`/`system:masters` to service accounts or broad groups; disable `automountServiceAccountToken` where not needed.
- Enable all EKS control-plane log types (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`).
- Enable EKS secrets envelope encryption with KMS.
- Lock private ECR repositories; remove `*`/cross-account principals from repository and registry policies unless explicitly required.
- Enforce IMDSv2 with a hop limit of 1 on nodes and apply network policies preventing pods from reaching IMDS.

## Tools

- `aws-cli` — primary ECS/EKS/ECR enumeration.
- `kubectl` — Kubernetes API enumeration and RBAC probing.
- `eksctl` — convenient cluster/identity inspection.
- `ScoutSuite`, `Prowler` — automated CSPM checks for the misconfigurations above.
- `cloudmapper` — visualizes network exposure of clusters and nodes.
- `Pacu` — modular AWS exploitation framework with ECS/EKS enumeration modules.

## References

- Amazon ECS API Reference — https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html
- Amazon EKS API Reference — https://docs.aws.amazon.com/eks/latest/APIReference/Welcome.html
- EKS cluster authentication — https://docs.aws.amazon.com/eks/latest/userguide/cluster-auth.html
- ECS task IAM roles — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- IAM roles for service accounts (IRSA) — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- Intro to ECS — https://hackingthe.cloud/aws/general-knowledge/intro-to-ecs/
