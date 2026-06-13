---
cstg_id: CSTG-AWS-ECR-ENUM
title: "AWS Ecr - Enumeration"
provider: aws
service: ecr
phase: services
required_access: read-only-audit
required_permissions:
  - ecr:DescribeRepositories
  - ecr:ListImages
  - ecr:DescribeImages
  - ecr:GetRepositoryPolicy
  - ecr:GetLifecyclePolicy
  - ecr:ListTagsForResource
  - ecr:BatchGetImage
  - ecr:GetDownloadUrlForLayer
  - ecr:GetAuthorizationToken
  - ecr-public:DescribeRepositories
  - ecr-public:GetRepositoryPolicy
references:
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/public/what-is-ecr.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html"
  - "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html"
  - "https://hackingthe.cloud/aws/enumeration/enum_ecr/"
license: CC BY-SA 4.0
---

## Summary

Amazon Elastic Container Registry (ECR) is a managed OCI-compatible registry for storing, versioning, and distributing container images and other OCI artifacts (Helm charts, SBOMs, signatures). It exists in two forms: **private registries**, one per account per region, addressed as `<account-id>.dkr.ecr.<region>.amazonaws.com`; and the **public gallery** (`public.ecr.aws`), a global registry for openly distributed images.

Enumeration of ECR is high value because container images are a frequent home for embedded secrets, hardcoded credentials, application source code, internal hostnames, and dependency manifests that reveal the broader environment. Repository and registry policies can also be misconfigured to permit cross-account or public pulls (and sometimes pushes), and images are consumed by ECS, EKS, App Runner, Lambda, and CodeBuild - so a tampered or readable image often translates into compute compromise.

The attacker objective in this phase is to inventory registries, repositories, image tags and digests, the policies governing access, scan findings, and ultimately to pull and unpack image layers to mine their contents - all without modifying anything.

## Prerequisites

- **Access level:** read-only audit credentials within the target account, or an unauthenticated/external principal where repository or registry policies grant cross-account or public access.
- **Permissions (private ECR):** the describe/list/get family above. Pulling image content additionally requires `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, and `ecr:GetDownloadUrlForLayer`. `ecr:GetAuthorizationToken` is account-wide (resource `*`) and not scoped to a repository.
- **Permissions (public ECR):** anonymous pulls of public images require no credentials. `aws ecr-public get-authorization-token` is only needed for higher rate limits or pushes.
- A working Docker, `crane`, `skopeo`, or `oras` client to retrieve and unpack layers.

See also: [ECR Privilege Escalation](../03-privilege-escalation/aws-ecr-privesc.md) and [ECR Persistence](../06-persistence/aws-ecr-persistence.md).

## Enumeration

### Identify the registry

```bash
# Confirm the current identity and account (the registry id defaults to this account)
aws sts get-caller-identity

# Describe registry-level settings: replication, scanning configuration, pull-through cache
aws ecr describe-registry --region us-east-1
aws ecr get-registry-policy --region us-east-1
aws ecr get-registry-scanning-configuration --region us-east-1
aws ecr describe-pull-through-cache-rules --region us-east-1
```

### List repositories

```bash
# All private repositories in a region
aws ecr describe-repositories --region us-east-1

# Just the names and URIs
aws ecr describe-repositories --region us-east-1 \
  --query 'repositories[].[repositoryName,repositoryUri,createdAt]' --output table

# Public repositories owned by this account (public registry is global, us-east-1 endpoint)
aws ecr-public describe-repositories --region us-east-1
```

ECR is regional - repeat `describe-repositories` across every enabled region. Enumerate enabled regions with `aws ec2 describe-regions --query 'Regions[].RegionName' --output text`.

### Enumerate images within a repository

```bash
REPO=my-app
REGION=us-east-1

# Tags and digests
aws ecr list-images --repository-name "$REPO" --region "$REGION"

# Detailed metadata: size, pushed time, manifest media type, artifact type
aws ecr describe-images --repository-name "$REPO" --region "$REGION"

# Filter for the latest-pushed tags
aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
  --query 'reverse(sort_by(imageDetails,&imagePushedAt))[].[imageTags[0],imageDigest,imagePushedAt]' \
  --output table
```

### Read policies, lifecycle, and tags

```bash
# Resource policy controlling who can pull/push (cross-account, public, conditions)
aws ecr get-repository-policy --repository-name "$REPO" --region "$REGION"

# Lifecycle policy - reveals retention and naming/tagging conventions
aws ecr get-lifecycle-policy --repository-name "$REPO" --region "$REGION"

# Resource tags often disclose owners, environments, and data classifications
aws ecr list-tags-for-resource \
  --resource-arn "arn:aws:ecr:$REGION:111122223333:repository/$REPO"

# Public repository policy
aws ecr-public get-repository-policy --repository-name "$REPO" --region us-east-1
```

### Review vulnerability scan findings

Scan findings are reconnaissance gold - they enumerate installed packages, versions, and known CVEs inside the image without pulling it.

```bash
# Basic scan findings for a specific image
aws ecr describe-image-scan-findings \
  --repository-name "$REPO" --image-id imageTag=latest --region "$REGION"
```

Enhanced scanning routes findings to Amazon Inspector; query them there:

```bash
aws inspector2 list-findings \
  --filter-criteria '{"ecrImageRepositoryName":[{"comparison":"EQUALS","value":"my-app"}]}' \
  --region us-east-1
```

### Authenticate and pull image content

```bash
# Obtain a 12-hour token and log the Docker client into the private registry
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin 111122223333.dkr.ecr.$REGION.amazonaws.com

docker pull 111122223333.dkr.ecr.$REGION.amazonaws.com/$REPO:latest

# Credential-free, daemonless pull of a public image
crane pull public.ecr.aws/<alias>/<repo>:tag image.tar
```

### Inspect layers and history without a full pull

`crane` and `skopeo` let you read configuration and per-layer history (often exposing build-time `ENV`, `ARG`, and `RUN` commands containing secrets) cheaply:

```bash
crane config 111122223333.dkr.ecr.$REGION.amazonaws.com/$REPO:latest | jq '.history'
crane manifest 111122223333.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
skopeo inspect --config docker://111122223333.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
```

### Unauthenticated / cross-account checks

For a known account id, region, and repository name (often leaked in IaC, CI logs, or task definitions), an external principal can test pull access directly. If `GetDownloadUrlForLayer` and `BatchGetImage` succeed cross-account, the repository policy is over-permissive.

```bash
aws ecr batch-get-image \
  --registry-id 111122223333 --repository-name "$REPO" \
  --image-ids imageTag=latest --region "$REGION"
```

## Misconfigurations & Findings

- **Public or wildcard repository policy.** A repository policy with `Principal: "*"` (or a broad external account) granting `ecr:BatchGetImage` / `ecr:GetDownloadUrlForLayer` exposes private images to anonymous or cross-account pulls, leaking everything baked into the image.
- **Public registry repositories holding sensitive images.** Images intended to be private published to `public.ecr.aws`, indexed and pullable by anyone.
- **Secrets baked into image layers.** Hardcoded AWS access keys, database passwords, API tokens, `.npmrc`/`.pip.conf` credentials, private keys, and `.env` files committed into layers. These persist even if a later layer "deletes" them.
- **Scanning disabled or stale.** No basic or enhanced scanning configured, so known-vulnerable base images and dependencies ship undetected.
- **Tag mutability enabled.** Mutable tags allow `latest` (or a release tag) to be silently overwritten, enabling supply-chain tampering (see Privilege Escalation / Persistence pages).
- **Overly broad IAM (not resource policy).** Identity policies granting `ecr:*` or `ecr:GetAuthorizationToken` plus pull actions on `Resource: "*"` to many principals.
- **Pull-through cache to untrusted upstreams** that can be poisoned or that silently mirror unvetted images into the trusted registry.
- **Informative tags and lifecycle policies** disclosing environment names, owners, and internal conventions useful for further targeting.

## Exploitation

In a read-only context, "exploitation" is extracting maximum intelligence from readable images:

1. **Enumerate every region and repository** (`describe-repositories` per region).
2. **Pull or layer-inspect each interesting image** using `docker pull`, `crane`, or `skopeo`.
3. **Mine layers for secrets and source.** Export the filesystem and run secret scanners:

   ```bash
   docker save 111122223333.dkr.ecr.$REGION.amazonaws.com/$REPO:latest -o image.tar
   mkdir layers && tar -xf image.tar -C layers
   trufflehog filesystem ./layers
   # or: docker history --no-trunc <image>   # reveals build-time commands/args
   ```
4. **Read image config history** for `ENV`/`ARG`-injected credentials and internal endpoints.
5. **Pivot:** discovered credentials become new identities; internal hostnames feed network recon; embedded role names feed [privilege-escalation analysis](../03-privilege-escalation/aws-ecr-privesc.md).

Note that pulling an image requires `GetAuthorizationToken` + `BatchGetImage` + `GetDownloadUrlForLayer`; missing any one blocks the layer download even when metadata is readable.

## Detection & Logging

ECR control-plane and data-plane actions are recorded in **AWS CloudTrail**:

- `GetAuthorizationToken`, `BatchGetImage`, and `GetDownloadUrlForLayer` mark image pulls. `GetDownloadUrlForLayer` is a data-style event emitted per layer - a burst against many repositories from one principal indicates bulk exfiltration.
- `DescribeRepositories`, `ListImages`, `DescribeImages`, `GetRepositoryPolicy`, and `GetLifecyclePolicy` indicate enumeration/reconnaissance.
- Cross-account pulls record the external `userIdentity.accountId` / `arn`, and the `recipientAccountId` differs from the caller.

Detection ideas:

- Alert on `GetDownloadUrlForLayer`/`BatchGetImage` where the caller's account differs from the resource owner.
- Alert on a single principal touching an abnormal number of distinct repositories in a short window.
- Alert on `GetAuthorizationToken` from unexpected principals, IPs, or regions.
- ECR pull metrics surface in CloudWatch; Amazon GuardDuty and Inspector provide managed detections for malicious/vulnerable images. Public registry (`ecr-public`) calls log under the `ecr-public` event source.

## Remediation & Hardening

- Scope repository policies to specific, known principals; never use `Principal: "*"` on private repositories. Audit registry and repository policies regularly.
- Apply least-privilege IAM: avoid `ecr:*` and avoid pull permissions on `Resource: "*"`; scope to required repository ARNs.
- Enable **enhanced scanning** (Inspector) registry-wide and gate deployments on results.
- Set repositories to **immutable tags** to prevent overwrite-based tampering.
- Never bake secrets into images - use runtime secret injection (Secrets Manager, SSM Parameter Store, task/pod environment from secret stores). Rotate any secret found in a layer; deleting the layer does not remove it from history.
- Restrict and vet **pull-through cache** upstreams; prefer signed images and enforce signature verification at deploy time.
- Use VPC endpoints (PrivateLink) for ECR so pulls do not traverse the public internet, and apply endpoint policies.
- Be deliberate about the public registry - publish only images explicitly intended to be public.

## Tools

- AWS CLI (`aws ecr`, `aws ecr-public`) and SDKs for control-plane enumeration.
- `crane`, `skopeo`, `oras`, and Docker for pulling and inspecting images/layers.
- Secret scanners (e.g. TruffleHog, Gitleaks) and image scanners (e.g. Trivy, Grype) for layer analysis.
- Multi-service cloud auditing toolkits that include ECR policy and image checks.

## References

- AWS - What is Amazon ECR: https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html
- AWS - ECR API Reference: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html
- AWS - Amazon ECR Public: https://docs.aws.amazon.com/AmazonECR/latest/public/what-is-ecr.html
- AWS - Registries: https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html
- AWS - Repository policies: https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
- Hacking the Cloud - Enumerate ECR: https://hackingthe.cloud/aws/enumeration/enum_ecr/
