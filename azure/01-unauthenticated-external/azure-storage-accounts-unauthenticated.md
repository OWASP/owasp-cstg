---
cstg_id: CSTG-AZURE-STORAGE-ACCOUNTS-UNAUTH
title: "AZURE Storage Accounts - Unauthenticated Access"
provider: azure
service: storage-accounts
phase: unauthenticated
required_access: unauthenticated
required_permissions: []
tools: [azure-cli, curl, MicroBurst, basicblobfinder, ffuf]
references:
  - "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure"
  - "https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs"
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview"
  - "https://hackingthe.cloud/azure/enumeration/get-azure-storage-account-info/"
license: CC BY-SA 4.0
---

## Summary

Azure Storage account names occupy a single global DNS namespace (`<account>.blob.core.windows.net`
and the matching `.file`, `.queue`, `.table`, and `.dfs` endpoints). Because the namespace is global
and predictable, accounts and the containers inside them can be discovered and probed without any
credentials. When a container or account is configured for anonymous (public) read access, or when a
Shared Access Signature (SAS) URL leaks, blob contents and listings become world-readable. This
phase covers what can be tested from the external, unauthenticated tier: name discovery, anonymous
read/list classification, SAS-token abuse, and subdomain-takeover of dangling storage DNS. Credentialed
configuration review is covered in [Azure Storage Accounts - Enumeration](../02-services/azure-storage-accounts-enum.md).

## Prerequisites

None. Every check is an anonymous HTTPS request to the public Blob/File/Queue/Table endpoints, or a
DNS lookup. The `az storage` CLI can operate without authentication using `--auth-mode login` is not
required; anonymous calls use `--account-name` with no key, or raw REST via `curl`.

## Enumeration

**Discover candidate account names.** Storage accounts are commonly named after the organisation,
product, environment, or region (`<org>data`, `<org>prod`, `<org>backups`, `<org>diag`, `cdnassets`).
Names are 3-24 characters, lowercase letters and digits only. Sources:

- Application source, JavaScript, mobile app bundles, and HTTP responses referencing
  `*.blob.core.windows.net`, `*.file.core.windows.net`, `*.queue.core.windows.net`,
  `*.table.core.windows.net`, `*.dfs.core.windows.net`, or `*.web.core.windows.net` (static website).
- CNAME records pointing at storage endpoints (custom-domain blob hosting / static sites).
- Certificate transparency logs and passive DNS for the `core.windows.net` suffix.
- Permutation/wordlist brute force on `<org><word>` patterns.

```bash
# Existence check: NXDOMAIN => account does not exist; resolves => account exists
for n in orgdata orgprod orgbackups orgdiag; do
  host "$n.blob.core.windows.net" >/dev/null 2>&1 && echo "EXISTS: $n"
done

# Automated discovery / permutation (MicroBurst PowerShell)
Invoke-EnumerateAzureBlobs -Base org -OutputFile found.txt

# Brute force at scale against the blob endpoint
ffuf -w wordlist.txt -u "https://FUZZ.blob.core.windows.net/" -mc 200,400,409
```

**Probe a discovered account for anonymous container listing.** The Blob service supports a
`comp=list` operation at account scope. If anonymous account-level enumeration is allowed (rare but
seen), it returns every container name:

```bash
ACCT=orgdata
curl -s "https://$ACCT.blob.core.windows.net/?comp=list" | xmllint --format -
```

**Probe a container for anonymous blob listing and read.** This is the most common finding. Container
names must usually be guessed (`backup`, `images`, `public`, `uploads`, `logs`, `web`, `$web`,
`data`, `media`):

```bash
ACCT=orgdata; CTR=backup
# Anonymous blob listing within a container
curl -s "https://$ACCT.blob.core.windows.net/$CTR?restype=container&comp=list" | xmllint --format -

# Anonymous read of a specific blob
curl -s "https://$ACCT.blob.core.windows.net/$CTR/secrets.json" -o secrets.json

# With the CLI, anonymous mode (no key, no login)
az storage blob list --account-name "$ACCT" --container-name "$CTR" --auth-mode key --account-key "" 2>/dev/null
```

HTTP status interpretation on the blob endpoint:

- `200` with XML body - anonymous listing/read permitted.
- `404 ContainerNotFound` / `BlobNotFound` - account exists, resource does not (keep guessing names).
- `409 / 400 InvalidQueryParameterValue` on a bare GET - account exists; access restricted.
- `403 AuthenticationFailed` / `ResourceNotFound` with `PublicAccessNotPermitted` - anonymous access
  is disabled at account or container level.

**SAS-token URLs.** If a URL containing a SAS query string leaks (`?sv=...&sig=...`), it grants
whatever the token's `sp` (permissions), `sr` (resource), and `se` (expiry) fields allow, with no
further authentication. Inspect and exercise a leaked token:

```bash
# Decode the granted scope from a leaked SAS URL
# sp=racwdl => read, add, create, write, delete, list; sr=c => container; se=expiry
echo "$SAS_URL" | grep -oE 'sp=[a-z]+|sr=[a-z]+|se=[^&]+|ss=[a-z]+|srt=[a-z]+'

# Use it directly
curl -s "https://$ACCT.blob.core.windows.net/$CTR?restype=container&comp=list&$SAS_QS"
```

## Misconfigurations & Findings

- **Anonymous container read/list** - container `Public access level` set to `Container` (list + read
  blobs) or `Blob` (read individual blobs if the name is known). Anyone can enumerate or download.
- **Account allows public access** - the account-level `allowBlobPublicAccess` flag is `true`,
  enabling any container to opt into anonymous access. Even with no public container today, this is a
  standing exposure.
- **Leaked SAS tokens** - long-lived, over-scoped, or account-level SAS URLs embedded in client code,
  mobile apps, emails, ticketing systems, or commit history. Account SAS (`ss`/`srt` present) can be
  catastrophic.
- **Static website / `$web` exposure** - the `$web` container served at `*.web.core.windows.net` may
  expose source, config, or directory listings.
- **Subdomain takeover** - a dangling custom-domain CNAME pointing at a deleted storage account whose
  globally unique name can be re-registered by an attacker.
- **No anonymous logging** - anonymous reads frequently leave no usable audit trail (see Detection),
  which is itself a reportable gap.

## Detection & Logging

Anonymous access is recorded only if **Storage Analytics logging** or **Azure Monitor diagnostic
settings** (the `StorageRead` / `StorageWrite` / `StorageDelete` log categories for the blob service)
are enabled and routed to a Log Analytics workspace or storage account; these are off by default, so
anonymous reads commonly leave no trace. Control-plane changes that enable public access (setting
`allowBlobPublicAccess`, changing a container's public access level) appear in **Azure Activity Logs**
as `Microsoft.Storage/storageAccounts/write` operations. **Microsoft Defender for Storage** can
raise alerts on anonymous access from unusual locations and on access using a leaked SAS, when
enabled. **Entra ID sign-in logs** are not generated for anonymous or SAS-based requests because no
identity authenticates.

## Remediation & Hardening

- Set the account flag **`allowBlobPublicAccess = false`** to globally disable anonymous container
  access regardless of per-container settings.
- Set every container's **public access level to `Private`**; serve genuinely public content via
  Azure CDN / Front Door fronting a private origin.
- Prefer **Entra ID (Azure AD) authorization** over keys and SAS; where SAS is required, use
  **user-delegation SAS** (Entra-backed, revocable) with short expiry and least-privilege `sp`.
- Enable a **firewall / private endpoints** (`Selected networks` or `Disabled` public access) so the
  endpoint is not reachable from the internet.
- Remove dangling DNS records pointing at deleted storage accounts to prevent takeover.
- Enable **diagnostic logging** for read/write/delete and **Microsoft Defender for Storage**.

## Tools

- **azure-cli (`az storage`)** / **curl** - authoritative anonymous probing of blob, container, and
  SAS endpoints.
- **MicroBurst** (`Invoke-EnumerateAzureBlobs`, `Invoke-EnumerateAzureSubDomains`) - account and
  container discovery via permutation.
- **basicblobfinder**, **ffuf** - bucket/container discovery and access classification at scale.

## References

- Microsoft Learn - Configure anonymous read access for containers and blobs
- Microsoft Learn - List Blobs (Blob service REST API)
- Microsoft Learn - Grant limited access with shared access signatures (SAS)
- hackingthe.cloud - Enumerate Azure storage account information
