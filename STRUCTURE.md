# CSTG Structure & Authoring Guide

The Cloud Security Testing Guide (CSTG) is organised as a **phase × service matrix** per cloud
provider. Each test page is an atomic Markdown file with YAML frontmatter, so the guide is both
human-readable and machine-consumable.

## Layout

```
<provider>/                       # aws | azure | gcp | kubernetes
  00-basic-information/           # platform model, auth, IAM concepts
  01-unauthenticated-external/    # no credentials - internet-facing surface
  02-services/                    # authenticated enumeration - one hub page per service
  03-privilege-escalation/        # one page per service; sections keyed by permission
  04-lateral-movement/
  05-post-exploitation/
  06-persistence/
```

File naming: `<provider>-<service>-<phase>.md` (e.g. `aws-s3-privesc.md`). A service recurs as a
file across the phase folders; the `02-services/` page is the **hub** that links out to that
service's other phases.

## Frontmatter (every page)

```yaml
---
cstg_id: CSTG-AWS-S3-PRIVESC        # CSTG-<PROVIDER>-<SERVICE>-<PHASE>
title: "AWS S3 - Privilege Escalation"
provider: aws                       # aws | azure | gcp | kubernetes
service: s3
phase: privilege-escalation         # basic-information | unauthenticated | services |
                                    # privilege-escalation | lateral-movement |
                                    # post-exploitation | persistence
required_access: assumed-breach     # unauthenticated | assumed-breach | read-only-audit | elevated
required_permissions:               # the access this page's techniques assume (neutral prerequisite)
  - s3:PutBucketPolicy
tools: [aws-cli, pacu, cloudfox]    # named neutrally
references:
  - "https://docs.aws.amazon.com/..."
license: CC BY-SA 4.0
---
```

`required_access` tiers (a neutral prerequisite describing what a tester needs to run the page -
NOT an instruction to any tool or agent):

| Tier | Meaning |
| --- | --- |
| `unauthenticated` | No credentials; only the internet-facing surface |
| `assumed-breach` | A single low-privilege principal / key set |
| `read-only-audit` | A read-only role (AWS SecurityAudit/ViewOnly, Azure Reader, GCP Viewer) |
| `elevated` | Broad read + selected mutate, often org-scoped |

## Page body (fixed section order)

1. **Summary** - what the page covers and the attacker objective.
2. **Prerequisites** - required access and permissions.
3. **Enumeration** - concrete CLI/API commands.
4. **Misconfigurations & Findings** - what is wrong and why it matters.
5. **Exploitation** - step-by-step attack paths (in privesc pages, one subsection per permission).
6. **Detection & Logging** - what the activity leaves in provider logs (CloudTrail, Activity Log,
   Cloud Audit Logs) and relevant managed detections.
7. **Remediation & Hardening** - how to prevent or fix it.
8. **Tools** - tools that assist, named neutrally.
9. **References** - primary sources.

Sections 6 and 7 (defence) are deliberately part of every page - CSTG documents both how to test
*and* how to fix, which distinguishes it from attacker-only references.

## Authoring principles

- **Vendor- and tool-agnostic.** No company names, no product/agent framing. CSTG is a neutral OWASP
  standard.
- **Comprehensive.** Cover the full known technique set for each service/phase. Do not omit
  commands, permissions, or attack paths.
- **Original wording.** Techniques and commands are public-domain facts and are used freely;
  prose is written originally, not copied from any single source. Cite primary sources in References.
