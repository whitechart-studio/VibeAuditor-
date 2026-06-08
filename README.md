# vibeAuditor

Audit AI-built apps before they ship.

vibeAuditor is a local-first security and quality audit CLI for vibe-coded and
AI-assisted software. It blends trusted open-source scanners with AI-app-specific
checks for secrets, auth gaps, Supabase mistakes, webhook risks, unsafe execution,
and prompt-injection surfaces.

The goal is simple: one command, one professional report.

## Why vibeAuditor

AI coding tools are fast, but they do not reliably prove that an app is safe to
ship. vibeAuditor gives builders a practical pre-ship gate: built-in checks for
the mistakes common in AI-built apps, plus a clean path to proven open-source
scanners such as Trivy, Semgrep, OSV-Scanner, Gitleaks, Syft, Grype, and ZAP.

## What it checks

- Exposed secrets and high-risk environment files.
- Supabase service-role key leaks and client/server boundary mistakes.
- Missing or suspicious auth guards around API routes.
- Stripe webhook handlers without signature verification.
- LLM prompt injection patterns, unsafe tool calls, and model output passed to code execution.
- Risky dependency manifests and lockfile presence.
- Optional external scanner availability: Trivy, Semgrep, OSV-Scanner, Gitleaks, Syft, Grype, and ZAP.

## Quick Start

Install from a local checkout:

```bash
pipx install .
```

Or during active development:

```bash
pipx install --editable .
```

```bash
vibeauditor /path/to/project
```

From this repository during development:

```bash
PYTHONPATH=src python3 -m vibeauditor .
```

Write JSON for CI or AI agents:

```bash
vibeauditor . --json report.json
```

Write a bucketed Markdown report for GitHub issues, PR comments, or product review:

```bash
vibeauditor . --markdown vibeauditor-report.md
```

Write a GitHub issue-friendly report with detailed finding sections instead of
wide tables:

```bash
vibeauditor . --github-markdown vibeauditor-github.md
```

Fail CI when high or critical findings exist:

```bash
vibeauditor . --fail-on high
```

Use a project profile:

```bash
vibeauditor . --profile next-supabase
```

GitHub Actions template:

```text
examples/github-actions/vibeauditor.yml
```

Copy it into `.github/workflows/vibeauditor.yml` in a repository where you want
vibeAuditor to run on pull requests.

## Optional Scanner Integrations

vibeAuditor does not install scanners for you. If these commands exist on your
machine, it can run them and include a short summary:

```bash
trivy fs .
semgrep scan --config auto .
osv-scanner scan source .
gitleaks detect --source .
```

Use:

```bash
vibeauditor . --external
```

## Example Output

vibeAuditor leads with a product decision, not a raw vulnerability dump:

```text
vibeAuditor Report
==================

Profile: next-supabase - Next.js and Supabase pre-ship checks.
Focus: supabase, auth, secrets, dependencies

Findings: 9 (critical 3, high 1, medium 5, low 0)
Verdict: BLOCKED - fix blocker findings before production
Primary reason: Credentials detected in env, source, or build output
Product risk: Blocker 3, High 1, Medium 3, Low 2

Top Actions
-----------
1. Rotate exposed credentials, remove real keys from env/build artifacts, and rerun gitleaks plus vibeAuditor.
2. Verify every write path derives identity from the server/session and blocks cross-user access with tests.
3. Prove RLS-sensitive tables deny direct anon/authenticated access or document SECURITY DEFINER-only access.

Risk Buckets
------------
| Domain                | Risk    | Findings | Status                |
| --------------------- | ------- | -------- | --------------------- |
| Secrets & Credentials | Blocker | 4        | Needs fix before ship |
| Auth & Access Control | High    | 1        | Needs owner review    |
| Data Privacy & RLS    | Medium  | 2        | Needs verification    |
| Developer Tooling     | Low     | 2        | Optional hardening    |
```

Detailed sections include asset context, confidence, product impact, AI fix
prompt, verification steps, and safely redacted evidence:

```text
Secrets & Credentials
---------------------
| Risk    | Conf      | Asset          | Location                     | Issue                              |
| ------- | --------- | -------------- | ---------------------------- | ---------------------------------- |
| Blocker | confirmed | local_env      | .env:2                       | Possible Supabase JWT-like key... |
| Blocker | confirmed | build_artifact | dist-ssr/entry-server.js:126 | Possible Supabase JWT-like key... |

AI fix prompt:
You are fixing credential exposure in this project. A Supabase JWT-like key was
found in build_artifact. Do not remove required runtime env usage. Ensure
browser/client code only receives public anon keys, never service-role or
private keys. Remove real values from env/build artifacts, update .env.example
with placeholders, verify .gitignore excludes local env and generated build
output, rotate any exposed credential, then rerun vibeAuditor and gitleaks.

Verification:
git ls-files .env .env.local dist-ssr/entry-server.js
gitleaks detect --source .
vibeauditor . --profile next-supabase
```

With `--external`, scanner coverage is summarized in the same report:

```text
Tooling Coverage
----------------
- Trivy: secrets found in .env and build output
- Semgrep: shell/spawn usage in developer scripts
- OSV-Scanner: no dependency issues found
- Gitleaks: leak detected in git history
- Syft: package inventory generated
- Grype: no vulnerabilities found
```

For GitHub issues, use the sectioned format:

```bash
vibeauditor . --profile next-supabase --github-markdown vibeauditor-github.md
```

It produces issue-friendly blocks like:

```markdown
## Secrets & Credentials

**Bucket risk:** Blocker
**Findings:** 4

### VA002: Possible Supabase JWT-like key exposed

- **Risk:** Blocker
- **Confidence:** confirmed
- **Asset context:** `build_artifact`
- **Location:** `dist-ssr/entry-server.js:126`
- **Fingerprint:** `0259095bde85a569`

**Product impact**

A Supabase JWT-like credential appears in build_artifact. If this is a
service-role key, it can bypass RLS and expose marketplace user, worker,
contractor, OTP, or payment data.
```

## Scanner Blend

vibeAuditor is designed as an orchestration layer, not a replacement for mature
security tools.

| Layer | Tool | Purpose |
| --- | --- | --- |
| Vibe rules | Built in | AI-app mistakes, Supabase/auth/webhook/LLM checks |
| SAST | Semgrep | insecure source patterns |
| Code intelligence | CodeQL | deeper semantic analysis for GitHub/open-source repos |
| Dependencies | OSV-Scanner | open-source package vulnerabilities |
| Repo/container/IaC | Trivy | vulnerabilities, secrets, misconfig, SBOM, licenses |
| Secrets | Gitleaks | high-signal secret detection |
| SBOM | Syft | software bill of materials |
| SBOM vulnerabilities | Grype | vulnerability scan from filesystem/SBOM |
| Live app | ZAP | dynamic web app security testing |

## Report Model

vibeAuditor groups findings into product-risk domains instead of dumping a flat
scanner list:

- Secrets & Credentials
- Auth & Access Control
- Data Privacy & RLS
- Payments & Webhooks
- AI / LLM Safety
- Supply Chain
- Infrastructure & Deployment
- General Code Quality

Each finding includes:

- severity
- product risk: `Blocker`, `High`, `Medium`, `Low`
- confidence: `confirmed`, `likely`, `needs_review`
- asset context: `tracked_source`, `local_env`, `build_artifact`, `developer_script`, `database_migration`, etc.
- domain bucket
- stable fingerprint
- product impact
- AI fix prompt
- verification step

This structure is designed for the next GitHub workflow:

```text
scan project -> bucket findings -> create/update GitHub issues -> close fixed buckets
```

## Suppressions

Known accepted-risk findings can be suppressed with `.vibeauditor.toml`.
Suppressions use stable fingerprints from the JSON or GitHub Markdown report.

```toml
[[suppress]]
fingerprint = "abc123def4567890"
reason = "Local developer script only spawns a static Semgrep command."
expires = "2026-07-01"
```

Suppressions should always include a reason and an expiry date so risk does not
silently disappear forever.

## Planned Rule Packs

- `next-supabase`: service-role exposure, RLS gaps, API auth, public env safety.
- `stripe-saas`: webhook signatures, payment state transitions, secret handling.
- `ai-agent`: prompt injection, unsafe tools, model output execution, data leaks.
- `mcp-server`: tool auth, filesystem/network boundaries, prompt/tool injection.
- `browser-extension`: manifest permissions, content-script leakage, token exposure.

Current profile names:

```text
default
next-supabase
ai-agent
stripe-saas
mcp-server
```

## Philosophy

This tool is not trying to replace mature scanners. It is a friendly front door:
fast local checks, plain-English findings, and pointers to the next best tool.
It is especially tuned for projects built quickly with Cursor, Codex, Claude Code,
Lovable, Bolt, v0, Replit, and similar workflows.
