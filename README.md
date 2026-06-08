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

```bash
python3 -m vibeauditor /path/to/project
```

From this repository during development:

```bash
PYTHONPATH=src python3 -m vibeauditor .
```

Write JSON for CI or AI agents:

```bash
PYTHONPATH=src python3 -m vibeauditor . --json report.json
```

Write a bucketed Markdown report for GitHub issues, PR comments, or product review:

```bash
PYTHONPATH=src python3 -m vibeauditor . --markdown vibeauditor-report.md
```

Write a GitHub issue-friendly report with detailed finding sections instead of
wide tables:

```bash
PYTHONPATH=src python3 -m vibeauditor . --github-markdown vibeauditor-github.md
```

Fail CI when high or critical findings exist:

```bash
PYTHONPATH=src python3 -m vibeauditor . --fail-on high
```

Use a project profile:

```bash
PYTHONPATH=src python3 -m vibeauditor . --profile next-supabase
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
PYTHONPATH=src python3 -m vibeauditor . --external
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
