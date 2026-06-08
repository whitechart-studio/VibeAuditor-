from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from .files import relative_path, safe_read
from .models import Finding, ScanContext


SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Supabase JWT-like key", re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b")),
]

ENV_SECRET_HINTS = re.compile(
    r"(SERVICE_ROLE|SECRET|PRIVATE_KEY|API_KEY|TOKEN|PASSWORD)\s*=\s*['\"]?[^'\"\s#]{12,}",
    re.IGNORECASE,
)

CLIENT_EXPOSED_SECRET = re.compile(
    r"(NEXT_PUBLIC|VITE|PUBLIC)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|TOKEN|PASSWORD)",
    re.IGNORECASE,
)

AUTH_HANDLER_HINT = re.compile(
    r"(export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)|app\.(get|post|put|patch|delete)|router\.(get|post|put|patch|delete))",
    re.IGNORECASE,
)

AUTH_GUARD_HINT = re.compile(
    r"(getServerSession|auth\(|getUser\(|getClaims\(|requireAuth|currentUser|verifyJwt|jwt\.verify|withAuth|isAuthenticated)",
    re.IGNORECASE,
)

DB_WRITE_HINT = re.compile(
    r"(\.insert\(|\.update\(|\.delete\(|\.upsert\(|prisma\.\w+\.(create|update|delete)|from\(.+\)\.(insert|update|delete|upsert))",
    re.IGNORECASE,
)

STRIPE_WEBHOOK_HINT = re.compile(r"(stripe\.webhooks|constructEvent|stripe-signature|webhook)", re.IGNORECASE)
STRIPE_VERIFY_HINT = re.compile(r"(constructEvent|stripe-signature)", re.IGNORECASE)

LLM_PROMPT_HINT = re.compile(
    r"(messages\s*:\s*\[|systemPrompt|\bprompt\s*[:=]|chat\.completions|responses\.create|generateText)",
    re.IGNORECASE,
)
USER_INPUT_HINT = re.compile(r"(req\.body|request\.json|searchParams|params\.|input\.|userInput|formData)", re.IGNORECASE)
UNSAFE_EXEC_HINT = re.compile(r"\b(eval|exec|Function|child_process|subprocess\.|os\.system|shell=True)\b")


def run_builtin_rules(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_env_files(context))
    findings.extend(check_file_contents(context))
    findings.extend(check_dependency_manifests(context))
    return sorted(findings, key=lambda item: (-severity_rank(item.severity), item.path, item.line or 0))


def check_env_files(context: ScanContext) -> Iterable[Finding]:
    for path in context.files:
        if not path.name.startswith(".env"):
            continue
        rel = relative_path(context.root, path)
        text = safe_read(path)
        severity = "critical" if ENV_SECRET_HINTS.search(text) else "medium"
        yield Finding(
            rule_id="VA001",
            title="Environment file committed",
            severity=severity,
            path=rel,
            line=1,
            category="secrets",
            message="This repository contains an environment file. AI-built apps often accidentally commit live keys here.",
            fix="Move real values to your deployment secret store, commit only .env.example, and rotate any key that was exposed.",
        )


def check_file_contents(context: ScanContext) -> Iterable[Finding]:
    for path in context.files:
        text = safe_read(path)
        if not text:
            continue
        rel = relative_path(context.root, path)
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for secret_name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    yield Finding(
                        rule_id="VA002",
                        title=f"Possible {secret_name} exposed",
                        severity="critical",
                        path=rel,
                        line=line_no,
                        category="secrets",
                        message=f"A value matching {secret_name} appears in source.",
                        fix="Remove the value from git history if committed, rotate it, and load it from runtime secrets.",
                        evidence=redact(line),
                    )
            if CLIENT_EXPOSED_SECRET.search(line):
                yield Finding(
                    rule_id="VA003",
                    title="Secret-like value exposed to client bundle",
                    severity="critical",
                    path=rel,
                    line=line_no,
                    category="secrets",
                    message="A public client env prefix is combined with a secret-like name.",
                    fix="Never expose service-role, private, token, or password values with NEXT_PUBLIC, VITE, or PUBLIC prefixes.",
                    evidence=line.strip(),
                )
            if UNSAFE_EXEC_HINT.search(line):
                yield Finding(
                    rule_id="VA004",
                    title="Unsafe dynamic execution surface",
                    severity="high",
                    path=rel,
                    line=line_no,
                    category="code-execution",
                    message="Dynamic code or shell execution is present. This is dangerous when AI-generated inputs can reach it.",
                    fix="Replace dynamic execution with explicit functions, allowlists, or safe subprocess APIs without shell evaluation.",
                    evidence=line.strip(),
                )

        if looks_like_unguarded_api_write(text):
            yield Finding(
                rule_id="VA005",
                title="API write path may be missing auth guard",
                severity="high",
                path=rel,
                line=find_first_line(lines, DB_WRITE_HINT),
                category="auth",
                message="This file looks like an API handler that writes data without an obvious auth/session check.",
                fix="Require user authentication and authorization before write/update/delete operations.",
            )

        if looks_like_unverified_stripe_webhook(text):
            yield Finding(
                rule_id="VA006",
                title="Stripe webhook may lack signature verification",
                severity="high",
                path=rel,
                line=find_first_line(lines, STRIPE_WEBHOOK_HINT),
                category="payments",
                message="This looks like a webhook handler but no Stripe signature verification was detected.",
                fix="Use stripe.webhooks.constructEvent with the raw body and STRIPE_WEBHOOK_SECRET before trusting the event.",
            )

        if looks_like_prompt_injection_risk(text):
            yield Finding(
                rule_id="VA007",
                title="User input appears to flow into an LLM prompt",
                severity="medium",
                path=rel,
                line=find_first_line(lines, LLM_PROMPT_HINT),
                category="ai",
                message="User-controlled input appears near prompt construction. This can enable prompt injection or tool misuse.",
                fix="Separate trusted instructions from user content, validate tool inputs, and add allowlists for actions the model can trigger.",
            )

        if path.suffix == ".sql" and "create policy" not in text.lower() and "alter table" in text.lower() and "enable row level security" in text.lower():
            yield Finding(
                rule_id="VA008",
                title="RLS enabled without nearby policy",
                severity="medium",
                path=rel,
                line=find_text_line(lines, "enable row level security"),
                category="supabase",
                message="RLS is enabled, but this SQL file does not appear to define policies.",
                fix="Add explicit SELECT/INSERT/UPDATE/DELETE policies and test them with anon and authenticated roles.",
            )


def check_dependency_manifests(context: ScanContext) -> Iterable[Finding]:
    names = {path.name for path in context.files}
    package_jsons = [path for path in context.files if path.name == "package.json"]
    for path in package_jsons:
        rel = relative_path(context.root, path)
        lock_present = bool({"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}.intersection(names))
        if not lock_present:
            yield Finding(
                rule_id="VA009",
                title="JavaScript project has no lockfile",
                severity="medium",
                path=rel,
                line=1,
                category="dependencies",
                message="No npm, pnpm, or yarn lockfile was found. AI agents may install drifting or vulnerable package versions.",
                fix="Commit a lockfile and run OSV-Scanner or Trivy in CI.",
            )

    if "requirements.txt" in names and "requirements.lock" not in names and "uv.lock" not in names and "poetry.lock" not in names:
        for path in context.files:
            if path.name == "requirements.txt":
                yield Finding(
                    rule_id="VA010",
                    title="Python requirements are not locked",
                    severity="low",
                    path=relative_path(context.root, path),
                    line=1,
                    category="dependencies",
                    message="requirements.txt exists without a detected lockfile.",
                    fix="Use uv, pip-tools, Poetry, or another lockfile workflow for reproducible installs.",
                )


def looks_like_unguarded_api_write(text: str) -> bool:
    return bool(AUTH_HANDLER_HINT.search(text) and DB_WRITE_HINT.search(text) and not AUTH_GUARD_HINT.search(text))


def looks_like_unverified_stripe_webhook(text: str) -> bool:
    return bool(STRIPE_WEBHOOK_HINT.search(text) and not STRIPE_VERIFY_HINT.search(text))


def looks_like_prompt_injection_risk(text: str) -> bool:
    return bool(LLM_PROMPT_HINT.search(text) and USER_INPUT_HINT.search(text))


def find_first_line(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    for line_no, line in enumerate(lines, start=1):
        if pattern.search(line):
            return line_no
    return None


def find_text_line(lines: list[str], needle: str) -> int | None:
    needle = needle.lower()
    for line_no, line in enumerate(lines, start=1):
        if needle in line.lower():
            return line_no
    return None


def redact(line: str) -> str:
    stripped = line.strip()
    if len(stripped) <= 16:
        return "<redacted>"
    return f"{stripped[:8]}...{stripped[-4:]}"


def severity_rank(severity: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return ranks.get(severity, 0)
