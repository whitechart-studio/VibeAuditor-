from __future__ import annotations

import re
from collections.abc import Iterable

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

STRIPE_WEBHOOK_HINT = re.compile(r"(stripe\.webhooks|stripe-signature|STRIPE_WEBHOOK_SECRET)", re.IGNORECASE)
STRIPE_VERIFY_HINT = re.compile(r"(constructEvent|stripe-signature)", re.IGNORECASE)
STRIPE_CONTEXT_HINT = re.compile(r"(stripe\.webhooks|STRIPE_WEBHOOK_SECRET|stripe-signature)", re.IGNORECASE)

LLM_PROMPT_HINT = re.compile(
    r"(messages\s*:\s*\[|systemPrompt|\bprompt\s*[:=]|chat\.completions|responses\.create|generateText)",
    re.IGNORECASE,
)
USER_INPUT_HINT = re.compile(r"(req\.body|request\.json|searchParams|params\.|input\.|userInput|formData)", re.IGNORECASE)
UNSAFE_EXEC_HINT = re.compile(r"\b(eval|exec|child_process|subprocess\.|os\.system|shell=True)\b|new\s+Function\b")
DOC_EXTENSIONS = {".md", ".mdx", ".txt"}


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
        tracked_text = "committed" if is_tracked(context, path) else "present locally"
        severity = "critical" if ENV_SECRET_HINTS.search(text) else "medium"
        yield Finding(
            rule_id="VA001",
            title="Environment file contains deploy-time configuration",
            severity=severity,
            path=rel,
            line=1,
            category="secrets",
            confidence="high" if is_tracked(context, path) else "medium",
            message=f"An environment file is {tracked_text}. AI-built apps often leak live keys through env files and build artifacts.",
            fix="Move real values to your deployment secret store, commit only .env.example, and rotate any key that was exposed.",
            ai_fix_prompt=(
                "Audit environment handling for this project. Keep real secrets out of git, keep only placeholders in .env.example, "
                "verify .gitignore excludes real .env files, and rotate any exposed Supabase or provider keys. Do not remove required runtime env usage."
            ),
            verification="Run git ls-files for .env files, run gitleaks, rebuild the app, and confirm no secret values appear in build output.",
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
            if not is_doc_file(path) and UNSAFE_EXEC_HINT.search(line):
                yield Finding(
                    rule_id="VA004",
                    title="Unsafe dynamic execution surface",
                    severity="high",
                    path=rel,
                    line=line_no,
                    category="code-execution",
                    confidence="medium",
                    message="Dynamic code or shell execution is present. This is dangerous when AI-generated inputs can reach it.",
                    fix="Replace dynamic execution with explicit functions, allowlists, or safe subprocess APIs without shell evaluation.",
                    evidence=line.strip(),
                    ai_fix_prompt=(
                        "Review this dynamic execution path. If it is necessary, ensure all inputs are hardcoded or allowlisted, "
                        "avoid shell evaluation, and add a test proving user-controlled or model-generated input cannot reach it."
                    ),
                )

        if looks_like_unguarded_api_write(text):
            yield Finding(
                rule_id="VA005",
                title="API write path may be missing auth guard",
                severity="high",
                path=rel,
                line=find_first_line(lines, DB_WRITE_HINT),
                category="auth",
                confidence="medium",
                message="This file looks like an API handler that writes data without an obvious auth/session check.",
                fix="Require user authentication and authorization before write/update/delete operations.",
                ai_fix_prompt=(
                    "Review this write path for auth and ownership. Ensure the authenticated user is derived from the server/session, "
                    "not trusted from client input, and verify Supabase RLS prevents cross-user writes. Add a negative test for another user attempting the same update."
                ),
            )

        if looks_like_unverified_stripe_webhook(text):
            yield Finding(
                rule_id="VA006",
                title="Stripe webhook may lack signature verification",
                severity="high",
                path=rel,
                line=find_first_line(lines, STRIPE_WEBHOOK_HINT),
                category="payments",
                confidence="high",
                message="This looks like a webhook handler but no Stripe signature verification was detected.",
                fix="Use stripe.webhooks.constructEvent with the raw body and STRIPE_WEBHOOK_SECRET before trusting the event.",
                ai_fix_prompt=(
                    "Secure this Stripe webhook. Use the raw request body and stripe.webhooks.constructEvent with STRIPE_WEBHOOK_SECRET, "
                    "reject invalid signatures, and add tests for valid, invalid, and replayed webhook events."
                ),
            )

        if looks_like_prompt_injection_risk(text):
            yield Finding(
                rule_id="VA007",
                title="User input appears to flow into an LLM prompt",
                severity="medium",
                path=rel,
                line=find_first_line(lines, LLM_PROMPT_HINT),
                category="ai",
                confidence="medium",
                message="User-controlled input appears near prompt construction. This can enable prompt injection or tool misuse.",
                fix="Separate trusted instructions from user content, validate tool inputs, and add allowlists for actions the model can trigger.",
                ai_fix_prompt=(
                    "Harden this LLM prompt flow. Separate system instructions from user content, treat user content as untrusted data, "
                    "validate every tool/action input with an allowlist, and add a prompt-injection test case."
                ),
            )

        if path.suffix == ".sql" and "create policy" not in text.lower() and "alter table" in text.lower() and "enable row level security" in text.lower():
            yield Finding(
                rule_id="VA008",
                title="RLS enabled without nearby policy",
                severity="medium",
                path=rel,
                line=find_text_line(lines, "enable row level security"),
                category="supabase",
                confidence="medium",
                message="RLS is enabled, but this SQL file does not appear to define policies.",
                fix="Add explicit SELECT/INSERT/UPDATE/DELETE policies and test them with anon and authenticated roles.",
                ai_fix_prompt=(
                    "Review this Supabase RLS migration. If direct table access is intended, add explicit policies for each role/action. "
                    "If access is only through SECURITY DEFINER functions or service role, document that design and add tests proving anon/authenticated users cannot access rows directly."
                ),
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
                confidence="high",
                message="No npm, pnpm, or yarn lockfile was found. AI agents may install drifting or vulnerable package versions.",
                fix="Commit a lockfile and run OSV-Scanner or Trivy in CI.",
                ai_fix_prompt="Generate and commit the appropriate JavaScript lockfile, then run dependency vulnerability scanning in CI.",
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
                    confidence="high",
                    message="requirements.txt exists without a detected lockfile.",
                    fix="Use uv, pip-tools, Poetry, or another lockfile workflow for reproducible installs.",
                    ai_fix_prompt="Add a reproducible Python dependency lock workflow and document the install command for contributors.",
                )


def looks_like_unguarded_api_write(text: str) -> bool:
    return bool(AUTH_HANDLER_HINT.search(text) and DB_WRITE_HINT.search(text) and not AUTH_GUARD_HINT.search(text))


def looks_like_unverified_stripe_webhook(text: str) -> bool:
    return bool(STRIPE_CONTEXT_HINT.search(text) and STRIPE_WEBHOOK_HINT.search(text) and not STRIPE_VERIFY_HINT.search(text))


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


def is_doc_file(path) -> bool:
    return path.suffix.lower() in DOC_EXTENSIONS or "docs" in path.parts


def is_tracked(context: ScanContext, path) -> bool:
    git_dir = context.root / ".git"
    if not git_dir.exists():
        return False
    try:
        import subprocess

        completed = subprocess.run(
            ["git", "ls-files", "--error-unmatch", relative_path(context.root, path)],
            cwd=context.root,
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
        return completed.returncode == 0
    except Exception:
        return False
