from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int | None
    message: str
    fix: str
    category: str
    evidence: str | None = None
    domain: str | None = None
    product_risk: str | None = None
    confidence: str = "medium"
    asset_context: str | None = None
    ai_fix_prompt: str | None = None
    verification: str | None = None
    likely_false_positive: bool = False

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}:{self.path}:{self.line or 0}:{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "product_risk": self.product_risk or product_risk_for_severity(self.severity),
            "confidence": self.confidence,
            "asset_context": self.asset_context or "unknown",
            "domain": self.domain or domain_for_category(self.category),
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "fix": self.fix,
            "category": self.category,
            "evidence": self.evidence,
            "ai_fix_prompt": self.ai_fix_prompt or default_ai_fix_prompt(self),
            "verification": self.verification or default_verification(self),
            "likely_false_positive": self.likely_false_positive,
        }


@dataclass
class ScanContext:
    root: Path
    files: list[Path] = field(default_factory=list)
    skipped_dirs: set[str] = field(default_factory=set)


@dataclass
class ExternalResult:
    command: str
    available: bool
    exit_code: int | None = None
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "available": self.available,
            "exit_code": self.exit_code,
            "summary": self.summary,
        }


DOMAIN_BY_CATEGORY = {
    "secrets": "Secrets & Credentials",
    "auth": "Auth & Access Control",
    "supabase": "Data Privacy & RLS",
    "payments": "Payments & Webhooks",
    "ai": "AI / LLM Safety",
    "dependencies": "Supply Chain",
    "code-execution": "Infrastructure & Deployment",
    "developer-tooling": "Developer Tooling",
}

PRODUCT_RISK_BY_SEVERITY = {
    "critical": "Blocker",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def domain_for_category(category: str) -> str:
    return DOMAIN_BY_CATEGORY.get(category, "General Code Quality")


def product_risk_for_severity(severity: str) -> str:
    return PRODUCT_RISK_BY_SEVERITY.get(severity, "Review")


def default_ai_fix_prompt(finding: Finding) -> str:
    location = finding.path if finding.line is None else f"{finding.path}:{finding.line}"
    return (
        f"Fix the vibeAuditor finding {finding.rule_id} at {location}. "
        f"Issue: {finding.title}. Asset context: {finding.asset_context or 'unknown'}. Product risk: {finding.message} "
        f"Make the smallest safe code or configuration change, preserve intended behavior, "
        f"and add or describe a verification step. Recommended fix: {finding.fix}"
    )


def default_verification(finding: Finding) -> str:
    if finding.category == "secrets":
        return "Run vibeAuditor plus gitleaks and confirm no real secret values remain outside approved local env files."
    if finding.category == "auth":
        return "Add or run an auth/RLS test proving a different user cannot perform this action."
    if finding.category == "supabase":
        return "Test the table or function as anon, authenticated owner, authenticated non-owner, and service role."
    if finding.category == "payments":
        return "Send a valid signed webhook and an invalid signature webhook; only the signed event should be accepted."
    if finding.category == "ai":
        return "Run a prompt-injection test and confirm model output cannot trigger unapproved actions."
    if finding.category == "dependencies":
        return "Regenerate the lockfile and run OSV-Scanner or Trivy with no unresolved high-risk findings."
    if finding.category == "developer-tooling":
        return "Confirm the script only accepts trusted static commands and cannot be reached from user or model input."
    return "Run the app tests plus vibeAuditor again and confirm this finding is gone or intentionally suppressed."
