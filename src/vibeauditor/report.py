from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import ExternalResult, Finding
from .profiles import Profile


SEVERITY_COLORS = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
RESET = "\033[0m"


def render_text(
    findings: list[Finding],
    external: list[ExternalResult],
    use_color: bool = True,
    profile: Profile | None = None,
) -> str:
    lines: list[str] = []
    counts = Counter(finding.severity for finding in findings)
    total = len(findings)
    lines.append("vibeAuditor Report")
    lines.append("==================")
    lines.append("")
    if profile:
        lines.append(f"Profile: {profile.name} - {profile.description}")
        lines.append(f"Focus: {', '.join(profile.focus)}")
        lines.append("")
    lines.append(
        f"Findings: {total} "
        f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']})"
    )
    lines.append("")

    if findings:
        for finding in findings:
            severity = format_severity(finding.severity, use_color)
            location = finding.path if finding.line is None else f"{finding.path}:{finding.line}"
            lines.append(f"[{severity}] {finding.title} ({finding.rule_id})")
            lines.append(f"  {location}")
            lines.append(f"  {finding.message}")
            if finding.evidence:
                lines.append(f"  Evidence: {finding.evidence}")
            lines.append(f"  Fix: {finding.fix}")
            lines.append("")
    else:
        lines.append("No built-in findings. Nice. Still run dependency and DAST scanners before shipping.")
        lines.append("")

    if external:
        lines.append("External Scanner Status")
        lines.append("-----------------------")
        for result in external:
            status = "available" if result.available else "missing"
            exit_text = "" if result.exit_code is None else f", exit {result.exit_code}"
            lines.append(f"- {result.command}: {status}{exit_text}")
            if result.summary and result.summary != status:
                for summary_line in result.summary.splitlines():
                    lines.append(f"  {summary_line}")
        lines.append("")

    return "\n".join(lines)


def write_json(
    path: Path,
    findings: list[Finding],
    external: list[ExternalResult],
    profile: Profile | None = None,
) -> None:
    payload = {
        "tool": "vibeauditor",
        "profile": None
        if profile is None
        else {
            "name": profile.name,
            "description": profile.description,
            "focus": list(profile.focus),
        },
        "findings": [finding.to_dict() for finding in findings],
        "external": [result.to_dict() for result in external],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def format_severity(severity: str, use_color: bool) -> str:
    label = severity.upper()
    if not use_color:
        return label
    return f"{SEVERITY_COLORS.get(severity, '')}{label}{RESET}"
