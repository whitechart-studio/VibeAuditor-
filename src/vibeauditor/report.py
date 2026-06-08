from __future__ import annotations

import json
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

from .models import ExternalResult, Finding, SEVERITY_ORDER, domain_for_category, product_risk_for_severity
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
    risk_counts = Counter(finding.product_risk or product_risk_for_severity(finding.severity) for finding in findings)
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
    lines.append(f"Verdict: {verdict(findings)}")
    if findings:
        lines.append(
            "Product risk: "
            + ", ".join(f"{name} {risk_counts[name]}" for name in ["Blocker", "High", "Medium", "Low"] if risk_counts[name])
        )
    lines.append("")

    if findings:
        for domain, domain_findings in bucket_findings(findings).items():
            lines.append(domain)
            lines.append("-" * len(domain))
            lines.extend(render_bucket_table(domain_findings, use_color=use_color))
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


def write_markdown(
    path: Path,
    findings: list[Finding],
    external: list[ExternalResult],
    profile: Profile | None = None,
) -> None:
    path.write_text(render_markdown(findings, external, profile=profile), encoding="utf-8")


def render_markdown(
    findings: list[Finding],
    external: list[ExternalResult],
    profile: Profile | None = None,
) -> str:
    counts = Counter(finding.severity for finding in findings)
    risk_counts = Counter(finding.product_risk or product_risk_for_severity(finding.severity) for finding in findings)
    lines = ["# vibeAuditor Report", ""]
    if profile:
        lines.append(f"**Profile:** `{profile.name}` - {profile.description}")
        lines.append("")
        lines.append(f"**Focus:** {', '.join(profile.focus)}")
        lines.append("")
    lines.append(f"**Verdict:** {verdict(findings)}")
    lines.append("")
    lines.append(
        f"**Findings:** {len(findings)} "
        f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']})"
    )
    if findings:
        lines.append("")
        lines.append(
            "**Product risk:** "
            + ", ".join(f"{name} {risk_counts[name]}" for name in ["Blocker", "High", "Medium", "Low"] if risk_counts[name])
        )
    lines.append("")

    if findings:
        for domain, domain_findings in bucket_findings(findings).items():
            lines.append(f"## {domain}")
            lines.append("")
            lines.append("| Risk | Confidence | Location | Issue | Product Impact | AI Fix Prompt | Verification |")
            lines.append("| --- | --- | --- | --- | --- | --- | --- |")
            for finding in domain_findings:
                data = finding.to_dict()
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            escape_md(data["product_risk"]),
                            escape_md(data["confidence"]),
                            escape_md(location(finding)),
                            escape_md(f"{finding.title} ({finding.rule_id})"),
                            escape_md(finding.message),
                            escape_md(data["ai_fix_prompt"]),
                            escape_md(data["verification"]),
                        ]
                    )
                    + " |"
                )
            lines.append("")
    else:
        lines.append("No built-in findings. Still run dependency and DAST scanners before shipping.")
        lines.append("")

    if external:
        lines.append("## External Scanner Status")
        lines.append("")
        lines.append("| Scanner command | Status | Summary |")
        lines.append("| --- | --- | --- |")
        for result in external:
            status = "available" if result.available else "missing"
            if result.exit_code is not None:
                status = f"{status}, exit {result.exit_code}"
            lines.append(f"| `{escape_md(result.command)}` | {escape_md(status)} | {escape_md(result.summary)} |")
        lines.append("")

    return "\n".join(lines)


def format_severity(severity: str, use_color: bool) -> str:
    label = severity.upper()
    if not use_color:
        return label
    return f"{SEVERITY_COLORS.get(severity, '')}{label}{RESET}"


def bucket_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in sorted(
        findings,
        key=lambda item: (
            -(SEVERITY_ORDER.get(item.severity, 0)),
            item.domain or domain_for_category(item.category),
            item.path,
            item.line or 0,
        ),
    ):
        grouped[finding.domain or domain_for_category(finding.category)].append(finding)
    return dict(grouped)


def render_bucket_table(findings: list[Finding], use_color: bool) -> list[str]:
    rows = [["Risk", "Conf", "Location", "Issue", "Product impact"]]
    for finding in findings:
        data = finding.to_dict()
        rows.append(
            [
                data["product_risk"],
                data["confidence"],
                location(finding),
                f"{finding.title} ({finding.rule_id})",
                finding.message,
            ]
        )
    table = render_ascii_table(rows)
    lines = table[:]
    lines.append("")
    for index, finding in enumerate(findings, start=1):
        data = finding.to_dict()
        lines.append(f"{index}. AI fix prompt: {wrap_inline(data['ai_fix_prompt'])}")
        lines.append(f"   Verification: {wrap_inline(data['verification'])}")
        if finding.evidence:
            lines.append(f"   Evidence: {finding.evidence}")
    return lines


def render_ascii_table(rows: list[list[str]]) -> list[str]:
    widths = [min(max(len(str(row[i])) for row in rows), limit) for i, limit in enumerate([10, 8, 32, 40, 56])]
    rendered: list[str] = []
    for row_index, row in enumerate(rows):
        cells = [clip(str(value), widths[index]).ljust(widths[index]) for index, value in enumerate(row)]
        rendered.append("| " + " | ".join(cells) + " |")
        if row_index == 0:
            rendered.append("| " + " | ".join("-" * width for width in widths) + " |")
    return rendered


def location(finding: Finding) -> str:
    return finding.path if finding.line is None else f"{finding.path}:{finding.line}"


def verdict(findings: list[Finding]) -> str:
    if any((finding.product_risk or product_risk_for_severity(finding.severity)) == "Blocker" for finding in findings):
        return "BLOCKED - fix blocker findings before production"
    if any(finding.severity == "high" for finding in findings):
        return "REVIEW - high-risk findings need owner review"
    if findings:
        return "PASS WITH NOTES - review medium/low hardening items"
    return "PASS - no built-in findings"


def clip(value: str, width: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= width:
        return normalized
    return normalized[: max(width - 1, 1)] + "…"


def wrap_inline(value: str) -> str:
    return "\n   ".join(textwrap.wrap(" ".join(value.split()), width=110))


def escape_md(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")
