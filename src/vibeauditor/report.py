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
    primary_reason = primary_blocker_reason(findings)
    if primary_reason:
        lines.append(f"Primary reason: {primary_reason}")
    if findings:
        lines.append(
            "Product risk: "
            + ", ".join(f"{name} {risk_counts[name]}" for name in ["Blocker", "High", "Medium", "Low"] if risk_counts[name])
        )
    lines.append("")

    if findings:
        lines.append("Top Actions")
        lines.append("-----------")
        for index, action in enumerate(top_actions(findings), start=1):
            lines.append(f"{index}. {action}")
        lines.append("")

        lines.append("Risk Buckets")
        lines.append("------------")
        lines.extend(render_bucket_summary(findings))
        lines.append("")

        for domain, domain_findings in bucket_findings(findings).items():
            lines.append(domain)
            lines.append("-" * len(domain))
            lines.extend(render_bucket_table(domain_findings, use_color=use_color))
            lines.append("")
    else:
        lines.append("No built-in findings. Nice. Still run dependency and DAST scanners before shipping.")
        lines.append("")

    if external:
        lines.append("Tooling Coverage")
        lines.append("----------------")
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


def write_github_markdown(
    path: Path,
    findings: list[Finding],
    external: list[ExternalResult],
    profile: Profile | None = None,
) -> None:
    path.write_text(render_github_markdown(findings, external, profile=profile), encoding="utf-8")


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
    primary_reason = primary_blocker_reason(findings)
    if primary_reason:
        lines.append(f"**Primary reason:** {primary_reason}")
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
        lines.append("## Top Actions")
        lines.append("")
        for index, action in enumerate(top_actions(findings), start=1):
            lines.append(f"{index}. {action}")
        lines.append("")

        lines.append("## Risk Buckets")
        lines.append("")
        lines.append("| Domain | Risk | Findings | Status |")
        lines.append("| --- | --- | ---: | --- |")
        for row in bucket_summary_rows(findings):
            lines.append(f"| {escape_md(row['domain'])} | {escape_md(row['risk'])} | {row['count']} | {escape_md(row['status'])} |")
        lines.append("")

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
        lines.append("## Tooling Coverage")
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


def render_github_markdown(
    findings: list[Finding],
    external: list[ExternalResult],
    profile: Profile | None = None,
) -> str:
    counts = Counter(finding.severity for finding in findings)
    lines = ["# vibeAuditor Product Risk Report", ""]
    if profile:
        lines.append(f"**Profile:** `{profile.name}`")
        lines.append("")
    lines.append(f"**Verdict:** {verdict(findings)}")
    reason = primary_blocker_reason(findings)
    if reason:
        lines.append(f"**Primary reason:** {reason}")
    lines.append(f"**Findings:** {len(findings)} total, {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium")
    lines.append("")

    if findings:
        lines.append("## Top Actions")
        lines.append("")
        for index, action in enumerate(top_actions(findings), start=1):
            lines.append(f"{index}. {action}")
        lines.append("")

        lines.append("## Risk Buckets")
        lines.append("")
        lines.append("| Domain | Risk | Findings | Status |")
        lines.append("| --- | --- | ---: | --- |")
        for row in bucket_summary_rows(findings):
            lines.append(f"| {escape_md(row['domain'])} | {escape_md(row['risk'])} | {row['count']} | {escape_md(row['status'])} |")
        lines.append("")

        for domain, domain_findings in bucket_findings(findings).items():
            lines.append(f"## {domain}")
            lines.append("")
            lines.append(f"**Bucket risk:** {highest_product_risk(domain_findings)}")
            lines.append(f"**Findings:** {len(domain_findings)}")
            lines.append("")
            for finding in domain_findings:
                data = finding.to_dict()
                lines.append(f"### {finding.rule_id}: {finding.title}")
                lines.append("")
                lines.append(f"- **Risk:** {data['product_risk']}")
                lines.append(f"- **Confidence:** {data['confidence']}")
                lines.append(f"- **Asset context:** `{data['asset_context']}`")
                lines.append(f"- **Location:** `{location(finding)}`")
                lines.append(f"- **Fingerprint:** `{data['fingerprint']}`")
                if finding.evidence:
                    lines.append(f"- **Evidence:** `{escape_md(finding.evidence)}`")
                lines.append("")
                lines.append("**Product impact**")
                lines.append("")
                lines.append(f"{finding.message}")
                lines.append("")
                lines.append("**AI fix prompt**")
                lines.append("")
                lines.append("```text")
                lines.append(data["ai_fix_prompt"])
                lines.append("```")
                lines.append("")
                lines.append("**Verification**")
                lines.append("")
                lines.append(f"```{verification_fence(data['verification'])}")
                lines.append(data["verification"])
                lines.append("```")
                lines.append("")
    else:
        lines.append("No built-in findings. Keep external scanner coverage enabled before production.")
        lines.append("")

    if external:
        lines.append("## Tooling Coverage")
        lines.append("")
        for result in external:
            status = "available" if result.available else "missing"
            lines.append(f"- `{result.command}`: {status}")
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


def top_actions(findings: list[Finding], limit: int = 3) -> list[str]:
    actions: list[str] = []
    domains = bucket_findings(findings)
    if "Secrets & Credentials" in domains:
        actions.append("Rotate exposed credentials, remove real keys from env/build artifacts, and rerun gitleaks plus vibeAuditor.")
    if "Auth & Access Control" in domains:
        actions.append("Verify every write path derives identity from the server/session and blocks cross-user access with tests.")
    if "Data Privacy & RLS" in domains:
        actions.append("Prove RLS-sensitive tables deny direct anon/authenticated access or document SECURITY DEFINER-only access.")
    if "Payments & Webhooks" in domains:
        actions.append("Verify webhook signature validation, replay handling, and idempotency before accepting payment state changes.")
    if "AI / LLM Safety" in domains:
        actions.append("Add prompt-injection tests and allowlist every tool/action the model can trigger.")
    if "Developer Tooling" in domains:
        actions.append("Review local/CI scripts that spawn commands before connecting them to AI-agent workflows.")
    if not actions:
        for finding in findings:
            if len(actions) >= limit:
                break
            action = finding.fix
            if action not in actions:
                actions.append(action)
    return actions[:limit]


def render_bucket_summary(findings: list[Finding]) -> list[str]:
    rows = [["Domain", "Risk", "Findings", "Status"]]
    for row in bucket_summary_rows(findings):
        rows.append([row["domain"], row["risk"], str(row["count"]), row["status"]])
    return render_ascii_table_with_limits(rows, [28, 10, 8, 24])


def bucket_summary_rows(findings: list[Finding]) -> list[dict[str, object]]:
    rows = []
    for domain, domain_findings in bucket_findings(findings).items():
        risk = highest_product_risk(domain_findings)
        rows.append(
            {
                "domain": domain,
                "risk": risk,
                "count": len(domain_findings),
                "status": status_for_risk(risk),
            }
        )
    return rows


def highest_product_risk(findings: list[Finding]) -> str:
    order = {"Blocker": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return max(
        (finding.product_risk or product_risk_for_severity(finding.severity) for finding in findings),
        key=lambda item: order.get(item, 0),
        default="Info",
    )


def status_for_risk(risk: str) -> str:
    return {
        "Blocker": "Needs fix before ship",
        "High": "Needs owner review",
        "Medium": "Needs verification",
        "Low": "Optional hardening",
        "Info": "Informational",
    }.get(risk, "Needs review")


def primary_blocker_reason(findings: list[Finding]) -> str | None:
    for finding in findings:
        if (finding.product_risk or product_risk_for_severity(finding.severity)) == "Blocker":
            if finding.category == "secrets":
                return "Credentials detected in env, source, or build output"
            return finding.title
    return None


def render_bucket_table(findings: list[Finding], use_color: bool) -> list[str]:
    rows = [["Risk", "Conf", "Asset", "Location", "Issue", "Product impact"]]
    for finding in findings:
        data = finding.to_dict()
        rows.append(
            [
                data["product_risk"],
                data["confidence"],
                data["asset_context"],
                location(finding),
                f"{finding.title} ({finding.rule_id})",
                finding.message,
            ]
        )
    table = render_ascii_table_with_limits(rows, [10, 13, 16, 32, 40, 56])
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
    return render_ascii_table_with_limits(rows, widths)


def render_ascii_table_with_limits(rows: list[list[str]], limits: list[int]) -> list[str]:
    widths = [min(max(len(str(row[i])) for row in rows), limits[i]) for i in range(len(limits))]
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


def verification_fence(value: str) -> str:
    shell_hints = ("git ", "gitleaks ", "vibeauditor ", "npm ", "pnpm ", "yarn ", "pytest", "supabase ")
    return "bash" if any(str(value).strip().startswith(hint) or f"; {hint}" in str(value) for hint in shell_hints) else "text"
