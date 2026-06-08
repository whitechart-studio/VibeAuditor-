from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .external import check_available_scanners, run_external_scanners
from .files import build_context
from .models import SEVERITY_ORDER
from .profiles import get_profile, profile_names
from .report import render_text, write_json, write_markdown
from .rules import run_builtin_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vibeauditor",
        description="Audit AI-built apps before they ship.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory to scan.")
    parser.add_argument(
        "--profile",
        choices=profile_names(),
        default="default",
        help="Audit profile to apply. Profiles tune report context now and will select rule packs as they grow.",
    )
    parser.add_argument("--json", dest="json_path", help="Write machine-readable JSON report to this path.")
    parser.add_argument("--markdown", dest="markdown_path", help="Write a bucketed Markdown report to this path.")
    parser.add_argument(
        "--external",
        action="store_true",
        help="Run supported external scanners if installed. Without this, only availability is shown.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 2 if findings at this severity or above exist.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text output.")
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    context = build_context(root)
    profile = get_profile(args.profile)
    findings = run_builtin_rules(context)
    external = run_external_scanners(root) if args.external else check_available_scanners()

    print(render_text(findings, external, use_color=not args.no_color, profile=profile))

    if args.json_path:
        write_json(Path(args.json_path), findings, external, profile=profile)
    if args.markdown_path:
        write_markdown(Path(args.markdown_path), findings, external, profile=profile)

    if args.fail_on and should_fail(findings, args.fail_on):
        return 2
    return 0


def should_fail(findings, threshold: str) -> bool:
    minimum = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= minimum for finding in findings)
