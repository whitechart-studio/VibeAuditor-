from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .models import ExternalResult


SCANNERS = [
    ("trivy", ["trivy", "fs", "--quiet", "."]),
    ("semgrep", ["semgrep", "scan", "--config", "auto", "--quiet", "."]),
    ("osv-scanner", ["osv-scanner", "scan", "source", "."]),
    ("gitleaks", ["gitleaks", "detect", "--source", ".", "--no-banner"]),
    ("syft", ["syft", ".", "-q"]),
    ("grype", ["grype", ".", "-q"]),
]


def check_available_scanners() -> list[ExternalResult]:
    results: list[ExternalResult] = []
    for name, command in SCANNERS:
        results.append(
            ExternalResult(
                command=" ".join(command),
                available=shutil.which(name) is not None,
                summary="available" if shutil.which(name) else "not installed",
            )
        )
    return results


def run_external_scanners(root: Path, timeout_seconds: int = 120) -> list[ExternalResult]:
    results: list[ExternalResult] = []
    for name, command in SCANNERS:
        if shutil.which(name) is None:
            results.append(ExternalResult(command=" ".join(command), available=False, summary="not installed"))
            continue
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
            output = (completed.stdout + "\n" + completed.stderr).strip()
            results.append(
                ExternalResult(
                    command=" ".join(command),
                    available=True,
                    exit_code=completed.returncode,
                    summary=summarize_output(output),
                )
            )
        except subprocess.TimeoutExpired:
            results.append(
                ExternalResult(
                    command=" ".join(command),
                    available=True,
                    exit_code=None,
                    summary=f"timed out after {timeout_seconds}s",
                )
            )
    return results


def summarize_output(output: str, max_lines: int = 10) -> str:
    if not output:
        return "no output"
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    return "\n".join(lines[:max_lines])
