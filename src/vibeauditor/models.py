from __future__ import annotations

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "fix": self.fix,
            "category": self.category,
            "evidence": self.evidence,
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
