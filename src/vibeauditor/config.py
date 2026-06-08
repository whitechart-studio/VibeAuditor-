from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding


CONFIG_NAMES = (".vibeauditor.toml", "vibeauditor.toml")


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str = ""
    expires: str = ""


@dataclass
class Config:
    suppressions: list[Suppression] = field(default_factory=list)


def load_config(root: Path) -> Config:
    for name in CONFIG_NAMES:
        path = root / name
        if path.exists():
            return parse_config(path)
    return Config()


def parse_config(path: Path) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return Config()

    suppressions = []
    for item in data.get("suppress", []):
        fingerprint = str(item.get("fingerprint", "")).strip()
        if not fingerprint:
            continue
        suppressions.append(
            Suppression(
                fingerprint=fingerprint,
                reason=str(item.get("reason", "")).strip(),
                expires=str(item.get("expires", "")).strip(),
            )
        )
    return Config(suppressions=suppressions)


def apply_suppressions(findings: list[Finding], config: Config) -> list[Finding]:
    suppressed = {item.fingerprint for item in config.suppressions}
    if not suppressed:
        return findings
    return [finding for finding in findings if finding.fingerprint not in suppressed]
