from __future__ import annotations

from pathlib import Path

from .models import ScanContext


DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".wrangler",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
}

TEXT_EXTENSIONS = {
    ".c",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".env",
    ".go",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".php",
    ".prisma",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".svelte",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

SPECIAL_TEXT_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
    "Dockerfile",
    "docker-compose.yml",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
}


def build_context(root: Path) -> ScanContext:
    context = ScanContext(root=root.resolve())
    for path in context.root.rglob("*"):
        if path.is_dir():
            continue
        relative_parts = path.relative_to(context.root).parts
        skipped = set(relative_parts).intersection(DEFAULT_SKIP_DIRS)
        if skipped:
            context.skipped_dirs.update(skipped)
            continue
        if is_probably_text(path):
            context.files.append(path)
    return context


def is_probably_text(path: Path) -> bool:
    return path.name in SPECIAL_TEXT_NAMES or path.suffix.lower() in TEXT_EXTENSIONS


def safe_read(path: Path, max_bytes: int = 512_000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
