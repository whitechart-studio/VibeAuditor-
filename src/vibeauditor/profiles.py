from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    focus: tuple[str, ...]


PROFILES = {
    "default": Profile(
        name="default",
        description="General AI-built app audit.",
        focus=("secrets", "auth", "dependencies", "ai", "payments"),
    ),
    "next-supabase": Profile(
        name="next-supabase",
        description="Next.js and Supabase pre-ship checks.",
        focus=("supabase", "auth", "secrets", "dependencies"),
    ),
    "ai-agent": Profile(
        name="ai-agent",
        description="LLM app, agent, and tool-calling checks.",
        focus=("ai", "code-execution", "secrets"),
    ),
    "stripe-saas": Profile(
        name="stripe-saas",
        description="SaaS payment and webhook checks.",
        focus=("payments", "auth", "secrets"),
    ),
    "mcp-server": Profile(
        name="mcp-server",
        description="MCP server boundary and tool-safety checks.",
        focus=("ai", "code-execution", "auth", "secrets"),
    ),
}


def profile_names() -> list[str]:
    return sorted(PROFILES)


def get_profile(name: str) -> Profile:
    return PROFILES[name]
