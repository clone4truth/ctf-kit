"""Conservative capability metadata and runtime policy for agent tool use."""

from __future__ import annotations

import os


STATEFUL = {
    "remember_challenge", "reset_agent_memory", "scaffold_new_tool",
    "browser_agent", "chain_tools", "chain_tools_sequential", "autonomous_solve",
}
DESTRUCTIVE = {"reset_agent_memory", "scaffold_new_tool"}
OPEN_WORLD_PREFIXES = ("external_",)
OPEN_WORLD = {
    "http_request", "browser_agent", "github_search", "whois_query",
    "dns_query", "dns_reverse", "crtsh_subdomains", "cve_lookup", "cve_search",
    "cve_research",
}


def metadata_for(name: str) -> dict:
    open_world = name in OPEN_WORLD or name.startswith(OPEN_WORLD_PREFIXES)
    destructive = name in DESTRUCTIVE
    read_only = name not in STATEFUL and not destructive
    return {
        "read_only": read_only,
        "destructive": destructive,
        "idempotent": read_only,
        "open_world": open_world,
        "safety_level": "admin" if destructive else ("lab" if open_world or not read_only else "passive"),
    }


def permits(required: str) -> bool:
    """Choose policy automatically; an optional env override can only restrict it."""
    levels = {"passive": 0, "lab": 1, "admin": 2}
    configured = os.environ.get("CTFKIT_SAFETY_MODE", "auto").lower()
    if configured == "auto":
        return True
    return levels.get(configured, 0) >= levels.get(required, 0)
