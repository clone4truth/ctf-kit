"""Auto-install CTF Kit integration into ALL agent CLI config folders.

Installs idempotently (safe to run on every MCP server start):

   1. ctf-memory.js plugin        -> ~/.config/opencode/plugins/ctf-memory.js
      + registered in ~/.config/opencode/opencode.json (mcp + plugin array)
   2. 'ctf-tools' MCP server       -> registered in every agent CLI config found:
      - Claude Code   ~/.claude.json                       (mcpServers)
      - Cursor        ~/.cursor/mcp.json                   (mcpServers)
      - Gemini CLI    ~/.gemini/settings.json              (mcpServers)
      - Windsurf      ~/.codeium/windsurf/mcp_config.json  (mcpServers)
      - opencode      ~/.config/opencode/opencode.json     (mcp)
   3. bundled skills (skills/*/SKILL.md) -> ~/.agents/skills/ and ~/.claude/skills/
      (opencode + Claude Code auto-load them by description; AI & LLM Security
      skill activates whenever an LLM-security task appears)

Existing entries in every target config are preserved; missing configs are skipped.

Usage: python scripts/install_agents.py
"""

import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OPENCODE_DIR = Path.home() / ".config" / "opencode"
PLUGIN_SRC = REPO / "plugins" / "ctf-memory.js"
PLUGIN_DST = OPENCODE_DIR / "plugins" / "ctf-memory.js"
PLUGIN_REF = "./plugins/ctf-memory.js"

SKILLS_SRC = REPO / "skills"
SKILL_DST_DIRS = [Path.home() / ".agents" / "skills", Path.home() / ".claude" / "skills"]

_VENV_PY = REPO / (".venv/Scripts/python.exe" if sys.platform == "win32" else ".venv/bin/python")
PY = str(_VENV_PY if _VENV_PY.exists() else sys.executable)
MCP_PY = str(REPO / "mcp_server.py")
SERVER_URL = os.environ.get("CTFKIT_SERVER_URL", "http://127.0.0.1:8765")
MCP_ARGS = [MCP_PY, "--server", SERVER_URL]

# (label, config path, key, server entry)
TARGETS = [
    ("opencode", OPENCODE_DIR / "opencode.json", "mcp",
     {"type": "local", "command": [PY, *MCP_ARGS], "enabled": True,
      "environment": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"}}),
    ("claude code", Path.home() / ".claude.json", "mcpServers",
     {"command": PY, "args": MCP_ARGS, "env": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"}}),
    ("cursor", Path.home() / ".cursor" / "mcp.json", "mcpServers",
     {"command": PY, "args": MCP_ARGS, "env": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"}}),
    ("gemini cli", Path.home() / ".gemini" / "settings.json", "mcpServers",
     {"command": PY, "args": MCP_ARGS, "env": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"}}),
    ("windsurf", Path.home() / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers",
     {"command": PY, "args": MCP_ARGS, "env": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"}}),
]

SERVER_NAME = "ctf-tools"


def _merge_mcp(path: Path, key: str, entry: dict) -> str:
    """Merge the ctf-tools entry under `key` in the JSON config (idempotent)."""
    if not path.exists():
        return "not found (skipped)"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    servers = cfg.setdefault(key, {})
    if SERVER_NAME in servers:
        current = servers[SERVER_NAME]
        changed = False
        for name in ("type", "command", "args", "enabled"):
            if name in entry and current.get(name) != entry[name]:
                current[name] = entry[name]
                changed = True
        env_key = "environment" if "environment" in entry else "env"
        desired_env = entry.get(env_key, {})
        current_env = current.setdefault(env_key, {})
        if not all(current_env.get(name) == value for name, value in desired_env.items()):
            current_env.update(desired_env)
            changed = True
        if not changed:
            return "already configured"
        path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        return "updated to central-backend profile"
    servers[SERVER_NAME] = entry
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return "registered"


def _install_skills() -> list[str]:
    """Copy bundled skills (skills/*/SKILL.md) into every agent skill dir (idempotent)."""
    report = []
    for skill_dir in sorted(SKILLS_SRC.glob("*/")):
        if not (skill_dir / "SKILL.md").exists():
            continue
        for dst_root in SKILL_DST_DIRS:
            dst = dst_root / skill_dir.name / "SKILL.md"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(skill_dir / "SKILL.md", dst)
            report.append(f"[skills] {skill_dir.name} -> {dst}")
    return report


def install() -> list[str]:
    report = []
    if OPENCODE_DIR.is_dir():
        PLUGIN_DST.parent.mkdir(parents=True, exist_ok=True)
        if PLUGIN_SRC.exists():
            shutil.copy2(PLUGIN_SRC, PLUGIN_DST)
            report.append(f"[opencode] plugin installed -> {PLUGIN_DST}")
    report.extend(_install_skills())
    for label, path, key, entry in TARGETS:
        report.append(f"[{label}] {SERVER_NAME}: {_merge_mcp(path, key, entry)} ({path})")
    return report


if __name__ == "__main__":
    for line in install():
        print(line)
