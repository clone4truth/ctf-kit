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

Existing entries in every target config are preserved; missing configs are skipped.

Usage: python scripts/install_agents.py
"""

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OPENCODE_DIR = Path.home() / ".config" / "opencode"
PLUGIN_SRC = REPO / "plugins" / "ctf-memory.js"
PLUGIN_DST = OPENCODE_DIR / "plugins" / "ctf-memory.js"
PLUGIN_REF = "./plugins/ctf-memory.js"

_VENV_PY = REPO / (".venv/Scripts/python.exe" if sys.platform == "win32" else ".venv/bin/python")
PY = str(_VENV_PY if _VENV_PY.exists() else sys.executable)
MCP_PY = str(REPO / "mcp_server.py")

# (label, config path, key, server entry)
TARGETS = [
    ("opencode", OPENCODE_DIR / "opencode.json", "mcp",
     {"type": "local", "command": [PY, MCP_PY], "enabled": True, "environment": {}}),
    ("claude code", Path.home() / ".claude.json", "mcpServers",
     {"command": PY, "args": [MCP_PY], "env": {}}),
    ("cursor", Path.home() / ".cursor" / "mcp.json", "mcpServers",
     {"command": PY, "args": [MCP_PY], "env": {}}),
    ("gemini cli", Path.home() / ".gemini" / "settings.json", "mcpServers",
     {"command": PY, "args": [MCP_PY], "env": {}}),
    ("windsurf", Path.home() / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers",
     {"command": PY, "args": [MCP_PY], "env": {}}),
]

SERVER_NAME = "ctf-tools"


def _merge_mcp(path: Path, key: str, entry: dict) -> str:
    """Merge the ctf-tools entry under `key` in the JSON config (idempotent)."""
    if not path.exists():
        return "not found (skipped)"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    servers = cfg.setdefault(key, {})
    if SERVER_NAME in servers:
        return "already configured"
    servers[SERVER_NAME] = entry
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return "registered"


def install() -> list[str]:
    report = []
    if OPENCODE_DIR.is_dir():
        PLUGIN_DST.parent.mkdir(parents=True, exist_ok=True)
        if PLUGIN_SRC.exists():
            shutil.copy2(PLUGIN_SRC, PLUGIN_DST)
            report.append(f"[opencode] plugin installed -> {PLUGIN_DST}")
    for label, path, key, entry in TARGETS:
        report.append(f"[{label}] {SERVER_NAME}: {_merge_mcp(path, key, entry)} ({path})")
    return report


if __name__ == "__main__":
    for line in install():
        print(line)