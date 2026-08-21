"""Agent installer preserves unrelated configuration and remains idempotent."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.install_agents import _merge_mcp


def test_merge_mcp_updates_transport_without_overwriting_other_servers(tmp_path: Path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps({
        "theme": "dark",
        "mcpServers": {
            "unrelated": {"command": "keep-me"},
            "ctf-tools": {
                "command": "old-python", "args": ["old-server.py"],
                "env": {"USER_SETTING": "preserved"},
            },
        },
    }), encoding="utf-8")
    desired = {
        "command": "/venv/python",
        "args": ["/repo/mcp_server.py", "--server", "http://127.0.0.1:8765"],
        "env": {"CTFKIT_MCP_PROFILE": "simple", "PYTHONUNBUFFERED": "1"},
    }

    assert _merge_mcp(config_path, "mcpServers", desired) == "updated to central-backend profile"
    updated = json.loads(config_path.read_text(encoding="utf-8"))
    assert updated["theme"] == "dark"
    assert updated["mcpServers"]["unrelated"] == {"command": "keep-me"}
    ctf = updated["mcpServers"]["ctf-tools"]
    assert ctf["command"] == desired["command"]
    assert ctf["args"] == desired["args"]
    assert ctf["env"]["USER_SETTING"] == "preserved"
    assert ctf["env"]["CTFKIT_MCP_PROFILE"] == "simple"
    assert _merge_mcp(config_path, "mcpServers", desired) == "already configured"


def test_merge_mcp_skips_missing_config(tmp_path: Path):
    assert _merge_mcp(tmp_path / "missing.json", "mcpServers", {}) == "not found (skipped)"
