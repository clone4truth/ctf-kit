"""Subprocess isolation for tool functions that must be forcibly stoppable."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


_NEVER_ISOLATE = {
    "autonomous_solve", "chain_tools", "chain_tools_sequential",
    "remember_challenge", "reset_agent_memory", "scaffold_new_tool",
}


def should_isolate(name: str, meta: dict) -> bool:
    """Return whether this invocation belongs in a killable worker process."""
    if os.environ.get("CTFKIT_WORKER") == "1" or name in _NEVER_ISOLATE:
        return False
    mode = os.environ.get("CTFKIT_ISOLATE", "risky").strip().lower()
    if mode in {"0", "false", "off", "none"}:
        return False
    if mode == "all":
        return bool(meta.get("read_only", True))
    return bool(meta.get("open_world") or meta.get("destructive"))


def run_isolated(name: str, args: dict, timeout: float) -> str:
    """Execute a registered function in a child and return its raw text output."""
    env = os.environ.copy()
    env["CTFKIT_WORKER"] = "1"
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, "-m", "ctfkit.worker", name],
        input=json.dumps(args, ensure_ascii=False),
        text=True,
        capture_output=True,
        cwd=root,
        env=env,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip()[-1000:] or f"worker exited {proc.returncode}"
        raise RuntimeError(detail)
    payload = json.loads(proc.stdout)
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    return str(payload.get("text", ""))
