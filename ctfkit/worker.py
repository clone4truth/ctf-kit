"""Private stdin/stdout protocol for isolated CTF Kit tool execution."""

from __future__ import annotations

import json
import sys

import ctfkit.modules  # noqa: F401
from .registry import TOOLS


def main() -> int:
    name = sys.argv[1] if len(sys.argv) == 2 else ""
    meta = TOOLS.get(name)
    if meta is None:
        print(json.dumps({"error": f"unknown tool: {name}"}))
        return 2
    try:
        args = json.loads(sys.stdin.read() or "{}")
        result = meta["fn"](**args)
        print(json.dumps({"text": result if isinstance(result, str) else str(result)}))
        return 0
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
