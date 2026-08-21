"""Private structured worker used by the persistent background job manager."""

from __future__ import annotations

import json
import os
import sys

import ctfkit.modules  # noqa: F401
from .registry import execute_tool


def main() -> int:
    name = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        arguments = json.loads(sys.stdin.read() or "{}")
        # The job process itself is the killable isolation boundary. Avoid a
        # nested worker so cancelling the process group stops child CLIs too.
        os.environ["CTFKIT_ISOLATE"] = "off"
        result = execute_tool(name, arguments)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    except Exception as ex:
        print(json.dumps({
            "tool": name, "status": "error", "ok": False,
            "text": f"ERROR: {type(ex).__name__}: {ex}", "error": str(ex),
        }, ensure_ascii=False), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
