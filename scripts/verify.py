#!/usr/bin/env python3
"""Run the complete deterministic CTF Kit verification flow.

The standalone build is optional because it is slower and requires the
development dependencies: ``python scripts/verify.py --build``.
"""
from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _run(label: str, command: list[str]) -> bool:
    started = time.perf_counter()
    print(f"\n==> {label}\n    {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    elapsed = time.perf_counter() - started
    state = "PASS" if result.returncode == 0 else "FAIL"
    print(f"<== {state} {label} ({elapsed:.2f}s)", flush=True)
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="also build the API and MCP executables")
    args = parser.parse_args()
    python = sys.executable
    checks = [
        ("Compile", [python, "-m", "compileall", "-q", "ctfkit", "server.py", "mcp_server.py", "scripts", "tests"]),
        ("Pytest", [python, "-m", "pytest", "-q"]),
        ("Smoke scenarios", [python, "tests/test_smoke.py"]),
        ("MCP handshake", [python, "tests/test_mcp.py"]),
        ("Core evaluation", [python, "scripts/eval_core.py"]),
        ("Advanced release gate", [python, "scripts/eval_advanced.py"]),
    ]
    if importlib.util.find_spec("pyright") is not None:
        checks.insert(1, ("Static analysis", [python, "-m", "pyright"]))
    if args.build:
        checks.append(("Standalone builds", [python, "scripts/build.py"]))

    failed = [label for label, command in checks if not _run(label, command)]
    print("\nVerification summary")
    print(f"  passed: {len(checks) - len(failed)}/{len(checks)}")
    if failed:
        print(f"  failed: {', '.join(failed)}")
        return 1
    print("  status: release checks are green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
