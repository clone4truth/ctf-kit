"""Build a standalone onefile exe with PyInstaller (API server + MCP server).
Usage:  python scripts/build.py            -> builds both servers
        python scripts/build.py mcp        -> MCP server only
        python scripts/build.py api        -> API server only
Requires: pip install pyinstaller
Output: dist/ctfkit_api[.exe], dist/ctfkit_mcp[.exe]
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(target: str, name: str):
    suffix = ".exe" if sys.platform == "win32" else ""
    out = ROOT / "dist" / f"{name}{suffix}"
    if importlib.util.find_spec("PyInstaller") is None:
        print("ERROR: pyinstaller not installed in this Python environment. "
              "Install requirements-dev.txt first.")
        sys.exit(1)
    sep = ";" if sys.platform == "win32" else ":"
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--clean", "--name", name,
        "--add-data", f"{ROOT / 'ctfkit' / 'flagformats.json'}{sep}ctfkit",
        str(ROOT / target),
    ], cwd=ROOT, check=True)
    print(f"OK: {out}")


def main():
    args = sys.argv[1:] or ["all"]
    if "mcp" in args:
        build("mcp_server.py", "ctfkit_mcp")
    if "api" in args:
        build("server.py", "ctfkit_api")
    if "all" in args:
        build("mcp_server.py", "ctfkit_mcp")
        build("server.py", "ctfkit_api")


if __name__ == "__main__":
    main()
