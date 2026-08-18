"""Plan: analyze a CTF problem BEFORE solving (for agents/providers without the MCP tool).

Usage:
    python scripts/plan.py "picoCTF web challenge: sql injection on the login page"
    python scripts/plan.py --file problem.txt
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfkit.modules.analyze import detect_challenge  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("text", nargs="?", default="", help="problem statement or keywords")
    ap.add_argument("--file", default="", help="read problem statement from a file")
    args = ap.parse_args()
    text = (Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file else args.text).strip()
    if not text:
        ap.print_help()
        sys.exit(1)
    print(detect_challenge(text))


if __name__ == "__main__":
    main()