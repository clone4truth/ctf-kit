"""Recall: search CTF memory + skills for relevant context before starting a challenge.

Usage:
    python scripts/recall.py "xor"              # keyword search
    python scripts/recall.py --all              # everything
    python scripts/recall.py --skill xor        # search skills only
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEM_DIR = ROOT / "memory"
SKILL_DIRS = [
    Path.home() / ".agents" / "skills",
    Path.home() / ".claude" / "skills",
]


def score(text: str, query: str) -> int:
    q = query.lower()
    words = [w for w in q.split() if len(w) > 2]
    score = 0
    for w in words:
        score += text.lower().count(w) * 2
    score += text.lower().count(q) * 3
    return score


def search_memory(query: str) -> list[tuple[int, Path]]:
    out = []
    if not MEM_DIR.is_dir():
        return out
    for f in sorted(MEM_DIR.glob("*.md"), reverse=True):
        if f.name == "_index.md":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        s = score(text, query)
        if s:
            out.append((s, f))
    return sorted(out, key=lambda x: -x[0])


def search_skills(query: str) -> list[tuple[int, Path]]:
    out = []
    for base in SKILL_DIRS:
        if not base.is_dir():
            continue
        for f in base.glob("*/SKILL.md"):
            text = f.read_text(encoding="utf-8", errors="replace")
            s = score(text, query)
            if s:
                out.append((s, f))
    return sorted(out, key=lambda x: -x[0])


def field(head: list[str], key: str) -> str:
    for l in head:
        if l.lstrip("- ").startswith(key):
            return l.split(":", 1)[1].strip()
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("query", nargs="?", default="", help="problem keywords (e.g. 'vigenere image lsb')")
    ap.add_argument("--all", action="store_true", help="show everything")
    ap.add_argument("--skill", action="store_true", help="search skills only")
    ap.add_argument("--limit", type=int, default=5)
    args = ap.parse_args()

    query = args.query.strip()
    if not query and not args.all:
        ap.print_help()
        sys.exit(1)

    if not args.skill:
        hits = search_memory(query) if not args.all else [(1, f) for f in sorted((MEM_DIR).glob("*.md"), reverse=True) if f.name != "_index.md"]
        if hits:
            print(f"== MEMORY ({len(hits)} hit{'s' if len(hits) != 1 else ''}) ==")
            for s, f in hits[: args.limit]:
                head = f.read_text(encoding="utf-8", errors="replace").splitlines()
                title = next((l[2:] for l in head if l.startswith("# ")), f.stem)
                status = field(head, "status:") or "?"
                tools = field(head, "tools:")
                flag = field(head, "flag:")
                print(f"  [{status}] {title} — {f.name}" + (f" — flag: {flag}" if flag and flag != "-" else "") + (f" — tools: {tools}" if tools and tools != "-" else ""))
        else:
            print("No memory entries match. (Nothing saved yet, or different keywords.)")

    if not args.skill:
        print()

    if not args.skill:
        skills = search_skills(query) if not args.all else [(1, f) for base in SKILL_DIRS if base.is_dir() for f in base.glob("*/SKILL.md")]
        seen = set()
        skills = [h for h in skills if not (h[1].parent.name in seen or seen.add(h[1].parent.name))]
        if skills:
            print(f"== SKILLS ({len(skills)} hit{'s' if len(skills) != 1 else ''}) ==")
            for s, f in skills[: args.limit]:
                name = f.parent.name
                desc = next((l.split(":", 1)[1].strip() for l in f.read_text(encoding="utf-8", errors="replace").splitlines() if l.startswith("description:")), "")
                print(f"  {name}: {desc[:100]}")
        else:
            print("No matching skills yet.")


if __name__ == "__main__":
    main()