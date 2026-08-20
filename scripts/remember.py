"""Remember: manually save a challenge memory (for providers without the auto plugin).

Usage:
    python scripts/remember.py --title "XOR login bypass" --tool xor_brute --flag "flag{abc}" \
        --note "key=0x7e, single-byte xor over base64 blob"
"""

import argparse
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MEM_DIR = ROOT / "memory"

from ctfkit.flagmeta import detect_ctf  # noqa: E402


def slug(s: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in s.lower())
    return "-".join(p for p in out.split("-") if p)[:60]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--title", required=True, help="challenge title")
    ap.add_argument("--tool", action="append", default=[], help="tool(s) used (repeatable)")
    ap.add_argument("--flag", default="", help="recovered flag, if any")
    ap.add_argument("--note", default="", help="what worked / lesson")
    ap.add_argument("--status", default="solved", choices=["solved", "wip"])
    ap.add_argument("--platform", default="", help="platform (auto-detected from title+note if empty)")
    ap.add_argument("--category", default="", help="category (auto-detected if empty)")
    ap.add_argument("--no-skill", action="store_true", help="skip skill generation")
    ap.add_argument("--problem", default="", help="challenge problem description/statement")
    ap.add_argument("--commands", default="", help="actual terminal commands used (newline-separated)")
    ap.add_argument("--evidence", default="", help="captured output proving the recovered flag")
    args = ap.parse_args()

    auto_platform, auto_category = detect_ctf(f"{args.title} {args.note}")
    platform = args.platform or auto_platform or "unknown"
    category = args.category or auto_category or "unknown"

    MEM_DIR.mkdir(parents=True, exist_ok=True)
    stamp = f"{date.today().isoformat()}_{slug(args.title)}"
    file = MEM_DIR / f"{stamp}.md"
    i = 1
    while file.exists():
        file = MEM_DIR / f"{stamp}_{i}.md"
        i += 1

    body = [
        f"# {args.title}",
        "",
        f"- date: {date.today().isoformat()}",
        f"- status: {args.status}",
        f"- platform: {platform}",
        f"- category: {category}",
        f"- tools: {', '.join(args.tool) or '-'}",
        f"- flag: {args.flag}" if args.flag else "- flag: -",
        "- provenance: manual",
        f"- iterations: 1",
        f"- tools_failed: -",
        "",
    ]
    if args.problem:
        body += [
            "## Problem Description",
            "",
            args.problem,
            "",
        ]
    body += [
        "## What worked / lessons",
        "",
        args.note or "_(add lessons here)_",
        "",
    ]
    if args.commands:
        body += [
            "## Commands / Terminal",
            "",
            "```bash",
            args.commands,
            "```",
            "",
        ]
    file.write_text("\n".join(body), encoding="utf-8")
    print(f"Saved: {file}")

    index = MEM_DIR / "_index.md"
    if index.exists():
        lines = index.read_text(encoding="utf-8").splitlines()
        lines.insert(5, f"- [{args.status.upper()}] **{args.title}** — {file.name} — {', '.join(args.tool) or '-'}")
        index.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("Index updated.")

    if args.flag and not args.no_skill:
        import re
        from pathlib import Path as P
        skill_name = f"ctf-{slug(category)}-{slug(args.tool[0] if args.tool else 'challenge')}"
        skill_body = f"""---
name: {skill_name}
description: CTF technique (category: {category}) from a solved {platform} challenge using {', '.join(args.tool) or 'analysis'}. Use when a challenge involves {', '.join(args.tool) or 'similar'} analysis.
---

# {args.title}

## What worked

{args.note or 'See memory file for details.'}

Full details: `memory/{file.name}`
"""
        for base in [P.home() / ".agents" / "skills", P.home() / ".claude" / "skills"]:
            target = base / skill_name / "SKILL.md"
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(skill_body, encoding="utf-8")
            print(f"Skill: {target}")

    from scripts.writeup import generate_writeup
    wu = generate_writeup(file)
    print(f"Writeup: {wu}")

    try:
        from ctfkit.modules.self_improve import self_improve_after_solve
        self_improve_after_solve(
            title=args.title,
            category=category,
            tools_used=args.tool,
            flag=args.flag,
            note=args.note,
            problem=args.problem
            ,commands=args.commands
            ,evidence=args.evidence
            ,source="manual"
        )
        print("Self-improvement state updated.")
    except Exception as ex:
        print(f"Self-improvement trigger skipped: {ex}")


if __name__ == "__main__":
    sys.exit(main())
