#!/usr/bin/env python3
"""Rebuild learning-state v2 from challenge memories with provenance checks."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ctfkit.modules  # noqa: F401,E402
from ctfkit.modules.self_improve import (  # noqa: E402
    _empty_state, _save_state, archive_legacy_state, self_improve_after_solve,
)


def field(text: str, name: str, default: str = "") -> str:
    match = re.search(rf"^- {re.escape(name)}:\s*(.*)$", text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else default


def section(text: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\s*$\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def main() -> int:
    backup = archive_legacy_state()
    _save_state(_empty_state())
    counts = {"learned": 0, "fixture": 0, "rejected": 0}

    for path in sorted((ROOT / "memory").glob("*.md")):
        if path.name == "_index.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        title_match = re.search(r"^# (.+)$", text, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else path.stem
        category = field(text, "category", "misc").lower()
        tools = [x.strip() for x in field(text, "tools").split(",") if x.strip() and x.strip() != "-"]
        flag = field(text, "flag")
        platform = field(text, "platform", "unknown")
        problem = section(text, "Problem Description") or title
        commands = section(text, "Commands / Terminal")
        note = section(text, "What worked / lessons") or section(text, "Approach")

        fixture = ("testdata/" in text.lower() or title.lower().startswith("agent:")) and platform.lower() == "unknown"
        source = "fixture" if fixture else "imported"
        result = self_improve_after_solve(
            title=title, category=category, tools_used=tools, flag=flag,
            note=note, problem=problem, commands=commands,
            evidence=text[:12000], source=source,
            challenge_id=f"memory:{path.stem}",
        )
        bucket = "learned" if result["learned"] else ("fixture" if "fixture" in result["reason"] else "rejected")
        counts[bucket] += 1
        print(f"{bucket.upper():8} {path.name}: {result['reason']}")

    print(f"Rebuilt learning v2: {counts}")
    if backup:
        print(f"Legacy state archived: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
