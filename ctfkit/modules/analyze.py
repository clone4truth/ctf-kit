"""Challenge analysis: detect platform/category, suggest tools, recall memory, extract flags.

The agent MUST run detect_challenge (or scripts/plan.py) BEFORE solving —
it produces the plan: category, platform, suggested tools, prior memory.
"""

import re
from pathlib import Path

from ..flagmeta import detect_ctf, detect_flag, extract_flags, suggested_tools
from ..registry import tool

ROOT = Path(__file__).resolve().parent.parent.parent


@tool(category="misc")
def detect_challenge(problem: str) -> str:
    """Analyze a CTF problem statement: detect category + platform, suggest tools, recall prior memory. Run BEFORE solving."""
    platform, category = detect_ctf(problem)
    hits = _recall(problem, limit=3)
    lines = [
        f"CATEGORY: {category or 'unknown'}",
        f"PLATFORM: {platform or 'unknown'}",
        "SUGGESTED TOOLS: " + (", ".join(suggested_tools(category)) if category else "run file_type/strings_extract/hexdump first, then decode_all"),
        "PLAN:",
        f"  1. Recall: python scripts/recall.py \"{problem[:60]}\"",
        f"  2. Inspect input (file_type / hexdump / strings_extract) -> confirm {category or 'the'} category",
        f"  3. Apply suggested tools above; try known techniques from memory",
        "  4. Extract the flag (any format) and verify it matches the expected pattern",
    ]
    if hits:
        lines.append("MEMORY (prior challenges):")
        lines.extend(f"  - [{s}] {t}" for s, t in hits)
    return "\n".join(lines)


@tool(category="misc")
def extract_flags_tool(text: str) -> str:
    """Extract ALL flag candidates from any text, any format (flag{...}, picoCTF{...}, HTB{...}, flag: xxx, hex digests...)."""
    flags = extract_flags(text)
    if not flags:
        return "No flag-like strings found."
    return f"{len(flags)} candidate(s):\n" + "\n".join(f"  {f}" for f in flags)


def _recall(query: str, limit: int = 3) -> list[tuple[int, str]]:
    """Score memory files against the query (mirror of scripts/recall.py)."""
    mem_dir = ROOT / "memory"
    if not mem_dir.is_dir():
        return []
    q = query.lower()
    words = [w for w in q.split() if len(w) > 2]
    out = []
    for f in sorted(mem_dir.glob("*.md"), reverse=True):
        if f.name == "_index.md":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        score = sum(text.lower().count(w) * 2 for w in words) + text.lower().count(q) * 3
        if score:
            title = next((l[2:] for l in text.splitlines() if l.startswith("# ")), f.stem)
            out.append((score, f"{title} ({f.name})"))
    return sorted(out, key=lambda x: -x[0])[:limit]


if __name__ == "__main__":
    print(detect_challenge("picoCTF web challenge: sql injection bypass on login page"))