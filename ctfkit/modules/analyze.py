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


@tool(category="misc")
def recall_knowledge(query: str, limit: int = 5) -> str:
    """Search CTF memory, past writeups, and agent skills for relevant solving techniques, keywords, and flags.
    
    :param query: Search keywords or problem terms (e.g. 'rsa fermat', 'jwt confusion', 'pcap usb')
    :param limit: Maximum number of results to return
    """
    mem_dir = ROOT / "memory"
    skill_dirs = [Path.home() / ".agents" / "skills", Path.home() / ".claude" / "skills"]
    q = query.lower().strip()
    words = [w for w in q.split() if len(w) > 2]
    
    # 1. Search Memory
    mem_hits = []
    if mem_dir.is_dir():
        for f in sorted(mem_dir.glob("*.md"), reverse=True):
            if f.name == "_index.md":
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            s = sum(text.lower().count(w) * 2 for w in words) + text.lower().count(q) * 3
            if s:
                mem_hits.append((s, f, text))
    mem_hits = sorted(mem_hits, key=lambda x: -x[0])[:limit]
    
    # 2. Search Skills
    skill_hits = []
    seen_skills = set()
    for sdir in skill_dirs:
        if not sdir.is_dir():
            continue
        for sf in sdir.glob("*/SKILL.md"):
            if sf.parent.name in seen_skills:
                continue
            stext = sf.read_text(encoding="utf-8", errors="replace")
            s = sum(stext.lower().count(w) * 2 for w in words) + stext.lower().count(q) * 3
            if s:
                seen_skills.add(sf.parent.name)
                skill_hits.append((s, sf, stext))
    skill_hits = sorted(skill_hits, key=lambda x: -x[0])[:limit]
    
    if not mem_hits and not skill_hits:
        return f"No matching memory or skills found for '{query}'."
        
    out = [
        "==================================================",
        f"🧠 RECALLED KNOWLEDGE REPORT for: '{query}'",
        "==================================================",
    ]
    
    if mem_hits:
        out.append(f"📁 Prior Challenge Memories ({len(mem_hits)} matched):")
        for score, f, text in mem_hits:
            lines = text.splitlines()
            title = next((l[2:] for l in lines if l.startswith("# ")), f.stem)
            category = next((l.split(":", 1)[1].strip() for l in lines if l.lstrip("- ").startswith("category:")), "unknown")
            flag = next((l.split(":", 1)[1].strip() for l in lines if l.lstrip("- ").startswith("flag:")), "-")
            tools = next((l.split(":", 1)[1].strip() for l in lines if l.lstrip("- ").startswith("tools:")), "-")
            out.append(f"  • [{category.upper()}] {title} (score: {score})")
            out.append(f"    - File: memory/{f.name}")
            if flag and flag != "-":
                out.append(f"    - Flag: {flag}")
            if tools and tools != "-":
                out.append(f"    - Tools: {tools}")
        out.append("--------------------------------------------------")
        
    if skill_hits:
        out.append(f"🚀 Installed Agent Skills ({len(skill_hits)} matched):")
        for score, sf, stext in skill_hits:
            sname = sf.parent.name
            sdesc = next((l.split(":", 1)[1].strip() for l in stext.splitlines() if l.startswith("description:")), "")
            out.append(f"  • Skill: {sname} (score: {score})")
            if sdesc:
                out.append(f"    - {sdesc[:120]}")
        out.append("--------------------------------------------------")
        
    return "\n".join(out)


@tool(category="misc")
def remember_challenge(
    title: str,
    category: str = "",
    tool: str = "",
    flag: str = "",
    note: str = "",
    platform: str = "",
    status: str = "solved"
) -> str:
    """Save challenge memory, generate/merge reusable AI Agent Skill in ~/.agents/skills/, and scaffold a POC writeup.
    
    :param title: Challenge title (e.g. 'Baby RSA Close Primes')
    :param category: Category ('crypto', 'web', 'stego', 'forensics', 'rev', 'pwn', 'osint', 'misc')
    :param tool: Primary tool(s) used (e.g. 'rsa_fermat' or 'sqli_payloads, http_request')
    :param flag: The captured flag string (e.g. 'flag{...}')
    :param note: Key lesson, vulnerability details, or what worked
    :param platform: CTF platform (e.g. 'picoCTF', 'HackTheBox', 'COMPFEST')
    :param status: Challenge status ('solved' or 'wip')
    """
    from datetime import date
    from ..flagmeta import detect_ctf
    
    auto_platform, auto_category = detect_ctf(f"{title} {note}")
    plat = platform or auto_platform or "unknown"
    cat = category or auto_category or "misc"
    
    mem_dir = ROOT / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    
    def slug(s: str) -> str:
        out = "".join(c if c.isalnum() else "-" for c in s.lower())
        return "-".join(p for p in out.split("-") if p)[:60]
        
    stamp = f"{date.today().isoformat()}_{slug(title)}"
    mem_file = mem_dir / f"{stamp}.md"
    i = 1
    while mem_file.exists():
        mem_file = mem_dir / f"{stamp}_{i}.md"
        i += 1
        
    tools_str = tool.strip()
    tools_list = [t.strip() for t in tools_str.split(",") if t.strip()] if tools_str else []
    
    body = [
        f"# {title}",
        "",
        f"- date: {date.today().isoformat()}",
        f"- status: {status}",
        f"- platform: {plat}",
        f"- category: {cat}",
        f"- tools: {', '.join(tools_list) or '-'}",
        f"- flag: {flag}" if flag else "- flag: -",
        "",
        "## What worked / lessons",
        "",
        note or "_(add lessons here)_",
        "",
    ]
    mem_file.write_text("\n".join(body), encoding="utf-8")
    
    # 1. Update Index
    index_file = mem_dir / "_index.md"
    if index_file.exists():
        lines = index_file.read_text(encoding="utf-8").splitlines()
        insert_idx = 5 if len(lines) >= 5 else len(lines)
        lines.insert(insert_idx, f"- [{status.upper()}] **{title}** — {mem_file.name} — {', '.join(tools_list) or '-'}")
        index_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        index_file.write_text(f"# CTF Memory Index\n\n- [{status.upper()}] **{title}** — {mem_file.name} — {', '.join(tools_list) or '-'}\n", encoding="utf-8")
        
    # 2. Generate / Merge Agent Skill
    skill_paths = []
    if flag:
        skill_slug = slug(tools_list[0] if tools_list else "technique")
        skill_name = f"ctf-{slug(cat)}-{skill_slug}"
        skill_body = f"""---
name: {skill_name}
description: CTF technique (category: {cat}) from a solved {plat} challenge using {', '.join(tools_list) or 'analysis'}. Use when facing {cat} challenges involving {', '.join(tools_list) or 'similar patterns'}.
---

# {title}

## Overview & Context
- **Platform:** {plat}
- **Category:** {cat}
- **Tools:** {', '.join(tools_list) or 'ctfkit tools'}
- **Recovered Flag:** `{flag}`

## What Worked & Actionable Lessons
{note or 'See memory file for details.'}

## Reference Memory
- `memory/{mem_file.name}`
"""
        for base in [Path.home() / ".agents" / "skills", Path.home() / ".claude" / "skills"]:
            target_skill = base / skill_name / "SKILL.md"
            if target_skill.exists():
                # Cumulative learning: append new challenge case study
                existing = target_skill.read_text(encoding="utf-8", errors="replace")
                append_entry = f"\n\n### Additional Case Study: {title} ({date.today().isoformat()})\n- **Platform:** {plat}\n- **Flag:** `{flag}`\n- **Notes:** {note}\n- **Ref:** `memory/{mem_file.name}`\n"
                target_skill.write_text(existing + append_entry, encoding="utf-8")
            else:
                target_skill.parent.mkdir(parents=True, exist_ok=True)
                target_skill.write_text(skill_body, encoding="utf-8")
            skill_paths.append(str(target_skill))
            
    # 3. Generate POC Writeup
    from scripts.writeup import generate_writeup
    wu_file = generate_writeup(mem_file)
    
    report = [
        "==================================================",
        "🧠 CTF MEMORY & AUTONOMOUS SKILL GENERATED",
        "==================================================",
        f"Title        : {title}",
        f"Category     : {cat.upper()} | Platform: {plat}",
        f"Tools Used   : {', '.join(tools_list) or '-'}",
        f"Flag         : {flag or 'N/A'}",
        f"Memory File  : memory/{mem_file.name}",
        f"Index File   : memory/_index.md (Updated)",
        f"POC Writeup  : writeups/{cat}/{wu_file.name}",
    ]
    if skill_paths:
        report.append(f"Agent Skills : {', '.join(skill_paths)}")
    report.append(f"Lessons/Note : {note}")
    report.append("==================================================")
    return "\n".join(report)


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


@tool(category="misc")
def triage_file(path: str) -> str:
    """One-click master triage: auto-detect file type, entropy, strings, embedded files/zlib, format inspection, and extract flags."""
    import os
    import math
    from ..utils import detect_type, printable, MAGIC
    from .forensics import _entropy
    from ..flagmeta import extract_flags
    
    if not os.path.exists(path):
        return f"File not found: {path}"
        
    data = open(path, "rb").read()
    size = len(data)
    filetype = detect_type(data[:64])
    entropy = _entropy(data[:65536]) if data else 0
    
    report = [
        "==================================================",
        f"🎯 CTF AUTO-TRIAGE REPORT: {os.path.basename(path)}",
        "==================================================",
        f"Path         : {path}",
        f"File Size    : {size} bytes ({size/1024:.2f} KB)",
        f"Detected Type: {filetype}",
        f"Entropy      : {entropy:.4f} bits/byte" + (" (High entropy - compressed/encrypted)" if entropy > 7.4 else " (Normal entropy)"),
        f"Header (hex) : {data[:16].hex()}",
        "--------------------------------------------------",
    ]
    
    # 1. Direct Flag Extraction
    text_content = data.decode("latin-1", "ignore")
    flags = extract_flags(text_content)
    if flags:
        report.append(f"🏆 IMMEDIATE FLAG(S) FOUND ({len(flags)}):")
        for f in flags:
            report.append(f"  ⭐ {f}")
        report.append("--------------------------------------------------")
        
    # 2. String Analysis & Keyword Scan
    keywords = ["flag", "pass", "admin", "secret", "ctf", "key", "root", "token"]
    found_kws = []
    for line in text_content.splitlines():
        for kw in keywords:
            if kw in line.lower() and len(line.strip()) < 120:
                found_kws.append(line.strip())
                break
    if found_kws:
        report.append(f"🔍 Interesting Strings / Keyword Matches ({len(found_kws)} found):")
        for kw_line in found_kws[:10]:
            report.append(f"  • {kw_line}")
        if len(found_kws) > 10:
            report.append(f"  ... ({len(found_kws) - 10} more)")
        report.append("--------------------------------------------------")
        
    # 3. Embedded Files & Zlib Streams
    zlib_matches = []
    import zlib
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]|\x1f\x8b\x08", data):
        start = m.start()
        try:
            if data[start] == 0x1f:
                d = zlib.decompress(data[start:], 16 + zlib.MAX_WBITS)
            else:
                d = zlib.decompress(data[start:])
            zlib_matches.append((start, len(d), printable(d, 80)))
        except Exception:
            pass
    if zlib_matches:
        report.append(f"📦 Embedded Zlib/Gzip Streams ({len(zlib_matches)}):")
        for st, l, prev in zlib_matches[:5]:
            report.append(f"  • @0x{st:x} ({l} bytes uncompressed) -> {prev}")
        report.append("--------------------------------------------------")
        
    # 4. Format-Specific Checks
    if data.startswith(b"\x7fELF"):
        from .rev_pwn import elf_info, checksec
        report.append("⚙️ ELF Binary Inspection:")
        report.append(checksec(path))
        report.append("--------------------------------------------------")
    elif data.startswith(b"MZ"):
        from .rev_pwn import pe_info
        report.append("🪟 Windows PE Inspection:")
        report.append(pe_info(path))
        report.append("--------------------------------------------------")
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        from .stego import png_fix_ihdr, stego_png_chunks
        report.append("🖼️ PNG Image Inspection:")
        report.append(png_fix_ihdr(path))
        report.append("--------------------------------------------------")
    elif data.startswith(b"PK\x03\x04"):
        from .forensics import zip_fix_pseudo_encrypt
        report.append("🗜️ ZIP Archive Inspection:")
        report.append(zip_fix_pseudo_encrypt(path))
        report.append("--------------------------------------------------")
    elif data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\x0a\x0d\x0d\x0a"):
        from .forensics import pcap_http
        report.append("🌐 PCAP Network Capture Inspection:")
        report.append(pcap_http(path, max_flows=5))
        report.append("--------------------------------------------------")
        
    report.append("💡 Recommended Next Steps: Use Suggested Tools from detect_challenge or run specific modules.")
    return "\n".join(report)


if __name__ == "__main__":
    print(detect_challenge("picoCTF web challenge: sql injection bypass on login page"))