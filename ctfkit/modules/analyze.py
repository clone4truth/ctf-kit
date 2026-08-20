"""Challenge analysis: detect platform/category, suggest tools, recall memory, extract flags.

The agent MUST run detect_challenge (or scripts/plan.py) BEFORE solving —
it produces the plan: category, platform, suggested tools, prior memory.
"""

import re
import os
from pathlib import Path

from ..flagmeta import detect_ctf, detect_flag, extract_flags, suggested_tools
from ..registry import tool, TOOLS

ROOT = Path(__file__).resolve().parent.parent.parent


@tool(category="misc")
def detect_challenge(problem: str) -> str:
    """Analyze a CTF problem statement: detect category + platform, suggest tools, recall prior memory. Run BEFORE solving.
    :param problem: problem
    """
    platform, category = detect_ctf(problem)
    hits = _recall(problem, limit=3)
    from .cve import detect_cves_in_problem, detect_software_in_problem
    cves = detect_cves_in_problem(problem)
    software = detect_software_in_problem(problem)
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
    if cves:
        lines.append(f"CVE: explicit CVE(s) in problem: {', '.join(cves)}")
        lines.append(f"  -> run ctf-tools cve_lookup(cve_id=...) for each, then ctf-tools cve_research(\"{problem[:80]}\") for the exploit plan")
    for s in software:
        lines.append(f"CVE: {s['name']} {s['version']} detected in problem")
        lines.append(f"  -> run ctf-tools cve_research(problem=...) to find the matching CVE + exploitation steps (local KB + NVD)")
    if hits:
        lines.append("MEMORY (prior challenges):")
        lines.extend(f"  - [{s}] {t}" for s, t in hits)

    # Self-Improvement Insights (fast-paths, learned patterns, failure warnings)
    try:
        from .self_improve import _load_state
        state = _load_state()
        text_lower = problem.lower()

        # 1. Fast-path check
        matched_fps = []
        for fp_name, fp_data in state.get("fast_paths", {}).items():
            if category and fp_data.get("category") == category:
                fp_kws = fp_name.replace("_", " ").split()
                if sum(1 for k in fp_kws if k in text_lower) >= 2:
                    matched_fps.append((fp_name, fp_data))
        if matched_fps:
            lines.append("⚡ FAST-PATH SHORTCUT:")
            for name, fp in matched_fps[:2]:
                lines.append(f"  -> {name}: use [{', '.join(fp['tools'][:4])}] (proven in {fp['count']} past solves)")

        # 2. Failure avoidance rules
        avoid_rules = [r for r in state.get("failure_rules", []) if not category or r.get("category") == category]
        if avoid_rules:
            lines.append("⚠️ AVOID (learned from past mistakes):")
            for r in avoid_rules[:2]:
                lines.append(f"  -> {r['condition']}: {r['reason'][:70]}")
    except Exception:
        pass

    return "\n".join(lines)


@tool(category="misc")
def analyze_target(target: str) -> str:
    """Decision engine: analyze a target/problem statement, detect category + platform, recall memory, and recommend the optimal tool chain.
    :param target: target
    """
    base = detect_challenge(target)
    chain = select_tools(target)
    return "\n".join([
        base,
        "",
        "DECISION ENGINE — RECOMMENDED TOOL CHAIN:",
        chain,
    ])


@tool(category="misc")
def select_tools(task: str, category: str = "", top: int = 8) -> str:
    """Decision engine: recommend the best tools for a task by keyword-matching the task against tool names, summaries, and docs.

    :param task: Task description or problem keywords (e.g. 'decode base64 hex flag')
    :param category: Restrict to one category (encoding, crypto, stego, forensics, web, rev, pwn, osint, misc)
    :param top: Maximum number of recommendations to return
    """
    words = [w for w in re.findall(r"[a-z0-9]{3,}", task.lower())]
    scored = []
    for meta in TOOLS.values():
        if category and meta["category"].lower() != category.lower():
            continue
        hay = f"{meta['name']} {meta['summary']} {meta['doc'][:300]}".lower()
        s = sum(hay.count(w) for w in words)
        if s:
            scored.append((s, meta))
    scored.sort(key=lambda x: -x[0])
    if not scored:
        return f"No tools matched '{task}'. Browse all tools via /api/tools or list_tools()."
    out = [f"TOP {min(top, len(scored))} TOOLS FOR: '{task}'"]
    for s, m in scored[:top]:
        params = ", ".join(
            p["name"] + (f"={p['default']}" if p.get("default") is not None else "")
            for p in m["params"]
        )
        out.append(f"  [{m['category']}] {m['name']} (score {s}) — {m['summary']}")
        out.append(f"      params: {params or '(none)'}")
    return "\n".join(out)


@tool(category="misc")
def optimize_parameters(tool_name: str, args_json: str = "") -> str:
    """Decision engine: return the exact parameter contract for a tool (types, required, defaults, descriptions) and validate provided args.

    :param tool_name: Registered tool name (e.g. 'caesar', 'rsa_fermat')
    :param args_json: Optional JSON object of proposed arguments to validate against the schema
    """
    meta = TOOLS.get(tool_name)
    if not meta:
        return f"Unknown tool: {tool_name}. Browse via /api/tools or select_tools."
    out = [
        f"PARAMETER CONTRACT: {tool_name} [{meta['category']}]",
        f"Summary: {meta['summary']}",
        "",
    ]
    for p in meta["params"]:
        req = "REQUIRED" if p["required"] else f"default={p['default']}"
        out.append(f"  {p['name']} ({p['type']}) [{req}] {p.get('desc', '')}".rstrip())
    if args_json:
        import json as _json
        try:
            args = _json.loads(args_json)
        except ValueError as ex:
            return "\n".join(out) + f"\n\nInvalid args_json: {ex}"
        known = {p["name"] for p in meta["params"]}
        unknown = sorted(k for k in args if k not in known)
        missing = sorted(p["name"] for p in meta["params"] if p["required"] and p["name"] not in args)
        out.append("")
        out.append(f"Provided args: {len(args)} | unknown: {unknown or '-'} | missing required: {missing or '-'}")
    return "\n".join(out)


@tool(category="misc")
def extract_flags_tool(text: str) -> str:
    """Extract ALL flag candidates from any text, any format (flag{...}, picoCTF{...}, HTB{...}, flag: xxx, hex digests...).
    :param text: input text
    """
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
            if "smoke-test" in f.name.lower():
                continue
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
    status: str = "solved",
    problem: str = "",
    commands: str = "",
    evidence: str = "",
    source: str = "manual",
) -> str:
    """Save challenge memory, generate/merge reusable AI Agent Skill in ~/.agents/skills/, and scaffold a POC writeup.

    :param title: Challenge title (e.g. 'Baby RSA Close Primes')
    :param category: Category ('crypto', 'web', 'stego', 'forensics', 'rev', 'pwn', 'osint', 'misc')
    :param tool: Primary tool(s) used (e.g. 'rsa_fermat' or 'sqli_payloads, http_request')
    :param flag: The captured flag string (e.g. 'flag{...}')
    :param note: Key lesson, vulnerability details, or what worked
    :param platform: CTF platform (e.g. 'picoCTF', 'HackTheBox', 'COMPFEST')
    :param status: Challenge status ('solved' or 'wip')
    :param problem: Challenge problem description/statement (for writeup)
    :param commands: Actual terminal commands used during solving (newline-separated)
    :param evidence: Relevant captured output that proves the recovered flag
    :param source: Provenance: manual, autonomous, imported, or fixture
    """
    synthetic_markers = ("smoke", "evaluation", "testdata/")
    if (any(marker in f"{title} {problem}".lower() for marker in synthetic_markers)
            or status.lower() in {"synthetic", "test"}):
        return "SKIPPED: synthetic/test challenges are not persisted to learning memory."
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
        f"- provenance: {source}",
        "",
    ]
    if problem:
        body += [
            "## Problem Description",
            "",
            problem,
            "",
        ]
    body += [
        "## What worked / lessons",
        "",
        note or "_(add lessons here)_",
        "",
    ]
    if commands:
        body += [
            "## Commands / Terminal",
            "",
            "```bash",
            commands,
            "```",
            "",
        ]
    if evidence:
        body += [
            "## Evidence",
            "",
            "```text",
            evidence[:12000],
            "```",
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
    if flag and os.environ.get("CTFKIT_AUTO_SKILLS") == "1":
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

    # 4. Trigger Autonomous Self-Improvement
    try:
        from .self_improve import self_improve_after_solve
        if status.lower() == "solved" and flag and "smoke" not in title.lower():
            self_improve_after_solve(
            title=title,
            category=cat,
            tools_used=tools_list,
            flag=flag,
            note=note,
            problem=problem,
            commands=commands,
            evidence=evidence,
            source=source,
            )
    except Exception as ex:
        log.warning("Self-improvement trigger failed: %s", ex)

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
        "Self-Improve : updated only for verified solved challenges",
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
        if "smoke-test" in f.name.lower():
            continue
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
    """One-click master triage: auto-detect file type, entropy, strings, embedded files/zlib, format inspection, and extract flags.
    :param path: input file path
    """
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


@tool(category="misc")
def entropy_calculator(data_or_path: str) -> str:
    """Calculate Shannon entropy and byte frequency distribution to identify encryption vs compression vs plaintext.

    :param data_or_path: File path or raw text string
    """
    import os
    import math

    if os.path.exists(data_or_path):
        raw = open(data_or_path, "rb").read()
        target_name = f"File: {data_or_path}"
    else:
        raw = data_or_path.encode("latin-1")
        target_name = "Raw Input Buffer"

    if not raw:
        return "ERROR: Input is empty."

    length = len(raw)
    freq = {}
    for b in raw:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    if entropy < 3.5:
        data_type = "Low Entropy (Plaintext ASCII / Repetitive Sparse Data)"
    elif entropy < 6.8:
        data_type = "Medium Entropy (Source Code, Executable Binary, Rich Text)"
    elif entropy < 7.6:
        data_type = "High Entropy (Compressed Data: Zip, Gzip, JPEG, MP3)"
    else:
        data_type = "Very High Entropy (~8.0: Strongly Encrypted / High-grade Pseudo-Random)"

    printable_count = sum(1 for b in raw if 32 <= b <= 126 or b in (10, 13, 9))
    printable_ratio = (printable_count / length) * 100

    lines = [
        f"=== Shannon Entropy & Distribution Analysis ===",
        f"  Target           : {target_name}",
        f"  Size             : {length} bytes",
        f"  Shannon Entropy  : {entropy:.4f} / 8.0000 bits per byte",
        f"  Unique Byte Count: {len(freq)} / 256",
        f"  Printable ASCII  : {printable_ratio:.2f}% ({printable_count} chars)",
        f"  Assessment       : {data_type}"
    ]
    return "\n".join(lines)


@tool(category="misc")
def regex_flag_search(text_or_path: str, custom_prefix: str = "") -> str:
    """Search for CTF flags across multiple standard formats (flag{}, ctf{}, picoCTF{}, HTB{}, THM{}, etc.) and custom patterns.

    :param text_or_path: File path or raw text string to scan
    :param custom_prefix: Optional custom flag prefix (e.g. 'SECRET' for SECRET{...})
    """
    import os
    import re

    if os.path.exists(text_or_path):
        text = open(text_or_path, "r", errors="ignore").read()
    else:
        text = text_or_path

    patterns = [
        r"(?:flag|FLAG)\{[^}\n\r\t]+\}",
        r"(?:ctf|CTF)\{[^}\n\r\t]+\}",
        r"picoCTF\{[^}\n\r\t]+\}",
        r"HTB\{[^}\n\r\t]+\}",
        r"THM\{[^}\n\r\t]+\}",
        r"DUCTF\{[^}\n\r\t]+\}",
        r"SECCON\{[^}\n\r\t]+\}",
        r"TryHards\{[^}\n\r\t]+\}",
        r"[A-Za-z0-9_]{2,15}\{[a-zA-Z0-9_\-\.!@#\$%\^&\*\+=: ]{3,80}\}",
    ]
    if custom_prefix:
        patterns.insert(0, rf"{re.escape(custom_prefix)}\{{[^}}\n\r\t]+\}}")

    found_flags = []
    seen = set()
    for pat in patterns:
        for m in re.finditer(pat, text):
            cand = m.group(0)
            if cand not in seen:
                seen.add(cand)
                found_flags.append(cand)

    if not found_flags:
        return "No standard CTF flag patterns matched in input."

    lines = [f"🏆 Found {len(found_flags)} Flag Candidate(s):"]
    for idx, fl in enumerate(found_flags, 1):
        lines.append(f"  [{idx}] {fl}")
    return "\n".join(lines)
