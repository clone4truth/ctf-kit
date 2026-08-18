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