"""Structured Planning and Hypothesis Engine for CTF Challenges.

Enforces a rigorous 3-Phase Thinking Gate:
1. Target Profiling — extracts artifacts, parameters, constraints, and technologies.
2. Hypothesis Tree — creates prioritized, budgeted attack vectors (max 2-3 attempts each).
3. Circuit Breaker & Adaptive Pivoting — detects dead ends and switches hypotheses automatically.
"""

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from ..flagmeta import detect_ctf, suggested_tools
from ..logging import log
from ..registry import tool, TOOLS

ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class TargetProfile:
    problem: str
    category: str
    platform: str
    target_type: str
    urls: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    numbers: list[str] = field(default_factory=list)
    hex_strings: list[str] = field(default_factory=list)
    b64_strings: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    software: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    id: str
    title: str
    category: str
    confidence: float
    budget: int
    attempts: int = 0
    status: str = "pending"  # pending, active, validated, pruned
    recommended_tools: list[str] = field(default_factory=list)
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)


def analyze_target_profile(problem: str) -> TargetProfile:
    """Deep inspection of problem statement to extract all parameters and constraints."""
    platform, category = detect_ctf(problem)
    category = category or "misc"
    platform = platform or "unknown"

    urls = re.findall(r"https?://[^\s\"'<>)\]]+", problem)
    files = re.findall(
        r"[\w./\\:\-]+\.(?:png|jpe?g|gif|bmp|webp|tif|ico|wav|mp3|flac|ogg|pcap|pcapng|zip|7z|rar|gz|pyc|elf|exe|dll|bin|pdf|txt|pem|key|sqlite|db|json|php|py|html)",
        problem,
        re.IGNORECASE
    )
    hex_strings = [h for h in re.findall(r"\b[0-9a-fA-F]{16,}\b", problem)]
    b64_strings = [b for b in re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", problem) if not b.isdigit()]
    numbers = [n for n in re.findall(r"\b\d{3,}\b", problem)]

    # Detect known CVEs & Software
    from .cve import detect_cves_in_problem, detect_software_in_problem
    cves = detect_cves_in_problem(problem)
    soft_list = [f"{s['name']} {s['version']}".strip() for s in detect_software_in_problem(problem)]

    # Infer Target Type
    target_type = "unknown"
    p_lower = problem.lower()
    if urls or any(k in p_lower for k in ["http", "web", "api", "endpoint", "curl", "login", "cookie"]):
        target_type = "web_service"
    elif any(f.endswith((".pcap", ".pcapng", ".wav", ".mp3", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".zip", ".pdf")) for f in files):
        target_type = "forensic_artifact"
    elif any(f.endswith((".elf", ".exe", ".dll", ".pyc", ".bin")) for f in files) or any(k in p_lower for k in ["binary", "overflow", "rop", "disassembl", "decompile"]):
        target_type = "binary_artifact"
    elif hex_strings or b64_strings or any(k in p_lower for k in ["rsa", "aes", "cipher", "decrypt", "modulus", "prime", "xor"]):
        target_type = "cryptographic_data"
    else:
        target_type = "generic_text"

    # Identify Key Constraints
    constraints = []
    if "waf" in p_lower or "filter" in p_lower or "blocked" in p_lower:
        constraints.append("WAF / Filtering detected — requires encoded/obfuscated payloads")
    if "symlink" in p_lower:
        constraints.append("Symlink traversal vector indicated")
    if "jwt" in p_lower or "token" in p_lower:
        constraints.append("Token-based auth / signature verification weakness")
    if "close prime" in p_lower or "fermat" in p_lower:
        constraints.append("RSA close primes vulnerability (Fermat factorization)")
    if "small e" in p_lower or "e=3" in p_lower:
        constraints.append("RSA small public exponent (Direct root / Hastad)")

    return TargetProfile(
        problem=problem,
        category=category,
        platform=platform,
        target_type=target_type,
        urls=urls,
        files=files,
        numbers=numbers,
        hex_strings=hex_strings,
        b64_strings=b64_strings,
        cves=cves,
        software=soft_list,
        constraints=constraints
    )


def generate_hypotheses(profile: TargetProfile) -> list[Hypothesis]:
    """Build a prioritized, budgeted tree of attack hypotheses."""
    hypotheses = []
    p_lower = profile.problem.lower()
    cat = profile.category

    # Check fast-paths & learned patterns first
    try:
        from .self_improve import _load_state
        loaded = _load_state()
        verified_memories = len(list((ROOT / "memory").glob("*.md"))) - int((ROOT / "memory" / "_index.md").exists())
        legacy_state = loaded.get("version", 1) < 2 or loaded.get("total_solves", 0) > verified_memories
        state = loaded if (not legacy_state or os.environ.get("CTFKIT_USE_LEGACY_LEARNING") == "1") else {}
        for fp_name, fp in state.get("fast_paths", {}).items():
            if fp.get("category") == cat:
                kws = fp_name.replace("_", " ").split()
                if sum(1 for k in kws if k in p_lower) >= 2:
                    hypotheses.append(Hypothesis(
                        id=f"HYP-{len(hypotheses)+1}",
                        title=f"Fast-Path: {fp_name}",
                        category=cat,
                        confidence=0.95,
                        budget=2,
                        recommended_tools=fp.get("tools", [])[:4],
                        rationale=f"Matches learned fast-path from {fp.get('count', 1)} prior successful solves."
                    ))
    except Exception:
        pass

    # Category-Specific Hypothesis Generators
    if cat == "web" or profile.target_type == "web_service":
        if profile.cves:
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title=f"Known CVE Exploitation ({profile.cves[0]})",
                category="web",
                confidence=0.90,
                budget=3,
                recommended_tools=["cve_lookup", "cve_research", "http_request"],
                rationale="Explicit CVE present in challenge statement."
            ))
        if any(k in p_lower for k in ["jwt", "token", "session"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="JWT/Session Token Forgery (Algorithm Confusion / None Alg / Weak Secret)",
                category="web",
                confidence=0.85,
                budget=2,
                recommended_tools=["jwt_decode", "jwt_forge", "jwt_key_confusion", "flask_session"],
                rationale="Challenge involves session/token manipulation."
            ))
        if any(k in p_lower for k in ["login", "auth", "admin", "password", "sql"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Authentication Bypass (SQLi / NoSQLi / IDOR)",
                category="web",
                confidence=0.80,
                budget=3,
                recommended_tools=["sqli_payloads", "nosql_payloads", "payload_encoders", "http_request"],
                rationale="Login or authorization boundary detected."
            ))
        if any(k in p_lower for k in ["template", "jinja", "render", "ssti", "{{"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Server-Side Template Injection (SSTI / RCE)",
                category="web",
                confidence=0.85,
                budget=2,
                recommended_tools=["ssti_payloads", "payload_encoders", "http_request"],
                rationale="Template rendering engine identified."
            ))
        if any(k in p_lower for k in ["file", "upload", "zip", "lfi", "traversal", "symlink"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="File Inclusion / Zip Symlink Traversal / Upload Bypass",
                category="web",
                confidence=0.85,
                budget=2,
                recommended_tools=["path_traversal_payloads", "file_upload_bypass", "http_request"],
                rationale="File upload or local file reading mechanism present."
            ))

    elif cat == "crypto" or profile.target_type == "cryptographic_data":
        if any(k in p_lower for k in ["rsa", "modulus", "prime", "e="]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="RSA Factorization / Small Exponent / Close Primes Attack",
                category="crypto",
                confidence=0.90,
                budget=3,
                recommended_tools=["rsa_fermat", "rsa_small_e", "rsa_wiener", "rsa_decrypt"],
                rationale="RSA public-key parameters provided."
            ))
        if any(k in p_lower for k in ["xor", "key", "stream", "otp"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="XOR Key Recovery / Single-byte Brute Force / Crib Drag",
                category="crypto",
                confidence=0.85,
                budget=2,
                recommended_tools=["xor_brute", "xor_crib_drag", "xor_keyed"],
                rationale="XOR encryption or crib dragging pattern detected."
            ))
        if any(k in p_lower for k in ["aes", "cbc", "gcm", "ecb", "block"]):
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Block Cipher Weakness (CBC Bit-Flip / GCM Nonce Reuse / ECB)",
                category="crypto",
                confidence=0.80,
                budget=2,
                recommended_tools=["aes_crypt", "aes_cbc_bitflip", "aes_gcm_nonce_reuse"],
                rationale="AES or block cipher mode specified."
            ))

    elif cat == "stego":
        hypotheses.append(Hypothesis(
            id=f"HYP-{len(hypotheses)+1}",
            title="Steganography LSB / Bit-Plane / Chunk Analysis",
            category="stego",
            confidence=0.90,
            budget=3,
            recommended_tools=["stego_metadata", "stego_png_chunks", "stego_lsb", "png_fix_ihdr"],
            rationale="Image/Audio carrier file with hidden data."
        ))

    elif cat == "forensics" or profile.target_type == "forensic_artifact":
        if any(f.endswith((".pcap", ".pcapng")) for f in profile.files) or "pcap" in p_lower:
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="PCAP Stream Extraction (HTTP Flows / DNS Exfil / USB Keystrokes)",
                category="forensics",
                confidence=0.90,
                budget=3,
                recommended_tools=["pcap_http", "pcap_dns_exfil", "pcap_usb_keystrokes", "triage_file"],
                rationale="Network capture artifact provided."
            ))
        else:
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Artifact Triage & Carving (Embedded Zlib / Hidden Files / Metadata)",
                category="forensics",
                confidence=0.85,
                budget=3,
                recommended_tools=["triage_file", "carve", "zlib_hunt", "strings_extract"],
                rationale="Forensic binary or container file analysis."
            ))

    elif cat == "rev" or cat == "pwn" or profile.target_type == "binary_artifact":
        if any(f.endswith(".pyc") for f in profile.files) or "pyc" in p_lower:
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Python Bytecode Decompilation & Magic Inspection",
                category="rev",
                confidence=0.95,
                budget=2,
                recommended_tools=["pyc_magic_info", "pyc_decompile_info", "strings_extract"],
                rationale="Python compiled bytecode artifact."
            ))
        else:
            hypotheses.append(Hypothesis(
                id=f"HYP-{len(hypotheses)+1}",
                title="Binary Mitigations & Buffer Overflow / ROP Chain Exploration",
                category="pwn",
                confidence=0.85,
                budget=3,
                recommended_tools=["checksec", "elf_info", "debruijn", "debruijn_find", "rop_gadgets"],
                rationale="Native executable challenge."
            ))

    # General Fallback Hypothesis
    if not hypotheses:
        hypotheses.append(Hypothesis(
            id="HYP-1",
            title="Multi-layer Encoding & Master Triage Sweep",
            category=cat,
            confidence=0.70,
            budget=2,
            recommended_tools=["decode_all", "decode_chain", "triage_file", "extract_flags_tool"],
            rationale="General CTF data inspection."
        ))

    # Sort hypotheses by confidence score descending
    hypotheses.sort(key=lambda h: -h.confidence)
    return hypotheses[:3]


@tool(category="misc")
def plan_challenge(problem_statement: str) -> str:
    """Master Planning Gate: Build a structured Target Profile, prioritized Hypothesis Tree, and budgeted execution plan BEFORE solving.

    Always run this first when starting a challenge. It prevents dead-end loops and ensures systematic problem understanding.

    :param problem_statement: Challenge description, problem text, and artifacts
    """
    profile = analyze_target_profile(problem_statement)
    hypotheses = generate_hypotheses(profile)

    lines = [
        "=" * 65,
        "🎯 CTF CHALLENGE PLANNER & HYPOTHESIS TREE",
        "=" * 65,
        f"Category     : {profile.category.upper()}",
        f"Platform     : {profile.platform}",
        f"Target Type  : {profile.target_type}",
    ]

    if profile.urls:
        lines.append(f"Target URL(s): {', '.join(profile.urls)}")
    if profile.files:
        lines.append(f"Artifact(s)  : {', '.join(profile.files)}")
    if profile.cves:
        lines.append(f"CVE Identified: {', '.join(profile.cves)}")
    if profile.software:
        lines.append(f"Software Tech: {', '.join(profile.software)}")
    if profile.constraints:
        lines.append(f"Constraints  : {'; '.join(profile.constraints)}")

    lines.append("")
    lines.append("🌲 PRIORITIZED HYPOTHESIS BOARD (Budgeted Trial Limits):")
    lines.append("-" * 65)

    for h in hypotheses:
        lines.append(f"[{h.id}] {h.title} (Confidence: {h.confidence:.0%})")
        lines.append(f"      Rationale : {h.rationale}")
        lines.append(f"      Trial Cap : Max {h.budget} attempts before pruning")
        lines.append(f"      Tools     : {', '.join(h.recommended_tools)}")
        lines.append("")

    lines.append("📋 RECOMMENDED EXECUTION SEQUENCE:")
    lines.append(f"  1. Activate {hypotheses[0].id}: '{hypotheses[0].title}'")
    lines.append(f"     Execute: {', '.join(hypotheses[0].recommended_tools[:2])}")
    lines.append("  2. If unsuccessful after budgeted attempts -> Prune and pivot immediately to next hypothesis.")
    lines.append("  3. Check output of every stage with extract_flags_tool.")
    lines.append("=" * 65)

    return "\n".join(lines)
