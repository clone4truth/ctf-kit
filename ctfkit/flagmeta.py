"""CTF platform & flag format detection.

Single source of truth: flagformats.json (also read by the opencode plugin).

API:
    detect_ctf(text)    -> (platform | None, category | None)
    detect_flag(text)   -> flag string | None
    extract_flags(text) -> list of ALL candidate flags (no exceptions)
    suggested_tools(cat)-> list of existing tool names for a category

Flag fallback chain (works for ANY flag shape, not just known platforms):
    1. detected platform's prefixes        e.g. picoCTF{...}
    2. all known platform prefixes         e.g. HTB{...}, COMPFEST{...}
    3. generic prefixes                    flag{...}, FLAG{...}, CTF{...}
    4. any-word brace                      wh4t{n3v3r_g0tt3n}
    5. flag keyword-adjacent               flag: abc123 / flag = xxx / FLAG-xxx
    6. hex digest near the word "flag"     32/40/64-hex string within 300 chars
"""

import json
import re
from pathlib import Path

_DATA = json.loads((Path(__file__).parent / "flagformats.json").read_text(encoding="utf-8"))

GENERIC_PREFIXES = _DATA["generic_prefixes"]
PLATFORMS = _DATA["platforms"]

_platform_by_name = {p["name"]: p for p in PLATFORMS}

_patterns: list[tuple[str, re.Pattern]] = []
for p in PLATFORMS:
    for prefix in p["prefixes"]:
        _patterns.append((p["name"], re.compile(re.escape(prefix) + r"[^}\n]{1,200}\}")))

_GENERIC_BRACE = re.compile(r"([A-Za-z0-9_]{2,16})\{[^}\n]{6,200}\}")
_FLAG_WORD = re.compile(r"flag[^\w]?[=:\-]?[^\w]?([A-Za-z0-9_\-+./=]{6,200})", re.IGNORECASE)
_HEX_NEAR_FLAG = re.compile(r"(?i)(flag.{0,300}?)([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})")

CATEGORY_KEYWORDS = {
    "web": ["web", "sql", "injection", "xss", "ssrf", "csrf", "http", "cookie", "jwt", "api", "php", "login", "bypass auth", "admin panel", "deserialization", "lfi", "rce", "ssti", "template injection", "reverse shell"],
    "crypto": ["crypto", "cipher", "encrypt", "decrypt", "xor", "rsa", "aes", "hash", "vigenere", "caesar", "base64", "rot", "otp", "cbc", "padding", "wiener", "fermat", "hastad", "lcg", "crib"],
    "pwn": ["pwn", "buffer overflow", "bof", "shellcode", "rop", "ret2", "format string", "heap", "exploitation", "gadget", "overwrite", "fmtstr", "pwntools"],
    "rev": ["reverse", " rev", "decompile", "disassembl", "assembly", "crackme", "obfuscation", "unpack", "anti-debug", "flare", "pe", "exe", "dll", "pyc", "bytecode"],
    "forensics": ["forensic", "pcap", "pcapng", "wireshark", "memory dump", "disk image", "carve", "metadata", "deleted", "timeline", "volatility", "exif", "gps", "keystrokes", "usb", "dns exfil", "pseudo encrypt"],
    "stego": ["stego", "steganograph", "lsb", "pixels", "hidden in", "embedded", "qrcode", "braille", "ihdr", "crc", "zero width", "audio", "wav", "dtmf"],
    "osint": ["osint", "geolocat", "social media", "recon", "twitter", "instagram", "search", "whois"],
    "misc": ["misc", "jail", "brainfuck", "esolang", "sanity", "base45", "base91", "triage"],
}

SUGGESTED_TOOLS = {
    "web": ["ssti_payloads", "revshell_generator", "php_filter_chain", "ssrf_obfuscator", "jwt_decode", "jwt_forge", "jwt_key_confusion", "http_request", "payload_encoders", "sqli_payloads", "decode_base"],
    "crypto": ["rsa_wiener", "rsa_fermat", "rsa_common_modulus", "rsa_hastad", "rsa_parse_key", "rsa_decrypt", "rsa_small_e", "xor_crib_drag", "xor_brute", "xor_keyed", "lcg_solve", "hash_length_extension", "aes_crypt", "aes_cbc_bitflip", "hash_identify", "hash_crack_common", "vigenere_keylength", "decode_all"],
    "pwn": ["checksec", "rop_gadgets", "fmtstr_payload_gen", "pwn_template", "shellcode_multi", "shellcode_x64", "debruijn", "debruijn_find"],
    "rev": ["pe_info", "elf_info", "checksec", "pyc_magic_info", "strings_extract", "hexdump", "decode_all"],
    "forensics": ["triage_file", "pcap_http", "pcap_dns_exfil", "pcap_usb_keystrokes", "zip_fix_pseudo_encrypt", "exif_gps_map", "file_type", "strings_extract", "hexdump", "carve", "zlib_hunt", "entropy_map", "decode_all"],
    "stego": ["png_fix_ihdr", "decode_zero_width", "encode_zero_width", "stego_audio_wav", "stego_dtmf_detect", "stego_lsb", "stego_metadata", "stego_channel", "stego_xor_images", "stego_png_chunks", "stego_gif_frames", "stego_compare"],
    "osint": ["dns_query", "dns_reverse", "crtsh_subdomains"],
    "misc": ["triage_file", "decode_chain", "decode_zero_width", "decode_base45", "decode_base91", "decode_all", "hexdump", "strings_extract", "file_type"],
}


def detect_ctf(text: str) -> tuple[str | None, str | None]:
    """Score platform + category keywords; returns (platform, category) or None."""
    t = text.lower()
    best_platform, best_pscore = None, 0
    for p in PLATFORMS:
        score = sum(2 for kw in p["keywords"] if kw in t)
        if score > best_pscore:
            best_platform, best_pscore = p["name"], score
    best_cat, best_cscore = None, 0
    for cat, kws in CATEGORY_KEYWORDS.items():
        score = sum(2 if " " in kw else 1 for kw in kws if kw in t)
        if score > best_cscore:
            best_cat, best_cscore = cat, score
    return (best_platform if best_pscore else None, best_cat if best_cscore else None)


def _flag_matches(text: str, platform: str | None = None) -> list[str]:
    """All flag candidates in priority order (may contain near-duplicates)."""
    out = []
    if platform:
        for name, pat in _patterns:
            if name == platform:
                out.extend(m.group(0) for m in pat.finditer(text))
    for _, pat in _patterns:
        out.extend(m.group(0) for m in pat.finditer(text))
    for prefix in GENERIC_PREFIXES:
        out.extend(m.group(0) for m in re.finditer(re.escape(prefix) + r"[^}\n]{1,200}\}", text))
    out.extend(m.group(0) for m in _GENERIC_BRACE.finditer(text))
    out.extend(m.group(0) for m in _FLAG_WORD.finditer(text))
    for m in _HEX_NEAR_FLAG.finditer(text):
        out.append(m.group(2))
    return out


def extract_flags(text: str, platform: str | None = None) -> list[str]:
    """ALL flag candidates, deduped in priority order."""
    seen = set()
    out = []
    for f in _flag_matches(text, platform):
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def detect_flag(text: str, platform: str | None = None) -> str | None:
    """Best single flag (first solid candidate)."""
    for f in extract_flags(text, platform):
        if f.startswith("flag") or f.startswith("FLAG") or "{" in f or len(f) >= 12:
            return f
    return extract_flags(text, platform)[0] if extract_flags(text, platform) else None


def suggested_tools(category: str | None) -> list[str]:
    return SUGGESTED_TOOLS.get(category or "misc", SUGGESTED_TOOLS["misc"])


def platform_names() -> list[str]:
    return list(_platform_by_name)


if __name__ == "__main__":
    samples = [
        "picoCTF{fl4g_h3re_123}",
        "HTB{pr1v3sc_2026}",
        "hacktoday{selamat_malam}",
        "THM{basic_web_enum}",
        "COMPFEST{b3r4s1l_l4g1}",
        "flag{simple_flag}",
        "FLAG{NO_SPACE}",
        "the answer is wh4t{n3v3r_g0tt3n}",
        "your flag: a1b2c3d4e5f6g7h8i9j0",
        "submit FLAG-9f86d081884c7d659a2feaa0c55ad015",
        "flag = 5d41402abc4b2a76b9719d911017c592",
    ]
    for s in samples:
        print(f"  {s!r:50} -> {detect_flag(s)!r}")
    print()
    for s in [
        "picoCTF web challenge: sql injection on the login page",
        "hackthebox crypto: xor cipher decode the flag",
        "compfest pwn buffer overflow ret2win",
        "solve this forensics pcap challenge",
    ]:
        print(f"  ctf: {detect_ctf(s)}  <- {s[:50]}")