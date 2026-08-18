"""Writeup/POC generator — creates writeups/<category>/<date>_<slug>.md from a memory file.

Usage:
    python scripts/writeup.py --memory memory/2026-08-18_xor-login.md
    python scripts/writeup.py --memory memory/x.md --steps "1. decode base64\n2. xor with key 0x7e"

The opencode plugin and scripts/remember.py call this automatically after a
flag is recovered. The agent should augment the step-by-step with the exact
commands it used (terminal / BurpSuite).
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WRITEUPS_DIR = ROOT / "writeups"

CATEGORY_CMDS = {
    "web": {
        "terminal": [
            "curl -v http://<target>/ --data 'user=admin'   # inspect raw response",
            "ffuf -u http://<target>/FUZZ -w wordlists/common.txt   # directory fuzz",
            "sqlmap -u 'http://<target>/login' --data 'user=admin&pass=x' --batch --dbs",
            "ctfkit: http_request / jwt_decode / jwt_forge / sqli_payloads / payload_encoders",
        ],
        "burp": [
            "Proxy: intercept the login/request flow; tamper Authorization / cookie headers",
            "Repeater: test sqli_payloads variants (' OR 1=1-- -) on params",
            "Intruder: fuzz params/headers with payload_encoders output",
            "Decoder: base64/JWT of captured tokens",
        ],
    },
    "crypto": {
        "terminal": [
            "ctfkit: decode_all / xor_brute / vigenere_keylength / frequency / caesar / rsa_decrypt / hash_identify",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('xor_brute', {'data_hex':'...','key_length':1}))\"",
            "openssl enc -d -aes-128-cbc -K <hex> -iv <hex>   # manual AES",
        ],
        "burp": ["Burp not typical for crypto — use CyberChef or the ctfkit tools above."],
    },
    "pwn": {
        "terminal": [
            "ctfkit: checksec <binary>  # NX/PIE/RELRO/Canary/Fortify",
            "ctfkit: rop_gadgets <binary> 'pop rdi'",
            "readelf -a <binary> | grep -E 'GNU|SYMBOL'   # symbols & sections",
            "objdump -d <binary> | grep -A5 win   # find win()/system()",
            "gdb -q ./<binary>   # break at offset, pattern offset via ctfkit debruijn",
            "python3 -c 'from pwn import *; ...'   # pwntools: cyclic(200), offset, ROP",
        ],
        "burp": ["Not applicable — use gdb/pwntools instead."],
    },
    "rev": {
        "terminal": [
            "file <binary> && strings -n 5 <binary> | head -50",
            "ctfkit: elf_info / strings_extract / hexdump / checksec",
            "objdump -d -M intel <binary>   # or ghidra/radare2 for decompilation",
            "strace -f ./<binary>   # syscall trace for hidden I/O",
        ],
        "burp": ["Not applicable — use ghidra / radare2 / objdump."],
    },
    "forensics": {
        "terminal": [
            "file <file>; ctfkit: file_type / hexdump / strings_extract / carve / zlib_hunt / entropy_map",
            "binwalk -e <file>   # extract embedded archives",
            "foremost -i <file> -o out/   # carve files",
            "tshark -r capture.pcap -Y http   # or ctfkit pcap_http",
        ],
        "burp": ["Not applicable — use binwalk/foremost/tshark."],
    },
    "stego": {
        "terminal": [
            "ctfkit: stego_lsb / stego_metadata / stego_channel / stego_png_chunks / stego_gif_frames / stego_compare",
            "zsteg <image>   # LSB/bit-plane scan",
            "steghide extract -sf <image>   # passphrase-less extraction",
            "binwalk <image>   # hidden payloads in gaps",
        ],
        "burp": ["Not applicable — use zsteg/steghide/binwalk."],
    },
    "osint": {
        "terminal": [
            "ctfkit: dns_query <domain> A / crtsh_subdomains <domain> / dns_reverse <ip>",
            "dig ANY <domain>; whois <domain>; host -t mx <domain>",
            "curl 'https://crt.sh/?q=%25.<domain>&output=json' | jq '.[].name_value'",
        ],
        "burp": ["Burp rarely needed — browser devtools + curl usually enough."],
    },
    "misc": {
        "terminal": [
            "ctfkit: decode_all / extract_flags_tool on every output",
            "file <file>; strings -a <file>; xxd <file> | head",
        ],
        "burp": ["Varies per challenge — start with terminal tools."],
    },
}


def field(lines: list[str], key: str) -> str:
    for l in lines:
        if l.lstrip("- ").startswith(key):
            return l.split(":", 1)[1].strip()
    return ""


def generate_writeup(memory_file: Path, steps: str = "") -> Path:
    lines = memory_file.read_text(encoding="utf-8", errors="replace").splitlines()
    title = next((l[2:] for l in lines if l.startswith("# ")), memory_file.stem)
    platform = field(lines, "platform:") or "unknown"
    category = field(lines, "category:") or "misc"
    tools = [t.strip() for t in field(lines, "tools:").split(",") if t.strip()]
    flag = field(lines, "flag:")

    # runs/approach captured by the plugin
    runs = []
    for l in lines:
        m = re.match(r"- `(\w+)`\s*(?:\((.*?)\))?\s*→\s*(\w+)", l)
        if m:
            runs.append((m.group(1), m.group(2) or "", m.group(3)))

    cat_cmds = CATEGORY_CMDS.get(category, CATEGORY_CMDS["misc"])
    slug = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:60]
    out_dir = WRITEUPS_DIR / category
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{date.today().isoformat()}_{slug}.md"
    i = 1
    while target.exists():
        target = out_dir / f"{date.today().isoformat()}_{slug}_{i}.md"
        i += 1

    steps_lines = steps.strip().splitlines() if steps.strip() else (
        [f"Run `{t}` {('with ' + a) if a else ''} → {s}." for t, a, s in runs] or ["_(expand with the exact steps used)_"]
    )
    step_md = "\n".join(f"{i}. {s}" for i, s in enumerate(steps_lines, 1))

    body = f"""# {title}

> Auto-generated writeup/POC — augment the step-by-step with the exact commands you used.

| Field | Value |
|---|---|
| Platform | {platform} |
| Category | {category} |
| Date | {date.today().isoformat()} |
| Status | solved |
| Flag | `{flag}` |

## TL;DR — best & fastest technique

Minimal path: {", ".join(tools) or "N/A"} → flag recovered.
{("Technique: " + runs[-1][0] + " → flag") if runs else ""}

## Step-by-step

{step_md}

## Tools & commands

### Terminal

```bash
{"\n".join(cat_cmds["terminal"])}
```

### BurpSuite

{"\n".join("- " + c for c in cat_cmds["burp"])}

## Flag

`{flag}`

## Lessons

_(copy from memory/ file)_
"""
    target.write_text(body, encoding="utf-8")
    return target


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--memory", required=True, help="memory .md file to convert")
    ap.add_argument("--steps", default="", help="optional multi-line step-by-step override")
    args = ap.parse_args()
    mem = Path(args.memory)
    if not mem.is_file():
        sys.exit(f"Memory file not found: {mem}")
    target = generate_writeup(mem, args.steps)
    print(f"Writeup: {target}")


if __name__ == "__main__":
    main()