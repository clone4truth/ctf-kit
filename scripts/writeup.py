"""Writeup/POC generator — creates writeups/<category>/<date>_<slug>.md from a memory file.

The generated writeup is a complete, end-to-end step-by-step POC:
  1. Plan (detect_challenge / recall_knowledge)
  2. Recon & fingerprinting (terminal + BurpSuite where applicable)
  3. Analysis / detection
  4. Exploitation / decode / solve
  5. Flag extraction & validation
  6. Save memory & skill

For web challenges it also embeds the full BurpSuite workflow (Proxy, Repeater,
Intruder, Decoder, Comparer, Session handling) with concrete steps.

Usage:
    python scripts/writeup.py --memory memory/2026-08-18_xor-login.md
    python scripts/writeup.py --memory memory/x.md --steps "1. decode base64\n2. xor with key 0x7e"

The opencode plugin and scripts/remember.py call this automatically after a
flag is recovered. The recorded ctf-tools MCP runs (tool + args) from the memory
file are injected into the steps, so the POC shows exactly what was executed.
"""

import argparse
import json
import re
import shlex
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent.parent
WRITEUPS_DIR = ROOT / "writeups"

# ---------------------------------------------------------------------------
# Per-category playbooks: complete end-to-end workflow, start to finish.
# Each phase = (phase_title, [steps]). Steps may embed [MCP] / [TERM] / [BURP]
# tags to clarify where each action happens.
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "web": {
        "intro": "Web exploitation lab — attack surface is a live HTTP(S) target.",
        "phases": [
            (
                "Phase 1 — Plan & recall (run BEFORE touching the target)",
                [
                    "[MCP] ctf-tools detect_challenge(problem=\"<problem statement>\") → category, platform, suggested tools",
                    "[MCP] ctf-tools recall_knowledge(query=\"<keywords>\") → prior memory/skills for the same technique",
                    "[MCP] ctf-tools select_tools(task=\"<keywords>\", category=\"web\") → pick the right tools",
                ],
            ),
            (
                "Phase 2 — Recon & fingerprinting",
                [
                    "[TERM] curl -sv http://<target>/   # raw headers, cookies, Set-Cookie, server banner",
                    "[TERM] ffuf -u http://<target>/FUZZ -w wordlists/common.txt -mc 200,204,301,302,403 -t 50   # directory fuzz",
                    "[TERM] nmap -sV -sC -p- <target> -oN recon.txt   # open ports + service versions",
                    "[TERM] curl -s http://<target>/robots.txt; curl -s http://<target>/.git/HEAD; curl -s http://<target>/api/docs",
                    "[MCP] ctf-tools browser_agent(action=\"full\", url=\"http://<target>/\") → rendered DOM, forms, links, JS-rendered flags",
                    "[MCP] ctf-tools http_request(method=\"GET\", url=\"http://<target>/\") → capture every response header/cookie",
                    "[MCP] ctf-tools cve_research(problem=\"<problem + software + version>\") → find the CVE + exploit plan for known products (NVD + local KB)",
                    "[TERM] whatweb http://<target>/   # product + version fingerprint for the CVE search",
                ],
            ),
            (
                "Phase 3 — Analysis & detection",
                [
                    "[MCP] ctf-tools cve_lookup(cve_id=\"CVE-...\") → severity, description, PoC references",
                    "[MCP] ctf-tools cve_search(software=\"<product>\", version=\"<version>\") → other CVEs for the same version",
                    "[TERM] searchsploit <product> <version>   # local exploit-db (or curl exploit-db search page)",
                    "[MCP] ctf-tools jwt_decode(token=...) / jwt_forge(...)   # if a JWT cookie is present, decode it first",
                    "[MCP] ctf-tools sqli_payloads(kind=\"auth_bypass\") → try on login params",
                    "[MCP] ctf-tools payload_encoders(payload=\"<injection>\") → WAF-bypass variants (url/hex/unicode/charcode)",
                    "[BURP] Proxy: intercept the login flow, observe params/headers/cookies being sent",
                ],
            ),
            (
                "Phase 4 — Exploitation",
                [
                    "[TERM] sqlmap -u 'http://<target>/login' --data 'user=admin&pass=x' --batch --dbs   # automated SQLi",
                    "[MCP] ctf-tools http_request(method=\"POST\", url=\"...\", data=\"...\", headers_csv=\"Cookie: ...\") → replay forged requests",
                    "[BURP] Repeater: tamper Authorization/cookie/params with payload variants from Phase 3",
                    "[BURP] Intruder: fuzz the vulnerable param with the payload_encoders output; grep-match for error strings",
                    "[MCP] ctf-tools ssti_payloads / xxe_payloads / path_traversal_payloads / command_injection_payloads → pick the matching injection type",
                ],
            ),
            (
                "Phase 5 — Flag extraction & validation",
                [
                    "[MCP] ctf-tools extract_flags_tool(text=response_body) → collect flag candidates from EVERY output",
                    "Validate the flag format against the detected platform (e.g. picoCTF{...}, tryhards{...})",
                    "[MCP] ctf-tools remember_challenge(title=..., category=\"web\", tool=..., flag=..., note=...) → auto-saves memory + this writeup",
                ],
            ),
        ],
        "terminal": [
            "curl -sv http://<target>/ | tee response.txt   # inspect raw response (headers, cookies, body)",
            "ffuf -u http://<target>/FUZZ -w wordlists/common.txt -mc 200,204,301,302,403 -t 50   # directory fuzz",
            "nmap -sV -sC -p- <target> -oN recon.txt   # port + service fingerprint",
            "curl -X POST http://<target>/login -d 'user=admin&pass=x' -b cookies.txt -c cookies.txt -v",
            "sqlmap -u 'http://<target>/login' --data 'user=admin&pass=x' --batch --dbs --risk=3 --level=3",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('http_request', {'url': 'http://<target>/', 'method': 'GET'}))\"",
        ],
        "burp": [
            "1. Proxy setup: Burp > Proxy > Options > Proxy Listeners > Add 127.0.0.1:8080; set browser (FoxyProxy) to use 127.0.0.1:8080 for HTTP+HTTPS; install Burp CA cert (visit http://burp/ > CA Certificate).",
            "2. Enable interception: Proxy > Intercept > 'Intercept is on' — walk through login/registration to map the request flow and spot hidden params/cookies.",
            "3. History review: Proxy > HTTP history — look for API endpoints, admin routes, tokens in URL/headers, and interesting responses (302 to admin, debug pages).",
            "4. Repeater: right-click the interesting request > Send to Repeater. Test auth bypass / injection payloads (e.g. ' OR 1=1-- -) on each param; toggle method; tamper Authorization / cookie / X-Forwarded-For headers.",
            "5. Intruder: Send to Intruder > Positions: mark the vulnerable param value; Payloads: paste the output of ctf-tools payload_encoders or a wordlist; Options: add grep-match for error patterns, flag{..., or length anomalies; run Attack.",
            "6. Decoder: copy the token/cookie > Decoder > decode base64/URL/hex; feed parts into ctf-tools jwt_decode for structured JWT analysis.",
            "7. Comparer: send baseline vs tampered requests in Repeater > select both responses > right-click > Send to Comparer — detect blind-SQLi/boolean differences.",
            "8. Session handling: Project options > Sessions > Macro: auto-fetch CSRF tokens before each Intruder/Repeater request so stateful attacks don't fail.",
            "9. Flag: search Burp history + Intruder results with ctf-tools extract_flags_tool; submit the validated flag.",
        ],
    },
    "crypto": {
        "intro": "Crypto lab — solve ciphers, hashes, or public-key math locally.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → confirm category 'crypto'",
                    "[MCP] ctf-tools recall_knowledge(query=\"<cipher/hash/rsa keywords>\") → prior techniques",
                    "[MCP] ctf-tools select_tools(task=..., category=\"crypto\")",
                ],
            ),
            (
                "Phase 2 — Identify the primitive",
                [
                    "[MCP] ctf-tools file_type(path=<given file>) or paste the raw text into decode_all(data=...) → see valid candidates at once",
                    "[MCP] ctf-tools hash_identify(hash_str=...) → md5/sha*/bcrypt/ntlm?",
                    "[MCP] ctf-tools frequency(text=...) → substitution-cipher hint; vigenere_keylength(ciphertext=...) → IC/Kasiski for Vigenere",
                    "[MCP] ctf-tools decode_chain(data=...) → auto-peel nested base64/hex/url/rot13 layers",
                ],
            ),
            (
                "Phase 3 — Solve",
                [
                    "[MCP] ctf-tools caesar/affine/atbash/rot47/vigenere/railfence/columnar/playfair/hill/morse/brainfuck → apply the matched cipher with its key",
                    "[MCP] ctf-tools xor_brute(data_hex=..., key_length=1) → single-byte XOR; xor_keyed / xor_crib_drag for known keys/cribs",
                    "[MCP] ctf-tools aes_crypt(data_b64=..., key_b64=..., mode=\"CBC\", iv_b64=...) / aes_cbc_bitflip / aes_gcm_nonce_reuse → AES family",
                    "[MCP] ctf-tools rsa_parse_key(...) → n,e,d,p,q; then rsa_decrypt / rsa_fermat / rsa_small_e / rsa_wiener / rsa_common_modulus / rsa_hastad based on the weakness",
                    "[MCP] ctf-tools lcg_solve(states_csv=...) / ecc_bsgs / paillier_decrypt / hash_length_extension → specialized math attacks",
                    "[TERM] openssl enc -d -aes-128-cbc -K <hexkey> -iv <hexiv> -in enc.bin   # manual AES when the tool needs raw files",
                    "[TERM] hashcat -m 0 -a 0 hash.txt wordlists/rockyou.txt   # or ctf-tools external_crypto(tool=\"hashcat\") / hash_crack_common",
                ],
            ),
            (
                "Phase 4 — Flag extraction & validation",
                [
                    "[MCP] ctf-tools extract_flags_tool(text=<decoded output>) → flag candidates from every stage output",
                    "Confirm the flag on the challenge platform; then remember_challenge to store memory + writeup.",
                ],
            ),
        ],
        "terminal": [
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('decode_all', {'data': '<ciphertext>'}))\"",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('xor_brute', {'data_hex': '<hex>', 'key_length': 1}))\"",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('rsa_fermat', {'n': <n>, 'e': 65537, 'ciphertext': <c>}))\"",
            "openssl enc -d -aes-128-cbc -K <hex> -iv <hex> -in enc.bin   # manual AES decrypt",
            "hashcat -m 0 -a 0 hash.txt wordlists/rockyou.txt   # dictionary crack (use ctf-tools external_crypto if hashcat is missing)",
        ],
        "burp": ["Burp not typical for crypto — use the ctf-tools MCP tools, CyberChef, or openssl/hashcat in the terminal."],
    },
    "pwn": {
        "intro": "Binary exploitation lab — reverse the binary, find the bug, write the exploit.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'pwn'",
                    "[MCP] ctf-tools recall_knowledge(query=\"bof/rop/format string/shellcode\") → prior exploit techniques",
                ],
            ),
            (
                "Phase 2 — Static analysis & mitigations",
                [
                    "[TERM] file ./<binary> && checksec --file=./<binary>   # arch, PIE, NX, RELRO, canary",
                    "[MCP] ctf-tools checksec(path=./<binary>) / elf_info(path=...) / strings_extract(path=...) → mitigations + hidden strings",
                    "[TERM] objdump -d -M intel ./<binary> | grep -E 'win|system|flag'   # find win()/system()/flag strings",
                    "[TERM] readelf -a ./<binary> | grep -E 'GNU|SYMBOL|NEEDED'   # symbols, PLT/GOT layout, libc deps",
                ],
            ),
            (
                "Phase 3 — Dynamic analysis & offset discovery",
                [
                    "[MCP] ctf-tools debruijn(length=200) → cyclic pattern; run the binary with it to find the crash offset",
                    "[MCP] ctf-tools debruijn_find(substring=<value from RIP/core dump>) → exact overflow offset",
                    "[TERM] gdb -q ./<binary>   # break on input handler, inspect stack; or r2 ./<binary>",
                    "[MCP] ctf-tools rop_gadgets(path=./<binary>, pattern=\"pop rdi\") → needed ROP gadgets",
                ],
            ),
            (
                "Phase 4 — Exploit",
                [
                    "[MCP] ctf-tools pwn_template(binary_path=..., remote_host=..., remote_port=...) → scaffold the pwntools script",
                    "[MCP] ctf-tools shellcode_x64(kind=\"execve_sh\") / shellcode_multi(arch=..., kind=...) → shellcode for the payload",
                    "[MCP] ctf-tools fmtstr_payload_gen(offset=..., target_addr=..., write_val=...) → format-string arbitrary write",
                    "[TERM] python3 exploit.py   # local: test against ./<binary>; remote: nc <host> <port> / directly in script",
                ],
            ),
            (
                "Phase 5 — Flag & save",
                [
                    "Grab the shell / flag output → extract_flags_tool → remember_challenge.",
                ],
            ),
        ],
        "terminal": [
            "file ./<binary>; checksec --file=./<binary>   # or ctf-tools checksec",
            "objdump -d -M intel ./<binary> | grep -A5 '<win>'",
            "gdb -q ./<binary>   # b *main, r < cyclic input, x/gx $rsp",
            "python3 -c 'from pwn import *; print(cyclic(200))'   # or ctf-tools debruijn",
            "python3 exploit.py   # local test, then switch to remote",
        ],
        "burp": ["Not applicable — use gdb/pwntools instead."],
    },
    "rev": {
        "intro": "Reverse engineering lab — recover the algorithm from a binary and extract the flag.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'rev'",
                    "[MCP] ctf-tools recall_knowledge(query=...)\n",
                ],
            ),
            (
                "Phase 2 — Identify & extract strings",
                [
                    "[TERM] file <binary>; strings -n 5 <binary> | head -50   # first pass",
                    "[MCP] ctf-tools strings_extract(path=<binary>, min_len=4) / elf_info / pe_info / pyc_magic_info",
                    "[MCP] ctf-tools hexdump(path=<binary>, offset=0, length=256) → inspect headers/embedded data",
                ],
            ),
            (
                "Phase 3 — Disassemble / decompile",
                [
                    "[TERM] objdump -d -M intel <binary>   # or ghidra / radare2 (r2 -A <binary>)",
                    "[TERM] strace -f ./<binary>   # syscall trace — reveals hidden I/O, key files",
                    "[MCP] ctf-tools checksec / entropy_map → packed or obfuscated? then upx -d <binary> if UPX-packed",
                ],
            ),
            (
                "Phase 4 — Recover the flag",
                [
                    "Re-implement the check algorithm in Python with the recovered key/transforms",
                    "[MCP] ctf-tools extract_flags_tool(text=<recovered string>) → flag candidates; remember_challenge.",
                ],
            ),
        ],
        "terminal": [
            "file <binary> && strings -n 5 <binary> | head -50",
            "objdump -d -M intel <binary> | grep -i -E 'flag|cmp|strcmp'",
            "strace -f ./<binary>   # trace syscalls",
            "r2 -A <binary>; afl; pdf @ main   # radare2 quick decompile",
            "upx -d <binary>   # if UPX-packed",
        ],
        "burp": ["Not applicable — use ghidra / radare2 / objdump."],
    },
    "forensics": {
        "intro": "Forensics lab — carve, parse, and inspect artifacts (files, pcaps, dumps).",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'forensics'",
                    "[MCP] ctf-tools recall_knowledge(query=\"pcap/carve/exif/volatility\")",
                ],
            ),
            (
                "Phase 2 — Initial triage",
                [
                    "[MCP] ctf-tools triage_file(path=<file>) → file type + entropy + strings + embedded files + flags in ONE pass",
                    "[MCP] ctf-tools file_type(path=...) / hexdump(path=..., length=64) / entropy_map(file_path=...) → hidden-data regions",
                    "[TERM] file <file>; exiftool <file>   # magic bytes + metadata",
                ],
            ),
            (
                "Phase 3 — Extraction",
                [
                    "[TERM] binwalk -e <file>   # embedded archives/firmware (or ctf-tools external_forensics(tool=\"binwalk\"))",
                    "[TERM] foremost -i <file> -o carved/   # carve by magic bytes (or ctf-tools carve)",
                    "[MCP] ctf-tools zlib_hunt(file_path=<file>) → decompress every zlib/gzip stream inside",
                    "[MCP] ctf-tools pcap_http(pcap_path=...) / pcap_dns_exfil(pcap_path=...) / pcap_usb_keystrokes(pcap_path=...) → parse traffic",
                    "[TERM] tshark -r capture.pcap -Y http -T fields -e http.host -e http.request.uri   # raw pcap greps",
                    "[MCP] ctf-tools ntfs_ads(path=...) / zip_fix_pseudo_encrypt(zip_path=...) → Windows/zip tricks",
                ],
            ),
            (
                "Phase 4 — Flag & save",
                [
                    "[MCP] ctf-tools extract_flags_tool on every artifact → remember_challenge.",
                ],
            ),
        ],
        "terminal": [
            "file <file>; exiftool <file>   # type + metadata",
            "binwalk -e <file> && ls _<file>.extracted/   # extract embedded",
            "foremost -i <file> -o carved/   # carve files",
            "tshark -r capture.pcap -Y http -T fields -e http.request.uri -e http.file_data   # HTTP from pcap",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('triage_file', {'path': '<file>'}))\"",
        ],
        "burp": ["Not applicable — use binwalk/foremost/tshark."],
    },
    "stego": {
        "intro": "Steganography lab — hide-and-seek inside images, audio, or GIFs.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'stego'",
                    "[MCP] ctf-tools recall_knowledge(query=\"lsb/jsteg/steghide/gif\")",
                ],
            ),
            (
                "Phase 2 — Metadata & structure",
                [
                    "[MCP] ctf-tools stego_metadata(image_path=<img>) → tEXt/zTXt/iTXt/EXIF strings",
                    "[MCP] ctf-tools stego_png_chunks(image_path=<img>) → unusual chunks, odd IDATs",
                    "[TERM] binwalk <img>; exiftool <img>   # appended payloads + metadata",
                ],
            ),
            (
                "Phase 3 — Extract hidden data",
                [
                    "[MCP] ctf-tools stego_lsb(image_path=<img>, plane=\"lsb\", channel=\"rgb\") → LSB extraction",
                    "[MCP] ctf-tools stego_channel(image_path=<img>, channel=\"R\") / stego_xor_images / stego_compare → channel/visual tricks",
                    "[MCP] ctf-tools stego_jsteg(image_path=<jpg>) / png_fix_ihdr(image_path=<png>) → JPEG DCT / broken-dimension PNGs",
                    "[MCP] ctf-tools stego_gif_frames(gif_path=<gif>) → extract every frame to PNG",
                    "[MCP] ctf-tools stego_audio_wav(wav_path=<wav>) / stego_dtmf_detect(wav_path=<wav>) → audio LSB / DTMF tones",
                    "[TERM] zsteg <img>; steghide extract -sf <img>; stegseek <img> wordlists/rockyou.txt   # or ctf-tools external_stego",
                ],
            ),
            (
                "Phase 4 — Flag & save",
                [
                    "Decode the extracted blob (decode_all) → extract_flags_tool → remember_challenge.",
                ],
            ),
        ],
        "terminal": [
            "zsteg <image>   # LSB/bit-plane scan",
            "steghide extract -sf <image>   # passphrase-less extraction",
            "stegseek <image> wordlists/rockyou.txt   # steghide password crack",
            "binwalk <image>; exiftool <image>   # hidden payloads + metadata",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('stego_lsb', {'image_path': '<image>', 'plane': 'lsb', 'channel': 'rgb'}))\"",
        ],
        "burp": ["Not applicable — use zsteg/steghide/binwalk."],
    },
    "osint": {
        "intro": "OSINT lab — gather open-source intelligence about a target.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'osint'",
                    "[MCP] ctf-tools recall_knowledge(query=\"dns/geolocation/social\")",
                ],
            ),
            (
                "Phase 2 — DNS & passive recon",
                [
                    "[MCP] ctf-tools dns_query(domain=<d>, record=\"ANY\") / dns_reverse(ip=...) / crtsh_subdomains(domain=<d>) → subdomains via CT logs",
                    "[TERM] dig ANY <domain>; whois <domain>; host -t mx <domain>",
                    "[TERM] curl 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value' | sort -u",
                ],
            ),
            (
                "Phase 3 — Geolocation & images",
                [
                    "[MCP] ctf-tools exif_gps_map(image_path=<img>) → GPS coords + maps link",
                    "[MCP] ctf-tools geocode(address=...) / geohash_decode(geohash=...) → find the place",
                    "[MCP] ctf-tools stego_metadata(image_path=<img>) → geotags in EXIF",
                ],
            ),
            (
                "Phase 4 — Flag & save",
                [
                    "Cross-check findings → extract_flags_tool → remember_challenge.",
                ],
            ),
        ],
        "terminal": [
            "dig ANY <domain>; whois <domain>; host -t mx <domain>",
            "curl 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value' | sort -u",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('crtsh_subdomains', {'domain': '<domain>'}))\"",
        ],
        "burp": ["Burp rarely needed — browser devtools + curl usually enough."],
    },
    "misc": {
        "intro": "Misc lab — anything goes: esolangs, jail, sanity checks, multi-layer encodings.",
        "phases": [
            (
                "Phase 1 — Plan & recall",
                [
                    "[MCP] ctf-tools detect_challenge(problem=...) → category 'misc'",
                    "[MCP] ctf-tools recall_knowledge(query=...)",
                ],
            ),
            (
                "Phase 2 — First pass",
                [
                    "[MCP] ctf-tools decode_all(data=<given text>) → every encoding tried at once",
                    "[MCP] ctf-tools decode_chain(data=...) → peel nested base64/hex/url/rot13 layers automatically",
                    "[TERM] file <file>; strings -a <file>; xxd <file> | head",
                ],
            ),
            (
                "Phase 3 — Solve the gimmick",
                [
                    "[MCP] ctf-tools brainfuck(code=...) / morse / decode_zero_width / encode_zero_width → esolang/unicode tricks",
                    "[MCP] ctf-tools extract_flags_tool(text=...) on every stage output — do not assume flag{...}",
                ],
            ),
            (
                "Phase 4 — Flag & save",
                [
                    "[MCP] ctf-tools remember_challenge(...) → memory + writeup.",
                ],
            ),
        ],
        "terminal": [
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('decode_all', {'data': '<blob>'}))\"",
            "file <file>; strings -a <file>; xxd <file> | head",
            "python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('decode_chain', {'data': '<blob>'}))\"",
        ],
        "burp": ["Varies per challenge — start with terminal tools."],
    },
}

# Tool name → concrete reproduction snippet for the "Agent reproduction" block.
TOOL_CMDS = {
    "http_request": "run_tool('http_request', {'url': '<target>', 'method': 'GET', 'headers_csv': 'Cookie: ...'})",
    "browser_agent": "run_tool('browser_agent', {'action': 'full', 'url': '<target>'})",
    "flask_session": "run_tool('flask_session', {'session_cookie': '<cookie>', 'secret': '<SECRET_KEY>', 'action': 'decode'})",
    "chain_tools": "run_tool('chain_tools', {'steps': '[{\"tool\":\"decode_all\",\"data\":\"$data\"},{\"tool\":\"extract_flags_tool\",\"text\":\"$prev\"}]', 'data': '<encoded>'})",
    "sqlite_reader": "run_tool('sqlite_reader', {'path': '<file.db>', 'table': ''})",
    "pdf_analyze": "run_tool('pdf_analyze', {'path': '<file.pdf>', 'object_id': 0})",
    "ecdsa_nonce_reuse": "run_tool('ecdsa_nonce_reuse', {'p': <p>, 'a': <a>, 'b': <b>, 'gx': <gx>, 'gy': <gy>, 'n': <n>, 'r1': <r1>, 's1': <s1>, 'h1': <h1>, 'r2': <r2>, 's2': <s2>, 'h2': <h2>})",
    "mt19937_predict": "run_tool('mt19937_predict', {'outputs_csv': '<624 outputs>', 'predict': 5})",
    "pollard_p1": "run_tool('pollard_p1', {'n': <n>, 'bound': 100000})",
    "pohlig_hellman": "run_tool('pohlig_hellman', {'g': <g>, 'h': <h>, 'p': <p>})",
    "dork_generator": "run_tool('dork_generator', {'domain': '<domain>', 'keywords': 'password,api_key', 'filetype': 'env', 'username': ''})",
    "github_search": "run_tool('github_search', {'query': '<query>', 'limit': 10})",
    "whois_query": "run_tool('whois_query', {'domain': '<domain>'})",
    "jwt_decode": "run_tool('jwt_decode', {'token': '<jwt>'})",
    "jwt_forge": "run_tool('jwt_forge', {'header_json': '{\"alg\":\"none\"}', 'payload_json': '{\"user\":\"admin\"}'})",
    "jwt_key_confusion": "run_tool('jwt_key_confusion', {'token': '<jwt>', 'rsa_public_key_pem': '<pem>'})",
    "sqli_payloads": "run_tool('sqli_payloads', {'kind': 'auth_bypass'})",
    "payload_encoders": "run_tool('payload_encoders', {'payload': \"' OR 1=1-- -\"})",
    "xxe_payloads": "run_tool('xxe_payloads', {'action': 'read_file', 'data': '/etc/passwd'})",
    "ssti_payloads": "run_tool('ssti_payloads', {'engine': 'jinja2', 'command': 'id'})",
    "command_injection_payloads": "run_tool('command_injection_payloads', {'os_type': 'linux', 'command': 'id'})",
    "path_traversal_payloads": "run_tool('path_traversal_payloads', {'target_file': '/etc/passwd', 'depth': 5})",
    "file_upload_bypass": "run_tool('file_upload_bypass', {'filename': 'shell.php', 'content_type': 'image/jpeg'})",
    "idor_payloads": "run_tool('idor_payloads', {'param_name': 'id', 'values': '1,2,3'})",
    "revshell_generator": "run_tool('revshell_generator', {'ip': '<your-ip>', 'port': 4444, 'shell_type': 'bash'})",
    "ssrf_obfuscator": "run_tool('ssrf_obfuscator', {'ip_or_host': '127.0.0.1', 'port': 80})",
    "graphql_introspect": "run_tool('graphql_introspect', {'url': '<target>/graphql'})",
    "php_filter_chain": "run_tool('php_filter_chain', {'resource': 'flag.php', 'action': 'base64'})",
    "oast_payload": "run_tool('oast_payload', {'domain': '<oast-domain>', 'keyword': '{{uname}}'})",
    "deserialization_payloads": "run_tool('deserialization_payloads', {'format': 'php', 'command': 'id'})",
    "decode_all": "run_tool('decode_all', {'data': '<ciphertext>'})",
    "decode_chain": "run_tool('decode_chain', {'data': '<blob>', 'max_depth': 8})",
    "decode_cascade": "run_tool('decode_cascade', {'data': '<blob>', 'max_depth': 8})",
    "decode_base": "run_tool('decode_base', {'encoded': '<str>', 'base': 64})",
    "decode_base45": "run_tool('decode_base45', {'encoded': '<str>'})",
    "decode_base91": "run_tool('decode_base91', {'encoded': '<str>'})",
    "decode_zero_width": "run_tool('decode_zero_width', {'text': '<text>'})",
    "encode_zero_width": "run_tool('encode_zero_width', {'secret': '<secret>', 'cover_text': '<cover>'})",
    "encode_url": "run_tool('encode_url', {'text': '<text>', 'decode': True})",
    "encode_html_entities": "run_tool('encode_html_entities', {'text': '<text>', 'decode': True})",
    "encode_unicode_escapes": "run_tool('encode_unicode_escapes', {'text': '<text>', 'decode': True})",
    "caesar": "run_tool('caesar', {'text': '<cipher>', 'shift': -1})",
    "affine": "run_tool('affine', {'text': '<cipher>'})",
    "atbash": "run_tool('atbash', {'text': '<cipher>'})",
    "bacon": "run_tool('bacon', {'text': '<a/b>', 'variant': '24'})",
    "beaufort": "run_tool('beaufort', {'ciphertext': '<cipher>', 'key': '<key>'})",
    "morse": "run_tool('morse', {'text': '<morse>', 'decode': True})",
    "rot47": "run_tool('rot47', {'text': '<cipher>'})",
    "vigenere": "run_tool('vigenere', {'ciphertext': '<cipher>', 'key': '<key>', 'decrypt': True})",
    "vigenere_keylength": "run_tool('vigenere_keylength', {'ciphertext': '<cipher>', 'max_len': 20})",
    "columnar": "run_tool('columnar', {'ciphertext': '<cipher>', 'key': '<key>', 'decrypt': True})",
    "railfence": "run_tool('railfence', {'text': '<cipher>', 'rails': 3, 'decrypt': True})",
    "playfair": "run_tool('playfair', {'ciphertext': '<cipher>', 'key': '<key>'})",
    "hill": "run_tool('hill', {'ciphertext': '<cipher>', 'a': 1, 'b': 2, 'c': 3, 'd': 4})",
    "frequency": "run_tool('frequency', {'text': '<cipher>'})",
    "brainfuck": "run_tool('brainfuck', {'code': '<bf-code>'})",
    "hash_generate": "run_tool('hash_generate', {'text': '<text>', 'algorithm': 'md5'})",
    "hash_identify": "run_tool('hash_identify', {'hash_str': '<hash>'})",
    "hash_crack_common": "run_tool('hash_crack_common', {'hash_hex': '<hash>', 'wordlist_path': 'wordlists/rockyou.txt'})",
    "hash_length_extension": "run_tool('hash_length_extension', {'original_data': '<data>', 'append_data': '<append>', 'original_hash': '<hash>', 'key_length': 16})",
    "xor_keyed": "run_tool('xor_keyed', {'data_hex': '<hex>', 'key_hex': '<hex>'})",
    "xor_brute": "run_tool('xor_brute', {'data_hex': '<hex>', 'key_length': 1})",
    "xor_crib_drag": "run_tool('xor_crib_drag', {'ct1_hex': '<hex>', 'crib': 'flag{'})",
    "aes_crypt": "run_tool('aes_crypt', {'data_b64': '<b64>', 'key_b64': '<b64>', 'mode': 'CBC', 'iv_b64': '<b64>'})",
    "aes_cbc_bitflip": "run_tool('aes_cbc_bitflip', {'original': '<pt>', 'target': '<new>', 'block_hex': '<hex>', 'block_index': 0})",
    "aes_gcm_nonce_reuse": "run_tool('aes_gcm_nonce_reuse', {'ct1_hex': '<hex>', 'ct2_hex': '<hex>'})",
    "rsa_decrypt": "run_tool('rsa_decrypt', {'n': <n>, 'e': <e>, 'ciphertext': <c>})",
    "rsa_fermat": "run_tool('rsa_fermat', {'n': <n>, 'e': 65537, 'ciphertext': <c>})",
    "rsa_small_e": "run_tool('rsa_small_e', {'n': <n>, 'e': 3, 'ciphertext': <c>})",
    "rsa_wiener": "run_tool('rsa_wiener', {'n': <n>, 'e': <e>, 'ciphertext': <c>})",
    "rsa_common_modulus": "run_tool('rsa_common_modulus', {'n': <n>, 'e1': <e1>, 'e2': <e2>, 'c1': <c1>, 'c2': <c2>})",
    "rsa_hastad": "run_tool('rsa_hastad', {'ciphertexts_csv': '<c1,c2,c3>', 'moduli_csv': '<n1,n2,n3>', 'e': 3})",
    "rsa_parse_key": "run_tool('rsa_parse_key', {'key_data_or_path': '<key.pem>'})",
    "lcg_solve": "run_tool('lcg_solve', {'states_csv': '<x0,x1,x2>'})",
    "ecc_point_ops": "run_tool('ecc_point_ops', {'px': <x>, 'py': <y>, 'a': 2, 'b': 2, 'p': <p>, 'scalar': <k>})",
    "ecc_bsgs": "run_tool('ecc_bsgs', {'px': <x>, 'py': <y>, 'qx': <x>, 'qy': <y>, 'a': 2, 'p': <p>, 'bound': 100000})",
    "paillier_keygen": "run_tool('paillier_keygen', {'bits': 32})",
    "paillier_decrypt": "run_tool('paillier_decrypt', {'ciphertext': <c>, 'p': <p>, 'q': <q>})",
    "stego_lsb": "run_tool('stego_lsb', {'image_path': '<img>', 'plane': 'lsb', 'channel': 'rgb'})",
    "stego_metadata": "run_tool('stego_metadata', {'image_path': '<img>'})",
    "stego_channel": "run_tool('stego_channel', {'image_path': '<img>', 'channel': 'R'})",
    "stego_png_chunks": "run_tool('stego_png_chunks', {'image_path': '<img>'})",
    "stego_gif_frames": "run_tool('stego_gif_frames', {'gif_path': '<gif>', 'out_dir': 'gif_frames'})",
    "stego_compare": "run_tool('stego_compare', {'path_a': '<a>', 'path_b': '<b>'})",
    "stego_xor_images": "run_tool('stego_xor_images', {'path_a': '<a>', 'path_b': '<b>'})",
    "stego_jsteg": "run_tool('stego_jsteg', {'image_path': '<jpg>', 'max_bytes': 512})",
    "stego_audio_wav": "run_tool('stego_audio_wav', {'wav_path': '<wav>', 'bit_plane': 0})",
    "stego_dtmf_detect": "run_tool('stego_dtmf_detect', {'wav_path': '<wav>'})",
    "png_fix_ihdr": "run_tool('png_fix_ihdr', {'image_path': '<png>'})",
    "file_type": "run_tool('file_type', {'path': '<file>'})",
    "hexdump": "run_tool('hexdump', {'path': '<file>', 'offset': 0, 'length': 256})",
    "strings_extract": "run_tool('strings_extract', {'path': '<file>', 'min_len': 4})",
    "entropy_map": "run_tool('entropy_map', {'file_path': '<file>', 'block_size': 4096})",
    "carve": "run_tool('carve', {'file_path': '<file>', 'out_dir': 'carved'})",
    "zlib_hunt": "run_tool('zlib_hunt', {'file_path': '<file>'})",
    "triage_file": "run_tool('triage_file', {'path': '<file>'})",
    "pcap_http": "run_tool('pcap_http', {'pcap_path': '<pcap>'})",
    "pcap_dns_exfil": "run_tool('pcap_dns_exfil', {'pcap_path': '<pcap>'})",
    "pcap_usb_keystrokes": "run_tool('pcap_usb_keystrokes', {'pcap_path': '<pcap>'})",
    "ntfs_ads": "run_tool('ntfs_ads', {'path': '<path>'})",
    "zip_fix_pseudo_encrypt": "run_tool('zip_fix_pseudo_encrypt', {'zip_path': '<zip>'})",
    "checksec": "run_tool('checksec', {'path': '<binary>'})",
    "elf_info": "run_tool('elf_info', {'path': '<binary>'})",
    "pe_info": "run_tool('pe_info', {'path': '<pe>'})",
    "rop_gadgets": "run_tool('rop_gadgets', {'path': '<binary>', 'pattern': 'pop rdi'})",
    "debruijn": "run_tool('debruijn', {'length': 200})",
    "debruijn_find": "run_tool('debruijn_find', {'substring': '<crash-value>'})",
    "fmtstr_payload_gen": "run_tool('fmtstr_payload_gen', {'offset': 6, 'target_addr': '0x...', 'write_val': '0x...', 'arch': '64'})",
    "shellcode_x64": "run_tool('shellcode_x64', {'kind': 'execve_sh'})",
    "shellcode_multi": "run_tool('shellcode_multi', {'arch': 'x64', 'kind': 'execve_sh'})",
    "pwn_template": "run_tool('pwn_template', {'binary_path': './vuln', 'remote_host': '<host>', 'remote_port': 1337})",
    "pyc_magic_info": "run_tool('pyc_magic_info', {'pyc_path_or_hex': '<file.pyc>'})",
    "extract_flags_tool": "run_tool('extract_flags_tool', {'text': '<output>'})",
    "dns_query": "run_tool('dns_query', {'domain': '<domain>', 'record': 'ANY'})",
    "dns_reverse": "run_tool('dns_reverse', {'ip': '<ip>'})",
    "crtsh_subdomains": "run_tool('crtsh_subdomains', {'domain': '<domain>', 'limit': 100})",
    "cve_research": "run_tool('cve_research', {'problem': '<problem + software + version>'})",
    "cve_lookup": "run_tool('cve_lookup', {'cve_id': 'CVE-YYYY-NNNNN'})",
    "cve_search": "run_tool('cve_search', {'software': '<product>', 'version': '<version>'})",
    "geocode": "run_tool('geocode', {'address': '<place>'})",
    "geohash_decode": "run_tool('geohash_decode', {'geohash': '<hash>'})",
    "exif_gps_map": "run_tool('exif_gps_map', {'image_path': '<img>'})",
    "external_recon": "run_tool('external_recon', {'tool': 'nmap', 'args': '-sV -sC <target>'})",
    "external_web": "run_tool('external_web', {'tool': 'ffuf', 'args': '-u http://<target>/FUZZ -w wordlists/common.txt'})",
    "external_crypto": "run_tool('external_crypto', {'tool': 'hashcat', 'args': '-m 0 -a 0 hash.txt wordlists/rockyou.txt'})",
    "external_forensics": "run_tool('external_forensics', {'tool': 'binwalk', 'args': '-e <file>'})",
    "external_stego": "run_tool('external_stego', {'tool': 'steghide', 'args': 'extract -sf <img>'})",
    "external_rev": "run_tool('external_rev', {'tool': 'radare2', 'args': '-A <binary>'})",
    "external_available": "run_tool('external_available', {})",
    "detect_challenge": "run_tool('detect_challenge', {'problem': '<problem statement>'})",
    "analyze_target": "run_tool('analyze_target', {'target': '<target>'})",
    "select_tools": "run_tool('select_tools', {'task': '<keywords>', 'category': '<cat>'})",
    "recall_knowledge": "run_tool('recall_knowledge', {'query': '<keywords>'})",
    "remember_challenge": "run_tool('remember_challenge', {'title': '<title>', 'category': '<cat>', 'tool': '<tools>', 'flag': '<flag>'})",
    "autonomous_solve": "run_tool('autonomous_solve', {'problem_statement': '<problem>'})",
    "get_agent_status": "run_tool('get_agent_status', {})",
}


def field(lines: list[str], key: str) -> str:
    for l in lines:
        if l.lstrip("- ").startswith(key):
            return l.split(":", 1)[1].strip()
    return ""


def section_text(lines: list[str], header: str) -> str:
    """Return the body text under a '## <header>' section (memory file format)."""
    out: list[str] = []
    in_sec = False
    for l in lines:
        if l.startswith("## "):
            in_sec = l[3:].strip().lower() == header.lower()
            continue
        if in_sec:
            if l.startswith("#"):
                break
            out.append(l)
    return "\n".join(out).strip()


def parse_runs(lines: list[str]) -> list[tuple[str, str, str, str]]:
    """Parse '## Approach' run lines: - `tool` (args_json) → ok|failed [out: snippet].

    Returns (tool, args_json, status, out_snippet) tuples; out is "" when absent.
    """
    runs: list[tuple[str, str, str, str]] = []
    for l in lines:
        m = re.match(r"- `([\w.]+)`\s*(?:\((.*?)\))?\s*→\s*(\w+)", l)
        if m:
            runs.append((m.group(1), m.group(2) or "", m.group(3), ""))
            continue
        om = re.match(r"^\s+out:\s*(.+)$", l)
        if om and runs:
            tool, args, ok, _ = runs[-1]
            runs[-1] = (tool, args, ok, om.group(1).strip())
    return runs


def _args_obj(args_json: str) -> dict:
    """Parse run args JSON into a dict ({} on failure)."""
    if not args_json:
        return {}
    try:
        obj = json.loads(args_json)
        return obj if isinstance(obj, dict) else {}
    except (ValueError, TypeError):
        return {}


def fmt_args(args_json: str) -> str:
    """Pretty-print run args (JSON) for the writeup."""
    if not args_json:
        return ""
    try:
        obj = json.loads(args_json)
        if not isinstance(obj, dict):
            return args_json
        parts = []
        for k, v in obj.items():
            vs = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
            if len(vs) > 80:
                vs = vs[:77] + "..."
            parts.append(f"{k}={vs}")
        return ", ".join(parts)
    except (ValueError, TypeError):
        return args_json[:120]


def tool_cmd(tool: str) -> str:
    val = TOOL_CMDS.get(tool)
    if val:
        if val.startswith("run_tool("):
            return f"python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print({val})\""
        return f"python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool({val}))\""
    return f"python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('{tool}', {{...}}))\""  # noqa: E501


def _py_literal(obj) -> str:
    """Python literal with single quotes (shell copy-paste friendly) for run args."""
    if isinstance(obj, dict):
        return "{" + ", ".join(f"'{k}': {_py_literal(v)}" for k, v in obj.items()) + "}"
    if isinstance(obj, list):
        return "[" + ", ".join(_py_literal(x) for x in obj) + "]"
    if isinstance(obj, str):
        return "'" + obj.replace("'", "\\'") + "'"
    if obj is True:
        return "True"
    if obj is False:
        return "False"
    if obj is None:
        return "None"
    return json.dumps(obj)


def run_tool_cmd(tool: str, args_json: str) -> str:
    """Real reproduction command for a recorded run, with its actual args."""
    args = _args_obj(args_json)
    if args:
        return f"python -c \"import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('{tool}', {_py_literal(args)}))\""
    return tool_cmd(tool)


def http_to_curl(args: dict) -> str:
    """Convert http_request run args into a real, copy-pasteable curl command."""
    url = args.get("url") or "http://<target>/"
    method = (args.get("method") or "GET").upper()
    parts = ["curl", "-s", "-i"]
    if method not in ("GET", "HEAD"):
        parts += ["-X", method]
    for h in (args.get("headers_csv") or "").splitlines():
        h = h.strip()
        if h:
            parts += ["-H", shlex.quote(h)]
    data = args.get("data") or ""
    if data:
        parts += ["--data", shlex.quote(data)]
    parts.append(shlex.quote(url))
    return " ".join(parts)


def http_to_burp(args: dict) -> str:
    """Convert http_request run args into a raw Burp Suite Repeater request block."""
    url = args.get("url") or "http://<target>/"
    method = (args.get("method") or "GET").upper()
    parts = urlsplit(url if "://" in url else "http://" + url)
    host = parts.netloc or "<target>"
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    has_ct = False
    for h in (args.get("headers_csv") or "").splitlines():
        h = h.strip()
        if h:
            lines.append(h)
            if h.lower().startswith("content-type"):
                has_ct = True
    data = args.get("data") or ""
    if data:
        if not has_ct:
            lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(data.encode('utf-8'))}")
        lines.append("")
        lines.append(data)
    else:
        lines.append("")
    return "\n".join(lines)


# Tool → (step title, technique explanation, takeaway) for step-by-step rendering.
STEP_META: dict[str, tuple[str, str, str]] = {
    "http_request": ("HTTP request to target", "Fetch/replay the HTTP request; capture status, headers, cookies, body.", "Headers/cookies/body here feed the next exploitation step."),
    "browser_agent": ("Browser recon (JS-rendered page)", "Headless Chrome renders the page and dumps DOM text, forms, links, security headers.", "JS-rendered flags/forms only appear after JavaScript runs."),
    "flask_session": ("Flask session cookie", "Decode/forge the itsdangerous cookie (base64(zlib(json)).timestamp.signature) with the SECRET_KEY.", "A leaked SECRET_KEY means full session forgery."),
    "chain_tools": ("Tool pipeline", "Run multiple tools back-to-back, passing each output into the next via $prev/$data placeholders.", "One call replaces a whole multi-step solve."),
    "sqlite_reader": ("SQLite dump", "List tables and dump rows; scan every field for flag patterns.", "Flags hide in DB rows far more often than you'd think."),
    "pdf_analyze": ("PDF analysis", "Parse objects, decompress FlateDecode streams, dump metadata.", "Flags live inside compressed streams / JS actions."),
    "ecdsa_nonce_reuse": ("ECDSA nonce reuse", "Recover k and the private key d from two signatures sharing k.", "The classic 'same k twice' signing bug."),
    "mt19937_predict": ("MT19937 state recovery", "Untemper 624 outputs to rebuild the generator state and predict the future.", "Any PRNG-based 'random' gate falls to this."),
    "pollard_p1": ("Pollard p-1 factorization", "Factor n when one prime has a smooth p-1.", "Smoothness is the crypto author's most common shortcut."),
    "pohlig_hellman": ("Pohlig-Hellman discrete log", "Solve g^x = h mod p by decomposing p-1 into small prime powers.", "Small-factor group order = instant dlog."),
    "dork_generator": ("OSINT dork generation", "Build Google/GitHub/Shodan search queries for a target.", "Recon starts with the right search strings."),
    "github_search": ("GitHub code search", "Search public code (grep.app) for leaked keys/.env/mentions.", "Leaked credentials often contain the flag or next hop."),
    "whois_query": ("WHOIS lookup", "Query registration/ownership info on port 43, following referrals.", "Infrastructure mapping for OSINT challenges."),
    "detect_challenge": ("Challenge analysis", "Auto-detect category + platform and build the plan.", "Confirms which tool family applies."),
    "recall_knowledge": ("Memory recall", "Search past challenges/skills for the same technique.", "Prior writeups often give the exact shortcut."),
    "cve_research": ("CVE research", "Resolve explicit CVE IDs / infer CVEs from software+version (NVD + local KB).", "Maps the problem to an exact CVE + exploit plan."),
    "cve_lookup": ("CVE lookup", "Fetch severity, description, references, PoC links for one CVE.", "Confirms whether the CVE is worth pursuing."),
    "cve_search": ("CVE search by product", "Search NVD keyword for a product/version.", "Broadens the CVE set for the detected software."),
    "sqli_payloads": ("SQL injection payloads", "Generate auth-bypass/union/boolean/time payloads.", "Feed the payloads into http_request or Burp Repeater."),
    "payload_encoders": ("WAF-bypass encoding", "Encode the injection into url/hex/unicode/charcode variants.", "Tries every encoding so one slips past the filter."),
    "jwt_decode": ("JWT decode", "Decode header+payload without verifying the signature.", "Reads the claims to find the role/token shape."),
    "jwt_forge": ("JWT forge", "Forge a token with alg none (empty secret) or HS256.", "Admin tokens are the classic web-flag win."),
    "jwt_key_confusion": ("JWT algorithm confusion (CVE-2015-9235)", "Sign a forged token with the RSA public key as HMAC secret.", "Public key is public — so the signature is forgeable."),
    "extract_flags_tool": ("Flag extraction", "Scan every output for any flag shape (word{...}, hex, flag: xxx).", "Never assume flag{...} — formats differ per platform."),
    "xss_payloads": ("XSS payloads", "Generate XSS payloads for the detected context.", "Test in browser_agent / Burp Repeater."),
    "sqli": ("SQL injection", "SQLi payload generation + detection.", "Probe each parameter with auth-bypass payloads first."),
    "decode_all": ("Encoding sweep", "Try every common encoding (base64/hex/url/html/binary/rot13...).", "One-shot answer for single-layer encodings."),
    "decode_chain": ("Multi-layer decoding", "Recursively peel nested base64/hex/url/rot13/zlib until plaintext/flag.", "For 'decode me N times' challenges."),
    "decode_base": ("Base decode", "Decode a number/string from base 2..85.", "Handles exotic bases (58/62/85)."),
    "caesar": ("Caesar shift", "Brute force all 25 shifts ranked by English score.", "Auto-ranks the readable plaintext."),
    "xor_brute": ("XOR brute force", "Single-byte or multi-byte key recovery by frequency.", "Classic single-byte XOR flag extraction."),
    "xor_crib_drag": ("XOR crib drag / KPA", "Crib-drag against one or two ciphertexts sharing a key.", "Recovers plaintext when a crib like 'flag{' is known."),
    "xor_keyed": ("XOR with known key", "XOR hex data with a hex key.", "Direct decode when the key is known."),
    "aes_crypt": ("AES decrypt/encrypt", "ECB/CBC/CFB/OFB/CTR/GCM with auto PKCS7 handling.", "Core for AES cookie/ciphertext challenges."),
    "aes_cbc_bitflip": ("CBC bit-flip", "Flip a cipher block so the next plaintext becomes the target.", "Modify an encrypted cookie value without the key."),
    "aes_gcm_nonce_reuse": ("GCM nonce reuse", "Recover plaintext from ct1^ct2 when a nonce is reused.", "ct1^ct2 = pt1^pt2 — trivial flag recovery."),
    "hash_identify": ("Hash identification", "Identify md5/sha*/bcrypt/ntlm from length+prefix.", "Pick the right cracker afterwards."),
    "hash_crack_common": ("Hash cracking", "Dictionary-crack md5/sha1/sha256/sha512.", "Fast win for weak passwords."),
    "hash_length_extension": ("Hash length extension", "Forge H(key||data) with appended payload.", "For cookie/HMAC signature challenges."),
    "rsa_parse_key": ("RSA key parse", "Extract n, e, d, p, q from PEM/OpenSSH keys.", "Gives p/q directly when a private key leaks."),
    "rsa_decrypt": ("RSA decrypt", "Decrypt with p/q or d; trial-division fallback.", "Direct solve when factors are known/small."),
    "rsa_fermat": ("RSA Fermat factorization", "Factor n when p,q are close.", "The classic 'close primes' CTF attack."),
    "rsa_small_e": ("RSA small exponent", "Take the e-th root when m^e < n.", "e=3 with tiny messages = instant plaintext."),
    "rsa_wiener": ("RSA Wiener attack", "Recover small private d from continued fractions.", "For tiny d challenges."),
    "rsa_common_modulus": ("RSA common modulus", "Recover m from c1,c2 with coprime e1,e2 and same n.", "Extended Euclid on e1,e2 → m = c1^a * c2^b."),
    "rsa_hastad": ("RSA broadcast (Håstad)", "CRT-combine identical messages sent with small e.", "e=3 with 3 ciphertexts → cube root of CRT."),
    "lcg_solve": ("LCG parameter recovery", "Recover a,c,m from consecutive outputs and predict.", "For PRNG prediction challenges."),
    "ecc_bsgs": ("ECC baby-step giant-step", "Discrete log on small-subgroup curves.", "Recover k from k*P = Q."),
    "ecc_point_ops": ("ECC point arithmetic", "Scalar multiplication / point addition on y²=x³+ax+b.", "Verify or build curve math by hand."),
    "paillier_decrypt": ("Paillier decrypt", "Decrypt with p,q (small challenges).", "Homomorphic-crypto challenges."),
    "file_type": ("File type detection", "Magic bytes + entropy stats.", "Confirms what the file really is."),
    "strings_extract": ("String extraction", "Printable strings (ascii/utf16).", "Flags often sit in plaintext strings."),
    "hexdump": ("Hexdump", "Offset + hex + ascii columns.", "Spot odd bytes / embedded structures."),
    "entropy_map": ("Entropy map", "Per-block entropy to find hidden/encrypted regions.", "High-entropy tail = appended encrypted blob."),
    "carve": ("File carving", "Extract embedded PNG/JPEG/ZIP/PDF/ELF by signature.", "Hidden archives live inside the carrier."),
    "zlib_hunt": ("zlib stream hunt", "Decompress every zlib/gzip stream in the file.", "Compressed flags are found this way."),
    "triage_file": ("Master triage", "file type + entropy + strings + embedded files + flags in one pass.", "Fastest first move on any artifact."),
    "pcap_http": ("PCAP HTTP extraction", "Per-stream HTTP payloads & printable text.", "Flags ride inside HTTP flows."),
    "pcap_dns_exfil": ("PCAP DNS exfil", "Recover exfiltrated subdomain labels.", "flag.a.b.c.dns → reassemble labels."),
    "pcap_usb_keystrokes": ("PCAP USB keystrokes", "Reconstruct typed text from HID packets.", "Keyboard pcap = typed flag."),
    "stego_metadata": ("Metadata extraction", "PNG text chunks, EXIF, basic info.", "Flags hide in tEXt/iTXt/EXIF."),
    "stego_png_chunks": ("PNG chunk dump", "All chunks with lengths + previews.", "Odd chunks = hidden data."),
    "stego_lsb": ("LSB extraction", "Extract bit-plane data (lsb/msb, channel, bit order).", "The stego classic."),
    "stego_channel": ("Channel isolation", "Isolate R/G/B/A to grayscale.", "Flags written in one channel."),
    "stego_xor_images": ("Image XOR", "Pixel-wise XOR of two images.", "Spot the difference between near-identical images."),
    "stego_compare": ("Image compare", "Coordinates of differing pixels.", "Find the altered region."),
    "stego_jsteg": ("JSteg extraction", "LSBs of quantized DCT AC coefficients (luma, zigzag).", "JPEG stego classic."),
    "stego_gif_frames": ("GIF frame split", "Extract every frame to PNG.", "Flag hides in a single frame."),
    "stego_audio_wav": ("WAV LSB extraction", "Bit-plane extraction from uncompressed WAV.", "Audio stego classic."),
    "stego_dtmf_detect": ("DTMF tone decode", "Decode phone keypad tones from WAV.", "Phone-number flags."),
    "png_fix_ihdr": ("PNG IHDR fix", "Brute width/height until CRC32 matches.", "Broken-dimension PNGs."),
    "checksec": ("Binary mitigations", "NX, PIE, RELRO, canary, fortify.", "Choose the exploit strategy."),
    "elf_info": ("ELF info", "Class, endianness, machine, entry point, sections.", "Quick binary orientation."),
    "pe_info": ("PE info", "Headers, sections, ASLR/DEP/CFG mitigations.", "Windows binary orientation."),
    "debruijn": ("De Bruijn pattern", "Generate a cyclic pattern to find the overflow offset.", "Feed into the binary, crash, then debruijn_find."),
    "debruijn_find": ("De Bruijn offset", "Locate the crash substring → exact offset.", "Offset = distance to RIP."),
    "rop_gadgets": ("ROP gadget search", "Find pop rdi / pop rsi / syscall gadgets in the binary.", "Assemble the ROP chain."),
    "fmtstr_payload_gen": ("Format string payload", "Generate %c%$n arbitrary-write payloads.", "Write to GOT/return address."),
    "shellcode_x64": ("x86_64 shellcode", "Null-free execve('/bin/sh') or XOR-encrypted variant.", "Direct shellcode for shellcoding challenges."),
    "shellcode_multi": ("Multi-arch shellcode", "Linux x64/x86, ARM32, AArch64, Windows x64.", "For exotic architectures."),
    "pwn_template": ("Pwn script template", "pwntools scaffold (local + remote).", "Start every exploit from here."),
    "pyc_magic_info": ("Pyc version fingerprint", "Python version from .pyc magic.", "Choose the right decompiler."),
    "revshell_generator": ("Reverse shell generator", "bash/nc/python3/php/powershell one-liners.", "Fire a listener, drop the shell."),
    "ssrf_obfuscator": ("SSRF obfuscation", "Decimal/hex/octal/IPv6 IP forms + cloud metadata URLs.", "Bypass IP filters."),
    "ssti_payloads": ("SSTI payloads", "Jinja2/Twig/Smarty/SpEL/Thymeleaf/EJS/ERB RCE.", "Probe {{7*7}} first, then escalate."),
    "xxe_payloads": ("XXE payloads", "File read, SSRF, OOB exfil, error-based, parameter entities.", "Classic /etc/passwd read."),
    "command_injection_payloads": ("Command injection", "Linux/Windows payloads with chaining + bypasses.", "Probe with id + sleep."),
    "path_traversal_payloads": ("Path traversal", "Depth-controlled LFI/RFI payloads + null byte.", "Read /etc/passwd."),
    "file_upload_bypass": ("Upload bypass", "Double ext, null byte, content-type spoof, magic bytes.", "Get a shell.php executed."),
    "idor_payloads": ("IDOR payloads", "Enumerate ids / object references.", "Try 1,2,3... and signed variants."),
    "deserialization_payloads": ("Deserialization payloads", "PHP/Python/Java/Ruby/Node object injection.", "For cookie/param deserialization bugs."),
    "php_filter_chain": ("PHP filter chain", "php://filter wrappers, data URIs, type-juggling hashes.", "Read source when direct include fails."),
    "graphql_introspect": ("GraphQL introspection", "Dump the schema via __schema query.", "Find hidden queries/mutations."),
    "oast_payload": ("OAST payloads", "HTTP/DNS callback templates for blind injections.", "Detect blind SSRF/XXE/SSTI/SQLi."),
    "dns_query": ("DNS query", "A/AAAA/MX/NS/TXT/CNAME/SOA records.", "TXT records can hold flags."),
    "dns_reverse": ("Reverse DNS", "PTR lookup on an IP.", "Map infrastructure."),
    "crtsh_subdomains": ("Subdomain enumeration", "Certificate Transparency via crt.sh.", "Passive subdomain discovery."),
    "geocode": ("Geocoding", "Forward/reverse Nominatim lookup.", "OSINT place-name flags."),
    "geohash_decode": ("Geohash decode", "Bounds + center + neighbors.", "Geohash = coordinate flag."),
    "exif_gps_map": ("EXIF GPS extraction", "Lat/Long + maps links from image EXIF.", "Photo-location OSINT."),
    "external_web": ("External web tool", "ffuf/gobuster/sqlmap/nikto/wfuzz wrapper.", "Automated web scanning."),
    "external_recon": ("External recon tool", "nmap/masscan/whatweb/dnsrecon wrapper.", "Port + service fingerprint."),
    "external_forensics": ("External forensics tool", "binwalk/exiftool/foremost/tshark wrapper.", "Heavy-duty artifact analysis."),
    "external_stego": ("External stego tool", "steghide/zsteg/outguess/stegseek wrapper.", "Brute passphrase + scans."),
    "external_crypto": ("External crypto tool", "hashcat/john/RsaCtfTool/xortool wrapper.", "GPU cracking & RSA attacks."),
    "external_rev": ("External rev tool", "objdump/readelf/radare2/gdb/ROPgadget wrapper.", "Disassembly & debugging."),
    "external_available": ("External tool inventory", "List installed external CLIs.", "Know what you can shell out to."),
    "select_tools": ("Tool selection", "Keyword-match the task against the tool arsenal.", "Pick the right tool quickly."),
    "optimize_parameters": ("Parameter check", "Validate args against the tool schema.", "Avoid malformed calls."),
    "analyze_target": ("Target analysis", "Decision engine: category + platform + tool chain.", "First move for any target."),
    "autonomous_solve": ("Autonomous solve", "Plan → recall → iterate → extract flag → learn.", "Let the agent grind the challenge."),
    "remember_challenge": ("Save memory & skill", "Persist memory + skill + POC writeup.", "Auto-learn for future challenges."),
    "get_agent_status": ("Agent status", "Learning statistics + tool success rates.", "Track what the agent learned."),
}


def step_meta(tool: str) -> tuple[str, str, str]:
    return STEP_META.get(tool, (tool.replace("_", " ").title(), "Run the ctf-tools tool to analyze the data.", "Check the output for the flag or the next clue."))


def run_step_md(run: tuple[str, str, str, str], category: str, idx: int) -> str:
    """Render one recorded run as a full step: title, technique, terminal cmd, Burp block, evidence, takeaway."""
    tool, args_json, ok, out = run
    title, technique, takeaway = step_meta(tool)
    args = _args_obj(args_json)
    flag = "✓" if ok == "ok" else "✗"
    out_lines = [f"### Step {idx} — {flag} {title}"]
    out_lines.append("")
    out_lines.append(f"**Teknik:** {technique}")
    if args:
        out_lines.append("")
        out_lines.append(f"**Args terekam:** `{fmt_args(args_json)}`")
    out_lines.append("")
    if tool == "http_request" and args.get("url"):
        out_lines.append("**Terminal (curl):**")
        out_lines.append("")
        out_lines.append("```bash")
        out_lines.append(http_to_curl(args))
        out_lines.append("```")
        if category == "web":
            out_lines.append("")
            out_lines.append("**Burp Suite — Repeater (paste request ini):**")
            out_lines.append("")
            out_lines.append("```http")
            out_lines.append(http_to_burp(args))
            out_lines.append("```")
    else:
        out_lines.append("**Terminal (ctf-kit CLI):**")
        out_lines.append("")
        out_lines.append("```bash")
        out_lines.append(run_tool_cmd(tool, args_json))
        out_lines.append("```")
    if out:
        out_lines.append("")
        out_lines.append("**Evidence (output aktual):**")
        out_lines.append("")
        out_lines.append("```")
        out_lines.append(out[:600])
        out_lines.append("```")
    out_lines.append("")
    out_lines.append(f"**Takeaway:** {takeaway}")
    out_lines.append("")
    return "\n".join(out_lines)


def attack_chain_md(runs: list[tuple[str, str, str, str]], tools: list[str]) -> str:
    """Summarize the attack chain from the recorded runs (or the tools field)."""
    lines = []
    if runs:
        for i, (tool, args_json, ok, _) in enumerate(runs, 1):
            title, _, _ = step_meta(tool)
            args = _args_obj(args_json)
            extra = ""
            if tool == "http_request" and args.get("url"):
                extra = f" → `{args['url']}`"
            lines.append(f"{i}. **{title}**{extra} — {'✓' if ok == 'ok' else '✗'} `{tool}`")
    else:
        for i, t in enumerate(tools, 1):
            title, _, _ = step_meta(t)
            lines.append(f"{i}. **{title}** — `{t}`")
    return "\n".join(lines)


def generate_writeup(memory_file: Path, steps: str = "") -> Path:
    lines = memory_file.read_text(encoding="utf-8", errors="replace").splitlines()
    title = next((l[2:] for l in lines if l.startswith("# ")), memory_file.stem)
    platform = field(lines, "platform:") or "unknown"
    category = field(lines, "category:") or "misc"
    tools = [t.strip() for t in field(lines, "tools:").split(",") if t.strip()]
    flag = field(lines, "flag:")
    runs = parse_runs(lines)
    lessons = section_text(lines, "What worked / lessons")
    evidence = section_text(lines, "Evidence snippet") or section_text(lines, "Result")
    evidence_lines = [l for l in evidence.splitlines() if l.strip() != "```"]
    evidence = "\n".join(evidence_lines).strip()
    if lessons.startswith("_") or lessons == "":
        lessons = "_(no lessons captured — add what worked: exact tool, params, and why it succeeded)_"

    pb = PLAYBOOKS.get(category, PLAYBOOKS["misc"])

    # ---- Step-by-step: explicit override wins; else real recorded runs; else playbook ----
    if steps.strip():
        steps_lines = [("step", s) for s in steps.strip().splitlines()]
    else:
        steps_lines = []

    step_md_lines: list[str] = []
    n = 0
    if steps_lines:
        for kind, text in steps_lines:
            if kind == "phase":
                step_md_lines += ["", f"**{text}**", ""]
            else:
                n += 1
                step_md_lines.append(f"{n}. {text}")
    elif runs:
        for i, run in enumerate(runs, 1):
            step_md_lines.append(run_step_md(run, category, i))
    else:
        # Fallback: playbook phases as the guide — flag the placeholders explicitly
        step_md_lines.append(
            "_No ctf-tools runs recorded in the memory file. Below is the reference "
            "playbook — replace `<target>` / `<file>` with the real values from your solve._\n"
        )
        step_md_lines.append("**Reference playbook (replace placeholders with real values):**")
        for phase_title, phase_steps in pb["phases"]:
            step_md_lines += ["", f"**{phase_title}**", ""]
            for s in phase_steps:
                n += 1
                step_md_lines.append(f"{n}. {s}")
    step_md = "\n".join(step_md_lines)

    # ---- Attack chain summary (soal1-13 style) ----
    chain_md = attack_chain_md(runs, tools)

    # ---- Agent reproduction block: one concrete command per unique tool used ----
    used_tools = list(dict.fromkeys(t for t, _, ok, _ in runs if ok == "ok"))
    repro = []
    for t in used_tools:
        repro.append(f"- `{t}` → {tool_cmd(t)}")
    if not repro:
        repro = ["- _(no successful ctf-tools runs recorded — list the exact tools + commands used)_"]
    repro_md = "\n".join(repro)

    slug = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:60]
    out_dir = WRITEUPS_DIR / category
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{date.today().isoformat()}_{slug}.md"
    i = 1
    while target.exists():
        target = out_dir / f"{date.today().isoformat()}_{slug}_{i}.md"
        i += 1

    # Target URL from the recorded http_request runs, if any
    target_url = ""
    for tool, args_json, _, _ in runs:
        if tool == "http_request":
            args = _args_obj(args_json)
            if args.get("url"):
                target_url = args["url"]
                break

    body = f"""# {title}

> POC Writeup — complete end-to-end reproduction (auto-generated from memory, agent-augmented).

| Field | Value |
|---|---|
| Platform | {platform} |
| Category | {category} |
| Date | {date.today().isoformat()} |
| Status | solved |
| Flag | `{flag}` |
| Source memory | `{memory_file.name}` |
{("| Target | `" + target_url + "` |") if target_url else ""}

## 1. TL;DR — best & fastest technique

Minimal path: {", ".join(tools) or "N/A"} → flag recovered.
{("Technique: `" + runs[-1][0] + "` (last successful run) → `" + flag + "`") if runs else ""}

## 2. Attack chain

{chain_md}

## 3. Step-by-step (start → finish)

{step_md}

## 4. Tools & commands

### 4.1 Terminal — {category.upper()} playbook

```bash
{"\n".join(pb["terminal"])}
```

### 4.2 BurpSuite

{"\n".join(pb["burp"])}

## 5. Agent reproduction (ctf-kit)

Replay the exact same solve:

{repro_md}

Run all ctf-tools via MCP (`ctf-tools <tool>`) or the CLI above. On future
challenges, first run `recall_knowledge` with keywords from this writeup
(`{", ".join(tools[:3]) or "flag"}`) — the technique will be auto-loaded.

## 6. Evidence

{("```\n" + evidence + "\n```") if evidence else "_(attach key output: response body, decoded text, crash log)_"}

## 7. What worked / lessons

{lessons}

## 8. Flag

`{flag}`
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
