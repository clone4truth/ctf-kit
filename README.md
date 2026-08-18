# CTF KIT — Competitive Toolkit

Modular CTF toolkit covering every category: **Encoding, Crypto, Stego,
Forensics, Web, Reverse Engineering, Pwn, OSINT**. One tool definition feeds
two surfaces: an **MCP server** (for LLM agents / opencode) and a **Web UI**
(dashboard with animations, loading states, and a live streaming log console).

## Workflow (every agent must follow)

1. **PLAN FIRST**: `detect_challenge` (MCP tool) / `python scripts/plan.py "<problem>"`
   — auto-detects category + platform, suggests tools, recalls memory.
2. **RECALL**: `python scripts/recall.py "<keywords>"` — prior memory + skills.
3. **SOLVE** with ctf-tools MCP tools.
4. **EXTRACT FLAG — any format** (`extract_flags` tool): `flag{...}`,
   `picoCTF{...}`, `HTB{...}`, `COMPFEST{...}`, `flag: xxx`, `FLAG-xxx`,
   hex digests, any `word{...}` — nothing assumed, nothing excluded.
5. **MEMORY + SKILL auto-save** (opencode plugin) / manual
   `python scripts/remember.py` (other providers).
6. **WRITEUP/POC auto-generated** at `writeups/<category>/` — step-by-step,
   best/fastest technique, terminal + BurpSuite commands per category; augment
   it with the exact commands you used.
7. **NEW TOOL auto-register** when a technique repeats:
   `python scripts/new_tool.py --name ... --category ... --params ...`

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# Web UI  -> http://localhost:8765
.venv\Scripts\python webui.py

# MCP server (stdio) — for opencode / Claude / other agents
.venv\Scripts\python mcp_server.py

# Tests
.venv\Scripts\python gen_testdata.py
.venv\Scripts\python test_smoke.py   # 54 tests covering all tools
.venv\Scripts\python test_mcp.py     # MCP handshake
```

## Use in opencode

`opencode.json` registers `ctf-tools` as an MCP server (90 tools). Restart
opencode after changing the config, and launch opencode from this folder so
the project config is picked up.

## Tools by category

| Category | Tools |
|---|---|
| **encoding** (12) | decode_base (2/8/16/32/36/58/62/64/85), decode_base45, decode_base91, decode_chain (auto-unpacker), decode_zero_width, encode_zero_width, encode_url, html entities, unicode escapes, morse, brainfuck, decode_all |
| **crypto** (30) | rsa_wiener, rsa_fermat, rsa_common_modulus, rsa_hastad, rsa_parse_key, rsa_decrypt, rsa_small_e, xor_crib_drag, xor_brute, xor_keyed, lcg_solve, hash_length_extension, caesar, atbash, affine, vigenere, beaufort, playfair, hill 2x2, railfence, columnar, bacon, rot47, frequency+bigram, vigenere_keylength, aes_crypt, aes_cbc_bitflip, hash_identify, hash_generate, hash_crack_common |
| **stego** (10) | png_fix_ihdr (CRC dimension recovery), stego_audio_wav (LSB), stego_dtmf_detect, stego_lsb, stego_metadata, stego_channel, stego_xor_images, stego_png_chunks, stego_gif_frames, stego_compare |
| **forensics** (11) | triage_file, pcap_http (PCAP & PCAPNG), pcap_dns_exfil, pcap_usb_keystrokes, zip_fix_pseudo_encrypt, exif_gps_map, file_type, strings_extract, hexdump, carve (15+ magics), zlib_hunt, entropy_map |
| **web** (10) | ssti_payloads (Jinja2/Twig/Smarty/SpEL/Thymeleaf/EJS/ERB), revshell_generator (multi-language & bypasses), php_filter_chain, ssrf_obfuscator, jwt_key_confusion (CVE-2015-9235), jwt_decode, jwt_forge, http_request, payload_encoders, sqli_payloads |
| **rev** (3) | pe_info (Windows PE32/PE32+ mitigations), elf_info (Linux ELF), pyc_magic_info |
| **pwn** (9) | checksec, rop_gadgets, fmtstr_payload_gen, pwn_template (pwntools), shellcode_multi (x86/x64/ARM/Win), shellcode_x64, debruijn, debruijn_find |
| **osint** (3) | dns_query (A/AAAA/MX/NS/TXT/CNAME), dns_reverse, crtsh_subdomains |
| **misc** (2) | detect_challenge, extract_flags_tool |

## Architecture

```
ctf-tools/
├── ctfkit/
│   ├── logging.py        # LogBus — streams logs to the UI via SSE
│   ├── registry.py       # @tool() decorator + run_tool + list_tools
│   ├── utils.py          # helpers: hex, english scoring, magic bytes, param introspection
│   └── modules/          # one file per category (encoding, crypto_classic,
│                         #   crypto_modern, stego, forensics, web, rev_pwn, osint)
├── web/
│   ├── app.py            # FastAPI: /api/tools, /api/run, /api/logs (SSE), /
│   └── static/           # index.html, style.css, app.js (dark cyber theme)
├── memory/               # per-challenge memory + _index.md (auto, plugin)
├── writeups/<category>/  # step-by-step POCs with terminal/BurpSuite commands (auto)
├── mcp_server.py         # MCP stdio entrypoint (mcp 2.0 MCPServer)
├── webui.py              # Web UI entrypoint
├── wordlists/common.txt  # small wordlist for hash_crack_common
├── test_smoke.py         # smoke tests for every tool
└── test_mcp.py           # MCP handshake test
```

## Log console

Every run is logged to the `ctfkit` logger (console + LogBus). The web UI
streams records through `/api/logs` (SSE) into the **LOG CONSOLE** panel at
the bottom of the screen, with per-level colors, category chips, a spinner
and blinking cursor while a tool is running, a "running" status pill in the
topbar, and a flash highlight on new lines. The MCP server writes logs to
stderr.

## Notes

- `rsa_decrypt` auto-tries PKCS1v15/OAEP after raw plaintext.
- `aes_crypt` auto-tries PKCS7 and no-padding for ECB/CBC.
- `stego_lsb` supports MSB bit planes and msb-first bit order.
- `pcap_http` is a minimal stdlib parser (Ethernet/IPv4/TCP), zero deps.

Demo test data lives in `testdata/` (generated by `gen_testdata.py`).