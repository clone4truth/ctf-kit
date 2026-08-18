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

`opencode.json` registers `ctf-tools` as an MCP server (57 tools). Restart
opencode after changing the config, and launch opencode from this folder so
the project config is picked up.

## Tools by category

| Category | Tools |
|---|---|
| **encoding** (7) | decode_base (2/8/16/32/36/58/62/64/85), encode_url, html entities, unicode escapes, morse, brainfuck, decode_all (auto-try everything) |
| **crypto** (22) | caesar (brute+scoring), atbash, affine, vigenere, beaufort, playfair, hill 2x2, railfence, columnar, bacon, rot47, frequency+bigram, vigenere_keylength (IC/Kasiski), xor_brute (multi-key), xor_keyed, rsa_decrypt (factoring + auto padding), rsa_small_e, aes_crypt (ECB/CBC/CFB/OFB/CTR/GCM + auto PKCS7), aes_cbc_bitflip, hash_identify, hash_generate, hash_crack_common |
| **stego** (7) | stego_lsb (lsb/msb, channel, bit order), stego_metadata (tEXt/EXIF), stego_channel, stego_xor_images, stego_png_chunks, stego_gif_frames, stego_compare |
| **forensics** (7) | file_type (magic+entropy), strings_extract (ascii/utf16), hexdump, carve (15+ magics), zlib_hunt, entropy_map, pcap_http |
| **web** (5) | jwt_decode, jwt_forge (none/HS256), http_request (GET/POST/HEAD, custom headers), payload_encoders (WAF-bypass variants), sqli_payloads |
| **rev** (1) | elf_info (class/machine/entry/phdr/shdr) |
| **pwn** (5) | checksec (NX/PIE/RELRO/Canary/Fortify), rop_gadgets (x86-64), shellcode_x64 (null-free execve + xor decoder), debruijn, debruijn_find |
| **osint** (3) | dns_query (A/AAAA/MX/NS/TXT/CNAME), dns_reverse, crtsh_subdomains |

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