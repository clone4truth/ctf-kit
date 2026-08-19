# CTF KIT — Claude Code Instructions

@memory/_index.md

CTF toolkit: 125 tools (encoding, crypto, stego, forensics, web, rev, pwn,
osint, misc) as an MCP server (`ctf-tools`, registered in `.mcp.json`) plus a REST
API server (`server.py`) with Swagger UI at `/docs`.

## Quickstart

```powershell
.venv\Scripts\python server.py          # API server -> http://localhost:8765/docs
.venv\Scripts\python mcp_server.py     # MCP server (stdio)
```

## Working a CTF challenge — REQUIRED WORKFLOW

**PLAN FIRST, always.** Never jump straight into tools.

1. **Plan.** Run `detect_challenge` (MCP) or `python scripts/plan.py "<problem statement>"` — it
   auto-detects the **category** and **platform** from the problem/lab, lists
   suggested tools, and recalls prior memory. Write the plan down before solving.
2. **Recall.** Run `recall_knowledge` (MCP) or `python scripts/recall.py "<problem keywords>"` — read matching
   `memory/*.md` files and skills. Apply prior lessons.
3. **Solve** using the `ctf-tools` MCP tools (check the tool list first, e.g.
   `decode_base`, `xor_brute`, `stego_lsb`, `caesar`, `jwt_decode`).
4. **Extract the flag — any format.** Do NOT assume `flag{...}`. Flags can be
   `picoCTF{...}`, `HTB{...}`, `COMPFEST{...}`, `flag: xxx`, `FLAG-xxx`, hex
   digests, or any `word{...}` shape. Use `extract_flags` (MCP tool) on every
   output that may contain the answer.
5. **Save memory after solving:**
   Use `remember_challenge` (MCP tool) or CLI:
   `python scripts/remember.py --title "..." --tool <tool> --flag "..." --note "what worked"`
   Always save when you recover a flag — this generates a reusable skill and a
   **writeup/POC** at `writeups/<category>/` with step-by-step + terminal/BurpSuite
   commands per category.
6. **Augment the writeup**: edit `writeups/<category>/<date>_<slug>.md` with the
   exact steps you used (commands, offsets, payloads) — the writeup = your
   best/fastest technique.
7. **Reusable technique? Add a tool.** Scaffold + auto-register (MCP + UI, no
   config change): `python scripts/new_tool.py --name <snake_case> --category <cat>
   --summary "..." --params "a:str,b:int"` then implement
   `ctfkit/modules/<name>.py`.
8. **Verify:** `python tests/test_smoke.py` (expect all OK).

## Testing & validation

- `python tests/gen_testdata.py` regenerates `testdata/` demo files.
- `python tests/test_smoke.py` — 101 smoke tests over all tools.
- `python tests/test_mcp.py` — MCP handshake check.
- REST API runs on port **8765** (8000 is blocked on this machine).

## Conventions

- One function per tool with `@tool(category=...)` decorator; docstring becomes
  the MCP/UI description; params via signature + `:param x: desc` lines.
- Keep module docstrings and output strings in English.
- Never invent scan/tool results; state "requires testing" if unverified.
