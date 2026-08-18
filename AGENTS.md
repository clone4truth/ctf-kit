# CTF KIT — Agent Instructions (universal: opencode, Claude Code, Cursor, Codex, Gemini CLI)

CTF toolkit with 90 tools (encoding, crypto, stego, forensics, web, rev, pwn,
osint, misc) exposed as a Headless MCP server, Cyberpunk Terminal UI (TUI), and REST API.

## Quickstart

```powershell
.venv\Scripts\python tui.py             # Cyberpunk Terminal UI (TUI dashboard)
.venv\Scripts\python cli.py list        # CLI tool runner & list
.venv\Scripts\python mcp_server.py      # MCP server (stdio JSON-RPC)
.venv\Scripts\python api_server.py      # Headless REST API -> http://localhost:8765/docs
```

## Working a CTF challenge — REQUIRED WORKFLOW

**PLAN FIRST, always.** Never jump straight into tools.

1. **Plan.** Run `detect_challenge` (MCP tool) or
   `python scripts/plan.py "<problem statement>"` — it auto-detects the
   **category** and **platform** from the problem/lab, lists suggested tools,
   and recalls prior memory. Write the plan down (todo list) before solving.
2. **Recall.** `python scripts/recall.py "<problem keywords>"` — read any
   matching `memory/*.md` and skills. Apply prior lessons.
3. **Solve** using the `ctf-tools` MCP tools (or TUI / CLI). Prefer existing
   tools; check tool names via `list_tools` / the MCP tool list first.
4. **Extract the flag — any format.** Do NOT assume `flag{...}`. Flags can be
   `picoCTF{...}`, `HTB{...}`, `COMPFEST{...}`, `flag: xxx`, `FLAG-xxx`, hex
   digests, or any `word{...}` shape. Use `extract_flags` (MCP tool) on every
   output that may contain the answer.
5. **Memory is automatic** (opencode plugin). In other providers, save it
   manually after solving: `python scripts/remember.py --title "..." --tool <tool> --flag "..." --note "what worked"`.
   Always save when you recover a flag.
6. **Writeup/POC auto-generated** at `writeups/<category>/<date>_<slug>.md`
   (memory + steps + terminal/BurpSuite commands per category). **Augment it**:
   edit the file with the exact step-by-step you used — commands, offsets,
   payloads, BurpSuite workflow. The writeup = your fastest/best technique.
7. **Reusable technique? Add a tool.** If a technique repeats across
   challenges, scaffold it and it auto-registers (MCP + TUI + CLI + API, no config change):
   `python scripts/new_tool.py --name <snake_case> --category <cat> --summary "..." --params "a:str,b:int"`
   Then implement the function body in the generated `ctfkit/modules/<name>.py`.
8. **Verify.** After adding tools: `python test_smoke.py` (expect all OK).

## Memory & skills

- `memory/_index.md` — index of all challenges (newest first); opencode loads it
  automatically into context. Re-read it when a challenge starts.
- `memory/*.md` — one file per challenge (status, tools, flag, lessons).
- Skills auto-generate to `~/.agents/skills/ctf-*` and `~/.claude/skills/ctf-*`
  (loaded by opencode and Claude Code on next start).
- Recall is `scripts/recall.py`; manual save is `scripts/remember.py`.

## Testing & validation

- `python gen_testdata.py` regenerates `testdata/` demo files.
- `python test_smoke.py` — 85 smoke tests over all tools.
- `python test_mcp.py` — MCP handshake check.
- REST API runs on port **8765** (8000 is blocked on this machine).

## Conventions

- Tools: one function per tool, `@tool(category=...)` decorator, docstring =
  MCP/UI description, params via signature + `:param x: desc` docstring lines.
- Keep every module's docstrings and output strings in English.
- Never invent scan/tool results; state "requires testing" if unverified.
