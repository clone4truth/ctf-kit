# CTF KIT — Agent Instructions (universal: opencode, Claude Code, Cursor, Codex, Gemini CLI)

CTF toolkit with 123 tools (encoding, crypto, stego, forensics, web, rev, pwn,
osint, misc) exposed as a Headless MCP server and REST API, including external
CLI tool wrappers per category (nmap, ffuf, sqlmap, binwalk, steghide, hashcat...).

## Quickstart

```powershell
.venv\Scripts\python server.py          # API Server -> http://localhost:8765/docs
.venv\Scripts\python mcp_server.py      # MCP server (stdio JSON-RPC for Claude/Cursor/OpenCode)
```

## Working a CTF challenge — REQUIRED WORKFLOW

**PLAN FIRST, always.** Never jump straight into tools.

1. **Plan.** Run `detect_challenge` (MCP tool) or
   `python scripts/plan.py "<problem statement>"` — it auto-detects the
   **category** and **platform** from the problem/lab, lists suggested tools,
   and recalls prior memory. Write the plan down (todo list) before solving.
2. **Recall.** Run `recall_knowledge` (MCP tool) or `python scripts/recall.py "<problem keywords>"` — read any
   matching `memory/*.md` and skills. Apply prior lessons.
3. **Solve** using the `ctf-tools` MCP tools. Prefer existing
   tools; check tool names via `list_tools` / the MCP tool list first.
4. **Extract the flag — any format.** Do NOT assume `flag{...}`. Flags can be
   `picoCTF{...}`, `HTB{...}`, `COMPFEST{...}`, `flag: xxx`, `FLAG-xxx`, hex
   digests, or any `word{...}` shape. Use `extract_flags` (MCP tool) on every
   output that may contain the answer.
5. **Memory is automatic.** Save directly via `remember_challenge` (MCP tool)
   or CLI: `python scripts/remember.py --title "..." --tool <tool> --flag "..." --note "what worked"`.
   Always save when you recover a flag to auto-generate skills and POC writeup.
6. **Writeup/POC auto-generated** at `writeups/<category>/<date>_<slug>.md`
   (memory + steps + terminal/BurpSuite commands per category). **Augment it**:
   edit the file with the exact step-by-step you used — commands, offsets,
   payloads, BurpSuite workflow. The writeup = your fastest/best technique.
7. **Reusable technique? Add a tool.** If a technique repeats across
   challenges, scaffold it and it auto-registers (MCP + API, no config change):
   `python scripts/new_tool.py --name <snake_case> --category <cat> --summary "..." --params "a:str,b:int"`
   Then implement the function body in the generated `ctfkit/modules/<name>.py`.
8. **Verify.** After adding tools: `python tests/test_smoke.py` (expect all OK).

## Memory & skills

- `memory/_index.md` — index of all challenges (newest first); opencode loads it
  automatically into context. Re-read it when a challenge starts.
- `memory/*.md` — one file per challenge (status, tools, flag, lessons).
- Skills auto-generate to `~/.agents/skills/ctf-*` and `~/.claude/skills/ctf-*`
  (loaded by opencode and Claude Code on next start).
- Bundled skills in `skills/<name>/SKILL.md` (e.g. `16-ai-llm-security`) sync to
  `~/.agents/skills/` + `~/.claude/skills/` on every MCP server start
  (`scripts/install_agents.py`, hooked in `mcp_server.py main()`), so any provider
  running the ctf-tools server gets them automatically; agents auto-load them by
  description when a matching task appears.
- Recall: `recall_knowledge` (MCP) / `scripts/recall.py`; Save: `remember_challenge` (MCP) / `scripts/remember.py`.

## Testing & validation

- `python tests/gen_testdata.py` regenerates `testdata/` demo files.
- `python tests/test_smoke.py` — 101 smoke tests over all tools.
- `python tests/test_mcp.py` — MCP handshake check.
- REST API runs on port **8765** (8000 is blocked on this machine).

## Conventions

- Tools: one function per tool, `@tool(category=...)` decorator, docstring =
  MCP/UI description, params via signature + `:param x: desc` docstring lines.
- Keep every module's docstrings and output strings in English.
- Never invent scan/tool results; state "requires testing" if unverified.
