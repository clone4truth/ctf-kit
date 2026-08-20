# CTF KIT — Agent Instructions (universal: opencode, Claude Code, Cursor, Codex, Gemini CLI)

CTF toolkit with 210 tools (encoding, crypto, stego, forensics, web, rev, pwn,
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
3. **CVE research (known product? do this BEFORE exploiting).** Run `cve_research`
   (MCP tool) with the problem + detected software/version. It resolves explicit
   CVE IDs and infers CVEs from software+version (NVD + local KB), returns
   severity/description/PoC links, and maps to the exact ctfkit exploit tool.
   Then `cve_lookup "<CVE-ID>"` for a single CVE, `cve_search "<product>"` to
   broaden. Skip if the challenge is purely custom code / pure crypto / pcap etc.
4. **Solve** using the `ctf-tools` MCP tools. Prefer existing
   tools; check tool names via `list_tools` / the MCP tool list first.
5. **Extract the flag — any format.** Do NOT assume `flag{...}`. Flags can be
   `picoCTF{...}`, `HTB{...}`, `COMPFEST{...}`, `flag: xxx`, `FLAG-xxx`, hex
   digests, or any `word{...}` shape. Use `extract_flags` (MCP tool) on every
   output that may contain the answer.
6. **Memory is automatic.** Save directly via `remember_challenge` (MCP tool)
   or CLI: `python scripts/remember.py --title "..." --tool <tool> --flag "..." --note "what worked" --problem "challenge description" --commands "actual commands used"`.
   **ALWAYS pass** `--problem` with the challenge problem statement/description
   and `--commands` with the actual terminal commands you used.
   Always save when you recover a flag to auto-generate skills and POC writeup.
7. **Writeup/POC auto-generated** at `writeups/<category>/<date>_<slug>.md`
   with the structure:
   - **Problem Description** — challenge statement and context
   - **PoC Walkthrough (Step-by-Step)** — complete reproduction flow
   - **Terminal Commands** — actual terminal commands executed
   - **Burp Suite PoC** — (web only) Repeater/Proxy steps
   - **Evidence** — output and proofs
   - **Flag** — recovered flag
   **Augment the writeup** if needed: edit with exact payloads, offsets, CVEs.
8. **Reusable technique? Add a tool.** If a technique repeats across
   challenges, scaffold it and it auto-registers (MCP + API, no config change):
   `python scripts/new_tool.py --name <snake_case> --category <cat> --summary "..." --params "a:str,b:int"`
   Then implement the function body in the generated `ctfkit/modules/<name>.py`.
9. **Verify.** After adding tools: `python tests/test_smoke.py` (expect all OK).

## Memory & skills

- `memory/_index.md` — index of all challenges (newest first); opencode loads it
  automatically into context. Re-read it when a challenge starts.
- `memory/*.md` — one file per challenge (status, tools, flag, lessons).
- `memory/self_improve_state.json` — accumulated learnings, ELO tool rankings, technique patterns, and fast-paths.

## Autonomous Self-Improvement Engine

The MCP server improves itself after every challenge:
- **`smart_tool_recommend`** — Recommends best tools based on historical win rates, technique patterns, and fast-paths.
- **`self_improve_report`** — Visualizes agent learning progress, top ranked tools per category, and learned shortcuts.
- **`optimize_workflow`** — Generates category-specific optimal execution flows derived from real solve data.
- **`self_diagnose`** — Analyzes tool health, detects failure rates, and suggests coverage improvements.
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
- `python tests/test_smoke.py` — 117 smoke scenarios with PASS/XFAIL separation.
- `python tests/test_mcp.py` — MCP handshake check.
- REST API runs on port **8765** (8000 is blocked on this machine).

## Conventions

- Tools: one function per tool, `@tool(category=...)` decorator, docstring =
  MCP/UI description, params via signature + `:param x: desc` docstring lines.
- Keep every module's docstrings and output strings in English.
- Never invent scan/tool results; state "requires testing" if unverified.
