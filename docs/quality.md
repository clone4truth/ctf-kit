# Quality model

CTF Kit does not equate a large tool count with solve readiness. Changes are
accepted only when the relevant layers remain green:

| Layer | Command | What it proves |
|---|---|---|
| Unit/architecture | `pytest -q` | contracts, safety, flags, job lifecycle/process cancellation, timeouts, writeups |
| Smoke | `python tests/test_smoke.py` | broad invocation and graceful degradation |
| MCP | `python tests/test_mcp.py` | protocol handshake, schemas, registry parity |
| Remote MCP | `pytest -q tests/test_remote_backend.py` | stdio MCP → HTTP backend → sync/job executor → centralized telemetry |
| Agent E2E | `CTF_E2E=1 python tests/test_agent_categories.py` | planning and local solves |
| Evaluation | `python scripts/eval_core.py` | deterministic recovery and false positives |
| Advanced gate | `python scripts/eval_advanced.py` | real decryption, nonce reuse, exploit-chain ordering, multi-byte XOR, layered web, archive metadata |

Run every deterministic layer in order with `python scripts/verify.py`. Add
`--build` after installing `requirements-dev.txt` to include both standalone
PyInstaller artifacts in the release check.

Smoke output distinguishes `PASS`, `XFAIL` (an intentionally unavailable or
invalid probe), and `FAIL`. An XFAIL is never evidence that the underlying
external tool works.

The evaluation includes blind cases whose statements omit the intended technique,
multi-layer decoding, and adversarial non-flag syntax. The deterministic score is
a regression indicator, not a claim that every real
tournament challenge can be solved. Release readiness additionally requires
successful representative challenges for web, crypto, stego, forensics, rev,
pwn, OSINT, and encoding, with challenge statements that do not reveal the
intended technique.

A **10.0/10 local release score** requires both the core evaluation and the
advanced gate to pass. A failed advanced case caps the score at **9.5**, even
when every basic probe passes. The advanced report is written to
`evals/latest_advanced_report.json` with per-case evidence and category coverage.
This remains a reproducible engineering gate—not a promise that every novel or
zero-day tournament challenge is automatically solvable.
