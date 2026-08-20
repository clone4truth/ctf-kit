# Quality model

CTF Kit does not equate a large tool count with solve readiness. Changes are
accepted only when the relevant layers remain green:

| Layer | Command | What it proves |
|---|---|---|
| Unit/architecture | `pytest -q` | contracts, safety, flags, timeouts, writeups |
| Smoke | `python tests/test_smoke.py` | broad invocation and graceful degradation |
| MCP | `python tests/test_mcp.py` | protocol handshake, schemas, registry parity |
| Agent E2E | `CTF_E2E=1 python tests/test_agent_categories.py` | planning and local solves |
| Evaluation | `python scripts/eval_core.py` | deterministic recovery and false positives |

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
