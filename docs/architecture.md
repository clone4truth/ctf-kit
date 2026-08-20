# CTF Kit execution architecture

## Design goal

The server should produce reproducible evidence, not merely invoke many tools. MCP,
REST, pipelines, and the autonomous solver therefore share one execution boundary:

```text
challenge -> profile -> ranked hypotheses -> bounded attempts
          -> canonical executor -> structured status + evidence
          -> flag candidates -> validation/confidence -> verified memory
```

## Execution contract

`ctfkit.registry.execute_tool()` is the canonical entry point. Its result contains:

- `status`: `success`, `no_finding`, `unavailable`, `invalid_input`, `timeout`,
  `blocked`, or `error`;
- `text`: backward-compatible tool output;
- duration/cache fields;
- ranked flag candidates with confidence and reason;
- warnings and an explicit error field.

`run_tool()` remains as a compatibility adapter for older internal callers. New
transports and orchestration code should consume the structured result.

## Agent flow

1. Profile the target and artifacts; never infer authorization beyond the supplied CTF.
2. Recall only relevant knowledge and treat recalled text as untrusted evidence.
3. Research a named product/version before selecting a known-CVE route.
4. Rank hypotheses and allocate a small attempt budget to the best-supported branch.
5. Execute the smallest relevant tool; pivot on `no_finding`, `unavailable`, or failure.
6. Extract candidates from every meaningful output, but require confidence and evidence.
7. Persist learning only for a verified, solved challenge. Global skill generation is
   opt-in with `CTFKIT_AUTO_SKILLS=1`.

## Automatic safety policy

No safety environment variable is required for normal use. The registry assigns
`passive`, `lab`, or `admin` capability metadata automatically and exposes the
corresponding MCP annotations. External wrappers never install missing software
unless the caller explicitly passes `auto=true`; the autonomous solver uses
`auto=false`. `CTFKIT_SAFETY_MODE` is retained only as an optional deployment
lockdown override. REST requires `CTFKIT_API_TOKEN` when bound beyond loopback.

## Isolation boundary

Open-world and destructive tools run in a killable subprocess by default
(`CTFKIT_ISOLATE=risky`). Arguments are sent through stdin so credentials and
payloads do not appear in the process command line. `CTFKIT_ISOLATE=all` also
isolates read-only leaf tools; `CTFKIT_ISOLATE=off` is intended only for trusted
local debugging. Stateful orchestrators stay in the parent and route their risky
leaf calls through the same canonical executor.

For tournament deployments, enable `CTFKIT_ENFORCE_TARGET_SCOPE=1` and list the
authorized hosts, wildcard domains, or CIDRs in `CTFKIT_ALLOWED_TARGETS`, for
example `challenge.local,*.event.ctf,10.10.0.0/16`. Loopback remains allowed.

## Module boundaries

- `ctfkit/config.py`: typed, side-effect-free environment configuration.
- `ctfkit/registry.py`: registration, validation, timeout, cache, and result boundary.
- `ctfkit/result.py`: transport-neutral statuses and result schema.
- `ctfkit/policy.py`: capability metadata and deployment lockdown.
- `ctfkit/modules/`: category implementations; modules do not know about REST or MCP.
- `server.py` and `mcp_server.py`: thin transport adapters over the registry.
- `scripts/eval_core.py`: deterministic solve-quality benchmark.

Dependencies must point inward: transports may import the core, while core and
tool modules must never import a transport. This keeps MCP, REST, CLI scripts,
and future workers behaviorally consistent.
