# CTF Kit execution architecture

## Design goal

The server should produce reproducible evidence, not merely invoke many tools.
The recommended deployment separates the AI-facing MCP bridge from the central
execution backend while preserving one execution boundary:

```text
AI client -> stdio MCP bridge -> authenticated HTTP backend
          -> synchronous executor or persistent job manager
          -> canonical executor -> cache/policy/isolation
          -> structured status + evidence -> central telemetry
```

This mirrors the proven HexStrike-style transport split: the MCP process is a
small client, while the backend owns execution, observability, and lifecycle.
Unlike a raw command endpoint, CTF Kit keeps every call constrained to the
typed registry and its safety metadata.

## Deployment modes

- **Central backend (recommended):** run `python server.py`, then configure MCP
  with `mcp_server.py --server http://127.0.0.1:8765`. MCP calls carry
  `X-CTFKit-Source: mcp`, and REST returns an `execution_id` for correlation.
- **Remote lab/VM:** point `--server` at the authorized Kali/CTF host and protect
  non-loopback deployments with `CTFKIT_API_TOKEN` plus `--token` on the bridge.
- **Local compatibility:** omit `--server`; MCP invokes the same registry in its
  own process, useful for recovery but without centralized backend telemetry.

The backend exposes `/api/telemetry`, `/api/executions`,
`/api/executions/{execution_id}`, and the compatibility alias
`/api/processes/list`. Recent telemetry is intentionally bounded in memory.

Long-running calls use `/api/jobs`. The backend validates the selected tool and
arguments against the typed registry before queueing it, applies a bounded
worker pool, and starts each job in an independent process group. State, final
structured results, and incremental diagnostic output are stored under
`memory/jobs/`; sensitive-looking argument values are redacted from job
metadata. Clients can poll, consume SSE output, or cancel the whole process
group. Jobs left active by a backend restart are recovered as `interrupted`
rather than incorrectly reported as running.

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
- `ctfkit/mcp_client.py`: retrying, token-aware HTTP client for the MCP bridge.
- `ctfkit/jobs.py`: bounded persistent job lifecycle and process-group control.
- `ctfkit/job_worker.py`: private structured job-process entry point.
- `mcp_server.py`: stdio MCP schema/discovery bridge; local or remote execution.
- `server.py`: central execution, jobs, correlation, logs, and bounded telemetry.
- `scripts/eval_core.py`: deterministic solve-quality benchmark.

Dependencies must point inward: transports may import the core, while core and
tool modules must never import a transport. This keeps MCP, REST, CLI scripts,
and future workers behaviorally consistent.
