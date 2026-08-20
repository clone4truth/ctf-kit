"""Central tool registry.

Each module registers functions with the @tool(...) decorator.
The registry is used by the MCP bridge (mcp_server.py) and the REST gateway
(server.py), so a single tool definition is exposed through two surfaces (MCP + REST).
"""

import json
import inspect
import re
import threading
import traceback
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
import time

from .cache import get as cache_get, put as cache_put
from .flagmeta import extract_flag_candidates
from .logging import log
from .policy import metadata_for, permits
from .result import ToolRunResult, ToolStatus, classify_output
from .isolation import run_isolated, should_isolate
from .config import target_scope_error
from .utils import tool_params

TOOLS: dict[str, dict] = {}

EXECUTION_LOG = Path(__file__).resolve().parent.parent / "memory" / "execution_log.json"
_LOG_LOCK = threading.Lock()  # ponytail: global lock; shard per tool if concurrent load matters

def _load_execution_log() -> dict:
    if EXECUTION_LOG.exists():
        try:
            return json.loads(EXECUTION_LOG.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"runs": {}, "failures": {}, "successes": {}, "contexts": {}}

def _save_execution_log(data: dict):
    # rotation: cap per-tool history and context entries so the file never grows unbounded
    for arr in (data.get("successes", {}), data.get("failures", {})):
        for key in list(arr):
            arr[key] = arr[key][-20:]
    ctx = data.get("contexts", {})
    if len(ctx) > 400:
        data["contexts"] = {k: v for k, v in list(ctx.items())[-400:]}
    EXECUTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=EXECUTION_LOG.parent,
                                     prefix="execution_log.", suffix=".tmp", delete=False) as tmp:
        json.dump(data, tmp, ensure_ascii=False)
        temp_name = tmp.name
    os.replace(temp_name, EXECUTION_LOG)


@contextmanager
def _process_log_lock():
    lock_path = EXECUTION_LOG.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as handle:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        yield

_SECRET_KEY = re.compile(r"(?i)(pass|secret|token|cookie|authorization|api.?key|flag)")


def _redact_args(args: dict) -> dict:
    return {k: "[REDACTED]" if _SECRET_KEY.search(k) else str(v)[:100] for k, v in args.items()}


def record_tool_execution(tool_name: str, success: bool, args: dict, duration: float, output_preview: str = "", context: str = ""):
    with _LOG_LOCK, _process_log_lock():
        data = _load_execution_log()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        if tool_name not in data["runs"]:
            data["runs"][tool_name] = {"total": 0, "success": 0, "failure": 0, "last_run": ""}

        data["runs"][tool_name]["total"] += 1
        data["runs"][tool_name]["last_run"] = ts

        if success:
            data["runs"][tool_name]["success"] += 1
            if tool_name not in data["successes"]:
                data["successes"][tool_name] = []
            if context and len(data["successes"][tool_name]) < 50:
                data["successes"][tool_name].append({
                    "time": ts, "context": context[:200], "output": "[REDACTED]"
                })
        else:
            data["runs"][tool_name]["failure"] += 1
            if tool_name not in data["failures"]:
                data["failures"][tool_name] = []
            if len(data["failures"][tool_name]) < 50:
                data["failures"][tool_name].append({
                    "time": ts, "args": _redact_args(args), "context": context[:200], "output": output_preview[:200]
                })

        if context:
            ctx_hash = context[:100].lower().strip()
            if ctx_hash not in data["contexts"]:
                data["contexts"][ctx_hash] = {"tools_tried": [], "successful": [], "failed": []}
            if tool_name not in data["contexts"][ctx_hash]["tools_tried"]:
                data["contexts"][ctx_hash]["tools_tried"].append(tool_name)
            if tool_name not in data["contexts"][ctx_hash].get(("successful" if success else "failed"), []):
                data["contexts"][ctx_hash].setdefault("successful" if success else "failed", [])
                data["contexts"][ctx_hash]["successful" if success else "failed"].append(tool_name)

        _save_execution_log(data)

def get_tool_history(tool_name: str) -> dict:
    data = _load_execution_log()
    return data.get("runs", {}).get(tool_name, {})

def get_failed_contexts(context_query: str) -> list:
    data = _load_execution_log()
    q = context_query.lower().strip()[:100]
    results = []
    for ctx_hash, ctx_data in data.get("contexts", {}).items():
        if q in ctx_hash or any(q in t for t in ctx_data.get("tools_tried", [])):
            results.append({"context": ctx_hash, **ctx_data})
    return results

def is_tool_failed_for_context(tool_name: str, context: str) -> bool:
    data = _load_execution_log()
    ctx_hash = context.lower().strip()[:100]
    ctx_data = data.get("contexts", {}).get(ctx_hash, {})
    return tool_name in ctx_data.get("failed", [])

CATEGORIES = {
    "encoding": "Encoding & Misc",
    "crypto": "Cryptography",
    "stego": "Steganography",
    "forensics": "Forensics",
    "web": "Web Exploitation",
    "rev": "Reverse Engineering",
    "pwn": "Binary Exploitation",
    "osint": "OSINT",
    "misc": "Miscellaneous",
}

# Side-effectful tools: never cache (stale network scans / state changes / long-running agents)
_NO_CACHE = {
    "http_request", "crtsh_subdomains", "remember_challenge", "scaffold_new_tool",
    "reset_agent_memory", "autonomous_solve", "external_web", "external_recon",
    "external_forensics", "external_stego", "external_crypto", "external_rev",
    "chain_tools", "github_search", "whois_query", "dns_query", "dns_reverse",
    "self_improve_report", "smart_tool_recommend", "self_diagnose", "optimize_workflow",
    "plan_challenge",
}

# Tools whose output should NOT be scanned for flags (avoid noise/recursion)
_FLAG_SKIP = {
    "extract_flags_tool", "remember_challenge", "scaffold_new_tool",
    "get_agent_status", "reset_agent_memory", "detect_challenge",
    "select_tools", "optimize_parameters", "recall_knowledge",
    "list_tools", "external_available",
    "self_improve_report", "smart_tool_recommend", "self_diagnose", "optimize_workflow",
    "plan_challenge",
}


def tool(name: str | None = None, category: str = "misc", timeout: float = 30.0,
         retries: int = 0, parallel_safe: bool = True, **capabilities):
    """Decorator: register a function as a CTF tool.

    :param name: optional tool name override
    :param category: tool category (encoding, crypto, stego, forensics, web, rev, pwn, osint, misc)
    :param timeout: default timeout in seconds for this tool
    :param retries: number of retries on failure (for idempotent tools)
    :param parallel_safe: whether tool can run in parallel with others (no shared state)
    """

    def deco(fn):
        key = name or fn.__name__
        doc = (inspect_doc := fn.__doc__ or "").strip()
        summary = doc.split("\n")[0] if doc else key
        policy = metadata_for(key)
        policy.update({k: v for k, v in capabilities.items() if k in policy})
        TOOLS[key] = {
            "fn": fn,
            "name": key,
            "category": category,
            "category_label": CATEGORIES.get(category, category),
            "summary": summary,
            "doc": doc,
            "params": tool_params(fn),
            "timeout": timeout,
            "retries": retries,
            "parallel_safe": parallel_safe,
            **policy,
        }
        return fn

    return deco


def execute_tool(name: str, args: dict | None = None) -> dict:
    """Canonical execution path used by MCP, REST, agents, and pipelines."""
    if name not in TOOLS:
        return ToolRunResult(name, "unknown", ToolStatus.INVALID_INPUT,
                             error=f"Unknown tool: {name}", text=f"ERROR: Unknown tool: {name}").to_dict()
    meta = TOOLS[name]
    fn = meta["fn"]
    args = args or {}
    if not permits(meta.get("safety_level", "passive")):
        text = f"BLOCKED: '{name}' is disabled by the configured safety-policy override."
        return ToolRunResult(name, meta["category"], ToolStatus.BLOCKED, text=text, error=text).to_dict()
    known = {p["name"] for p in meta["params"]}
    unknown = sorted(set(args) - known)
    if unknown:
        text = f"ERROR: unknown argument(s) for {name}: {', '.join(unknown)}"
        return ToolRunResult(name, meta["category"], ToolStatus.INVALID_INPUT, text=text, error=text).to_dict()
    sig_args = dict(args)
    param_types = {p["name"]: p.get("type") for p in meta["params"]}
    for k, v in list(sig_args.items()):
        expected_type = param_types.get(k)
        if expected_type in ("int", "integer") and isinstance(v, str):
            try:
                sig_args[k] = int(v)
            except (ValueError, TypeError):
                pass
        elif expected_type in ("float", "number") and isinstance(v, str):
            try:
                sig_args[k] = float(v)
            except (ValueError, TypeError):
                pass
        elif expected_type in ("bool", "boolean") and isinstance(v, str):
            sig_args[k] = v.lower() in ("1", "true", "yes", "y")

    for k, v in list(sig_args.items()):
        # OS-agnostic: Windows backslashes break Linux-run tools — normalize every path-like arg
        if (k.endswith("path") or k == "file") and isinstance(v, str):
            sig_args[k] = v.replace("\\", "/")

    if meta.get("open_world"):
        scope_error = target_scope_error(sig_args)
        if scope_error:
            text = f"BLOCKED: {scope_error}"
            return ToolRunResult(name, meta["category"], ToolStatus.BLOCKED,
                                 text=text, error=scope_error).to_dict()

    try:
        inspect.signature(fn).bind(**sig_args)
    except TypeError as ex:
        text = f"ERROR: invalid arguments for {name}: {ex}"
        return ToolRunResult(name, meta["category"], ToolStatus.INVALID_INPUT,
                             text=text, error=str(ex)).to_dict()

    cached = cache_get(name, sig_args) if name not in _NO_CACHE else None
    if cached is not None:
        log.info("[%s] %s cache HIT", meta["category"], name)
        flags = [] if name in _FLAG_SKIP else extract_flag_candidates(cached)
        return ToolRunResult(name, meta["category"], classify_output(cached), text=cached,
                             cached=True, flags=flags).to_dict()

    import time as _time
    _start = _time.monotonic()
    log.info("[%s] %s running: %s", meta["category"], name,
             ", ".join(f"{k}={v}" for k, v in _redact_args(sig_args).items()))

    # Get tool-specific timeout and retries
    tool_timeout = meta.get("timeout", 30.0)
    tool_retries = meta.get("retries", 0)

    last_error = None
    for attempt in range(tool_retries + 1):
        try:
            # Run with timeout
            import concurrent.futures
            if should_isolate(name, meta):
                result = run_isolated(name, sig_args, tool_timeout)
            else:
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(fn, **sig_args)
                try:
                    result = future.result(timeout=tool_timeout)
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)

            if not isinstance(result, str):
                result = str(result)
            status = classify_output(result)
            if name == "autonomous_solve":
                status = (ToolStatus.SUCCESS if "AGENT RUN COMPLETE: SOLVED" in result
                          else ToolStatus.NO_FINDING)
            if status == ToolStatus.SUCCESS and name not in _NO_CACHE:
                cache_put(name, sig_args, result)

            # Auto-extract flags from every successful tool output
            _flags_found = []
            if status == ToolStatus.SUCCESS and name not in _FLAG_SKIP:
                try:
                    _flags_found = extract_flag_candidates(result)
                except Exception:
                    pass
            if name == "autonomous_solve":
                solved = re.search(r"(?m)^🏆 FLAG FOUND:\s*(.+)$", result)
                _flags_found = extract_flag_candidates(solved.group(1)) if solved else []

            log.info("[%s] %s done in %.2fs (%d chars)%s", meta["category"], name,
                     _time.monotonic() - _start, len(result),
                     f" FLAG DETECTED: {_flags_found[0]['value']}" if _flags_found else "")

            duration = _time.monotonic() - _start
            if not name.startswith("_test_"):
                record_tool_execution(
                    tool_name=name,
                    success=status == ToolStatus.SUCCESS,
                    args=sig_args,
                    duration=duration,
                    output_preview=result[:300],
                    context=meta.get("summary", name),
                )

            return ToolRunResult(name, meta["category"], status, text=result,
                                 duration_ms=round(duration * 1000, 2), flags=_flags_found).to_dict()
        except concurrent.futures.TimeoutError:
            last_error = f"Tool timeout after {tool_timeout}s"
            log.warning("[%s] %s attempt %d/%d timed out", meta["category"], name, attempt + 1, tool_retries + 1)
        except Exception as ex:
            last_error = ex
            log.warning("[%s] %s attempt %d/%d failed: %s", meta["category"], name, attempt + 1, tool_retries + 1, ex)

    # All retries exhausted
    status = ToolStatus.TIMEOUT if "timeout" in str(last_error).lower() else ToolStatus.ERROR
    error_msg = f"ERROR: {last_error}"
    log.error("[%s] %s FAILED after %.2fs: %s", meta["category"], name,
              _time.monotonic() - _start, last_error)

    duration = _time.monotonic() - _start
    if not name.startswith("_test_"):
        record_tool_execution(
            tool_name=name,
            success=False,
            args=sig_args,
            duration=duration,
            output_preview=error_msg[:300],
            context=meta.get("summary", name),
        )

    return ToolRunResult(name, meta["category"], status, text=error_msg,
                         duration_ms=round(duration * 1000, 2), error=str(last_error)).to_dict()


def run_tool(name: str, args: dict) -> str:
    """Backward-compatible text API. New callers should use execute_tool()."""
    result = execute_tool(name, args)
    text = result["text"]
    if result.get("flags"):
        values = "\n".join(f"  -> {f['value']} ({f['confidence']:.0%})" for f in result["flags"][:5])
        text += f"\n\nFLAG CANDIDATES:\n{values}"
    return text


def list_tools(category: str | None = None) -> list[dict]:
    """List tools for the UI (without 'fn', not serializable)."""
    out = []
    for meta in TOOLS.values():
        if category and meta["category"] != category:
            continue
        out.append({k: v for k, v in meta.items() if k != "fn"})
    return out
