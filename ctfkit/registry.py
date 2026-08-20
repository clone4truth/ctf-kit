"""Central tool registry.

Each module registers functions with the @tool(...) decorator.
The registry is used by the MCP bridge (mcp_server.py) and the REST gateway
(server.py), so a single tool definition is exposed through two surfaces (MCP + REST).
"""

import json
import threading
import traceback
from pathlib import Path
import time

from .cache import get as cache_get, put as cache_put
from .logging import log
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
    EXECUTION_LOG.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

def record_tool_execution(tool_name: str, success: bool, args: dict, duration: float, output_preview: str = "", context: str = ""):
    with _LOG_LOCK:
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
                    "time": ts, "context": context[:200], "output": output_preview[:200]
                })
        else:
            data["runs"][tool_name]["failure"] += 1
            if tool_name not in data["failures"]:
                data["failures"][tool_name] = []
            if len(data["failures"][tool_name]) < 50:
                data["failures"][tool_name].append({
                    "time": ts, "args": {k: str(v)[:100] for k, v in args.items()}, "context": context[:200], "output": output_preview[:200]
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
}


def tool(name: str | None = None, category: str = "misc", timeout: float = 30.0, retries: int = 0, parallel_safe: bool = True):
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
        }
        return fn

    return deco


def run_tool(name: str, args: dict) -> str:
    """Run a tool with start/end logging + error handling + execution tracking + timeout/retry."""
    if name not in TOOLS:
        raise KeyError(f"Unknown tool: {name}")
    meta = TOOLS[name]
    fn = meta["fn"]
    sig_args = {k: v for k, v in args.items() if k in {p["name"] for p in meta["params"]}}
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

    cached = cache_get(name, sig_args) if name not in _NO_CACHE else None
    if cached is not None:
        log.info("[%s] %s cache HIT", meta["category"], name)
        return cached

    import time as _time
    _start = _time.monotonic()
    log.info("[%s] %s running: %s", meta["category"], name,
             ", ".join(f"{k}={str(v)[:60]}" for k, v in sig_args.items()))
    
    # Get tool-specific timeout and retries
    tool_timeout = meta.get("timeout", 30.0)
    tool_retries = meta.get("retries", 0)
    
    last_error = None
    for attempt in range(tool_retries + 1):
        try:
            # Run with timeout
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fn, **sig_args)
                result = future.result(timeout=tool_timeout)
            
            if not isinstance(result, str):
                result = str(result)
            if not result.startswith("ERROR") and name not in _NO_CACHE:
                cache_put(name, sig_args, result)
            log.info("[%s] %s done in %.2fs (%d chars)", meta["category"], name,
                     _time.monotonic() - _start, len(result))
            
            duration = _time.monotonic() - _start
            record_tool_execution(
                tool_name=name,
                success=not result.startswith("ERROR"),
                args=sig_args,
                duration=duration,
                output_preview=result[:300],
                context=meta.get("summary", name),
            )
            
            return result
        except concurrent.futures.TimeoutError:
            last_error = f"Tool timeout after {tool_timeout}s"
            log.warning("[%s] %s attempt %d/%d timed out", meta["category"], name, attempt + 1, tool_retries + 1)
        except Exception as ex:
            last_error = ex
            log.warning("[%s] %s attempt %d/%d failed: %s", meta["category"], name, attempt + 1, tool_retries + 1, ex)
    
    # All retries exhausted
    error_msg = f"ERROR: {last_error}\n{traceback.format_exc(limit=3)}"
    log.error("[%s] %s FAILED after %.2fs: %s", meta["category"], name,
              _time.monotonic() - _start, last_error)
    
    duration = _time.monotonic() - _start
    record_tool_execution(
        tool_name=name,
        success=False,
        args=sig_args,
        duration=duration,
        output_preview=error_msg[:300],
        context=meta.get("summary", name),
    )
    
    return error_msg


def list_tools(category: str | None = None) -> list[dict]:
    """List tools for the UI (without 'fn', not serializable)."""
    out = []
    for meta in TOOLS.values():
        if category and meta["category"] != category:
            continue
        out.append({k: v for k, v in meta.items() if k != "fn"})
    return out
