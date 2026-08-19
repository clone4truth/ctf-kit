"""Central tool registry.

Each module registers functions with the @tool(...) decorator.
The registry is used by the MCP bridge (mcp_server.py) and the REST gateway
(server.py), so a single tool definition is exposed through two surfaces (MCP + REST).
"""

import json
import traceback
from pathlib import Path
import time

from .cache import get as cache_get, put as cache_put
from .logging import log
from .utils import tool_params

TOOLS: dict[str, dict] = {}

EXECUTION_LOG = Path(__file__).resolve().parent.parent / "memory" / "execution_log.json"

def _load_execution_log() -> dict:
    if EXECUTION_LOG.exists():
        try:
            return json.loads(EXECUTION_LOG.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"runs": {}, "failures": {}, "successes": {}, "contexts": {}}

def _save_execution_log(data: dict):
    EXECUTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    EXECUTION_LOG.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def record_tool_execution(tool_name: str, success: bool, args: dict, duration: float, output_preview: str = "", context: str = ""):
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
}


def tool(name: str | None = None, category: str = "misc"):
    """Decorator: register a function as a CTF tool."""

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
        }
        return fn

    return deco


def run_tool(name: str, args: dict) -> str:
    """Run a tool with start/end logging + error handling + execution tracking."""
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

    if "path" in sig_args and isinstance(sig_args["path"], str):
        sig_args["path"] = sig_args["path"].replace("\\", "/")

    cached = cache_get(name, sig_args)
    if cached is not None:
        log.info("[%s] %s cache HIT", meta["category"], name)
        return cached

    import time as _time
    _start = _time.monotonic()
    log.info("[%s] %s running: %s", meta["category"], name,
             ", ".join(f"{k}={str(v)[:60]}" for k, v in sig_args.items()))
    try:
        result = fn(**sig_args)
        if not isinstance(result, str):
            result = str(result)
        if not result.startswith("ERROR"):
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
    except Exception as ex:
        log.error("[%s] %s FAILED after %.2fs: %s", meta["category"], name,
                  _time.monotonic() - _start, ex)
        error_msg = f"ERROR: {ex}\n{traceback.format_exc(limit=3)}"
        
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
