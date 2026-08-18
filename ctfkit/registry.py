"""Registri tool terpusat.

Setiap module mendaftarkan fungsi dengan decorator @tool(...).
Registry dipakai oleh MCP bridge (mcp_server.py) dan web UI (web/app.py),
sehingga satu definisi tool -> dua permukaan (MCP + UI).
"""

import traceback

from .logging import log
from .utils import tool_params

TOOLS: dict[str, dict] = {}

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
    """Run a tool with start/end logging + error handling."""
    if name not in TOOLS:
        raise KeyError(f"Unknown tool: {name}")
    meta = TOOLS[name]
    fn = meta["fn"]
    sig_args = {k: v for k, v in args.items() if k in {p["name"] for p in meta["params"]}}
    if "path" in sig_args and isinstance(sig_args["path"], str):
        sig_args["path"] = sig_args["path"].replace("\\", "/")
    import time as _time
    _start = _time.monotonic()
    log.info("[%s] %s running: %s", meta["category"], name,
             ", ".join(f"{k}={str(v)[:60]}" for k, v in sig_args.items()))
    try:
        result = fn(**sig_args)
        if not isinstance(result, str):
            result = str(result)
        log.info("[%s] %s done in %.2fs (%d chars)", meta["category"], name,
                 _time.monotonic() - _start, len(result))
        return result
    except Exception as ex:
        log.error("[%s] %s FAILED after %.2fs: %s", meta["category"], name,
                  _time.monotonic() - _start, ex)
        return f"ERROR: {ex}\n{traceback.format_exc(limit=3)}"


def list_tools(category: str | None = None) -> list[dict]:
    """List tools for the UI (without 'fn', not serializable)."""
    out = []
    for meta in TOOLS.values():
        if category and meta["category"] != category:
            continue
        out.append({k: v for k, v in meta.items() if k != "fn"})
    return out
