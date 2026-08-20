#!/usr/bin/env python3
"""CTF KIT — Main Server Engine

Core backend server managing the registered CTF operations with REST API,
Swagger UI documentation, and rich visual telemetry.

Usage:
    python server.py [--host 127.0.0.1] [--port 8765]
"""

import argparse
import asyncio
import datetime
import os
import secrets
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn
from fastapi import FastAPI, UploadFile, File, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.cache import snapshot as cache_snapshot
from ctfkit.config import is_loopback_host, settings
from ctfkit.registry import TOOLS, execute_tool as execute_registered_tool, run_tool, list_tools, CATEGORIES
from ctfkit.logging import log

console = Console()
STARTED_AT = time.monotonic()
MAX_UPLOAD_BYTES = settings.max_upload_bytes

CAT_ICONS = {
    "crypto": "🔐",
    "encoding": "🔤",
    "forensics": "🔍",
    "stego": "🖼️",
    "web": "🌐",
    "rev": "⚙️",
    "pwn": "💥",
    "osint": "🛰️",
    "misc": "🎯"
}

EVENT_STYLES = {
    "start": ("RUN", "cyan", "▶"),
    "success": ("DONE", "green", "✓"),
    "no_finding": ("EMPTY", "yellow", "◇"),
    "unavailable": ("SKIP", "yellow", "○"),
    "blocked": ("BLOCK", "magenta", "◆"),
    "invalid_input": ("INPUT", "yellow", "!"),
    "timeout": ("TIME", "red", "◷"),
    "error": ("FAIL", "red", "×"),
}


def print_event(state: str, name: str, category: str,
                elapsed_ms: float | None = None, detail: str = "") -> None:
    """Render one compact and consistent terminal event."""
    label, color, symbol = EVENT_STYLES.get(state, EVENT_STYLES["error"])
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    duration = f" [dim]{elapsed_ms:,.1f} ms[/dim]" if elapsed_ms is not None else ""
    suffix = f"  [dim]│ {detail}[/dim]" if detail else ""
    console.print(
        f"[dim]{timestamp}[/dim]  [{color}]{symbol} {label:<5}[/{color}]  "
        f"[bold]{name}[/bold]  [dim]{category}[/dim]{duration}{suffix}"
    )

app = FastAPI(
    title="CTF Kit — AI Security & CTF Engine",
    description="Headless Security & CTF Engine exposing cybersecurity tools for AI Agents and REST clients.",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

API_TOKEN = settings.api_token


@app.middleware("http")
async def _authz(request: Request, call_next):
    """Require `Authorization: Bearer <token>` on /api/* when CTFKIT_API_TOKEN is set."""
    protected = request.url.path.startswith("/api") or request.url.path == "/upload"
    if API_TOKEN and protected and request.method != "OPTIONS":
        if request.headers.get("Authorization", "") != f"Bearer {API_TOKEN}":
            return JSONResponse({"detail": "Invalid or missing API token"}, status_code=401)
    return await call_next(request)


@app.get("/health", tags=["Status"])
@app.get("/api/health", tags=["Status"])
def health() -> dict:
    """Comprehensive telemetry, operational readiness, and tool status."""
    categories = sorted(list({t["category"] for t in TOOLS.values()}))
    checks = {
        "registry": len(TOOLS) > 0,
        "memory_writable": os.access(os.path.join(os.path.dirname(__file__), "memory"), os.W_OK),
        "testdata_present": os.path.isdir(os.path.join(os.path.dirname(__file__), "testdata")),
    }
    ready = all(checks.values())
    return {
        "status": "ok" if ready else "degraded",
        "ready": ready,
        "version": __version__,
        "server_engine": "CTF Kit",
        "tools_registered": len(TOOLS),
        "categories_count": len(categories),
        "categories": categories,
        "mcp_enabled": True,
        "checks": checks,
        "uptime_seconds": round(time.monotonic() - STARTED_AT, 2),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.get("/api/tools", tags=["Tools"])
def get_tools(category: str | None = Query(None, description="Filter tools by category")) -> dict:
    """List all registered tools with metadata, descriptions, and parameter schemas."""
    items = list_tools()
    if category:
        items = [t for t in items if t["category"].lower() == category.lower()]
    categories = {}
    for t in items:
        categories.setdefault(t["category"], {"label": t["category_label"], "tools": []})["tools"].append(t)
    return {"total": len(items), "tools": items, "categories": categories}


@app.get("/api/tools/{name}", tags=["Tools"])
def get_tool_detail(name: str) -> dict:
    """Get full specification and parameter documentation for a specific tool."""
    tool = TOOLS.get(name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")
    return {
        "name": tool["name"],
        "category": tool["category"],
        "category_label": tool["category_label"],
        "summary": tool["summary"],
        "doc": tool["doc"],
        "parameters": [
            {
                "name": p["name"],
                "type": p["type"],
                "required": p["required"],
                "default": p["default"],
                "doc": p["desc"]
            }
            for p in tool["params"]
        ]
    }


@app.get("/dashboard", tags=["Status"])
@app.get("/api/dashboard", tags=["Status"])
def dashboard() -> HTMLResponse:
    """Minimal dependency-free HTML tool explorer."""
    tools = sorted(TOOLS.values(), key=lambda t: (t["category"], t["name"]))
    chips = "".join(
        f"<span class='chip'>{c} · {sum(1 for t in tools if t['category'] == c)}</span>"
        for c in sorted({t["category"] for t in tools}))
    rows = "".join(
        f"<tr><td><code>{t['name']}</code></td><td>{t['category']}</td>"
        f"<td>{t['summary']}</td><td class='mono'>{', '.join(p['name'] for p in t['params'])}</td></tr>"
        for t in tools)
    return HTMLResponse(f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>CTF Kit — Tool Explorer</title>
<style>
body{{font-family:ui-monospace,Consolas,monospace;background:#0f172a;color:#e2e8f0;margin:2rem;}}
h1{{color:#38bdf8}} .chip{{background:#1e293b;border:1px solid #334155;border-radius:999px;padding:2px 10px;margin:0 4px 6px 0;display:inline-block}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}} th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #1e293b}}
th{{color:#94a3b8;font-size:.8em;text-transform:uppercase}} code{{color:#a5f3fc}} .mono{{color:#cbd5e1;font-size:.85em}}
</style></head><body>
<h1>⚡ CTF Kit — {len(tools)} Tools</h1>
{chips}
<table><thead><tr><th>Tool</th><th>Category</th><th>Description</th><th>Params</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>""")


@app.post("/api/run", tags=["Execution"])
async def execute_request(payload: dict) -> dict:
    """Execute a security or CTF tool asynchronously in worker thread pool."""
    name = payload.get("name", "")
    args = payload.get("arguments") or payload.get("args") or {}

    if not name or name not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")

    start = time.monotonic()
    tool_meta = TOOLS[name]
    cat = tool_meta.get("category", "tool")
    print_event("start", name, cat)

    try:
        result = await asyncio.get_running_loop().run_in_executor(None, execute_registered_tool, name, args)
        elapsed = (time.monotonic() - start) * 1000
        print_event(result.get("status", "error"), name, cat, elapsed)

        return {**result, "name": name, "result": result["text"], "elapsed_ms": round(elapsed, 2)}
    except Exception as ex:
        elapsed = (time.monotonic() - start) * 1000
        print_event("error", name, cat, elapsed, str(ex))
        return {
            "ok": False,
            "name": name,
            "category": cat,
            "result": f"ERROR: {ex}",
            "error": str(ex),
            "elapsed_ms": round(elapsed, 2)
        }


@app.get("/api/cache/stats", tags=["Intelligence"])
def get_cache_stats() -> dict:
    """LRU result-cache performance statistics (hits, misses, evictions)."""
    return {"ok": True, **cache_snapshot()}


@app.post("/api/intelligence/analyze-target", tags=["Intelligence"])
def intel_analyze_target(payload: dict) -> dict:
    """Decision engine: analyze a target/problem statement and recommend a tool chain."""
    return {"ok": True, "result": run_tool("analyze_target", payload)}


@app.post("/api/intelligence/select-tools", tags=["Intelligence"])
def intel_select_tools(payload: dict) -> dict:
    """Decision engine: recommend the best tools for a task."""
    return {"ok": True, "result": run_tool("select_tools", payload)}


@app.post("/api/intelligence/optimize-parameters", tags=["Intelligence"])
def intel_optimize_parameters(payload: dict) -> dict:
    """Decision engine: parameter contract + validation for a tool."""
    return {"ok": True, "result": run_tool("optimize_parameters", payload)}


@app.get("/api/categories/{category}", tags=["Categories"])
@app.get("/api/{category}", tags=["Categories"])
def get_category_tools(category: str) -> dict:
    """List all tools within a specific category (e.g. crypto, encoding, web, forensics, pwn, rev, stego, osint, misc)."""
    items = [t for t in list_tools() if t["category"].lower() == category.lower()]
    if not items:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found or contains no tools.")
    return {
        "category": category.lower(),
        "total": len(items),
        "tools": items
    }


@app.post("/api/categories/{category}/{tool_name}", tags=["Categories"])
@app.post("/api/{category}/{tool_name}", tags=["Categories"])
async def execute_category_tool(category: str, tool_name: str, payload: dict | None = None) -> dict:
    """Execute a specific security or CTF tool under its dedicated category namespace."""
    body = payload or {}
    if isinstance(body, dict) and ("arguments" in body or "args" in body):
        args = body.get("arguments") or body.get("args") or {}
    else:
        args = body

    tool = TOOLS.get(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found.")
    if tool.get("category", "").lower() != category.lower():
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{tool_name}' belongs to category '{tool.get('category')}', not '{category}'."
        )
    return await execute_request({"name": tool_name, "arguments": args})


@app.post("/upload", tags=["Files"])
@app.post("/api/upload", tags=["Files"])
async def upload_challenge_file(file: UploadFile = File(...)) -> dict:
    """Upload challenge artifact (PCAP, firmware, image, binary, zip) for tool analysis."""
    upload_dir = os.path.join(os.path.dirname(__file__), "testdata", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    clean_name = os.path.basename(file.filename or "upload.bin")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Upload exceeds {MAX_UPLOAD_BYTES} bytes")
    stored_name = f"{secrets.token_hex(8)}_{clean_name}"
    file_path = os.path.join(upload_dir, stored_name)
    with open(file_path, "wb") as f:
        f.write(content)
    rel_path = f"testdata/uploads/{stored_name}"
    
    print_event("success", clean_name, "upload", detail=f"{len(content):,} bytes → {rel_path}")
    
    return {
        "ok": True,
        "path": rel_path,
        "filename": clean_name,
        "size": len(content),
        "message": f"File uploaded successfully to {rel_path}. Pass this path to tools like triage_file, strings_extract, etc."
    }


def print_server_dashboard(host: str, port: int):
    """Render a compact startup dashboard without fake loading delays."""
    base = f"http://{host}:{port}"

    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        "[bold cyan]╔═╗╔╦╗╔═╗  ╦╔═╦╔╦╗[/bold cyan]\n"
        "[bold cyan]║   ║ ╠╣   ╠╩╗║ ║ [/bold cyan]\n"
        "[bold cyan]╚═╝ ╩ ╚    ╩ ╩╩ ╩ [/bold cyan]",
        f"[green]● ONLINE[/green]\n[dim]version {__version__}[/dim]",
    )
    header.add_row(
        "[dim]Autonomous security workspace[/dim]",
        f"[bold]{len(TOOLS)}[/bold] [dim]tools  •  {len(CATEGORIES)} categories[/dim]",
    )
    console.print(Panel(header, border_style="cyan", box=box.ROUNDED, padding=(0, 1)))

    endpoints = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    endpoints.add_column(style="dim", width=10)
    endpoints.add_column(style="cyan")
    endpoints.add_row("API", base)
    endpoints.add_row("Docs", f"{base}/docs")
    endpoints.add_row("Health", f"{base}/health")
    endpoints.add_row("Security", "Bearer token" if API_TOKEN else "Localhost")

    categories = Table.grid(expand=True, padding=(0, 2))
    for _ in range(3):
        categories.add_column(ratio=1)
    cells = []
    for cat in CATEGORIES:
        count = sum(1 for item in TOOLS.values() if item["category"] == cat)
        cells.append(f"{CAT_ICONS.get(cat, '•')} [dim]{cat:<11}[/dim] [bold green]{count:>3}[/bold green]")
    for index in range(0, len(cells), 3):
        categories.add_row(*cells[index:index + 3])

    console.print(Panel(endpoints, title="[bold]Endpoints[/bold]", border_style="grey37", box=box.ROUNDED))
    console.print(Panel(categories, title="[bold]Registry[/bold]", border_style="grey37", box=box.ROUNDED))
    console.print("[dim]Tool activity[/dim]  [grey37]────────────────────────────────────────[/grey37]")


def main():
    parser = argparse.ArgumentParser(description="CTF Kit Main Server Engine")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port number (default 8765)")
    args = parser.parse_args()

    if not is_loopback_host(args.host) and not API_TOKEN:
        parser.error("CTFKIT_API_TOKEN is required when binding REST to a non-loopback host")

    print_server_dashboard(args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
