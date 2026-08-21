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
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn
from fastapi import FastAPI, UploadFile, File, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.cache import snapshot as cache_snapshot
from ctfkit.config import is_loopback_host, settings
from ctfkit.registry import TOOLS, execute_tool as execute_registered_tool, run_tool, list_tools, CATEGORIES
from ctfkit.logging import log
from ctfkit.jobs import JobManager, JobNotFound

console = Console()
STARTED_AT = time.monotonic()
MAX_UPLOAD_BYTES = settings.max_upload_bytes
_TELEMETRY_LOCK = threading.RLock()
_ACTIVE_EXECUTIONS: dict[str, dict] = {}
_RECENT_EXECUTIONS: list[dict] = []
_STATUS_COUNTS: dict[str, int] = {}
_TOOL_COUNTS: dict[str, int] = {}
try:
    _JOB_WORKERS = int(os.environ.get("CTFKIT_JOB_WORKERS", "4"))
except ValueError:
    _JOB_WORKERS = 4
JOB_MANAGER = JobManager(
    Path(__file__).resolve().parent / "memory" / "jobs",
    max_workers=_JOB_WORKERS,
)

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
    "cancelled": ("CANCEL", "magenta", "■"),
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
    suffix = f"  [dim]│ {escape(str(detail))}[/dim]" if detail else ""
    console.print(
        f"[dim]{timestamp}[/dim]  [{color}]{symbol} {label:<5}[/{color}]  "
        f"[bold]{escape(str(name))}[/bold]  [dim]{escape(str(category))}[/dim]{duration}{suffix}"
    )


def _track_start(name: str, category: str, source: str) -> str:
    run_id = secrets.token_hex(6)
    with _TELEMETRY_LOCK:
        _ACTIVE_EXECUTIONS[run_id] = {
            "id": run_id, "tool": name, "category": category, "source": source,
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "started_monotonic": time.monotonic(),
        }
    return run_id


def _track_finish(run_id: str, result: dict, elapsed_ms: float) -> None:
    with _TELEMETRY_LOCK:
        item = _ACTIVE_EXECUTIONS.pop(run_id, {"id": run_id})
        item.pop("started_monotonic", None)
        item.update({
            "status": result.get("status", "error"), "ok": bool(result.get("ok")),
            "cached": bool(result.get("cached")), "duration_ms": round(elapsed_ms, 2),
            "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
        _RECENT_EXECUTIONS.append(item)
        del _RECENT_EXECUTIONS[:-200]
        status = item["status"]
        tool_name = item.get("tool", "unknown")
        _STATUS_COUNTS[status] = _STATUS_COUNTS.get(status, 0) + 1
        _TOOL_COUNTS[tool_name] = _TOOL_COUNTS.get(tool_name, 0) + 1

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
        "job_manager": JOB_MANAGER.max_workers > 0,
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


async def _execute_payload(payload: dict, source: str = "rest") -> dict:
    """Execute one request while tracking centralized telemetry and correlation."""
    name = payload.get("name", "")
    args = payload.get("arguments") or payload.get("args") or {}

    if not name or name not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")

    start = time.monotonic()
    tool_meta = TOOLS[name]
    cat = tool_meta.get("category", "tool")
    run_id = _track_start(name, cat, source)
    print_event("start", name, cat, detail=f"source={source} run={run_id}")

    try:
        result = await asyncio.get_running_loop().run_in_executor(None, execute_registered_tool, name, args)
        elapsed = (time.monotonic() - start) * 1000
        _track_finish(run_id, result, elapsed)
        print_event(result.get("status", "error"), name, cat, elapsed,
                    f"source={source} run={run_id}")

        return {**result, "name": name, "result": result["text"],
                "elapsed_ms": round(elapsed, 2), "execution_id": run_id, "source": source}
    except Exception as ex:
        elapsed = (time.monotonic() - start) * 1000
        result = {
            "ok": False,
            "name": name,
            "category": cat,
            "status": "error",
            "result": f"ERROR: {ex}",
            "error": str(ex),
            "elapsed_ms": round(elapsed, 2),
            "execution_id": run_id,
            "source": source,
        }
        _track_finish(run_id, result, elapsed)
        print_event("error", name, cat, elapsed, f"source={source} run={run_id} error={ex}")
        return result


@app.post("/api/run", tags=["Execution"])
async def execute_request(payload: dict, request: Request) -> dict:
    """Execute a security or CTF tool asynchronously in the central backend."""
    source = request.headers.get("X-CTFKit-Source", "rest")[:40]
    return await _execute_payload(payload, source=source)


@app.get("/api/cache/stats", tags=["Intelligence"])
def get_cache_stats() -> dict:
    """LRU result-cache performance statistics (hits, misses, evictions)."""
    return {"ok": True, **cache_snapshot()}


@app.get("/api/telemetry", tags=["Status"])
def get_telemetry() -> dict:
    """Central execution telemetry shared by REST and remote MCP clients."""
    with _TELEMETRY_LOCK:
        return {
            "ok": True,
            "uptime_seconds": round(time.monotonic() - STARTED_AT, 2),
            "total_executions": sum(_STATUS_COUNTS.values()),
            "active_executions": len(_ACTIVE_EXECUTIONS),
            "status_counts": dict(sorted(_STATUS_COUNTS.items())),
            "tool_counts": dict(sorted(_TOOL_COUNTS.items(), key=lambda item: (-item[1], item[0]))),
            "cache": cache_snapshot(),
            "jobs": JOB_MANAGER.stats(),
            "recent": list(reversed(_RECENT_EXECUTIONS[-20:])),
        }


@app.get("/api/executions", tags=["Status"])
def list_active_executions() -> dict:
    """List executions currently active in the central backend."""
    now = time.monotonic()
    with _TELEMETRY_LOCK:
        items = []
        for value in _ACTIVE_EXECUTIONS.values():
            item = {key: val for key, val in value.items() if key != "started_monotonic"}
            item["runtime_seconds"] = round(now - value["started_monotonic"], 3)
            items.append(item)
    return {"ok": True, "count": len(items), "executions": items}


@app.get("/api/processes/list", tags=["Status"])
def list_active_processes() -> dict:
    """Compatibility view of active synchronous executions and background jobs."""
    executions = list_active_executions()["executions"]
    jobs = JOB_MANAGER.list(status="active", limit=500)
    return {
        "ok": True, "count": len(executions) + len(jobs),
        "executions": executions, "jobs": jobs,
    }


@app.get("/api/executions/{run_id}", tags=["Status"])
def get_execution_status(run_id: str) -> dict:
    """Get active or recent execution status by correlation ID."""
    with _TELEMETRY_LOCK:
        if run_id in _ACTIVE_EXECUTIONS:
            value = _ACTIVE_EXECUTIONS[run_id]
            item = {key: val for key, val in value.items() if key != "started_monotonic"}
            item["runtime_seconds"] = round(time.monotonic() - value["started_monotonic"], 3)
            return {"ok": True, "state": "active", "execution": item}
        for item in reversed(_RECENT_EXECUTIONS):
            if item.get("id") == run_id:
                return {"ok": True, "state": "finished", "execution": item}
    raise HTTPException(status_code=404, detail=f"Execution '{run_id}' not found.")


@app.post("/api/jobs", tags=["Jobs"], status_code=202)
async def submit_job(payload: dict, request: Request) -> dict:
    """Queue a registered tool in a bounded, killable background process."""
    tool_name = payload.get("name") or payload.get("tool_name") or ""
    arguments = payload.get("arguments") or payload.get("args") or {}
    source = request.headers.get("X-CTFKit-Source", "rest")[:40]
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        raise HTTPException(status_code=400, detail="name must be a string and arguments must be an object")
    try:
        job = JOB_MANAGER.submit(tool_name, arguments, source=source)
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex)) from ex
    print_event("start", tool_name, job["category"], detail=f"source={source} job={job['id']}")
    return {"ok": True, "job": job}


@app.get("/api/jobs", tags=["Jobs"])
def list_jobs(status: str = "", limit: int = 100) -> dict:
    """List persisted background jobs, newest first."""
    jobs = JOB_MANAGER.list(status=status, limit=limit)
    return {"ok": True, "count": len(jobs), "jobs": jobs}


@app.get("/api/jobs/{job_id}", tags=["Jobs"])
def get_job(job_id: str) -> dict:
    """Get job lifecycle metadata and the final structured result, if ready."""
    try:
        return {"ok": True, "job": JOB_MANAGER.get(job_id)}
    except JobNotFound as ex:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.") from ex


@app.get("/api/jobs/{job_id}/output", tags=["Jobs"])
def get_job_output(job_id: str, offset: int = 0, limit: int = 65536) -> dict:
    """Read an incremental chunk of job logs using a byte cursor."""
    try:
        return {"ok": True, **JOB_MANAGER.read_output(job_id, offset=offset, limit=limit)}
    except JobNotFound as ex:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.") from ex


@app.get("/api/jobs/{job_id}/stream", tags=["Jobs"])
def stream_job_output(job_id: str, offset: int = 0) -> StreamingResponse:
    """Stream incremental job logs and the terminal state as SSE events."""
    try:
        JOB_MANAGER.get(job_id, include_result=False)
    except JobNotFound as ex:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.") from ex

    async def events():
        cursor = max(0, int(offset))
        idle_ticks = 0
        while True:
            chunk = JOB_MANAGER.read_output(job_id, offset=cursor)
            cursor = chunk["next_offset"]
            if chunk["output"]:
                yield f"event: output\ndata: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                idle_ticks = 0
            else:
                idle_ticks += 1
            if chunk["terminal"]:
                job = JOB_MANAGER.get(job_id, include_result=False)
                yield f"event: status\ndata: {json.dumps(job, ensure_ascii=False)}\n\n"
                return
            if idle_ticks >= 40:
                yield ": keep-alive\n\n"
                idle_ticks = 0
            await asyncio.sleep(0.25)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/jobs/{job_id}/cancel", tags=["Jobs"])
def cancel_job(job_id: str) -> dict:
    """Cancel a queued job or terminate the complete running process group."""
    try:
        job = JOB_MANAGER.cancel(job_id)
    except JobNotFound as ex:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.") from ex
    print_event("cancelled", job["tool"], job["category"], detail=f"job={job_id}")
    return {"ok": True, "job": job}


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
async def execute_category_tool(category: str, tool_name: str, request: Request,
                                payload: dict | None = None) -> dict:
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
    source = request.headers.get("X-CTFKit-Source", "rest-category")[:40]
    return await _execute_payload({"name": tool_name, "arguments": args}, source=source)


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
