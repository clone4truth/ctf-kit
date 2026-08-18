#!/usr/bin/env python3
"""CTF KIT — Main Server Engine (HexStrike-style Architecture)

Core backend server managing 90 security & CTF operations with REST API,
Swagger UI documentation, and process execution pool.

Usage:
    python server.py [--host 127.0.0.1] [--port 8765]
"""

import argparse
import asyncio
import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn
from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align

import ctfkit.modules  # noqa: F401
from ctfkit.registry import TOOLS, run_tool, list_tools
from ctfkit.logging import log

console = Console()

BANNER = """[bold cyan]
 ██████╗████████╗███████╗    ██╗  ██╗██╗████████╗
██╔════╝╚══██╔══╝██╔════╝    ██║ ██╔╝██║╚══██╔══╝
██║        ██║   █████╗      █████╔╝ ██║   ██║   
██║        ██║   ██╔══╝      ██╔═██╗ ██║   ██║   
╚██████╗   ██║   ██║         ██║  ██╗██║   ██║   
 ╚═════╝   ╚═╝   ╚═╝         ╚═╝  ╚═╝╚═╝   ╚═╝   
[/bold cyan][bold green]  ⚡ AI-POWERED CTF & SECURITY ENGINE (90 TOOLS)[/bold green]
"""

app = FastAPI(
    title="CTF Kit — AI Security & CTF Engine",
    description="HexStrike-style Headless Security & CTF Engine exposing 90 tools for AI Agents and REST clients.",
    version="2.5.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["Status"])
def health() -> dict:
    """Server health status and tool telemetry."""
    return {
        "status": "healthy",
        "engine": "ctf-kit",
        "version": "2.5.0",
        "tools_count": len(TOOLS),
        "uptime_seconds": round(time.monotonic(), 2)
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
        "name": tool.name,
        "category": tool.category,
        "summary": tool.summary,
        "doc": tool.doc,
        "parameters": [
            {
                "name": p.name,
                "type": p.type,
                "required": p.required,
                "default": p.default,
                "doc": p.doc
            }
            for p in tool.parameters
        ]
    }


@app.post("/api/run", tags=["Execution"])
async def execute_tool(payload: dict) -> dict:
    """Execute a security or CTF tool asynchronously in worker thread pool."""
    name = payload.get("name", "")
    args = payload.get("arguments") or payload.get("args") or {}

    if not name or name not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")

    start = time.monotonic()
    try:
        result = await asyncio.get_running_loop().run_in_executor(None, run_tool, name, args)
        elapsed = (time.monotonic() - start) * 1000
        is_error = isinstance(result, str) and result.startswith("ERROR:")
        return {
            "ok": not is_error,
            "name": name,
            "result": result,
            "error": result if is_error else None,
            "elapsed_ms": round(elapsed, 2)
        }
    except Exception as ex:
        elapsed = (time.monotonic() - start) * 1000
        return {
            "ok": False,
            "name": name,
            "result": f"ERROR: {ex}",
            "error": str(ex),
            "elapsed_ms": round(elapsed, 2)
        }


@app.post("/api/upload", tags=["Files"])
async def upload_challenge_file(file: UploadFile = File(...)) -> dict:
    """Upload challenge artifact or capture file for local tool inspection."""
    upload_dir = os.path.join(os.path.dirname(__file__), "testdata", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    clean_name = os.path.basename(file.filename or "upload.bin")
    file_path = os.path.join(upload_dir, clean_name)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    rel_path = f"testdata/uploads/{clean_name}"
    return {"ok": True, "path": rel_path, "filename": clean_name, "size": len(content)}


def print_server_banner(host: str, port: int):
    console.print(Align.center(BANNER))
    
    table = Table(show_header=False, box=None)
    table.add_row("[bold cyan]Server URL:[/bold cyan]", f"[bold green]http://{host}:{port}[/bold green]")
    table.add_row("[bold cyan]Swagger API Docs:[/bold cyan]", f"[bold yellow]http://{host}:{port}/docs[/bold yellow]")
    table.add_row("[bold cyan]MCP Stdio Server:[/bold cyan]", "[bold white]python mcp_server.py[/bold white]")
    table.add_row("[bold cyan]Total Operations:[/bold cyan]", f"[bold magenta]{len(TOOLS)} Tools Across 9 Modules[/bold magenta]")
    
    console.print(Panel(table, title="[bold green]⚡ CTF-KIT SERVER ONLINE[/bold green]", border_style="cyan"))
    console.print("[dim]Press Ctrl+C to terminate server process.[/dim]\n")


def main():
    parser = argparse.ArgumentParser(description="CTF Kit Server (HexStrike Architecture)")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port number (default 8765)")
    args = parser.parse_args()

    print_server_banner(args.host, args.port)
    uvicorn.run("server.py:app", host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
