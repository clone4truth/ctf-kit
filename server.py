#!/usr/bin/env python3
"""CTF KIT — Main Server Engine

Core backend server managing 90 security & CTF operations with REST API,
Swagger UI documentation, and rich visual telemetry.

Usage:
    python server.py [--host 127.0.0.1] [--port 8765]
"""

import argparse
import asyncio
import datetime
import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn
from fastapi import FastAPI, UploadFile, File, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn
)

from ctfkit import __version__
from ctfkit.registry import TOOLS, run_tool, list_tools, CATEGORIES
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

app = FastAPI(
    title="CTF Kit — AI Security & CTF Engine",
    description="Headless Security & CTF Engine exposing cybersecurity tools for AI Agents and REST clients.",
    version=__version__,
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


@app.get("/health", tags=["Status"])
@app.get("/api/health", tags=["Status"])
def health() -> dict:
    """Comprehensive telemetry, operational readiness, and tool status."""
    categories = sorted(list({t["category"] for t in TOOLS.values()}))
    return {
        "status": "ok",
        "ready": True,
        "version": __version__,
        "server_engine": "CTF Kit",
        "tools_registered": len(TOOLS),
        "categories_count": len(categories),
        "categories": categories,
        "mcp_enabled": True,
        "uptime_seconds": round(time.monotonic(), 2),
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
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    tool_meta = TOOLS[name]
    cat = tool_meta.get("category", "tool")
    icon = CAT_ICONS.get(cat, "⚡")

    console.print(f"[dim]{timestamp}[/dim] [bold cyan]▶ RUNNING[/bold cyan] {icon} [bold white]{name}[/bold white] [dim]({cat})[/dim]")

    try:
        result = await asyncio.get_running_loop().run_in_executor(None, run_tool, name, args)
        elapsed = (time.monotonic() - start) * 1000
        is_error = isinstance(result, str) and result.startswith("ERROR:")
        
        if is_error:
            console.print(f"[dim]{timestamp}[/dim] [bold red]✖ FAILED[/bold red]  {icon} [bold white]{name}[/bold white] [red]({elapsed:.1f}ms)[/red]")
        else:
            console.print(f"[dim]{timestamp}[/dim] [bold green]✔ FINISHED[/bold green] {icon} [bold white]{name}[/bold white] [green]({elapsed:.1f}ms)[/green]")

        return {
            "ok": not is_error,
            "name": name,
            "result": result,
            "error": result if is_error else None,
            "elapsed_ms": round(elapsed, 2)
        }
    except Exception as ex:
        elapsed = (time.monotonic() - start) * 1000
        console.print(f"[dim]{timestamp}[/dim] [bold red]✖ EXCEPTION[/bold red] {icon} [bold white]{name}[/bold white]: {ex}")
        return {
            "ok": False,
            "name": name,
            "result": f"ERROR: {ex}",
            "error": str(ex),
            "elapsed_ms": round(elapsed, 2)
        }


@app.post("/upload", tags=["Files"])
@app.post("/api/upload", tags=["Files"])
async def upload_challenge_file(file: UploadFile = File(...)) -> dict:
    """Upload challenge artifact (PCAP, firmware, image, binary, zip) for tool analysis."""
    upload_dir = os.path.join(os.path.dirname(__file__), "testdata", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    clean_name = os.path.basename(file.filename or "upload.bin")
    file_path = os.path.join(upload_dir, clean_name)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    rel_path = f"testdata/uploads/{clean_name}"
    
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{timestamp}[/dim] [bold magenta]📦 UPLOADED[/bold magenta] [bold white]{clean_name}[/bold white] [dim]({len(content)} bytes -> {rel_path})[/dim]")
    
    return {
        "ok": True,
        "path": rel_path,
        "filename": clean_name,
        "size": len(content),
        "message": f"File uploaded successfully to {rel_path}. Pass this path to tools like triage_file, strings_extract, etc."
    }


def animate_initialization():
    """Display slick progress bar and category loading animation on startup."""
    console.print(Align.center(BANNER))
    console.print("")

    categories = list(CATEGORIES.keys())
    
    with Progress(
        SpinnerColumn("dots12", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=32, style="grey37", complete_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[bold cyan]Initializing CTF Kit Engine...", total=len(categories) + 1)
        
        for cat in categories:
            icon = CAT_ICONS.get(cat, "•")
            label = CATEGORIES.get(cat, cat.upper())
            tools_in_cat = [t for t in TOOLS.values() if t["category"] == cat]
            progress.update(task, description=f"Loading {icon} {label} ({len(tools_in_cat)} tools)...", advance=1)
            time.sleep(0.04)
            
        progress.update(task, description="[bold green]Readying JSON-RPC MCP Bridge...", advance=1)
        time.sleep(0.05)


def print_server_dashboard(host: str, port: int):
    """Render modern cyberpunk server status dashboard."""
    # Summary Grid
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)

    # Server Info Table
    info_table = Table(show_header=False, box=None, padding=(0, 1))
    info_table.add_row("[bold cyan]API Server URL:[/bold cyan]", f"[bold green]http://{host}:{port}[/bold green]")
    info_table.add_row("[bold cyan]Interactive Docs:[/bold cyan]", f"[bold yellow]http://{host}:{port}/docs[/bold yellow]")
    info_table.add_row("[bold cyan]Health Telemetry:[/bold cyan]", f"[bold cyan]http://{host}:{port}/health[/bold cyan]")
    info_table.add_row("[bold cyan]MCP Protocol:[/bold cyan]", "[bold white]mcp_server.py (stdio)[/bold white]")

    # Category Breakdown Table
    cat_table = Table(show_header=False, box=None, padding=(0, 1))
    for cat, label in list(CATEGORIES.items())[:5]:
        icon = CAT_ICONS.get(cat, "•")
        count = sum(1 for t in TOOLS.values() if t["category"] == cat)
        cat_table.add_row(f"{icon} [bold white]{label}[/bold white]", f"[bold green]{count} tools[/bold green]")

    grid.add_row(
        Panel(info_table, title="[bold cyan]⚡ SERVER STATUS[/bold cyan]", border_style="cyan"),
        Panel(cat_table, title="[bold green]📦 MODULE TELEMETRY[/bold green]", border_style="green")
    )

    console.print(grid)
    console.print(Panel(
        f"[bold green]✔ ENGINE ONLINE:[/bold green] [bold white]{len(TOOLS)} Tools Active[/bold white] | "
        f"[bold yellow]Listening on http://{host}:{port}[/bold yellow] | "
        f"[dim]Press Ctrl+C to Stop[/dim]",
        border_style="bright_blue"
    ))
    console.print("")


def main():
    parser = argparse.ArgumentParser(description="CTF Kit Main Server Engine")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port number (default 8765)")
    args = parser.parse_args()

    animate_initialization()
    print_server_dashboard(args.host, args.port)
    uvicorn.run("server.py:app", host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
