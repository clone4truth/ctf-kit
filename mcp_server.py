#!/usr/bin/env python3
"""CTF KIT — Headless MCP Server & Gateway Bridge (stdio JSON-RPC)

Exposes 92 cybersecurity & CTF operations directly to AI Agents
(Claude Desktop, Cursor, Cline, Copilot, OpenCode, VS Code) via MCP protocol.

Operates as a thin client bridge to the central FastAPI Gateway
(http://127.0.0.1:8765) with automatic local in-process fallback.

Usage:
    python mcp_server.py
"""

import functools
import inspect
import json
import os
import sys
import urllib.error
import urllib.request
from mcp.server.mcpserver import MCPServer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.registry import TOOLS
from ctfkit.logging import log

console = Console(stderr=True)
GATEWAY_URL = os.environ.get("CTFKIT_API_URL", "http://127.0.0.1:8765").rstrip("/")

server = MCPServer(
    "ctf-tools",
    version=__version__,
    description="Comprehensive AI-powered CTF & Security Toolkit covering crypto, stego, forensics, web, rev, pwn, osint, encoding, misc."
)


def make_gateway_bridge(meta: dict):
    """Wrap tool function to execute via FastAPI Central Gateway with local fallback."""
    original_fn = meta["fn"]
    tool_name = meta["name"]
    category = meta.get("category", "misc")
    sig = inspect.signature(original_fn)

    @functools.wraps(original_fn)
    def bridge_fn(*args, **kwargs):
        # 1. Package arguments
        try:
            bound = sig.bind_partial(*args, **kwargs)
            arguments = bound.arguments
        except Exception:
            arguments = dict(kwargs)

        # 2. Attempt execution via central FastAPI Gateway
        payload = json.dumps(arguments).encode("utf-8")
        req = urllib.request.Request(
            f"{GATEWAY_URL}/api/categories/{category}/{tool_name}",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "CTFKit-MCP-Bridge/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("result", "")
        except (urllib.error.URLError, TimeoutError, ConnectionRefusedError, OSError):
            # 3. Resilient Fallback: Execute directly in-process if server is not running
            return original_fn(*args, **kwargs)

    return bridge_fn


def build_server() -> MCPServer:
    for meta in TOOLS.values():
        bridge = make_gateway_bridge(meta)
        server.add_tool(bridge, name=meta["name"], description=meta["doc"] or meta["summary"])
    log.info("MCP server ready: %d tools registered (Gateway: %s)", len(TOOLS), GATEWAY_URL)
    return server


def print_interactive_notice():
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold cyan]Status:[/bold cyan]", "[bold green]Listening for JSON-RPC 2.0 on STDIN/STDOUT[/bold green]")
    table.add_row("[bold cyan]Active Tools:[/bold cyan]", f"[bold magenta]{len(TOOLS)} Tools Across 9 Modules[/bold magenta]")
    table.add_row("[bold cyan]Central Gateway:[/bold cyan]", f"[bold green]{GATEWAY_URL}[/bold green] [dim](FastAPI Core Engine)[/dim]")
    table.add_row("[bold cyan]AI Clients:[/bold cyan]", "[bold white]Claude Desktop, Cursor, Cline, OpenCode, Copilot[/bold white]")
    table.add_row("[bold cyan]REST Server:[/bold cyan]", "[bold yellow]python server.py (OpenAPI at /docs)[/bold yellow]")
    table.add_row("[bold cyan]Test Protocol:[/bold cyan]", "[bold cyan]python tests/test_mcp.py[/bold cyan]")
    
    console.print(Panel(table, title="[bold green]⚡ CTF KIT — MCP GATEWAY BRIDGE (STDIO MODE)[/bold green]", border_style="cyan"))
    console.print("[dim]This process bridges AI Agent tool calls to the central FastAPI Gateway. Press Ctrl+C to exit.[/dim]\n")


def main():
    build_server()
    if sys.stdin.isatty():
        print_interactive_notice()
    try:
        server.run()  # transport default: stdio
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()