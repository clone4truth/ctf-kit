#!/usr/bin/env python3
"""CTF KIT — Headless MCP Server (stdio JSON-RPC)

Exposes 90 cybersecurity & CTF operations directly to AI Agents
(Claude Desktop, Cursor, Cline, Copilot, OpenCode, VS Code) via MCP protocol.

Usage:
    python mcp_server.py
"""

import sys
from mcp.server.mcpserver import MCPServer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.registry import TOOLS
from ctfkit.logging import log

console = Console(stderr=True)
server = MCPServer(
    "ctf-tools",
    version=__version__,
    description="Comprehensive AI-powered CTF & Security Toolkit: 90 tools covering crypto, stego, forensics, web, rev, pwn, osint, encoding."
)


def build_server() -> MCPServer:
    for meta in TOOLS.values():
        server.add_tool(meta["fn"], name=meta["name"], description=meta["doc"] or meta["summary"])
    log.info("MCP server ready: %d tools registered", len(TOOLS))
    return server


def print_interactive_notice():
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold cyan]Status:[/bold cyan]", "[bold green]Listening for JSON-RPC 2.0 on STDIN/STDOUT[/bold green]")
    table.add_row("[bold cyan]Active Tools:[/bold cyan]", f"[bold magenta]{len(TOOLS)} Tools Across 9 Modules[/bold magenta]")
    table.add_row("[bold cyan]AI Clients:[/bold cyan]", "[bold white]Claude Desktop, Cursor, Cline, OpenCode, Copilot[/bold white]")
    table.add_row("[bold cyan]REST Server:[/bold cyan]", "[bold yellow]python server.py (OpenAPI at /docs)[/bold yellow]")
    table.add_row("[bold cyan]Test Protocol:[/bold cyan]", "[bold cyan]python tests/test_mcp.py[/bold cyan]")
    
    console.print(Panel(table, title="[bold green]⚡ CTF KIT — MCP SERVER (STDIO MODE)[/bold green]", border_style="cyan"))
    console.print("[dim]This process is designed to be launched automatically by MCP clients. Press Ctrl+C to exit.[/dim]\n")


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