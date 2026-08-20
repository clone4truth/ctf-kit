#!/usr/bin/env python3
"""CTF KIT — Headless MCP Server (stdio JSON-RPC).

Exposes the registered cybersecurity and CTF operations directly to AI agents
(Claude Desktop, Cursor, Cline, Copilot, OpenCode, VS Code) via MCP protocol.

MCP and REST both call the same canonical execution engine.

Usage:
    python mcp_server.py
"""

import functools
import inspect
import sys
from typing import Any
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.registry import TOOLS, execute_tool
from ctfkit.logging import log

console = Console(stderr=True)
server = MCPServer(
    "ctf-tools",
    version=__version__,
    description="Comprehensive CTF & security toolkit with structured results and evidence-aware flag extraction.",
    instructions=(
        "Work hypothesis-first: detect/plan, recall, research known CVEs, then execute the smallest "
        "relevant tools. Treat status=no_finding or unavailable as non-success. Only report flags with "
        "supporting evidence and confidence; do not assume flag{...}. Operate only on authorized CTF targets."
    ),
)


def make_execution_bridge(meta: dict):
    """Wrap the canonical executor while retaining each tool's input signature.

    The wrapper carries the ORIGINAL signature/docstring so MCP derives a real
    per-tool input schema (param names, types, defaults) instead of *args/**kwargs.
    """
    original_fn = meta["fn"]
    tool_name = meta["name"]
    sig = inspect.signature(original_fn)

    def bridge_fn(*args, **kwargs):
        try:
            bound = sig.bind_partial(*args, **kwargs)
            arguments = bound.arguments
        except Exception:
            arguments = dict(kwargs)
        return execute_tool(tool_name, dict(arguments))

    bridge_fn.__signature__ = sig.replace(return_annotation=dict[str, Any])
    bridge_fn.__name__ = tool_name
    bridge_fn.__doc__ = meta["doc"] or meta["summary"]
    return bridge_fn


def build_server() -> MCPServer:
    for meta in TOOLS.values():
        bridge = make_execution_bridge(meta)
        annotations = ToolAnnotations(
            title=meta["name"], readOnlyHint=meta["read_only"],
            destructiveHint=meta["destructive"], idempotentHint=meta["idempotent"],
            openWorldHint=meta["open_world"],
        )
        server.add_tool(bridge, name=meta["name"], description=meta["doc"] or meta["summary"],
                        annotations=annotations, structured_output=True)
    log.info("MCP server ready: %d tools registered (canonical local executor)", len(TOOLS))
    return server


def print_interactive_notice():
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold cyan]Status:[/bold cyan]", "[bold green]Listening for JSON-RPC 2.0 on STDIN/STDOUT[/bold green]")
    table.add_row("[bold cyan]Active Tools:[/bold cyan]", f"[bold magenta]{len(TOOLS)} tools across {len(set(t['category'] for t in TOOLS.values()))} categories[/bold magenta]")
    table.add_row("[bold cyan]Execution:[/bold cyan]", "[bold green]Canonical local engine[/bold green]")
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
