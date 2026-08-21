#!/usr/bin/env python3
"""CTF KIT — Headless MCP Server (stdio JSON-RPC).

Exposes the registered cybersecurity and CTF operations directly to AI agents
(Claude Desktop, Cursor, Cline, Copilot, OpenCode, VS Code) via MCP protocol.

MCP and REST both call the same canonical execution engine.

Usage:
    python mcp_server.py
"""

import functools
import argparse
import inspect
import os
import sys
from typing import Any
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ctfkit.modules  # noqa: F401
from ctfkit import __version__
from ctfkit.mcp_client import BackendUnavailable, CTFKitBackendClient
from ctfkit.registry import TOOLS, execute_tool
from ctfkit.logging import log

console = Console(stderr=True)
MCP_PROFILE = os.environ.get("CTFKIT_MCP_PROFILE", "full").strip().lower()
BACKEND: CTFKitBackendClient | None = None
SIMPLE_TOOLS = {
    "detect_challenge", "plan_challenge", "recall_knowledge", "cve_research",
    "extract_flags_tool", "select_tools", "smart_tool_recommend",
    "autonomous_solve", "chain_tools", "remember_challenge",
    "external_available", "self_diagnose",
}
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


def find_ctf_tools(query: str = "", category: str = "", limit: int = 12) -> dict[str, Any]:
    """Find the best CTF Kit tools without loading all tool schemas.

    :param query: technique, artifact, vulnerability, or task keywords
    :param category: optional category filter
    :param limit: maximum compact matches to return
    """
    words = [word for word in query.lower().split() if word]
    matches = []
    for meta in TOOLS.values():
        if category and meta["category"].lower() != category.lower():
            continue
        haystack = f"{meta['name']} {meta['summary']} {meta['doc']}".lower()
        score = sum(3 if word in meta["name"].lower() else 1 for word in words if word in haystack)
        if words and score == 0:
            continue
        matches.append((score, meta["name"], meta))
    matches.sort(key=lambda item: (-item[0], item[1]))
    items = [
        {
            "name": meta["name"], "category": meta["category"],
            "summary": meta["summary"], "parameters": meta["params"],
        }
        for _, _, meta in matches[:max(1, min(int(limit), 50))]
    ]
    return {"query": query, "category": category or None, "count": len(items), "tools": items}


def run_ctf_tool(tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run any registered CTF Kit tool by name through the canonical executor.

    Use find_ctf_tools first when the correct tool or parameters are unknown.

    :param tool_name: exact registered tool name
    :param arguments: tool arguments from find_ctf_tools
    """
    return _execute(tool_name, arguments or {})


def backend_health() -> dict[str, Any]:
    """Check MCP transport mode and central backend readiness."""
    if BACKEND is None:
        return {"mode": "local", "ready": True, "tools_registered": len(TOOLS)}
    return {"mode": "remote", "server": BACKEND.server_url, **BACKEND.health()}


def backend_telemetry() -> dict[str, Any]:
    """Get centralized REST/MCP execution telemetry from the backend."""
    if BACKEND is None:
        return {"mode": "local", "note": "central telemetry requires --server"}
    return {"mode": "remote", "server": BACKEND.server_url, **BACKEND.telemetry()}


def _background_error(ex: BackendUnavailable) -> dict[str, Any]:
    message = str(ex)
    status = "invalid_input" if "backend HTTP 400" in message else "unavailable"
    return {"ok": False, "status": status, "error": message}


def submit_background_job(tool_name: str,
                          arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a registered tool asynchronously in the central backend.

    Use this for long-running scans or analysis, then poll get_background_job.
    Requires MCP remote-backend mode (`--server`).

    :param tool_name: exact registered tool name
    :param arguments: tool arguments from find_ctf_tools
    """
    if BACKEND is None:
        return {"ok": False, "status": "unavailable", "error": "background jobs require --server"}
    try:
        return BACKEND.submit_job(tool_name, arguments or {})
    except BackendUnavailable as ex:
        return _background_error(ex)


def get_background_job(job_id: str, output_offset: int = 0) -> dict[str, Any]:
    """Get background-job status, result, and incremental server log output.

    :param job_id: job ID returned by submit_background_job
    :param output_offset: byte cursor returned by the previous call
    """
    if BACKEND is None:
        return {"ok": False, "status": "unavailable", "error": "background jobs require --server"}
    try:
        return {
            "status": BACKEND.get_job(job_id),
            "output": BACKEND.get_job_output(job_id, offset=output_offset),
        }
    except BackendUnavailable as ex:
        return _background_error(ex)


def list_background_jobs(status: str = "", limit: int = 50) -> dict[str, Any]:
    """List persisted backend jobs, optionally filtered by lifecycle state.

    :param status: active, queued, running, cancelling, completed, failed, cancelled, or interrupted
    :param limit: maximum jobs to return
    """
    if BACKEND is None:
        return {"ok": False, "status": "unavailable", "error": "background jobs require --server"}
    try:
        return BACKEND.list_jobs(status=status, limit=limit)
    except BackendUnavailable as ex:
        return _background_error(ex)


def cancel_background_job(job_id: str) -> dict[str, Any]:
    """Cancel a queued job or terminate its complete backend process group.

    :param job_id: job ID returned by submit_background_job
    """
    if BACKEND is None:
        return {"ok": False, "status": "unavailable", "error": "background jobs require --server"}
    try:
        return BACKEND.cancel_job(job_id)
    except BackendUnavailable as ex:
        return _background_error(ex)


def _execute(name: str, arguments: dict | None = None) -> dict[str, Any]:
    if BACKEND is None:
        return execute_tool(name, arguments or {})
    try:
        return BACKEND.execute_tool(name, arguments or {})
    except BackendUnavailable as ex:
        return {
            "tool": name, "category": TOOLS.get(name, {}).get("category", "unknown"),
            "status": "unavailable", "ok": False, "text": f"BACKEND UNAVAILABLE: {ex}",
            "error": str(ex), "duration_ms": 0.0, "cached": False, "flags": [], "warnings": [],
        }


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
        return _execute(tool_name, dict(arguments))

    bridge_fn.__signature__ = sig.replace(return_annotation=dict[str, Any])
    bridge_fn.__name__ = tool_name
    bridge_fn.__doc__ = meta["doc"] or meta["summary"]
    return bridge_fn


def build_server() -> MCPServer:
    selected = TOOLS.values() if MCP_PROFILE == "full" else (
        meta for name, meta in TOOLS.items() if name in SIMPLE_TOOLS
    )
    selected_count = 0
    for meta in selected:
        selected_count += 1
        bridge = make_execution_bridge(meta)
        annotations = ToolAnnotations(
            title=meta["name"], readOnlyHint=meta["read_only"],
            destructiveHint=meta["destructive"], idempotentHint=meta["idempotent"],
            openWorldHint=meta["open_world"],
        )
        server.add_tool(bridge, name=meta["name"], description=meta["doc"] or meta["summary"],
                        annotations=annotations, structured_output=True)
    if MCP_PROFILE != "full":
        server.add_tool(find_ctf_tools, name="find_ctf_tools", structured_output=True)
        server.add_tool(run_ctf_tool, name="run_ctf_tool", structured_output=True)
        selected_count += 2
    server.add_tool(backend_health, name="backend_health", structured_output=True)
    server.add_tool(backend_telemetry, name="backend_telemetry", structured_output=True)
    server.add_tool(submit_background_job, name="submit_background_job", structured_output=True)
    server.add_tool(get_background_job, name="get_background_job", structured_output=True)
    server.add_tool(list_background_jobs, name="list_background_jobs", structured_output=True)
    server.add_tool(cancel_background_job, name="cancel_background_job", structured_output=True)
    selected_count += 6
    log.info("MCP server ready: profile=%s, %d schemas exposed, %d tools executable",
             MCP_PROFILE, selected_count, len(TOOLS))
    return server


def print_interactive_notice():
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold cyan]Status:[/bold cyan]", "[bold green]Listening for JSON-RPC 2.0 on STDIN/STDOUT[/bold green]")
    table.add_row("[bold cyan]Profile:[/bold cyan]", f"[bold magenta]{MCP_PROFILE}[/bold magenta]")
    table.add_row("[bold cyan]Available Tools:[/bold cyan]", f"[bold magenta]{len(TOOLS)} tools across {len(set(t['category'] for t in TOOLS.values()))} categories[/bold magenta]")
    execution = f"Central REST backend — {BACKEND.server_url}" if BACKEND else "Canonical local engine"
    table.add_row("[bold cyan]Execution:[/bold cyan]", f"[bold green]{execution}[/bold green]")
    table.add_row("[bold cyan]AI Clients:[/bold cyan]", "[bold white]Claude Desktop, Cursor, Cline, OpenCode, Copilot[/bold white]")
    table.add_row("[bold cyan]REST Server:[/bold cyan]", "[bold yellow]python server.py (OpenAPI at /docs)[/bold yellow]")
    table.add_row("[bold cyan]Test Protocol:[/bold cyan]", "[bold cyan]python tests/test_mcp.py[/bold cyan]")
    
    console.print(Panel(table, title="[bold green]⚡ CTF KIT — MCP GATEWAY BRIDGE (STDIO MODE)[/bold green]", border_style="cyan"))
    console.print("[dim]This process bridges AI Agent tool calls to the central FastAPI Gateway. Press Ctrl+C to exit.[/dim]\n")


def parse_args():
    parser = argparse.ArgumentParser(description="CTF Kit MCP bridge")
    parser.add_argument("--server", default=os.environ.get("CTFKIT_SERVER_URL", ""),
                        help="central REST backend URL; omit for local compatibility mode")
    parser.add_argument("--token", default=os.environ.get("CTFKIT_API_TOKEN", ""),
                        help="backend bearer token (prefer CTFKIT_API_TOKEN)")
    parser.add_argument("--timeout", type=float, default=300, help="backend request timeout")
    parser.add_argument("--retries", type=int, default=2, help="backend connection retries")
    return parser.parse_args()


def main():
    global BACKEND
    args = parse_args()
    if args.server:
        BACKEND = CTFKitBackendClient(args.server, token=args.token, timeout=args.timeout,
                                      retries=args.retries)
        try:
            health = BACKEND.health()
            if not health.get("ready"):
                raise BackendUnavailable(f"backend is degraded: {health.get('checks', {})}")
        except BackendUnavailable as ex:
            log.error("MCP backend connection failed: %s", ex)
            raise SystemExit(2) from ex
    build_server()
    if sys.stdin.isatty():
        print_interactive_notice()
    try:
        server.run()  # transport default: stdio
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
