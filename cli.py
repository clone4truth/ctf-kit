#!/usr/bin/env python3
"""CTF KIT — Command Line Interface (CLI)

Usage:
    python cli.py list [--category <cat>]
    python cli.py run <tool> [--param value ...]
    python cli.py triage <file_path>
    python cli.py info <tool>
    python cli.py extract <text_or_file>
    python cli.py api [--port 8765]
    python cli.py mcp
"""

import argparse
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import ctfkit.modules  # noqa
from ctfkit.registry import TOOLS, run_tool, list_tools
from ctfkit.flagmeta import detect_flag


def cmd_list(args):
    tools = list_tools()
    if args.category:
        tools = [t for t in tools if t["category"].lower() == args.category.lower()]

    if args.json:
        print(json.dumps(tools, indent=2))
        return

    print(f"\n⚡ CTF KIT — Registered Tools ({len(tools)} tools):\n" + "=" * 60)
    current_cat = ""
    for t in sorted(tools, key=lambda x: (x["category"], x["name"])):
        if t["category"] != current_cat:
            current_cat = t["category"]
            print(f"\n[{current_cat.upper()}]")
        print(f"  • {t['name']:<24} - {t.get('summary', '')}")
    print("\n" + "=" * 60)


def cmd_run(args, extra_args):
    tool_name = args.tool
    tool_info = TOOLS.get(tool_name)
    if not tool_info:
        print(f"Error: Tool '{tool_name}' not found. Run 'python cli.py list' to see available tools.", file=sys.stderr)
        sys.exit(1)

    # Parse extra args of format --key value or --flag
    kwargs = {}
    i = 0
    while i < len(extra_args):
        arg = extra_args[i]
        if arg.startswith("--"):
            key = arg[2:]
            if i + 1 < len(extra_args) and not extra_args[i + 1].startswith("--"):
                val = extra_args[i + 1]
                i += 2
            else:
                val = True
                i += 1
            kwargs[key] = val
        else:
            i += 1

    try:
        output = run_tool(tool_name, kwargs)
        print(output)
        flag = detect_flag(output)
        if flag:
            print(f"\n[🏆 FLAG FOUND]: {flag}")
    except Exception as ex:
        print(f"Error executing {tool_name}: {ex}", file=sys.stderr)
        sys.exit(1)


def cmd_triage(args):
    path = args.file
    if not os.path.exists(path):
        print(f"Error: File '{path}' not found.", file=sys.stderr)
        sys.exit(1)

    output = run_tool("triage_file", {"path": path})
    print(output)
    flag = detect_flag(output)
    if flag:
        print(f"\n[🏆 FLAG FOUND]: {flag}")


def cmd_info(args):
    tool_name = args.tool
    tool_info = TOOLS.get(tool_name)
    if not tool_info:
        print(f"Error: Tool '{tool_name}' not found.", file=sys.stderr)
        sys.exit(1)

    print(f"\nTool: {tool_name}")
    print(f"Category: {tool_info.category}")
    print(f"Description: {tool_info.summary}")
    print("\nParameters:")
    for p in tool_info.parameters:
        req = "required" if p.required else f"optional (default: {p.default})"
        print(f"  --{p.name:<16} [{p.type}] - {req} - {p.doc or ''}")
    print("")


def cmd_extract(args):
    target = args.target
    if os.path.exists(target):
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        content = target

    output = run_tool("extract_flags_tool", {"text": content})
    print(output)


def main():
    parser = argparse.ArgumentParser(description="CTF Kit — Command Line Security & CTF Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # list
    p_list = subparsers.add_parser("list", help="List all available tools")
    p_list.add_argument("-c", "--category", help="Filter by category")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")

    # run
    p_run = subparsers.add_parser("run", help="Run a tool with arguments")
    p_run.add_argument("tool", help="Tool name to execute")

    # triage
    p_triage = subparsers.add_parser("triage", help="Auto-triage a challenge file")
    p_triage.add_argument("file", help="Path to mystery file")

    # info
    p_info = subparsers.add_parser("info", help="Get parameter schema and doc for a tool")
    p_info.add_argument("tool", help="Tool name")

    # extract
    p_ext = subparsers.add_parser("extract", help="Extract flags from text or file")
    p_ext.add_argument("target", help="Text or file path")

    # mcp
    subparsers.add_parser("mcp", help="Launch Headless MCP stdio Server")

    # api
    p_api = subparsers.add_parser("api", help="Launch Headless REST API Server")
    p_api.add_argument("-p", "--port", type=int, default=8765, help="Port to listen on (default 8765)")
    p_api.add_argument("--host", default="127.0.0.1", help="Host (default 127.0.0.1)")

    # tui
    subparsers.add_parser("tui", help="Launch Interactive Terminal UI")

    args, extra = parser.parse_known_args()

    if args.command == "list":
        cmd_list(args)
    elif args.command == "run":
        cmd_run(args, extra)
    elif args.command == "triage":
        cmd_triage(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "extract":
        cmd_extract(args)
    elif args.command == "mcp":
        from mcp_server import main as mcp_main
        mcp_main()
    elif args.command == "api" or args.command == "server":
        import uvicorn
        print(f"Starting Headless REST API on http://{args.host}:{args.port} (Swagger docs: http://{args.host}:{args.port}/docs)")
        uvicorn.run("server:app", host=args.host, port=args.port, log_level="info")
    elif args.command == "tui":
        from tui import show_dashboard
        show_dashboard()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
