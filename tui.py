#!/usr/bin/env python3
"""CTF KIT — Cyberpunk Terminal User Interface (TUI)

Interactive terminal dashboard, tool runner, and triage suite.
Usage:
    python tui.py
"""

import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.align import Align
from rich.syntax import Syntax

import ctfkit.modules  # noqa: Populates tool registry
from ctfkit.registry import TOOLS, run_tool, list_tools
from ctfkit.flagmeta import detect_flag, CATEGORY_KEYWORDS

console = Console()

BANNER = """[bold cyan]
 ██████╗████████╗███████╗    ██╗  ██╗██╗████████╗
██╔════╝╚══██╔══╝██╔════╝    ██║ ██╔╝██║╚══██╔══╝
██║        ██║   █████╗      █████╔╝ ██║   ██║   
██║        ██║   ██╔══╝      ██╔═██╗ ██║   ██║   
╚██████╗   ██║   ██║         ██║  ██╗██║   ██║   
 ╚═════╝   ╚═╝   ╚═╝         ╚═╝  ╚═╝╚═╝   ╚═╝   
[/bold cyan][bold green]  ⚡ AI-POWERED CTF & SECURITY TOOLKIT (90 TOOLS) // HEXSTRIKE-EDITION[/bold green]
"""

CAT_ICONS = {
    "all": "✨",
    "crypto": "🔐",
    "forensics": "🔍",
    "stego": "🖼️ ",
    "web": "🌐",
    "rev": "⚙️ ",
    "pwn": "💥",
    "encoding": "🔤",
    "osint": "🛰️ ",
    "misc": "⚡"
}

CAT_COLORS = {
    "crypto": "cyan",
    "forensics": "blue",
    "stego": "magenta",
    "web": "bright_magenta",
    "rev": "yellow",
    "pwn": "red",
    "encoding": "green",
    "osint": "bright_blue",
    "misc": "white"
}


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    console.print(Align.center(BANNER))


def show_dashboard():
    while True:
        clear_screen()
        print_header()

        # Stats Table
        stats_table = Table(title="[bold white]SYS STATUS & TOOLKIT OVERVIEW[/bold white]", box=None, show_header=False)
        stats_table.add_row(
            f"[bold cyan]Total Tools:[/bold cyan] {len(TOOLS)}",
            f"[bold green]MCP Mode:[/bold green] Active (stdio)",
            f"[bold yellow]REST API:[/bold yellow] Ready",
            f"[bold magenta]Categories:[/bold magenta] 9 Modules"
        )
        console.print(Panel(stats_table, border_style="cyan"))

        console.print("[bold yellow]MAIN MENU / OPERATIONS:[/bold yellow]")
        menu_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        menu_table.add_column("Key", style="bold green", width=6)
        menu_table.add_column("Operation", style="bold white", width=30)
        menu_table.add_column("Description", style="dim")

        menu_table.add_row("1", "Browse & Execute Tools", "Explore 90 tools categorized by domain with parameter prompt")
        menu_table.add_row("2", "Search Tools", "Quick keyword search across tool names, docs, and parameters")
        menu_table.add_row("3", "Challenge Auto-Triage", "One-click deep inspection of mysterious challenge files")
        menu_table.add_row("4", "Launch Headless MCP Server", "Start stdio JSON-RPC MCP server for Claude / Cursor / Copilot")
        menu_table.add_row("5", "Launch Headless REST API", "Start FastAPI microservice with Swagger UI at /docs")
        menu_table.add_row("6", "Flag Extractor & Analyzer", "Extract flags and parse challenge problem descriptions")
        menu_table.add_row("0", "Exit", "Close the terminal interface")

        console.print(menu_table)
        console.print("")

        choice = Prompt.ask("[bold cyan]ctfkit[/bold cyan] >", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")

        if choice == "0":
            console.print("[bold green]Goodbye![/bold green]")
            sys.exit(0)
        elif choice == "1":
            browse_categories()
        elif choice == "2":
            search_tools_interactive()
        elif choice == "3":
            triage_interactive()
        elif choice == "4":
            launch_mcp_server()
        elif choice == "5":
            launch_api_server()
        elif choice == "6":
            flag_extractor_interactive()


def browse_categories():
    categories = sorted(list({t["category"] for t in list_tools()}))
    
    while True:
        clear_screen()
        print_header()
        
        cat_table = Table(title="[bold white]TOOL CATEGORIES[/bold white]", header_style="bold cyan")
        cat_table.add_column("No", style="bold green", width=4)
        cat_table.add_column("Category", style="bold white", width=18)
        cat_table.add_column("Tool Count", style="yellow", width=12)
        cat_table.add_column("Sample Capabilities", style="dim")

        counts = {}
        for t in list_tools():
            counts[t["category"]] = counts.get(t["category"], 0) + 1

        for i, cat in enumerate(categories, 1):
            icon = CAT_ICONS.get(cat, "📦")
            color = CAT_COLORS.get(cat, "white")
            cat_table.add_row(
                str(i),
                f"{icon} [{color}]{cat.upper()}[/{color}]",
                str(counts.get(cat, 0)),
                ", ".join(t["name"] for t in list_tools() if t["category"] == cat)[:50] + "..."
            )

        cat_table.add_row("A", "✨ [bold cyan]ALL TOOLS[/bold cyan]", str(len(TOOLS)), "List all 90 tools in a single view")
        cat_table.add_row("B", "🔙 [bold red]Back to Main Menu[/bold red]", "-", "-")

        console.print(cat_table)
        console.print("")

        valid_choices = [str(i) for i in range(1, len(categories) + 1)] + ["A", "a", "B", "b"]
        choice = Prompt.ask("[bold cyan]Select Category[/bold cyan]", choices=valid_choices, default="1")

        if choice.upper() == "B":
            return
        elif choice.upper() == "A":
            browse_tools_in_category(None)
        else:
            idx = int(choice) - 1
            browse_tools_in_category(categories[idx])


def browse_tools_in_category(category: str | None):
    tools = [t for t in list_tools() if category is None or t["category"] == category]
    
    while True:
        clear_screen()
        print_header()

        title = f"[bold white]TOOLS IN {category.upper() if category else 'ALL CATEGORIES'}[/bold white] ({len(tools)} tools)"
        tools_table = Table(title=title, header_style="bold cyan")
        tools_table.add_column("No", style="bold green", width=4)
        tools_table.add_column("Tool Name", style="bold white", width=24)
        tools_table.add_column("Category", width=12)
        tools_table.add_column("Summary", style="dim")

        for i, t in enumerate(tools, 1):
            color = CAT_COLORS.get(t["category"], "white")
            tools_table.add_row(
                str(i),
                f"[bold]{t['name']}[/bold]",
                f"[{color}]{t['category']}[/{color}]",
                t.get("summary", "")[:75]
            )

        tools_table.add_row("B", "🔙 [bold red]Back[/bold red]", "-", "-")
        console.print(tools_table)
        console.print("")

        valid = [str(i) for i in range(1, len(tools) + 1)] + ["B", "b"]
        choice = Prompt.ask("[bold cyan]Select Tool to Execute[/bold cyan]", choices=valid, default="1")

        if choice.upper() == "B":
            return
        
        selected_tool = tools[int(choice) - 1]
        run_tool_interactive(selected_tool)


def search_tools_interactive():
    clear_screen()
    print_header()
    query = Prompt.ask("[bold yellow]Enter Search Keyword (e.g. rsa, pcap, jwt, stego, shellcode)[/bold yellow]").strip().lower()
    
    if not query:
        return

    matches = []
    for t in list_tools():
        if query in t["name"].lower() or query in t.get("summary", "").lower() or query in t["category"].lower():
            matches.append(t)

    if not matches:
        console.print(f"[bold red]No tools found matching '{query}'.[/bold red]")
        Prompt.ask("\nPress Enter to continue...")
        return

    clear_screen()
    print_header()
    table = Table(title=f"[bold white]SEARCH RESULTS FOR '{query.upper()}'[/bold white] ({len(matches)} matches)", header_style="bold cyan")
    table.add_column("No", style="bold green", width=4)
    table.add_column("Tool Name", style="bold white", width=24)
    table.add_column("Category", width=12)
    table.add_column("Summary", style="dim")

    for i, t in enumerate(matches, 1):
        color = CAT_COLORS.get(t["category"], "white")
        table.add_row(str(i), t["name"], f"[{color}]{t['category']}[/{color}]", t.get("summary", ""))

    table.add_row("B", "🔙 [bold red]Back[/bold red]", "-", "-")
    console.print(table)
    console.print("")

    valid = [str(i) for i in range(1, len(matches) + 1)] + ["B", "b"]
    choice = Prompt.ask("[bold cyan]Select Tool to Execute[/bold cyan]", choices=valid, default="1")

    if choice.upper() == "B":
        return

    run_tool_interactive(matches[int(choice) - 1])


def run_tool_interactive(tool_info: dict):
    clear_screen()
    print_header()

    name = tool_info["name"]
    cat = tool_info["category"]
    color = CAT_COLORS.get(cat, "cyan")

    console.print(Panel(
        f"[bold white]{name}[/bold white] | Category: [{color}]{cat.upper()}[/{color}]\n[dim]{tool_info.get('summary', '')}[/dim]",
        title="[bold green]TOOL WORKSPACE[/bold green]",
        border_style=color
    ))

    args = {}
    params = tool_info.get("parameters", [])

    if params:
        console.print("\n[bold yellow]ENTER PARAMETERS:[/bold yellow]")
        for p in params:
            p_name = p["name"]
            p_type = p.get("type", "str")
            p_default = p.get("default")
            p_doc = p.get("doc", "")

            prompt_text = f"  [bold cyan]{p_name}[/bold cyan] ({p_type})"
            if p_doc:
                prompt_text += f" [dim]- {p_doc}[/dim]"

            if p_type in ("bool", "boolean"):
                val = Confirm.ask(prompt_text, default=bool(p_default))
                args[p_name] = val
            elif p_type in ("int", "number"):
                val_str = Prompt.ask(prompt_text, default=str(p_default) if p_default is not None else "")
                args[p_name] = int(val_str) if val_str else (p_default or 0)
            else:
                default_str = str(p_default) if p_default is not None else ""
                val_str = Prompt.ask(prompt_text, default=default_str)
                args[p_name] = val_str

    console.print("\n[bold yellow]⚡ Executing...[/bold yellow]")
    start = time.monotonic()
    try:
        output = run_tool(name, args)
        elapsed = (time.monotonic() - start) * 1000
    except Exception as ex:
        output = f"ERROR: {ex}"
        elapsed = (time.monotonic() - start) * 1000

    console.print("\n" + "=" * 60)
    console.print(Panel(
        output,
        title=f"[bold green]EXECUTION OUTPUT ({elapsed:.1f}ms)[/bold green]",
        border_style="green"
    ))

    # Auto flag detection
    flag = detect_flag(output)
    if flag:
        console.print(Panel(
            f"[bold green]🏆 FLAG DETECTED:[/bold green] [bold white]{flag}[/bold white]",
            border_style="bold green"
        ))

    console.print("=" * 60)
    Prompt.ask("\n[bold cyan]Press Enter to return...[/bold cyan]")


def triage_interactive():
    clear_screen()
    print_header()

    console.print(Panel(
        "[bold white]ONE-CLICK CHALLENGE FILE TRIAGE[/bold white]\n"
        "Runs file magic inspection, entropy map, string extraction, embedded zlib hunt,\n"
        "ELF/PE/PNG/PCAP/ZIP specialized forensics, and auto-flag extraction in 1 step.",
        title="[bold cyan]🎯 AUTO-TRIAGE[/bold cyan]",
        border_style="cyan"
    ))

    file_path = Prompt.ask("[bold yellow]Enter Path to Challenge File[/bold yellow]").strip().strip('"').strip("'")
    if not file_path or not os.path.exists(file_path):
        console.print(f"[bold red]File not found: '{file_path}'[/bold red]")
        Prompt.ask("\nPress Enter to continue...")
        return

    console.print(f"\n[bold green]Analyzing '{file_path}'...[/bold green]\n")
    output = run_tool("triage_file", {"path": file_path})
    
    console.print(Panel(output, title="[bold green]TRIAGE REPORT[/bold green]", border_style="green"))

    flag = detect_flag(output)
    if flag:
        console.print(Panel(
            f"[bold green]🏆 FLAG DETECTED:[/bold green] [bold white]{flag}[/bold white]",
            border_style="bold green"
        ))

    Prompt.ask("\n[bold cyan]Press Enter to continue...[/bold cyan]")


def flag_extractor_interactive():
    clear_screen()
    print_header()

    text = Prompt.ask("[bold yellow]Paste Output / Problem Statement / Raw Text[/bold yellow]")
    if not text:
        return

    output = run_tool("extract_flags_tool", {"text": text})
    console.print(Panel(output, title="[bold green]FLAG EXTRACTION RESULTS[/bold green]", border_style="green"))
    Prompt.ask("\n[bold cyan]Press Enter to continue...[/bold cyan]")


def launch_mcp_server():
    clear_screen()
    print_header()
    console.print(Panel(
        "[bold green]Launching Headless MCP stdio Server (90 Tools Exposed)...[/bold green]\n"
        "This process will now accept JSON-RPC messages via stdin/stdout.\n"
        "Press Ctrl+C to terminate server.",
        border_style="green"
    ))
    from mcp_server import main
    main()


def launch_api_server():
    clear_screen()
    print_header()
    console.print(Panel(
        "[bold green]Launching Headless REST API Server with OpenAPI / Swagger UI...[/bold green]\n"
        "Endpoint: [bold cyan]http://127.0.0.1:8765[/bold cyan]\n"
        "Swagger Docs: [bold cyan]http://127.0.0.1:8765/docs[/bold cyan]\n"
        "Press Ctrl+C to stop server.",
        border_style="green"
    ))
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8765, log_level="info")


if __name__ == "__main__":
    try:
        show_dashboard()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Session terminated.[/bold yellow]")
