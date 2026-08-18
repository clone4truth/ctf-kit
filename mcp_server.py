"""MCP bridge: expose semua tool dari registry ctfkit ke MCP (stdio).

Jalankan: python mcp_server.py
"""

import sys
from mcp.server.mcpserver import MCPServer

import ctfkit.modules  # noqa: F401  (mendaftarkan semua tool)
from ctfkit.registry import TOOLS
from ctfkit.logging import log

server = MCPServer("ctf-tools", version="1.0.0", description="CTF toolkit: crypto, stego, forensics, web, rev, pwn, osint")


def build_server() -> MCPServer:
    for meta in TOOLS.values():
        server.add_tool(meta["fn"], name=meta["name"], description=meta["doc"] or meta["summary"])
    log.info("MCP server ready: %d tools registered", len(TOOLS))
    return server


def main():
    build_server()
    if sys.stdin.isatty():
        print("=" * 60)
        print("⚡ CTF-KIT MCP SERVER (stdio mode)")
        print("Listening for JSON-RPC protocol on stdio...")
        print("• For REST API & OpenAPI docs, run: python server.py")
        print("• For test handshake, run: python test_mcp.py")
        print("=" * 60)
    try:
        server.run()  # transport default: stdio
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()