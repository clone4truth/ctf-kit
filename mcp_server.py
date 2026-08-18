"""MCP bridge: expose semua tool dari registry ctfkit ke MCP (stdio).

Jalankan: python mcp_server.py
"""

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


if __name__ == "__main__":
    build_server()
    server.run()  # transport default: stdio