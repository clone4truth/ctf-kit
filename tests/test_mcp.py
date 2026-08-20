"""Test MCP stdio handshake + tool list. Jalankan: python tests/test_mcp.py"""
import asyncio
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REQS = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "ctfkit-test", "version": "1"}}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "caesar", "arguments": {"text": "Spwwz Hzpwwoi", "shift": -1}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "stego_lsb", "arguments": {"image_path": "testdata/lsb.png", "max_bytes": 64}}},
]


async def main():
    mcp_script = os.path.join(REPO_ROOT, "mcp_server.py")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, mcp_script,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env={**os.environ, "CTFKIT_MCP_PROFILE": "full"},
        cwd=REPO_ROOT)
    lines = []

    async def collect():
        proc.stdout._limit = 8 * 1024 * 1024  # ponytail: tools/list line exceeds default 64KB with per-tool schemas
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
            lines.append(json.loads(line))
            if len(lines) >= len(REQS):
                return

    for r in REQS:
        proc.stdin.write((json.dumps(r) + "\n").encode())
    await proc.stdin.drain()
    await asyncio.wait_for(collect(), 30)
    try:
        proc.stdin.close()
        await proc.stdin.wait_closed()
    except Exception:
        pass
    try:
        proc.terminate()
        await proc.wait()
    except Exception:
        proc.kill()

    by_id = {r["id"]: r for r in lines if "id" in r}
    assert by_id.get(1, {}).get("result", {}).get("protocolVersion"), "initialize gagal"
    tools = by_id[2]["result"]["tools"]
    print(f"INIT OK — {len(tools)} tools registered")
    names = [t["name"] for t in tools]
    print("contoh:", ", ".join(names[:8]))
    for tid in (3, 4):
        res = by_id[tid]["result"]
        print(f"call {REQS[tid-1]['params']['name']}: {res['content'][0]['text'][:60]!r}")
    import ctfkit.modules  # noqa: F401
    from ctfkit.registry import TOOLS
    assert len(tools) == len(TOOLS), f"MCP={len(tools)} berbeda dari registry={len(TOOLS)}"
    print(f"MCP HANDSHAKE OK — All {len(tools)} tools exposed properly")


if __name__ == "__main__":
    asyncio.run(main())
