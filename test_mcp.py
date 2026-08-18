"""Test MCP stdio handshake + tool list. Jalankan: python test_mcp.py"""
import asyncio
import json
import sys

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
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "mcp_server.py",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL)
    lines = []

    async def collect():
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
    assert len(tools) == 57, f"harus 57 tool, dapat {len(tools)}"
    print("MCP HAND SHAKE OK")


asyncio.run(main())