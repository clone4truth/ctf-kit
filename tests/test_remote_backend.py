"""Live central-backend test for the HexStrike-style MCP -> REST flow."""

from __future__ import annotations

import os
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

from ctfkit.mcp_client import BackendUnavailable, CTFKitBackendClient


ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_remote_mcp_client_executes_and_reports_central_telemetry():
    port = _free_port()
    server_url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "CTFKIT_API_TOKEN": ""}
    process = subprocess.Popen(
        [sys.executable, "server.py", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    client = CTFKitBackendClient(server_url, timeout=2, retries=0)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                if client.health().get("ready"):
                    break
            except BackendUnavailable:
                pass
            if time.monotonic() >= deadline:
                raise AssertionError("central backend did not become ready")
            time.sleep(0.1)

        result = client.execute_tool("caesar", {"text": "ABC", "shift": 1})
        assert result["status"] == "success"
        assert result["source"] == "mcp"
        assert result["execution_id"]
        assert "BCD" in result["result"]

        telemetry = client.telemetry()
        assert telemetry["total_executions"] >= 1
        event = telemetry["recent"][0]
        assert event["id"] == result["execution_id"]
        assert event["source"] == "mcp"
        assert event["tool"] == "caesar"

        queued = client.submit_job("caesar", {"text": "GHI", "shift": 1})
        job_id = queued["job"]["id"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = client.get_job(job_id)["job"]
            if job["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("remote backend job did not finish")
        assert job["status"] == "completed"
        assert "HIJ" in job["result"]["text"]
        assert client.get_job_output(job_id)["terminal"] is True

        mcp_env = {**env, "CTFKIT_MCP_PROFILE": "simple"}
        mcp = subprocess.Popen(
            [sys.executable, "mcp_server.py", "--server", server_url],
            cwd=ROOT, env=mcp_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        try:
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "remote-test", "version": "1"},
                }},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                    "name": "run_ctf_tool", "arguments": {
                        "tool_name": "caesar", "arguments": {"text": "DEF", "shift": 1},
                    },
                }},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                    "name": "backend_telemetry", "arguments": {},
                }},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                    "name": "submit_background_job", "arguments": {
                        "tool_name": "caesar", "arguments": {"text": "JKL", "shift": 1},
                    },
                }},
            ]
            responses = []
            for request in requests:
                mcp.stdin.write(json.dumps(request) + "\n")
                mcp.stdin.flush()
                responses.append(json.loads(mcp.stdout.readline()))
            assert responses[0]["result"]["protocolVersion"]
            assert "EFG" in responses[1]["result"]["content"][0]["text"]
            assert '"source": "mcp"' in responses[1]["result"]["content"][0]["text"]
            assert '"total_executions": 2' in responses[2]["result"]["content"][0]["text"]
            assert '"status": "queued"' in responses[3]["result"]["content"][0]["text"]
        finally:
            mcp.terminate()
            try:
                mcp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mcp.kill()
                mcp.wait(timeout=5)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
