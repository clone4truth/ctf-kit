"""Compact MCP profile tests: small schema list, full registry reachability."""

import json
import os
from pathlib import Path
import subprocess
import sys

os.environ["CTFKIT_MCP_PROFILE"] = "simple"

from mcp_server import (  # noqa: E402
    MCP_PROFILE, SIMPLE_TOOLS, backend_health, find_ctf_tools, run_ctf_tool,
)
from ctfkit.registry import TOOLS  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
TRANSPORT_TOOLS = {
    "backend_health", "backend_telemetry", "submit_background_job",
    "get_background_job", "list_background_jobs", "cancel_background_job",
}


def test_simple_profile_is_compact_but_searches_full_registry():
    assert MCP_PROFILE == "simple"
    assert len(SIMPLE_TOOLS) + 2 < len(TOOLS) / 10
    result = find_ctf_tools("close prime rsa factor", category="crypto")
    names = {item["name"] for item in result["tools"]}
    assert "rsa_fermat" in names
    fermat = next(item for item in result["tools"] if item["name"] == "rsa_fermat")
    assert any(param["name"] == "n" for param in fermat["parameters"])


def test_simple_gateway_executes_tools_not_directly_exposed():
    assert "caesar" not in SIMPLE_TOOLS
    result = run_ctf_tool("caesar", {"text": "ABC", "shift": 1})
    assert result["status"] == "success"
    assert "BCD" in result["text"]


def test_simple_gateway_keeps_validation_and_unknown_tool_errors():
    invalid = run_ctf_tool("caesar", {"wrong": "value"})
    assert invalid["status"] == "invalid_input"
    missing = run_ctf_tool("does_not_exist", {})
    assert missing["status"] == "invalid_input"


def test_backend_health_reports_local_compatibility_mode():
    health = backend_health()
    assert health["mode"] == "local" and health["ready"]


def test_simple_stdio_profile_exposes_only_compact_workflow_schemas():
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "simple-profile-test", "version": "1"},
        }},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    process = subprocess.Popen(
        [sys.executable, "mcp_server.py"], cwd=ROOT,
        env={**os.environ, "CTFKIT_MCP_PROFILE": "simple"},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    responses = {}
    try:
        assert process.stdin and process.stdout
        for request in requests:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            response = json.loads(process.stdout.readline())
            responses[response["id"]] = response
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    names = {tool["name"] for tool in responses[2]["result"]["tools"]}
    expected = set(SIMPLE_TOOLS) | {"find_ctf_tools", "run_ctf_tool"} | TRANSPORT_TOOLS
    assert names == expected
    assert len(names) == 20
    assert len(names) < len(TOOLS) / 10
