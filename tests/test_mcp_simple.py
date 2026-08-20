"""Compact MCP profile tests: small schema list, full registry reachability."""

import os

os.environ["CTFKIT_MCP_PROFILE"] = "simple"

from mcp_server import MCP_PROFILE, SIMPLE_TOOLS, find_ctf_tools, run_ctf_tool  # noqa: E402
from ctfkit.registry import TOOLS  # noqa: E402


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
