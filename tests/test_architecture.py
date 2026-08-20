"""Regression tests for the canonical execution and agent-safety architecture."""

import time

import ctfkit.modules  # noqa: F401
from ctfkit.flagmeta import extract_flag_candidates, extract_flags
from ctfkit.modules.agent import AgentState
from ctfkit.modules.orchestrate import _resolve
from ctfkit.registry import TOOLS, execute_tool, tool
from ctfkit.result import ToolStatus, classify_output
from ctfkit.config import Settings, is_loopback_host, target_scope_error
from ctfkit.isolation import run_isolated


def test_legacy_output_statuses_are_not_false_successes():
    assert classify_output("TOOL 'x' NOT INSTALLED; requires testing") == ToolStatus.UNAVAILABLE
    assert classify_output("No flags detected") == ToolStatus.NO_FINDING
    assert classify_output("ERROR: bad input") == ToolStatus.ERROR


def test_flag_candidates_filter_code_and_rank_real_flags():
    assert extract_flags("body{background:#eee;width:60vw} map{key:value} a:visited{color:#348}") == []
    candidates = extract_flag_candidates("evidence: picoCTF{verified_example}")
    assert candidates[0]["value"] == "picoCTF{verified_example}"
    assert candidates[0]["confidence"] >= 0.9


def test_step_placeholder_and_project_path_are_safe():
    assert _resolve("x=$step.0", "", "", {"step_0": "proof"}) == "x=proof"
    state = AgentState("../../outside")
    assert state.state_path.parent.name == "projects"
    assert ".." not in state.state_path.name


def test_policy_and_argument_validation(monkeypatch):
    monkeypatch.setenv("CTFKIT_SAFETY_MODE", "passive")
    blocked = execute_tool("scaffold_new_tool", {"name_hint": "x", "category": "misc", "summary": "x"})
    assert blocked["status"] == "blocked"
    invalid = execute_tool("caesar", {"unknown": "x"})
    assert invalid["status"] == "invalid_input"


def test_runtime_configuration_is_typed_and_zero_config(monkeypatch):
    monkeypatch.delenv("CTFKIT_ALLOW_INSTALL", raising=False)
    monkeypatch.setenv("CTFKIT_MAX_UPLOAD_BYTES", "invalid")
    config = Settings.from_env()
    assert config.allow_install is True
    assert config.max_upload_bytes == 64 * 1024 * 1024
    assert is_loopback_host("127.0.0.1") and is_loopback_host("::1")
    assert not is_loopback_host("0.0.0.0")


def test_strict_target_scope_supports_hosts_wildcards_and_cidrs():
    config = Settings(
        api_token="", cors_origins=(), max_upload_bytes=1024,
        safety_mode="auto", allow_install=False, docker_enabled=False,
        docker_pull=False, enforce_target_scope=True,
        allowed_targets=("challenge.local", "*.ctf.example", "10.10.0.0/16"),
    )
    assert target_scope_error({"url": "https://challenge.local/login"}, config) is None
    assert target_scope_error({"host": "box.ctf.example"}, config) is None
    assert target_scope_error({"ip": "10.10.4.2"}, config) is None
    assert target_scope_error({"url": "https://outside.example"}, config)


def test_registry_quality_contract():
    assert len(TOOLS) >= 200
    assert set(meta["category"] for meta in TOOLS.values()) == {
        "encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint", "misc"
    }
    for name, meta in TOOLS.items():
        assert meta["summary"].strip(), name
        assert meta["doc"].strip(), name
        assert meta["safety_level"] in {"passive", "lab", "admin"}, name
        assert isinstance(meta["read_only"], bool), name
        assert isinstance(meta["destructive"], bool), name
        param_names = [param["name"] for param in meta["params"]]
        assert len(param_names) == len(set(param_names)), name


def test_isolated_worker_uses_stdin_protocol():
    assert "BCD" in run_isolated("caesar", {"text": "ABC", "shift": 1}, 5)


def test_timeout_returns_without_waiting_for_worker_shutdown():
    @tool(name="_test_slow", timeout=0.03)
    def slow() -> str:
        time.sleep(0.25)
        return "done"

    started = time.monotonic()
    result = execute_tool("_test_slow", {})
    elapsed = time.monotonic() - started
    TOOLS.pop("_test_slow", None)
    assert result["status"] == "timeout"
    assert elapsed < 0.15


def test_learning_v2_requires_provenance_and_deduplicates(tmp_path, monkeypatch):
    from ctfkit.modules import self_improve as si

    monkeypatch.setattr(si, "STATE_FILE", tmp_path / "state.json")
    rejected = si.self_improve_after_solve(
        title="Unproven", category="crypto", tools_used=["rsa_fermat"],
        flag="flag{unproven}", note="", problem="", source="manual",
    )
    assert not rejected["learned"] and "problem" in rejected["reason"]

    accepted = si.self_improve_after_solve(
        title="Verified", category="crypto", tools_used=["rsa_fermat"],
        flag="flag{verified}", note="close primes", problem="RSA close primes",
        commands="python solve.py", evidence="factorization recovered flag{verified}",
        source="manual",
    )
    duplicate = si.self_improve_after_solve(
        title="Verified", category="crypto", tools_used=["rsa_fermat"],
        flag="flag{verified}", note="close primes", problem="RSA close primes",
        commands="python solve.py", evidence="factorization recovered flag{verified}",
        source="manual",
    )
    state = si._load_state()
    assert accepted["learned"] and not duplicate["learned"]
    assert state["version"] == 2 and state["verified_solves"] == 1 and state["rejected_solves"] == 1
