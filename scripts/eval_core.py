#!/usr/bin/env python3
"""Deterministic quality benchmark with coverage, false-positive, and agent metrics."""

import json
import shutil
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ctfkit.modules  # noqa: F401,E402
from ctfkit.flagmeta import extract_flag_candidates  # noqa: E402
from ctfkit.registry import execute_tool  # noqa: E402

CATEGORIES = {"encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint", "misc"}
AGENT_CASES = [
    {"id": "agent-crypto-base64", "category": "crypto", "iterations": 2,
     "problem": "Smoke evaluation CTF crypto base64 payload cGljb0NURntldmFsX2ZpeHR1cmV9", "flag": "picoCTF{eval_fixture}"},
    {"id": "agent-web-jwt", "category": "web", "iterations": 3,
     "problem": "Smoke evaluation CTF web JWT token eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.abc", "flag": "flag{jwt}"},
    {"id": "agent-stego-lsb", "category": "stego", "iterations": 3,
     "problem": "Smoke evaluation CTF stego LSB hidden flag in testdata/lsb.png", "flag": "flag{lsb_hidden}"},
    {"id": "agent-forensics-pcap", "category": "forensics", "iterations": 3,
     "problem": "Smoke evaluation CTF forensics inspect HTTP traffic in testdata/test.pcap", "flag": "flag{http_extracted}"},
    {"id": "agent-blind-encoding", "category": "encoding", "iterations": 4,
     "problem": "Smoke evaluation: recover the submission token from cGljb0NURntldmFsX2ZpeHR1cmV9", "flag": "picoCTF{eval_fixture}"},
    {"id": "agent-blind-image", "category": "stego", "iterations": 5,
     "problem": "Smoke evaluation: recover the submission token from this artifact: testdata/lsb.png", "flag": "flag{lsb_hidden}"},
]


def main() -> int:
    started = time.perf_counter()
    cases = json.loads((ROOT / "evals" / "ctf_cases.json").read_text(encoding="utf-8"))
    results, covered = [], set()
    for case in cases:
        result = execute_tool(case["tool"], case["args"])
        flags = [item["value"] for item in extract_flag_candidates(result["text"])]
        expected_ok = (case.get("expected_flag") in flags if case.get("expected_flag")
                       else case.get("expected_contains", "") in result["text"])
        ok = result["ok"] and result["category"] == case["category"] and expected_ok
        if ok:
            covered.add(case["category"])
        results.append({"id": case["id"], "category": case["category"], "passed": ok,
                        "status": result["status"], "flags": flags})
        print(f"{'PASS' if ok else 'FAIL'} {case['id']}: status={result['status']} flags={flags}")

    negative_samples = [
        "body{background:#eee;width:60vw;margin:15vh auto}",
        "function flags_tool() { return false; }",
        "const map{not_a_flag_value};",
        "a:visited{color:#348}",
        "JSON object user{name:admin, role:operator}",
        "Rust function main(){println!(\"hello\")}",
        "template {{ user.profile.name }} and CSS @media{width:10px}",
        "HTTP header Feature-Flags: alpha,beta",
    ]
    false_candidates = sum(bool(extract_flag_candidates(sample)) for sample in negative_samples)
    precision_ok = false_candidates == 0
    print(f"{'PASS' if precision_ok else 'FAIL'} flag-negative-suite: false_candidates={false_candidates}")

    agent_results = []
    for case in AGENT_CASES:
        project_id = f"core-eval-{case['id']}"
        result = execute_tool("autonomous_solve", {
            "problem_statement": case["problem"], "max_iterations": case["iterations"], "project_id": project_id,
        })
        flags = [item["value"] for item in result["flags"]]
        ok = result["status"] == "success" and case["flag"] in flags
        agent_results.append({"id": case["id"], "category": case["category"],
                              "passed": ok, "status": result["status"], "flags": flags})
        print(f"{'PASS' if ok else 'FAIL'} {case['id']}: status={result['status']} flags={flags}")
        (ROOT / "ctfkit" / "memory" / "projects" / f"{project_id}.json").unlink(missing_ok=True)

    direct_rate = sum(r["passed"] for r in results) / max(1, len(results))
    agent_rate = sum(r["passed"] for r in agent_results) / max(1, len(agent_results))
    coverage_rate = len(covered) / len(CATEGORIES)
    precision_rate = float(precision_ok)
    quality_score = round(10 * (0.45 * direct_rate + 0.25 * agent_rate
                                + 0.15 * coverage_rate + 0.15 * precision_rate), 2)
    report = {
        "schema_version": 2, "quality_score_10": quality_score,
        "direct": {"passed": sum(r["passed"] for r in results), "total": len(results)},
        "agent": {"passed": sum(r["passed"] for r in agent_results), "total": len(agent_results)},
        "category_coverage": {"covered": sorted(covered), "total": len(CATEGORIES), "rate": coverage_rate},
        "flag_false_positives": false_candidates,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "cases": results, "agent_cases": agent_results,
    }
    report_path = ROOT / "evals" / "latest_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    shutil.rmtree(ROOT / "ctfkit" / "memory" / "runs", ignore_errors=True)
    print(f"CORE EVAL: score={quality_score}/10 direct={report['direct']} agent={report['agent']} coverage={len(covered)}/{len(CATEGORIES)}")
    print(f"Report: {report_path}")
    return 0 if direct_rate == agent_rate == coverage_rate == precision_rate == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
