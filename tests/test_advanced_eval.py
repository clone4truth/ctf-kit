"""Regression checks for the strict 10/10 release gate."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_logging_setup_is_idempotent():
    from ctfkit.logging import setup_logging

    first = setup_logging()
    second = setup_logging()
    assert first[0] is second[0]
    assert first[1] is second[1]


def test_advanced_release_gate_passes_with_evidence():
    subprocess.run([sys.executable, "tests/gen_testdata.py"], cwd=ROOT, check=True, capture_output=True, text=True)
    result = subprocess.run([sys.executable, "scripts/eval_advanced.py"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((ROOT / "evals/latest_advanced_report.json").read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["score_cap_10"] == 10.0
    assert report["summary"] == {"passed": 7, "total": 7}
    assert all(case["passed"] for case in report["cases"])
