"""Background job lifecycle, persistence, redaction, and process control."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import ctfkit.modules  # noqa: F401
from ctfkit.jobs import JobManager


def _wait_terminal(manager: JobManager, job_id: str, timeout: float = 10) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = manager.get(job_id)
        if job["status"] in {"completed", "failed", "cancelled", "interrupted"}:
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


def test_background_job_persists_result_output_and_redacts_secrets(tmp_path: Path):
    manager = JobManager(tmp_path, max_workers=1)
    try:
        submitted = manager.submit(
            "encode_zero_width", {"secret": "do-not-persist", "cover_text": "hello world"},
            source="unit-test",
        )
        assert submitted["arguments"]["secret"] == "[REDACTED]"
        job = _wait_terminal(manager, submitted["id"])
        assert job["status"] == "completed"
        assert job["result_status"] == "success"
        assert job["result"]["tool"] == "encode_zero_width"
        assert "do-not-persist" not in (tmp_path / f"{job['id']}.json").read_text(encoding="utf-8")

        output = manager.read_output(job["id"])
        assert output["terminal"] is True
        assert output["next_offset"] >= output["offset"]
        assert manager.stats()["status_counts"]["completed"] == 1
    finally:
        manager.shutdown(cancel_running=True)


def test_restart_marks_orphaned_jobs_interrupted(tmp_path: Path):
    state = {
        "id": "orphaned123", "tool": "caesar", "category": "crypto",
        "source": "test", "status": "running", "created_at": "2026-01-01T00:00:00+00:00",
        "started_at": "2026-01-01T00:00:01+00:00", "finished_at": None,
        "progress": 10, "pid": 999999, "return_code": None, "error": None,
        "output_bytes": 0, "arguments": {},
    }
    (tmp_path / "orphaned123.json").write_text(json.dumps(state), encoding="utf-8")
    manager = JobManager(tmp_path, max_workers=1)
    try:
        recovered = manager.get("orphaned123")
        assert recovered["status"] == "interrupted"
        assert "restarted" in recovered["error"]
        assert recovered["finished_at"]
    finally:
        manager.shutdown()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_process_group_termination_stops_worker():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        JobManager._terminate_group(process)
        assert process.wait(timeout=3) is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_manager_cancel_transitions_running_job_to_cancelled(tmp_path: Path, monkeypatch):
    real_popen = subprocess.Popen

    def slow_worker(*_args, **kwargs):
        return real_popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=kwargs.get("stdin"), stdout=kwargs.get("stdout"), stderr=kwargs.get("stderr"),
            text=kwargs.get("text", False), cwd=kwargs.get("cwd"), env=kwargs.get("env"),
            start_new_session=True,
        )

    monkeypatch.setattr("ctfkit.jobs.subprocess.Popen", slow_worker)
    manager = JobManager(tmp_path, max_workers=1)
    try:
        submitted = manager.submit("caesar", {"text": "ABC", "shift": 1})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            running = manager.get(submitted["id"], include_result=False)
            if running["status"] == "running" and running["pid"]:
                break
            time.sleep(0.02)
        else:
            raise AssertionError("job did not enter running state")
        manager.cancel(submitted["id"])
        cancelled = _wait_terminal(manager, submitted["id"])
        assert cancelled["status"] == "cancelled"
        assert cancelled["error"] == "cancelled by user"
    finally:
        manager.shutdown(cancel_running=True)
