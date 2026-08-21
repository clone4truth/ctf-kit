"""Persistent, bounded, killable background jobs for registered CTF tools."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import inspect
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import uuid

from .registry import TOOLS
from .logging import log


TERMINAL_STATES = {"completed", "failed", "cancelled", "interrupted"}
_SECRET_KEY = re.compile(r"(?i)(pass|secret|token|cookie|authorization|api.?key|flag)")


class JobNotFound(KeyError):
    pass


def _utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _safe_arguments(arguments: dict) -> dict:
    return {
        key: "[REDACTED]" if _SECRET_KEY.search(key) else str(value)[:200]
        for key, value in arguments.items()
    }


class JobManager:
    """Run registered tools in independent process groups with persisted history."""

    def __init__(self, root: Path, max_workers: int = 4, history_limit: int = 500):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_workers = max(1, min(int(max_workers), 32))
        self.history_limit = max(20, int(history_limit))
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._processes: dict[str, subprocess.Popen] = {}
        self._futures: dict[str, Future] = {}
        self._cancel_requested: set[str] = set()
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers,
                                            thread_name_prefix="ctfkit-job")
        self._load_history()

    def _state_path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.json"

    def _result_path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.result.json"

    def _log_path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.log"

    def _atomic_json(self, path: Path, value: dict) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.root,
                                         prefix=path.name + ".", suffix=".tmp",
                                         delete=False) as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            temp_name = handle.name
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _persist(self, job_id: str) -> None:
        self._atomic_json(self._state_path(job_id), self._jobs[job_id])

    def _load_history(self) -> None:
        for path in sorted(self.root.glob("*.json")):
            if path.name.endswith(".result.json"):
                continue
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if item.get("status") in {"queued", "running", "cancelling"}:
                item["status"] = "interrupted"
                item["finished_at"] = _utc_now()
                item["error"] = "backend restarted before the job completed"
                self._atomic_json(path, item)
            self._jobs[item["id"]] = item

    def _public(self, item: dict, include_result: bool = False) -> dict:
        value = dict(item)
        if include_result and self._result_path(item["id"]).exists():
            try:
                value["result"] = json.loads(self._result_path(item["id"]).read_text(encoding="utf-8"))
            except Exception:
                value["result"] = None
        return value

    def submit(self, tool_name: str, arguments: dict | None = None,
               source: str = "rest") -> dict:
        arguments = arguments or {}
        meta = TOOLS.get(tool_name)
        if meta is None:
            raise ValueError(f"unknown tool: {tool_name}")
        unknown = sorted(set(arguments) - {param["name"] for param in meta["params"]})
        if unknown:
            raise ValueError(f"unknown argument(s) for {tool_name}: {', '.join(unknown)}")
        try:
            inspect.signature(meta["fn"]).bind(**arguments)
        except TypeError as ex:
            raise ValueError(f"invalid arguments for {tool_name}: {ex}") from ex

        job_id = uuid.uuid4().hex[:16]
        now = _utc_now()
        item = {
            "id": job_id, "tool": tool_name, "category": meta["category"],
            "source": source[:40], "status": "queued", "progress": 0,
            "arguments": _safe_arguments(arguments), "created_at": now,
            "started_at": None, "finished_at": None, "pid": None,
            "return_code": None, "error": None, "output_bytes": 0,
        }
        with self._lock:
            self._jobs[job_id] = item
            self._persist(job_id)
            self._futures[job_id] = self._executor.submit(
                self._run_job, job_id, tool_name, arguments
            )
        self._prune_history()
        return self._public(item)

    def _append_log(self, job_id: str, text: str) -> None:
        if not text:
            return
        path = self._log_path(job_id)
        with path.open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(text)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["output_bytes"] = path.stat().st_size
        for line in text.rstrip().splitlines():
            log.info("[job:%s] %s", job_id, line)

    def _run_job(self, job_id: str, tool_name: str, arguments: dict) -> None:
        with self._lock:
            if job_id in self._cancel_requested:
                self._finish_cancelled(job_id)
                return
            item = self._jobs[job_id]
            item.update(status="running", progress=5, started_at=_utc_now())
            self._persist(job_id)

        env = os.environ.copy()
        env["CTFKIT_JOB_WORKER"] = "1"
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "ctfkit.job_worker", tool_name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, cwd=Path(__file__).resolve().parent.parent, env=env,
                **kwargs,
            )
        except Exception as ex:
            self._append_log(job_id, f"[ctfkit-job] worker start failed: {ex}\n")
            with self._lock:
                item = self._jobs[job_id]
                item.update(status="failed", progress=100, finished_at=_utc_now(),
                            error=f"worker start failed: {ex}")
                self._persist(job_id)
            return
        with self._lock:
            self._processes[job_id] = process
            self._jobs[job_id]["pid"] = process.pid
            self._jobs[job_id]["progress"] = 10
            self._persist(job_id)

        try:
            stdout_parts: list[str] = []

            def read_stdout():
                if process.stdout:
                    stdout_parts.append(process.stdout.read())

            def read_stderr():
                if process.stderr:
                    for line in process.stderr:
                        self._append_log(job_id, line)

            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            if process.stdin:
                process.stdin.write(json.dumps(arguments, ensure_ascii=False))
                process.stdin.close()
            return_code = process.wait()
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            with self._lock:
                self._processes.pop(job_id, None)
                cancelled = job_id in self._cancel_requested
                item = self._jobs[job_id]
                item["return_code"] = return_code
                if cancelled:
                    self._finish_cancelled(job_id)
                    return
                try:
                    result = json.loads("".join(stdout_parts) or "{}")
                except json.JSONDecodeError as ex:
                    result = {
                        "status": "error", "ok": False,
                        "text": "ERROR: invalid worker output", "error": str(ex),
                    }
                self._atomic_json(self._result_path(job_id), result)
                result_status = result.get("status", "error")
                item["status"] = "failed" if result_status in {"error", "timeout"} else "completed"
                item["progress"] = 100
                item["finished_at"] = _utc_now()
                item["error"] = result.get("error")
                item["result_status"] = result_status
                item["flags_count"] = len(result.get("flags", []))
                self._append_log(
                    job_id,
                    f"[ctfkit-job] finished tool={tool_name} lifecycle={item['status']} "
                    f"result={result_status} return_code={return_code}\n",
                )
                self._persist(job_id)
        except Exception as ex:
            log.exception("[job:%s] background worker supervision failed", job_id)
            with self._lock:
                self._processes.pop(job_id, None)
                item = self._jobs[job_id]
                if job_id in self._cancel_requested:
                    self._finish_cancelled(job_id)
                else:
                    item.update(status="failed", progress=100, finished_at=_utc_now(),
                                error=f"job supervision failed: {ex}")
                    self._append_log(job_id, f"[ctfkit-job] supervision failed: {ex}\n")
                    self._persist(job_id)

    def _finish_cancelled(self, job_id: str) -> None:
        item = self._jobs[job_id]
        item.update(status="cancelled", progress=100, finished_at=_utc_now(),
                    error="cancelled by user")
        self._append_log(job_id, f"[ctfkit-job] cancelled tool={item['tool']}\n")
        self._persist(job_id)

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            item = self._jobs.get(job_id)
            if item is None:
                raise JobNotFound(job_id)
            if item["status"] in TERMINAL_STATES:
                return self._public(item)
            self._cancel_requested.add(job_id)
            item["status"] = "cancelling"
            self._persist(job_id)
            future = self._futures.get(job_id)
            process = self._processes.get(job_id)
            if process is None and future and future.cancel():
                self._finish_cancelled(job_id)
                return self._public(item)
        if process is not None:
            self._terminate_group(process)
        return self.get(job_id)

    @staticmethod
    def _terminate_group(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, timeout=5, check=False)
            else:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass

    def get(self, job_id: str, include_result: bool = True) -> dict:
        with self._lock:
            item = self._jobs.get(job_id)
            if item is None:
                raise JobNotFound(job_id)
            return self._public(item, include_result=include_result)

    def list(self, status: str = "", limit: int = 100) -> list[dict]:
        with self._lock:
            items = list(self._jobs.values())
        if status == "active":
            items = [item for item in items if item["status"] not in TERMINAL_STATES]
        elif status:
            items = [item for item in items if item["status"] == status]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        return [self._public(item) for item in items[:max(1, min(int(limit), 500))]]

    def stats(self) -> dict:
        """Return a compact lifecycle summary for backend telemetry."""
        with self._lock:
            counts: dict[str, int] = {}
            for item in self._jobs.values():
                state = item["status"]
                counts[state] = counts.get(state, 0) + 1
        active = sum(counts.get(state, 0) for state in ("queued", "running", "cancelling"))
        return {
            "max_workers": self.max_workers,
            "total": sum(counts.values()),
            "active": active,
            "status_counts": dict(sorted(counts.items())),
        }

    def shutdown(self, cancel_running: bool = False) -> None:
        """Release worker threads; optionally stop active process groups first."""
        if cancel_running:
            with self._lock:
                active_ids = [
                    job_id for job_id, item in self._jobs.items()
                    if item["status"] not in TERMINAL_STATES
                ]
            for job_id in active_ids:
                self.cancel(job_id)
        self._executor.shutdown(wait=True, cancel_futures=True)

    def read_output(self, job_id: str, offset: int = 0, limit: int = 65536) -> dict:
        item = self.get(job_id, include_result=False)
        path = self._log_path(job_id)
        offset = max(0, int(offset))
        data = b""
        if path.exists():
            with path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(max(1, min(int(limit), 1024 * 1024)))
        return {
            "job_id": job_id, "status": item["status"], "offset": offset,
            "next_offset": offset + len(data), "output": data.decode("utf-8", "replace"),
            "terminal": item["status"] in TERMINAL_STATES,
        }

    def _prune_history(self) -> None:
        with self._lock:
            terminal = [item for item in self._jobs.values() if item["status"] in TERMINAL_STATES]
            terminal.sort(key=lambda item: item.get("finished_at") or item["created_at"], reverse=True)
            expired = terminal[self.history_limit:]
            for item in expired:
                job_id = item["id"]
                self._jobs.pop(job_id, None)
                for path in (self._state_path(job_id), self._result_path(job_id), self._log_path(job_id)):
                    path.unlink(missing_ok=True)
