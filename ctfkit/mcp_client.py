"""Lightweight HTTP client used by the MCP bridge in remote-backend mode."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class BackendUnavailable(RuntimeError):
    """Raised when the configured CTF Kit backend cannot be reached."""


class CTFKitBackendClient:
    """Small dependency-free client for the central REST execution backend."""

    def __init__(self, server_url: str, token: str = "", timeout: float = 300,
                 retries: int = 2, retry_delay: float = 0.25):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_delay = max(0.0, float(retry_delay))

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", "X-CTFKit-Source": "mcp"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(f"{self.server_url}/{path.lstrip('/')}", data=body,
                          headers=headers, method=method)
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as ex:
                try:
                    detail = json.loads(ex.read().decode("utf-8")).get("detail", str(ex))
                except Exception:
                    detail = str(ex)
                raise BackendUnavailable(f"backend HTTP {ex.code}: {detail}") from ex
            except (URLError, TimeoutError, OSError) as ex:
                last_error = ex
                if attempt < self.retries:
                    time.sleep(self.retry_delay * (attempt + 1))
        raise BackendUnavailable(f"cannot reach CTF Kit backend at {self.server_url}: {last_error}")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def telemetry(self) -> dict[str, Any]:
        return self._request("GET", "/api/telemetry")

    def execute_tool(self, name: str, arguments: dict | None = None) -> dict[str, Any]:
        return self._request("POST", "/api/run", {"name": name, "arguments": arguments or {}})

    def submit_job(self, name: str, arguments: dict | None = None) -> dict[str, Any]:
        return self._request("POST", "/api/jobs", {"name": name, "arguments": arguments or {}})

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/jobs/{job_id}")

    def get_job_output(self, job_id: str, offset: int = 0,
                       limit: int = 65536) -> dict[str, Any]:
        query = urlencode({"offset": max(0, int(offset)), "limit": max(1, int(limit))})
        return self._request("GET", f"/api/jobs/{job_id}/output?{query}")

    def list_jobs(self, status: str = "", limit: int = 100) -> dict[str, Any]:
        query = urlencode({"status": status, "limit": max(1, int(limit))})
        return self._request("GET", f"/api/jobs?{query}")

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        return self._request("POST", f"/api/jobs/{job_id}/cancel", {})
