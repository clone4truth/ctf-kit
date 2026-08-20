"""Canonical execution results for every CTF Kit transport."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import re


class ToolStatus(StrEnum):
    SUCCESS = "success"
    NO_FINDING = "no_finding"
    UNAVAILABLE = "unavailable"
    INVALID_INPUT = "invalid_input"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    ERROR = "error"


_UNAVAILABLE = re.compile(r"(?i)\b(not installed|unavailable|manual install|requires testing)\b")
_NO_FINDING = re.compile(r"(?i)(^no |^not found|^nothing found|^0 (?:result|match|candidate)|attack failed|no clear .+ detected)")
_FAILURE = re.compile(r"(?i)^(error\b|exception\b|failed(?:\s+to)?\b|install failed\b|attack failed\b)")
_INVALID = re.compile(r"(?i)(^invalid\b|^missing required\b|\bis required\b|must be (?:equal|a |an ))")


def classify_output(text: str) -> ToolStatus:
    """Classify legacy string-returning tools without treating absence as success."""
    value = (text or "").strip()
    if value.lower().startswith("timeout"):
        return ToolStatus.TIMEOUT
    if value.lower().startswith("blocked"):
        return ToolStatus.BLOCKED
    if _UNAVAILABLE.search(value):
        return ToolStatus.UNAVAILABLE
    if _INVALID.search(value):
        return ToolStatus.INVALID_INPUT
    if _NO_FINDING.search(value):
        return ToolStatus.NO_FINDING
    if _FAILURE.search(value):
        return ToolStatus.ERROR
    return ToolStatus.SUCCESS


@dataclass(slots=True)
class ToolRunResult:
    tool: str
    category: str
    status: ToolStatus
    text: str = ""
    duration_ms: float = 0.0
    cached: bool = False
    flags: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in {ToolStatus.SUCCESS, ToolStatus.NO_FINDING}

    def to_dict(self) -> dict:
        value = asdict(self)
        value["status"] = self.status.value
        value["ok"] = self.ok
        return value
