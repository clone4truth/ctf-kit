"""Typed runtime configuration shared by REST, MCP, and tool execution.

Environment parsing lives here so transports and tools do not each invent
slightly different defaults.  Importing this module never changes the host.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import ipaddress
from urllib.parse import urlsplit


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True, slots=True)
class Settings:
    api_token: str
    cors_origins: tuple[str, ...]
    max_upload_bytes: int
    safety_mode: str
    allow_install: bool
    docker_enabled: bool
    docker_pull: bool
    enforce_target_scope: bool
    allowed_targets: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.environ.get(
                "CTFKIT_CORS_ORIGINS", "http://127.0.0.1,http://localhost"
            ).split(",")
            if origin.strip()
        )
        return cls(
            api_token=os.environ.get("CTFKIT_API_TOKEN", ""),
            cors_origins=origins,
            max_upload_bytes=_positive_int_env("CTFKIT_MAX_UPLOAD_BYTES", 64 * 1024 * 1024),
            safety_mode=os.environ.get("CTFKIT_SAFETY_MODE", "auto").lower(),
            # Tool calls already require the explicit auto=true argument. Keep
            # the normal local-lab experience zero-config while deployments can
            # still disable installation with CTFKIT_ALLOW_INSTALL=0.
            allow_install=_bool_env("CTFKIT_ALLOW_INSTALL", default=True),
            docker_enabled=_bool_env("CTFKIT_DOCKER"),
            docker_pull=_bool_env("CTFKIT_DOCKER_PULL"),
            enforce_target_scope=_bool_env("CTFKIT_ENFORCE_TARGET_SCOPE"),
            allowed_targets=tuple(
                item.strip().lower()
                for item in os.environ.get("CTFKIT_ALLOWED_TARGETS", "").split(",")
                if item.strip()
            ),
        )


def is_loopback_host(host: str) -> bool:
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def _host_matches(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.rstrip(".").lower()
    if is_loopback_host(host):
        return True
    for entry in allowed:
        candidate = entry.rstrip(".").lower()
        if candidate.startswith("*.") and host.endswith(candidate[1:]):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(candidate, strict=False):
                return True
        except ValueError:
            if host == candidate:
                return True
    return False


def target_scope_error(args: dict, config: Settings | None = None) -> str | None:
    """Validate URL/host-like arguments when strict target scope is enabled."""
    config = config or settings
    if not config.enforce_target_scope:
        return None
    candidates: list[str] = []
    for key, value in args.items():
        if not isinstance(value, str):
            continue
        if key in {"url", "host", "domain", "ip", "ip_or_host", "remote_host"}:
            candidates.append(value)
        if key == "args":
            candidates.extend(part for part in value.split() if "://" in part)
    for candidate in candidates:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname or candidate.split(":", 1)[0]
        if host and not _host_matches(host, config.allowed_targets):
            return f"target '{host}' is outside CTFKIT_ALLOWED_TARGETS"
    return None


settings = Settings.from_env()
