"""Central logger with LogBus for streaming logs to the web UI via SSE.

- "ctfkit" logger is used by every module
- LogBus keeps the latest records (ring buffer) + an event for polling
- Console handler stays active for CLI/MCP usage
"""

import logging
import threading
import time
from collections import deque

_LOG = logging.getLogger("ctfkit")
_CONFIGURED = False

_LEVEL_STYLE = {
    "DEBUG": "\x1b[36m", "INFO": "\x1b[32m", "WARNING": "\x1b[33m",
    "ERROR": "\x1b[31m", "CRITICAL": "\x1b[41;37m",
}
_RESET = "\x1b[0m"


class LogBus(logging.Handler):
    """Handler that stores records in a thread-safe deque for UI polling."""

    def __init__(self, maxlen: int = 500):
        super().__init__()
        self.records = deque(maxlen=maxlen)
        self._evt = threading.Event()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append({
                "ts": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "msg": self.format(record),
            })
            self._evt.set()
        except Exception:
            pass

    def drain(self) -> list[dict]:
        """Take all new records since the last poll."""
        self._evt.clear()
        return list(self.records)


class _ColorConsole(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        color = _LEVEL_STYLE.get(record.levelname, "")
        return f"{color}{base}{_RESET}"


def setup_logging(level: int = logging.INFO) -> tuple[logging.Logger, LogBus]:
    """Initialize the global logger once. Returns (logger, bus)."""
    global _CONFIGURED
    if _CONFIGURED:
        return _LOG, _bus
    _bus = LogBus()
    fmt = "%(asctime)s %(levelname)-8s %(name)s | %(message)s"
    console = logging.StreamHandler()
    console.setFormatter(_ColorConsole(fmt))
    _bus.setFormatter(logging.Formatter("%(message)s"))
    _LOG.setLevel(level)
    _LOG.addHandler(console)
    _LOG.addHandler(_bus)
    _LOG.propagate = False
    _CONFIGURED = True
    return _LOG, _bus


log, bus = setup_logging()
