"""Central logger with LogBus for streaming logs to the web UI via SSE.

- "ctfkit" logger is used by every module
- LogBus keeps the latest records (ring buffer) + an event for polling
- Console handler stays active for CLI/MCP usage
"""

import logging
import sys
import threading
import time
from collections import deque
from loguru import logger as _loguru

_LOG = logging.getLogger("ctfkit")
_CONFIGURED = False
_bus: "LogBus"

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


class _ProgressArea:
    """Per-tool progress rows; each overwrites its own terminal line in place.

    Uses ANSI cursor moves (\\x1b[1A / \\x1b[{n}B) so parallel tools each get
    their own live row; normal logs append below the area.
    """

    def __init__(self):
        self._rows: list[tuple[str, str]] = []  # (key, msg), top -> bottom
        self._width = 0

    def active(self) -> bool:
        return bool(self._rows)

    def update(self, stream, key: str, msg: str) -> None:
        for i, (k, _) in enumerate(self._rows):
            if k == key:
                self._rows[i] = (key, msg)
                break
        else:
            if not self._rows:
                stream.write("\n")  # area starts on its own line
            self._rows.append((key, msg))
        self._width = max(self._width, len(msg))
        self._redraw(stream)

    def remove(self, stream, key: str) -> None:
        old = len(self._rows)
        self._rows = [(k, m) for k, m in self._rows if k != key]
        if not self._rows:
            if old:
                self._redraw(stream, extra=old, blank_all=True)  # blank with old width
                self._width = 0
                stream.write(f"\x1b[{old}A\r\x1b[2K")  # collapse flush with history
            return
        self._redraw(stream, extra=1)  # blank the freed trailing row (width kept)

    def _redraw(self, stream, extra: int = 0, blank_all: bool = False) -> None:
        n = len(self._rows)
        total = n + extra
        for i in range(total - 1, -1, -1):
            stream.write("\x1b[1A\r")
            if not blank_all and i < n:
                stream.write(self._rows[i][1].ljust(self._width) + "\x1b[K")
            else:
                stream.write(" " * self._width + "\x1b[K")
        stream.write(f"\x1b[{total}B")


class _Console(logging.StreamHandler):
    """Console handler: progress records render as per-tool live bars.

    A record tagged ``progress=True`` (with ``progress_key``) updates one bar;
    ``progress_done=<key>`` removes that bar; plain records append below.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._area = _ProgressArea()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.acquire()  # parallel tool threads share this stream
            try:
                msg = record.getMessage()
                stream = self.stream
                done_key = getattr(record, "progress_done", None)
                if done_key:
                    self._area.remove(stream, done_key)
                if getattr(record, "progress", False):
                    key = getattr(record, "progress_key", "") or "tool"
                    self._area.update(stream, key, msg)
                else:
                    if not self._area.active() and getattr(stream, "isatty", lambda: False)():
                        stream.write("\r\x1b[2K")
                    _loguru.opt(exception=record.exc_info, depth=1).log(record.levelname, msg)
                stream.flush()
            finally:
                self.release()
        except Exception:
            self.handleError(record)


def setup_logging(level: int = logging.INFO) -> tuple[logging.Logger, LogBus]:
    """Initialize the global logger once. Returns (logger, bus)."""
    global _CONFIGURED, _bus
    if _CONFIGURED:
        return _LOG, _bus
    _loguru.remove()
    _loguru.add(
        sys.stderr,
        level=logging.getLevelName(level),
        format=("<dim>{time:HH:mm:ss}</dim>  "
                "<level>{level: <7}</level> <dim>│</dim> <level>{message}</level>"),
        colorize=sys.stderr.isatty(),
        enqueue=True,
        backtrace=True,
        diagnose=False,
    )
    _bus = LogBus()
    console = _Console(sys.stderr)
    _bus.setFormatter(logging.Formatter("%(message)s"))
    _LOG.setLevel(level)
    _LOG.addHandler(console)
    _LOG.addHandler(_bus)
    _LOG.propagate = False
    _CONFIGURED = True
    return _LOG, _bus


log, bus = setup_logging()
