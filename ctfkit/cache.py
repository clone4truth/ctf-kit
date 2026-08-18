"""LRU result cache for tool executions.

Cache key = tool name + sorted JSON args. Only successful (non-ERROR) results
are stored. Thread-safe via a single lock; a global lock is fine at this scale
(per-key locks if contention ever matters).
"""

import json
import threading
from collections import OrderedDict

MAX_SIZE = 256
_cache: OrderedDict[str, str] = OrderedDict()
_lock = threading.Lock()
stats = {"hits": 0, "misses": 0, "evictions": 0}


def _key(name: str, args: dict) -> str:
    return name + ":" + json.dumps(args, sort_keys=True, default=str)


def get(name: str, args: dict) -> str | None:
    k = _key(name, args)
    with _lock:
        v = _cache.get(k)
        if v is not None:
            _cache.move_to_end(k)
            stats["hits"] += 1
            return v
        stats["misses"] += 1
    return None


def put(name: str, args: dict, result: str) -> None:
    k = _key(name, args)
    with _lock:
        _cache[k] = result
        _cache.move_to_end(k)
        while len(_cache) > MAX_SIZE:
            _cache.popitem(last=False)
            stats["evictions"] += 1


def snapshot() -> dict:
    with _lock:
        return {"size": len(_cache), "max_size": MAX_SIZE, **stats}


def clear() -> None:
    with _lock:
        _cache.clear()
        stats.update(hits=0, misses=0, evictions=0)


if __name__ == "__main__":
    put("caesar", {"text": "abc", "shift": 1}, "bcd")
    assert get("caesar", {"text": "abc", "shift": 1}) == "bcd"
    assert get("caesar", {"text": "abc", "shift": 2}) is None
    s = snapshot()
    assert s["hits"] == 1 and s["misses"] == 1
    print("cache self-check OK:", s)