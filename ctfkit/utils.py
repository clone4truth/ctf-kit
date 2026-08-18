"""Shared helpers for all ctfkit modules."""

import inspect
import re

# ---------------------------------------------------------------------------
# Encoding / conversion
# ---------------------------------------------------------------------------

def to_hex(b: bytes) -> str:
    return b.hex()

def from_hex(h: str) -> bytes:
    return bytes.fromhex(h.replace(" ", "").replace("0x", "").replace(",", ""))

def b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()

def from_b64(s: str) -> bytes:
    import base64
    return base64.b64decode(s + "=" * (-len(s) % 4))

def printable(b: bytes, limit: int = 1000) -> str:
    """Bytes -> ascii string; non-printable chars become '.'"""
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b[:limit])

def nice_bytes(b: bytes, limit: int = 300) -> str:
    """Short representation: ascii when clean, hex otherwise."""
    if not b:
        return "(empty)"
    if all(32 <= x < 127 or x in (9, 10, 13) for x in b[:2000]):
        return b[:limit].decode("utf-8", "replace")
    return b[:limit].hex()

# ---------------------------------------------------------------------------
# English scoring (for brute-force ciphers)
# ---------------------------------------------------------------------------

_ENGLISH_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}

def english_score(text: bytes) -> float:
    score = 0.0
    for ch in text:
        c = chr(ch).lower()
        if c in _ENGLISH_FREQ:
            score += _ENGLISH_FREQ[c]
        elif ch in (32, 10, 13, 9, 44, 46, 39, 34, 33, 63, 58, 59, 45, 95, 123, 125):
            score += 1.5
        elif ch < 32 or ch > 126:
            score -= 10
    return score

def best_lines(results: list[tuple[float, str]], top: int = 5) -> str:
    """Sort candidates [(score, label)] and take the top."""
    results.sort(key=lambda x: x[0], reverse=True)
    return "\n".join(label for _, label in results[:top])

# ---------------------------------------------------------------------------
# Magic bytes (file type)
# ---------------------------------------------------------------------------

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image (87a)"),
    (b"GIF89a", "GIF image (89a)"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP (EOCD)"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"RIFF", "RIFF (AVI/WAV)"),
    (b"BM", "BMP image"),
    (b"OggS", "Ogg container"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"\x52\x61\x72\x21\x1a\x07", "RAR archive"),
    (b"MZ", "PE executable (DOS stub)"),
    (b"SQLite format 3", "SQLite database"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"ITSF", "CHM"),
    (b"\x1a\x45\xdf\xa3", "Matroska/WebM"),
    (b"\x00\x00\x01\xba", "MPEG-PS video"),
    (b"ftyp", "MP4/MOV"),
    (b"ID3", "MP3 (ID3 tag)"),
]

def detect_type(data: bytes) -> str:
    for magic, name in sorted(MAGIC, key=lambda m: -len(m[0])):
        if data.startswith(magic):
            return name
    return "Unknown"

# ---------------------------------------------------------------------------
# Param introspection for MCP/UI
# ---------------------------------------------------------------------------

_PARAM_DESC_RE = re.compile(r":param\s+(\w+)\s*:\s*([^\n]+)")

def tool_params(fn) -> list[dict]:
    """Extract params from signature + docstring param docs (if any)."""
    sig = inspect.signature(fn)
    doc = inspect.getdoc(fn) or ""
    descs = dict(_PARAM_DESC_RE.findall(doc))
    params = []
    for name, p in sig.parameters.items():
        if name in ("self", "ctx", "context"):
            continue
        t = p.annotation if p.annotation is not inspect.Parameter.empty else str
        jt = {"int": "int", "str": "str", "bool": "bool", "float": "float"}.get(getattr(t, "__name__", str(t)), "str")
        params.append({
            "name": name,
            "type": jt,
            "required": p.default is inspect.Parameter.empty,
            "default": None if p.default is inspect.Parameter.empty else p.default,
            "desc": descs.get(name, "").strip(),
        })
    return params
