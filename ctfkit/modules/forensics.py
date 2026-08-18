"""Forensics: file type, strings, hexdump, carving, zlib hunt, entropy, pcap HTTP."""

import math
import os
import re
import struct
import zlib

from ..registry import tool
from ..utils import detect_type, printable, MAGIC


@tool(category="forensics")
def file_type(path: str) -> str:
    """Detect file type from magic bytes + basic entropy stats."""
    data = open(path, "rb").read()
    head = data[:64]
    name = detect_type(head)
    ext = os.path.splitext(path)[1]
    entropy = _entropy(data[:65536]) if data else 0
    return (f"path: {path}\ntype: {name}\noriginal extension: {ext or '-'}\n"
            f"size: {len(data)} bytes ({len(data)/1024:.1f} KB)\n"
            f"magic (16): {head[:16].hex()}\nentropy (first 64KB): {entropy:.4f} bits/byte"
            + ("  <- possibly encrypted/compressed" if entropy > 7.5 else ""))


@tool(category="forensics")
def strings_extract(path: str, min_len: int = 4, encoding: str = "ascii") -> str:
    """Extract printable strings. encoding: ascii / utf16 / both."""
    data = open(path, "rb").read()
    out = []
    patterns = []
    if encoding in ("ascii", "both"):
        patterns.append(("ascii", rb"[\x20-\x7e]{%d,}" % min_len))
    if encoding in ("utf16", "both"):
        patterns.append(("utf16", rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for enc, pat in patterns:
        for m in re.finditer(pat, data):
            s = m.group()
            out.append(s.decode("utf-16-le" if enc == "utf16" else "ascii"))
    body = "\n".join(out[:500])
    if len(out) > 500:
        body += f"\n... ({len(out)} total strings, showing 500)"
    return f"{len(out)} strings found (min_len={min_len}):\n{body}"


@tool(category="forensics")
def hexdump(path: str, offset: int = 0, length: int = 256, group: int = 8) -> str:
    """Hexdump: offset, hex + ascii column. group = bytes per hex group."""
    data = open(path, "rb").read()
    chunk = data[offset:offset + length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hexs = []
        for g in range(0, len(row), group):
            hexs.append(" ".join(f"{b:02x}" for b in row[g:g + group]))
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset + i:08x}  {'  '.join(hexs):<47}  |{asc}|")
    return "\n".join(lines) or f"Offset {offset} is past end of file ({len(data)} bytes)."


def _end_of_file(data: bytes, start: int, magic: bytes) -> int:
    if magic == b"\x89PNG\r\n\x1a\n":
        m = re.search(b"IEND\xaeB`\x82", data[start:])
        return start + m.end() if m else len(data)
    if magic == b"\xff\xd8\xff":
        for m in re.finditer(b"\xff\xd9", data[start:]):
            return start + m.end()
        return len(data)
    if magic == b"PK\x03\x04":
        m = re.search(b"PK\x05\x06", data[start:])
        return start + (m.end() + 22 if m else len(data))
    if magic == b"%PDF":
        m = re.search(rb"%%EOF", data[start:])
        return start + m.end() if m else len(data)
    if magic == b"RIFF":
        return start + 8 + int.from_bytes(data[start + 4:start + 8], "little")
    return len(data)


@tool(category="forensics")
def carve(file_path: str, out_dir: str = "carved") -> str:
    """Carve embedded files (PNG/JPEG/GIF/ZIP/PDF/RIFF/ELF/...) from a blob. Saved to out_dir."""
    data = open(file_path, "rb").read()
    os.makedirs(out_dir, exist_ok=True)
    found = []
    base = os.path.basename(file_path)
    for magic, name in sorted(MAGIC, key=lambda m: -len(m[0])):
        for m in re.finditer(re.escape(magic), data, flags=re.DOTALL):
            start = m.start()
            end = _end_of_file(data, start, magic)
            if end <= start:
                continue
            ext = name.split()[0].lower().replace("/", "_")
            fn = os.path.join(out_dir, f"{base}_{start:x}.{ext}")
            with open(fn, "wb") as f:
                f.write(data[start:end])
            found.append(f"0x{start:x} ({start}) {name} -> {fn} ({end - start} bytes)")
    return "\n".join(found) if found else "No embedded files found."


@tool(category="forensics")
def zlib_hunt(file_path: str) -> str:
    """Find every zlib/gzip stream inside a file, decompress, preview. For compressed flags."""
    data = open(file_path, "rb").read()
    found = []
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]|\x1f\x8b\x08", data, flags=re.DOTALL):
        start = m.start()
        try:
            if data[start] == 0x1f:
                d = zlib.decompress(data[start:], 16 + zlib.MAX_WBITS)
                kind = "gzip"
            else:
                d = zlib.decompress(data[start:])
                kind = "zlib"
        except Exception:
            continue
        found.append(f"0x{start:x} [{kind}] {len(d)} bytes -> {printable(d, 200)}")
    return "\n".join(found) if found else "No valid zlib/gzip streams found."


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


@tool(category="forensics")
def entropy_map(file_path: str, block_size: int = 4096) -> str:
    """Per-block entropy (for finding hidden data at end of file / encrypted regions)."""
    data = open(file_path, "rb").read()
    lines = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        e = _entropy(block)
        bar = "#" * int(e * 20 / 8)
        lines.append(f"0x{i:08x} {e:.2f} |{bar}")
    return f"entropy per {block_size} bytes:\n" + "\n".join(lines)


@tool(category="forensics")
def pcap_http(pcap_path: str, max_flows: int = 20) -> str:
    """Parse a minimal PCAP (Ethernet/IP/TCP) and extract HTTP payloads + printable text per TCP flow."""
    data = open(pcap_path, "rb").read()
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return "Not a pcap (bad magic)."
    le = data[:4] == b"\xd4\xc3\xb2\xa1"
    link_type = struct.unpack("<I" if le else ">I", data[20:24])[0]
    pos = 24
    flows = {}
    n_packets = 0
    while pos + 16 <= len(data):
        if le:
            ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", data[pos:pos + 16])
        else:
            ts_sec, ts_usec, incl, orig = struct.unpack(">IIII", data[pos:pos + 16])
        pos += 16
        if pos + incl > len(data):
            break
        pkt = data[pos:pos + incl]
        pos += incl
        n_packets += 1
        if link_type == 1:  # Ethernet
            if len(pkt) < 14:
                continue
            eth_type = int.from_bytes(pkt[12:14], "big")
            pkt = pkt[14:]
        elif link_type == 101:  # raw IP
            eth_type = 0x0800
        else:
            continue
        if eth_type != 0x0800 or len(pkt) < 20:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        if proto != 6 or len(pkt) < ihl + 20:
            continue
        sport = int.from_bytes(pkt[ihl:ihl + 2], "big")
        dport = int.from_bytes(pkt[ihl + 2:ihl + 4], "big")
        payload = pkt[ihl + 20:]
        if not payload:
            continue
        flow = (sport, dport) if sport < dport else (dport, sport)
        flows.setdefault(flow, []).append(payload)
    out = [f"{n_packets} packets read, {len(flows)} TCP flows"]
    for (sa, da), chunks in list(flows.items())[:max_flows]:
        blob = b"".join(chunks)
        out.append(f"\n=== flow {sa}<->{da} ({len(blob)} bytes payload) ===")
        if b"HTTP" in blob[:2048]:
            head = blob[:2048].decode("latin-1", "replace")
            out.append("HTTP detected:\n" + head[:1000])
        else:
            out.append(printable(blob, 400))
    return "\n".join(out)