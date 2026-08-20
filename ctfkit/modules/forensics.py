"""Forensics: file type, strings, hexdump, carving, zlib hunt, entropy, pcap HTTP."""

import math
import os
import re
import sys
import struct
import zlib

from ..registry import tool
from ..utils import detect_type, printable, MAGIC


@tool(category="forensics")
def file_type(path: str) -> str:
    """Detect file type from magic bytes + basic entropy stats.
    :param path: input file path
    """
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
    """Extract printable strings. encoding: ascii / utf16 / both.
    :param min_len: min len
    :param path: input file path
    :param encoding: encoding
    """
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
    """Hexdump: offset, hex + ascii column. group = bytes per hex group.
    :param offset: offset
    :param group: group
    :param length: length
    :param path: input file path
    """
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
    """Carve embedded files (PNG/JPEG/GIF/ZIP/PDF/RIFF/ELF/...) from a blob. Saved to out_dir.
    :param out_dir: output directory
    :param file_path: input file path
    """
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
    """Find every zlib/gzip stream inside a file, decompress, preview. For compressed flags.
    :param file_path: input file path
    """
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
    """Per-block entropy (for finding hidden data at end of file / encrypted regions).
    :param file_path: input file path
    :param block_size: block size
    """
    data = open(file_path, "rb").read()
    lines = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        e = _entropy(block)
        bar = "#" * int(e * 20 / 8)
        lines.append(f"0x{i:08x} {e:.2f} |{bar}")
    return f"entropy per {block_size} bytes:\n" + "\n".join(lines)


def _iter_packets(data: bytes):
    """Universal packet iterator supporting both classic PCAP and modern PCAPNG formats."""
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        # Classic PCAP
        le = data[:4] == b"\xd4\xc3\xb2\xa1"
        link_type = struct.unpack("<I" if le else ">I", data[20:24])[0]
        pos = 24
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
            yield link_type, pkt
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        # PCAPNG format
        pos = 0
        link_type = 1  # default Ethernet
        le = True
        while pos + 8 <= len(data):
            block_type = int.from_bytes(data[pos:pos + 4], "little" if le else "big")
            block_len = int.from_bytes(data[pos + 4:pos + 8], "little" if le else "big")
            if block_len < 12 or pos + block_len > len(data):
                break
            body = data[pos + 8:pos + block_len - 4]
            if block_type == 0x0A0D0D0A:  # Section Header Block
                if len(body) >= 4:
                    magic = body[:4]
                    if magic == b"\x1a\x2b\x3c\x4d":
                        le = True
                    elif magic == b"\x4d\x3c\x2b\x1a":
                        le = False
            elif block_type == 0x00000001:  # Interface Description Block
                if len(body) >= 2:
                    link_type = int.from_bytes(body[:2], "little" if le else "big")
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) >= 20:
                    caplen = int.from_bytes(body[12:16], "little" if le else "big")
                    pkt_data = body[20:20 + caplen]
                    yield link_type, pkt_data
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) >= 4:
                    caplen = int.from_bytes(body[:4], "little" if le else "big")
                    pkt_data = body[4:4 + caplen]
                    yield link_type, pkt_data
            pos += block_len


@tool(category="forensics")
def pcap_http(pcap_path: str, max_flows: int = 20) -> str:
    """Parse PCAP / PCAPNG files and extract HTTP payloads & printable text per TCP stream.
    :param max_flows: max flows
    :param pcap_path: path to the pcap file
    """
    data = open(pcap_path, "rb").read()
    flows = {}
    n_packets = 0

    for link_type, pkt in _iter_packets(data):
        n_packets += 1
        if link_type == 1:  # Ethernet
            if len(pkt) < 14:
                continue
            eth_type = int.from_bytes(pkt[12:14], "big")
            pkt = pkt[14:]
        elif link_type in (101, 12):  # Raw IP
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
        tcp_off = ((pkt[ihl + 12] >> 4) & 0x0F) * 4
        payload = pkt[ihl + tcp_off:]
        if not payload:
            continue
        flow = (sport, dport) if sport < dport else (dport, sport)
        flows.setdefault(flow, []).append(payload)

    if not n_packets:
        return "Could not read any packets from file (unsupported format or empty capture)."

    out = [f"{n_packets} packets read, {len(flows)} TCP flows found"]
    for (sa, da), chunks in list(flows.items())[:max_flows]:
        blob = b"".join(chunks)
        out.append(f"\n=== Flow {sa} <-> {da} ({len(blob)} bytes payload) ===")
        if b"HTTP" in blob[:2048] or b"GET " in blob[:2048] or b"POST " in blob[:2048]:
            head = blob[:2048].decode("latin-1", "replace")
            out.append("HTTP Detected:\n" + head[:800])
        else:
            out.append(printable(blob, 400))
    return "\n".join(out)


@tool(category="forensics")
def pcap_dns_exfil(pcap_path: str) -> str:
    """Extract DNS query subdomains from PCAP/PCAPNG to recover exfiltrated flags or data.
    :param pcap_path: path to the pcap file
    """
    data = open(pcap_path, "rb").read()
    queries = []

    for link_type, pkt in _iter_packets(data):
        if link_type == 1:
            if len(pkt) < 14:
                continue
            eth_type = int.from_bytes(pkt[12:14], "big")
            pkt = pkt[14:]
        elif link_type in (101, 12):
            eth_type = 0x0800
        else:
            continue

        if eth_type != 0x0800 or len(pkt) < 28:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        if proto != 17 or len(pkt) < ihl + 8:  # UDP
            continue

        sport = int.from_bytes(pkt[ihl:ihl + 2], "big")
        dport = int.from_bytes(pkt[ihl + 2:ihl + 4], "big")
        if dport != 53 and sport != 53:
            continue

        udp_payload = pkt[ihl + 8:]
        if len(udp_payload) < 12:
            continue

        # Parse DNS Question
        pos = 12
        domain_parts = []
        while pos < len(udp_payload):
            length = udp_payload[pos]
            if length == 0:
                break
            pos += 1
            if pos + length > len(udp_payload):
                break
            part = udp_payload[pos:pos + length].decode("latin-1", "replace")
            domain_parts.append(part)
            pos += length

        if domain_parts:
            full_domain = ".".join(domain_parts)
            if full_domain not in queries:
                queries.append(full_domain)

    if not queries:
        return "No DNS queries found in PCAP."

    out = [f"Found {len(queries)} unique DNS queries:\n"]
    out.extend(f"  {q}" for q in queries[:40])
    if len(queries) > 40:
        out.append(f"  ... ({len(queries) - 40} more queries)")

    # Attempt extraction of hex or base64 subdomains
    subdomains = [q.split(".")[0] for q in queries]
    joined_hex = "".join(s for s in subdomains if re.fullmatch(r"[0-9a-fA-F]+", s))
    if len(joined_hex) >= 8 and len(joined_hex) % 2 == 0:
        try:
            raw = bytes.fromhex(joined_hex)
            out.append(f"\n🏆 Decoded Hex Exfiltration ({len(raw)} bytes):\n{printable(raw, 500)}")
        except Exception:
            pass

    return "\n".join(out)


_USB_HID_KEYS = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0a: ('g', 'G'), 0x0b: ('h', 'H'),
    0x0c: ('i', 'I'), 0x0d: ('j', 'J'), 0x0e: ('k', 'K'), 0x0f: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1a: ('w', 'W'), 0x1b: ('x', 'X'),
    0x1c: ('y', 'Y'), 0x1d: ('z', 'Z'), 0x1e: ('1', '!'), 0x1f: ('2', '@'),
    0x20: ('3', '#'), 0x21: ('4', '$'), 0x22: ('5', '%'), 0x23: ('6', '^'),
    0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'), 0x2a: ('[BACKSPACE]', '[BACKSPACE]'), 0x2c: (' ', ' '),
    0x2d: ('-', '_'), 0x2e: ('=', '+'), 0x2f: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x33: (';', ':'), 0x34: ("'", '"'), 0x36: (',', '<'),
    0x37: ('.', '>'), 0x38: ('/', '?'),
}


@tool(category="forensics")
def pcap_usb_keystrokes(pcap_path: str) -> str:
    """Parse USB HID keyboard packets in PCAP/PCAPNG to reconstruct typed text and flags.
    :param pcap_path: path to the pcap file
    """
    data = open(pcap_path, "rb").read()
    typed = []

    for link_type, pkt in _iter_packets(data):
        # Look for 8-byte HID keyboard report: [modifier, reserved, key1, key2, ...]
        hid_data = None
        if len(pkt) == 8:
            hid_data = pkt
        elif len(pkt) >= 8 and (b"\x00\x00" in pkt or len(pkt) in (27, 35, 64)):
            # USB header offset extraction
            hid_data = pkt[-8:]

        if not hid_data or len(hid_data) != 8:
            continue

        mod = hid_data[0]
        shift = bool(mod & 0x22)
        keycode = hid_data[2]

        if keycode in _USB_HID_KEYS:
            char = _USB_HID_KEYS[keycode][1 if shift else 0]
            if char == '[BACKSPACE]':
                if typed:
                    typed.pop()
            else:
                typed.append(char)

    result = "".join(typed)
    return (f"🏆 Reconstructed USB Keystrokes ({len(typed)} characters):\n"
            f"----------------------------------------\n"
            f"{result or 'No USB keyboard HID keystrokes identified.'}\n"
            f"----------------------------------------")


@tool(category="forensics")
def zip_fix_pseudo_encrypt(zip_path: str, out_path: str = "") -> str:
    """Detect and fix pseudo-encrypted ZIP archives (clears the fake encryption bit 0x0001).
    :param out_path: output file path
    :param zip_path: path to the ZIP file
    """
    data = bytearray(open(zip_path, "rb").read())
    fixed_count = 0

    # Check Local File Headers (PK\x03\x04)
    pos = 0
    while True:
        pos = data.find(b"PK\x03\x04", pos)
        if pos == -1 or pos + 8 > len(data):
            break
        flags = int.from_bytes(data[pos + 6:pos + 8], "little")
        if flags & 0x0001:
            data[pos + 6] &= 0xFE  # clear bit 0
            fixed_count += 1
        pos += 4

    # Check Central Directory Headers (PK\x01\x02)
    pos = 0
    while True:
        pos = data.find(b"PK\x01\x02", pos)
        if pos == -1 or pos + 10 > len(data):
            break
        flags = int.from_bytes(data[pos + 8:pos + 10], "little")
        if flags & 0x0001:
            data[pos + 8] &= 0xFE  # clear bit 0
            fixed_count += 1
        pos += 4

    if fixed_count == 0:
        return "No pseudo-encryption flags found in ZIP archive (headers appear normal)."

    dest = out_path or (os.path.splitext(zip_path)[0] + "_unlocked.zip")
    with open(dest, "wb") as f:
        f.write(data)

    return (f"🏆 Successfully fixed {fixed_count} pseudo-encryption flags in ZIP!\n"
            f"Unlocked archive saved to: {dest}\n"
            f"You can now extract {dest} without a password prompt.")


@tool(category="forensics")
def exif_gps_map(image_path: str) -> str:
    """Extract EXIF GPS coordinates from an image and generate decimal Lat/Long and Maps links.
    :param image_path: path to the image file
    """
    from PIL import Image, ExifTags
    try:
        img = Image.open(image_path)
        exif = img._getexif()
        if not exif:
            return "No EXIF metadata found in image."
    except Exception as ex:
        return f"Failed to read image EXIF: {ex}"

    gps_info = None
    for tag_id, val in exif.items():
        if ExifTags.TAGS.get(tag_id) == "GPSInfo":
            gps_info = val
            break

    if not gps_info:
        return "No GPSInfo tag found in EXIF metadata."

    def to_deg(val):
        if not val:
            return 0.0
        d, m, s = val[0], val[1], val[2]
        d_val = d[0] / d[1] if isinstance(d, tuple) else float(d)
        m_val = m[0] / m[1] if isinstance(m, tuple) else float(m)
        s_val = s[0] / s[1] if isinstance(s, tuple) else float(s)
        return d_val + (m_val / 60.0) + (s_val / 3600.0)

    lat_ref = gps_info.get(1, "N")
    lat_val = to_deg(gps_info.get(2))
    if lat_ref == "S":
        lat_val = -lat_val

    lon_ref = gps_info.get(3, "E")
    lon_val = to_deg(gps_info.get(4))
    if lon_ref == "W":
        lon_val = -lon_val

    alt = gps_info.get(6, 0)
    alt_val = alt[0] / alt[1] if isinstance(alt, tuple) else float(alt)

    gmaps_url = f"https://www.google.com/maps?q={lat_val:.6f},{lon_val:.6f}"
    osm_url = f"https://www.openstreetmap.org/?mlat={lat_val:.6f}&mlon={lon_val:.6f}#map=16/{lat_val:.6f}/{lon_val:.6f}"

    return (f"📍 EXIF GPS Coordinates Located:\n"
            f"Latitude  : {lat_val:.6f}° ({lat_ref})\n"
            f"Longitude : {lon_val:.6f}° ({lon_ref})\n"
            f"Altitude  : {alt_val:.2f} m\n\n"
            f"Google Maps : {gmaps_url}\n"
            f"OpenStreetMap: {osm_url}")


@tool(category="forensics")
def ntfs_ads(path: str) -> str:
    """List NTFS Alternate Data Streams (ADS) on a file or directory — hidden flags often live in :stream.

    :param path: file or directory path to inspect for ADS
    """
    import subprocess as _sp
    if sys.platform == "win32":
        try:
            out = _sp.run(["cmd", "/c", "dir", "/R", path], capture_output=True, text=True).stdout
        except OSError:
            return "ERROR: dir /R failed."
        ads = [ln.strip() for ln in out.splitlines() if ":" in ln and ("$DATA" in ln or ": " in ln)]
        ads = [a for a in ads if ":" in a and not a.startswith("Volume")]
        return "ADS found:\n" + "\n".join(ads) if ads else f"No ADS found on {path} (or file missing)."
    try:
        out = _sp.run(["getfattr", "-d", "-m", "-", path], capture_output=True, text=True).stdout
        return f"getfattr output:\n{out}" if out.strip() else f"No xattrs/ADS found on {path}."
    except OSError:
        return "ERROR: getfattr not installed. apt install attr"

@tool(category="forensics")
def sqlite_reader(path: str, table: str = "") -> str:
    """Read SQLite databases: list tables, dump rows, and scan every field for flag patterns.

    Uses Python stdlib sqlite3 — works even when the sqlite3 CLI is missing.

    :param path: path to the .db / .sqlite file
    :param table: optional table name to dump (default: all tables)
    """
    import sqlite3 as _sq
    from ..flagmeta import extract_flags, detect_flag
    try:
        with open(path, "rb") as fh:
            if fh.read(16) != b"SQLite format 3\x00":
                return "ERROR: not a SQLite database (magic 'SQLite format 3' missing)"
    except OSError as e:
        return f"ERROR: {e}"
    try:
        con = _sq.connect(f"file:{path}?mode=ro", uri=True)
        con.text_factory = bytes
        cur = con.cursor()
    except _sq.Error as e:
        return f"ERROR: {e}"
    try:
        cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
        tables = [(r[0].decode("utf-8", "replace"), r[1].decode()) for r in cur.fetchall()]
        if not tables:
            return "No tables found."
        out = [f"tables ({len(tables)}):"]
        for name, typ in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{name}"')
                cnt = cur.fetchone()[0]
            except _sq.Error:
                cnt = "?"
            out.append(f"  - {name} ({typ}, rows={cnt})")
        targets = [table] if table else [t[0] for t in tables]
        hits = []
        for name in targets:
            try:
                cur.execute(f'SELECT * FROM "{name}" LIMIT 200')
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
            except _sq.Error as e:
                out.append(f"  [{name}] ERROR: {e}")
                continue
            out.append("")
            out.append(f"== {name} ==")
            out.append(" | ".join(cols))
            for row in rows:
                cells = []
                for v in row:
                    if isinstance(v, bytes):
                        s = printable(v, 120)
                    else:
                        s = str(v)[:120]
                    cells.append(s)
                out.append(" | ".join(cells))
                for v in row:
                    s = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
                    fl = extract_flags(s)
                    if fl:
                        hits.append((name, s[:200], fl))
        con.close()
        if hits:
            out.append("")
            out.append("FLAG CANDIDATES:")
            for name, src, fl in hits:
                out.append(f"  [{name}] {src} -> {fl}")
        return "\n".join(out)[:12000]
    except _sq.Error as e:
        con.close()
        return f"ERROR: {e}"


@tool(category="forensics")
def pdf_analyze(path: str, object_id: int = 0) -> str:
    """Analyze PDF files: object map, metadata, and every FlateDecode stream (auto-decompressed).

    Flags are often hidden inside compressed streams (zlib) or JavaScript actions.

    :param path: path to the PDF file
    :param object_id: dump a single object in detail (0 = summarize all)
    """
    import hashlib as _hl
    try:
        data = open(path, "rb").read()
    except OSError as e:
        return f"ERROR: {e}"
    if not data.startswith(b"%PDF-"):
        return "ERROR: not a PDF (magic %PDF- missing)"
    version = data[5:8].decode("utf-8", "replace")
    objs = re.findall(rb"(\d+)\s+0\s+obj\b(.*?)endobj", data, re.S)
    out = [f"PDF version {version}, {len(objs)} objects, {len(data)} bytes"]
    meta: dict[str, str] = {}
    streams = []
    for num, body in objs:
        num_i = int(num)
        body_txt = body[:3000]
        dict_part = body_txt.split(b"stream")[0] if b"stream" in body_txt else body_txt
        is_stream = b"stream" in body_txt
        length = 0
        filt = ""
        lm = re.search(rb"/Length\s+(\d+)", dict_part)
        if lm:
            length = int(lm.group(1))
        fm = re.search(rb"/Filter\s*(?:\[([^\]]*)\]|/(\w+))", dict_part)
        if fm:
            filt = (fm.group(1) or fm.group(2)).decode("utf-8", "replace").strip()
        for key in (b"/Title", b"/Author", b"/Creator", b"/Producer", b"/Subject", b"/Keywords"):
            km = re.search(re.escape(key) + rb"\s*\(([^)]*)\)", body_txt)
            if km:
                meta[key.decode()] = km.group(1).decode("utf-8", "replace")
        if is_stream:
            sbody = body_txt.split(b"stream", 1)[1]
            sbody = sbody.lstrip(b"\r\n")
            raw = sbody[:length] if length else sbody
            streams.append((num_i, length, filt, raw))
    if meta:
        out.append("")
        out.append("metadata:")
        for k, v in meta.items():
            out.append(f"  {k}: {v}")
    out.append("")
    out.append(f"streams: {len(streams)}")
    hits = []
    for num_i, length, filt, raw in streams:
        dec = raw
        if "Flate" in filt or filt == "":
            try:
                dec = zlib.decompress(raw)
            except Exception:
                pass
        text = printable(dec, 4000)
        out.append(f"  obj {num_i}: /Length={length} /Filter={filt or '(none)'} -> {len(dec)} bytes")
        if b"flag" in dec.lower() or b"{" in dec[:2000]:
            lines = [l for l in dec.splitlines() if b"flag" in l.lower() or b"{" in l]
            for l in lines[:5]:
                out.append(f"    candidate: {printable(l, 300)}")
        h = _hl.sha256(dec).hexdigest()[:16]
        out.append(f"    sha256[0:16]: {h}")
        if text:
            out.append(f"    preview: {text[:400]}")
    if object_id:
        for num_i, length, filt, raw in streams:
            if num_i == object_id:
                dec = raw
                if "Flate" in filt or filt == "":
                    try:
                        dec = zlib.decompress(raw)
                    except Exception:
                        pass
                out.append("")
                out.append(f"== object {object_id} stream ==")
                out.append(printable(dec, 4000))
    if hits:
        out.append("")
        out.append("FLAG CANDIDATES: " + ", ".join(hits))
    return "\n".join(out)[:12000]


@tool(category="forensics")
def pcap_credentials_extract(pcap_path: str) -> str:
    """Extract plaintext credentials from PCAP (HTTP Basic Auth, FTP USER/PASS, SMTP AUTH, Telnet, POST data).

    :param pcap_path: Path to the PCAP capture file
    """
    import base64
    import os

    if not os.path.exists(pcap_path):
        return f"ERROR: File not found: {pcap_path}"

    data = open(pcap_path, "rb").read()
    creds = []
    seen = set()

    for link_type, pkt in _iter_packets(data):
        if link_type == 1 and len(pkt) > 14:
            pkt = pkt[14:]
        if len(pkt) < 20:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 20 or pkt[9] != 6:  # TCP only
            continue
        tcp_off = ((pkt[ihl + 12] >> 4) & 0x0F) * 4
        payload = pkt[ihl + tcp_off:]
        if not payload:
            continue

        text = payload.decode("latin-1", errors="ignore")

        # 1. HTTP Basic Auth
        for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
            b64_val = m.group(1)
            try:
                dec = base64.b64decode(b64_val).decode("utf-8", errors="replace")
                entry = f"[HTTP Basic Auth] -> {dec}"
                if entry not in seen:
                    seen.add(entry)
                    creds.append(entry)
            except Exception:
                pass

        # 2. FTP USER / PASS
        for m in re.finditer(r"(?:USER|PASS)\s+([^\r\n]+)", text):
            entry = f"[FTP] -> {m.group(0)}"
            if entry not in seen:
                seen.add(entry)
                creds.append(entry)

        # 3. HTTP Form POST login
        if "POST " in text and ("password=" in text or "pass=" in text or "user=" in text):
            post_body = text.split("\r\n\r\n", 1)[-1][:300].strip()
            if post_body and any(k in post_body for k in ("pass=", "password=", "user=", "token=")):
                entry = f"[HTTP POST Form] -> {post_body}"
                if entry not in seen:
                    seen.add(entry)
                    creds.append(entry)

    if not creds:
        return "No standard plaintext credentials (HTTP Basic, FTP, Form POST) detected in capture."

    return f"Extracted {len(creds)} Credential(s) from PCAP:\n\n" + "\n".join(f"  {c}" for c in creds[:50])


@tool(category="forensics")
def mbr_gpt_analyze(file_path: str) -> str:
    """Inspect Master Boot Record (MBR) partition tables and GUID Partition Table (GPT) disk headers.

    :param file_path: Path to the raw disk / image file
    """
    import os
    import struct

    if not os.path.exists(file_path):
        return f"ERROR: File not found: {file_path}"

    fsize = os.path.getsize(file_path)
    if fsize < 512:
        return "ERROR: File size smaller than 512-byte sector."

    with open(file_path, "rb") as f:
        sector0 = f.read(512)
        sector1 = f.read(512) if fsize >= 1024 else b""

    lines = [
        f"Disk Image: {file_path} ({fsize} bytes / {fsize / (1024*1024):.2f} MB)",
        f"MBR Boot Signature (offset 510): {sector0[510:512].hex().upper()}"
    ]

    # Check MBR Partition Table at 0x1BE (4 entries of 16 bytes)
    PART_TYPES = {
        0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended",
        0x06: "FAT16", 0x07: "NTFS / exFAT", 0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)",
        0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)", 0x82: "Linux Swap",
        0x83: "Linux Native (ext2/ext3/ext4)", 0x8E: "Linux LVM", 0xEE: "GPT Protective MBR",
        0xEF: "EFI System Partition"
    }

    lines.append("\n=== MBR Partition Table ===")
    for i in range(4):
        offset = 0x1BE + i * 16
        entry = sector0[offset:offset+16]
        boot_flag, start_chs, p_type, end_chs, lba_start, num_sectors = struct.unpack("<B3sB3sII", entry)
        if p_type != 0x00 or num_sectors != 0:
            type_name = PART_TYPES.get(p_type, f"Unknown (0x{p_type:02x})")
            boot_str = "BOOTABLE" if boot_flag == 0x80 else "Normal"
            size_mb = (num_sectors * 512) / (1024 * 1024)
            lines.append(
                f"  Partition {i+1}: Type 0x{p_type:02x} ({type_name}) | {boot_str}\n"
                f"    LBA Start   : {lba_start} (byte offset 0x{lba_start * 512:x})\n"
                f"    Sectors     : {num_sectors} ({size_mb:.2f} MB)"
            )

    # Check GPT Signature in Sector 1
    if sector1.startswith(b"EFI PART"):
        lines.append("\n=== GPT Header Detected (Sector 1) ===")
        gpt_sig, gpt_rev, hdr_size, hdr_crc, res, cur_lba, bkp_lba, first_lba, last_lba = struct.unpack("<8sIIIIQQQQ", sector1[:56])
        lines.append(
            f"  GPT Revision : 0x{gpt_rev:08x}\n"
            f"  Current LBA  : {cur_lba}\n"
            f"  First Usable : LBA {first_lba}\n"
            f"  Last Usable  : LBA {last_lba}"
        )

    return "\n".join(lines)


@tool(category="forensics")
def linux_shadow_hash_analyze(shadow_entry: str) -> str:
    """Analyze a Linux /etc/shadow password hash entry, identifying algorithm, salt, rounds, and hash format.

    :param shadow_entry: Full /etc/shadow line or hash string (e.g. 'root:$6$rounds=5000$saltsalt$hash...:19000:0:99999:7:::')
    """
    clean = shadow_entry.strip()
    if ":" in clean:
        parts = clean.split(":")
        user = parts[0]
        hash_part = parts[1]
    else:
        user = "unknown"
        hash_part = clean

    if not hash_part.startswith("$"):
        return f"User: {user}\nPassword field does not contain a standard modular crypt hash (e.g. locked account or plain string): {hash_part}"

    tokens = hash_part.split("$")
    # tokens[0] is empty, tokens[1] is id, tokens[2] is salt/rounds, etc.
    algo_id = tokens[1] if len(tokens) > 1 else ""

    ALGO_NAMES = {
        "1": "MD5-crypt ($1$)",
        "2a": "Bcrypt / Blowfish ($2a$)",
        "2b": "Bcrypt ($2b$)",
        "2y": "Bcrypt ($2y$)",
        "5": "SHA-256 crypt ($5$)",
        "6": "SHA-512 crypt ($6$)",
        "y": "Yescrypt ($y$ - modern Linux standard)",
        "7": "Scrypt ($7$)",
        "argon2id": "Argon2id ($argon2id$)",
        "argon2i": "Argon2i ($argon2i$)",
    }

    algo_desc = ALGO_NAMES.get(algo_id, f"Custom / Unknown algorithm (${algo_id}$)")

    lines = [
        f"Linux /etc/shadow Analysis:",
        f"  User Name  : {user}",
        f"  Algorithm  : {algo_desc}",
        f"  Raw Hash   : {hash_part[:60]}...",
    ]

    # Extract salt and rounds
    if algo_id in ("5", "6"):
        if "rounds=" in tokens[2]:
            rounds = tokens[2].split("=")[1]
            salt = tokens[3] if len(tokens) > 3 else ""
            hash_val = tokens[4] if len(tokens) > 4 else ""
            lines.append(f"  Rounds     : {rounds}")
            lines.append(f"  Salt       : {salt}")
            lines.append(f"  Hash Value : {hash_val[:32]}...")
        else:
            salt = tokens[2] if len(tokens) > 2 else ""
            hash_val = tokens[3] if len(tokens) > 3 else ""
            lines.append(f"  Salt       : {salt}")
            lines.append(f"  Hash Value : {hash_val[:32]}...")

    lines.append("\nCracking guidance (John the Ripper / Hashcat):")
    if algo_id == "6":
        lines.append("  Hashcat mode : -m 1800 (sha512crypt)")
        lines.append("  John format  : sha512crypt")
    elif algo_id == "5":
        lines.append("  Hashcat mode : -m 7400 (sha256crypt)")
    elif algo_id == "1":
        lines.append("  Hashcat mode : -m 500 (md5crypt)")
    elif algo_id.startswith("2"):
        lines.append("  Hashcat mode : -m 3200 (bcrypt)")

    return "\n".join(lines)


@tool(category="forensics")
def linux_history_audit(history_path_or_content: str) -> str:
    """Audit Linux .bash_history or .zsh_history for leaked passwords, API keys, hidden artifacts, and sudo usage.

    :param history_path_or_content: Path to history file or raw multiline history string
    """
    import os
    import re

    if os.path.exists(history_path_or_content):
        content = open(history_path_or_content, "r", errors="ignore").read()
    else:
        content = history_path_or_content

    lines = content.splitlines()
    findings = []

    SUSPICIOUS_PATTERNS = [
        (r"(?:mysql|psql|ssh|curl|wget|sudo)\s+.*-p[^\s]+", "Command with inline password flag (-p)"),
        (r"export\s+[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)=[^\s]+", "Environment variable secret export"),
        (r"echo\s+['\"][A-Za-z0-9+/=]{16,}['\"]\s*\|\s*base64\s+-d", "Decoded base64 payload"),
        (r"flag\{[^}]+\}", "Flag string in command history"),
        (r"chmod\s+[4-7]?[0-7]{3}\s+[^\s]+", "File permissions alteration"),
        (r"(?:scp|rsync|nc|ncat|netcat)\s+.*", "File transfer / network activity"),
        (r"python[23]?\s+-c\s+['\"].*['\"]", "Inline Python script execution"),
        (r"\/tmp\/[^\s]+", "Execution of /tmp directory artifact"),
    ]

    for idx, line in enumerate(lines, 1):
        clean_l = line.strip()
        # zsh history timestamp format : <timestamp>:<duration>;<command>
        if clean_l.startswith(":") and ";" in clean_l:
            clean_l = clean_l.split(";", 1)[1]

        for pattern, desc in SUSPICIOUS_PATTERNS:
            if re.search(pattern, clean_l, re.IGNORECASE):
                findings.append(f"  [Line {idx}] {desc}:\n    → `{clean_l}`")
                break

    if not findings:
        return f"Audited {len(lines)} history line(s). No high-priority sensitive keywords found."

    return f"Linux History Audit ({len(findings)} noteworthy event(s) across {len(lines)} lines):\n\n" + "\n\n".join(findings[:30])


@tool(category="forensics")
def linux_cron_audit(cron_content: str) -> str:
    """Audit Linux /etc/crontab or crontab files, explaining schedule and flagging wildcard or security risks.

    :param cron_content: Content of crontab or path to file
    """
    import os
    if os.path.exists(cron_content):
        content = open(cron_content, "r", errors="ignore").read()
    else:
        content = cron_content

    lines = content.splitlines()
    entries = []

    for idx, l in enumerate(lines, 1):
        l_str = l.strip()
        if not l_str or l_str.startswith("#"):
            continue

        parts = l_str.split()
        if len(parts) >= 5:
            # Check system crontab (minute hour dom month dow user command) vs user crontab (minute hour dom month dow command)
            sched = " ".join(parts[:5])
            rest = parts[5:]

            wildcard_warning = ""
            cmd_full = " ".join(rest)
            if "tar " in cmd_full and "*" in cmd_full:
                wildcard_warning = " ⚠️ WILDCARD INJECTION HAZARD (tar * privilege escalation)"
            elif "rsync " in cmd_full and "*" in cmd_full:
                wildcard_warning = " ⚠️ WILDCARD INJECTION HAZARD (rsync * privilege escalation)"
            elif "/tmp/" in cmd_full:
                wildcard_warning = " ⚠️ SCRIPT RUNS FROM /tmp (writable directory hazard)"

            entries.append(
                f"  Entry #{len(entries)+1} (Line {idx}):\n"
                f"    Schedule: `{sched}`\n"
                f"    Command : `{cmd_full}`{wildcard_warning}"
            )

    if not entries:
        return "No active cron jobs found in content."

    return f"Linux Crontab Audit ({len(entries)} job(s)):\n\n" + "\n\n".join(entries)


@tool(category="forensics")
def linux_wtmp_utmp_parse(path: str, max_records: int = 50) -> str:
    """Parse Linux binary login accounting records (/var/log/wtmp, /var/run/utmp, btmp).

    :param path: Path to the wtmp, utmp, or btmp file
    :param max_records: Max records to return (default 50)
    """
    import os
    import struct
    import time

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    RECORD_SIZE = 384  # Standard 64-bit Linux utmp record size
    data = open(path, "rb").read()
    if len(data) < RECORD_SIZE:
        return f"File size too small for standard Linux utmp/wtmp record ({len(data)} bytes)."

    TYPE_NAMES = {
        0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
        5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"
    }

    records = []
    for offset in range(0, len(data) - RECORD_SIZE + 1, RECORD_SIZE):
        chunk = data[offset:offset+RECORD_SIZE]
        ut_type, ut_pid = struct.unpack("<hi", chunk[:6])
        ut_line = chunk[8:40].decode("latin-1", errors="ignore").rstrip("\x00")
        ut_id = chunk[40:44].decode("latin-1", errors="ignore").rstrip("\x00")
        ut_user = chunk[44:76].decode("latin-1", errors="ignore").rstrip("\x00")
        ut_host = chunk[76:332].decode("latin-1", errors="ignore").rstrip("\x00")
        tv_sec, tv_usec = struct.unpack("<ii", chunk[336:344])

        if ut_user or ut_host or ut_type in (2, 7):
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(tv_sec)) if tv_sec > 0 else "N/A"
            type_str = TYPE_NAMES.get(ut_type, f"Type_{ut_type}")
            records.append(f"  [{t_str} UTC] {type_str:<12} | User: {ut_user:<12} | Line: {ut_line:<8} | Host/IP: {ut_host or 'local'}")

    if not records:
        return "No valid login records decoded from file."

    return f"Parsed {len(records)} Linux Login Record(s) from {path}:\n\n" + "\n".join(records[-max_records:])


@tool(category="forensics")
def linux_core_dump_strings(core_path: str, min_len: int = 4) -> str:
    """Analyze a Linux ELF core dump file (core.<pid>) to extract heap/stack memory strings and flag candidates.

    :param core_path: Path to the core dump file
    :param min_len: Minimum string length (default 4)
    """
    import os
    import re

    if not os.path.exists(core_path):
        return f"ERROR: File not found: {core_path}"

    data = open(core_path, "rb").read()
    if not data.startswith(b"\x7fELF"):
        return f"ERROR: File does not appear to be an ELF core dump (magic: {data[:4].hex()})"

    # Extract printable ASCII and UTF-8 strings
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    matches = [m.group(0).decode("latin-1", errors="ignore") for m in re.finditer(pattern, data)]

    flags = [s for s in matches if "flag{" in s.lower() or "ctf{" in s.lower() or "secret" in s.lower()]

    lines = [
        f"Linux Core Dump Analysis: {core_path} ({len(data)} bytes)",
        f"Total Strings Extracted : {len(matches)}",
        f"High Priority Candidates: {len(flags)}",
    ]
    if flags:
        lines.append("\n🚩 Flag / Secret Matches in Memory:")
        for fl in dict.fromkeys(flags)[:20]:
            lines.append(f"  → {fl}")

    return "\n".join(lines)


@tool(category="forensics")
def gzip_timestamp_extract(path: str) -> str:
    """Extract creation timestamp, original filename, extra flags, and OS identifier from GZIP (.gz) header.

    :param path: Path to the .gz file
    """
    import os
    import struct
    import time

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read(1024)
    if len(data) < 10 or data[:2] != b"\x1f\x8b":
        return "ERROR: File is not a valid GZIP archive (magic mismatch)."

    cm = data[2]
    flags = data[3]
    mtime, xfl, os_id = struct.unpack("<IBB", data[4:10])

    OS_NAMES = {
        0: "FAT (MS-DOS/OS/2/NT)", 1: "Amiga", 2: "VMS", 3: "Unix / Linux",
        4: "VM/CMS", 5: "Atari TOS", 6: "HPFS (OS/2)", 7: "Macintosh",
        8: "Z-System", 9: "CP/M", 10: "TOPS-20", 11: "NTFS", 12: "QDOS", 13: "Acorn RISCOS", 255: "Unknown"
    }

    t_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(mtime)) if mtime > 0 else "Timestamp not set"

    lines = [
        f"GZIP Archive Header Analysis for {path}:",
        f"  Compression Method : Deflate ({cm})" if cm == 8 else f"  Compression Method : {cm}",
        f"  Header Timestamp   : {mtime} ({t_str})",
        f"  Operating System   : {OS_NAMES.get(os_id, f'OS_{os_id}')}",
        f"  Header Flags (0x{flags:02x}) : "
    ]

    idx = 10
    if flags & 0x04:  # FEXTRA
        lines.append("    • FEXTRA present")
        if len(data) >= idx + 2:
            xlen = struct.unpack("<H", data[idx:idx+2])[0]
            idx += 2 + xlen
    if flags & 0x08:  # FNAME (original filename)
        null_idx = data.find(b"\x00", idx)
        if null_idx != -1:
            orig_name = data[idx:null_idx].decode("latin-1", errors="replace")
            lines.append(f"    • Original Filename (FNAME): '{orig_name}' 📁")
            idx = null_idx + 1
    if flags & 0x10:  # FCOMMENT
        null_idx = data.find(b"\x00", idx)
        if null_idx != -1:
            comment = data[idx:null_idx].decode("latin-1", errors="replace")
            lines.append(f"    • Comment (FCOMMENT): '{comment}' 💬")
    if flags & 0x02:  # FHCRC
        lines.append("    • Header CRC16 present")

    return "\n".join(lines)


@tool(category="forensics")
def tar_header_analyze(path: str) -> str:
    """Analyze POSIX USTAR / GNU tar archive 512-byte header blocks, listing permissions, timestamps, and files.

    :param path: Path to the .tar file
    """
    import os
    import struct
    import time

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read()
    if len(data) < 512:
        return "ERROR: File size smaller than 512-byte tar block."

    TYPE_MAP = {
        b"0": "Regular file", b"\x00": "Regular file", b"1": "Hard link",
        b"2": "Symbolic link", b"3": "Char device", b"4": "Block device",
        b"5": "Directory", b"6": "FIFO / pipe", b"7": "Contiguous file",
        b"g": "PAX global header", b"x": "PAX extended header"
    }

    entries = []
    offset = 0
    while offset + 512 <= len(data):
        block = data[offset:offset+512]
        if block == b"\x00" * 512:
            break

        name = block[:100].decode("latin-1", errors="replace").rstrip("\x00")
        mode_str = block[100:108].decode("latin-1", errors="ignore").strip("\x00 ")
        uid_str = block[108:116].decode("latin-1", errors="ignore").strip("\x00 ")
        gid_str = block[116:124].decode("latin-1", errors="ignore").strip("\x00 ")
        size_str = block[124:136].decode("latin-1", errors="ignore").strip("\x00 ")
        mtime_str = block[136:148].decode("latin-1", errors="ignore").strip("\x00 ")
        typeflag = block[156:157]
        magic = block[257:263].decode("latin-1", errors="ignore").rstrip("\x00")

        try:
            size = int(size_str, 8) if size_str else 0
        except ValueError:
            size = 0

        try:
            mtime = int(mtime_str, 8) if mtime_str else 0
            t_formatted = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(mtime))
        except ValueError:
            t_formatted = "N/A"

        ftype = TYPE_MAP.get(typeflag, f"Type_{typeflag}")
        entries.append(
            f"  • {name:<32} | {ftype:<14} | Size: {size:<8} bytes | Mtime: {t_formatted} | Mode: 0{mode_str}"
        )

        # Advance by header + aligned file blocks
        file_blocks = (size + 511) // 512
        offset += 512 * (1 + file_blocks)

    if not entries:
        return "No valid tar headers parsed from file."

    return f"TAR Archive Header Inspection ({len(entries)} entry/entries):\n\n" + "\n".join(entries[:50])


@tool(category="forensics")
def png_ancillary_chunks(path: str) -> str:
    """Inspect all ancillary PNG chunks (tEXt, zTXt, iTXt, pHYs, tIME, eXIf, bKGD, etc.) for hidden forensic data.

    :param path: Path to the PNG image file
    """
    import os
    import struct
    import zlib

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "ERROR: File is not a valid PNG image."

    chunks = []
    offset = 8
    while offset + 8 <= len(data):
        length = struct.unpack(">I", data[offset:offset+4])[0]
        ctype = data[offset+4:offset+8].decode("latin-1", errors="replace")
        cdata = data[offset+8:offset+8+length]
        crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0] if offset+12+length <= len(data) else 0

        info = f"  Chunk [{ctype}] ({length} bytes) @ offset 0x{offset:x}"

        # Detailed payload parsing for text and metadata chunks
        if ctype == "tEXt":
            if b"\x00" in cdata:
                k, v = cdata.split(b"\x00", 1)
                info += f" -> Keyword: '{k.decode('latin-1', 'replace')}' | Text: '{v.decode('latin-1', 'replace')}'"
        elif ctype == "zTXt":
            if b"\x00" in cdata:
                k, rest = cdata.split(b"\x00", 1)
                if len(rest) > 1:
                    cm = rest[0]
                    try:
                        decomp = zlib.decompress(rest[1:]).decode("latin-1", "replace")
                        info += f" -> Keyword: '{k.decode('latin-1', 'replace')}' | Decompressed zTXt: '{decomp}'"
                    except Exception:
                        pass
        elif ctype == "tIME" and length == 7:
            y, m, d, h, mi, s = struct.unpack(">HBBBBB", cdata)
            info += f" -> Timestamp: {y}-{m:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d} UTC"

        chunks.append(info)
        offset += 12 + length

    return f"PNG Chunks Analysis for {path} ({len(chunks)} chunks):\n\n" + "\n".join(chunks)


@tool(category="forensics")
def wav_header_analyze(path: str) -> str:
    """Analyze RIFF WAV audio container header chunks (fmt, data, cue, LIST, INFO) and format properties.

    :param path: Path to the WAV audio file
    """
    import os
    import struct

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read(4096)
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return "ERROR: File is not a valid RIFF/WAVE audio file."

    riff_size = struct.unpack("<I", data[4:8])[0]
    lines = [
        f"RIFF/WAVE Audio Header Analysis: {path}",
        f"  Total File Payload Size: {riff_size + 8} bytes",
        f"\nChunks in Header:"
    ]

    offset = 12
    while offset + 8 <= len(data):
        chunk_id = data[offset:offset+4].decode("latin-1", errors="replace")
        chunk_size = struct.unpack("<I", data[offset+4:offset+8])[0]
        cdata = data[offset+8:offset+8+chunk_size]

        info = f"  • Chunk '{chunk_id}' ({chunk_size} bytes) @ offset 0x{offset:x}"
        if chunk_id == "fmt " and len(cdata) >= 16:
            a_fmt, channels, s_rate, b_rate, block_align, bits_sample = struct.unpack("<HHIIHH", cdata[:16])
            FMT_NAMES = {1: "PCM (Uncompressed)", 3: "IEEE Float", 6: "A-law", 7: "u-law"}
            info += (
                f"\n      Format      : {FMT_NAMES.get(a_fmt, f'Format_{a_fmt}')}\n"
                f"      Channels    : {channels} ({'Mono' if channels == 1 else 'Stereo'})\n"
                f"      Sample Rate : {s_rate} Hz\n"
                f"      Bit Depth   : {bits_sample}-bit ({block_align} bytes/frame)"
            )
        elif chunk_id == "data":
            info += f" -> Main audio sample buffer ({chunk_size} bytes)"

        lines.append(info)
        offset += 8 + ((chunk_size + 1) & ~1)  # 2-byte word aligned

    return "\n".join(lines)
