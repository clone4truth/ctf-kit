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
    """Parse PCAP / PCAPNG files and extract HTTP payloads & printable text per TCP stream."""
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
    """Extract DNS query subdomains from PCAP/PCAPNG to recover exfiltrated flags or data."""
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
    """Parse USB HID keyboard packets in PCAP/PCAPNG to reconstruct typed text and flags."""
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
    """Detect and fix pseudo-encrypted ZIP archives (clears the fake encryption bit 0x0001)."""
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
    """Extract EXIF GPS coordinates from an image and generate decimal Lat/Long and Maps links."""
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