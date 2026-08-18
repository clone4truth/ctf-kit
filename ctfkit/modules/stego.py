"""Steganography: LSB/MSB bit-plane, metadata/EXIF, channel isolation, image XOR, PNG chunk dump, GIF frames."""

import os

from ..registry import tool
from ..utils import printable


@tool(category="stego")
def stego_lsb(image_path: str, plane: str = "lsb", channel: str = "rgb", bit_order: str = "lsb-first", max_bytes: int = 0) -> str:
    """Extract data from a bit plane. plane: lsb/msb. channel: rgb/rgba/g (grayscale). bit_order: lsb-first/msb-first."""
    from PIL import Image
    img = Image.open(image_path)
    if channel == "g":
        img = img.convert("L")
    else:
        img = img.convert("RGB" if channel == "rgb" else "RGBA")
    pixels = list(img.getdata())
    bits = []
    for px in pixels:
        vals = px if isinstance(px, tuple) else (px,)
        for v in vals:
            bits.append((v >> 0 if plane == "lsb" else v >> 7) & 1)
    if bit_order == "msb-first":
        chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
        bits = []
        for c in chunks:
            bits.extend(reversed(c))
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    if max_bytes:
        out = out[:max_bytes]
    return f"total {len(out)} bytes ({len(bits)} bits available)\nhex (first 300): {out[:300].hex()}\nascii (first 300): {printable(out, 300)}"


@tool(category="stego")
def stego_metadata(image_path: str) -> str:
    """Extract metadata: PNG text chunks (tEXt/zTXt/iTXt), EXIF, and basic info."""
    from PIL import Image, ExifTags
    img = Image.open(image_path)
    res = [f"format: {img.format} | size: {img.size} | mode: {img.mode}"]
    for k, v in (img.info or {}).items():
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8", "replace")
            except Exception:
                v = v.hex()
        res.append(f"[info] {k}: {v}")
    try:
        exif = img.getexif()
        for tag_id, val in exif.items():
            name = ExifTags.TAGS.get(tag_id, tag_id)
            res.append(f"[exif] {name}: {val}")
    except Exception as ex:
        res.append(f"[exif] error: {ex}")
    return "\n".join(res)


@tool(category="stego")
def stego_channel(image_path: str, channel: str = "R", out_path: str = "channel.png") -> str:
    """Isolate one color channel (R/G/B/A) into a grayscale image. Saved to out_path."""
    from PIL import Image
    idx = {"R": 0, "G": 1, "B": 2, "A": 3}[channel.upper()]
    img = Image.open(image_path).convert("RGBA")
    w, h = img.size
    out = Image.new("L", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            out.putpixel((x, y), px[x, y][idx])
    out.save(out_path)
    return f"Channel {channel.upper()} saved to {out_path} ({w}x{h})."


@tool(category="stego")
def stego_xor_images(path_a: str, path_b: str, out_path: str = "xor_result.png") -> str:
    """XOR two images (pixel-wise). Result saved to out_path. For spotting near-identical images."""
    from PIL import Image
    a = Image.open(path_a).convert("RGB")
    b = Image.open(path_b).convert("RGB")
    if a.size != b.size:
        return f"Sizes differ: {a.size} vs {b.size}. Resize first."
    w, h = a.size
    out = Image.new("RGB", (w, h))
    pa, pb = a.load(), b.load()
    for y in range(h):
        for x in range(w):
            ra, ga, ba = pa[x, y]
            rb, gb, bb = pb[x, y]
            out.putpixel((x, y), (ra ^ rb, ga ^ gb, ba ^ bb))
    out.save(out_path)
    return f"XOR result saved to {out_path} ({w}x{h})."


@tool(category="stego")
def stego_png_chunks(image_path: str) -> str:
    """Dump all PNG chunks (type, length, data preview). For finding hidden chunks or odd IDATs."""
    data = open(image_path, "rb").read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "Not a PNG."
    pos = 8
    res = [f"PNG signature ok, total {len(data)} bytes"]
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8].decode("latin-1")
        if pos + 12 + length > len(data):
            res.append(f"@{pos:08x} TRUNCATED CHUNK: {ctype} len={length}")
            break
        chunk = data[pos + 8:pos + 8 + length]
        extra = ""
        if ctype in ("tEXt", "zTXt", "iTXt"):
            try:
                extra = f" -> {chunk[:100].decode('utf-8', 'replace')}"
            except Exception:
                pass
        res.append(f"@{pos:08x} {ctype:<5} len={length:>8}{extra}")
        pos += 12 + length
    return "\n".join(res)


@tool(category="stego")
def stego_gif_frames(gif_path: str, out_dir: str = "gif_frames") -> str:
    """Extract every GIF frame to PNG. Flags often hide in a single frame."""
    from PIL import Image
    img = Image.open(gif_path)
    os.makedirs(out_dir, exist_ok=True)
    saved = []
    n = getattr(img, "n_frames", 1)
    for i in range(n):
        img.seek(i)
        fn = os.path.join(out_dir, f"frame_{i:03d}.png")
        img.save(fn)
        saved.append(fn)
    return f"{n} frames extracted:\n" + "\n".join(saved)


@tool(category="stego")
def stego_compare(path_a: str, path_b: str) -> str:
    """Compare two images: list coordinates of differing pixels (for visual stego)."""
    from PIL import Image
    a = Image.open(path_a).convert("RGB")
    b = Image.open(path_b).convert("RGB")
    if a.size != b.size:
        return f"Sizes differ: {a.size} vs {b.size}."
    pa, pb = a.load(), b.load()
    diffs = []
    w, h = a.size
    for y in range(h):
        for x in range(w):
            if pa[x, y] != pb[x, y]:
                diffs.append((x, y, pa[x, y], pb[x, y]))
    if not diffs:
        return "Identical (no differing pixels)."
    out = [f"{len(diffs)} pixels differ ({100*len(diffs)/(w*h):.2f}%)"]
    for x, y, va, vb in diffs[:50]:
        out.append(f"({x},{y}): {va} -> {vb}")
    if len(diffs) > 50:
        out.append(f"... and {len(diffs)-50} more.")
    return "\n".join(out)