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
    idx = {"R": 0, "G": 1, "B": 2, "A": 3}
    ch = channel.upper()
    if ch not in idx and len(ch) > 1:
        ch = ch[0]
    img = Image.open(image_path).convert("RGBA")
    w, h = img.size
    out = Image.new("L", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            out.putpixel((x, y), px[x, y][idx[ch]])
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


@tool(category="stego")
def png_fix_ihdr(image_path: str, out_path: str = "") -> str:
    """Fix PNG image dimensions by brute-forcing width/height matching the IHDR chunk CRC32."""
    import struct
    import zlib
    
    data = open(image_path, "rb").read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "Not a valid PNG file."
    
    if len(data) < 33 or data[12:16] != b"IHDR":
        return "Cannot find IHDR chunk at expected offset 12."
    
    curr_w, curr_h = struct.unpack(">II", data[16:24])
    rest_ihdr = data[24:29]  # bit_depth, color_type, compression, filter, interlace
    expected_crc = struct.unpack(">I", data[29:33])[0]
    curr_crc = zlib.crc32(data[12:29]) & 0xFFFFFFFF
    
    if curr_crc == expected_crc:
        return f"IHDR CRC32 is already valid: 0x{expected_crc:08x} (Width: {curr_w}, Height: {curr_h})."
    
    # Brute-force dimensions
    found = None
    # First search assuming width is correct and height was cropped (most common CTF trick)
    for h in range(1, 4096):
        test_payload = b"IHDR" + struct.pack(">II", curr_w, h) + rest_ihdr
        if (zlib.crc32(test_payload) & 0xFFFFFFFF) == expected_crc:
            found = (curr_w, h)
            break
            
    # If not found, search both width and height
    if not found:
        for w in range(1, 2048):
            for h in range(1, 2048):
                test_payload = b"IHDR" + struct.pack(">II", w, h) + rest_ihdr
                if (zlib.crc32(test_payload) & 0xFFFFFFFF) == expected_crc:
                    found = (w, h)
                    break
            if found:
                break
                
    if not found:
        return f"Could not find dimensions matching CRC 0x{expected_crc:08x} (Current CRC: 0x{curr_crc:08x})."
    
    w_new, h_new = found
    fixed_data = data[:16] + struct.pack(">II", w_new, h_new) + data[24:]
    
    dest = out_path or (os.path.splitext(image_path)[0] + "_fixed.png")
    with open(dest, "wb") as f:
        f.write(fixed_data)
        
    return (f"🏆 PNG IHDR Dimensions Successfully Recovered!\n"
            f"Original Dimensions : {curr_w} x {curr_h} (CRC mismatch: 0x{curr_crc:08x})\n"
            f"Recovered Dimensions: {w_new} x {h_new} (CRC valid: 0x{expected_crc:08x})\n"
            f"Saved fixed PNG to  : {dest}")


@tool(category="stego")
def stego_audio_wav(wav_path: str, bit_plane: int = 0, max_bytes: int = 500) -> str:
    """Extract LSB steganography data from uncompressed WAV audio files."""
    import wave
    try:
        with wave.open(wav_path, "rb") as wf:
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            framerate = wf.getframerate()
            n_frames = wf.getnframes()
            frames = wf.readframes(min(n_frames, 2000000))
    except Exception as ex:
        return f"Failed to open WAV audio file: {ex}"
    
    # Extract samples
    bits = []
    if sampwidth == 1:
        # 8-bit unsigned
        for b in frames:
            bits.append((b >> bit_plane) & 1)
    elif sampwidth == 2:
        # 16-bit signed
        import struct
        samples = struct.unpack(f"<{len(frames)//2}h", frames)
        for s in samples:
            bits.append((s >> bit_plane) & 1)
    else:
        return f"Unsupported sample width: {sampwidth * 8}-bit. Supported: 8-bit or 16-bit PCM."
        
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
        if max_bytes and len(out) >= max_bytes:
            break
            
    return (f"WAV Audio Stego Extracted:\n"
            f"Channels: {n_channels} | Rate: {framerate} Hz | Depth: {sampwidth*8}-bit | Bit-Plane: {bit_plane}\n"
            f"Extracted {len(out)} bytes:\n"
            f"hex: {out[:200].hex()}\n"
            f"ascii: {printable(out, 300)}")


@tool(category="stego")
def stego_dtmf_detect(wav_path: str) -> str:
    """Decode DTMF (Dual-Tone Multi-Frequency) phone dial keypad tones from a WAV audio file."""
    import wave
    import math
    import struct
    
    try:
        with wave.open(wav_path, "rb") as wf:
            sampwidth = wf.getsampwidth()
            framerate = wf.getframerate()
            frames = wf.readframes(wf.getnframes())
    except Exception as ex:
        return f"Failed to open WAV: {ex}"
    
    if sampwidth == 1:
        samples = [b - 128 for b in frames]
    elif sampwidth == 2:
        samples = list(struct.unpack(f"<{len(frames)//2}h", frames))
    else:
        return f"Unsupported audio bit depth: {sampwidth * 8}-bit."
        
    low_freqs = [697, 770, 852, 941]
    high_freqs = [1209, 1336, 1477, 1633]
    dtmf_map = {
        (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
        (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
        (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
        (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
    }
    
    def goertzel(samples_chunk, target_freq, sample_rate):
        n = len(samples_chunk)
        k = int(0.5 + (n * target_freq) / sample_rate)
        omega = (2.0 * math.pi * k) / n
        coeff = 2.0 * math.cos(omega)
        q0 = q1 = q2 = 0.0
        for s in samples_chunk:
            q0 = coeff * q1 - q2 + s
            q2 = q1
            q1 = q0
        return q1 * q1 + q2 * q2 - coeff * q1 * q2
    
    chunk_size = int(framerate * 0.04)  # 40ms window
    decoded = []
    last_char = None
    
    for i in range(0, len(samples) - chunk_size, chunk_size):
        chunk = samples[i:i + chunk_size]
        # Energy threshold
        energy = sum(s * s for s in chunk) / max(len(chunk), 1)
        if energy < 100000:
            last_char = None
            continue
            
        best_low = max(low_freqs, key=lambda f: goertzel(chunk, f, framerate))
        best_high = max(high_freqs, key=lambda f: goertzel(chunk, f, framerate))
        
        char = dtmf_map.get((best_low, best_high))
        if char:
            if char != last_char:
                decoded.append(char)
                last_char = char
        else:
            last_char = None
            
    res = "".join(decoded)
    return f"DTMF Keypad Sequence: {res or 'No clear DTMF tones detected.'}"