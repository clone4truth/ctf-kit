"""Steganography: LSB/MSB bit-plane, metadata/EXIF, channel isolation, image XOR, PNG chunk dump, GIF frames."""

import math
import os

from ..registry import tool
from ..utils import printable

_ZIGZAG = (
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
)


class _BitReader:
    """MSB-first JPEG bit reader over an entropy-coded segment."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.acc = 0
        self.nbits = 0
        self.restart = False

    def read(self, n: int) -> int:
        while self.nbits < n:
            if self.pos >= len(self.data):
                self.acc = (self.acc << 8) | 0xFF
                self.nbits += 8
                continue
            byte = self.data[self.pos]
            self.pos += 1
            if byte == 0xFF:
                nxt = self.data[self.pos] if self.pos < len(self.data) else 0
                if nxt == 0x00:
                    self.pos += 1  # byte stuffing
                elif 0xD0 <= nxt <= 0xD7:
                    self.pos += 1
                    self.acc = 0
                    self.nbits = 0
                    self.restart = True
                    continue
                # other markers mid-scan: leave for caller (end of segment)
            self.acc = (self.acc << 8) | byte
            self.nbits += 8
        self.nbits -= n
        return (self.acc >> self.nbits) & ((1 << n) - 1)


def _build_huff(counts: bytes, symbols: bytes) -> dict:
    """Canonical JPEG Huffman table: {(code, length): symbol}."""
    table = {}
    code = 0
    k = 0
    for i in range(16):
        for _ in range(counts[i]):
            table[(code, i + 1)] = symbols[k]
            k += 1
            code += 1
        code <<= 1
    return table


def _huff_decode(reader: _BitReader, table: dict) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | reader.read(1)
        sym = table.get((code, length))
        if sym is not None:
            return sym
    return -1


def _extend(value: int, size: int) -> int:
    if size and value < (1 << (size - 1)):
        value -= (1 << size) - 1
    return value


def _jpeg_coefficients(data: bytes) -> list:
    """Decode quantized DCT coefficients (baseline sequential JPEG, 8-bit).
    Returns list of (component_index, zigzag_coeffs[64]) per block, in MCU order,
    with DC prediction applied and coefficient values EXACT (from the bitstream).
    Raises ValueError on unsupported formats (progressive, 12-bit, lossless)."""
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("not a JPEG (missing SOI)")
    pos = 2
    quant_tables = {}
    huff = {}
    width = height = 0
    comps = []
    restart_interval = 0
    while pos < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:  # SOS: start of scan
            break
        seg_len = (data[pos + 2] << 8) | data[pos + 3]
        body = data[pos + 4:pos + 2 + seg_len]
        if marker == 0xDB:  # DQT
            i = 0
            while i < len(body):
                pq_tq = body[i]
                i += 1
                zig = list(body[i:i + 64])
                i += 64
                if pq_tq >> 4:  # 16-bit tables unsupported
                    raise ValueError("16-bit quantization table unsupported")
                flat = [0] * 64
                for z, v in zip(_ZIGZAG, zig):
                    flat[z] = v
                quant_tables[pq_tq & 0x0F] = flat
        elif marker == 0xC4:  # DHT
            i = 0
            while i < len(body):
                tc_th = body[i]
                i += 1
                counts = body[i:i + 16]
                i += 16
                n = sum(counts)
                syms = body[i:i + n]
                i += n
                huff[(tc_th >> 4, tc_th & 0x0F)] = _build_huff(counts, syms)
        elif marker == 0xC0:  # SOF0 baseline
            if body[0] != 8:
                raise ValueError("only 8-bit baseline JPEG supported")
            height = (body[1] << 8) | body[2]
            width = (body[3] << 8) | body[4]
            ncomp = body[5]
            j = 6
            for _ in range(ncomp):
                cid = body[j]
                h, v = body[j + 1] >> 4, body[j + 1] & 0x0F
                tq = body[j + 2]
                comps.append({"id": cid, "h": h, "v": v, "tq": tq})
                j += 3
        elif marker == 0xDD:  # DRI
            restart_interval = (body[0] << 8) | body[1]
        elif 0xC1 <= marker <= 0xCF or marker in (0xD9, 0xDC, 0xDE, 0xDF):
            if marker in (0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                raise ValueError("only baseline sequential JPEG supported (found marker 0x%02X)" % marker)
        pos += 2 + seg_len
    if pos >= len(data) or data[pos] != 0xFF or data[pos + 1] != 0xDA:
        raise ValueError("no SOS found")
    seg_len = (data[pos + 2] << 8) | data[pos + 3]
    sos = data[pos + 4:pos + 2 + seg_len]
    ncomp = sos[0]
    scan = {}
    j = 1
    for _ in range(ncomp):
        cid = sos[j]
        tdc, tac = sos[j + 1] >> 4, sos[j + 1] & 0x0F
        scan[cid] = (tdc, tac)
        j += 2
    ss, se, ah_al = sos[j], sos[j + 1], sos[j + 2]
    if ss != 0 or se != 63 or ah_al != 0:
        raise ValueError("only full spectral selection (Ss=0, Se=63) supported")
    scan_start = pos + 2 + seg_len
    entropy = data[scan_start:]
    # trim at EOI, keep stuffing bytes
    eoi = entropy.find(b"\xff\xd9")
    if eoi != -1:
        entropy = entropy[:eoi]
    reader = _BitReader(entropy)
    max_h = max((c["h"] for c in comps), default=1)
    max_v = max((c["v"] for c in comps), default=1)
    mcu_w = (width + 8 * max_h - 1) // (8 * max_h)
    mcu_h = (height + 8 * max_v - 1) // (8 * max_v)
    total_mcus = mcu_w * mcu_h
    blocks = []
    pred = {cid: 0 for cid in scan}
    mcu_count = 0
    for mcu in range(total_mcus):
        if restart_interval and mcu_count == restart_interval:
            mcu_count = 0
            for cid in pred:
                pred[cid] = 0
        for comp in comps:
            if comp["id"] not in scan:
                continue
            tdc, tac = scan[comp["id"]]
            dc_tab = huff.get((0, tdc))
            ac_tab = huff.get((1, tac))
            if dc_tab is None or ac_tab is None:
                raise ValueError("missing Huffman table")
            for _ in range(comp["h"] * comp["v"]):
                coeffs = [0] * 64
                dc_cat = _huff_decode(reader, dc_tab)
                if dc_cat < 0:
                    raise ValueError("bad DC Huffman code")
                if dc_cat:
                    coeffs[0] = pred[comp["id"]] + _extend(reader.read(dc_cat), dc_cat)
                else:
                    coeffs[0] = pred[comp["id"]]
                pred[comp["id"]] = coeffs[0]
                k = 1
                while k < 64:
                    rs = _huff_decode(reader, ac_tab)
                    if rs < 0:
                        raise ValueError("bad AC Huffman code")
                    if rs == 0x00:  # EOB
                        break
                    run, size = rs >> 4, rs & 0x0F
                    if run == 15 and size == 0:  # ZRL
                        k += 16
                        continue
                    k += run
                    if k < 64:
                        coeffs[k] = _extend(reader.read(size), size)
                        k += 1
                blocks.append((comp["id"], coeffs))
        mcu_count += 1
    return blocks


@tool(category="stego")
def stego_lsb(image_path: str, plane: str = "lsb", channel: str = "rgb", bit_order: str = "lsb-first", max_bytes: int = 0) -> str:
    """Extract data from a bit plane. plane: lsb/msb. channel: rgb/rgba/g (grayscale). bit_order: lsb-first/msb-first.
    :param channel: color channel (R/G/B/A)
    :param max_bytes: max bytes
    :param bit_order: bit order
    :param image_path: path to the image file
    :param plane: plane
    """
    from PIL import Image
    img = Image.open(image_path)
    if channel == "g":
        img = img.convert("L")
        raw = img.tobytes()          # 1 byte/pixel
    else:
        img = img.convert("RGB" if channel == "rgb" else "RGBA")
        raw = img.tobytes()          # contiguous R,G,B(,A) values — same order as getdata()
    plane_bit = 0 if plane == "lsb" else 7
    bits = [(v >> plane_bit) & 1 for v in raw]
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
    """Extract metadata: PNG text chunks (tEXt/zTXt/iTXt), EXIF, and basic info.
    :param image_path: path to the image file
    """
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
    """Isolate one color channel (R/G/B/A) into a grayscale image. Saved to out_path.
    :param out_path: output file path
    :param channel: color channel (R/G/B/A)
    :param image_path: path to the image file
    """
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
    """XOR two images (pixel-wise). Result saved to out_path. For spotting near-identical images.
    :param path_a: path a
    :param path_b: path b
    :param out_path: output file path
    """
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
    """Dump all PNG chunks (type, length, data preview). For finding hidden chunks or odd IDATs.
    :param image_path: path to the image file
    """
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
    """Extract every GIF frame to PNG. Flags often hide in a single frame.
    :param out_dir: output directory
    :param gif_path: path to the GIF file
    """
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
    """Compare two images: list coordinates of differing pixels (for visual stego).
    :param path_a: path a
    :param path_b: path b
    """
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
    """Fix PNG image dimensions by brute-forcing width/height matching the IHDR chunk CRC32.
    :param out_path: output file path
    :param image_path: path to the image file
    """
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
    """Extract LSB steganography data from uncompressed WAV audio files.
    :param max_bytes: max bytes
    :param bit_plane: bit plane
    :param wav_path: path to the WAV file
    """
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
    """Decode DTMF (Dual-Tone Multi-Frequency) phone dial keypad tones from a WAV audio file.
    :param wav_path: path to the WAV file
    """
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


@tool(category="stego")
def stego_jsteg(image_path: str, max_bytes: int = 512) -> str:
    """Extract JSteg hidden data from a JPEG: LSBs of quantized DCT AC coefficients (luma plane, zigzag order, JSteg skip rule). Decodes the JPEG bitstream directly — exact coefficients.

    :param image_path: path to the JPEG file
    :param max_bytes: max bytes to extract
    """
    try:
        with open(image_path, "rb") as f:
            data = f.read()
    except OSError as ex:
        return f"ERROR: {ex}"
    try:
        blocks = _jpeg_coefficients(data)
    except ValueError as ex:
        return f"ERROR: {ex}"
    bits = []
    for cid, coeffs in blocks:
        if cid != 1:  # component 1 = luma (JPEG component numbering starts at 1)
            continue
        for c in coeffs[1:]:  # AC only, zigzag order (entropy order = zigzag)
            if abs(c) <= 1:
                continue
            bits.append(c & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    if max_bytes:
        out = out[:max_bytes]
    text = printable(bytes(out), 400)
    has_flag = "flag{" in text.lower() or "ctf{" in text.lower()
    return (f"total {len(out)} bytes ({len(bits)} usable coefficients)\n"
            f"hex (first 400): {bytes(out[:400]).hex()}\n"
            f"ascii (first 400): {text}"
            + ("\n[!] Looks like embedded data (flag pattern found)" if has_flag else ""))


@tool(category="stego")
def stego_audio_spectrogram(wav_path: str, out_img_path: str = "") -> str:
    """Generate audio spectrogram image using SoX or native FFT to reveal visual text hidden in audio frequencies.

    :param wav_path: Path to the WAV audio file
    :param out_img_path: Path to save the spectrogram PNG (default: <wav_name>_spectrogram.png)
    """
    import os
    import shutil
    import subprocess

    if not os.path.exists(wav_path):
        return f"ERROR: File not found: {wav_path}"

    dest = out_img_path or (os.path.splitext(wav_path)[0] + "_spectrogram.png")

    sox_bin = shutil.which("sox")
    if sox_bin:
        cmd = [sox_bin, wav_path, "-n", "spectrogram", "-o", dest]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(dest):
            return (
                f"🏆 Spectrogram image successfully generated!\n"
                f"Saved to: {dest} ({os.path.getsize(dest)} bytes)\n"
                f"Open or view this image with view_file to read visual text embedded in audio."
            )
        else:
            return f"SoX execution failed: {res.stderr}"
    else:
        return "SoX utility not installed. Install sox or use external spectrogram viewer."


@tool(category="stego")
def stego_audio_morse(wav_path: str, threshold: float = 0.25) -> str:
    """Automatically detect tone bursts in a WAV file and decode Morse code to plaintext.

    :param wav_path: Path to the WAV audio file
    :param threshold: Energy threshold ratio for tone detection (default 0.25)
    """
    import struct
    import wave

    try:
        with wave.open(wav_path, "rb") as wf:
            n_ch = wf.getnchannels()
            width = wf.getsampwidth()
            fr = wf.getframerate()
            n_frames = wf.getnframes()
            raw = wf.readframes(n_frames)
    except Exception as ex:
        return f"ERROR: Failed to open WAV: {ex}"

    fmt = f"<{n_frames * n_ch}h" if width == 2 else f"<{n_frames * n_ch}B"
    samples = list(struct.unpack(fmt, raw))
    if n_ch == 2:
        samples = samples[::2]

    abs_s = [abs(x) for x in samples]
    max_v = max(abs_s) if abs_s else 0
    if max_v == 0:
        return "Audio is completely silent."

    thresh = max_v * threshold
    win = int(fr * 0.01)
    step = int(fr * 0.005)
    dt = 0.005

    states = []
    for i in range(0, len(samples) - win, step):
        w_max = max(abs_s[i:i+win])
        states.append(1 if w_max > thresh else 0)

    rle = []
    if not states:
        return "Audio too short."
    cur = states[0]
    count = 0
    for s in states:
        if s == cur:
            count += 1
        else:
            rle.append((cur, count * dt))
            cur = s
            count = 1
    rle.append((cur, count * dt))

    cleaned = [(s, d) for s, d in rle if d >= 0.015]
    tones = [d for s, d in cleaned if s == 1]
    if len(tones) < 3:
        return "No repeated tone bursts detected in audio."

    med_tone = sorted(tones)[len(tones)//2]
    tone_thresh = med_tone * 1.5

    morse_symbols = []
    for s, d in cleaned:
        if s == 1:
            morse_symbols.append("." if d < tone_thresh else "-")
        else:
            if d > 0.4:
                morse_symbols.append(" / ")
            elif d > 0.15:
                morse_symbols.append(" ")

    morse_str = "".join(morse_symbols).strip()

    MORSE_DICT = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
        '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
        '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-',
        '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@'
    }

    words = morse_str.split(" / ")
    decoded_words = []
    for w in words:
        chars = w.split(" ")
        dec = "".join(MORSE_DICT.get(c, "?") for c in chars if c)
        decoded_words.append(dec)

    return (
        f"Morse Signal Detected:\n"
        f"Raw Morse : {morse_str}\n"
        f"Decoded   : {' '.join(decoded_words)}"
    )


@tool(category="stego")
def stego_steghide_extract(file_path: str, passphrase: str = "", out_path: str = "") -> str:
    """Extract embedded secret data from JPEG, BMP, WAV, or AU files using Steghide.

    :param file_path: Path to the stego carrier file
    :param passphrase: Password to decrypt the hidden data (default empty)
    :param out_path: Optional custom output path
    """
    import os
    import shutil
    import subprocess

    if not os.path.exists(file_path):
        return f"ERROR: File not found: {file_path}"

    steghide_bin = shutil.which("steghide") or "/tmp/steghide_bin/usr/bin/steghide"
    if not os.path.exists(steghide_bin) and not shutil.which("steghide"):
        return "ERROR: steghide binary not available on system."

    dest = out_path or (os.path.splitext(file_path)[0] + "_steghide.txt")

    env = os.environ.copy()
    if os.path.exists("/tmp/steghide_bin/usr/lib/x86_64-linux-gnu"):
        env["LD_LIBRARY_PATH"] = f"/tmp/steghide_bin/usr/lib/x86_64-linux-gnu:{env.get('LD_LIBRARY_PATH', '')}"

    cmd = [steghide_bin, "extract", "-sf", file_path, "-p", passphrase, "-xf", dest, "-f"]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if os.path.exists(dest):
        try:
            content = open(dest, "rb").read()
            text = content.decode("utf-8", errors="replace")
            return (
                f"🏆 Steghide extraction successful!\n"
                f"Output saved to: {dest} ({len(content)} bytes)\n"
                f"Content preview:\n{text[:500]}"
            )
        except Exception as ex:
            return f"Extracted file {dest} but could not read: {ex}"
    else:
        return f"Steghide extraction failed (passphrase={passphrase!r}): {res.stderr or res.stdout}"


@tool(category="stego")
def stego_whitespace_snow(text_or_path: str) -> str:
    """Decode trailing whitespace steganography (tabs and spaces at line endings) into binary and ASCII.

    :param text_or_path: Path to text file or raw text containing trailing whitespace
    """
    import os
    if os.path.exists(text_or_path):
        lines = open(text_or_path, "r", errors="ignore").readlines()
    else:
        lines = text_or_path.splitlines(keepends=True)

    bits = []
    for l in lines:
        # Strip newline but preserve trailing spaces and tabs
        no_nl = l.rstrip("\r\n")
        trailing = no_nl[len(no_nl.rstrip(" \t")):]
        for ch in trailing:
            if ch == " ":
                bits.append("0")
            elif ch == "\t":
                bits.append("1")

    if not bits:
        return "No trailing whitespace (spaces/tabs) detected at line endings."

    bit_str = "".join(bits)
    if len(bit_str) < 8:
        return f"Found {len(bit_str)} trailing whitespace bits: {bit_str}"

    # Convert to bytes
    byte_arr = [int(bit_str[i:i+8], 2) for i in range(0, len(bit_str) - 7, 8)]
    raw = bytes(byte_arr)

    try:
        text = raw.decode("utf-8")
        return (
            f"🏆 Whitespace Steganography Decoded ({len(bit_str)} bits, {len(raw)} bytes):\n"
            f"Text (UTF-8):\n{text}\n\nHex:\n{raw.hex()}"
        )
    except UnicodeDecodeError:
        return (
            f"🏆 Whitespace Steganography Decoded ({len(bit_str)} bits, {len(raw)} bytes):\n"
            f"Latin-1:\n{raw.decode('latin-1', errors='replace')}\n\nHex:\n{raw.hex()}"
        )


@tool(category="stego")
def stego_bmp_color_palette(image_path: str) -> str:
    """Inspect BMP indexed color palette (RGBQUAD) entries for hidden ASCII bytes in reserved/alpha channels.

    :param image_path: Path to the BMP image
    """
    import os
    import struct

    if not os.path.exists(image_path):
        return f"ERROR: File not found: {image_path}"

    data = open(image_path, "rb").read(2048)
    if len(data) < 54 or data[:2] != b"BM":
        return "ERROR: File is not a valid BMP image."

    data_offset = struct.unpack("<I", data[10:14])[0]
    header_size = struct.unpack("<I", data[14:18])[0]
    bpp = struct.unpack("<H", data[28:30])[0]
    num_colors = struct.unpack("<I", data[46:50])[0]

    lines = [
        f"BMP Color Palette Stego Analysis: {image_path}",
        f"  Bits Per Pixel (bpp): {bpp}",
        f"  Palette Offset      : 0x{14 + header_size:x}",
        f"  Data Offset         : 0x{data_offset:x}"
    ]

    palette_size = data_offset - (14 + header_size)
    if palette_size <= 0:
        return "\n".join(lines) + "\n\nNo color palette table in this BMP (direct 24-bit or 32-bit RGB image)."

    palette_data = data[14+header_size:data_offset]
    reserved_bytes = bytearray()
    all_bytes = bytearray()

    for i in range(0, len(palette_data) - 3, 4):
        b, g, r, a = palette_data[i:i+4]
        reserved_bytes.append(a)
        all_bytes.extend([b, g, r])

    lines.append(f"  Palette Entries     : {len(palette_data) // 4} colors")

    res_text = "".join(chr(c) if 32 <= c <= 126 else "." for c in reserved_bytes)
    lines.append(f"\nReserved 4th Byte ASCII Preview:\n  {res_text}")

    return "\n".join(lines)


@tool(category="stego")
def stego_rgb_plane_extract(image_path: str, plane: str = "red_0") -> str:
    """Analyze RGB and Alpha color channel bit planes for hidden watermarks and visual stego.

    :param image_path: Path to PNG or BMP image
    :param plane: Bit plane to inspect ('red_0', 'green_0', 'blue_0', 'alpha_0', 'red_7')
    """
    import os
    if not os.path.exists(image_path):
        return f"ERROR: File not found: {image_path}"

    try:
        from PIL import Image
    except ImportError:
        return "ERROR: PIL / Pillow library required for bit plane visual extraction."

    try:
        img = Image.open(image_path).convert("RGBA")
        width, height = img.size
        pixels = list(img.getdata())
    except Exception as ex:
        return f"ERROR: Failed to open image with PIL: {ex}"

    p_clean = plane.lower().strip()
    channel_idx = 0  # 0=R, 1=G, 2=B, 3=A
    bit_idx = 0

    if "green" in p_clean:
        channel_idx = 1
    elif "blue" in p_clean:
        channel_idx = 2
    elif "alpha" in p_clean:
        channel_idx = 3

    for i in range(8):
        if str(i) in p_clean:
            bit_idx = i
            break

    extracted_bits = []
    for px in pixels[:4000]:
        val = px[channel_idx]
        extracted_bits.append((val >> bit_idx) & 1)

    # Convert first bits to bytes
    byte_arr = bytearray()
    for i in range(0, len(extracted_bits) - 7, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | extracted_bits[i+j]
        byte_arr.append(b)

    text_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in byte_arr[:200])

    return (
        f"Bit Plane Extraction ({image_path}):\n"
        f"  Channel : {['Red', 'Green', 'Blue', 'Alpha'][channel_idx]} (Bit {bit_idx})\n"
        f"  Image Size : {width}x{height} ({len(pixels)} pixels)\n"
        f"  Extracted Stream Preview:\n    {text_preview}\n\n"
        f"  Hex Sample (first 64 bytes): {byte_arr[:64].hex()}"
    )