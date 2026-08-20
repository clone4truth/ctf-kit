"""Generate test data for smoke tests."""
import math
import os
import random
import struct
import tarfile
import io
import zlib

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTDATA_DIR = os.path.join(REPO_ROOT, "testdata")
os.makedirs(TESTDATA_DIR, exist_ok=True)

random.seed(7)

# PNG with flag in tEXt chunk
from PIL import Image, PngImagePlugin
img = Image.new("RGB", (16, 16))
px = img.load()
for y in range(16):
    for x in range(16):
        px[x, y] = (random.randrange(256), random.randrange(256), random.randrange(256))
info = PngImagePlugin.PngInfo()
info.add_text("flag", "flag{hidden_in_text_chunk}")
img.save(os.path.join(TESTDATA_DIR, "meta2.png"), pnginfo=info)

# PNG with flag in LSB
px2 = bytearray(img.tobytes())
msg = b"flag{lsb_hidden}"
bits = "".join(f"{b:08b}" for b in msg)
for i, b in enumerate(bits):
    px2[i] = (px2[i] & 0xFE) | int(b)
Image.frombytes("RGB", (16, 16), bytes(px2)).save(os.path.join(TESTDATA_DIR, "lsb.png"))

# blob with embedded PNG + trailing junk
blob = b"junk" * 100 + open(os.path.join(TESTDATA_DIR, "meta2.png"), "rb").read() + b"trailing"
open(os.path.join(TESTDATA_DIR, "blob.bin"), "wb").write(blob)

# hidden zlib stream
payload = b"flag{zlib_stream}" + b"\x00" * 50
stream = zlib.compress(payload)
open(os.path.join(TESTDATA_DIR, "zlib.bin"), "wb").write(b"\x41" * 100 + stream + b"\x42" * 100)

# GIF 2 frame
frames = []
for i in range(2):
    f = Image.new("RGB", (8, 8), (i * 100, 50, 150))
    frames.append(f)
frames[0].save(os.path.join(TESTDATA_DIR, "test.gif"), save_all=True, append_images=frames[1:], duration=200, loop=0)

# PCAP minimal: Ethernet + IPv4 + TCP + HTTP GET
pcap = bytearray()
pcap += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
http = b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\n\r\nflag{http_extracted}"
ip_len = 20 + 20 + len(http)
pkt = (
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    + struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_len, 0x1234, 0x4000, 64, 6, 0,
                  bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    + struct.pack(">HHIIBBHHH", 12345, 80, 1, 1, 5, 0x18, 65535, 0, 0)
    + http
)
pcap += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
open(os.path.join(TESTDATA_DIR, "test.pcap"), "wb").write(bytes(pcap))

# Repeating-XOR binary used by the advanced reverse-engineering benchmark.
xor_plain = b"noise::flag{xor_binary_recovered}::end"
xor_key = b"K3Y"
xor_blob = bytes(byte ^ xor_key[i % len(xor_key)] for i, byte in enumerate(xor_plain))
open(os.path.join(TESTDATA_DIR, "xor_flag.bin"), "wb").write(b"\x00\xffCTF" + xor_blob)

# Deterministic TAR metadata fixture (the analyzer intentionally inspects headers).
with tarfile.open(os.path.join(TESTDATA_DIR, "evidence.tar"), "w") as archive:
    content = b"flag{tar_evidence_recovered}\n"
    entry = tarfile.TarInfo("evidence/flag{tar_header_found}.txt")
    entry.size, entry.mode, entry.mtime = len(content), 0o640, 1_700_000_000
    archive.addfile(entry, io.BytesIO(content))

# dummy x86-64 ELF with PT_GNU_STACK (NX), pop rdi; ret gadget
elf_header = struct.pack(
    "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 64, 0, 0, 64, 56, 2, 64, 3, 0)
phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000, 0x1000)  # PT_LOAD RX (executable)
phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0x1000, 0x501000, 0x1000, 0x1000, 0x1000, 0x1000)  # PT_GNU_STACK RW
code = b"\x90" * 32 + b"\x5f\xc3" + b"\x5e\xc3" + b"\x0f\x05\xc3" + b"\x90" * 8
open(os.path.join(TESTDATA_DIR, "dummy.elf"), "wb").write(b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7) + elf_header + phdrs + code)

# PNG with corrupted IHDR height (modified from 16 to 1, CRC kept original)
png_raw = bytearray(open(os.path.join(TESTDATA_DIR, "meta2.png"), "rb").read())
# IHDR chunk: offset 12 is 'IHDR', 16-20 is width (16), 20-24 is height (16)
png_raw[20:24] = struct.pack(">I", 1)  # tamper height to 1
open(os.path.join(TESTDATA_DIR, "corrupt_ihdr.png"), "wb").write(png_raw)

# simple WAV audio file (16-bit PCM mono 8000Hz) with LSB flag
import wave
wav_file = os.path.join(TESTDATA_DIR, "audio.wav")
with wave.open(wav_file, "wb") as wf:
    wf.setnchannels(1)
    wf.setsampwidth(2)
    wf.setframerate(8000)
    samples = []
    wav_secret = b"flag{audio_lsb_found}"
    wav_bits = "".join(f"{b:08b}" for b in wav_secret)
    for i in range(len(wav_bits) + 100):
        val = int(10000 * math.sin(2 * math.pi * 440 * i / 8000))
        bit = int(wav_bits[i]) if i < len(wav_bits) else 0
        val = (val & ~1) | bit
        samples.append(val)
    wf.writeframes(struct.pack(f"<{len(samples)}h", *samples))

# Minimal Windows PE executable (PE32+)
pe_data = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40))  # e_lfanew = 0x40
pe_data += b"PE\x00\x00"  # Signature
pe_data += struct.pack("<HHIIIHH", 0x8664, 1, 0x60000000, 0, 0, 0xf0, 0x0002)  # COFF: AMD64, 1 section, EXECUTABLE
# Optional Header (PE32+ 0x20b)
pe_data += struct.pack("<HBBIIIIIIQIIHH", 0x20b, 1, 0, 0x200, 0x200, 0, 0x1000, 0x1000, 0, 0x140000000, 0x1000, 0x200, 6, 0)
pe_data += b"\x00" * (0xf0 - 44)  # pad optional header
# Section .text
pe_data += b".text\x00\x00\x00" + struct.pack("<IIIIIIHHI", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
pe_data += b"\x90" * 512
open(os.path.join(TESTDATA_DIR, "dummy.exe"), "wb").write(pe_data)

# Pseudo-encrypted ZIP
import zipfile
import io
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("secret.txt", "flag{pseudo_zip_unlocked}")
zip_bytes = bytearray(zip_buf.getvalue())
# Set bit 0 of general purpose flag in Local File Header (offset 6)
if zip_bytes[:4] == b"PK\x03\x04":
    zip_bytes[6] |= 0x01
open(os.path.join(TESTDATA_DIR, "pseudo.zip"), "wb").write(zip_bytes)

# SQLite database with a flag
import sqlite3
db_file = os.path.join(TESTDATA_DIR, "flag.db")
if os.path.exists(db_file):
    os.remove(db_file)
conn = sqlite3.connect(db_file)
conn.execute("CREATE TABLE users (id INTEGER, username TEXT, secret TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'admin', 'flag{sqlite_reader_found}')")
conn.execute("INSERT INTO users VALUES (2, 'guest', 'nothing here')")
conn.commit()
conn.close()

# Minimal PDF with a compressed stream containing the flag
pdf = bytearray(b"%PDF-1.4\n")
objects = []
objs = []
# Object 1: Catalog
objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
# Object 2: Pages
objs.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
# Object 3: Page with a content stream
objs.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n")
secret = b"flag{pdf_stream_flag}"
compressed = zlib.compress(b"BT /F1 24 Tf 50 100 Td (" + secret + b") Tj ET")
objs.append(b"4 0 obj\n<< /Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream\nendobj\n")
for o in objs:
    pdf += o
pdf += b"xref\n"
off = 9
offsets = [0]
for o in objs:
    offsets.append(off)
    off += len(o)
pdf += b"0 " + str(len(objs) + 1).encode() + b"\n"
pdf += b"0000000000 65535 f \n"
for i in range(1, len(objs) + 1):
    pdf += f"{offsets[i]:010d} 00000 n \n".encode()
pdf += b"trailer\n<< /Size " + str(len(objs) + 1).encode() + b" /Root 1 0 R >>\nstartxref\n" + str(off).encode() + b"\n%%EOF"
open(os.path.join(TESTDATA_DIR, "mini.pdf"), "wb").write(bytes(pdf))

print("testdata ready")
