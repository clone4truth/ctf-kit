"""Generate testdata untuk smoke test."""
import os
import random
import struct
import zlib

random.seed(7)
os.makedirs("testdata", exist_ok=True)

# PNG dengan flag di tEXt chunk
from PIL import Image, PngImagePlugin
img = Image.new("RGB", (16, 16))
px = img.load()
for y in range(16):
    for x in range(16):
        px[x, y] = (random.randrange(256), random.randrange(256), random.randrange(256))
info = PngImagePlugin.PngInfo()
info.add_text("flag", "flag{hidden_in_text_chunk}")
img.save("testdata/meta2.png", pnginfo=info)

# PNG dengan flag di LSB
px2 = bytearray(img.tobytes())
msg = b"flag{lsb_hidden}"
bits = "".join(f"{b:08b}" for b in msg)
for i, b in enumerate(bits):
    px2[i] = (px2[i] & 0xFE) | int(b)
Image.frombytes("RGB", (16, 16), bytes(px2)).save("testdata/lsb.png")

# blob berisi PNG tertanam + trailing junk
blob = b"junk" * 100 + open("testdata/meta2.png", "rb").read() + b"trailing"
open("testdata/blob.bin", "wb").write(blob)

# zlib stream tersembunyi
payload = b"flag{zlib_stream}" + b"\x00" * 50
stream = zlib.compress(payload)
open("testdata/zlib.bin", "wb").write(b"\x41" * 100 + stream + b"\x42" * 100)

# GIF 2 frame
frames = []
for i in range(2):
    f = Image.new("RGB", (8, 8), (i * 100, 50, 150))
    frames.append(f)
frames[0].save("testdata/test.gif", save_all=True, append_images=frames[1:], duration=200, loop=0)

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
open("testdata/test.pcap", "wb").write(bytes(pcap))

# ELF dummy x86-64 dengan PT_GNU_STACK (NX), gadget pop rdi; ret
elf_header = struct.pack(
    "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 64, 0, 0, 64, 56, 2, 64, 3, 0)
phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000, 0x1000)  # PT_LOAD RX (executable)
phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0x1000, 0x501000, 0x1000, 0x1000, 0x1000, 0x1000)  # PT_GNU_STACK RW
code = b"\x90" * 32 + b"\x5f\xc3" + b"\x5e\xc3" + b"\x0f\x05\xc3" + b"\x90" * 8
open("testdata/dummy.elf", "wb").write(b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7) + elf_header + phdrs + code)

print("testdata ready")