import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)
os.chdir(REPO_ROOT)

import ctfkit.modules
from ctfkit.modules.stego import _jpeg_coefficients, _ZIGZAG
from ctfkit.registry import run_tool

FLAG = b"flag{jsteg_roundtrip_ok}"

DC_COUNTS = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
DC_SYMS = bytes(range(12))
AC_COUNTS = bytes([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D])
AC_SYMS = bytes([
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
    0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA,
])


def canonical(counts, syms):
    codes = {}
    code = 0
    k = 0
    for i in range(16):
        for _ in range(counts[i]):
            codes[syms[k]] = (code, i + 1)
            k += 1
            code += 1
        code <<= 1
    return codes


DC_CODES = canonical(DC_COUNTS, DC_SYMS)
AC_CODES = canonical(AC_COUNTS, AC_SYMS)


class BW:
    def __init__(self):
        self.buf = bytearray()
        self.acc = 0
        self.nbits = 0

    def write(self, code, n):
        for i in range(n - 1, -1, -1):
            self.acc = (self.acc << 1) | ((code >> i) & 1)
            self.nbits += 1
            if self.nbits == 8:
                self.buf.append(self.acc)
                if self.acc == 0xFF:
                    self.buf.append(0x00)
                self.acc = 0
                self.nbits = 0

    def finish(self):
        if self.nbits:
            self.buf.append(self.acc << (8 - self.nbits))
            if self.buf[-1] == 0xFF:
                self.buf.append(0x00)
            self.acc = 0
            self.nbits = 0


def seg(marker, body):
    return bytes([0xFF, marker]) + (len(body) + 2).to_bytes(2, "big") + body


def build_jpeg(blocks, w_blocks=None, h_blocks=None):
    """blocks: list of 64-int coefficient lists (fabricated, no pixels).
    Dims derived so every MCU has entropy; empty blocks pad the rest."""
    nblocks = len(blocks)
    if h_blocks is None:
        h_blocks = 1 if nblocks <= 4 else (nblocks + 3) // 4
    if w_blocks is None:
        w_blocks = nblocks // h_blocks + (1 if nblocks % h_blocks else 0)
    flat = [32] * 64
    dqt_body = bytes([0]) + bytes(flat[z] for z in _ZIGZAG)
    dht_body = bytes([0x00]) + DC_COUNTS + DC_SYMS + bytes([0x10]) + AC_COUNTS + AC_SYMS
    h8, w8 = h_blocks * 8, w_blocks * 8
    sof0_body = bytes([8]) + h8.to_bytes(2, "big") + w8.to_bytes(2, "big") + bytes([1, 1, 0x11, 0])
    sos_body = bytes([1, 1, 0x00, 0, 63, 0])
    out = bytearray(b"\xff\xd8")
    out += seg(0xDB, dqt_body)
    out += seg(0xC4, dht_body)
    out += seg(0xC0, sof0_body)
    out += seg(0xDA, sos_body)
    w = BW()
    pred = 0
    total = w_blocks * h_blocks
    for bi in range(total):
        coeffs = blocks[bi] if bi < nblocks else [0] * 64
        diff = (100 + bi * 13) - pred
        pred = 100 + bi * 13
        cat = diff.bit_length() if diff else 0
        if diff < 0:
            diff += (1 << cat) - 1
        code, clen = DC_CODES[cat]
        w.write(code, clen)
        if cat:
            w.write(diff, cat)
        zero_run = 0
        for k in range(1, 64):
            c = coeffs[k]
            if c == 0:
                zero_run += 1
                if zero_run == 16:
                    code, clen = AC_CODES[0xF0]
                    w.write(code, clen)
                    zero_run = 0
                continue
            while zero_run > 15:
                code, clen = AC_CODES[0xF0]
                w.write(code, clen)
                zero_run -= 16
            size = abs(c).bit_length()
            val = c + (1 << size) - 1 if c < 0 else c
            code, clen = AC_CODES[(zero_run << 4) | size]
            w.write(code, clen)
            w.write(val, size)
            zero_run = 0
        if not all(c != 0 for c in coeffs[1:]):
            code, clen = AC_CODES[0x00]
            w.write(code, clen)
    w.finish()
    out += w.buf
    out += b"\xff\xd9"
    return bytes(out)


bits = []
for b in FLAG:
    for i in range(7, -1, -1):
        bits.append((b >> i) & 1)

blocks = []
bi = 0
while bi * 63 < len(bits):
    coeffs = [0] * 64
    for k in range(1, 64):
        if bi * 63 + k - 1 < len(bits):
            coeffs[k] = 3 + (1 - bits[bi * 63 + k - 1])  # abs 3 or 4; LSB == data bit
    blocks.append(coeffs)
    bi += 1
jpeg = build_jpeg(blocks)
open(os.path.join(REPO_ROOT, "testdata", "jsteg_synth.jpg"), "wb").write(jpeg)

decoded = _jpeg_coefficients(jpeg)
assert len(decoded) == len(blocks), "block count"
rec = []
for cid, coeffs in decoded:
    for c in coeffs[1:]:
        if abs(c) > 1:
            rec.append(c & 1)
out_bytes = bytearray()
for i in range(0, len(rec) - 7, 8):
    out_bytes.append(int("".join(str(b) for b in rec[i:i + 8]), 2))
assert bytes(out_bytes[:26]) == FLAG, "roundtrip mismatch: %r" % bytes(out_bytes[:26])


out = run_tool("stego_jsteg", dict(image_path=os.path.join(REPO_ROOT, "testdata", "jsteg_synth.jpg"), max_bytes=64))

assert FLAG.decode() in out, "tool extraction failed"