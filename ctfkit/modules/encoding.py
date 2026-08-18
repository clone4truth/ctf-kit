"""Encoding & Misc: base family, url, html, morse, unicode, brainfuck, decode_all."""

import base64
import html
import re
import urllib.parse
import zlib

from ..registry import tool
from ..utils import b64, printable, from_b64


@tool(category="encoding")
def decode_base(encoded: str, base: int = 64) -> str:
    """Decode a number/string to bytes (hex output). Base: 2, 8, 16, 32, 36, 58, 62, 64, 85."""
    e = encoded.strip()
    try:
        if base == 64:
            raw = from_b64(e)
        elif base == 32:
            raw = base64.b32decode(e, casefold=True)
        elif base == 85:
            try:
                raw = base64.b85decode(e)
            except Exception:
                raw = base64.a85decode(e)
        elif base == 58:
            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            n = 0
            for c in e:
                n = n * 58 + alphabet.index(c)
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        elif base in (2, 8, 16, 36, 62):
            alphabet62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            n = int(e, base) if base != 62 else 0
            if base == 62:
                for c in e:
                    n = n * 62 + alphabet62.index(c)
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        else:
            return f"Base {base} is not supported."
        return f"hex: {raw.hex()}\nascii: {printable(raw)}"
    except Exception as ex:
        return f"Failed to decode base{base}: {ex}"


@tool(category="encoding")
def encode_url(text: str, decode: bool = False) -> str:
    """URL encode/decode (urllib). decode=True for the reverse."""
    return urllib.parse.unquote(text) if decode else urllib.parse.quote(text)


@tool(category="encoding")
def encode_html_entities(text: str, decode: bool = False) -> str:
    """HTML entity encode/decode (e.g. &lt; &#x2F;). decode=True for the reverse."""
    return html.unescape(text) if decode else html.escape(text, quote=True)


@tool(category="encoding")
def encode_unicode_escapes(text: str, decode: bool = False) -> str:
    """Unicode escapes: '\\u0041 \\x41' <-> text. decode=True: escapes -> text."""
    if decode:
        return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    return " ".join(f"\\u{ord(c):04x}" for c in text)


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", ".----.": "'", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
    "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-",
    "..--.-": "_", "...-..-": "$", ".--.-.": "@", ".-...": "&",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


@tool(category="encoding")
def morse(text: str, decode: bool = True) -> str:
    """Morse code. decode=True: '.' '-' -> text (letters separated by 1 space, words by 2). decode=False: text -> morse."""
    if decode:
        out = []
        for word in re.split(r"\s{2,}", text.strip()):
            for tok in word.split():
                out.append(_MORSE.get(tok, "?"))
            out.append(" ")
        return "".join(out).strip()
    return "  ".join(" ".join(_MORSE_REV.get(c.upper(), "?") for c in w)
                     for w in text.upper().split())


_BF = {">": 1, "<": -1, "+": 1, "-": -1}


@tool(category="encoding")
def brainfuck(code: str, input_str: str = "") -> str:
    """Brainfuck interpreter (+ - < > [ ] . ,). input_str feeds ','."""
    tape = [0] * 30000
    ptr = 15000
    pc = 0
    out = []
    inp = iter(input_str)
    jumps = {}
    stack = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return "ERROR: unmatched ']' in brainfuck code."
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
    if stack:
        return "ERROR: unmatched '[' in brainfuck code."
    steps = 0
    while pc < len(code):
        c = code[pc]
        if c == ">":
            ptr += 1
        elif c == "<":
            ptr -= 1
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == ",":
            tape[ptr] = ord(next(inp, "\0"))
        elif c == "[" and tape[ptr] == 0:
            pc = jumps[pc]
        elif c == "]" and tape[ptr] != 0:
            pc = jumps[pc]
        pc += 1
        steps += 1
        if steps > 10_000_000:
            return "ERROR: infinite loop (10M step limit)."
    return "".join(out)


@tool(category="encoding")
def decode_all(data: str) -> str:
    """Try every common encoding (base64/hex/url/html/binary/octal/rot13/morse/unicode) and show valid candidates."""
    data = data.strip()
    results = []
    candidates = {
        "base64": lambda: from_b64(data),
        "base64 urlsafe": lambda: base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)),
        "hex": lambda: bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", data)),
        "url": lambda: urllib.parse.unquote(data).encode(),
        "html": lambda: html.unescape(data).encode(),
        "binary": lambda: int(data.replace(" ", ""), 2).to_bytes((len(data.replace(" ", "")) + 7) // 8, "big"),
        "octal": lambda: bytes(int(o, 8) for o in re.findall(r"[0-7]{1,3}", data)),
        "ascii decimal": lambda: bytes(int(a) for a in re.findall(r"\d+", data)),
        "rot13": lambda: data.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")).encode(),
        "morse": lambda: _morse_try(data),
        "unicode escape": lambda: re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), data).encode(),
        "zlib": lambda: _zlib_try(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", data))) if re.fullmatch(r"[0-9a-fA-F\s]+", data) else b"",
    }
    for name, fn in candidates.items():
        try:
            raw = fn()
            if isinstance(raw, bytes) and raw:
                if all(32 <= b < 127 or b in (10, 13) for b in raw[:2000]):
                    results.append(f"[{name}] {raw.decode('utf-8', 'replace')}")
        except Exception:
            pass
    return "\n".join(results) if results else "No valid candidates."


@tool(category="encoding")
def decode_base45(encoded: str) -> str:
    """Decode Base45 (RFC 9285 - QR codes / health certificates)."""
    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    charmap = {c: i for i, c in enumerate(charset)}
    e = encoded.strip()
    try:
        out = bytearray()
        i = 0
        while i < len(e):
            if i + 3 <= len(e):
                c0 = charmap[e[i]]
                c1 = charmap[e[i + 1]]
                c2 = charmap[e[i + 2]]
                val = c0 + c1 * 45 + c2 * 45 * 45
                out.append(val // 256)
                out.append(val % 256)
                i += 3
            elif i + 2 <= len(e):
                c0 = charmap[e[i]]
                c1 = charmap[e[i + 1]]
                val = c0 + c1 * 45
                out.append(val)
                i += 2
            else:
                return "Invalid Base45 string length."
        return f"hex: {out.hex()}\nascii: {printable(out)}"
    except Exception as ex:
        return f"Failed to decode Base45: {ex}"


@tool(category="encoding")
def decode_base91(encoded: str) -> str:
    """Decode basE91 binary-to-text encoding."""
    lookup = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$',
        '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<',
        '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"'
    ]
    decode_table = {c: i for i, c in enumerate(lookup)}
    e = encoded.strip()
    try:
        v = -1
        b = 0
        n = 0
        out = bytearray()
        for c in e:
            if c not in decode_table:
                continue
            c_val = decode_table[c]
            if v < 0:
                v = c_val
            else:
                v += c_val * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v + 1:
            out.append((b | v << n) & 255)
        return f"hex: {out.hex()}\nascii: {printable(out)}"
    except Exception as ex:
        return f"Failed to decode basE91: {ex}"


_ZW_MAP = {
    "\u200b": "ZWSP",
    "\u200c": "ZWNJ",
    "\u200d": "ZWJ",
    "\ufeff": "ZWNBSP",
    "\u2060": "WJ",
    "\u200e": "LRM",
    "\u200f": "RLM",
}


@tool(category="encoding")
def decode_zero_width(text: str) -> str:
    """Extract and decode hidden Zero-Width Unicode characters (ZWSP, ZWNJ, ZWJ, ZWNBSP, WJ)."""
    found_chars = [c for c in text if c in _ZW_MAP]
    if not found_chars:
        return "No zero-width unicode characters found in the input text."
    
    unique_chars = sorted(set(found_chars), key=lambda c: found_chars.index(c))
    summary = f"Found {len(found_chars)} zero-width characters ({', '.join(_ZW_MAP[c] for c in unique_chars)})."
    
    results = [summary]
    # Try binary permutations if 2 distinct chars
    if len(unique_chars) == 2:
        c0, c1 = unique_chars[0], unique_chars[1]
        for zero, one, label in [(c0, c1, f"{_ZW_MAP[c0]}=0, {_ZW_MAP[c1]}=1"),
                                 (c1, c0, f"{_ZW_MAP[c1]}=0, {_ZW_MAP[c0]}=1")]:
            bits = "".join("0" if c == zero else "1" for c in found_chars)
            bytes_list = []
            for i in range(0, len(bits) - 7, 8):
                bytes_list.append(int(bits[i:i + 8], 2))
            raw = bytes(bytes_list)
            txt = printable(raw)
            results.append(f"[{label}] (8-bit):\n  hex: {raw.hex()}\n  ascii: {txt}")
            # Also try 7-bit ASCII
            bytes7 = []
            for i in range(0, len(bits) - 6, 7):
                bytes7.append(int(bits[i:i + 7], 2))
            results.append(f"[{label}] (7-bit):\n  ascii: {printable(bytes(bytes7))}")
    elif len(unique_chars) == 1:
        # Maybe length-based or morse
        results.append(f"Single char {_ZW_MAP[unique_chars[0]]} repeated {len(found_chars)} times.")
    else:
        # Multiple zero width chars, try morse / quaternary / custom mapping
        results.append(f"Raw sequence: {' '.join(_ZW_MAP.get(c, '?') for c in found_chars[:50])}" +
                       (f" ... ({len(found_chars)} total)" if len(found_chars) > 50 else ""))
    return "\n\n".join(results)


@tool(category="encoding")
def encode_zero_width(secret: str, cover_text: str = "FLAG") -> str:
    """Hide a secret message inside cover text using Zero-Width spaces (ZWSP=0, ZWNJ=1)."""
    bits = "".join(f"{b:08b}" for b in secret.encode())
    zw = "".join("\u200b" if bit == "0" else "\u200c" for bit in bits)
    if len(cover_text) > 1:
        return cover_text[0] + zw + cover_text[1:]
    return cover_text + zw


@tool(category="encoding")
def decode_chain(data: str, max_depth: int = 8) -> str:
    """Recursively peel nested multi-layer encodings (Base64, Hex, URL, HTML, Rot13, Zlib, Binary) until flag or plaintext is reached."""
    from ..flagmeta import detect_flag
    
    current = data.strip()
    history = [f"Step 0 (raw): {current[:80]}..."]
    
    transforms = [
        ("Base64", lambda s: from_b64(s).decode("latin-1")),
        ("Base64-URL", lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("latin-1")),
        ("Hex", lambda s: bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s)).decode("latin-1") if len(re.sub(r"[^0-9a-fA-F]", "", s)) >= 4 and len(re.sub(r"[^0-9a-fA-F]", "", s)) % 2 == 0 else ""),
        ("URL", lambda s: urllib.parse.unquote(s) if "%" in s else ""),
        ("HTML", lambda s: html.unescape(s) if "&" in s and ";" in s else ""),
        ("Binary", lambda s: "".join(chr(int(b, 2)) for b in re.findall(r"[01]{8}", s)) if re.fullmatch(r"[\s01]+", s) and len(re.findall(r"[01]{8}", s)) >= 1 else ""),
        ("Zlib-Hex", lambda s: zlib.decompress(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s))).decode("latin-1") if re.fullmatch(r"[0-9a-fA-F\s]+", s) and len(s) >= 8 else ""),
        ("Rot13", lambda s: s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))),
    ]
    
    flag = detect_flag(current)
    if flag:
        return f"Flag detected at step 0!\nFlag: {flag}\nData: {current}"
    
    seen = {current}
    for step in range(1, max_depth + 1):
        best_candidate = None
        best_name = ""
        
        for name, fn in transforms:
            try:
                cand = fn(current)
                if not cand or cand in seen or cand == current:
                    continue
                # Check if readable
                cand_bytes = cand.encode("latin-1", "ignore")
                printable_ratio = sum(1 for b in cand_bytes if 32 <= b < 127 or b in (10, 13, 9)) / max(len(cand_bytes), 1)
                if printable_ratio > 0.8:
                    best_candidate = cand
                    best_name = name
                    # If flag found, prioritize immediately
                    if detect_flag(cand):
                        break
            except Exception:
                pass
        
        if not best_candidate:
            break
        
        seen.add(best_candidate)
        current = best_candidate.strip()
        history.append(f"Step {step} [{best_name}]: {current[:80]}" + ("..." if len(current) > 80 else ""))
        
        flag = detect_flag(current)
        if flag:
            history.append(f"\n🏆 FLAG RECOVERED: {flag}")
            break
    
    return "\n".join(history) + f"\n\nFinal Text:\n{current}"


def _morse_try(data: str) -> bytes:
    if not re.fullmatch(r"[.\-\s]+", data):
        raise ValueError("not morse")
    return morse(data).encode()


def _zlib_try(data: bytes) -> bytes:
    import zlib
    return zlib.decompress(data)