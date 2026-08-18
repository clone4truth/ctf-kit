"""Encoding & Misc: base family, url, html, morse, unicode, brainfuck, decode_all."""

import base64
import html
import re
import urllib.parse

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
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
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


def _morse_try(data: str) -> bytes:
    if not re.fullmatch(r"[.\-\s]+", data):
        raise ValueError("not morse")
    return morse(data).encode()


def _zlib_try(data: bytes) -> bytes:
    import zlib
    return zlib.decompress(data)