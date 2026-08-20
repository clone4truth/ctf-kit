"""Encoding & Misc: base family, url, html, morse, unicode, brainfuck, decode_all."""

import base64
import html
import re
import urllib.parse
import zlib

from ..registry import tool
from ..utils import b64, printable, from_b64, english_score


@tool(category="encoding")
def decode_base(encoded: str, base: int = 64) -> str:
    """Decode a number/string to bytes (hex output). Base: 2, 8, 16, 32, 36, 58, 62, 64, 85.
    :param base: base
    :param encoded: encoded string to decode
    """
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
    """URL encode/decode (urllib). decode=True for the reverse.
    :param text: input text
    :param decode: decode
    """
    return urllib.parse.unquote(text) if decode else urllib.parse.quote(text)


@tool(category="encoding")
def encode_html_entities(text: str, decode: bool = False) -> str:
    """HTML entity encode/decode (e.g. &lt; &#x2F;). decode=True for the reverse.
    :param text: input text
    :param decode: decode
    """
    return html.unescape(text) if decode else html.escape(text, quote=True)


@tool(category="encoding")
def encode_unicode_escapes(text: str, decode: bool = False) -> str:
    """Unicode escapes: '\\u0041 \\x41' <-> text. decode=True: escapes -> text.
    :param text: input text
    :param decode: decode
    """
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
    """Morse code. decode=True: '.' '-' -> text (letters separated by 1 space, words by 2). decode=False: text -> morse.
    :param text: input text
    :param decode: decode
    """
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
    """Brainfuck interpreter (+ - < > [ ] . ,). input_str feeds ','.
    :param input_str: input str
    :param code: program/source code input
    """
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
    """Try every common encoding (base64/hex/url/html/binary/octal/rot13/morse/unicode) and show valid candidates.
    :param data: input data to process
    """
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
    """Decode Base45 (RFC 9285 - QR codes / health certificates).
    :param encoded: encoded string to decode
    """
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
    """Decode basE91 binary-to-text encoding.
    :param encoded: encoded string to decode
    """
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
    """Extract and decode hidden Zero-Width Unicode characters (ZWSP, ZWNJ, ZWJ, ZWNBSP, WJ).
    :param text: input text
    """
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
    """Hide a secret message inside cover text using Zero-Width spaces (ZWSP=0, ZWNJ=1).
    :param secret: secret value
    :param cover_text: cover text
    """
    bits = "".join(f"{b:08b}" for b in secret.encode())
    zw = "".join("\u200b" if bit == "0" else "\u200c" for bit in bits)
    if len(cover_text) > 1:
        return cover_text[0] + zw + cover_text[1:]
    return cover_text + zw


@tool(category="encoding")
def decode_chain(data: str, max_depth: int = 8) -> str:
    """Recursively peel nested multi-layer encodings (Base64, Hex, URL, HTML, Rot13, Zlib, Binary) until flag or plaintext is reached.
    :param data: input data to process
    :param max_depth: max depth
    """
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


@tool(category="encoding")
def decode_cascade(data: str, max_depth: int = 8) -> str:
    """Auto peel repeated encodings (Ciphey-style): base64/hex/url/html/rot13/binary until text settles or a flag appears.
    :param data: input data to process
    :param max_depth: max depth
    """
    rot13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    current = data.strip()
    seen = {current}
    history = []
    for step in range(1, max_depth + 1):
        cands = []
        try:
            b = from_b64(current)
            if b and b != current.encode():
                cands.append(("base64", b.decode("latin-1")))
        except Exception:
            pass
        try:
            h = current.replace("0x", "").replace(" ", "").replace(",", "")
            if re.fullmatch(r"[0-9a-fA-F]+", h) and len(h) % 2 == 0:
                cands.append(("hex", bytes.fromhex(h).decode("latin-1")))
        except Exception:
            pass
        if "%" in current:
            cands.append(("url", urllib.parse.unquote(current)))
        if "&" in current and ";" in current:
            cands.append(("html", html.unescape(current)))
        if re.search(r"[A-Za-z]", current):
            _rot = current.translate(rot13)
            if english_score(_rot.encode()) > english_score(current.encode()):
                cands.append(("rot13", _rot))
        if re.fullmatch(r"[01\s]+", current):
            bits = current.replace(" ", "")
            if len(bits) % 8 == 0:
                cands.append(("binary", int(bits, 2).to_bytes(len(bits) // 8, "big").decode("latin-1")))
        best = None
        for name, cand in cands:
            if cand == current or cand in seen:
                continue
            pr = sum(1 for ch in cand if ch.isprintable() or ch in "\n\r\t") / max(len(cand), 1)
            if pr < 0.7:
                continue
            score = (10 if "flag" in cand.lower() else 0) + pr
            if best is None or score > best[0]:
                best = (score, name, cand)
        if not best:
            break
        seen.add(best[2])
        current = best[2].strip()
        history.append(f"Step {step} [{best[1]}]: {current[:90]}")
        if re.search(r"\b\w{2,}\{[^}\n]{2,}\}", current):
            break
    if not history:
        return "No layered encoding detected."
    return "\n".join(history) + f"\n\nFinal: {current}"


def _zlib_try(data: bytes) -> bytes:
    import zlib
    return zlib.decompress(data)


@tool(category="encoding")
def decode_custom_base64(ciphertext: str, alphabet: str) -> str:
    """Decode base64 ciphertext encoded with a custom 64-character alphabet.

    :param ciphertext: The encoded base64 string
    :param alphabet: The custom 64-character substitution table (e.g. reverse, shuffled, or leet)
    """
    import base64
    clean_alpha = alphabet.strip()
    if len(clean_alpha) != 64:
        return f"ERROR: Custom alphabet must be exactly 64 characters long (received {len(clean_alpha)} chars)."

    std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trans = str.maketrans(clean_alpha, std_alpha)

    clean_cipher = ciphertext.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    # Preserve padding '='
    unpadded = clean_cipher.rstrip("=")
    pad_len = len(clean_cipher) - len(unpadded)

    translated = unpadded.translate(trans) + ("=" * pad_len)

    try:
        raw = base64.b64decode(translated)
        try:
            return f"Decoded Text (UTF-8):\n{raw.decode('utf-8')}\n\nHex:\n{raw.hex()}"
        except UnicodeDecodeError:
            return f"Decoded Bytes (Latin-1 / Binary):\n{raw.decode('latin-1', errors='replace')}\n\nHex:\n{raw.hex()}"
    except Exception as ex:
        return f"ERROR: Failed to decode base64: {ex}"


@tool(category="encoding")
def decode_quoted_printable_uu(data: str, mode: str = "auto") -> str:
    """Decode Quoted-Printable (=3D, =20) or UUencoded (begin 644 ...) data streams.

    :param data: The encoded string
    :param mode: 'auto', 'quoted_printable', or 'uuencode'
    """
    import binascii
    import quopri

    mode_clean = mode.lower().strip()
    results = []

    # 1. Quoted printable
    if mode_clean in ("auto", "quoted_printable", "qp"):
        try:
            qp_dec = quopri.decodestring(data.encode("utf-8"))
            results.append(f"=== Quoted-Printable Decoded ===\n{qp_dec.decode('utf-8', errors='replace')}")
        except Exception as ex:
            if mode_clean == "quoted_printable":
                results.append(f"Quoted-Printable error: {ex}")

    # 2. UUEncode
    if mode_clean in ("auto", "uuencode", "uu"):
        try:
            # Strip header 'begin ...' and footer 'end'
            lines = data.strip().splitlines()
            uu_lines = [l for l in lines if not l.startswith("begin ") and l.strip() != "end" and l.strip() != "`"]
            uu_payload = "\n".join(uu_lines)
            decoded = binascii.a2b_uu(uu_payload)
            results.append(f"=== UUDecode Decoded ===\n{decoded.decode('utf-8', errors='replace')}")
        except Exception as ex:
            if mode_clean == "uuencode":
                results.append(f"UUDecode error: {ex}")

    if not results:
        return "ERROR: Could not decode data with specified mode."
    return "\n\n".join(results)


@tool(category="encoding")
def tap_code(data: str, mode: str = "decode") -> str:
    """Encode or decode Tap Code (Polybius 5x5 grid with K replaced by C).

    :param data: Text or tap dots (e.g. '. ... .. ..' -> 'HE')
    :param mode: 'decode' (dots to text) or 'encode' (text to dots)
    """
    GRID = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'J'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]

    CHAR_MAP = {}
    for r in range(5):
        for c in range(5):
            CHAR_MAP[GRID[r][c]] = (r + 1, c + 1)
    CHAR_MAP['K'] = (1, 3) # K = C

    mode_clean = mode.lower().strip()
    if mode_clean == "encode":
        out = []
        for ch in data.upper():
            if ch in CHAR_MAP:
                r, c = CHAR_MAP[ch]
                out.append(f"{'.' * r} {'.' * c}")
            elif ch == ' ':
                out.append("/")
        return " ".join(out)
    else:
        # Decode: format can be pairs of dot counts like '. ...  .. ..' or '1 3  2 2' or '13 22'
        tokens = data.strip().replace("/", " / ").split()
        res = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == "/":
                res.append(" ")
                i += 1
                continue

            # If format is '.. ...'
            if set(t) == {'.'}:
                if i + 1 < len(tokens) and set(tokens[i+1]) == {'.'}:
                    r = len(t)
                    c = len(tokens[i+1])
                    if 1 <= r <= 5 and 1 <= c <= 5:
                        res.append(GRID[r-1][c-1])
                    i += 2
                    continue
            # If format is numbers '1 3'
            elif t.isdigit():
                if len(t) == 2:
                    r, c = int(t[0]), int(t[1])
                    if 1 <= r <= 5 and 1 <= c <= 5:
                        res.append(GRID[r-1][c-1])
                elif len(t) == 1 and i + 1 < len(tokens) and tokens[i+1].isdigit():
                    r, c = int(t), int(tokens[i+1])
                    if 1 <= r <= 5 and 1 <= c <= 5:
                        res.append(GRID[r-1][c-1])
                    i += 2
                    continue
            i += 1
        return f"Tap Code Decoded: {''.join(res)}"


@tool(category="encoding")
def linux_octal_escape_decode(data: str) -> str:
    """Decode Linux shell octal escape sequences (e.g. \\146\\154\\141\\147), hex escapes (\\x66), and unicode.

    :param data: Obfuscated string containing octal/hex escape codes
    """
    import re
    clean = data.strip()

    # 1. Octal escapes: \040 or \146 or 146 154 141 147
    def _repl_octal(m):
        val = int(m.group(1), 8)
        return chr(val) if val < 256 else m.group(0)

    # Match \040, \146, \40
    res_octal = re.sub(r"\\([0-3]?[0-7]{1,2}|[0-7]{3})", _repl_octal, clean)

    # 2. Raw space-separated octal numbers: e.g. "146 154 141 147 173"
    if re.fullmatch(r"[0-7]{2,3}(\s+[0-7]{2,3})+", clean):
        try:
            bytes_list = [int(tok, 8) for tok in clean.split()]
            res_space_octal = bytes(bytes_list).decode("latin-1", errors="replace")
            return f"Decoded Octal Stream:\n{res_space_octal}"
        except Exception:
            pass

    # 3. Hex escapes: \x66\x6c\x61\x67
    def _repl_hex(m):
        return chr(int(m.group(1), 16))
    res_hex = re.sub(r"\\x([0-9a-fA-F]{2})", _repl_hex, res_octal)

    # 4. Unicode escapes: \u0066
    def _repl_uni(m):
        return chr(int(m.group(1), 16))
    res_final = re.sub(r"\\u([0-9a-fA-F]{4})", _repl_uni, res_hex)

    return (
        f"Decoded Shell Escape Output:\n"
        f"{res_final}"
    )


@tool(category="encoding")
def a1z26_cipher(data: str, mode: str = "decode") -> str:
    """Encode or decode A1Z26 cipher (1=A, 2=B, ..., 26=Z).

    :param data: Text string (encode) or numbers (e.g. '6-12-1-7' or '6 12 1 7' to decode)
    :param mode: 'decode' (numbers to letters) or 'encode' (letters to numbers)
    """
    import re
    mode_clean = mode.lower().strip()
    if mode_clean == "encode":
        out = []
        for ch in data.upper():
            if 'A' <= ch <= 'Z':
                out.append(str(ord(ch) - ord('A') + 1))
            elif ch == ' ':
                out.append("/")
            else:
                out.append(ch)
        return "-".join(out)
    else:
        # Decode: handles hyphens, commas, spaces
        tokens = re.split(r"[\s\-_,]+", data.strip())
        res = []
        for t in tokens:
            if t == "/":
                res.append(" ")
            elif t.isdigit():
                val = int(t)
                if 1 <= val <= 26:
                    res.append(chr(ord('A') + val - 1))
                else:
                    res.append(f"[{t}]")
            elif t:
                res.append(t)
        return f"A1Z26 Decoded: {''.join(res)}"


@tool(category="encoding")
def baudot_code(data: str, mode: str = "decode") -> str:
    """Decode or encode 5-bit Baudot / ITA2 teleprinter code.

    :param data: 5-bit binary tokens (e.g. '11000 10000 10010') or text to encode
    :param mode: 'decode' or 'encode'
    """
    LETTERS = {
        "00000": "", "00100": " ", "10111": "Q", "10011": "W", "00001": "E",
        "01010": "R", "10000": "T", "10101": "Y", "00111": "U", "00110": "I",
        "11000": "O", "10110": "P", "00011": "A", "00101": "S", "01001": "D",
        "01101": "F", "11010": "G", "10100": "H", "01011": "J", "01111": "K",
        "10010": "L", "10001": "Z", "10111": "X", "01110": "C", "11110": "V",
        "11001": "B", "10000": "N", "01100": "M", "11011": "<FIGS>", "11111": "<LTRS>"
    }

    mode_clean = mode.lower().strip()
    if mode_clean == "decode":
        bits = [b.strip() for b in data.replace(",", " ").split() if b.strip()]
        res = []
        for b in bits:
            res.append(LETTERS.get(b, "?"))
        return f"Baudot ITA2 Decoded: {''.join(res)}"
    else:
        REV = {v: k for k, v in LETTERS.items() if v and not v.startswith("<")}
        out = [REV.get(ch, "?????") for ch in data.upper() if ch in REV or ch == " "]
        return " ".join(out)


@tool(category="encoding")
def punycode_decode(domain_or_text: str) -> str:
    """Decode or encode RFC 3492 Punycode / Internationalized Domain Names (IDN, xn--...).

    :param domain_or_text: Punycode encoded string (e.g. 'xn--flg-tka.com') or unicode text
    """
    clean = domain_or_text.strip()
    results = []

    # Try IDNA decoding
    try:
        dec_idna = clean.encode("ascii").decode("idna")
        results.append(f"IDNA Decoded Domain: {dec_idna}")
    except Exception:
        pass

    # Try raw punycode decoding
    raw_puny = clean.replace("xn--", "")
    try:
        dec_raw = raw_puny.encode("ascii").decode("punycode")
        results.append(f"Punycode Decoded   : {dec_raw}")
    except Exception:
        pass

    if not results:
        # Try encoding instead
        try:
            enc = clean.encode("idna").decode("ascii")
            return f"IDNA / Punycode Encoded: {enc}"
        except Exception as ex:
            return f"Punycode processing failed: {ex}"

    return "\n".join(results)


@tool(category="encoding")
def dna_encoding(data: str, mode: str = "decode") -> str:
    """Decode or encode DNA nucleotide bases (A, C, G, T) to binary / ASCII text.

    :param data: DNA sequence (e.g. 'ACTG...') or ASCII text
    :param mode: 'decode' (DNA to text) or 'encode' (text to DNA)
    """
    DNA_MAP = {"A": "00", "C": "01", "G": "10", "T": "11"}
    REV_MAP = {"00": "A", "01": "C", "10": "G", "11": "T"}

    clean = data.strip().upper().replace(" ", "").replace("\n", "")
    mode_clean = mode.lower().strip()

    if mode_clean == "decode":
        bits = "".join(DNA_MAP.get(c, "") for c in clean)
        if len(bits) % 8 != 0:
            bits = bits[:len(bits) - (len(bits) % 8)]
        if not bits:
            return "ERROR: No valid DNA bases (A, C, G, T) found in data."
        byte_arr = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
        raw = bytes(byte_arr)
        try:
            return f"DNA Decoded Text (UTF-8):\n{raw.decode('utf-8')}\n\nHex:\n{raw.hex()}"
        except UnicodeDecodeError:
            return f"DNA Decoded Raw (Latin-1):\n{raw.decode('latin-1', errors='replace')}\n\nHex:\n{raw.hex()}"
    else:
        raw_b = data.encode("utf-8")
        bits = "".join(f"{b:08b}" for b in raw_b)
        dna_seq = "".join(REV_MAP[bits[i:i+2]] for i in range(0, len(bits), 2))
        return f"DNA Encoded Sequence:\n{dna_seq}"


@tool(category="encoding")
def base62_decode_encode(data: str, mode: str = "decode") -> str:
    """Encode or decode Base62 (0-9, a-z, A-Z) large integers and byte streams.

    :param data: String or integer to encode/decode
    :param mode: 'decode' or 'encode'
    """
    B62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    mode_clean = mode.lower().strip()

    if mode_clean == "decode":
        clean = data.strip()
        num = 0
        for ch in clean:
            idx = B62_CHARS.find(ch)
            if idx == -1:
                return f"ERROR: Invalid Base62 character '{ch}'"
            num = num * 62 + idx

        # Convert integer to bytes
        num_len = (num.bit_length() + 7) // 8 or 1
        raw_bytes = num.to_bytes(num_len, "big")
        try:
            return f"Base62 Decoded:\n  Integer : {num}\n  Text    : {raw_bytes.decode('utf-8')}\n  Hex     : {raw_bytes.hex()}"
        except UnicodeDecodeError:
            return f"Base62 Decoded:\n  Integer : {num}\n  Raw Hex : {raw_bytes.hex()}"
    else:
        try:
            num = int(data.strip())
        except ValueError:
            num = int.from_bytes(data.encode("utf-8"), "big")

        if num == 0:
            return "0"
        res = []
        while num > 0:
            res.append(B62_CHARS[num % 62])
            num //= 62
        return "".join(reversed(res))