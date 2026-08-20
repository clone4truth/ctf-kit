"""Classic ciphers: caesar, atbash, affine, vigenere, beaufort, playfair,
hill, railfence, columnar, bacon + frequency & IC analysis (vigenere key length)."""

import math
import re

from ..registry import tool
from ..utils import english_score, best_lines

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _clean(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", text).upper()


@tool(category="crypto")
def caesar(text: str, shift: int = -1) -> str:
    """Caesar shift. shift=-1 (default) = brute force all 25, ranked by English score.
    :param text: input text
    :param shift: Caesar shift amount
    """
    if shift < 0:
        results = []
        for s in range(26):
            out = "".join(chr((ord(c) - 65 + s) % 26 + 65) if "A" <= c <= "Z"
                          else chr((ord(c) - 97 + s) % 26 + 97) if "a" <= c <= "z" else c
                          for c in text)
            results.append((english_score(out.encode()), f"shift={s}: {out}"))
        return best_lines(results)
    s = shift % 26
    return "".join(chr((ord(c) - 65 + s) % 26 + 65) if "A" <= c <= "Z"
                   else chr((ord(c) - 97 + s) % 26 + 97) if "a" <= c <= "z" else c
                   for c in text)


@tool(category="crypto")
def atbash(text: str) -> str:
    """Atbash (A<->Z). Symmetric.
    :param text: input text
    """
    return "".join(chr(155 - ord(c)) if "A" <= c <= "Z"
                   else chr(219 - ord(c)) if "a" <= c <= "z" else c
                   for c in text)


@tool(category="crypto")
def affine(text: str, a: int = -1, b: int = 0) -> str:
    """Affine cipher decrypt: plain = a^-1 * (c - b) mod 26. a=-1 = brute force all valid (a,b).
    :param a: a
    :param text: input text
    :param b: b
    """
    def decrypt_one(ct, aa, bb):
        try:
            inv = pow(aa, -1, 26)
        except ValueError:
            return None
        return "".join(chr((inv * (ord(c) - 65 - bb)) % 26 + 65) if "A" <= c <= "Z"
                       else chr((inv * (ord(c) - 97 - bb)) % 26 + 97) if "a" <= c <= "z" else c
                       for c in ct)

    if a < 0:
        results = []
        for aa in range(26):
            if math.gcd(aa, 26) != 1:
                continue
            for bb in range(26):
                out = decrypt_one(text, aa, bb)
                if out:
                    results.append((english_score(out.encode()), f"a={aa} b={bb}: {out}"))
        return best_lines(results, top=8)
    out = decrypt_one(text, a, b)
    return out or "a must be coprime with 26 (gcd(a,26)==1)."


@tool(category="crypto")
def vigenere(ciphertext: str, key: str, decrypt: bool = True) -> str:
    """Vigenere. decrypt=True (default): cipher->plain. decrypt=False: plain->cipher.
    :param decrypt: decrypt
    :param key: secret key or password
    :param ciphertext: ciphertext to decrypt
    """
    key = _clean(key)
    if not key:
        return "Empty key."
    out, ki = [], 0
    for c in ciphertext:
        if "A" <= c <= "Z":
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 65 + (-k if decrypt else k)) % 26 + 65))
            ki += 1
        elif "a" <= c <= "z":
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 97 + (-k if decrypt else k)) % 26 + 97))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


@tool(category="crypto")
def beaufort(ciphertext: str, key: str) -> str:
    """Beaufort cipher (symmetric): plain = key - cipher mod 26.
    :param key: secret key or password
    :param ciphertext: ciphertext to decrypt
    """
    key = _clean(key)
    if not key:
        return "Empty key."
    out, ki = [], 0
    for c in ciphertext:
        if "A" <= c <= "Z":
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((k - (ord(c) - 65)) % 26 + 65))
            ki += 1
        elif "a" <= c <= "z":
            k = ord(key[ki % len(key)]) - 65
            out.append(chr((k - (ord(c) - 97)) % 26 + 97))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


@tool(category="crypto")
def railfence(text: str, rails: int, decrypt: bool = False) -> str:
    """Rail fence. decrypt=False (default): plain->cipher. decrypt=True: cipher->plain.
    :param text: input text
    :param rails: number of rails for rail fence
    :param decrypt: decrypt
    """
    n = len(text)
    cycle = 2 * (rails - 1)
    if decrypt:
        pattern = [min(i % cycle, cycle - i % cycle) for i in range(n)]
        counts = [pattern.count(r) for r in range(rails)]
        pos, rows = 0, []
        for c in counts:
            rows.append(text[pos:pos + c])
            pos += c
        idx = [0] * rails
        out = []
        for i in range(n):
            r = pattern[i]
            out.append(rows[r][idx[r]])
            idx[r] += 1
        return "".join(out)
    fence = [[] for _ in range(rails)]
    for i, c in enumerate(text):
        fence[min(i % cycle, cycle - i % cycle)].append(c)
    return "".join("".join(r) for r in fence)


@tool(category="crypto")
def playfair(ciphertext: str, key: str) -> str:
    """Playfair decrypt. Key deduplicates, 'J' merged into 'I' (standard CTF convention).
    :param key: secret key or password
    :param ciphertext: ciphertext to decrypt
    """
    key = _clean(key).replace("J", "I")
    table = []
    for c in key + ALPHA.replace("J", ""):
        if c not in table:
            table.append(c)
    pos = {c: (i // 5, i % 5) for i, c in enumerate(table)}
    ct = _clean(ciphertext).replace("J", "I")
    out = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i + 1] if i + 1 < len(ct) else "X"
        if a == b:
            b = "X"
        r1, c1 = pos[a]
        r2, c2 = pos[b]
        if r1 == r2:
            out += [table[r1 * 5 + (c1 - 1) % 5], table[r2 * 5 + (c2 - 1) % 5]]
        elif c1 == c2:
            out += [table[((r1 - 1) % 5) * 5 + c1], table[((r2 - 1) % 5) * 5 + c2]]
        else:
            out += [table[r1 * 5 + c2], table[r2 * 5 + c1]]
    return "".join(out).rstrip("X")


@tool(category="crypto")
def hill(ciphertext: str, a: int, b: int, c: int, d: int) -> str:
    """Hill cipher 2x2 decrypt. Key matrix [[a,b],[c,d]] must be invertible mod 26.
    :param b: b
    :param c: c
    :param ciphertext: ciphertext to decrypt
    :param d: RSA private exponent
    :param a: a
    """
    det = (a * d - b * c) % 26
    try:
        inv_det = pow(det, -1, 26)
    except ValueError:
        return "Matrix is not invertible mod 26 (det is not coprime with 26)."
    inv = [[(inv_det * d) % 26, (-inv_det * b) % 26],
           [(-inv_det * c) % 26, (inv_det * a) % 26]]
    ct = _clean(ciphertext)
    if len(ct) % 2:
        ct += "X"
    out = []
    for i in range(0, len(ct), 2):
        x, y = ord(ct[i]) - 65, ord(ct[i + 1]) - 65
        out.append(chr((inv[0][0] * x + inv[0][1] * y) % 26 + 65))
        out.append(chr((inv[1][0] * x + inv[1][1] * y) % 26 + 65))
    return "".join(out)


@tool(category="crypto")
def columnar(ciphertext: str, key: str, decrypt: bool = False) -> str:
    """Columnar transposition. decrypt=False: plain->cipher (X padded). decrypt=True: cipher->plain.
    :param decrypt: decrypt
    :param key: secret key or password
    :param ciphertext: ciphertext to decrypt
    """
    key = _clean(key)
    order = sorted(range(len(key)), key=lambda i: key[i])
    if decrypt:
        rows = math.ceil(len(ciphertext) / len(key))
        n_full = len(key) - (rows * len(key) - len(ciphertext))
        cols, pos = {}, 0
        for rank, col in enumerate(order):
            h = rows if col < n_full else rows - 1
            cols[col] = ciphertext[pos:pos + h]
            pos += h
        return "".join(cols[i % len(key)][i // len(key)] for i in range(len(ciphertext)))
    text = _clean(ciphertext)
    if len(text) % len(key):
        text += "X" * (len(key) - len(text) % len(key))
    cols = {c: [] for c in range(len(key))}
    for i, ch in enumerate(text):
        cols[i % len(key)].append(ch)
    return "".join("".join(cols[c]) for c in order)


@tool(category="crypto")
def bacon(text: str, variant: str = "24") -> str:
    """Bacon's cipher. Decode A/B pairs (case-insensitive). variant 24 (I/J, U/V) or 26.
    :param text: input text
    :param variant: cipher variant
    """
    pairs = {
        "24": {f"{i:05b}": chr(65 + i) if i < 24 else "I/J" for i in range(24)},
        "26": {f"{i:05b}": chr(65 + i) for i in range(26)},
    }
    table = pairs[variant]
    seq = re.sub(r"[^A-Za-z]", "", text)
    seq = "".join("0" if c.lower() in "ab" else c for c in seq)
    if re.search(r"[^01]", seq):
        return "A/B mode: only a/A (0) and b/B (1) letters are used; the rest are ignored. Input does not match."
    out = "".join(table.get(seq[i:i + 5], "?") for i in range(0, len(seq) - 4, 5))
    return out or "Not enough bits (needs a multiple of 5)."


@tool(category="crypto")
def frequency(text: str) -> str:
    """Letter frequency + bigrams (for substitution ciphers).
    :param text: input text
    """
    letters = re.sub(r"[^A-Za-z]", "", text).lower()
    if not letters:
        return "No letters found."
    counts = {c: letters.count(c) for c in set(letters)}
    bigrams = {}
    for i in range(len(letters) - 1):
        bg = letters[i:i + 2]
        bigrams[bg] = bigrams.get(bg, 0) + 1
    n = len(letters)
    single = "\n".join(f"{c}: {v} ({100*v/n:.2f}%)" for c, v in sorted(counts.items(), key=lambda x: -x[1]))
    top_bg = "\n".join(f"{k}: {v}" for k, v in sorted(bigrams.items(), key=lambda x: -x[1])[:10])
    return f"total {n} letters\n\nUNIGRAM:\n{single}\n\nBIGRAM TOP 10:\n{top_bg}"


@tool(category="crypto")
def vigenere_keylength(ciphertext: str, max_len: int = 20) -> str:
    """Guess the Vigenere key length via Index of Coincidence (Kasiski).
    :param max_len: max len
    :param ciphertext: ciphertext to decrypt
    """
    ct = _clean(ciphertext)
    if len(ct) < 40:
        return "Text too short for IC analysis (need ~40+ letters)."
    rows = []
    for m in range(1, max_len + 1):
        ics = []
        for r in range(m):
            chunk = ct[r::m]
            if len(chunk) < 4:
                continue
            counts = [chunk.count(c) for c in set(chunk)]
            n = len(chunk)
            ic = sum(k * (k - 1) for k in counts) / (n * (n - 1)) if n > 1 else 0
            ics.append(ic)
        if not ics:
            continue
        avg = sum(ics) / len(ics)
        rows.append((abs(avg - 0.066), m, avg))
    rows.sort()
    out = []
    for _, m, ic in rows[:5]:
        out.append(f"key length {m}: IC avg = {ic:.4f} (English ~0.066, random ~0.038)")
    return "\n".join(out)


@tool(category="crypto")
def rot47(text: str, decrypt: bool = True) -> str:
    """ROT47 (ASCII 33-126). Symmetric.
    :param text: input text
    :param decrypt: decrypt
    """
    return "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in text)


@tool(category="crypto")
def autokey_cipher(text: str, key: str, decrypt: bool = True) -> str:
    """Autokey cipher (Vigenere variant where the key extends itself with the plaintext).

    :param text: Ciphertext or plaintext
    :param key: Initial key word
    :param decrypt: True to decrypt, False to encrypt
    """
    clean_k = [ord(c) - 65 for c in key.upper() if 'A' <= c <= 'Z']
    if not clean_k:
        return "ERROR: Key must contain alphabetic characters."

    out = []
    if not decrypt:
        # Encrypt
        full_key = list(clean_k)
        for ch in text:
            if 'A' <= ch.upper() <= 'Z':
                is_upper = ch.isupper()
                p_val = ord(ch.upper()) - 65
                k_val = full_key[len(out)] if len(out) < len(full_key) else 0
                full_key.append(p_val)
                c_val = (p_val + k_val) % 26
                out.append(chr(65 + c_val) if is_upper else chr(97 + c_val))
            else:
                out.append(ch)
        return "".join(out)
    else:
        # Decrypt
        full_key = list(clean_k)
        for ch in text:
            if 'A' <= ch.upper() <= 'Z':
                is_upper = ch.isupper()
                c_val = ord(ch.upper()) - 65
                k_val = full_key[len(out)]
                p_val = (c_val - k_val) % 26
                full_key.append(p_val)
                out.append(chr(65 + p_val) if is_upper else chr(97 + p_val))
            else:
                out.append(ch)
        return "".join(out)


@tool(category="crypto")
def gronsfeld_cipher(text: str, key_digits: str, decrypt: bool = True) -> str:
    """Gronsfeld cipher (Vigenere variant using numeric key digits 0-9).

    :param text: Ciphertext or plaintext
    :param key_digits: Numeric key string (e.g. '12345')
    :param decrypt: True to decrypt, False to encrypt
    """
    digits = [int(d) for d in key_digits if d.isdigit()]
    if not digits:
        return "ERROR: key_digits must contain numeric characters (0-9)."

    out = []
    k_idx = 0
    sign = -1 if decrypt else 1
    for ch in text:
        if 'A' <= ch <= 'Z':
            shift = digits[k_idx % len(digits)] * sign
            out.append(chr(65 + (ord(ch) - 65 + shift) % 26))
            k_idx += 1
        elif 'a' <= ch <= 'z':
            shift = digits[k_idx % len(digits)] * sign
            out.append(chr(97 + (ord(ch) - 97 + shift) % 26))
            k_idx += 1
        else:
            out.append(ch)
    return "".join(out)


@tool(category="crypto")
def bifid_cipher(text: str, key: str = "KEYWORD", period: int = 5, decrypt: bool = True) -> str:
    """Bifid Cipher encoder/decoder (fractionated Polybius square cipher with period).

    :param text: Ciphertext or plaintext
    :param key: Alphabet key for Polybius square (J replaced by I)
    :param period: Block period length (default 5)
    :param decrypt: True to decrypt, False to encrypt
    """
    clean_k = []
    for c in key.upper().replace("J", "I"):
        if 'A' <= c <= 'Z' and c not in clean_k:
            clean_k.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in clean_k:
            clean_k.append(c)

    pos_map = {clean_k[i]: (i // 5 + 1, i % 5 + 1) for i in range(25)}
    grid_map = {(i // 5 + 1, i % 5 + 1): clean_k[i] for i in range(25)}

    clean_t = [c for c in text.upper().replace("J", "I") if c in pos_map]
    if not clean_t:
        return "ERROR: No valid alphabetic characters found in text."

    out = []
    for i in range(0, len(clean_t), period):
        block = clean_t[i:i+period]
        if not decrypt:
            rows = [pos_map[c][0] for c in block]
            cols = [pos_map[c][1] for c in block]
            combined = rows + cols
            for j in range(0, len(combined), 2):
                out.append(grid_map[(combined[j], combined[j+1])])
        else:
            coords = []
            for c in block:
                r, cl = pos_map[c]
                coords.extend([r, cl])
            mid = len(coords) // 2
            rows = coords[:mid]
            cols = coords[mid:]
            for r, cl in zip(rows, cols):
                out.append(grid_map[(r, cl)])

    return "".join(out)


@tool(category="crypto")
def rc4_crypt(data: str, key: str, data_is_hex: bool = False) -> str:
    """Encrypt or decrypt data using the RC4 (Rivest Cipher 4 / ARC4) stream cipher.

    :param data: Input text or hex string
    :param key: Secret key string
    :param data_is_hex: Set to True if data is hex-encoded
    """
    key_b = key.encode("utf-8")
    if not key_b:
        return "ERROR: Key cannot be empty."

    if data_is_hex:
        clean_h = data.strip().replace("0x", "").replace(" ", "").replace("\n", "")
        try:
            data_b = bytes.fromhex(clean_h)
        except ValueError:
            return "ERROR: Invalid hex input in data."
    else:
        data_b = data.encode("latin-1")

    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_b[i % len(key_b)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    out = bytearray()
    for b in data_b:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(b ^ k)

    try:
        text_utf8 = out.decode("utf-8")
        return f"RC4 Result (UTF-8 Text):\n{text_utf8}\n\nHex:\n{out.hex()}"
    except UnicodeDecodeError:
        return f"RC4 Result (Latin-1 / Binary):\n{out.decode('latin-1', errors='replace')}\n\nHex:\n{out.hex()}"