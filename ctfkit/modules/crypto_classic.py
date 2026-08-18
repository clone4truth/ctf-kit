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
    """Caesar shift. shift=-1 (default) = brute force all 25, ranked by English score."""
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
    """Atbash (A<->Z). Symmetric."""
    return "".join(chr(155 - ord(c)) if "A" <= c <= "Z"
                   else chr(219 - ord(c)) if "a" <= c <= "z" else c
                   for c in text)


@tool(category="crypto")
def affine(text: str, a: int = -1, b: int = 0) -> str:
    """Affine cipher decrypt: plain = a^-1 * (c - b) mod 26. a=-1 = brute force all valid (a,b)."""
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
    """Vigenere. decrypt=True (default): cipher->plain. decrypt=False: plain->cipher."""
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
    """Beaufort cipher (symmetric): plain = key - cipher mod 26."""
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
    """Rail fence. decrypt=False (default): plain->cipher. decrypt=True: cipher->plain."""
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
    """Playfair decrypt. Key deduplicates, 'J' merged into 'I' (standard CTF convention)."""
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
    """Hill cipher 2x2 decrypt. Key matrix [[a,b],[c,d]] must be invertible mod 26."""
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
    """Columnar transposition. decrypt=False: plain->cipher (X padded). decrypt=True: cipher->plain."""
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
    """Bacon's cipher. Decode A/B pairs (case-insensitive). variant 24 (I/J, U/V) or 26."""
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
    """Letter frequency + bigrams (for substitution ciphers)."""
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
    """Guess the Vigenere key length via Index of Coincidence (Kasiski)."""
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
    """ROT47 (ASCII 33-126). Symmetric."""
    return "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in text)