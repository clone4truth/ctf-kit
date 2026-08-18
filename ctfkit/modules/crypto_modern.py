"""Modern crypto: XOR, RSA, AES (all modes), hash id/generate, CBC bit-flip."""

import hashlib
import re

from ..registry import tool
from ..utils import from_hex, from_b64, b64, printable


@tool(category="crypto")
def xor_brute(data_hex: str, key_length: int = 1) -> str:
    """Brute-force XOR with a multi-byte key. key_length=1: single byte. key_length>1: frequency-based key recovery per position."""
    from ..utils import english_score, best_lines
    data = from_hex(data_hex)
    results = []
    for kl in range(1, key_length + 1):
        key = bytearray()
        for pos in range(kl):
            best = []
            for k in range(256):
                out = bytes(data[i] ^ k for i in range(pos, len(data), kl))
                best.append((english_score(out), k))
            best.sort(reverse=True)
            key.append(best[0][1])
        out = bytes(data[i] ^ key[i % kl] for i in range(len(data)))
        results.append((english_score(out), f"key_len={kl} key={bytes(key).hex()} ({printable(bytes(key))}): {out.decode('utf-8', 'replace')}"))
    return best_lines(results)


@tool(category="crypto")
def xor_keyed(data_hex: str, key_hex: str) -> str:
    """XOR with a known key (hex)."""
    data = from_hex(data_hex)
    key = from_hex(key_hex)
    if not key:
        return "Empty key."
    out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return f"hex: {out.hex()}\nascii: {printable(out)}"


@tool(category="crypto")
def rsa_decrypt(n: int, e: int, ciphertext: int, p: int = 0, q: int = 0, d: int = 0) -> str:
    """RSA decrypt. Provide p/q or d. Without both: try trial-division factoring (small n). Auto-tries paddings."""
    if not d:
        if not p:
            for i in range(2, int(n ** 0.5) + 1):
                if n % i == 0:
                    p, q = i, n // i
                    break
            if not p:
                return "n cannot be factored by trial division. Provide p, q, or d."
        try:
            d = pow(e, -1, (p - 1) * (q - 1))
        except ValueError:
            return "e is not coprime with phi. Check the e value."
    m = pow(ciphertext, d, n)
    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    res = [f"d = {d}", f"plaintext hex: {pt.hex()}"]
    if all(32 <= b < 127 or b in (10, 13) for b in pt[:2000]):
        res.append(f"plaintext ascii: {pt.decode('utf-8', 'replace')}")
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as pad
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
        pub = rsa_mod.RSAPublicNumbers(e, n).public_key()
        attempts = [
            ("PKCS1v15", pad.PKCS1v15()),
            ("OAEP-SHA1", pad.OAEP(pad.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
            ("OAEP-SHA256", pad.OAEP(pad.MGF1(hashes.SHA256()), hashes.SHA256(), None)),
        ]
        for name, p in attempts:
            try:
                res.append(f"{name}: {pub.decrypt(pt, p).decode('utf-8', 'replace')}")
            except Exception:
                pass
    except Exception:
        pass
    return "\n".join(res)


@tool(category="crypto")
def rsa_small_e(n: int, e: int, ciphertext: int) -> str:
    """RSA with a small exponent (e=3 etc): try taking the e-th root without mod n (m^e < n)."""
    try:
        m = round(ciphertext ** (1 / e))
        while m ** e < ciphertext:
            m += 1
        while m ** e > ciphertext:
            m -= 1
        if m ** e != ciphertext:
            return "Not a small-e attack (m^e >= n, or ciphertext is not a perfect power)."
        pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
        return f"m = {m}\nhex: {pt.hex()}\nascii: {printable(pt)}"
    except Exception as ex:
        return f"Failed: {ex}"


_AES_MODES = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM"}


@tool(category="crypto")
def aes_crypt(data_b64: str, key_b64: str, mode: str = "ECB", iv_b64: str = "",
              tag_b64: str = "", encrypt: bool = False) -> str:
    """AES decrypt/encrypt. mode: ECB/CBC/CFB/OFB/CTR/GCM. Input/output base64. Auto-tries PKCS7 & no padding."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    mode = mode.upper()
    if mode not in _AES_MODES:
        return f"Mode must be one of: {sorted(_AES_MODES)}"
    data = from_b64(data_b64)
    key = from_b64(key_b64)
    iv = from_b64(iv_b64) if iv_b64 else b"\x00" * 16
    tag = from_b64(tag_b64) if tag_b64 else None
    if mode == "GCM" and not encrypt and not tag:
        return "GCM decrypt requires tag_b64."
    results = []
    for pad_name, do_pad in [("PKCS7", True), ("no-pad", False)]:
        try:
            if mode == "ECB":
                cipher = Cipher(algorithms.AES(key), modes.ECB())
            elif mode == "CTR":
                cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            elif mode == "GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            else:
                cipher = Cipher(algorithms.AES(key), getattr(modes, mode)(iv))
            op = cipher.encryptor() if encrypt else cipher.decryptor()
            inp = data
            if encrypt and do_pad and mode in ("ECB", "CBC"):
                padlen = 16 - len(inp) % 16
                inp += bytes([padlen]) * padlen
            out = op.update(inp) + op.finalize()
            if not encrypt and do_pad and mode in ("ECB", "CBC") and out and 1 <= out[-1] <= 16:
                out = out[:-out[-1]]
            results.append(f"[{mode} {pad_name}]\nb64: {b64(out)}\nhex: {out.hex()}")
            results.append(f"ascii: {printable(out)}")
        except Exception as ex:
            results.append(f"[{mode} {pad_name}] failed: {ex}")
    return "\n".join(results)


@tool(category="crypto")
def aes_cbc_bitflip(block_hex: str, original: str, target: str, block_index: int = 0) -> str:
    """CBC bit-flip: compute C' so the next plaintext block changes from 'original' to 'target'.
    block_hex = ciphertext block index (block_index), original = known plaintext, target = desired plaintext.
    """
    c = from_hex(block_hex)
    orig = original.encode()
    tgt = target.encode()
    if not (len(orig) == len(tgt) == len(c)):
        return "original, target, and ciphertext block lengths must be equal."
    out = bytes(c[i] ^ orig[i] ^ tgt[i] for i in range(len(c)))
    return f"new ciphertext block (hex): {out.hex()}\n(IV for block 0: {out.hex()})"


@tool(category="crypto")
def hash_identify(hash_str: str) -> str:
    """Identify hash type: bcrypt/$6$/MD5/SHA-1/SHA-2/NTLM/MD4 etc. from length & prefix."""
    h = hash_str.strip()
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        return "bcrypt"
    if h.startswith("$6$"):
        return "SHA-512 crypt"
    if h.startswith("$5$"):
        return "SHA-256 crypt"
    if h.startswith("$1$"):
        return "MD5 crypt"
    if h.startswith("$apr1$"):
        return "Apache MD5 (apr1)"
    if h.startswith("$sha1$"):
        return "SHA-1 crypt"
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        return "MD5 / MD4 / NTLM / LM (32 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{40}", h):
        return "SHA-1 (40 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{56}", h):
        return "SHA-224 (56 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{64}", h):
        return "SHA-256 / SHA3-256 / RIPEMD-160? (64 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{96}", h):
        return "SHA-384 (96 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{128}", h):
        return "SHA-512 / SHA3-512 / Whirlpool (128 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{16}", h):
        return "CRC-64 / MySQL (16 hex)"
    if re.fullmatch(r"[0-9a-fA-F]{8}", h):
        return "CRC-32 / Adler-32 (8 hex)"
    return f"Unknown format ({len(h)} chars). Check hashcat --example-hashes."


@tool(category="crypto")
def hash_generate(text: str, algorithm: str = "md5") -> str:
    """Generate a hash. algorithm: md5/sha1/sha224/sha256/sha384/sha512/sha3_256/sha3_512/md4/ntlm."""
    alg = algorithm.lower().replace("-", "_")
    if alg in ("ntlm", "md4"):
        if alg == "ntlm":
            try:
                return hashlib.new("md4", text.encode("utf-16-le")).hexdigest()
            except ValueError:
                return "MD4 not available in this OpenSSL build. Try 'md4' through another tool."
        return hashlib.new("md4", text.encode()).hexdigest()
    try:
        return getattr(hashlib, alg)(text.encode()).hexdigest()
    except AttributeError:
        return f"Unknown algorithm '{algorithm}'."


@tool(category="crypto")
def hash_crack_common(hash_hex: str, wordlist_path: str = "", max_lines: int = 100000) -> str:
    """Crack a common hash (md5/sha1/sha256/sha512) with a wordlist. Default: small bundled wordlist."""
    import os
    h = hash_hex.strip().lower()
    alg = hash_identify(h)
    algo = "md5"
    if "SHA-1" in alg:
        algo = "sha1"
    elif "SHA-256" in alg:
        algo = "sha256"
    elif "SHA-512" in alg:
        algo = "sha512"
    path = wordlist_path or os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "common.txt")
    if not os.path.exists(path):
        return f"Wordlist not found: {path}. Provide wordlist_path (e.g. rockyou.txt)."
    found = None
    for i, line in enumerate(open(path, encoding="utf-8", errors="ignore")):
        if i >= max_lines:
            break
        word = line.strip()
        if hashlib.new(algo, word.encode()).hexdigest() == h:
            found = word
            break
    if found:
        return f"Found ({algo}): {found}"
    return f"Not found in {path} (max {max_lines} lines)."