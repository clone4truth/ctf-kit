"""Modern crypto: XOR, RSA, AES (all modes), hash id/generate, CBC bit-flip."""

import hashlib
import re
import urllib.parse

from ..registry import tool
from ..utils import from_hex, from_b64, b64, printable


@tool(category="crypto")
def xor_brute(data_hex: str, key_length: int = 1) -> str:
    """Brute-force XOR with a multi-byte key. key_length=1: single byte. key_length>1: frequency-based key recovery per position.
    :param data_hex: hex-encoded input data
    :param key_length: key length in bits
    """
    from ..utils import english_score, best_lines
    data = from_hex(data_hex)
    if not data:
        return "Empty or invalid hex data."
    key_length = max(1, min(key_length, len(data)))
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
    """XOR with a known key (hex).
    :param key_hex: hex-encoded key
    :param data_hex: hex-encoded input data
    """
    data = from_hex(data_hex)
    key = from_hex(key_hex)
    if not key:
        return "Empty key."
    out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return f"hex: {out.hex()}\nascii: {printable(out)}"


@tool(category="crypto")
def rsa_decrypt(n: int, e: int, ciphertext: int, p: int = 0, q: int = 0, d: int = 0) -> str:
    """RSA decrypt. Provide p/q or d. Without both: try trial-division factoring (small n). Auto-tries paddings.
    :param e: RSA public exponent
    :param ciphertext: ciphertext to decrypt
    :param d: RSA private exponent
    :param q: RSA prime q
    :param p: RSA prime p
    :param n: RSA modulus
    """
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
    """RSA with a small exponent (e=3 etc): try taking the e-th root without mod n (m^e < n).
    :param n: RSA modulus
    :param e: RSA public exponent
    :param ciphertext: ciphertext to decrypt
    """
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
    """AES decrypt/encrypt. mode: ECB/CBC/CFB/OFB/CTR/GCM. Input/output base64. Auto-tries PKCS7 & no padding.
    :param mode: cipher mode
    :param tag_b64: tag b64
    :param key_b64: key b64
    :param iv_b64: iv b64
    :param data_b64: data b64
    :param encrypt: encrypt
    """
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
    :param original: original plaintext
    :param block_index: block index
    :param block_hex: hex-encoded cipher block
    :param target: target
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
    """Identify hash type: bcrypt/$6$/MD5/SHA-1/SHA-2/NTLM/MD4 etc. from length & prefix.
    :param hash_str: hash string to identify/analyze
    """
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
    """Generate a hash. algorithm: md5/sha1/sha224/sha256/sha384/sha512/sha3_256/sha3_512/md4/ntlm.
    :param text: input text
    :param algorithm: hash algorithm name
    """
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
    """Crack a common hash (md5/sha1/sha256/sha512) with a wordlist. Default: small bundled wordlist.
    :param hash_hex: hash hex
    :param max_lines: max lines
    :param wordlist_path: wordlist path
    """
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


def _isqrt(n: int) -> int:
    """Integer square root using math.isqrt or Newton's method."""
    import math
    if hasattr(math, "isqrt"):
        return math.isqrt(n)
    if n <= 0:
        return 0
    x = int(math.isqrt(n))
    return x


@tool(category="crypto")
def rsa_wiener(n: int, e: int, ciphertext: int = 0) -> str:
    """Wiener's attack for RSA with small private exponent d (d < 1/3 * n^(1/4)).
    :param n: RSA modulus
    :param e: RSA public exponent
    :param ciphertext: ciphertext to decrypt
    """
    import math

    def cont_frac(num, den):
        while den:
            q = num // den
            yield q
            num, den = den, num - q * den

    def convergents(cf):
        n0, d0 = 0, 1
        n1, d1 = 1, 0
        for q in cf:
            n = q * n1 + n0
            d = q * d1 + d0
            yield n, d
            n0, d0 = n1, d1
            n1, d1 = n, d

    for k, d in convergents(cont_frac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr >= 0:
            sq = _isqrt(discr)
            if sq * sq == discr and (s + sq) % 2 == 0:
                p = (s + sq) // 2
                q = (s - sq) // 2
                if p * q == n:
                    res = [
                        "🏆 Wiener's Attack Succeeded!",
                        f"p = {p}",
                        f"q = {q}",
                        f"d = {d}",
                        f"phi = {phi}",
                    ]
                    if ciphertext:
                        m = pow(ciphertext, d, n)
                        pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
                        res.append(f"plaintext hex: {pt.hex()}")
                        res.append(f"plaintext ascii: {printable(pt)}")
                    return "\n".join(res)
    return "Wiener's attack failed (d might not be small enough, d >= 1/3 * n^0.25)."


@tool(category="crypto")
def rsa_fermat(n: int, e: int = 65537, ciphertext: int = 0, max_iter: int = 1000000) -> str:
    """Fermat factorization when prime factors p and q are close (|p - q| is small).
    :param n: RSA modulus
    :param e: RSA public exponent
    :param max_iter: maximum iterations (control knob)
    :param ciphertext: ciphertext to decrypt
    """
    import math
    a = _isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    step = 0
    while step < max_iter:
        b = _isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                phi = (p - 1) * (q - 1)
                try:
                    d = pow(e, -1, phi)
                except ValueError:
                    d = 0
                res = [
                    f"🏆 Fermat Factorization Succeeded in {step} iterations!",
                    f"p = {p}",
                    f"q = {q}",
                    f"diff = {abs(p - q)}",
                    f"d = {d}",
                ]
                if ciphertext and d:
                    m = pow(ciphertext, d, n)
                    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
                    res.append(f"plaintext hex: {pt.hex()}")
                    res.append(f"plaintext ascii: {printable(pt)}")
                return "\n".join(res)
        a += 1
        b2 = a * a - n
        step += 1
    return f"Fermat factorization reached max iterations ({max_iter}). Primes are not close enough."


@tool(category="crypto")
def rsa_common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> str:
    """Common Modulus attack: same n, different coprime public exponents e1, e2 on the same message.
    :param e2: e2
    :param c1: c1
    :param e1: e1
    :param n: RSA modulus
    :param c2: c2
    """
    import math

    def ext_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = ext_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return g, x, y

    g, a, b = ext_gcd(e1, e2)
    if g != 1:
        return f"Exponents are not coprime (gcd(e1,e2) = {g}). Cannot perform attack."

    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return (f"🏆 Common Modulus Attack Succeeded!\n"
            f"m (int): {m}\n"
            f"plaintext hex: {pt.hex()}\n"
            f"plaintext ascii: {printable(pt)}")


@tool(category="crypto")
def rsa_hastad(ciphertexts_csv: str, moduli_csv: str, e: int = 3) -> str:
    """Hastad's Broadcast attack (Chinese Remainder Theorem for identical message sent with small e).
    :param ciphertexts_csv: comma-separated ciphertexts
    :param moduli_csv: comma-separated RSA moduli
    :param e: RSA public exponent
    """
    import math
    from functools import reduce

    c_list = [int(x.strip(), 0) for x in ciphertexts_csv.split(",") if x.strip()]
    n_list = [int(x.strip(), 0) for x in moduli_csv.split(",") if x.strip()]

    if len(c_list) < e or len(n_list) < e:
        return f"Need at least e={e} ciphertexts and moduli (provided {len(c_list)} ciphertexts, {len(n_list)} moduli)."

    # CRT
    N = reduce(lambda a, b: a * b, n_list[:e])
    result = 0
    for c_i, n_i in zip(c_list[:e], n_list[:e]):
        m_i = N // n_i
        inv = pow(m_i, -1, n_i)
        result = (result + c_i * m_i * inv) % N

    # Compute e-th root
    m = round(result ** (1 / e))
    while m ** e < result:
        m += 1
    while m ** e > result:
        m -= 1
    if m ** e != result:
        return f"e-th root not exact: m^e != CRT result. Check if message was padded or different per recipient."

    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return (f"🏆 Hastad Broadcast Attack Succeeded!\n"
            f"m (int): {m}\n"
            f"plaintext hex: {pt.hex()}\n"
            f"plaintext ascii: {printable(pt)}")


@tool(category="crypto")
def rsa_parse_key(key_data_or_path: str) -> str:
    """Parse RSA public or private keys (.pem / .pub / .key / OpenSSH) into n, e, d, p, q.
    :param key_data_or_path: key material or path to key file
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import os

    raw = key_data_or_path.strip()
    if os.path.exists(raw):
        data = open(raw, "rb").read()
    else:
        data = raw.encode()

    try:
        # Try private key
        key = serialization.load_pem_private_key(data, password=None)
        nums = key.private_numbers()
        pub = nums.public_numbers
        return (f"RSA PRIVATE KEY:\n"
                f"n (modulus, {key.key_size} bits) = {pub.n}\n"
                f"e (public exp) = {pub.e}\n"
                f"d (private exp) = {nums.d}\n"
                f"p = {nums.p}\n"
                f"q = {nums.q}\n"
                f"dmp1 (d mod p-1) = {nums.dmp1}\n"
                f"dmq1 (d mod q-1) = {nums.dmq1}\n"
                f"iqmp (q^-1 mod p) = {nums.iqmp}")
    except Exception:
        pass

    try:
        # Try public key PEM
        key = serialization.load_pem_public_key(data)
        nums = key.public_numbers()
        return (f"RSA PUBLIC KEY:\n"
                f"n (modulus, {key.key_size} bits) = {nums.n}\n"
                f"e (public exp) = {nums.e}")
    except Exception:
        pass

    try:
        # Try OpenSSH public key
        key = serialization.load_ssh_public_key(data)
        nums = key.public_numbers()
        return (f"RSA SSH PUBLIC KEY:\n"
                f"n (modulus, {key.key_size} bits) = {nums.n}\n"
                f"e (public exp) = {nums.e}")
    except Exception as ex:
        return f"Failed to parse RSA key: {ex}"


@tool(category="crypto")
def xor_crib_drag(ct1_hex: str, ct2_hex: str = "", crib: str = "flag{") -> str:
    """Known Plaintext Attack (KPA) / Crib dragging against one ciphertext or two ciphertexts sharing a key.
    :param crib: crib
    :param ct1_hex: ct1 hex
    :param ct2_hex: ct2 hex
    """
    c1 = from_hex(ct1_hex)
    crib_bytes = crib.encode("utf-8")

    if not ct2_hex:
        # Single ciphertext crib drag: assume crib starts or exists at offset i
        results = [f"Dragging crib {crib!r} against single ciphertext ({len(c1)} bytes):"]
        for i in range(len(c1) - len(crib_bytes) + 1):
            key_fragment = bytes(c1[i + j] ^ crib_bytes[j] for j in range(len(crib_bytes)))
            results.append(f"offset {i:3d}: key fragment (hex)={key_fragment.hex()} ({printable(key_fragment)})")
        return "\n".join(results[:50])

    c2 = from_hex(ct2_hex)
    min_len = min(len(c1), len(c2))
    xored = bytes(c1[k] ^ c2[k] for k in range(min_len))

    results = [
        f"C1 ⊕ C2 length: {min_len} bytes",
        f"Dragging crib {crib!r} across C1 ⊕ C2 (reveals other plaintext if crib is in C1 or C2):\n"
    ]
    for i in range(min_len - len(crib_bytes) + 1):
        revealed = bytes(xored[i + j] ^ crib_bytes[j] for j in range(len(crib_bytes)))
        results.append(f"pos {i:3d}: {printable(revealed)}  (hex: {revealed.hex()})")

    return "\n".join(results[:60])


@tool(category="crypto")
def lcg_solve(states_csv: str, m: int = 0) -> str:
    """Recover LCG parameters (a, c, m) from consecutive outputs (x0, x1, x2, ...) and predict future states.
    :param m: m
    :param states_csv: comma-separated states
    """
    import math
    from functools import reduce

    states = [int(x.strip(), 0) for x in states_csv.split(",") if x.strip()]
    if len(states) < 3:
        return "Need at least 3 consecutive states (e.g. '123, 456, 789')."

    if not m:
        if len(states) < 6:
            return "Modulus m unknown: need at least 6 consecutive states to reliably deduce m via GCD."
        diffs = [s1 - s0 for s0, s1 in zip(states[:-1], states[1:])]
        zeroes = [t2 * t0 - t1 * t1 for t0, t1, t2 in zip(diffs[:-2], diffs[1:-1], diffs[2:])]
        m = abs(reduce(math.gcd, zeroes))
        if m <= 1:
            return "Could not automatically deduce modulus m. Please supply m."

    x0, x1, x2 = states[0], states[1], states[2]
    try:
        a = ((x2 - x1) * pow(x1 - x0, -1, m)) % m
        c = (x1 - a * x0) % m
    except ValueError:
        return f"Failed to compute modular inverse with m={m}. (x1 - x0) and m are not coprime."

    # Predict next 5 states
    curr = states[-1]
    predictions = []
    for _ in range(5):
        curr = (a * curr + c) % m
        predictions.append(str(curr))

    return (f"🏆 LCG Parameters Recovered!\n"
            f"Multiplier (a) = {a}\n"
            f"Increment  (c) = {c}\n"
            f"Modulus    (m) = {m}\n"
            f"Next 5 states  = {', '.join(predictions)}")


@tool(category="crypto")
def hash_length_extension(original_data: str, append_data: str, original_hash: str,
                          key_length: int = 16, algorithm: str = "md5") -> str:
    """Generate Hash Length Extension payload and forged signature for H(key || original_data).
    :param original_data: original data
    :param algorithm: hash algorithm name
    :param append_data: data to append
    :param original_hash: original hash value
    :param key_length: key length in bits
    """
    import struct
    alg = algorithm.lower().replace("-", "_")

    def pad_md5(msg_len):
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
        pad += struct.pack("<Q", msg_len * 8)
        return pad

    def pad_sha1_256(msg_len):
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
        pad += struct.pack(">Q", msg_len * 8)
        return pad

    orig_b = original_data.encode("latin-1")
    app_b = append_data.encode("latin-1")
    total_orig_len = key_length + len(orig_b)

    if alg == "md5":
        glue_padding = pad_md5(total_orig_len)
    else:
        glue_padding = pad_sha1_256(total_orig_len)

    forged_data = orig_b + glue_padding + app_b

    return (f"Hash Length Extension for {alg.upper()}:\n"
            f"Key length assumed : {key_length} bytes\n"
            f"Original Data      : {original_data!r}\n"
            f"Appended Data      : {append_data!r}\n"
            f"Glue Padding (hex) : {glue_padding.hex()}\n"
            f"Full Payload (hex) : {forged_data.hex()}\n"
            f"URL-Encoded Payload: {urllib.parse.quote(forged_data)}\n"
            f"Note: To compute the exact final hash, pass the internal state derived from {original_hash} into {alg} compressor.")


@tool(category="crypto")
def aes_gcm_nonce_reuse(ct1_hex: str, ct2_hex: str, pt1_hex: str = "") -> str:
    """Recover plaintext when two AES-GCM messages reuse a nonce: ct1^ct2 = pt1^pt2. Provide one known plaintext to recover the other.
    :param pt1_hex: pt1 hex
    :param ct1_hex: ct1 hex
    :param ct2_hex: ct2 hex
    """
    try:
        c1, c2 = from_hex(ct1_hex), from_hex(ct2_hex)
    except Exception as ex:
        return f"ERROR: invalid ciphertext hex: {ex}"
    if not c1 or not c2:
        return "ERROR: empty ciphertext."
    n = min(len(c1), len(c2))
    keystream = bytes(a ^ b for a, b in zip(c1[:n], c2[:n]))
    out = [f"keystream (ct1^ct2): {keystream.hex()}"]
    if pt1_hex.strip():
        try:
            p1 = from_hex(pt1_hex)
        except Exception as ex:
            return f"ERROR: invalid plaintext hex: {ex}"
        m = min(n, len(p1))
        p2 = bytes(k ^ x for k, x in zip(keystream[:m], p1[:m]))
        out.append(f"recovered pt2 hex: {p2.hex()}")
        out.append(f"recovered pt2 ascii: {printable(p2)}")
    else:
        out.append("pt1_hex empty: supply the known plaintext (hex) to recover the other message.")
    return "\n".join(out)


def _ecc_add(px, py, qx, qy, a, p):
    if px is None:
        return qx, qy
    if qx is None:
        return px, py
    if px == qx and (py + qy) % p == 0:
        return None, None
    if px == qx and py == qy:
        lam = (3 * px * px + a) * pow(2 * py, -1, p) % p
    else:
        lam = (qy - py) * pow(qx - px, -1, p) % p
    rx = (lam * lam - px - qx) % p
    ry = (lam * (px - rx) - py) % p
    return rx, ry


@tool(category="crypto")
def ecc_point_ops(px: int = 0, py: int = 0, qx: int = 0, qy: int = 0, a: int = 2, b: int = 2, p: int = 17, scalar: int = 0) -> str:
    """Elliptic curve point arithmetic on y^2 = x^3 + ax + b over GF(p): scalar multiplication (double-and-add) and point addition.

    :param px: x coordinate of point P
    :param py: y coordinate of point P
    :param qx: x coordinate of point Q (for addition)
    :param qy: y coordinate of point Q (for addition)
    :param a: curve coefficient a
    :param b: curve coefficient b
    :param p: prime field modulus
    :param scalar: scalar to multiply P by (0 = just add P+Q)
    """
    try:
        if scalar:
            rx, ry = None, None
            tx, ty = px, py
            s = scalar
            while s:
                if s & 1:
                    rx, ry = _ecc_add(rx, ry, tx, ty, a, p)
                tx, ty = _ecc_add(tx, ty, tx, ty, a, p)
                s >>= 1
            return f"{scalar} * ({px}, {py}) mod {p} = ({rx}, {ry})" if rx is not None else f"{scalar} * ({px}, {py}) = point at infinity"
        rx, ry = _ecc_add(px, py, qx, qy, a, p)
        return f"({px}, {py}) + ({qx}, {qy}) = ({rx}, {ry})" if rx is not None else "sum = point at infinity"
    except Exception as ex:
        return f"ERROR: {ex}"


@tool(category="crypto")
def ecc_bsgs(px: int, py: int, qx: int, qy: int, a: int = 2, p: int = 0, bound: int = 100000) -> str:
    """Baby-step giant-step discrete log: find k with k*P = Q on y^2 = x^3 + ax + b over GF(p). Use when the subgroup is small.

    :param px: x coordinate of base point P
    :param py: y coordinate of base point P
    :param qx: x coordinate of target point Q
    :param qy: y coordinate of target point Q
    :param a: curve coefficient a
    :param p: prime field modulus
    :param bound: search bound for k
    """
    import math
    try:
        m = math.isqrt(bound) + 1
        table = {}
        cur = None
        for j in range(m):
            table.setdefault((cur[0] if cur else None, cur[1] if cur else None), j)
            cur = (px, py) if cur is None else _ecc_add(cur[0], cur[1], px, py, a, p)
        mpx, mpy = None, None
        for _ in range(m):
            mpx, mpy = (px, py) if mpx is None else _ecc_add(mpx, mpy, px, py, a, p)
        step = (mpx, (-mpy) % p)  # -m*P
        rx, ry = qx, qy
        for i in range(m + 1):
            if (rx, ry) in table:
                k = table[(rx, ry)] + i * m
                if k > bound:
                    continue
                return f"k = {k}  (check: k*P = ({qx}, {qy}))"
            rx, ry = _ecc_add(rx, ry, step[0], step[1], a, p)
        return f"No k found within bound {bound} (try larger bound or smaller subgroup)."
    except Exception as ex:
        return f"ERROR: {ex}"


@tool(category="crypto")
def paillier_keygen(bits: int = 32) -> str:
    """Generate Paillier keypair (for homomorphic-encryption challenges). bits: prime size.

    :param bits: bit size of each prime p and q
    """
    try:
        import sympy
        p = sympy.randprime(2 ** (bits - 1), 2 ** bits)
        q = sympy.randprime(2 ** (bits - 1), 2 ** bits)
        while q == p:
            q = sympy.randprime(2 ** (bits - 1), 2 ** bits)
    except ImportError:
        return "ERROR: sympy not installed. pip install sympy"
    n = p * q
    lam = (p - 1) * (q - 1)
    g = n + 1
    mu = pow(lam, -1, n)
    return (f"p={p}\nq={q}\nn={n}\ng={g}\nlambda={lam}\nmu={mu}\n"
            f"public (n,g) | private (lambda,mu)")


@tool(category="crypto")
def paillier_decrypt(ciphertext: int, p: int, q: int, g: int = 0) -> str:
    """Decrypt a Paillier ciphertext given the primes p,q (small challenges).

    :param ciphertext: Paillier ciphertext c
    :param p: prime p
    :param q: prime q
    :param g: generator g (default n+1)
    """
    try:
        n = p * q
        g = g or n + 1
        lam = (p - 1) * (q - 1)
        c_lam = pow(ciphertext, lam, n * n)
        m = (c_lam - 1) // n * pow(lam, -1, n) % n
        return f"m = {m}"
    except Exception as ex:
        return f"ERROR: {ex}"

def _ec_add(px, py, qx, qy, a, p):
    """Point addition on y^2 = x^3 + ax + b mod p (None = point at infinity)."""
    if px is None:
        return (qx, qy)
    if qx is None:
        return (px, py)
    if px == qx and (py + qy) % p == 0:
        return (None, None)
    if px == qx and py == qy:
        lam = (3 * px * px + a) * pow(2 * py, -1, p) % p
    else:
        lam = (qy - py) * pow(qx - px, -1, p) % p
    x3 = (lam * lam - px - qx) % p
    y3 = (lam * (px - x3) - py) % p
    return (x3, y3)


def _ec_mul(k, px, py, a, p):
    r = (None, None)
    bx, by = px, py
    while k:
        if k & 1:
            r = _ec_add(r[0], r[1], bx, by, a, p)
        bx, by = _ec_add(bx, by, bx, by, a, p)
        k >>= 1
    return r


def _factor_smooth(n: int) -> list[tuple[int, int]]:
    """Trial-division factorization into (prime, exponent) pairs."""
    fac = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            e = 0
            while n % d == 0:
                n //= d
                e += 1
            fac.append((d, e))
        d += 1
    if n > 1:
        fac.append((n, 1))
    return fac


def _is_prime(n: int) -> bool:
    """Trial-division primality check (fine for the small moduli PH handles)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


@tool(category="crypto")
def ecdsa_nonce_reuse(p: int, a: int, b: int, gx: int, gy: int, n: int, r1: int, s1: int, h1: int, r2: int, s2: int, h2: int, q1x: int = 0, q1y: int = 0) -> str:
    """ECDSA nonce reuse attack: recover the nonce k and the private key d from two signatures sharing k.

    k = (h1 - h2) * (s1 - s2)^-1 mod n, then d = (s1*k - h1) * r1^-1 mod n.
    Verify against public key Q1 = d*G when q1x/q1y are provided.

    :param p: curve prime p
    :param a: curve coefficient a
    :param b: curve coefficient b
    :param gx: base point G x
    :param gy: base point G y
    :param n: subgroup order of G
    :param r1: signature 1 r
    :param s1: signature 1 s
    :param h1: message hash 1 (as integer)
    :param r2: signature 2 r
    :param s2: signature 2 s
    :param h2: message hash 2 (as integer)
    :param q1x: public key Q1 x (optional verification)
    :param q1y: public key Q1 y (optional verification)
    """
    try:
        if (s1 - s2) % n == 0:
            return "ERROR: s1 == s2 mod n (not a nonce reuse case?)"
        k = (h1 - h2) * pow(s1 - s2, -1, n) % n
        d = (s1 * k - h1) * pow(r1, -1, n) % n
        lines = [
            f"k (nonce)  = {k}",
            f"d (private)= {d}",
            f"k (hex)    = {k:016x}",
            f"d (hex)    = {d:016x}",
        ]
        if q1x or q1y:
            qx, qy = _ec_mul(d, gx, gy, a, p)
            lines.append(f"d*G = ({qx}, {qy})")
            lines.append(f"Q1  = ({q1x}, {q1y})")
            lines.append("verify d*G == Q1: " + ("MATCH" if (qx == q1x and qy == q1y) else "MISMATCH"))
        return "\n".join(lines)
    except Exception as ex:
        return f"ERROR: {ex}"


@tool(category="crypto")
def mt19937_predict(outputs_csv: str, predict: int = 5) -> str:
    """Recover the MT19937 (Mersenne Twister) internal state from 624 consecutive 32-bit outputs and predict the next values.

    Undoes the tempering transform to rebuild state[624], then forwards the generator.

    :param outputs_csv: 624 consecutive 32-bit outputs (comma-separated)
    :param predict: how many future outputs to predict (default 5)
    """
    try:
        outs = [int(x.strip()) for x in outputs_csv.split(",") if x.strip()]
    except ValueError:
        return "ERROR: outputs_csv must be comma-separated integers"
    if len(outs) < 624:
        return f"ERROR: need 624 outputs to recover the state (got {len(outs)})"
    outs = outs[:624]

    def _unshift_right(x: int, shift: int) -> int:
        res = x
        for _ in range(5):
            res = x ^ (res >> shift)
        return res

    def _unshift_left(x: int, shift: int, mask: int) -> int:
        res = x
        for _ in range(5):
            res = x ^ ((res << shift) & mask)
        return res

    def untemper(x: int) -> int:
        x = _unshift_right(x, 18)
        x = _unshift_left(x, 15, 0xEFC60000)
        x = _unshift_left(x, 7, 0x9D2C5680)
        x = _unshift_right(x, 11)
        return x & 0xFFFFFFFF

    state = [untemper(o) for o in outs]
    idx = 624  # force a twist on the first fetch

    def _twist():
        for i in range(624):
            y = (state[i] & 0x80000000) + (state[(i + 1) % 624] & 0x7FFFFFFF)
            state[i] = state[(i + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)

    def _temper(y: int) -> int:
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= (y >> 18)
        return y & 0xFFFFFFFF

    def next_int() -> int:
        nonlocal idx
        if idx >= 624:
            _twist()
            idx = 0
        y = state[idx]
        idx += 1
        return _temper(y)

    pred = [next_int() for _ in range(predict)]
    lines = [f"state recovered: {len(state)} uint32 values", f"next {predict} outputs:"]
    for i, v in enumerate(pred, 1):
        lines.append(f"  #{i}: {v}")
    return "\n".join(lines)


@tool(category="crypto")
def pollard_p1(n: int, bound: int = 100000) -> str:
    """Pollard p-1 factorization: works when one factor p has a smooth p-1 (all prime factors of p-1 <= bound).

    :param n: RSA modulus / composite to factor
    :param bound: smoothness bound (default 100000)
    """
    import math as _math
    if n < 2:
        return "ERROR: n must be >= 2"
    if _math.isqrt(n) ** 2 == n:
        return f"n is a perfect square: {_math.isqrt(n)}^2"
    a = 2
    primes = []
    for cand in range(2, bound + 1):
        if all(cand % p for p in primes):
            primes.append(cand)
    try:
        for p in primes:
            pe = p
            while pe * p <= bound:
                pe *= p
            a = pow(a, pe, n)
            g = _math.gcd(a - 1, n)
            if 1 < g < n:
                q = n // g
                return f"factors found:\np = {g}\nq = {q}\np*q = n: {g * q == n}\nbound needed: <= {p}"
        return f"no factor found with bound {bound} (p-1 not B-smooth?)"
    except Exception as ex:
        return f"ERROR: {ex}"


@tool(category="crypto")
def pohlig_hellman(g: int, h: int, p: int) -> str:
    """Pohlig-Hellman discrete log: solve g^x = h mod p when p-1 factors into small primes.

    :param g: generator
    :param h: target value
    :param p: prime modulus
    """
    if p < 2 or not _is_prime(p):
        return "ERROR: p must be prime"
    fac = _factor_smooth(p - 1)
    if max(f for f, _ in fac) > 1_000_000:
        return f"ERROR: p-1 has a too-large prime factor {max(f for f, _ in fac)}; Pohlig-Hellman will not help"
    # order of g (divide out prime powers)
    order = p - 1
    for q, e in fac:
        while order % q == 0 and pow(g, order // q, p) == 1:
            order //= q
    ofac = _factor_smooth(order)
    if max(f for f, _ in ofac) > 1_000_000:
        return f"ERROR: order of g has a too-large prime factor {max(f for f, _ in ofac)}"
    # for each prime power q^e || order, find x mod q^e (digit-by-digit)
    xs = []
    for q, e in ofac:
        qe = q ** e
        gamma = pow(g, order // q, p)  # order q
        xj = 0
        hj = h
        for j in range(e):
            # c = (h * g^-x_so_far)^(order / q^(j+1)) == gamma^(d_j)
            c = pow(hj, order // (q ** (j + 1)), p)
            d = 0
            for cand in range(q):
                if pow(gamma, cand, p) == c:
                    d = cand
                    break
            xj += d * (q ** j)
            hj = hj * pow(g, -d * (q ** j), p) % p
        xs.append((qe, xj % qe))
    # CRT combine
    x = 0
    M = 1
    for qe, xi in xs:
        t = pow(M % qe, -1, qe)
        x = (x + M * ((xi - x) % qe) * t) % (M * qe)
        M *= qe
    check = pow(g, x, p)
    lines = [
        f"p-1 factors: {fac}",
        f"order of g: {order}",
        f"local solutions: {xs}",
        f"x = {x}",
        f"verify g^x = h: {check == h}",
    ]
    return "\n".join(lines)


@tool(category="crypto")
def xor_known_plaintext(ciphertext_hex: str, known_plaintext: str = "flag{", max_key_len: int = 32) -> str:
    """Recover repeating XOR key and decrypt ciphertext using known plaintext prefix (e.g. 'flag{', PNG header, XML).

    :param ciphertext_hex: The hex-encoded ciphertext
    :param known_plaintext: Known plaintext prefix at offset 0
    :param max_key_len: Maximum key length to test (default 32)
    """
    clean_hex = ciphertext_hex.strip().replace("0x", "").replace(" ", "").replace("\n", "")
    try:
        ct = bytes.fromhex(clean_hex)
    except ValueError:
        return "ERROR: Invalid hex in ciphertext_hex."

    known_bytes = known_plaintext.encode("utf-8")
    if len(known_bytes) > len(ct):
        return "ERROR: known_plaintext is longer than ciphertext."

    recovered_prefix = bytes(c ^ k for c, k in zip(ct[:len(known_bytes)], known_bytes))

    results = [
        f"Ciphertext Length : {len(ct)} bytes",
        f"Known Prefix      : {known_plaintext!r} ({len(known_bytes)} bytes)",
        f"Recovered Key Part: {recovered_prefix!r} (hex: {recovered_prefix.hex()})\n"
    ]

    # Try possible key lengths <= len(known_bytes)
    found_any = False
    for klen in range(1, min(len(known_bytes), max_key_len) + 1):
        key = recovered_prefix[:klen]
        # Check if the recovered prefix repeats cleanly with period klen
        consistent = True
        for i in range(len(known_bytes)):
            if recovered_prefix[i] != key[i % klen]:
                consistent = False
                break
        if consistent:
            dec = bytes(c ^ key[i % klen] for i, c in enumerate(ct))
            pr_ratio = sum(1 for b in dec if 32 <= b <= 126 or b in (10, 13, 9)) / len(dec)
            results.append(
                f"Candidate Key (len={klen}): {key!r} (hex: {key.hex()})\n"
                f"Printable Ratio : {pr_ratio*100:.1f}%\n"
                f"Decrypted Preview:\n{dec[:300].decode('latin-1', errors='replace')}\n"
            )
            found_any = True

    if not found_any:
        results.append("No short periodic key fully contained within known prefix. Recovered key prefix shown above.")

    return "\n".join(results)


@tool(category="crypto")
def discrete_log_bsgs(g: int, h: int, p: int, max_steps: int = 1000000) -> str:
    """Solve discrete logarithm g^x = h mod p using Baby-step Giant-step algorithm (O(sqrt(p)) complexity).

    :param g: Base / generator
    :param h: Target value
    :param p: Modulus
    :param max_steps: Maximum baby steps table limit (default 1,000,000)
    """
    import math
    if p <= 2:
        return "ERROR: Modulus p must be > 2."

    # m = ceil(sqrt(p))
    m = int(math.isqrt(p)) + 1
    if m > max_steps:
        m = max_steps

    # 1. Baby steps: compute g^j mod p for j in 0..m-1 and store in hash table
    tbl = {}
    cur = 1
    for j in range(m):
        if cur not in tbl:
            tbl[cur] = j
        cur = (cur * g) % p

    # 2. Giant steps: compute h * (g^(-m))^i mod p for i in 0..m-1
    # g_inv_m = (g^m)^(-1) mod p
    g_m = pow(g, m, p)
    try:
        g_inv_m = pow(g_m, -1, p)
    except ValueError:
        return "ERROR: Base g is not coprime to modulus p."

    gamma = h % p
    for i in range(m):
        if gamma in tbl:
            j = tbl[gamma]
            x = i * m + j
            # Verify
            if pow(g, x, p) == h % p:
                return (
                    f"Discrete Logarithm Solved:\n"
                    f"  x = {x}\n"
                    f"  Verify: {g}^{x} mod {p} == {pow(g, x, p)} (Target: {h % p})"
                )
        gamma = (gamma * g_inv_m) % p

    return f"No discrete log solution found within search bound m={m}."


@tool(category="crypto")
def linux_ssh_key_inspect(key_data_or_path: str) -> str:
    """Inspect OpenSSH public or private keys, extracting key type, bit length, fingerprint, and comment.

    :param key_data_or_path: Path to key file (e.g. id_rsa.pub) or raw key string
    """
    import base64
    import hashlib
    import os

    if os.path.exists(key_data_or_path):
        content = open(key_data_or_path, "r", errors="ignore").read().strip()
    else:
        content = key_data_or_path.strip()

    lines = [f"OpenSSH Key Inspection:"]

    # 1. Public key format: <type> <b64_blob> <comment>
    parts = content.split()
    if len(parts) >= 2 and any(parts[0].startswith(p) for p in ("ssh-", "ecdsa-")):
        k_type = parts[0]
        b64_blob = parts[1]
        pad = len(b64_blob) % 4
        if pad:
            b64_blob += "=" * (4 - pad)
        comment = " ".join(parts[2:]) if len(parts) > 2 else "None"
        try:
            raw = base64.b64decode(b64_blob)
            fp_sha256 = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            fp_md5 = ":".join(f"{b:02x}" for b in hashlib.md5(raw).digest())
            lines.extend([
                f"  Key Type    : {k_type}",
                f"  Comment     : {comment}",
                f"  Blob Size   : {len(raw)} bytes",
                f"  SHA256 Fingerprint: SHA256:{fp_sha256}",
                f"  MD5 Fingerprint   : MD5:{fp_md5}",
            ])
            return "\n".join(lines)
        except Exception as ex:
            lines.append(f"  Error parsing base64 blob: {ex}")

    # 2. Private key header check
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in content:
        lines.extend([
            f"  Format      : OpenSSH Private Key (Ed25519 or modern RSA)",
            f"  Encrypted   : {'Yes (AES/bcrypt)' if 'bcrypt' in content else 'No (Plaintext PEM)'}",
            f"  Size        : {len(content)} characters"
        ])
    elif "-----BEGIN RSA PRIVATE KEY-----" in content:
        lines.extend([
            f"  Format      : Legacy OpenSSL RSA Private Key (PEM PKCS#1)",
            f"  Encrypted   : {'Yes' if 'Proc-Type: 4,ENCRYPTED' in content else 'No (Plaintext PEM)'}",
        ])
    else:
        lines.append(f"  Unrecognized key header: {content[:80]}...")

    return "\n".join(lines)


@tool(category="crypto")
def linux_gpg_key_inspect(key_data_or_path: str) -> str:
    """Inspect OpenPGP / GPG ASCII-armored key blocks, extracting packet tags, key ID, and creation metadata.

    :param key_data_or_path: Path to GPG key file or raw PGP ASCII armor string
    """
    import base64
    import os
    import time

    if os.path.exists(key_data_or_path):
        content = open(key_data_or_path, "r", errors="ignore").read().strip()
    else:
        content = key_data_or_path.strip()

    if "BEGIN PGP" not in content:
        return "ERROR: String does not contain '-----BEGIN PGP...' ASCII armor header."

    lines = ["OpenPGP / GPG Key Block Analysis:"]

    # Extract body between armor headers
    in_body = False
    body_b64 = []
    for line in content.splitlines():
        if line.startswith("-----BEGIN PGP"):
            in_body = True
            lines.append(f"  Header: {line}")
            continue
        if line.startswith("-----END PGP"):
            in_body = False
            break
        if in_body:
            if ":" in line and not body_b64:  # Header metadata like Version: ...
                lines.append(f"  Meta  : {line}")
                continue
            if line.startswith("="):  # CRC24 checksum line
                lines.append(f"  CRC24 : {line}")
                continue
            body_b64.append(line.strip())

    try:
        raw = base64.b64decode("".join(body_b64))
        lines.append(f"  Raw Payload Size: {len(raw)} bytes")

        # Check PGP packet tag in first byte (Old format: 10xxxxxx, New format: 11xxxxxx)
        first_b = raw[0]
        if first_b & 0x80:
            is_new = bool(first_b & 0x40)
            tag = (first_b & 0x3F) if is_new else ((first_b >> 2) & 0x0F)
            PGP_TAGS = {
                1: "Public-Key Encrypted Session Key",
                2: "Signature Packet",
                6: "Public-Key Packet",
                5: "Secret-Key Packet",
                14: "Public-Subkey Packet",
                13: "User ID Packet",
            }
            tag_name = PGP_TAGS.get(tag, f"Tag_{tag}")
            lines.append(f"  First Packet Type: {tag_name} ({'New' if is_new else 'Old'} format)")
    except Exception as ex:
        lines.append(f"  Payload decoding error: {ex}")

    return "\n".join(lines)
