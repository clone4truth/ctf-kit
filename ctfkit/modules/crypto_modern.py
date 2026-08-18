"""Modern crypto: XOR, RSA, AES (all modes), hash id/generate, CBC bit-flip."""

import hashlib
import re
import urllib.parse

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
    """Wiener's attack for RSA with small private exponent d (d < 1/3 * n^(1/4))."""
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
    """Fermat factorization when prime factors p and q are close (|p - q| is small)."""
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
    """Common Modulus attack: same n, different coprime public exponents e1, e2 on the same message."""
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
    """Hastad's Broadcast attack (Chinese Remainder Theorem for identical message sent with small e)."""
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
    """Parse RSA public or private keys (.pem / .pub / .key / OpenSSH) into n, e, d, p, q."""
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
    """Known Plaintext Attack (KPA) / Crib dragging against one ciphertext or two ciphertexts sharing a key."""
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
    """Recover LCG parameters (a, c, m) from consecutive outputs (x0, x1, x2, ...) and predict future states."""
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
    """Generate Hash Length Extension payload and forged signature for H(key || original_data)."""
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