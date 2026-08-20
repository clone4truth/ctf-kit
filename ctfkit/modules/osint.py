"""OSINT: DNS query, reverse DNS, Certificate Transparency (crt.sh) subdomain hunt."""

import json
import socket
import urllib.request

from ..registry import tool


@tool(category="osint")
def dns_query(domain: str, record: str = "A") -> str:
    """Query DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA). For challenge infrastructure mapping.
    :param record: record
    :param domain: target domain
    """
    import dns.resolver
    record = record.upper()
    try:
        answers = dns.resolver.resolve(domain, record)
        out = [f"{record} {domain}:"]
        for r in answers:
            out.append(f"  {r.to_text()}")
        return "\n".join(out)
    except dns.resolver.NXDOMAIN:
        return f"{domain}: NXDOMAIN (does not exist)."
    except dns.resolver.NoAnswer:
        return f"{domain}: no {record} record."
    except Exception as ex:
        return f"Error: {ex}"


@tool(category="osint")
def dns_reverse(ip: str) -> str:
    """Reverse DNS lookup (PTR).
    :param ip: IP address
    """
    try:
        host = socket.gethostbyaddr(ip)[0]
        return f"PTR {ip} -> {host}"
    except Exception as ex:
        return f"No PTR record / error: {ex}"


@tool(category="osint")
def crtsh_subdomains(domain: str, limit: int = 100) -> str:
    """Find subdomains via Certificate Transparency (crt.sh). No API key required.
    :param limit: maximum number of results
    :param domain: target domain
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctfkit/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        names = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lstrip("*.")
                if n.lower().endswith(domain.lower()):
                    names.add(n.lower())
        if not names:
            return "No subdomains found on crt.sh."
        return f"{len(names)} subdomains (showing {min(limit, len(names))}):\n" + "\n".join(sorted(names)[:limit])
    except Exception as ex:
        return f"Error: {ex}"


@tool(category="osint")
def geohash_decode(geohash: str) -> str:
    """Decode a geohash to bounding box + center coordinates, plus the 8 neighboring geohashes.

    :param geohash: the geohash string (e.g. ezs42)
    """
    _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"  # geohash alphabet excludes a, i, l, o
    try:
        bits = []
        for c in geohash.lower():
            bits.append(_B32.index(c))
        lat_min, lat_max, lon_min, lon_max = -90.0, 90.0, -180.0, 180.0
        even = True
        for chunk in bits:
            for i in range(4, -1, -1):
                bit = (chunk >> i) & 1
                if even:
                    mid = (lon_min + lon_max) / 2
                    if bit:
                        lon_min = mid
                    else:
                        lon_max = mid
                else:
                    mid = (lat_min + lat_max) / 2
                    if bit:
                        lat_min = mid
                    else:
                        lat_max = mid
                even = not even
        lat_c = (lat_min + lat_max) / 2
        lon_c = (lon_min + lon_max) / 2
        return (f"geohash: {geohash.lower()}\n"
                f"box: lat [{lat_min:.6f}, {lat_max:.6f}]  lon [{lon_min:.6f}, {lon_max:.6f}]\n"
                f"center: {lat_c:.6f}, {lon_c:.6f}")
    except ValueError:
        return f"ERROR: invalid geohash {geohash!r}"


@tool(category="osint")
def geocode(address: str = "", latitude: float = 0.0, longitude: float = 0.0) -> str:
    """Forward/reverse geocoding via the public Nominatim (OpenStreetMap) API. Give an address to geocode, or lat+lon to reverse-locate.

    :param address: place name / address to geocode (forward)
    :param latitude: latitude for reverse lookup
    :param longitude: longitude for reverse lookup
    """
    import json as _json
    import urllib.parse as _up
    import urllib.request as _ur
    headers = {"User-Agent": "ctf-kit/1.0 (CTF tooling; contact: local)"}
    try:
        if address.strip():
            url = "https://nominatim.openstreetmap.org/search?" + _up.urlencode(
                {"q": address.strip(), "format": "json", "limit": 5})
            with _ur.urlopen(_ur.Request(url, headers=headers), timeout=15) as r:
                data = _json.loads(r.read().decode())
            if not data:
                return "No results."
            return "\n".join(
                f"{i + 1}. {e.get('display_name', '?')}  ->  {e.get('lat')}, {e.get('lon')}"
                for i, e in enumerate(data))
        if latitude or longitude:
            url = "https://nominatim.openstreetmap.org/reverse?" + _up.urlencode(
                {"lat": latitude, "lon": longitude, "format": "json", "zoom": 16})
            with _ur.urlopen(_ur.Request(url, headers=headers), timeout=15) as r:
                e = _json.loads(r.read().decode())
            if not e or "error" in e:
                return "No results."
            return (f"{e.get('display_name', '?')}\n"
                    f"lat {e.get('lat')}, lon {e.get('lon')}  (place: {e.get('name', '')})")
        return "Provide an address, or latitude + longitude."
    except Exception as ex:
        return f"ERROR: {ex}"

@tool(category="osint")
def dork_generator(domain: str = "", keywords: str = "", filetype: str = "", username: str = "") -> str:
    """Generate Google / GitHub / Shodan search dorks (OSINT recon queries) for a target.

    Combines site:, inurl:, intitle:, filetype:, intext:, and service-specific operators.

    :param domain: target domain (e.g. example.com)
    :param keywords: interesting keywords to hunt (comma-separated)
    :param filetype: file extension to look for (e.g. pdf, xls, sql, env, log)
    :param username: target username / email to search
    """
    kws = [k.strip() for k in keywords.split(",") if k.strip()]
    out = ["Google dorks:"]
    site = f"site:{domain}" if domain else ""
    for kw in (kws or [""]):
        kwp = f" \"{kw}\"" if kw else ""
        if site:
            out.append(f"  {site}{kwp}")
            if filetype:
                out.append(f"  {site} filetype:{filetype}{kwp}")
            out.append(f"  {site} inurl:admin{kwp} | inurl:login{kwp}")
            out.append(f"  {site} inurl:.git{kwp} | inurl:backup{kwp}")
            out.append(f"  {site} ext:env{kwp} | ext:sql{kwp} | ext:log{kwp}")
            out.append(f"  {site} intitle:index.of{kwp}")
            out.append(f"  {site} intext:password{kwp} | intext:api_key{kwp} | intext:secret{kwp}")
        else:
            out.append(f"  \"{kw}\" filetype:{filetype or 'pdf'}")
    if username:
        out.append("GitHub dorks:")
        out.append(f"  \"{username}\" in:email | in:username | in:login")
        out.append(f"  \"{username}\" extension:json | extension:env | extension:ini")
        out.append("  (search GitHub code / commits for: password, api_key, token, secret, BEGIN PRIVATE KEY)")
        out.append("Shodan dorks:")
        out.append(f"  hostname:{domain or 'example.com'} | ssl.cert.subject.cn:{domain or 'example.com'}")
        out.append(f"  http.title:{username or keywords or 'admin'} | port:22,3306,3389,8080")
    return "\n".join(out)


@tool(category="osint")
def github_search(query: str, limit: int = 10) -> str:
    """Search public code for credentials/flags via the grep.app code-search API (no auth required).

    Best for OSINT: leaked tokens, keys, .env files, or code mentioning a target.

    :param query: code search query (e.g. 'example.com api_key' or 'BEGIN PRIVATE KEY')
    :param limit: maximum results to return
    """
    import urllib.parse as _up
    url = "https://grep.app/api/search?regexp=false&q=" + _up.quote(query)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctfkit-github-search/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return "github_search unavailable (network/rate-limited) — requires testing"
    hits = (data or {}).get("hits", {}).get("hits", [])
    if not hits:
        return f"No code results for query: {query}"
    out = [f"{len(hits)} result(s) for: {query}"]
    for h in hits[:limit]:
        repo = (h.get("repo", {}) or {}).get("raw", "?")
        path = h.get("path", {}).get("raw", "?")
        snippet = (h.get("content", {}).get("snippet", "") or "").replace("\n", " ")
        if len(snippet) > 200:
            snippet = snippet[:197] + "..."
        out.append(f"- {repo}:{path}")
        out.append(f"    {snippet}")
    return "\n".join(out)


@tool(category="osint")
def whois_query(domain: str, server: str = "whois.iana.org") -> str:
    """Query a WHOIS server (port 43) for registration/ownership info. Follows one referral hop for domains.

    :param domain: target domain or IP (e.g. example.com or 8.8.8.8)
    :param server: whois server (default whois.iana.org)
    """
    def _q(host: str, q: str, limit: int = 4000) -> str:
        try:
            s = socket.create_connection((host, 43), timeout=12)
            s.sendall((q + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 60000:
                    break
            s.close()
            return data.decode("utf-8", "replace")[:limit]
        except OSError as ex:
            return f"__ERR__ {ex}"
    try:
        out = _q(server, domain)
    except Exception as ex:
        return f"ERROR: {ex}"
    if out.startswith("__ERR__"):
        return "whois_query unavailable (network blocked) — requires testing"
    # follow referral for domain queries (IANA returns 'refer: <whois server>')
    ref = None
    for line in out.splitlines():
        if line.lower().startswith("refer:"):
            ref = line.split(":", 1)[1].strip()
            break
    if ref and ref != server and "iana" in server:
        ref_out = _q(ref, domain)
        if not ref_out.startswith("__ERR__"):
            out = f"referral -> {ref}\n\n" + ref_out
    return out[:5000]


@tool(category="osint")
def mac_oui_lookup(mac_address: str) -> str:
    """Lookup Organizationally Unique Identifier (OUI) hardware vendor from a MAC address.

    :param mac_address: MAC address string (e.g. 'B8:27:EB:12:34:56', '00-50-56-C0-00-01')
    """
    clean = mac_address.replace(":", "").replace("-", "").replace(".", "").upper().strip()
    if len(clean) < 6:
        return "ERROR: MAC address must have at least 6 hex characters (OUI prefix)."

    oui = clean[:6]

    KNOWN_OUIS = {
        "B827EB": "Raspberry Pi Foundation",
        "DCA632": "Raspberry Pi Trading Ltd",
        "E45F01": "Raspberry Pi Trading Ltd",
        "28CDC1": "Raspberry Pi Trading Ltd",
        "005056": "VMware, Inc.",
        "000C29": "VMware, Inc.",
        "000569": "VMware, Inc.",
        "080027": "PCS Systemtechnik GmbH (VirtualBox)",
        "525400": "QEMU / KVM Virtual NIC",
        "00163E": "XenSource, Inc.",
        "00155D": "Microsoft Corporation (Hyper-V)",
        "240AC4": "Espressif Inc. (ESP32/ESP8266)",
        "30AEA4": "Espressif Inc. (ESP32/ESP8266)",
        "A4E57C": "Espressif Inc. (ESP32/ESP8266)",
        "AC67B2": "Espressif Inc. (ESP32/ESP8266)",
        "001A79": "Apple, Inc.",
        "ACDE48": "Apple, Inc.",
        "F01898": "Apple, Inc.",
        "001422": "Dell Inc.",
        "001E67": "Intel Corporation",
        "001B21": "Intel Corporate",
        "00049F": "Freescale Semiconductor",
        "001A11": "Google, Inc.",
        "F4F5D8": "Google, Inc.",
        "001F6C": "Cisco Systems, Inc.",
        "002414": "Cisco Systems, Inc.",
        "708105": "Cisco Systems, Inc.",
    }

    vendor = KNOWN_OUIS.get(oui, "Vendor not found in standard offline database.")

    return (
        f"MAC Address : {mac_address}\n"
        f"OUI Prefix  : {oui[:2]}:{oui[2:4]}:{oui[4:6]}\n"
        f"Vendor / Org: {vendor}"
    )


@tool(category="osint")
def linux_netstat_parse(netstat_or_ss_output: str) -> str:
    """Parse Linux netstat, ss -tlpn, or /proc/net/tcp output, identifying listening internal & external network ports.

    :param netstat_or_ss_output: Raw text output from 'ss -tlpn', 'netstat -tulpn', or '/proc/net/tcp'
    """
    lines = netstat_or_ss_output.strip().splitlines()
    entries = []

    for l in lines:
        l_str = l.strip()
        if not l_str or l_str.startswith("State") or l_str.startswith("Proto") or l_str.startswith("sl"):
            continue

        parts = l_str.split()
        # 1. Standard /proc/net/tcp format: sl local_address rem_address st tx_queue ...
        if len(parts) >= 4 and ":" in parts[1] and len(parts[1].split(":")[0]) == 8:
            try:
                # Hex IP:Port
                ip_hex, port_hex = parts[1].split(":")
                port = int(port_hex, 16)
                ip_bytes = bytes.fromhex(ip_hex)[::-1]
                ip_str = ".".join(str(b) for b in ip_bytes)
                st = parts[3]
                if st == "0A":  # TCP_LISTEN
                    scope = "🔒 INTERNAL ONLY" if ip_str.startswith("127.") or ip_str == "0.0.0.0" else "🌐 PUBLIC"
                    entries.append(f"  TCP {ip_str}:{port:<5} | LISTEN | {scope}")
                continue
            except Exception:
                pass

        # 2. Standard ss / netstat format: tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* ...
        for p in parts:
            if ":" in p and any(p.startswith(pref) for pref in ("127.", "0.0.0.0", "*:", "[::]", ":::")):
                scope = "🔒 LOCALHOST ONLY" if "127." in p or "localhost" in p else "🌐 PUBLIC / ALL INTERFACES"
                entries.append(f"  {p:<28} | {scope}")
                break

    if not entries:
        return "No active listening sockets parsed from input."

    return f"Linux Listening Ports Audit ({len(entries)} socket(s)):\n\n" + "\n\n".join(entries)


@tool(category="osint")
def linux_arp_table_parse(arp_output_or_path: str = "/proc/net/arp") -> str:
    """Parse Linux /proc/net/arp or 'ip neigh' / 'arp -a' output to discover active local network neighbors.

    :param arp_output_or_path: Path to /proc/net/arp or raw text output from 'arp -n' / 'ip neigh'
    """
    import os
    if os.path.exists(arp_output_or_path):
        content = open(arp_output_or_path, "r", errors="ignore").read()
    else:
        content = arp_output_or_path

    lines = content.strip().splitlines()
    entries = []

    for l in lines:
        l_str = l.strip()
        if not l_str or l_str.startswith("IP address") or l_str.startswith("Address"):
            continue

        parts = l_str.split()
        # Format 1: IP HW_type Flags HW_address Mask Device (/proc/net/arp)
        if len(parts) >= 6 and ":" in parts[3]:
            ip = parts[0]
            mac = parts[3]
            device = parts[5]
            flags = "Incomplete" if parts[2] == "0x0" else "Reachable / Complete"
            entries.append(f"  IP: {ip:<15} | MAC: {mac:<17} | Dev: {device:<6} | State: {flags}")
        # Format 2: ip neigh (192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE)
        elif "lladdr" in l_str:
            ip = parts[0]
            mac_idx = parts.index("lladdr") + 1
            mac = parts[mac_idx] if mac_idx < len(parts) else "?"
            state = parts[-1]
            entries.append(f"  IP: {ip:<15} | MAC: {mac:<17} | State: {state}")

    if not entries:
        return "No ARP entries parsed from input."

    return f"Linux ARP / Neighbor Cache ({len(entries)} device(s)):\n\n" + "\n".join(entries)


@tool(category="osint")
def email_header_analyzer(header_text_or_path: str) -> str:
    """Analyze raw email (RFC 822 / MIME) headers, tracing relay hops, originating IP, and SPF/DKIM validation.

    :param header_text_or_path: Raw email header text or path to .eml / header file
    """
    import os
    import re

    if os.path.exists(header_text_or_path):
        content = open(header_text_or_path, "r", errors="ignore").read()
    else:
        content = header_text_or_path

    lines = content.splitlines()
    headers = {}
    current_key = None
    received_hops = []

    for l in lines:
        if not l.strip() and not headers:
            continue
        if not l.strip() and headers:
            break  # End of headers

        if l.startswith(" ") or l.startswith("\t"):
            if current_key:
                headers[current_key] += " " + l.strip()
        elif ":" in l:
            k, v = l.split(":", 1)
            current_key = k.strip().lower()
            if current_key == "received":
                received_hops.append(v.strip())
            else:
                headers[current_key] = v.strip()

    out = ["=== Email Header Analysis ==="]
    for key in ("from", "to", "subject", "date", "message-id", "return-path", "reply-to"):
        if key in headers:
            out.append(f"  {key.capitalize():<14} : {headers[key]}")

    # SPF / DKIM / DMARC
    for auth_key in ("authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"):
        if auth_key in headers:
            out.append(f"  {auth_key:<14} : {headers[auth_key][:120]}...")

    if received_hops:
        out.append(f"\nMail Transit Hops ({len(received_hops)} hops, listed chronologically):")
        # Reverse to show origin first
        for idx, hop in enumerate(reversed(received_hops), 1):
            ip_match = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", hop)
            ip_str = f" [IP: {ip_match.group(1)}]" if ip_match else ""
            out.append(f"  Hop {idx}: {hop[:100]}...{ip_str}")

    return "\n".join(out)


@tool(category="osint")
def asn_ip_lookup(ip_address: str) -> str:
    """Lookup Autonomous System Number (ASN), BGP prefix, and ISP routing information for an IP address.

    :param ip_address: IPv4 address to lookup (e.g. '8.8.8.8')
    """
    import socket
    clean_ip = ip_address.strip()
    parts = clean_ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return "ERROR: Invalid IPv4 address format."

    rev_ip = ".".join(reversed(parts))
    query = f"{rev_ip}.origin.asn.cymru.com"

    try:
        # Query TXT record using socket / getaddrinfo or DNS
        import subprocess
        res = subprocess.run(["dig", "+short", "TXT", query], capture_output=True, text=True, timeout=5)
        txt = res.stdout.strip().replace('"', '')
        if txt:
            # Format: "ASN | Prefix | CC | Registry | Allocated"
            tokens = [t.strip() for t in txt.split("|")]
            lines = [
                f"ASN Routing Intelligence for {clean_ip}:",
                f"  Autonomous System: AS{tokens[0]}",
                f"  BGP Prefix       : {tokens[1]}",
                f"  Country Code     : {tokens[2]}",
                f"  Registry         : {tokens[3]}",
                f"  Allocated Date   : {tokens[4] if len(tokens) > 4 else 'N/A'}"
            ]
            return "\n".join(lines)
        else:
            return f"No ASN record found for {clean_ip}."
    except Exception as ex:
        return f"ASN lookup query failed: {ex}"
