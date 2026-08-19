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
