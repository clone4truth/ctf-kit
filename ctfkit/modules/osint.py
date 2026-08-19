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