"""OSINT: DNS query, reverse DNS, Certificate Transparency (crt.sh) subdomain hunt."""

import json
import socket
import urllib.request

from ..registry import tool


@tool(category="osint")
def dns_query(domain: str, record: str = "A") -> str:
    """Query DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA). For challenge infrastructure mapping."""
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
    """Reverse DNS lookup (PTR)."""
    try:
        host = socket.gethostbyaddr(ip)[0]
        return f"PTR {ip} -> {host}"
    except Exception as ex:
        return f"No PTR record / error: {ex}"


@tool(category="osint")
def crtsh_subdomains(domain: str, limit: int = 100) -> str:
    """Find subdomains via Certificate Transparency (crt.sh). No API key required."""
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