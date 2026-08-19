"""CVE research tools — understand a challenge, find the relevant CVE, and get an exploit plan.

Every challenge flow that involves a known product/version (web app, framework,
service, binary) should run `cve_research` on the problem statement BEFORE
picking the exploit tool. It:

  1. Detects explicit CVE IDs in the problem text.
  2. Detects software + version from the problem text.
  3. Queries the NVD API (online) for details + exploit references.
  4. Falls back to a curated local CTF CVE knowledge base when offline.
  5. Maps the CVE to a concrete ctfkit tool + exploitation steps.

Network is optional: every function degrades gracefully to the local knowledge
base and returns actionable next steps either way.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..registry import tool

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_URL = "https://cve.circl.lu/api/cve/{}"
_TIMEOUT = 8

# Software keyword -> display name. Keys are matched case-insensitively as
# substrings in the problem text.
SOFTWARE_NAMES = {
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "tomcat": "Apache Tomcat",
    "websphere": "IBM WebSphere",
    "weblogic": "Oracle WebLogic",
    "struts": "Apache Struts2",
    "jenkins": "Jenkins",
    "gitlab": "GitLab",
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "phpmyadmin": "phpMyAdmin",
    "php-fpm": "PHP-FPM",
    "phpunit": "PHPUnit",
    "laravel": "Laravel",
    "symfony": "Symfony",
    "react": "React",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "node": "Node.js",
    "express": "Express",
    "spring": "Spring",
    "java": "Java/JVM",
    "log4j": "Apache Log4j",
    "log4shell": "Apache Log4j (Log4Shell)",
    "solr": "Apache Solr",
    "elasticsearch": "Elasticsearch",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "openssh": "OpenSSH",
    "ssh": "OpenSSH",
    "sudo": "sudo",
    "openssl": "OpenSSL",
    "exim": "Exim",
    "postfix": "Postfix",
    "dovecot": "Dovecot",
    "proftpd": "ProFTPD",
    "vsftpd": "vsftpd",
    "samba": "Samba",
    "exchange": "Microsoft Exchange",
    "iis": "Microsoft IIS",
    "windows": "Windows",
    "linux": "Linux kernel",
    "owncloud": "ownCloud",
    "nextcloud": "Nextcloud",
    "xstream": "XStream",
    "fastjson": "Fastjson",
    "shiro": "Apache Shiro",
    "runc": "runc",
    "git": "Git",
    "php": "PHP",
    "python": "Python",
    "flask": "Flask",
    "django": "Django",
    "ruby": "Ruby on Rails",
    "rails": "Ruby on Rails",
    "webmin": "Webmin",
    "zabbix": "Zabbix",
    "grafana": "Grafana",
    "kubernetes": "Kubernetes",
}

# Curated CTF-relevant CVE knowledge base (offline fallback + tool mapping).
# Each entry: (software_key, version_fragment, cve, severity, title, tip, ctfkit_tool)
CVE_KB = [
    ("react", "19", "CVE-2025-55182", "CRITICAL", "React Server Components pre-auth RCE",
     "Send a crafted request to the SSR endpoint; header/cookie injection triggers RCE. "
     "Use http_request/browser_agent to hit the page, then replay the PoC payload.",
     "http_request"),
    ("laravel", "", "CVE-2018-15133", "CRITICAL", "Laravel APP_KEY RCE via unserialize",
     "If .env / APP_KEY leaks, build a forged laravel_session cookie (AES-256-CBC + HMAC). "
     "Use deserialization_payloads then craft the cookie.",
     "deserialization_payloads"),
    ("apache", "2.4.49", "CVE-2021-41773", "HIGH", "Apache path traversal + RCE",
     "GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd then POST with payload to get RCE. "
     "Use path_traversal_payloads.",
     "path_traversal_payloads"),
    ("apache", "2.4.50", "CVE-2021-42013", "HIGH", "Apache path traversal + RCE (bypass)",
     "Double-URL-encode: /.%%32%65/... Use payload_encoders to bypass the fix.",
     "payload_encoders"),
    ("struts", "", "CVE-2017-5638", "HIGH", "Apache Struts2 OGNL RCE",
     "Content-Type header OGNL injection. Use ssti_payloads for OGNL-ish payloads or "
     "payload_encoders to WAF-bypass.",
     "ssti_payloads"),
    ("spring", "", "CVE-2022-22965", "CRITICAL", "Spring4Shell RCE",
     "class.module.classLoader payloads via form params. Use ssti_payloads / http_request.",
     "http_request"),
    ("log4j", "", "CVE-2021-44228", "CRITICAL", "Log4Shell JNDI RCE",
     "Inject ${jndi:ldap://<oast>} in every input; catch the callback with oast_payload, "
     "then run a JNDI exploit to get RCE.",
     "oast_payload"),
    ("phpmyadmin", "4.8", "CVE-2018-12613", "HIGH", "phpMyAdmin LFI to RCE",
     "index.php?target=db_sql.php%253f../../../../etc/passwd — LFI then write shell. "
     "Use path_traversal_payloads.",
     "path_traversal_payloads"),
    ("tomcat", "9", "CVE-2017-12615", "HIGH", "Tomcat PUT JSP upload",
     "PUT /shell.jsp/ with %20 or .jsp; then execute. Use file_upload_bypass.",
     "file_upload_bypass"),
    ("tomcat", "", "CVE-2020-1938", "HIGH", "Ghostcat AJP file read/RCE",
     "Read arbitrary files via AJP 8009. If 8009 open, use path_traversal_payloads via AJP.",
     "path_traversal_payloads"),
    ("weblogic", "", "CVE-2020-14882", "CRITICAL", "WebLogic console RCE",
     "GET /console/css/%252e%252e%252fconsole.portal with exec payload. Use http_request + payload_encoders.",
     "payload_encoders"),
    ("jenkins", "", "CVE-2024-23897", "HIGH", "Jenkins args4j arbitrary file read",
     "POST /cli with binary payload leaks file contents. Use http_request to read /etc/passwd.",
     "http_request"),
    ("gitlab", "", "CVE-2021-22205", "CRITICAL", "GitLab ExifTool RCE",
     "POST /uploads/user with a crafted DjVu image. Use file_upload_bypass + http_request.",
     "file_upload_bypass"),
    ("wordpress", "", "CVE-2019-8942", "HIGH", "WordPress media upload RCE",
     "Crop-image path traversal + PHP fallback. Use file_upload_bypass.",
     "file_upload_bypass"),
    ("php", "", "CVE-2019-11043", "HIGH", "PHP-FPM RCE (php.ini bypass)",
     "Add ?a[]=1&a[]=2 to any php page; send crafted path-info. Replay with http_request.",
     "http_request"),
    ("phpunit", "", "CVE-2017-9841", "HIGH", "PHPUnit eval-stdin RCE",
     "POST PHP code to /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php. Use http_request.",
     "http_request"),
    ("exim", "", "CVE-2019-10149", "CRITICAL", "Exim RCE (return of the wizarD)",
     "SMTP MAIL FROM with ${run{...}} expansion. Use http_request/raw socket.",
     "http_request"),
    ("webmin", "", "CVE-2019-15107", "CRITICAL", "Webmin password_change RCE",
     "POST /password_change.cgi with crafted data; root RCE without auth.",
     "http_request"),
    ("openssh", "", "CVE-2024-6387", "CRITICAL", "regreSSHion OpenSSH RCE",
     "Race-based RCE via LoginGraceTime. Check ssh version first, then craft exploit.",
     "http_request"),
    ("ssh", "", "CVE-2024-6387", "CRITICAL", "regreSSHion OpenSSH RCE",
     "Race-based RCE via LoginGraceTime. Check ssh version first, then craft exploit.",
     "http_request"),
    ("openssl", "", "CVE-2014-0160", "HIGH", "Heartbleed memory leak",
     "Send heartbeat request to leak memory (private keys / cookies).",
     "http_request"),
    ("runc", "", "CVE-2019-5736", "HIGH", "runc container escape",
     "Overwrite runc binary from inside container. Local exploit.",
     "shellcode_multi"),
    ("sudo", "", "CVE-2021-3156", "HIGH", "sudo Baron Samedit heap overflow",
     "sudoedit -s -u#-1 exploit for local privilege escalation.",
     "shellcode_multi"),
    ("sudo", "1.8", "CVE-2019-14287", "HIGH", "sudo runas user#-1 bypass",
     "sudo -u#-1 id → root. Check sudoers.",
     "http_request"),
    ("windows", "", "CVE-2021-34527", "CRITICAL", "PrintNightmare LPE/RCE",
     "spoolsv.dll exploit for local/remote RCE.",
     "revshell_generator"),
    ("windows", "", "CVE-2017-0144", "CRITICAL", "EternalBlue SMB RCE",
     "MS17-010 SMB exploit (msfvenom/metasploit) for Windows 7/Server 2008.",
     "revshell_generator"),
    ("git", "", "CVE-2022-39253", "MODERATE", "Git arbitrary file read via submodule",
     "Malicious .gitmodules can read files. Check repo for submodules.",
     "path_traversal_payloads"),
    ("kubernetes", "", "CVE-2023-44487", "HIGH", "HTTP/2 Rapid Reset DoS",
     "Rapid reset streams exhaust server resources.",
     "http_request"),
    ("nginx", "", "CVE-2021-23017", "HIGH", "nginx resolver off-by-one",
     "DNS resolver buffer overflow — craft a malicious DNS response.",
     "http_request"),
    ("drupal", "", "CVE-2018-7600", "CRITICAL", "Drupalgeddon2 RCE",
     "Form API array injection → RCE. Use http_request + payload_encoders.",
     "payload_encoders"),
    ("xstream", "", "CVE-2021-21349", "CRITICAL", "XStream deserialization RCE",
     "XML deserialization gadget chains. Use deserialization_payloads.",
     "deserialization_payloads"),
    ("fastjson", "", "CVE-2022-25845", "CRITICAL", "Fastjson deserialization RCE",
     "@type gadget in JSON body. Use deserialization_payloads.",
     "deserialization_payloads"),
    ("shiro", "", "CVE-2016-4437", "CRITICAL", "Apache Shiro rememberMe deserialization",
     "Forged rememberMe cookie (AES-CBC key). Use deserialization_payloads + cookie craft.",
     "deserialization_payloads"),
    ("owncloud", "", "CVE-2023-49103", "HIGH", "ownCloud phpinfo info disclosure",
     "GET /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php leaks config/credentials.",
     "http_request"),
    ("grafana", "", "CVE-2021-43798", "HIGH", "Grafana directory traversal",
     "GET /public/plugins/<plugin>/../../../../etc/passwd. Use path_traversal_payloads.",
     "path_traversal_payloads"),
    ("mongodb", "", "CVE-2013-3966", "HIGH", "MongoDB no-auth / opcodes",
     "Open 27017 without auth → dump all collections.",
     "http_request"),
    ("redis", "", "CVE-2022-0543", "CRITICAL", "Redis Lua sandbox escape RCE",
     "eval 'return os.execute(\"id\")' with Debian package Lua. Use http_request.",
     "http_request"),
    ("elasticsearch", "", "CVE-2015-3337", "HIGH", "Elasticsearch directory traversal",
     "GET /_plugin/head/../../../../etc/passwd. Use path_traversal_payloads.",
     "path_traversal_payloads"),
    ("docker", "", "CVE-2019-13139", "HIGH", "Docker image build RCE",
     "Malicious Dockerfile can run commands at build time.",
     "revshell_generator"),
]

# JWT alg confusion is a 'pattern' CVE — matched from problem keywords too.
PATTERN_CVES = [
    ("jwt", "CVE-2015-9235", "HIGH", "JWT RSA→HS256 key confusion",
     "Change alg to HS256 and sign with the RSA public key (kid tricks too). "
     "Use jwt_key_confusion — it does this automatically.",
     "jwt_key_confusion"),
    ("deserialization", "CVE-2015-1427", "HIGH", "Elasticsearch Groovy sandbox RCE",
     "Search API script with Groovy escape. Use deserialization_payloads.",
     "deserialization_payloads"),
]


def _get(url: str) -> dict | None:
    """Fetch JSON from url with a short timeout. Returns None on any failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctfkit-cve-research/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def _kb_for(software: str) -> list[dict]:
    """Local knowledge-base entries matching a software keyword."""
    key = software.lower()
    hits = []
    for (sw, ver, cve, sev, title, tip, tool) in CVE_KB:
        if sw == key or sw in key or key in sw:
            hits.append({"cve": cve, "severity": sev, "title": title,
                         "tip": tip, "tool": tool, "version": ver, "source": "local-kb"})
    for (kw, cve, sev, title, tip, tool) in PATTERN_CVES:
        if kw in key:
            hits.append({"cve": cve, "severity": sev, "title": title,
                         "tip": tip, "tool": tool, "version": "", "source": "pattern"})
    return hits


def _parse_explicit_cves(problem: str) -> list[str]:
    return sorted(set(re.findall(r"(?i)cve-\d{4}-\d{4,7}", problem)))


def _parse_software(problem: str) -> list[dict]:
    """Detect (software, version) pairs in the problem text."""
    text = problem.lower()
    found: list[dict] = []
    for key, name in SOFTWARE_NAMES.items():
        if key in text:
            versions = re.findall(rf"{re.escape(key)}\s*(?:v|version\s*)?\s*(\d+(?:\.\d+)+(?:[.-][a-z0-9]+)?)", text)
            versions += re.findall(rf"\b(\d+\.\d+(?:\.\d+)?)\b", text)
            # keep only versions near the keyword mention
            near = []
            for m in re.finditer(re.escape(key), text):
                window = text[m.start():m.start() + 40]
                vm = re.search(r"(\d+(?:\.\d+)+(?:[.-][a-z0-9]+)?)", window)
                if vm and vm.group(1) not in near:
                    near.append(vm.group(1))
            found.append({
                "key": key, "name": name,
                "version": near[0] if near else (versions[0] if versions else ""),
            })
    return found


def _format_nvd_cve(v: dict) -> str:
    """Pretty-print one NVD CVE entry."""
    cve_id = v.get("id", "?")
    desc = ""
    for d in v.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d["value"]
            break
    if len(desc) > 400:
        desc = desc[:397] + "..."
    sev = "?"
    score = "?"
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if k in v.get("metrics", {}):
            data = v["metrics"][k][0].get("cvssData", {})
            score = str(data.get("baseScore", "?"))
            sev = data.get("baseSeverity", data.get("severity", "?"))
            break
    refs = [r.get("url") for r in v.get("references", []) if r.get("url")][:5]
    lines = [
        f"• {cve_id} | {sev} (CVSS {score})",
        f"  {desc}",
    ]
    if refs:
        lines.append("  References:")
        lines += [f"    - {r}" for r in refs]
    return "\n".join(lines)


def _exploit_links(cve_id: str) -> str:
    return (f"  PoC search: https://github.com/search?q={cve_id}+poc&type=code\n"
            f"  Exploit-DB:  https://www.exploit-db.com/search?cve={cve_id}\n"
            f"  NVD:         https://nvd.nist.gov/vuln/detail/{cve_id}")


@tool(category="web")
def cve_lookup(cve_id: str) -> str:
    """Look up a single CVE ID on NVD: severity, description, references, and exploit pointers.
    :param cve_id: CVE identifier (e.g. CVE-2025-55182)
    """
    cve_id = cve_id.strip().upper()
    if not re.match(r"CVE-\d{4}-\d{4,7}$", cve_id):
        return "⚠️ Invalid CVE ID format — use e.g. CVE-2025-55182."

    data = _get(f"{NVD_CVE_URL}?cveId={cve_id}")
    if not data or not data.get("vulnerabilities"):
        # offline: check local KB by CVE id
        for (sw, ver, cve, sev, title, tip, tool) in CVE_KB:
            if cve == cve_id:
                return (f"⚠️ NVD unreachable — local knowledge base hit:\n"
                        f"• {cve_id} | {sev} | {title}\n  {tip}\n"
                        f"  Next: run ctf-tools {tool} (or the equivalent MCP tool).\n" + _exploit_links(cve_id))
        return f"⚠️ Could not reach NVD for {cve_id} (offline). Try later or search GitHub/exploit-db:\n" + _exploit_links(cve_id)

    v = data["vulnerabilities"][0]["cve"]
    return _format_nvd_cve(v) + "\n" + _exploit_links(v.get("id", cve_id))


@tool(category="web")
def cve_search(software: str, version: str = "") -> str:
    """Keyword-search the NVD API for CVEs affecting a software product (optionally a version).
    :param software: product name (e.g. 'Apache HTTP Server')
    :param version: optional product version (e.g. '2.4.49')
    """
    query = f"{software} {version}".strip()
    data = _get(f"{NVD_CVE_URL}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=6")
    if not data:
        hits = _kb_for(software)
        if hits:
            out = [f"⚠️ NVD unreachable — local knowledge base for '{software}':"]
            for h in hits:
                out.append(f"• {h['cve']} | {h['severity']} | {h['title']}\n  {h['tip']}\n  Next: ctf-tools {h['tool']}")
            return "\n".join(out)
        return f"⚠️ Could not reach NVD and no local KB entry for '{software}'. Try cve_lookup with a specific ID."

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return f"No NVD results for '{query}'. Try a different keyword or cve_lookup('<CVE-ID>')."

    out = [f"NVD results for '{query}' ({len(vulns)} found):"]
    for item in vulns:
        out.append(_format_nvd_cve(item.get("cve", {})))
    out.append("Next: pick the matching CVE and run cve_lookup('<CVE-ID>') for exploit pointers.")
    return "\n".join(out)


@tool(category="web")
def cve_research(problem: str) -> str:
    """Understand a challenge, find the relevant CVE (from explicit IDs or software/version), and get an exploit plan. Run BEFORE exploiting a known product.
    :param problem: problem statement or target description (include software + version if known)
    """
    cves = _parse_explicit_cves(problem)
    software = _parse_software(problem)
    soft_line = ", ".join(f"{s['name']} {s['version']}".strip() for s in software) or "none detected"

    lines = [
        "🔎 CVE RESEARCH —",
        f"Problem      : {problem[:160]}",
        f"Explicit CVEs: {', '.join(cves) or 'none'}",
        f"Software     : {soft_line}",
        "",
    ]

    seen: dict[str, dict] = {}

    # 1. Explicit CVE IDs
    for cve in cves:
        data = _get(f"{NVD_CVE_URL}?cveId={cve}")
        if data and data.get("vulnerabilities"):
            v = data["vulnerabilities"][0]["cve"]
            seen[cve] = {"text": _format_nvd_cve(v), "source": "nvd"}
        else:
            for (sw, ver, c, sev, title, tip, tool) in CVE_KB:
                if c == cve:
                    seen[cve] = {"text": f"• {cve} | {sev} | {title}\n  {tip}\n  Next: ctf-tools {tool}", "source": "local-kb"}
                    break

    # 2. Software + version → NVD keyword search + local KB
    for s in software:
        query = f"{s['name']} {s['version']}".strip()
        data = _get(f"{NVD_CVE_URL}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=3")
        if data and data.get("vulnerabilities"):
            for item in data["vulnerabilities"][:3]:
                v = item.get("cve", {})
                cid = v.get("id")
                if cid and cid not in seen:
                    seen[cid] = {"text": _format_nvd_cve(v), "source": "nvd"}
        for h in _kb_for(s["key"]):
            if h["cve"] not in seen:
                ver_note = f" (targets {s['name']} {h['version']})" if h["version"] else ""
                seen[h["cve"]] = {
                    "text": (f"• {h['cve']} | {h['severity']} | {h['title']}{ver_note}\n"
                             f"  {h['tip']}\n  Next: ctf-tools {h['tool']}"),
                    "source": "local-kb",
                }

    if not seen:
        lines.append("No CVE matched yet. Manual next steps:")
        lines.append("  - Identify the exact product + version (browser_agent / whatweb / curl headers / package files).")
        lines.append("  - Run cve_search(software='<product>', version='<version>') with the exact banner/version.")
        lines.append("  - Or cve_lookup('<CVE-ID>') if the problem names one.")
    else:
        lines.append(f"RELEVANT CVEs ({len(seen)}):")
        for cid in sorted(seen):
            lines.append(seen[cid]["text"])
            lines.append(_exploit_links(cid))
            lines.append("")

    # 3. Exploitation plan (map to ctfkit tools)
    tools_hinted = sorted({h.get("tool", "") for h in seen.values() if h.get("tool")})
    if tools_hinted:
        lines.append("EXPLOITATION PLAN — try in order:")
        for i, tool_name in enumerate(tools_hinted, 1):
            lines.append(f"  {i}. ctf-tools {tool_name} (MCP) → or python -c "
                         f"\"import ctfkit.modules; from ctfkit.registry import run_tool; "
                         f"print(run_tool('{tool_name}', {{}}))\"")
        lines.append("  Next: probe the target, capture the vulnerable request in Burp (Proxy→Repeater),")
        lines.append("        replay the PoC, and extract_flags_tool on every response.")

    lines.append("")
    lines.append("📌 If the product is custom/unknown: run cve_search('<product>') + recall_knowledge('<keywords>'),")
    lines.append("   then fall back to generic web tools (path_traversal / file_upload_bypass / ssti_payloads).")
    return "\n".join(lines)


# Backwards-compatible aliases used by discover_techniques().
def detect_cves_in_problem(problem: str) -> list[str]:
    return _parse_explicit_cves(problem)


def detect_software_in_problem(problem: str) -> list[dict]:
    return _parse_software(problem)