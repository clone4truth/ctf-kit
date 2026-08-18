"""Headless Chrome browser agent for CTF web challenges: dump JS-rendered page
content (flags hidden behind client-side JS), screenshots for visual analysis,
form recon for injection targets, and security-header recon.

Requires: pip install selenium (Selenium 4.6+ auto-manages chromedriver via
Selenium Manager). Returns a clear availability message if Chrome is missing.
"""

import os
import urllib.request

from ..registry import tool

SHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "browser_shots")

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (force HTTPS; missing on HTTP-only sites)",
    "Content-Security-Policy": "CSP (XSS mitigation; missing = risky)",
    "X-Frame-Options": "clickjacking protection (missing = frameable)",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "referrer leakage control",
}


def header_report(headers: dict) -> list[str]:
    """Security header analysis (pure, testable)."""
    lines = []
    for h, note in SECURITY_HEADERS.items():
        v = headers.get(h)
        lines.append(f"  {'OK' if v else 'MISSING'} {h}" + (f" = {v[:80]}" if v else f" ({note})"))
    return lines


def _driver():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    return webdriver.Chrome(options=opts)


def _url_headers(url: str, timeout: int) -> dict:
    if url.startswith("data:"):
        return {}
    req = urllib.request.Request(url, headers={"User-Agent": "CTFKit-BrowserAgent/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {k: v for k, v in resp.headers.items()}


@tool(category="web")
def browser_agent(action: str = "full", url: str = "", js: str = "", out_path: str = "") -> str:
    """Headless Chrome browser agent for CTF web challenges. Dump JS-rendered page text, screenshot, extract forms/links, analyze security headers, run custom JS.

    :param action: 'content' (rendered page text — flags in JS-rendered pages) | 'navigate' | 'screenshot' | 'forms' | 'headers' | 'js' | 'full' (default)
    :param url: Target URL (supports data: URLs for offline testing)
    :param js: JavaScript to execute when action='js'
    :param out_path: Screenshot destination (default testdata/browser_shots/shot.png)
    """
    if not url:
        return "ERROR: url is required for this action."
    path = out_path or os.path.join(SHOT_DIR, "shot.png")
    try:
        driver = _driver()
    except Exception as ex:
        return (f"BROWSER AGENT UNAVAILABLE: {ex}\n"
                "Install Chrome/Chromium + 'pip install selenium' (Selenium Manager auto-downloads chromedriver).")
    try:
        driver.set_page_load_timeout(30)
        driver.get(url)

        if action == "content":
            text = driver.execute_script("return document.body ? document.body.innerText : ''")
            text = "\n".join(l for l in text.splitlines() if l.strip())
            if not text.strip():
                return "No rendered text on page (JS-only? try action='js' to inspect)."
            return f"RENDERED PAGE TEXT ({len(text)} chars):\n{text}"

        if action == "screenshot":
            os.makedirs(os.path.dirname(path), exist_ok=True)
            driver.save_screenshot(path)
            return f"Screenshot saved: {path} ({os.path.getsize(path)} bytes)"

        if action == "js":
            result = driver.execute_script(js)
            return f"JS RESULT:\n{result}"

        if action == "forms":
            forms = driver.execute_script(
                "return Array.from(document.forms).map(f => ({action: f.action, method: f.method,"
                " inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type})).filter(i => i.name)}))"
            )
            if not forms:
                return "No forms detected on page."
            lines = [f"{len(forms)} form(s) detected:"]
            for f in forms:
                inputs = ", ".join(f"{i['name']}:{i['type']}" for i in f["inputs"]) or "(no named inputs)"
                lines.append(f"  action={f['action'] or '?'} method={f['method'] or 'GET'}")
                lines.append(f"    inputs: {inputs}")
            return "\n".join(lines)

        title = driver.title
        links = driver.execute_script("return document.querySelectorAll('a[href]').length")
        forms_n = driver.execute_script("return document.forms.length")
        headers = _url_headers(url, 10)

        report = [
            "==================================================",
            f"🌐 BROWSER AGENT REPORT: {url}",
            "==================================================",
            f"Title        : {title}",
            f"Final URL    : {driver.current_url}",
            f"Links        : {links}",
            f"Forms        : {forms_n}",
            "--------------------------------------------------",
            "SECURITY HEADERS:",
        ]
        report += header_report(headers)
        if action == "headers":
            return "\n".join(report)

        if action == "full":
            os.makedirs(os.path.dirname(path), exist_ok=True)
            driver.save_screenshot(path)
            report.append(f"Screenshot   : {path} ({os.path.getsize(path)} bytes)")
            return "\n".join(report)

        return "\n".join(report)
    finally:
        driver.quit()


if __name__ == "__main__":
    hr = header_report({"Strict-Transport-Security": "max-age=31536000"})
    assert any("OK Strict-Transport-Security" in l for l in hr)
    assert any("MISSING Content-Security-Policy" in l for l in hr)
    print("header_report self-check OK")