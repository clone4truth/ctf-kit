"""Headless Chrome browser agent for CTF web challenges: dump JS-rendered page
content (flags hidden behind client-side JS), screenshots for visual analysis,
form recon for injection targets, and security-header recon.

Requires: pip install selenium (Selenium 4.6+ auto-manages chromedriver via
Selenium Manager). Returns a clear availability message if Chrome is missing.

Session persistence: cookies and localStorage are saved to testdata/browser_sessions/<session_id>.json
and restored across browser_agent calls with the same session_id.
"""

import json
import os
import urllib.request
import re
from pathlib import Path
from typing import Any

from ..registry import tool

SHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "browser_shots")
SESSION_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "browser_sessions")

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


def _session_file(session_id: str) -> Path:
    """Get session file path for cookie/localStorage persistence."""
    Path(SESSION_DIR).mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:80]
    return Path(SESSION_DIR) / f"{safe_id}.json"


def _load_session(session_id: str) -> dict:
    """Load cookies and localStorage from session file."""
    path = _session_file(session_id)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"cookies": [], "localStorage": {}}


def _save_session(session_id: str, cookies: list, localStorage: dict):
    """Save cookies and localStorage to session file."""
    path = _session_file(session_id)
    path.write_text(json.dumps({"cookies": cookies, "localStorage": localStorage}, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _driver(session_id: str = ""):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    driver = webdriver.Chrome(options=opts)
    
    # Restore session if session_id provided
    if session_id:
        session = _load_session(session_id)
        if session.get("cookies"):
            # Navigate to domain first to set cookies
            pass  # Will restore after first navigation
    return driver


def _restore_session(driver, session_id: str):
    """Restore cookies and localStorage to driver."""
    if not session_id:
        return
    session = _load_session(session_id)
    # We need to navigate to the domain first before setting cookies
    # This will be called after first get() to the target domain


def _url_headers(url: str, timeout: int) -> dict:
    if url.startswith("data:"):
        return {}
    req = urllib.request.Request(url, headers={"User-Agent": "CTFKit-BrowserAgent/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {k: v for k, v in resp.headers.items()}


@tool(category="web")
def browser_agent(action: str = "full", url: str = "", js: str = "", out_path: str = "", session_id: str = "") -> str:
    """Headless Chrome browser agent for CTF web challenges. Dump JS-rendered page text, screenshot, extract forms/links, analyze security headers, run custom JS.

    Session persistence: pass session_id to persist cookies/localStorage across calls.
    Use action='login' for login flow: provide url, js to fill form, then session persists.
    
    :param action: 'content' (rendered page text — flags in JS-rendered pages) | 'navigate' | 'screenshot' | 'forms' | 'headers' | 'js' | 'full' (default) | 'login' (form fill + persist session) | 'cookies' (dump cookies)
    :param url: Target URL (supports data: URLs for offline testing)
    :param js: JavaScript to execute when action='js' or 'login'
    :param out_path: Screenshot destination (default testdata/browser_shots/shot.png)
    :param session_id: Session identifier for cookie/localStorage persistence
    """
    if not url:
        return "ERROR: url is required for this action."
    shot_root = Path(SHOT_DIR).resolve()
    path_obj = (shot_root / (Path(out_path).name if out_path else "shot.png")).resolve()
    path = str(path_obj)
    try:
        driver = _driver(session_id)
    except Exception as ex:
        return (f"BROWSER AGENT UNAVAILABLE: {ex}\n"
                "Install Chrome/Chromium + 'pip install selenium' (Selenium Manager auto-downloads chromedriver).")
    try:
        driver.set_page_load_timeout(30)
        driver.get(url)

        # Restore session after navigation to domain
        if session_id:
            session = _load_session(session_id)
            for cookie in session.get("cookies", []):
                try:
                    driver.add_cookie(cookie)
                except Exception:
                    pass
            for key, value in session.get("localStorage", {}).items():
                driver.execute_script(f"window.localStorage.setItem({json.dumps(key)}, {json.dumps(value)});")
            # Reload to apply cookies
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

        if action == "login":
            # Execute login JS (e.g., fill form and submit)
            if not js:
                return "ERROR: js parameter required for login action (form fill/submit script)"
            result = driver.execute_script(js)
            # Persist session after login
            cookies = driver.get_cookies()
            localStorage = driver.execute_script("return Object.fromEntries(Object.entries(localStorage));")
            _save_session(session_id, cookies, localStorage)
            return f"LOGIN RESULT:\n{result}\nSession persisted: {session_id}"

        if action == "cookies":
            cookies = driver.get_cookies()
            localStorage = driver.execute_script("return Object.fromEntries(Object.entries(localStorage));")
            if session_id:
                _save_session(session_id, cookies, localStorage)
            return f"COOKIES ({len(cookies)}):\n{json.dumps(cookies, indent=2)}\n\nLOCALSTORAGE ({len(localStorage)} keys):\n{json.dumps(localStorage, indent=2)}"

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
        # Persist session on exit if session_id provided
        if session_id:
            try:
                cookies = driver.get_cookies()
                localStorage = driver.execute_script("return Object.fromEntries(Object.entries(localStorage));")
                _save_session(session_id, cookies, localStorage)
            except Exception:
                pass
        driver.quit()


if __name__ == "__main__":
    hr = header_report({"Strict-Transport-Security": "max-age=31536000"})
    assert any("OK Strict-Transport-Security" in l for l in hr)
    assert any("MISSING Content-Security-Policy" in l for l in hr)
    print("header_report self-check OK")
