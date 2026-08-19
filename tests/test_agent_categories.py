"""Agent flow tests per category.

Fast strategy + comprehension tests for ALL 8 categories (no tool execution),
plus real end-to-end solves for categories with local testdata:
crypto (RSA close primes), stego (testdata/meta2.png), forensics (testdata/test.pcap).
web/osint/pwn/rev need a live target or a real vulnerable binary — their flow is
covered at strategy level; the solve paths require testing on a CTF instance.

Run: python tests/test_agent_categories.py   (CTF_E2E=0 skips the slow solves)
"""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
os.chdir(REPO_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import ctfkit.modules.agent  # noqa: registers every tool
from ctfkit.modules.agent import AgentState, _build_strategy, _understand_problem, autonomous_solve
from ctfkit.modules.external import ALLOWED as EXTERNAL_TOOLS

RUN_E2E = os.environ.get("CTF_E2E", "1") != "0"
TESTS: list[tuple[str, object]] = []


def test(name, fn):
    TESTS.append((name, fn))


def _plan(category: str, tools: str = "") -> str:
    return (f"CATEGORY: {category}\nPLATFORM: test\nSUGGESTED TOOLS: {tools}\n"
            "PLAN:\n  1. Inspect the input\n  2. Apply suggested tools and extract the flag")


def _strategy(problem: str, category: str, tools: str = ""):
    understanding = _understand_problem(problem)
    return _build_strategy(_plan(category, tools), "", AgentState(), category,
                           problem, hints=understanding["hints"])


def _ext_names(steps):
    return [s["args"]["tool"] for s in steps if s["source"] == "external"]


# ---------------------------------------------------------------- comprehension
def t_understand_lsb():
    u = _understand_problem("Find the flag hidden in the LSB of this PNG image: testdata/meta2.png")
    assert u["targets"]["file"] == "testdata/meta2.png", u
    assert u["hints"][0][0] == "lsb", u
    assert "lsb" in u["summary"], u


def t_understand_rsa():
    u = _understand_problem("RSA with close primes, decrypt: n=85070591730234615902737140005361155371 e=65537 c=18363045798433718843640502273308931278")
    assert u["hints"][0][0] == "rsa", u
    assert u["targets"]["big_int"], u
    assert "rsa" in u["summary"], u


def t_understand_sqli():
    u = _understand_problem("The login page is vulnerable to SQL injection, get admin: http://10.10.10.10/login")
    assert u["hints"][0][0] == "sql", u
    assert u["targets"]["url"] == "http://10.10.10.10/login", u


def t_understand_zip():
    u = _understand_problem("Unlock the password-protected archive testdata/pseudo.zip")
    assert u["targets"]["file"] == "testdata/pseudo.zip", u
    assert u["hints"][0][0] == "zip", u


# ------------------------------------------------------------- strategy per category
def t_osint_strategy():
    s = _strategy("Recon 10.10.10.5, enumerate ports and subdomains, find the flag", "osint",
                  "dns_query, dns_reverse")
    assert s, "osint: empty strategy"
    assert s[0]["tool"] == "external_recon", s[0]
    assert all(x["source"] == "external" for x in s[:5]), "osint: external must come first"
    names = _ext_names(s)
    assert "nmap" in names, names
    assert set(names) <= set(EXTERNAL_TOOLS["osint"]), set(names) - set(EXTERNAL_TOOLS["osint"])


def t_web_strategy():
    s = _strategy("SQL injection in the login form at http://10.10.10.5:8080/login — bypass auth and find the flag", "web",
                  "http_request, sqli_payloads")
    assert s and s[0]["tool"] == "external_web", s[0] if s else "web: empty strategy"
    names = _ext_names(s)
    assert "sqlmap" in names and "nmap" in names, names
    assert names.index("sqlmap") < names.index("nmap"), "web: sqlmap must be hint-prioritized over nmap"


def t_forensics_strategy():
    s = _strategy("Analyze the memory dump testdata/blob.bin and find the flag", "forensics",
                  "triage_file, strings_extract")
    assert s and s[0]["tool"] == "external_forensics", s[0] if s else "forensics: empty strategy"
    names = _ext_names(s)
    assert "file" in names, names
    assert set(names) <= set(EXTERNAL_TOOLS["forensics"]), set(names) - set(EXTERNAL_TOOLS["forensics"])


def t_stego_strategy():
    s = _strategy("A flag is hidden inside testdata/meta2.png using steganography", "stego",
                  "stego_metadata, stego_png_chunks")
    assert s and s[0]["tool"] == "external_stego", s[0] if s else "stego: empty strategy"
    names = _ext_names(s)
    assert "zsteg" in names, names


def t_crypto_strategy():
    problem = "RSA with close primes, decrypt: n=85070591730234615902737140005361155371 e=65537 c=18363045798433718843640502273308931278"
    s = _strategy(problem, "crypto", "rsa_fermat, rsa_wiener, decode_all")
    assert s, "crypto: empty strategy"
    assert not _ext_names(s), "crypto: no external steps without a file/hash target"
    assert s[0]["tool"] == "rsa_fermat", f"crypto: rsa hint must put rsa_fermat first, got {s[0]['tool']}"


def t_rev_strategy():
    s = _strategy("Reverse the binary testdata/dummy.elf and find the flag", "rev",
                  "elf_info, strings_extract")
    assert s and s[0]["tool"] == "external_rev", s[0] if s else "rev: empty strategy"
    names = _ext_names(s)
    assert "readelf" in names and set(names) <= set(EXTERNAL_TOOLS["rev"]), names


def t_pwn_strategy():
    s = _strategy("testdata/dummy.elf has a buffer overflow on the stack, get the flag", "pwn",
                  "checksec, debruijn, pwn_template")
    assert s and s[0]["tool"] == "external_rev", s[0] if s else "pwn: empty strategy"
    names = _ext_names(s)
    assert "checksec" in names, names
    assert names[0] == "checksec", "pwn: overflow hint must prioritize checksec"


def t_encoding_strategy():
    s = _strategy("Decode this base64 message and submit the flag: aGVsbG8gY3RmIQ==", "encoding",
                  "decode_all, decode_base")
    assert s, "encoding: empty strategy"
    assert not _ext_names(s), "encoding: no external wrapper for encoding"
    assert any(step["tool"] in ("decode_all", "decode_base") for step in s), [x["tool"] for x in s]


def t_no_duplicate_keys():
    for category in ("osint", "web", "forensics", "stego", "crypto", "rev", "pwn"):
        s = _strategy(f"find the flag in testdata/blob.bin (category {category})", category)
        keys = [x["key"] for x in s]
        assert len(keys) == len(set(keys)), f"{category}: duplicate step keys {keys}"


# ------------------------------------------------------------------ e2e solves
def t_e2e_crypto_rsa():
    out = autonomous_solve("RSA challenge: the two primes used for the modulus are very close to each other. "
                           "Recover the private key and decrypt the ciphertext. "
                           "n=85070591730234615902737140005361155371 e=65537 c=18363045798433718843640502273308931278",
                           max_iterations=4)
    # may be solved fresh (FLAG FOUND) or from saved experience (Already solved)
    assert "flag{fermat}" in out, out[-600:]
    assert "SOLVED" in out, out[-300:]


def t_e2e_stego_metadata():
    out = autonomous_solve("A flag is hidden inside testdata/meta2.png using steganography, find it", max_iterations=4)
    assert "flag{hidden_in_text_chunk}" in out and "SOLVED" in out, out[-600:]


def t_e2e_forensics_pcap():
    out = autonomous_solve("Analyze the network capture testdata/test.pcap and extract the flag", max_iterations=4)
    assert "flag{http_extracted}" in out and "SOLVED" in out, out[-600:]


test("understand: lsb", t_understand_lsb)
test("understand: rsa", t_understand_rsa)
test("understand: sqli", t_understand_sqli)
test("understand: zip", t_understand_zip)
test("osint strategy", t_osint_strategy)
test("web strategy", t_web_strategy)
test("forensics strategy", t_forensics_strategy)
test("stego strategy", t_stego_strategy)
test("crypto strategy", t_crypto_strategy)
test("rev strategy", t_rev_strategy)
test("pwn strategy", t_pwn_strategy)
test("encoding strategy", t_encoding_strategy)
test("no duplicate keys", t_no_duplicate_keys)
if RUN_E2E:
    test("e2e: crypto RSA close primes -> flag{fermat}", t_e2e_crypto_rsa)
    test("e2e: stego meta2.png -> flag{hidden_in_text_chunk}", t_e2e_stego_metadata)
    test("e2e: forensics test.pcap -> flag{http_extracted}", t_e2e_forensics_pcap)
else:
    print("CTF_E2E=0: skipping the 3 slow end-to-end solve tests")

passed = failed = 0
for name, fn in TESTS:
    try:
        fn()
        passed += 1
        print(f"  OK  {name}")
    except Exception as ex:
        failed += 1
        print(f"FAIL  {name}: {ex}")
print(f"\n{passed}/{passed + failed} category tests passed, {failed} failed")
sys.exit(1 if failed else 0)
