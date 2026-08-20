"""External CLI tool wrappers per category (nmap, ffuf, sqlmap, binwalk, ...).

Runs installed binaries via subprocess. Missing tools are auto-installed
(winget / apt / brew / pip per platform) when auto=True, then re-checked.
On Linux, tools without a specific installer fall back to `apt-get install -y <name>`.
Output is truncated to keep MCP/API responses small; never invented results.

SecLists wordlists: auto-downloaded to testdata/wordlists/ on first use.
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from ..logging import log
from ..registry import tool

_MAX_OUT = 8000
_INSTALL_TIMEOUT = 600

PIP = sys.executable  # installs into the venv the server runs from
_VENV_BIN = Path(sys.executable).parent

# Wordlist directory
WORDLIST_DIR = Path(__file__).resolve().parent.parent / "testdata" / "wordlists"
SEC_LISTS_URL = "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"
SEC_LISTS_DIR = WORDLIST_DIR / "SecLists-master"

def _ensure_seclists():
    """Download and extract SecLists if not present."""
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    if SEC_LISTS_DIR.exists():
        return str(SEC_LISTS_DIR)
    
    import urllib.request
    import zipfile
    import tempfile
    
    log.info("[external] Downloading SecLists wordlists...")
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            urllib.request.urlretrieve(SEC_LISTS_URL, tmp.name)
            log.info("[external] Extracting SecLists...")
            with zipfile.ZipFile(tmp.name, 'r') as z:
                z.extractall(WORDLIST_DIR)
        os.unlink(tmp.name)
        log.info(f"[external] SecLists ready at {SEC_LISTS_DIR}")
        return str(SEC_LISTS_DIR)
    except Exception as e:
        log.warning(f"[external] SecLists download failed: {e}")
        return str(WORDLIST_DIR)  # fallback

def _get_default_wordlist(category: str) -> str:
    """Get default wordlist path for a tool category."""
    seclists = _ensure_seclists()
    
    # Common wordlist mappings
    wordlists = {
        "dir": os.path.join(seclists, "Discovery", "Web-Content", "raft-medium-directories.txt"),
        "file": os.path.join(seclists, "Discovery", "Web-Content", "raft-medium-files.txt"),
        "subdomain": os.path.join(seclists, "Discovery", "DNS", "subdomains-top1million-110000.txt"),
        "password": os.path.join(seclists, "Passwords", "Common-Credentials", "10k-most-common.txt"),
        "user": os.path.join(seclists, "Usernames", "Names", "names.txt"),
        "generic": os.path.join(seclists, "Discovery", "Web-Content", "raft-medium-words.txt"),
    }
    
    # Return appropriate wordlist or fallback to rockyou if available
    rockyou = "/usr/share/wordlists/rockyou.txt"
    if os.path.exists(rockyou):
        wordlists["password"] = rockyou
    
    return wordlists.get(category, wordlists["generic"])

# tool -> {platform: install command or None if no auto-installer known}
INSTALL_CMD = {
    "nmap": {"win32": "winget install -e --id Insecure.Nmap --accept-source-agreements --accept-package-agreements",
             "linux": "apt-get install -y nmap", "darwin": "brew install nmap"},
    "masscan": {"linux": "apt-get install -y masscan", "darwin": "brew install masscan"},
    "whatweb": {"linux": "apt-get install -y whatweb"},
    "dnsrecon": {"linux": "apt-get install -y dnsrecon"},
    "ffuf": {"linux": "apt-get install -y ffuf", "darwin": "brew install ffuf"},
    "gobuster": {"linux": "apt-get install -y gobuster", "darwin": "brew install gobuster"},
    "sqlmap": {"win32": f'"{PIP}" -m pip install --quiet sqlmap', "linux": "apt-get install -y sqlmap", "darwin": "brew install sqlmap"},
    "nikto": {"linux": "apt-get install -y nikto", "darwin": "brew install nikto"},
    "wfuzz": {"linux": "apt-get install -y wfuzz", "darwin": "brew install wfuzz"},
    "binwalk": {"linux": "apt-get install -y binwalk", "darwin": "brew install binwalk"},
    "exiftool": {"linux": "apt-get install -y libimage-exiftool-perl", "darwin": "brew install exiftool"},
    "foremost": {"linux": "apt-get install -y foremost"},
    "bulk_extractor": {"linux": "apt-get install -y bulk-extractor"},
    "volatility3": {"win32": f'"{PIP}" -m pip install --quiet volatility3', "linux": "pipx install volatility3", "darwin": "pipx install volatility3"},
    "steghide": {"linux": "apt-get install -y steghide", "darwin": "brew install steghide"},
    "zsteg": {"linux": "gem install zsteg", "darwin": "gem install zsteg"},
    "outguess": {"linux": "apt-get install -y outguess"},
    "hashcat": {"win32": "winget install -e --id Hashcat.Hashcat --accept-source-agreements --accept-package-agreements",
                "linux": "apt-get install -y hashcat", "darwin": "brew install hashcat"},
    "john": {"win32": "winget install -e --id Openwall.John --accept-source-agreements --accept-package-agreements",
             "linux": "apt-get install -y john", "darwin": "brew install john"},
    "objdump": {"linux": "apt-get install -y binutils"},
    "readelf": {"linux": "apt-get install -y binutils"},
    "r2": {"win32": "winget install -e --id radareorg.radare2 --accept-source-agreements --accept-package-agreements",
           "linux": "apt-get install -y radare2", "darwin": "brew install radare2"},
    "one_gadget": {"linux": "gem install one_gadget", "darwin": "gem install one_gadget"},
    "dirsearch": {"win32": f'"{PIP}" -m pip install --quiet dirsearch', "linux": f'"{PIP}" -m pip install --quiet dirsearch'},
    "arjun": {"win32": f'"{PIP}" -m pip install --quiet arjun', "linux": f'"{PIP}" -m pip install --quiet arjun'},
    "sherlock": {"win32": f'"{PIP}" -m pip install --quiet sherlock', "linux": f'"{PIP}" -m pip install --quiet sherlock'},
    "maigret": {"win32": f'"{PIP}" -m pip install --quiet maigret', "linux": f'"{PIP}" -m pip install --quiet maigret'},
    "wafw00f": {"win32": f'"{PIP}" -m pip install --quiet wafw00f', "linux": f'"{PIP}" -m pip install --quiet wafw00f'},
    "ssh-audit": {"win32": f'"{PIP}" -m pip install --quiet ssh-audit', "linux": f'"{PIP}" -m pip install --quiet ssh-audit'},
    "pwntools": {"win32": f'"{PIP}" -m pip install --quiet pwntools', "linux": f'"{PIP}" -m pip install --quiet pwntools'},
    "ROPgadget": {"win32": f'"{PIP}" -m pip install --quiet ROPGadget', "linux": f'"{PIP}" -m pip install --quiet ROPGadget'},
    "ropper": {"win32": f'"{PIP}" -m pip install --quiet ropper', "linux": f'"{PIP}" -m pip install --quiet ropper'},
    "angr": {"win32": f'"{PIP}" -m pip install --quiet angr', "linux": f'"{PIP}" -m pip install --quiet angr'},
    "xortool": {"win32": f'"{PIP}" -m pip install --quiet xortool', "linux": f'"{PIP}" -m pip install --quiet xortool'},
    "stegano": {"win32": f'"{PIP}" -m pip install --quiet stegano', "linux": f'"{PIP}" -m pip install --quiet stegano'},
    "olevba": {"win32": f'"{PIP}" -m pip install --quiet oletools', "linux": f'"{PIP}" -m pip install --quiet oletools'},
    "oledump": {"win32": f'"{PIP}" -m pip install --quiet oletools', "linux": f'"{PIP}" -m pip install --quiet oletools'},
    "pdf-parser": {"win32": f'"{PIP}" -m pip install --quiet pdf-parser', "linux": f'"{PIP}" -m pip install --quiet pdf-parser'},
    "hashid": {"win32": f'"{PIP}" -m pip install --quiet hashid', "linux": f'"{PIP}" -m pip install --quiet hashid'},
    "z3": {"win32": f'"{PIP}" -m pip install --quiet z3-solver', "linux": f'"{PIP}" -m pip install --quiet z3-solver'},
    "theHarvester": {"linux": "apt-get install -y theharvester", "darwin": "brew install theHarvester"},
    "spiderfoot": {"win32": f'"{PIP}" -m pip install --quiet spiderfoot', "linux": f'"{PIP}" -m pip install --quiet spiderfoot'},
    "wpscan": {"linux": "gem install wpscan", "darwin": "gem install wpscan"},
    "fierce": {"linux": f'"{PIP}" -m pip install --quiet fierce', "darwin": f'"{PIP}" -m pip install --quiet fierce'},
    "testssl.sh": {"linux": "apt-get install -y testssl.sh"},
    "ghidra_headless": {"linux": "apt-get install -y ghidra", "darwin": "brew install --cask ghidra"},
    "commix": {"linux": "apt-get install -y commix"},
    "feroxbuster": {"linux": "apt-get install -y feroxbuster", "darwin": "brew install feroxbuster"},
    "rustscan": {"darwin": "brew install rustscan"},
    "sleuthkit": {"linux": "apt-get install -y sleuthkit", "darwin": "brew install sleuthkit"},
    "tshark": {"linux": "apt-get install -y tshark", "darwin": "brew install wireshark"},
    "zbarimg": {"linux": "apt-get install -y zbar-tools", "darwin": "brew install zbar"},
    "pngcheck": {"linux": "apt-get install -y pngcheck", "darwin": "brew install pngcheck"},
    "fcrackzip": {"linux": "apt-get install -y fcrackzip", "darwin": "brew install fcrackzip"},
    "testdisk": {"linux": "apt-get install -y testdisk", "darwin": "brew install testdisk"},
    "qpdf": {"linux": "apt-get install -y qpdf", "darwin": "brew install qpdf"},
    "upx": {"linux": "apt-get install -y upx-ucl", "darwin": "brew install upx"},
    "patchelf": {"linux": "apt-get install -y patchelf", "darwin": "brew install patchelf"},
    "gdb": {"linux": "apt-get install -y gdb", "darwin": "brew install gdb"},
    "strace": {"linux": "apt-get install -y strace", "darwin": "brew install strace"},
    "ltrace": {"linux": "apt-get install -y ltrace", "darwin": "brew install ltrace"},
    "hydra": {"linux": "apt-get install -y hydra", "darwin": "brew install hydra"},
    "enum4linux": {"linux": "apt-get install -y enum4linux"},
    "smbclient": {"linux": "apt-get install -y smbclient", "darwin": "brew install smbclient"},
    "nbtscan": {"linux": "apt-get install -y nbtscan"},
    "onesixtyone": {"linux": "apt-get install -y onesixtyone"},
    "snmpwalk": {"linux": "apt-get install -y snmp"},
    "sslscan": {"linux": "apt-get install -y sslscan", "darwin": "brew install sslscan"},
    "dirb": {"linux": "apt-get install -y dirb", "darwin": "brew install dirb"},
    "wpscan": {"linux": "gem install wpscan", "darwin": "gem install wpscan"},
    "qemu": {"linux": "apt-get install -y qemu-user"},
    "7z": {"linux": "apt-get install -y p7zip-full", "darwin": "brew install p7zip"},
    "unzip": {"linux": "apt-get install -y unzip"},
    "sqlite3": {"linux": "apt-get install -y sqlite3", "win32": "winget install -e --id SQLite.SQLite --accept-source-agreements --accept-package-agreements"},
    "pdftotext": {"linux": "apt-get install -y poppler-utils", "darwin": "brew install poppler"},
    "convert": {"linux": "apt-get install -y imagemagick", "darwin": "brew install imagemagick"},
    "identify": {"linux": "apt-get install -y imagemagick", "darwin": "brew install imagemagick"},
    "ffmpeg": {"linux": "apt-get install -y ffmpeg", "darwin": "brew install ffmpeg"},
    "sox": {"linux": "apt-get install -y sox", "darwin": "brew install sox"},
    "searchsploit": {"linux": "apt-get install -y exploitdb"},
    "stegdetect": {"linux": "apt-get install -y stegdetect"},
}

# tool -> {platform: install command or None if no auto-installer known}
HINT = {
    "nmap": "apt install nmap", "masscan": "apt install masscan",
    "whatweb": "apt install whatweb", "dnsrecon": "apt install dnsrecon",
    "ffuf": "apt install ffuf", "gobuster": "apt install gobuster",
    "sqlmap": "apt install sqlmap", "nikto": "apt install nikto",
    "wfuzz": "apt install wfuzz", "binwalk": "apt install binwalk",
    "exiftool": "apt install libimage-exiftool-perl", "foremost": "apt install foremost",
    "bulk_extractor": "apt install bulk-extractor", "volatility3": "pipx install volatility3",
    "steghide": "apt install steghide", "zsteg": "gem install zsteg",
    "outguess": "apt install outguess", "hashcat": "apt install hashcat",
    "john": "apt install john", "objdump": "apt install binutils",
    "readelf": "apt install binutils", "r2": "apt install radare2",
    "one_gadget": "gem install one_gadget", "rp++": "github.com/0vercl0k/rp",
    "rustscan": "cargo install rustscan", "naabu": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "go install github.com/owasp-amass/amass/v4/...@master",
    "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "gospider": "go install github.com/jaeles-project/gospider@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "aquatone": "go install github.com/michenriksen/aquatone@latest",
    "xsstrike": "git clone https://github.com/s0md3v/XSStrike",
    "jwt_tool": "git clone https://github.com/ticarpi/jwt_tool",
    "RsaCtfTool": "git clone https://github.com/RsaCtfTool/RsaCtfTool",
    "sherlock": "pip install sherlock", "maigret": "pip install maigret",
    "recon-ng": "pip install recon-ng", "wpscan": "gem install wpscan",
    "dirsearch": "pip install dirsearch", "arjun": "pip install arjun",
    "feroxbuster": "apt install feroxbuster", "wafw00f": "pip install wafw00f",
    "ssh-audit": "pip install ssh-audit", "spiderfoot": "pip install spiderfoot",
    "testssl.sh": "apt install testssl.sh", "commix": "apt install commix",
    "searchsploit": "apt install exploitdb", "hydra": "apt install hydra",
    "enum4linux": "apt install enum4linux", "smbclient": "apt install smbclient",
    "nbtscan": "apt install nbtscan", "onesixtyone": "apt install onesixtyone",
    "snmpwalk": "apt install snmp", "sslscan": "apt install sslscan",
    "dirb": "apt install dirb", "sleuthkit": "apt install sleuthkit",
    "tshark": "apt install tshark", "zbarimg": "apt install zbar-tools",
    "pngcheck": "apt install pngcheck", "fcrackzip": "apt install fcrackzip",
    "testdisk": "apt install testdisk", "qpdf": "apt install qpdf",
    "upx": "apt install upx-ucl", "patchelf": "apt install patchelf",
    "gdb": "apt install gdb", "strace": "apt install strace", "ltrace": "apt install ltrace",
    "pwntools": "pip install pwntools", "ROPgadget": "pip install ROPgadget",
    "ropper": "pip install ropper", "angr": "pip install angr",
    "xortool": "pip install xortool", "stegano": "pip install stegano",
    "olevba": "pip install oletools", "oledump": "pip install oletools",
    "pdf-parser": "pip install pdf-parser", "hashid": "pip install hashid",
    "stegdetect": "apt install stegdetect", "stegseek": "github.com/RickdeJager/stegseek",
    "mp3stego": "github.com/fabienpe/MP3Stego", "qemu": "apt install qemu-user",
    "7z": "apt install p7zip-full", "unzip": "apt install unzip",
    "sqlite3": "apt install sqlite3", "pdftotext": "apt install poppler-utils",
    "convert": "apt install imagemagick", "identify": "apt install imagemagick",
    "ffmpeg": "apt install ffmpeg", "sox": "apt install sox",
    "curl": "apt install curl", "whois": "apt install whois",
    "dig": "apt install dnsutils", "host": "apt install dnsutils",
    "traceroute": "apt install traceroute", "nc": "apt install netcat-openbsd",
    "socat": "apt install socat", "msfvenom": "apt install metasploit-framework",
    "file": "apt install file", "strings": "apt install binutils",
    "xxd": "apt install xxd", "base64": "apt install coreutils",
    "capinfos": "apt install tshark", "gpg": "apt install gnupg",
    "mmls": "apt install sleuthkit", "fls": "apt install sleuthkit",
    "fsstat": "apt install sleuthkit",
    "foremost": "apt install foremost", "scalpel": "apt install scalpel",
}

# External tools per category — ordered by workflow priority (recon first).
ALLOWED = {
    "osint": [
        "nmap", "masscan", "rustscan", "naabu", "whatweb", "dnsrecon", "dnsenum",
        "dnsx", "subfinder", "amass", "theHarvester", "fierce", "httpx", "nuclei",
        "aquatone", "wafw00f", "spiderfoot", "whois", "dig", "host", "traceroute",
        "enum4linux", "smbclient", "nbtscan", "onesixtyone", "snmpwalk", "sslscan",
        "testssl.sh", "ssh-audit", "searchsploit", "sherlock", "maigret", "recon-ng",
    ],
    "web": [
        "nmap", "whatweb", "nikto", "gobuster", "ffuf", "wfuzz", "dirb", "dirsearch",
        "feroxbuster", "sqlmap", "nuclei", "wafw00f", "xsstrike", "dalfox", "commix",
        "wpscan", "jwt_tool", "hydra", "curl", "httpx", "arjun", "katana", "gospider",
        "searchsploit",
    ],
    "forensics": [
        "file", "strings", "xxd", "exiftool", "binwalk", "foremost", "scalpel",
        "bulk_extractor", "volatility3", "tshark", "capinfos", "7z", "unzip",
        "zipinfo", "testdisk", "sleuthkit", "mmls", "fls", "fsstat", "olevba",
        "oledump", "pdf-parser", "pdftotext", "qpdf", "gpg", "fcrackzip",
        "zip2john", "rar2john", "keepass2john", "sqlite3", "base64",
    ],
    "stego": [
        "zsteg", "steghide", "stegseek", "outguess", "stegdetect", "pngcheck",
        "zbarimg", "convert", "identify", "ffmpeg", "sox", "exiftool", "strings",
        "binwalk", "foremost",
    ],
    "crypto": [
        "hashcat", "john", "hashid", "xortool", "RsaCtfTool", "openssl", "gpg",
        "fcrackzip", "zip2john", "rar2john", "keepass2john", "z3", "base64", "xxd",
        "ccrypt", "findmyhash",
    ],
    "rev": [
        "file", "readelf", "objdump", "nm", "strings", "gdb", "ltrace", "strace",
        "r2", "angr", "retdec", "upx", "patchelf", "one_gadget", "rp++",
        "ROPgadget", "ropper", "checksec", "qemu", "pwntools", "nc", "socat",
        "msfvenom", "searchsploit", "ghidra_headless",
    ],
    "pwn": [
        "checksec", "ROPgadget", "ropper", "one_gadget", "rp++", "gdb", "pwntools",
        "nc", "socat", "msfvenom", "searchsploit", "patchelf", "readelf", "objdump",
        "r2", "file",
    ],
}

# Default argument templates per tool. Placeholders are filled from the problem
# statement: {host} {url} {file} {hash} {hashfile} {wordlist} {outdir} {port}.
# Tools without a template are still callable manually via the wrapper, but the
# agent only auto-queues tools that have one.
DEFAULT_ARGS = {
    # --- osint / recon ---
    "nmap": "-sV -T4 {host}",
    "masscan": "{host} -p1-10000 --rate 1000",
    "rustscan": "-a {host} --ulimit 5000",
    "naabu": "-host {host} -p -",
    "whatweb": "{url}",
    "dnsrecon": "-d {host}",
    "dnsenum": "{host}",
    "dnsx": "-d {host} -a -cname -mx -ns -txt",
    "subfinder": "-d {host}",
    "amass": "enum -passive -d {host}",
    "theHarvester": "-d {host} -b all -l 100",
    "fierce": "--domain {host}",
    "httpx": "-u {url}",
    "nuclei": "-u {url}",
    "aquatone": "--scan-timeout 30 {url}",
    "wafw00f": "{url}",
    "spiderfoot": "-q -s {host} -m all",
    "whois": "{host}",
    "dig": "{host} ANY +short",
    "host": "{host}",
    "traceroute": "{host}",
    "enum4linux": "-a {host}",
    "smbclient": "-L //{host} -N",
    "nbtscan": "{host}",
    "onesixtyone": "{host}",
    "snmpwalk": "-v2c -c public {host}",
    "sslscan": "{host}",
    "testssl.sh": "--quiet {host}",
    "ssh-audit": "{host}",
    # --- web ---
    "nikto": "-h {url}",
    "gobuster": "dir -u {url} -w {wordlist}",
    "ffuf": "-u {url}/FUZZ -w {wordlist}",
    "wfuzz": "-u {url}/FUZZ -w {wordlist}",
    "dirb": "{url} {wordlist}",
    "dirsearch": "-u {url} -e php,html,txt",
    "feroxbuster": "-u {url} -w {wordlist}",
    "sqlmap": "-u {url} --batch --level=1 --risk=1",
    "xsstrike": "-u {url}",
    "dalfox": "url {url}",
    "commix": "-u {url} --batch",
    "wpscan": "--url {url} --no-banner",
    "hydra": "-l admin -P {wordlist} {host} http-get /",
    "curl": "-s -i {url}",
    "arjun": "-u {url}",
    "katana": "-u {url}",
    "gospider": "-s {url}",
    # --- forensics ---
    "file": "{file}",
    "strings": "-a {file}",
    "xxd": "{file}",
    "exiftool": "{file}",
    "binwalk": "{file}",
    "foremost": "-i {file} -o {outdir}/foremost_out",
    "scalpel": "{file} -o {outdir}/scalpel_out",
    "bulk_extractor": "{file} -o {outdir}/bulk_out",
    "volatility3": "-f {file}",
    "tshark": "-r {file} -Y http -T fields -e http.request.uri -e http.host",
    "capinfos": "{file}",
    "7z": "l {file}",
    "unzip": "-l {file}",
    "zipinfo": "{file}",
    "testdisk": "/list {file}",
    "mmls": "{file}",
    "fls": "-r {file}",
    "fsstat": "{file}",
    "olevba": "{file}",
    "oledump": "{file}",
    "pdf-parser": "{file}",
    "pdftotext": "{file} -",
    "qpdf": "--check {file}",
    "gpg": "--list-packets {file}",
    "fcrackzip": "-u -D -p {wordlist} {file}",
    "zip2john": "{file}",
    "rar2john": "{file}",
    "keepass2john": "{file}",
    "sqlite3": "{file} .tables",
    "base64": "-d {file}",
    # --- stego ---
    "zsteg": "{file}",
    "steghide": "extract -sf {file} -p ''",
    "stegseek": "{file} {wordlist}",
    "outguess": "-r {file} {outdir}/outguess.txt",
    "stegdetect": "{file}",
    "pngcheck": "{file}",
    "zbarimg": "{file}",
    "convert": "{file} -negate {outdir}/negated.png",
    "identify": "{file}",
    "ffmpeg": "-i {file} {outdir}/frame_%03d.png",
    "sox": "{file} -n stat",
    # --- crypto ---
    "hashcat": "{hash} -a 3 -m 0 ?a?a?a?a?a",
    "john": "--format=raw-md5 {hashfile}",
    "hashid": "{hash}",
    "xortool": "-x {file}",
    "openssl": "dgst -sha256 {file}",
    "ccrypt": "-d {file}",
    "findmyhash": "{hash}",
    "RsaCtfTool": "--publickey {file}",
    # --- rev ---
    "readelf": "-h -l -S {file}",
    "objdump": "-d {file}",
    "nm": "{file}",
    "gdb": "-batch -ex 'info functions' {file}",
    "ltrace": "{file}",
    "strace": "{file}",
    "r2": "-q -c 'ii; iE; afl' {file}",
    "upx": "-t {file}",
    "patchelf": "--print-all {file}",
    "one_gadget": "{file}",
    "rp++": "-f {file} -r 5",
    "ROPgadget": "--binary {file} --depth 5",
    "ropper": "--file {file}",
    "checksec": "--file {file}",
    "qemu": "{file}",
    "ghidra_headless": "analyzeHeadless {outdir}/ghidra_proj {outdir}/ghidra_proj -import {file} -postScript {outdir}/analysis.py",
    # --- pwn ---
    "pwntools": "checksec {file}",
    "nc": "-vz {host} {port}",
    "socat": "-T10 -d -d tcp:{host}:{port}",
    "msfvenom": "-p linux/x64/shell_reverse_tcp LHOST={host} LPORT={port} -f elf -o {outdir}/payload.elf",
}

# tools that were in ALLOWED but have no auto-queued template
_NO_TEMPLATE = {"searchsploit", "sherlock", "maigret", "recon-ng", "jwt_tool", "retdec", "angr", "clang", "gcc", "sleuthkit", "z3"}


def _find_exe(name: str) -> str | None:
    """which(), plus the venv bin dir (pip-installed CLIs live there)."""
    found = shutil.which(name)
    if found:
        return found
    for cand in (_VENV_BIN / name, _VENV_BIN / f"{name}.exe"):
        if cand.is_file():
            return str(cand)
    return None


def _split_args(args: str) -> list[str]:
    """shlex with real quoting (gdb -ex '...' / r2 -c '...' keep groups).
    Windows: normalize backslashes so posix parsing doesn't eat them."""
    raw = args.replace("\\", "/") if sys.platform == "win32" else args
    return shlex.split(raw, posix=True)


def _docker_prefix() -> list[str] | None:
    """Run missing tools via a Kali container when Docker is available.
    Disable with CTFKIT_DOCKER=0; auto-pull with CTFKIT_DOCKER_PULL=1."""
    if os.environ.get("CTFKIT_DOCKER", "0") != "1":
        return None
    docker = shutil.which("docker")
    if not docker:
        return None
    img = os.environ.get("CTFKIT_DOCKER_IMAGE", "kalilinux/kali-rolling")
    try:
        inspect = subprocess.run([docker, "image", "inspect", img], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return None
    if inspect.returncode != 0:
        if os.environ.get("CTFKIT_DOCKER_PULL") != "1":
            return None
        subprocess.run([docker, "pull", img], capture_output=True, timeout=600)
    return [docker, "run", "--rm", "--network", "none", "-v", f"{os.getcwd()}:/work:ro", "-w", "/work", img]


def _auto_install(name: str, timeout: int = _INSTALL_TIMEOUT) -> str:
    from ..config import settings

    if not settings.allow_install:
        return ("AUTO-INSTALL BLOCKED by CTFKIT_ALLOW_INSTALL=0. "
                "Remove that override or install the dependency manually.")
    if os.environ.get("CTFKIT_SAFETY_MODE", "auto").lower() not in {"auto", "admin"}:
        return "AUTO-INSTALL BLOCKED by the configured safety-policy override."
    cmd = INSTALL_CMD.get(name, {}).get(sys.platform)
    if not cmd and sys.platform.startswith("linux"):
        cmd = f"apt-get install -y {name}"
    if not cmd:
        return f"No auto-installer known for '{name}' on this OS. Manual: {HINT.get(name, 'apt install ' + name)}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        if _find_exe(name):
            return f"INSTALLED '{name}' via: {cmd}"
        if proc.returncode != 0 and shutil.which("sudo") and sys.platform.startswith("linux"):
            sudo_cmd = cmd.replace("apt-get", "sudo apt-get", 1)
            subprocess.run(sudo_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if _find_exe(name):
                return f"INSTALLED '{name}' via: {sudo_cmd}"
        return (f"INSTALL FAILED for '{name}' ({cmd}) exit={proc.returncode}: "
                f"{proc.stderr.strip()[-500:] or proc.stdout.strip()[-500:]}")
    except subprocess.TimeoutExpired:
        return f"INSTALL TIMEOUT after {timeout}s for '{name}' ({cmd})"
    except OSError as ex:
        return f"INSTALL ERROR for '{name}': {ex}"


_PROGRESS_RES = (
    (re.compile(r"Progress:\s*\[(\d+)/(\d+)\]"), "ffuf"),           # ffuf
    (re.compile(r"Progress:\s*(\d+)\s*/\s*(\d+)"), "gobuster"),     # gobuster dir
    (re.compile(r"Progress\.+:\s*(\d+)/(\d+)\s*\((\d+)%\)"), "hashcat"),
    (re.compile(r"(\d+)g\s+\d+:\d+:\d+:\d+\s+(\d+)%"), "john"),     # john
)
_GENERIC_PCT = re.compile(r"(\d{1,3})%")


def _parse_progress(line: str) -> tuple[float | None, str | None, str | None]:
    """Extract (percent, current, total) from a tool's progress line, if any."""
    for pat, kind in _PROGRESS_RES:
        m = pat.search(line)
        if m:
            if kind == "john":
                return float(m.group(2)), None, None
            if kind == "hashcat":
                return float(m.group(3)), m.group(1), m.group(2)
            return float(m.group(1)) / float(m.group(2)) * 100.0, m.group(1), m.group(2)
    m = _GENERIC_PCT.search(line)
    if m:
        return float(m.group(1)), None, None
    return None, None, None


def _emit_progress(name: str, pct: float, cur: str | None, total: str | None, elapsed: float):
    filled = max(0, min(12, int(round(pct / 100.0 * 12))))
    bar = "█" * filled + "░" * (12 - filled)
    extra = f" [{cur}/{total}]" if cur and total else ""
    log.info("⏳ [%s] %s %3.0f%%%s (t+%.0fs)", name, bar, pct, extra, elapsed,
             extra={"progress": True, "progress_key": name})


_PROGRESS_COUNTS: dict[str, int] = {}  # tool -> currently running instances
_PROGRESS_SEQ: dict[str, int] = {}     # tool -> monotonic run number (unique keys)
_PROGRESS_LOCK = threading.Lock()


def _run_external(name: str, args: str, timeout: int, auto: bool) -> str:
    exe = _find_exe(name)
    install_report = ""
    if not exe:
        if auto:
            install_report = _auto_install(name, timeout=min(int(timeout), _INSTALL_TIMEOUT))
            exe = _find_exe(name)
    prefix = None
    if not exe:
        prefix = _docker_prefix()
    if not exe and not prefix:
        if auto:
            return install_report + " - result requires testing after manual install."
        return (f"TOOL '{name}' NOT INSTALLED (hint: {HINT.get(name, 'apt install ' + name)}). "
                "Result requires testing on a system with the tool.")
    import queue as _q
    import time as _time
    started = _time.time()
    try:
        cmd = [*prefix, name, *_split_args(args)] if prefix else [exe, *_split_args(args)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
    except OSError:
        return f"TOOL '{name}' FAILED TO RUN. Result requires testing."

    with _PROGRESS_LOCK:
        _PROGRESS_COUNTS[name] = _PROGRESS_COUNTS.get(name, 0) + 1
        _PROGRESS_SEQ[name] = _PROGRESS_SEQ.get(name, 0) + 1
        seq = _PROGRESS_SEQ[name]
        concurrent = _PROGRESS_COUNTS[name]
    label = name if concurrent == 1 else f"{name}#{seq}"
    key = f"{name}#{seq}"  # unique per invocation -> parallel runs get own rows
    where = "(docker)" if prefix else ""
    log.info("▶ [external] %s %s: %s %s", label, where, name, args,
             extra={"progress": True, "progress_key": key})

    try:
        return _run_proc(name, label, key, proc, args, timeout, started)
    finally:
        with _PROGRESS_LOCK:
            _PROGRESS_COUNTS[name] -= 1


def _run_proc(name: str, label: str, key: str, proc, args: str, timeout: int, started: float) -> str:
    """Stream a spawned process's output; returns the tail of its stdout."""
    import queue as _q
    import time as _time
    chunks = _q.Queue()

    def _pump(stream, tag):
        try:
            for line in iter(stream.readline, ""):
                chunks.put((tag, line))
        finally:
            stream.close()

    threading.Thread(target=_pump, args=(proc.stdout, "out"), daemon=True).start()
    threading.Thread(target=_pump, args=(proc.stderr, "err"), daemon=True).start()

    out_lines: list[str] = []
    err_lines: list[str] = []
    last_pct = -1
    last_progress = 0.0
    killed = False

    while _time.time() - started < timeout:
        try:
            tag, line = chunks.get(timeout=0.3)
        except _q.Empty:
            if proc.poll() is not None and chunks.empty():
                break
            continue
        for piece in line.split("\r"):  # tools overwrite the same line via \r
            piece = piece.rstrip()
            if not piece:
                continue
            (out_lines if tag == "out" else err_lines).append(piece)
            pct, cur, total = _parse_progress(piece)
            if pct is not None and (pct >= 100 or pct >= last_pct + 5 or _time.time() - last_progress >= 2.0):
                last_pct = pct
                last_progress = _time.time()
                _emit_progress(label, pct, cur, total, _time.time() - started)
    else:
        proc.kill()
        killed = True

    while True:  # drain anything the reader threads still hold
        try:
            tag, line = chunks.get(timeout=0.5)
        except _q.Empty:
            break
        for piece in line.split("\r"):
            piece = piece.rstrip()
            if piece:
                (out_lines if tag == "out" else err_lines).append(piece)

    proc.wait(timeout=5)
    elapsed = _time.time() - started
    if killed:
        log.warning("⏹ [external] %s KILLED after %.1fs (timeout %ds)", label, elapsed, timeout,
                    extra={"progress_done": key})
        return f"TIMEOUT after {timeout}s - try a narrower scope."
    log.info("⏹ [external] %s done in %.1fs (%d lines)", label, elapsed, len(out_lines),
             extra={"progress_done": key})
    out = "\n".join(out_lines)[-_MAX_OUT:]
    if proc.returncode != 0 and err_lines:
        err_tail = "\n".join(err_lines)[-1000:]
        out = f"ERROR: external command exited {proc.returncode}\n{out}\n[stderr] {err_tail}"
    return out.strip() or f"(exit {proc.returncode}, no output)"


def _wrapper(category: str, tool_name: str, args: str, timeout: int, auto: bool) -> str:
    if tool_name not in ALLOWED[category]:
        return f"Unsupported tool '{tool_name}'. Allowed: {sorted(ALLOWED[category])}"
    return _run_external(tool_name, args, timeout, auto)


@tool(category="osint")
def external_recon(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external recon/network tool: nmap, masscan, whatweb, dnsrecon, subfinder, amass, ... Missing tool is auto-installed when auto=True.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("osint", tool, args, timeout, auto)


@tool(category="web")
def external_web(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external web tool: nmap, gobuster, ffuf, sqlmap, nikto, wfuzz, dirsearch, ... Missing tool is auto-installed when auto=True.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("web", tool, args, timeout, auto)


@tool(category="forensics")
def external_forensics(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external forensics tool: binwalk, exiftool, foremost, tshark, volatility3, ... Auto-installs when missing.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("forensics", tool, args, timeout, auto)


@tool(category="stego")
def external_stego(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external stego tool: steghide, zsteg, outguess, stegseek, pngcheck, zbarimg, ... Missing tool is auto-installed when auto=True.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("stego", tool, args, timeout, auto)


@tool(category="crypto")
def external_crypto(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external crypto tool: hashcat, john, hashid, xortool, RsaCtfTool, ... Missing tool is auto-installed when auto=True.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("crypto", tool, args, timeout, auto)


@tool(category="rev")
def external_rev(tool: str, args: str = "", timeout: int = 120, auto: bool = False) -> str:
    """Run an external rev tool: objdump, readelf, r2, gdb, ROPgadget, upx, checksec, ghidra_headless, ... Missing tool is auto-installed when auto=True.
    :param args: args
    :param auto: auto
    :param timeout: timeout in seconds
    :param tool: tool
    """
    return _wrapper("rev", tool, args, timeout, auto)


@tool(category="misc")
def external_available() -> str:
    """List which external CLI tools are installed on this system, grouped by category."""
    lines = []
    for category, names in sorted(ALLOWED.items()):
        lines.append(f"{category}: " + ", ".join(
            f"{n} [INSTALLED]" if _find_exe(n) else f"{n} [missing - auto-installable: {bool(INSTALL_CMD.get(n, {}).get(sys.platform))}]"
            for n in sorted(names)))
    return "\n".join(lines)


@tool(category="misc")
def wordlist_path(category: str = "generic") -> str:
    """Get a default wordlist path for the given category (auto-downloads SecLists if missing).

    Categories: dir, file, subdomain, password, user, generic
    :param category: wordlist category
    """
    path = _get_default_wordlist(category)
    if os.path.exists(path):
        return f"WORDLIST: {path}"
    # Try to download if missing
    _ensure_seclists()
    path = _get_default_wordlist(category)
    if os.path.exists(path):
        return f"WORDLIST: {path}"
    return f"WORDLIST NOT FOUND: {path} (manual download required)"
