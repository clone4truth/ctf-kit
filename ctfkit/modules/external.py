"""External CLI tool wrappers per category (nmap, ffuf, sqlmap, binwalk, ...).

Runs installed binaries via subprocess. Missing tools are auto-installed
(winget / apt / brew / pip per platform) when auto=True, then re-checked.
Output is truncated to keep MCP/API responses small; never invented results.
"""

import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from ..registry import tool

_MAX_OUT = 8000
_INSTALL_TIMEOUT = 600

PIP = sys.executable  # installs into the venv the server runs from
_VENV_BIN = Path(sys.executable).parent

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
}

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
}

ALLOWED = {
    "osint": {"nmap", "masscan", "whatweb", "dnsrecon"},
    "web": {"ffuf", "gobuster", "sqlmap", "nikto", "wfuzz"},
    "forensics": {"binwalk", "exiftool", "foremost", "bulk_extractor", "volatility3"},
    "stego": {"steghide", "zsteg", "outguess"},
    "crypto": {"hashcat", "john"},
    "rev": {"objdump", "readelf", "r2", "one_gadget", "rp++"},
}


def _find_exe(name: str) -> str | None:
    """which(), plus the venv bin dir (pip-installed CLIs live there)."""
    found = shutil.which(name)
    if found:
        return found
    for cand in (_VENV_BIN / name, _VENV_BIN / f"{name}.exe"):
        if cand.is_file():
            return str(cand)
    return None


def _auto_install(name: str, timeout: int = _INSTALL_TIMEOUT) -> str:
    cmd = INSTALL_CMD.get(name, {}).get(sys.platform)
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


def _run_external(name: str, args: str, timeout: int, auto: bool) -> str:
    if not _find_exe(name):
        if auto:
            install_report = _auto_install(name)
            if not _find_exe(name):
                return install_report + " - result requires testing after manual install."
        else:
            return (f"TOOL '{name}' NOT INSTALLED (hint: {HINT.get(name, 'apt install ' + name)}). "
                    "Result requires testing on a system with the tool.")
    try:
        proc = subprocess.run([_find_exe(name), *shlex.split(args)], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        out = proc.stdout[-_MAX_OUT:]
        if proc.returncode != 0 and proc.stderr:
            out += f"\n[stderr] {proc.stderr[-1000:]}"
        return out.strip() or f"(exit {proc.returncode}, no output)"
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s - try a narrower scope."
    except OSError:
        return f"TOOL '{name}' FAILED TO RUN. Result requires testing."


def _wrapper(category: str, tool_name: str, args: str, timeout: int, auto: bool) -> str:
    if tool_name not in ALLOWED[category]:
        return f"Unsupported tool '{tool_name}'. Allowed: {sorted(ALLOWED[category])}"
    return _run_external(tool_name, args, timeout, auto)


@tool(category="osint")
def external_recon(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external recon/network tool: nmap, masscan, whatweb, dnsrecon. Missing tool is auto-installed when auto=True."""
    return _wrapper("osint", tool, args, timeout, auto)


@tool(category="web")
def external_web(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external web tool: ffuf, gobuster, sqlmap, nikto, wfuzz. Missing tool is auto-installed when auto=True."""
    return _wrapper("web", tool, args, timeout, auto)


@tool(category="forensics")
def external_forensics(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external forensics tool: binwalk, exiftool, foremost, bulk_extractor, volatility3. Auto-installs when missing."""
    return _wrapper("forensics", tool, args, timeout, auto)


@tool(category="stego")
def external_stego(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external stego tool: steghide, zsteg, outguess. Missing tool is auto-installed when auto=True."""
    return _wrapper("stego", tool, args, timeout, auto)


@tool(category="crypto")
def external_crypto(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external crypto tool: hashcat, john. Missing tool is auto-installed when auto=True."""
    return _wrapper("crypto", tool, args, timeout, auto)


@tool(category="rev")
def external_rev(tool: str, args: str = "", timeout: int = 120, auto: bool = True) -> str:
    """Run an external rev tool: objdump, readelf, r2, one_gadget, rp++. Missing tool is auto-installed when auto=True."""
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