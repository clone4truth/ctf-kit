"""Autonomous CTF solving agent with self-improvement capabilities.

The agent learns from mistakes, avoids repeating failed techniques,
and develops new strategies based on accumulated experience.
"""

import json
import re
import time
from pathlib import Path
from typing import Any

from ..flagmeta import extract_flags, detect_flag
from ..logging import log
from ..registry import tool, TOOLS, run_tool
from .analyze import detect_challenge, recall_knowledge, select_tools, optimize_parameters
from .external import ALLOWED as EXTERNAL_TOOLS, DEFAULT_ARGS as EXTERNAL_ARGS, _NO_TEMPLATE

AGENT_STATE_FILE = Path(__file__).resolve().parent.parent / "memory" / "agent_state.json"
NEW_TOOL_COUNTER_FILE = Path(__file__).resolve().parent.parent / "memory" / "new_tool_counter.json"


def _load_new_tool_counter() -> int:
    if NEW_TOOL_COUNTER_FILE.exists():
        try:
            return int(json.loads(NEW_TOOL_COUNTER_FILE.read_text(encoding="utf-8")).get("counter", 0))
        except Exception:
            pass
    return 0


def _save_new_tool_counter(value: int):
    NEW_TOOL_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    NEW_TOOL_COUNTER_FILE.write_text(json.dumps({"counter": value}, indent=2), encoding="utf-8")


@tool(category="misc")
def scaffold_new_tool(name_hint: str, category: str, summary: str, params: str = "data:str") -> str:
    """Scaffold a new tool module and auto-register it when existing tools are insufficient.
    :param params: params
    :param name_hint: name hint
    :param category: category
    :param summary: summary
    """
    import re as _re
    counter = _load_new_tool_counter() + 1
    safe_name = _re.sub(r"[^a-z0-9_]", "", name_hint.lower().strip().replace("-", "_").replace(" ", "_")) or f"agent_tool_{counter}"
    if safe_name[0].isdigit():
        safe_name = f"tool_{safe_name}"
    safe_name = safe_name[:40]
    unique_name = safe_name if counter == 1 else f"{safe_name}_{counter}"

    valid_cats = {"encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint", "misc"}
    if category not in valid_cats:
        category = "misc"

    MODULES = Path(__file__).resolve().parent
    init = MODULES / "__init__.py"
    file = MODULES / f"{unique_name}.py"

    if file.exists():
        return f"Tool already exists: {file}"

    sig_parts = []
    body_parts = []
    for spec in params.split(","):
        spec = spec.strip()
        if not spec:
            continue
        parts = spec.split(":")
        pname = parts[0].strip()
        ptype = parts[1].strip() if len(parts) > 1 else "str"
        if ptype == "int":
            sig_parts.append(f"{pname}: int = 0")
            body_parts.append(f"    {pname} = int({pname})")
        elif ptype == "bool":
            sig_parts.append(f"{pname}: bool = False")
        else:
            sig_parts.append(f"{pname}: str = ''")
            body_parts.append(f"    {pname} = str({pname})")

    src = f'''"""{summary}."""\n\nfrom ..registry import tool\n\n\n@tool(category={category!r})\ndef {unique_name}({", ".join(sig_parts)}) -> str:\n    """{summary}."""\n'''
    if body_parts:
        src += "\n".join(body_parts) + "\n"
    joined = ", ".join(sig_parts)
    src += f'    return "TODO: implement {unique_name} with params: {joined}."\n'

    file.write_text(src, encoding="utf-8")
    _save_new_tool_counter(counter)

    if init.exists():
        text = init.read_text(encoding="utf-8")
        if f"from . import {unique_name}" not in text:
            text = text.rstrip()
            if text.endswith("  # noqa: F401"):
                text = text[: text.rfind("  # noqa")] + f", {unique_name}  # noqa: F401\n"
            else:
                text = text + f"\nfrom . import {unique_name}  # noqa: F401\n"
            init.write_text(text, encoding="utf-8")

    import importlib
    import ctfkit.modules as mods
    importlib.reload(mods)

    from ..registry import TOOLS
    if unique_name in TOOLS:
        return f"Scaffolded and registered new tool: {unique_name} (category: {category})"
    return f"Scaffolded new tool: {unique_name} (registration may require restart)"


class AgentState:
    """Persistent state for the autonomous agent."""

    def __init__(self):
        self.state_path = AGENT_STATE_FILE
        self.state = self._load()

    def _load(self) -> dict:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "total_runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "tool_history": {},
            "failed_techniques": {},
            "successful_techniques": {},
            "learned_strategies": [],
            "challenge_experience": {},
        }

    def save(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(self.state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def record_tool_run(self, tool_name: str, success: bool, category: str, context: str = ""):
        key = tool_name
        if key not in self.state["tool_history"]:
            self.state["tool_history"][key] = {
                "total": 0,
                "success": 0,
                "failure": 0,
                "last_used": "",
                "contexts": [],
            }
        entry = self.state["tool_history"][key]
        entry["total"] += 1
        entry["last_used"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if context and len(entry["contexts"]) < 20:
            entry["contexts"].append(context[:200])

        if success:
            entry["success"] += 1
            self.state["successful_runs"] += 1
            if key not in self.state["successful_techniques"]:
                self.state["successful_techniques"][key] = []
            if context and context not in self.state["successful_techniques"][key]:
                self.state["successful_techniques"][key].append(context[:200])
        else:
            entry["failure"] += 1
            self.state["failed_runs"] += 1
            technique_key = f"{category}:{context[:100] if context else 'unknown'}"
            if technique_key not in self.state["failed_techniques"]:
                self.state["failed_techniques"][technique_key] = []
            if tool_name not in self.state["failed_techniques"][technique_key]:
                self.state["failed_techniques"][technique_key].append(tool_name)

    def is_technique_failed(self, category: str, context: str, tool_name: str) -> bool:
        technique_key = f"{category}:{context[:100] if context else 'unknown'}"
        failed_tools = self.state["failed_techniques"].get(technique_key, [])
        return tool_name in failed_tools

    def get_alternative_tools(self, category: str, context: str, exclude: list[str]) -> list[str]:
        """Suggest tools not yet tried for this context."""
        candidates = []
        context_key = context.lower()
        for name, meta in TOOLS.items():
            if exclude and name in exclude:
                continue
            if meta["category"] != category:
                continue
            hay = f"{name} {meta['summary']} {meta['doc'][:300]}".lower()
            if any(w in hay for w in context_key.split()[:5]):
                candidates.append(name)
        return candidates[:8]

    def update_challenge_experience(self, challenge_id: str, experience: dict):
        self.state["challenge_experience"][challenge_id] = experience
        self.save()

    def learn_new_strategy(self, strategy: str):
        if strategy not in self.state["learned_strategies"]:
            self.state["learned_strategies"].append(strategy)
            self.save()

    def increment_total_runs(self):
        self.state["total_runs"] += 1
        self.save()


def _extract_knowledge(query: str, limit: int = 3) -> str:
    """Retrieve relevant knowledge from memory and installed skills (context7-style)."""
    try:
        return recall_knowledge(query, limit=limit)
    except Exception as ex:
        log.warning("Knowledge retrieval failed: %s", ex)
        return f"Knowledge retrieval failed: {ex}"


# params (csv key data, PEM key material) can't be inferred from free text —
# queueing them would produce guaranteed-ERROR runs
_UNINFERABLE = {"rsa_hastad", "rsa_parse_key"}


def _infer_args(tool_name: str, context: str, problem_statement: str, knowledge: str) -> dict:
    """Infer tool arguments from context, problem statement, and recalled knowledge."""
    import re
    args = {}
    try:
        contract_text = optimize_parameters(tool_name)
    except Exception:
        return args

    param_names = []
    param_types: dict[str, str] = {}
    for line in contract_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("PARAMETER") or line_stripped.startswith("Summary"):
            continue
        if "(" in line_stripped and ")" in line_stripped:
            param_name = line_stripped.split("(")[0].strip().split()[0]
            param_names.append(param_name)
            _tm = re.search(r"\((\w+)\)", line_stripped)
            if _tm:
                param_types[param_name] = _tm.group(1)

    text = f"{problem_statement} {context} {knowledge}".lower()

    def _pick(pattern: str, *sources: str) -> list[str]:
        for src in sources:
            m = re.findall(pattern, src.lower())
            if m:
                return m
        return []

    hex_strings = _pick(r"[0-9a-f]{16,}", problem_statement, context, knowledge)
    numbers = _pick(r"\b\d{3,}\b", problem_statement, context, knowledge)
    labeled: dict[str, str] = {}
    for _lbl in ("n", "e", "c", "d", "p", "q", "e1", "e2", "c1", "c2", "key_length", "rails", "shift", "offset", "port", "m", "length", "hash"):
        for _src in (problem_statement, context, knowledge):
            _m2 = re.search(rf"\b{_lbl}\b\s*[=:]\s*(\d+)", _src.lower())
            if _m2:
                labeled[_lbl] = _m2.group(1)
                break
    # RSA parameters and other labeled values must not leak into generic params
    # (rails=1000036000099 would hang railfence); keep only leftover numbers
    numbers = [x for x in numbers if x not in labeled.values()]
    # hex/b64 candidates that are substrings of n/e/c (e.g. the first 16 digits
    # of a modulus) are garbage — drop anything contained in a labeled value
    short_hex = [h for h in _pick(r"[0-9a-f]{8,16}", problem_statement, context, knowledge)
                 if not any(h in v for v in labeled.values())]
    b64_blobs = [b for b in _pick(r"[A-Za-z0-9+/]{16,}={0,2}", problem_statement, context, knowledge)
                 if not any(b in v for v in labeled.values())]
    hex_strings = [h for h in _pick(r"[0-9a-f]{16,}", problem_statement, context, knowledge)
                   if not any(h in v for v in labeled.values())]
    path_hits = _pick(
        r"[\w./\\:\-]+\.(?:png|jpe?g|gif|bmp|webp|tif|ico|wav|mp3|flac|ogg|pcap|pcapng|zip|7z|rar|gz|pyc|elf|exe|dll|bin|pdf|txt|pem|key|sqlite|db|docx|xlsx|pptx|jar|apk|mp4)",
        problem_statement, context, knowledge,
    )
    urls = _pick(r"https?://[^\s\"'<>)\]]+", problem_statement, context, knowledge)

    for param in param_names:
        if param == "max_iter":  # control knob, not challenge data — keep tool default
            continue
        if param in ("url", "host", "domain", "remote_host", "port"):
            if param == "url":
                args[param] = urls[0] if urls else "http://example.com"
            else:
                _host = urls[0].split("://")[-1].split("/")[0].split(":")[0] if urls else ""
                _port = ""
                if urls:
                    try:
                        _port = str(int(urls[0].split("://")[-1].split("/")[0].split(":")[1]))
                    except Exception:
                        _port = ""
                if param == "port":
                    args[param] = labeled.get("port") or _port or "4444"
                elif param in ("host", "domain", "remote_host"):
                    args[param] = _host or {"host": "example.com", "domain": "example.com", "remote_host": "chall.ctf.org"}[param]
            continue
        if param in ("path_a", "path_b"):
            _idx = 0 if param == "path_a" else 1
            if len(path_hits) > _idx:
                args[param] = path_hits[_idx]
            continue
        if param == "code":
            args[param] = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++"
            continue
        if param == "encoded":
            args[param] = (b64_blobs[0] if b64_blobs else
                           (hex_strings[0] if hex_strings else
                            (short_hex[0] if short_hex else "aGVsbG8gY3RmIQ==")))
            continue
        if param == "hash_str":
            args[param] = labeled.get("hash") or (hex_strings[0] if hex_strings else
                                                  (short_hex[0] if short_hex else "e99a18c428cb38d5f260853678922e03"))
            continue
        if param in ("original_data", "append_data"):
            args[param] = (hex_strings[0] if hex_strings else
                           (short_hex[0] if short_hex else "61646d696e3d66616c7365")) if param == "original_data" else "admin=true"
            continue
        if param.endswith("_csv") and numbers:
            args[param] = ", ".join(numbers[:3])
            continue
        if param in ("path", "file_path", "image_path", "gif_path", "pcap_path", "zip_path", "wav_path", "binary_path", "pyc_path_or_hex"):
            if path_hits:
                args[param] = path_hits[0]
                continue
        if "b64" in param:
            args[param] = b64_blobs[0] if b64_blobs else "aGVsbG8gY3RmIQ=="
        elif "hex" in param or param in ("ciphertext", "data_hex", "block_hex", "original_hash", "key_hex"):
            if param == "ciphertext" and labeled.get("c"):
                args[param] = labeled["c"]
            elif param_types.get(param, "") == "int" and numbers:
                idx = {"ciphertext": 2, "block_index": 1}.get(param, 0)
                args[param] = numbers[idx] if len(numbers) > idx else numbers[-1]
            elif short_hex:
                args[param] = short_hex[0]
            elif hex_strings:
                args[param] = hex_strings[0]
            else:
                args[param] = "1b1e15101b1e1510" if param != "original_hash" else "e99a18c428cb38d5f260853678922e03"
        elif param in ("n", "modulus", "moduli"):
            args[param] = labeled.get("n") or (numbers[0] if numbers else "3233")
        elif param in ("e",):
            args[param] = labeled.get("e") or (numbers[1] if len(numbers) > 1 else (numbers[0] if numbers else "17"))
        elif param in ("key_length", "rails", "offset", "length", "max_bytes", "block_size", "timeout", "max_body", "min_len", "max_flows"):
            if labeled.get(param):
                args[param] = labeled[param]
            elif numbers:
                args[param] = numbers[0]
            elif param == "key_length":
                args[param] = "1"
            elif param == "rails":
                args[param] = "3"
            elif param == "timeout":
                args[param] = "10"
            else:
                args[param] = "64"
        elif param in ("shift", "a", "b", "d", "e1", "e2", "c1", "c2", "target_addr", "write_val", "arch"):
            if labeled.get(param):
                args[param] = labeled[param]
            elif numbers:
                args[param] = numbers[0]
            elif param == "shift":
                args[param] = "3"
            elif param == "arch":
                args[param] = "64"
            else:
                args[param] = "1"
        elif param in ("key", "key_hex", "header_json", "payload_json", "secret", "token", "rsa_public_key_pem"):
            if param == "secret" and "none" in text:
                args[param] = ""
            elif param == "token":
                args[param] = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmbGFnIjoiZmxhZ3tqd3R9"
            elif param == "rsa_public_key_pem":
                args[param] = "test_public_key_bytes"
            elif param in ("header_json", "payload_json"):
                args[param] = '{"alg":"none","typ":"JWT"}' if param == "header_json" else '{"user":"admin"}'
            else:
                args[param] = "LEMON"
        elif param in ("text", "data", "input", "payload"):
            if "base64" in text:
                args[param] = b64_blobs[0] if b64_blobs else "aGVsbG8gY3RmIQ=="
            elif "morse" in text or "..." in text:
                args[param] = ".... . .-.. .-.. ---"
            elif "brainfuck" in text or "+" in text:
                args[param] = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++"
            else:
                args[param] = "hello ctf!"
        elif param in ("variant", "engine", "kind", "shell_type", "encoding", "action", "method"):
            if param == "variant" and "bacon" in tool_name:
                args[param] = "24"
            elif param == "engine":
                args[param] = "jinja2"
            elif param == "kind":
                if "shellcode" in tool_name:
                    args[param] = "execve_sh"
                elif "sql" in text or "auth" in text:
                    args[param] = "auth_bypass"
                else:
                    args[param] = "xor"
            elif param == "shell_type":
                args[param] = "bash"
            elif param == "encoding":
                args[param] = "raw"
            elif param == "action":
                args[param] = "content"
            elif param == "method":
                args[param] = "GET"
        elif param in ("plane", "channel", "bit_order"):
            args[param] = "lsb" if param == "plane" else "rgb" if param == "channel" else "lsb-first"
        elif param == "states_csv":
            args[param] = "25, 40, 55, 70, 85, 100"
        elif param == "m":
            args[param] = labeled.get("m") or "101"
        elif param == "algorithm":
            args[param] = "md5" if ("md5" in text or "hash" in text) else "sha256"
        elif param == "format":
            args[param] = "PNG"
        elif param == "mode":
            args[param] = "ECB"
        elif param == "record":
            args[param] = "A"
        elif param == "target":
            args[param] = "admin=true;role=1x"
        elif param == "original":
            args[param] = "AAAAAAAAAAAAAAAA"
        elif param == "crib":
            args[param] = "flag{"
        elif param == "states":
            args[param] = "25, 40, 55"
        elif param == "wordlist":
            args[param] = "testdata/wordlist.txt"
        elif param == "out_dir":
            args[param] = "testdata/carved"
        elif param == "max_depth":
            args[param] = "5"
        elif param == "pattern":
            args[param] = ""
        elif param == "substring":
            args[param] = "abba"
        elif param == "ip":
            args[param] = "8.8.8.8"
        elif param == "domain":
            args[param] = "example.com"
        elif param == "remote_host":
            args[param] = "chall.ctf.org"
        elif param == "remote_port":
            args[param] = "1337"
        elif param == "tool_name":
            args[param] = "caesar"
        elif param == "args_json":
            args[param] = "{}"
        elif param == "query":
            args[param] = problem_statement[:60]
        elif param == "limit":
            args[param] = "5"
        elif param == "top":
            args[param] = "8"
        elif param == "category":
            args[param] = ""
        elif param == "status":
            args[param] = "solved"
        elif param == "title":
            args[param] = f"Agent: {problem_statement[:40]}"
        elif param == "note":
            args[param] = "Auto-generated by autonomous agent"
        elif param == "flag":
            args[param] = ""
        elif param == "tool":
            args[param] = tool_name
        elif param == "platform":
            args[param] = "unknown"
        elif param == "problem":
            args[param] = problem_statement[:120]
        elif param == "max_iterations":
            args[param] = "8"

    return args


_EXTERNAL_WRAPPERS = (
    "external_recon", "external_web", "external_forensics",
    "external_stego", "external_crypto", "external_rev",
)

_HINT_KEYWORDS = {
    "sql": (["sql", "injection", "sqli", "login bypass", "union"], "sqli"),
    "xss": (["xss", "cross-site", "reflected"], "xss"),
    "ssti": (["ssti", "template injection", "jinja", "twig", "smarty"], "ssti"),
    "lfi": (["lfi", "rfi", "path traversal", "local file", "remote file", "include"], "lfi"),
    "upload": (["upload", "webshell"], "upload"),
    "jwt": (["jwt", "json web token"], "jwt"),
    "deser": (["deserialization", "serialize", "unserialize", "pickle"], "deser"),
    "ssrf": (["ssrf", "server-side request"], "ssrf"),
    "xxe": (["xxe", "external entity", "xml entity"], "xxe"),
    "rce": (["command injection", "rce", "remote code", "code execution", "shell"], "rce"),
    "rsa": (["rsa", "fermat", "wiener", "private key", "public key", "close prime",
             "common modulus", "hastad", "small e", "cryptosystem"], "rsa"),
    "xor": (["xor", "vigenere", "single-byte", "repeating key"], "xor"),
    "caesar": (["caesar", "shift", "rot"], "caesar"),
    "hash": (["hash", "md5", "sha1", "sha256", "ntlm", "bcrypt", "crack the"], "hash"),
    "aes": (["aes", "ecb", "cbc", "gcm", "cipher", "encryption", "decrypt the"], "aes"),
    "lsb": (["lsb", "stegano", "hidden in the image", "hidden in image", "pixel"], "lsb"),
    "metadata": (["metadata", "exif", "comment", "chunk", "png"], "metadata"),
    "zip": (["zip", "archive", "compressed", "password protected", "pseudo-encrypt"], "zip"),
    "pcap": (["pcap", "capture", "packet", "network traffic", "wireshark", "usb"], "pcap"),
    "mem": (["memory", "volatility", "memory dump"], "mem"),
    "bo": (["buffer overflow", "stack", "ret2win", "overflow"], "bo"),
    "fmt": (["format string"], "fmt"),
    "rop": (["rop", "ret2libc", "gadget"], "rop"),
    "shellcode": (["shellcode", "spawn a shell", "execve"], "shellcode"),
    "rev": (["reverse", "decompile", "disassemble", "flag checker", "crackme", "keygen"], "rev"),
    "dns": (["dns", "subdomain", "recon", "certificate", "ct log"], "dns"),
    "whois": (["whois", "registrant", "owner of"], "whois"),
    "gps": (["gps", "coordinates", "latitude", "location of"], "gps"),
    "b64": (["base64", "encoded"], "b64"),
}

# hint family -> external tool names that should run first
_HINT_EXTERNAL = {
    "sql": {"sqlmap"}, "rsa": {"RsaCtfTool"}, "hash": {"hashcat", "john", "hashid", "findmyhash"},
    "rev": {"readelf", "objdump", "nm", "r2", "gdb", "angr"},
    "zip": {"7z", "unzip", "zipinfo", "fcrackzip", "zip2john", "rar2john"},
    "pcap": {"tshark", "capinfos"}, "mem": {"volatility3"},
    "b64": {"base64", "xxd"}, "dns": {"dnsrecon", "dnsenum", "dnsx", "subfinder", "amass"},
    "whois": {"whois"}, "metadata": {"exiftool"}, "lsb": {"zsteg"},
    "xor": {"xortool"}, "rce": {"commix", "hydra"},
    "bo": {"gdb", "pwntools", "checksec"}, "fmt": {"gdb", "pwntools"},
    "rop": {"ROPgadget", "ropper", "rp++", "one_gadget"},
    "shellcode": {"msfvenom", "pwntools", "gdb"},
    "upload": {"curl", "ffuf"}, "xss": {"xsstrike", "dalfox"},
    "gps": {"exiftool", "identify"}, "lfi": {"ffuf", "gobuster", "dirsearch"},
}


def _understand_problem(problem_statement: str, knowledge: str = "") -> dict:
    """Parse the problem into structured understanding (targets + technique hints).

    The agent reads the problem like an analyst: what is being attacked, with
    which technique family, and what the expected flag format is — so the tool
    queue is prioritized by relevance instead of brute force. Only the problem
    statement itself drives comprehension; recalled knowledge never overrides it.
    """
    text = problem_statement.lower()

    def _pick(pattern: str) -> list[str]:
        return re.findall(pattern, text)

    urls = _pick(r"https?://[^\s\"'<>]+")
    ips = _pick(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    domains = _pick(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ctf|local|htb|xyz|me|club|top|site|edu|gov)\b")
    files = _pick(
        r"[\w./\\:\-]+\.(?:png|jpe?g|gif|bmp|webp|wav|mp3|flac|pcap|pcapng|zip|7z|rar|pyc|elf|exe|dll|bin|pdf|pem|key|sqlite|db|raw|mem|img|jpg|txt|jar|apk|py|js|json|csv)")
    hashes = [h for h in _pick(r"\b[0-9a-f]{16,128}\b")
              if not (len(h) >= 30 and set(h) <= set("0123456789"))]
    b64 = [b for b in _pick(r"[A-Za-z0-9+/]{20,}={0,2}")
           if not (len(b) >= 30 and set(b) <= set("0123456789"))]
    big_ints = _pick(r"\b\d{30,}\b")

    fam_score: dict[str, int] = {}
    for fam, (keywords, _label) in _HINT_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text)
        if hits:
            fam_score[fam] = fam_score.get(fam, 0) + hits
    hints = sorted(fam_score.items(), key=lambda x: -x[1])

    flag_prefix = ""
    m = re.search(r"(picoctf|htb|flag|compfest|ctf)\{", text)
    if m:
        flag_prefix = m.group(1)

    target = files[0] if files else (urls[0] if urls else (ips or domains or [""])[0])
    if not target:
        target = hashes[0] if hashes else (b64[0] if b64 else "the challenge data")
    top = hints[0][0] if hints else "generic"
    focus_label = dict(_HINT_KEYWORDS)[top][1] if top in _HINT_KEYWORDS else top
    summary = (f"Target: {target} | Fokus: {focus_label}"
               f"{' | Format flag: ' + flag_prefix + '{...}' if flag_prefix else ''}")

    return {
        "summary": summary,
        "targets": {"url": urls[0] if urls else "", "host": (ips or domains or [""])[0],
                    "file": files[0] if files else "", "hash": hashes[0] if hashes else "",
                    "big_int": big_ints[0] if big_ints else "", "b64": b64[0] if b64 else ""},
        "hints": hints,
        "flag_prefix": flag_prefix,
    }

_EXTERNAL_FAIL_MARKERS = (
    "NOT INSTALLED", "INSTALL FAILED", "INSTALL TIMEOUT", "INSTALL ERROR",
    "TIMEOUT after", "Unsupported tool", "FAILED TO RUN", "requires testing",
)


def _write_hash_file(hash_str: str) -> str:
    """Write a hash to a temp file (john needs a file, not an inline hash)."""
    import base64
    import tempfile
    if not re.fullmatch(r"[0-9a-fA-F]+", hash_str) and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", hash_str):
        try:
            hash_str = base64.b64decode(hash_str).hex()
        except Exception:
            pass
    p = Path(tempfile.gettempdir()) / "ctfkit_john_hash.txt"
    p.write_text(hash_str.strip(), encoding="utf-8")
    return str(p)


def _external_steps(
    category: str,
    problem_statement: str,
    knowledge: str,
    excluded: list[str],
    extra_context: str = "",
    hints: list[tuple[str, int]] | None = None,
) -> list[dict]:
    """Queue the category's external CLI tools (nmap, gobuster, binwalk, ...) before custom tools.

    Data-driven: every tool in EXTERNAL_TOOLS[category] that has a DEFAULT_ARGS
    template gets queued, guarded by the targets it needs (URL/host/file/hash).
    Tools matching the problem's technique hints (sqlmap for SQLi, hashcat for
    hashes, zsteg for LSB, ...) run FIRST; the rest follow in ALLOWED order.
    Each external tool gets its own step key so a failed ffuf run still lets
    gobuster/sqlmap of the same wrapper be tried later.
    """
    import tempfile
    import urllib.parse
    # targets come from the PROBLEM (+ latest tool output), never from recalled
    # knowledge — memory files would hijack the queue (meta2.png in crypto etc.)

    def _pick(pattern: str, *sources: str) -> list[str]:
        for src in sources:
            m = re.findall(pattern, src.lower())
            if m:
                return m
        return []

    urls = _pick(r"https?://[^\s\"'<>]+", problem_statement, extra_context)
    ips = _pick(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", problem_statement, extra_context)
    domains = _pick(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ctf|local|htb|xyz|me|club|top|site)\b",
                    problem_statement, extra_context)
    files = _pick(
        r"[\w./\\:\-]+\.(?:png|jpe?g|gif|bmp|webp|wav|mp3|flac|pcap|pcapng|zip|7z|rar|pyc|elf|exe|dll|bin|pdf|pem|key|sqlite|db|raw|mem|img|jpg|txt)",
        problem_statement, extra_context,
    )
    hexes = [h for h in _pick(r"[0-9a-f]{16,}", problem_statement, extra_context)
             if not (len(h) >= 30 and set(h) <= set("0123456789"))]
    b64s = [b for b in _pick(r"[A-Za-z0-9+/]{16,}={0,2}", problem_statement, extra_context)
            if not (len(b) >= 30 and set(b) <= set("0123456789"))]
    hash_str = (hexes or b64s or [""])[0]

    url = urls[0] if urls else ""
    host = (ips or domains or [""])[0]
    if not host and url:
        host = urllib.parse.urlsplit(url).hostname or ""
    port = str(urllib.parse.urlsplit(url).port) if url and urllib.parse.urlsplit(url).port else "80"
    f = files[0] if files else ""
    wl = "/usr/share/wordlists/rockyou.txt"
    out = tempfile.gettempdir()

    wrappers = {
        "osint": "external_recon",
        "web": "external_web",
        "forensics": "external_forensics",
        "stego": "external_stego",
        "crypto": "external_crypto",
        "rev": "external_rev",
        "pwn": "external_rev",
    }
    wrapper = wrappers.get(category)
    if not wrapper:
        return []

    values = {"host": host, "url": url, "file": f, "hash": hash_str,
              "hashfile": _write_hash_file(hash_str), "wordlist": wl, "outdir": out, "port": port}

    priority: set[str] = set()
    for fam, _hits in (hints or []):
        priority |= _HINT_EXTERNAL.get(fam, set())

    steps = []
    ordered = [t for t in EXTERNAL_TOOLS.get(category, []) if t in priority] + \
              [t for t in EXTERNAL_TOOLS.get(category, []) if t not in priority]
    for tool_name in ordered:
        key = f"{wrapper}:{tool_name}"
        if key in excluded:
            continue
        tpl = EXTERNAL_ARGS.get(tool_name)
        if not tpl or tool_name in _NO_TEMPLATE:
            continue
        placeholders = set(re.findall(r"\{(\w+)\}", tpl))
        if not hash_str and placeholders & {"hash", "hashfile"}:
            continue
        if any(not values[p] for p in placeholders):
            continue
        args = tpl.format(**values)
        steps.append({
            "tool": wrapper,
            "key": key,
            "args": {"tool": tool_name, "args": args, "timeout": "60", "auto": True},
            "reason": f"external: {tool_name} {args}",
            "source": "external",
        })
    return steps


def _build_strategy(
    plan: str,
    knowledge: str,
    state: AgentState,
    category: str,
    problem_statement: str = "",
    exclude: list[str] | None = None,
    extra_context: str = "",
    hints: list[tuple[str, int]] | None = None,
) -> list[dict]:
    """Build a step-by-step strategy based on plan, knowledge, and learned experience.

    exclude: tools already tried in this run — never repeat a failed technique.
    extra_context: latest tool output; steers the next picks toward what the data looks like.
    hints: (technique family, hit count) from problem comprehension; external tools
    matching the hints run first, and custom tools are reordered by relevance.
    """
    steps: list[dict] = []
    excluded: list[str] = list(exclude or [])
    hint = f" {extra_context[:400]}" if extra_context else ""

    for step in _external_steps(category, problem_statement, knowledge, excluded, extra_context, hints):
        steps.append(step)
        excluded.append(step["key"])

    knowledge_lower = knowledge.lower()
    for line in plan.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("==") or line_stripped.startswith("-"):
            continue
        if line_stripped.startswith("SUGGESTED TOOLS:"):
            for name in line_stripped.split(":", 1)[1].replace(",", " ").split():
                if name in TOOLS and name not in excluded and not name.startswith("external_") and name not in _UNINFERABLE:
                    steps.append({
                        "tool": name,
                        "key": name,
                        "args": _infer_args(name, line_stripped, problem_statement, knowledge),
                        "reason": "suggested for this category",
                        "source": "suggested",
                    })
                    excluded.append(name)
            continue
        if re.match(r"^(\d+\.|CATEGORY:|PLATFORM:|PLAN:|MEMORY|RECALL|STEP)", line_stripped, re.I):
            continue

        recommended = select_tools(f"{line_stripped}{hint}", category=category, top=8)
        for tool_line in recommended.splitlines()[1:]:
            if "[" in tool_line and "]" in tool_line:
                tool_name = tool_line.split("]")[1].split("(")[0].strip()
                if tool_name in TOOLS and tool_name not in excluded and not tool_name.startswith("external_") and tool_name not in _UNINFERABLE:
                    if not state.is_technique_failed(category, line_stripped, tool_name):
                        inferred_args = _infer_args(tool_name, line_stripped, problem_statement, knowledge)
                        steps.append({
                            "tool": tool_name,
                            "key": tool_name,
                            "args": inferred_args,
                            "reason": line_stripped,
                            "source": "plan",
                        })
                        excluded.append(tool_name)
                        break

    if not steps:
        for name, meta in TOOLS.items():
            if category and meta["category"] != category:
                continue
            if name in excluded or name.startswith("external_") or name in _UNINFERABLE:
                continue
            if not state.is_technique_failed(category, category, name):
                inferred_args = _infer_args(name, category, problem_statement, knowledge)
                steps.append({
                    "tool": name,
                    "key": name,
                    "args": inferred_args,
                    "reason": f"fallback {category} tool",
                    "source": "fallback",
                })
                excluded.append(name)
            if len(steps) >= 5:
                break

    if hints:
        ext_count = sum(1 for s in steps if s["source"] == "external")

        def _score(step: dict) -> int:
            name = step["tool"]
            summary = TOOLS.get(name, {}).get("summary", "").lower()
            return sum(hits for fam, hits in hints
                       if fam in name.lower() or fam in summary[:200])

        steps = steps[:ext_count] + sorted(steps[ext_count:], key=_score, reverse=True)

    return steps[:10]


def discover_techniques(problem_statement: str, category: str = "") -> str:
    """Discover solving techniques from problem analysis, CVE patterns, and prior knowledge."""
    text = problem_statement.lower()
    keywords = [w for w in re.findall(r"[a-z0-9_]{3,}", text) if len(w) > 2]
    cves = sorted(set(re.findall(r"cve-\d{4}-\d{4,7}", text)))
    versions = sorted(set(re.findall(r"\b\d+\.\d+(?:\.\d+)?\b", text)))
    software = []
    for kw in keywords:
        if kw in ("apache", "nginx", "linux", "windows", "php", "python", "node", "java", "openssl", "ssh", "ftp", "smtp", "mysql", "postgresql", "mongodb", "redis", "jenkins", "git", "docker", "kubernetes", "aws", "azure", "gcp"):
            software.append(kw)

    lines = [
        "🔍 TECHNIQUE DISCOVERY",
        f"Problem: {problem_statement[:120]}",
        f"Category: {category or 'unknown'}",
        f"CVEs detected: {', '.join(cves) if cves else 'none'}",
        f"Versions detected: {', '.join(versions) if versions else 'none'}",
        f"Software detected: {', '.join(software) if software else 'none'}",
        "",
    ]

    if cves or software:
        lines.append("📋 CVE-BASED RESEARCH:")
        try:
            from .cve import cve_lookup, cve_search
            for cve in cves[:5]:
                lines.append(cve_lookup(cve)[:500])
            for sw in software[:3]:
                res = cve_search(sw, "")
                lines.append(res[:500])
        except Exception:
            for cve in cves[:5]:
                lines.append(f"  - Search exploit-db/GitHub/NVD for {cve.upper()} (NVD unreachable)")
        lines.append("")

    lines.append("🧩 TECHNIQUE RECOMMENDATIONS:")
    from .external import ALLOWED as _ext_allowed
    ext_tools = ", ".join(sorted(_ext_allowed.get(category, [])))
    lines.append(f"🔌 EXTERNAL CLIs for {category}: {ext_tools or '(none wrapped)'}")
    recs = []
    for line in problem_statement.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        rec = select_tools(line_stripped, category=category, top=5)
        if rec and "No tools matched" not in rec:
            recs.append(rec)
        if len(recs) >= 3:
            break

    if recs:
        for rec in recs:
            lines.append(rec)
    else:
        lines.append("  - Inspect input files: file_type, strings_extract, hexdump")
        lines.append("  - Try encoding/decoding chains: decode_all, decode_chain")
        lines.append("  - Check for steganography: stego_metadata, stego_png_chunks")
        lines.append("  - Check for crypto: caesar, xor_brute, rsa_fermat")
        lines.append("  - Check for web: jwt_decode, sqli_payloads, ssti_payloads")

    lines.append("")
    lines.append("📚 KNOWLEDGE BASE:")
    knowledge = recall_knowledge(problem_statement, limit=3)
    lines.append(knowledge[:600])

    return "\n".join(lines)


def _llm_pick(problem_statement: str, category: str, tried: list[str], last_output: str) -> str | None:
    """Optional LLM steering: ask an OpenAI-compatible endpoint (env CTFKIT_LLM_ENDPOINT)
    which tool to try next. Any failure returns None and the heuristic continues."""
    import os as _os
    import urllib.request as _ur
    import json as _json
    endpoint = _os.environ.get("CTFKIT_LLM_ENDPOINT", "")
    if not endpoint:
        return None
    avail = sorted(
        n for n, m in TOOLS.items()
        if m["category"] == category and n not in tried and not n.startswith("external_") and n not in _UNINFERABLE)
    if not avail:
        return None
    prompt = (f"CTF challenge: {problem_statement[:500]}\n"
              f"Category: {category}. Tools already tried: {', '.join(sorted(tried)[-15:])}\n"
              f"Last tool outputs: {last_output[:600]}\n"
              f"Choose exactly one tool name from: {', '.join(avail)}. Reply with the name only.")
    body = _json.dumps({
        "model": _os.environ.get("CTFKIT_LLM_MODEL", "default"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode()
    headers = {"Content-Type": "application/json"}
    if _os.environ.get("CTFKIT_LLM_KEY"):
        headers["Authorization"] = f"Bearer {_os.environ['CTFKIT_LLM_KEY']}"
    req = _ur.Request(endpoint, data=body, headers=headers)
    try:
        with _ur.urlopen(req, timeout=20) as resp:
            data = _json.loads(resp.read().decode())
        text = ((data.get("choices") or [{}])[0].get("message", {}) or {}).get("content", "") or data.get("content", "")
        for cand in re.split(r"[,\s]+", text):
            cand = cand.strip("`'\"();[]{}")
            if cand in avail:
                return cand
    except Exception:
        return None
    return None


@tool(category="misc")
def autonomous_solve(problem_statement: str, max_iterations: int = 8) -> str:
    """Autonomous agent: plan -> recall -> iterative solve -> extract flag -> learn.
    :param problem_statement: problem statement
    :param max_iterations: max iterations
    """

    state = AgentState()
    state.increment_total_runs()
    start_time = time.time()

    challenge_id = f"{problem_statement[:60].lower().replace(' ', '-')}"
    excluded_tools: list[str] = []
    if challenge_id in state.state["challenge_experience"]:
        exp = state.state["challenge_experience"][challenge_id]
        excluded_tools = exp.get("excluded_tools", [])
        if exp.get("flag_found") and exp.get("flag"):
            report = [
                "==================================================",
                "🤖 AUTONOMOUS AGENT — SELF-IMPROVING SOLVER",
                "==================================================",
                f"Problem: {problem_statement[:120]}",
                f"Already solved in a previous run: {exp['flag']}",
                "==================================================",
                "🏁 AGENT RUN COMPLETE: SOLVED (from experience)",
                "==================================================",
            ]
            return "\n".join(report)

    current_iteration = 0

    report = [
        "==================================================",
        "🤖 AUTONOMOUS AGENT — SELF-IMPROVING SOLVER",
        "==================================================",
        f"Problem: {problem_statement[:120]}",
        f"Max iterations: {max_iterations} | Known-failed tools excluded: {len(excluded_tools)}",
        "",
    ]

    plan_output = detect_challenge(problem_statement)
    report.append("📋 PLAN:")
    report.append(plan_output)
    report.append("")

    category = "misc"
    platform = "unknown"
    for line in plan_output.splitlines():
        if line.startswith("CATEGORY:"):
            category = line.split(":", 1)[1].strip()
        elif line.startswith("PLATFORM:"):
            platform = line.split(":", 1)[1].strip()

    knowledge = _extract_knowledge(problem_statement, limit=3)
    report.append("🧠 RECALLED KNOWLEDGE:")
    report.append(knowledge[:800])
    report.append("")

    understanding = _understand_problem(problem_statement, knowledge)
    report.append("🧠 PEMAHAMAN SOAL:")
    report.append(f"  {understanding['summary']}")
    if understanding["hints"]:
        report.append("  Teknik terdeteksi: " + ", ".join(
            f"{fam} (x{hits})" for fam, hits in understanding["hints"][:5]))
    report.append("")

    # CVE research: understand the problem -> find the CVE -> get an exploit plan
    cve_report = ""
    try:
        from .cve import cve_research, detect_cves_in_problem, detect_software_in_problem
        if detect_cves_in_problem(problem_statement) or detect_software_in_problem(problem_statement):
            cve_report = cve_research(problem_statement)
            report.append("🔎 CVE RESEARCH:")
            report.append(cve_report[:1800])
            report.append("")
    except Exception as ex:
        cve_report = ""
        report.append(f"(cve_research skipped: {ex})")
        report.append("")

    tried_tools: set[str] = set(excluded_tools)
    failed_keys: set[str] = set(excluded_tools)
    last_output = ""
    success_tool = ""

    strategy = _build_strategy(
        plan_output, knowledge, state, category, problem_statement,
        exclude=sorted(tried_tools), extra_context=last_output,
        hints=understanding["hints"],
    )
    if not strategy:
        report.append("❌ No viable strategy found. Try a different challenge description.")
        return "\n".join(report)

    report.append(f"⚡ ADAPTIVE STRATEGY ({len(strategy)} steps):")
    for i, step in enumerate(strategy, 1):
        report.append(f"  {i}. [{step['tool']}] {step['reason']} (source: {step['source']})")
    report.append("")

    # Prefer the CVE-mapped exploit tool first when research found one
    if cve_report:
        mapped = re.findall(r"Next: ctf-tools ([\w]+)", cve_report)
        for tool_name in dict.fromkeys(mapped):
            if tool_name not in {s.get("key") for s in strategy}:
                strategy.insert(0, {
                    "tool": tool_name,
                    "key": tool_name,
                    "args": _infer_args(tool_name, plan_output, problem_statement, knowledge),
                    "reason": f"CVE research maps to {tool_name}",
                    "source": "cve",
                })
        if mapped:
            report.append(f"🎯 CVE RESEARCH: prioritizing {', '.join(dict.fromkeys(mapped))} first")
            report.append("")

    flag_found = False
    flag_text = ""
    iterations_used = 0
    final_note = ""

    for iteration in range(current_iteration, max_iterations):
        iterations_used = iteration + 1
        report.append(f"--- Iteration {iteration + 1}/{max_iterations} ---")

        llm_pick = _llm_pick(problem_statement, category, sorted(tried_tools), last_output)
        if llm_pick:
            strategy = [{
                "tool": llm_pick, "key": llm_pick,
                "args": _infer_args(llm_pick, plan_output, problem_statement, knowledge),
                "reason": "LLM steering pick", "source": "llm",
            }] + [s for s in strategy if s.get("key") != llm_pick]
            report.append(f"🎯 LLM STEERING: trying {llm_pick} first")

        if not strategy:
            report.append("🧠 Known techniques exhausted. Running technique discovery for a breakthrough...")
            report.append("")
            discovery = discover_techniques(problem_statement, category)
            report.append(discovery[:1500])
            report.append("")
            if iteration + 1 < max_iterations:
                try:
                    hint = f"agent_{category}_variant_{iteration + 1}"
                    scaffold_result = scaffold_new_tool(
                        name_hint=hint,
                        category=category,
                        summary=f"Auto-scaffolded tool for {category} challenge variant discovered by agent",
                        params="data:str",
                    )
                    report.append(f"🛠️ BREAKTHROUGH: {scaffold_result}")
                    state.learn_new_strategy(f"{category}:scaffolded_new_tool_{hint}")
                except Exception as ex:
                    report.append(f"   Discovery/breakthrough failed: {ex}")
            strategy = _build_strategy(
                plan_output, knowledge, state, category, problem_statement,
                exclude=sorted(tried_tools), extra_context=last_output,
                hints=understanding["hints"],
            )
            report.append(f"⚡ POST-DISCOVERY STRATEGY ({len(strategy)} steps):")
            for i, step in enumerate(strategy, 1):
                report.append(f"  {i}. [{step['tool']}] {step['reason']} (source: {step['source']})")
            report.append("")
            if not strategy:
                report.append("   Still no viable strategy after discovery. Ending early.")
                break

        ran_any = False
        for step in strategy:
            tool_name = step["tool"]
            step_key = step.get("key", tool_name)
            if step_key in tried_tools:
                continue
            tried_tools.add(step_key)
            ran_any = True

            report.append(f"🔧 Trying: {tool_name} (reason: {step['reason']})")
            try:
                result = run_tool(tool_name, step["args"])
                success = not result.startswith("ERROR")
                if tool_name in _EXTERNAL_WRAPPERS:
                    success = success and not any(m in result for m in _EXTERNAL_FAIL_MARKERS)
                state.record_tool_run(
                    tool_name,
                    success=success,
                    category=category,
                    context=step["reason"],
                )

                if success:
                    report.append(f"✅ {tool_name} succeeded ({len(result)} chars)")
                    flags = extract_flags(result)
                    if flags:
                        flag_found = True
                        flag_text = flags[0]
                        success_tool = tool_name
                        report.append(f"🏆 FLAG FOUND: {flag_text}")
                        final_note = f"Found flag using {tool_name} on iteration {iteration + 1}"
                        state.learn_new_strategy(
                            f"{category}:use_{tool_name}_for_similar_challenges"
                        )
                        break
                    last_output = result
                    report.append(f"   Output preview: {result[:200]}")
                else:
                    report.append(f"❌ {tool_name} failed: {result[:200]}")
                    failed_keys.add(step_key)
                    state.learn_new_strategy(
                        f"{category}:avoid_{tool_name}_for_{step['reason'][:50]}"
                    )
                    last_output = f"{last_output}\n{result[:200]}"

            except Exception as ex:
                report.append(f"❌ {tool_name} exception: {ex}")
                failed_keys.add(step_key)
                state.record_tool_run(
                    tool_name,
                    success=False,
                    category=category,
                    context=step["reason"],
                )
                last_output = f"{last_output}\n{ex}"

            if flag_found:
                break

        if flag_found:
            break

        if not ran_any:
            strategy = []
            continue

        if iteration + 1 < max_iterations:
            report.append("🔄 No flag yet — rebuilding strategy: excluding failed techniques, steering with latest output...")
            report.append("")
            strategy = _build_strategy(
                plan_output, knowledge, state, category, problem_statement,
                exclude=sorted(tried_tools), extra_context=last_output,
            )
            report.append(f"⚡ NEW STRATEGY ({len(strategy)} steps):")
            for i, step in enumerate(strategy, 1):
                report.append(f"  {i}. [{step['tool']}] {step['reason']} (source: {step['source']})")
            report.append("")

    elapsed = time.time() - start_time
    state.update_challenge_experience(challenge_id, {
        "iteration": iterations_used,
        "excluded_tools": sorted(failed_keys),
        "flag_found": flag_found,
        "flag": flag_text,
        "elapsed": elapsed,
    })
    state.save()

    status = "SOLVED" if flag_found else "FAILED"
    report.append("")
    report.append("==================================================")
    report.append(f"🏁 AGENT RUN COMPLETE: {status}")
    report.append("==================================================")
    report.append(f"Iterations used: {iterations_used}")
    report.append(f"Tools tried (never repeated): {len(tried_tools)}")
    report.append(f"Time elapsed: {elapsed:.2f}s")
    report.append(f"Total agent runs (session): {state.state['total_runs']}")
    report.append(f"Tool runs successful: {state.state['successful_runs']}/{state.state['successful_runs'] + state.state['failed_runs']}")
    if flag_text:
        report.append(f"Flag: {flag_text}")

    if flag_found and final_note:
        try:
            from .analyze import remember_challenge
            remember_challenge(
                title=f"Agent: {problem_statement[:50]}",
                category=category,
                tool=success_tool or "autonomous_agent",
                flag=flag_text,
                note=final_note,
                platform=platform,
                status="solved",
            )
        except Exception as ex:
            log.warning("Memory save failed: %s", ex)

    return "\n".join(report)


@tool(category="misc")
def get_agent_status() -> str:
    """Return current agent learning status and statistics including tool success/failure rates."""
    state = AgentState()
    s = state.state
    lines = [
        "==================================================",
        "📊 AUTONOMOUS AGENT STATUS",
        "==================================================",
        f"Total runs      : {s['total_runs']}",
        f"Successful      : {s['successful_runs']}",
        f"Failed          : {s['failed_runs']}",
        f"Success rate    : {(s['successful_runs']/max(1,s['total_runs'])*100):.1f}%",
        f"Learned strategies: {len(s['learned_strategies'])}",
        f"Failed techniques : {len(s['failed_techniques'])}",
        f"Successful techniques: {len(s['successful_techniques'])}",
        f"Challenge experience: {len(s['challenge_experience'])}",
        "",
        "📈 TOP SUCCESSFUL TOOLS:",
    ]
    tool_success = sorted(
        [(k, v) for k, v in s["tool_history"].items() if v["success"] > 0],
        key=lambda x: -x[1]["success"],
    )[:10]
    for name, data in tool_success:
        lines.append(f"  ✅ {name}: {data['success']}/{data['total']} ({data['success']/max(1,data['total'])*100:.0f}%)")

    lines.append("")
    lines.append("❌ MOST FAILED TOOLS:")
    tool_fail = sorted(
        [(k, v) for k, v in s["tool_history"].items() if v["failure"] > 0],
        key=lambda x: -x[1]["failure"],
    )[:10]
    for name, data in tool_fail:
        lines.append(f"  ❌ {name}: {data['failure']}/{data['total']} ({data['failure']/max(1,data['total'])*100:.0f}%)")

    lines.append("")
    lines.append("🧠 LEARNED STRATEGIES:")
    for strat in s["learned_strategies"][-10:]:
        lines.append(f"  • {strat}")

    return "\n".join(lines)


@tool(category="misc")
def reset_agent_memory() -> str:
    """Reset all agent learning memory (use with caution). Clears learned strategies and tool history."""
    if AGENT_STATE_FILE.exists():
        AGENT_STATE_FILE.unlink()
    return "Agent memory reset complete. All learned strategies and tool history cleared."
