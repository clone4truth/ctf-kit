"""New tool scaffold — drop a module in ctfkit/modules/ and it AUTO-REGISTERS
in the MCP server + web UI (57 tools -> 58, no config change needed).

Usage:
    python scripts/new_tool.py --name b64_xor --category crypto --summary "XOR after base64" \
        --params data_hex:str:text@hex,key:int
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ROOT / "ctfkit" / "modules"

VALID_CATS = {"encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--name", required=True, help="tool name (snake_case)")
    ap.add_argument("--category", required=True, choices=sorted(VALID_CATS))
    ap.add_argument("--summary", required=True, help="one-line description (becomes MCP/UI description)")
    ap.add_argument("--params", required=True, help="param specs: name:type[:default] comma-separated (type: str|int|bool)")
    ap.add_argument("--no-bump", action="store_true", help="skip updating __init__ import hint")
    args = ap.parse_args()

    name = args.name.strip()
    if not name.isidentifier():
        sys.exit(f"Invalid tool name: {name!r}")

    params = []
    for spec in args.params.split(","):
        parts = [p.strip() for p in spec.split(":")]
        if len(parts) < 2 or parts[1] not in ("str", "int", "bool"):
            sys.exit(f"Bad param spec: {spec!r} (use name:str|int|bool[:default])")
        params.append(parts)

    sig = []
    body_lines = []
    for p in params:
        pname, ptype = p[0], p[1]
        default = p[2] if len(p) > 2 else ""
        if ptype == "int":
            sig.append(f"{pname}: int" + (f" = {default}" if default else ""))
            body_lines.append(f"    {pname} = int({pname})")
        elif ptype == "bool":
            sig.append(f"{pname}: bool = {default or 'False'}")
        else:
            sig.append(f"{pname}: str" + (f" = {default!r}" if default else ""))
    doc = args.summary + "."
    src = f'"""{args.summary}."""\n\nfrom ..registry import tool\n\n\n@tool(category={args.category!r})\ndef {name}({", ".join(sig)}) -> str:\n    """{doc}"""\n'
    if body_lines:
        src += "\n".join(body_lines) + "\n"
    src += '    return f"TODO: implement {name} with {", ".join(p[0] for p in params) or "no params"}."\n'

    file = MODULES / f"{name}.py"
    if file.exists():
        sys.exit(f"Already exists: {file}")
    file.write_text(src, encoding="utf-8")
    print(f"Created: {file}")

    if not args.no_bump:
        init = MODULES / "__init__.py"
        if init.exists():
            text = init.read_text(encoding="utf-8")
            if f"import .{name}" not in text:
                text = text.rstrip()
                text = text[: text.rfind("  # noqa")] + f", {name}  # noqa: F401\n" if "  # noqa" in text else text + f"\nfrom . import {name}  # noqa: F401\n"
                init.write_text(text, encoding="utf-8")
                print(f"Registered import in {init}")

    print('Verify: python -c "import ctfkit.modules; from ctfkit.registry import list_tools; print(len(list_tools()))"  (should be +1)')


if __name__ == "__main__":
    sys.exit(main())