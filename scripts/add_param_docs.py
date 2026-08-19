"""One-off tool: append `:param x: desc` docstring lines to every @tool function
that lacks them, using the same glossary fallback as utils.tool_params.

Safe: uses ast node spans (exact character offsets), keeps summary first line,
never touches non-docstring code. Run:  python scripts/add_param_docs.py [--write]
"""

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ctfkit.utils import _PARAM_GLOSSARY  # noqa: E402

MODULES = Path(__file__).resolve().parent.parent / "ctfkit" / "modules"
PARAM_RE = re.compile(r":param\s+(\w+)")


def _desc(name: str) -> str:
    if name in _PARAM_GLOSSARY:
        return _PARAM_GLOSSARY[name]
    return name.replace("_", " ").replace("csv", "(comma-separated)").strip()


def _insert_doc_params(src: str, fn: ast.FunctionDef, doc: ast.Constant) -> str:
    existing = set(PARAM_RE.findall(ast.get_docstring(fn) or ""))
    sig = {p.arg for p in fn.args.args if p.arg not in ("self", "ctx", "context")}
    missing = [n for n in sig if n not in existing]
    if not missing:
        return src
    param_lines = "\n".join(f"    :param {n}: {_desc(n)}" for n in missing)
    lines = src.split("\n")
    start_line, start_col = doc.lineno - 1, doc.col_offset
    end_line, end_col = doc.end_lineno - 1, doc.end_col_offset
    if start_line == end_line:
        inner = lines[start_line][start_col:end_col]
        inner = inner[3:-3].strip()
        new_doc = f'"""{inner}\n{param_lines}\n    """'
        lines[start_line] = lines[start_line][:start_col] + new_doc + lines[start_line][end_col:]
    else:
        first = lines[start_line][start_col:].rstrip()
        new_doc = f"{first}\n{param_lines}\n    \"\"\""
        lines[start_line] = lines[start_line][:start_col] + new_doc
        lines[end_line] = lines[end_line][end_col:]
        del lines[start_line + 1:end_line]
    return "\n".join(lines)


def process(path: Path, write: bool = False) -> int:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    targets = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.decorator_list:
            continue
        is_tool = False
        for d in node.decorator_list:
            func = d.func if isinstance(d, ast.Call) else d
            if (isinstance(func, ast.Name) and func.id == "tool") or \
               (isinstance(func, ast.Attribute) and func.attr == "tool"):
                is_tool = True
                break
        if not is_tool:
            continue
        body0 = node.body[0] if node.body else None
        if isinstance(body0, ast.Expr) and isinstance(body0.value, ast.Constant) and isinstance(body0.value.value, str):
            targets.append((node.lineno, node, body0.value))
    changed = 0
    for _, fn, doc in sorted(targets, key=lambda t: t[0], reverse=True):  # bottom-up: offsets stay valid
        new_src = _insert_doc_params(src, fn, doc)
        if new_src != src:
            src = new_src
            changed += 1
    if changed and write:
        path.write_text(src, encoding="utf-8")
    return changed


def main():
    write = "--write" in sys.argv
    total = 0
    for f in sorted(MODULES.glob("*.py")):
        n = process(f, write)
        if n:
            total += n
            print(f"{'WRITE' if write else 'would fix':<10} {f.name}: {n} function(s)")
    print(f"{'WROTE' if write else 'DRY-RUN'} total: {total} functions updated")


if __name__ == "__main__":
    main()