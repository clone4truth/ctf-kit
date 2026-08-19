"""Tool chaining / pipeline orchestration for multi-step solves.

Lets the agent (or CLI user) run several registered tools back-to-back in a
single call, passing each tool's output into the next step's arguments.
"""

import json
import re

from ..registry import tool, run_tool

_PLACEHOLDER = re.compile(r"\$prev(?:\.(\d+))?|\$data")


def _resolve(value: str, prev_output: str, data: str) -> str:
    """Replace $prev / $prev.N / $data placeholders inside an arg string."""
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok == "$data":
            return data
        if tok == "$prev":
            return prev_output
        return _line(prev_output, int(m.group(1)))
    return _PLACEHOLDER.sub(repl, value)


def _line(text: str, idx: int) -> str:
    """$prev.N = the N-th line of the previous output (0-based)."""
    lines = [l for l in text.splitlines() if l.strip()]
    return lines[idx].strip() if 0 <= idx < len(lines) else ""


@tool(category="misc")
def chain_tools(steps: str, data: str = "") -> str:
    """Run multiple ctf-tools back-to-back; pass each output into the next step.

    steps = JSON array of {tool, args}. Placeholders inside args:
      $data   -> the initial `data` argument
      $prev   -> full output of the previous step
      $prev.N -> N-th non-empty line of the previous output (0-based)

    Example:
      [{"tool":"decode_all","data":"$data"},
       {"tool":"extract_flags_tool","text":"$prev"}]
    :param steps: JSON array of steps (tool + args with placeholders)
    :param data: initial data injected via $data
    """
    try:
        plan = json.loads(steps)
    except (ValueError, TypeError):
        return "ERROR: steps must be a JSON array, e.g. [{\"tool\":\"decode_all\",\"data\":\"$data\"}]"
    if not isinstance(plan, list) or not plan:
        return "ERROR: steps must be a non-empty JSON array"
    out: list[str] = []
    prev = data
    for i, step in enumerate(plan, 1):
        if not isinstance(step, dict) or "tool" not in step:
            out.append(f"Step {i}: skipped (invalid step object)")
            continue
        tool_name = str(step["tool"])
        raw_args = {k: v for k, v in step.items() if k != "tool"}
        args = {k: _resolve(v, prev, data) if isinstance(v, str) else v for k, v in raw_args.items()}
        try:
            result = run_tool(tool_name, args)
        except Exception as e:  # noqa: BLE001 - surface any tool failure
            out.append(f"Step {i} [{tool_name}]: EXCEPTION {e}")
            break
        ok = "ERROR" not in result
        snippet = result.strip()
        if len(snippet) > 500:
            snippet = snippet[:500] + "…"
        out.append(f"Step {i} [{tool_name}] args={json.dumps(args, ensure_ascii=False)} -> {'ok' if ok else 'failed'}")
        out.append("  " + snippet.replace("\n", "\n  "))
        prev = result
        if not ok:
            break
    return "\n".join(out)