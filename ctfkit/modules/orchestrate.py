"""Tool chaining / pipeline orchestration for multi-step solves.

Lets the agent (or CLI user) run several registered tools back-to-back in a
single call, passing each tool's output into the next step's arguments.

Supports parallel execution for independent steps (DAG-aware).
"""

import asyncio
import json
import re
from typing import Any

from ..registry import tool, execute_tool, TOOLS

_PLACEHOLDER = re.compile(r"\$prev(?:\.(\d+))?|\$step\.(\d+)|\$data")
_MAX_STEPS = 20
_RECURSIVE_TOOLS = {"chain_tools", "chain_tools_sequential", "autonomous_solve", "scaffold_new_tool"}


def _resolve(value: str, prev_output: str, data: str, results: dict) -> str:
    """Replace $prev / $prev.N / $data / $step.N placeholders inside an arg string."""
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok == "$data":
            return data
        if tok == "$prev":
            return prev_output
        # $prev.N
        if tok.startswith("$prev."):
            return _line(prev_output, int(m.group(1)))
        # $step.N - reference to a specific step's output
        if tok.startswith("$step."):
            step_idx = int(m.group(2))
            return results.get(f"step_{step_idx}", "")
        return tok
    return _PLACEHOLDER.sub(repl, value)


def _line(text: str, idx: int) -> str:
    """$prev.N = the N-th line of the previous output (0-based)."""
    lines = [l for l in text.splitlines() if l.strip()]
    return lines[idx].strip() if 0 <= idx < len(lines) else ""


def _build_dag(plan: list[dict]) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
    """
    Build dependency graph from plan.
    Returns (dependencies, dependents) where:
    - dependencies[step_idx] = list of step indices this step depends on
    - dependents[step_idx] = list of step indices that depend on this step
    """
    dependencies = {i: [] for i in range(len(plan))}
    dependents = {i: [] for i in range(len(plan))}
    
    for i, step in enumerate(plan):
        args_str = json.dumps(step.get("args", {}))
        # Find all $prev, $prev.N and $step.N references
        has_bare_prev = "$prev" in args_str and "$prev." not in args_str  # $prev without index
        prev_refs = re.findall(r"\$prev\.(\d+)", args_str)
        step_refs = re.findall(r"\$step\.(\d+)", args_str)
        
        for ref in prev_refs:
            dep_idx = int(ref)
            if dep_idx < i:  # only backward references allowed
                dependencies[i].append(dep_idx)
                dependents[dep_idx].append(i)
        
        for ref in step_refs:
            dep_idx = int(ref)
            if dep_idx < i:
                dependencies[i].append(dep_idx)
                dependents[dep_idx].append(i)
        
        # Bare $prev depends on the immediately previous step
        if has_bare_prev and i > 0:
            dependencies[i].append(i - 1)
            dependents[i - 1].append(i)
    
    return dependencies, dependents


def _topological_levels(dependencies: dict[int, list[int]], dependents: dict[int, list[int]]) -> list[list[int]]:
    """Group steps by topological level (steps in same level can run in parallel)."""
    levels = []
    remaining = set(dependencies.keys())
    completed = set()
    
    while remaining:
        # Find all steps with no unmet dependencies
        ready = [i for i in remaining if all(d in completed for d in dependencies[i])]
        if not ready:
            # Circular dependency - fallback to sequential
            ready = [min(remaining)]
        levels.append(ready)
        completed.update(ready)
        remaining -= set(ready)
    
    return levels


async def _run_step(step_idx: int, step: dict, data: str, results: dict) -> tuple[int, str]:
    """Run a single step asynchronously."""
    tool_name = step["tool"]
    args = step.get("args", {})
    
    # Resolve placeholders in args
    prev_output = results.get(f"step_{step_idx - 1}", "") if step_idx > 0 else ""
    resolved_args = {}
    for k, v in args.items():
        if isinstance(v, str):
            resolved_args[k] = _resolve(v, prev_output, data, results)
        else:
            resolved_args[k] = v
    
    # Run tool in thread pool (since run_tool is sync)
    loop = asyncio.get_event_loop()
    try:
        execution = await loop.run_in_executor(None, execute_tool, tool_name, resolved_args)
        output = execution["text"]
        if not execution["ok"]:
            output = f"[{execution['status']}] {output}"
        return step_idx, output
    except Exception as e:
        return step_idx, f"ERROR: {e}"


@tool(category="misc")
def chain_tools(steps: str, data: str = "", parallel: bool = True) -> str:
    """Run multiple ctf-tools back-to-back; pass each output into the next step.

    steps = JSON array of {tool, args}. Placeholders inside args:
      $data      -> the initial `data` argument
      $prev      -> full output of the previous step
      $prev.N    -> N-th non-empty line of the previous output (0-based)
      $step.N    -> full output of step N (0-based, any previous step)

    Example:
      [
        {"tool":"decode_all","args":{"data":"$data"}},
        {"tool":"extract_flags_tool","args":{"text":"$prev"}}
      ]

    With parallel=true (default), independent steps run concurrently.
    
    :param steps: JSON array of steps (tool + args with placeholders)
    :param data: initial data injected via $data
    :param parallel: whether to run independent steps in parallel (default: true)
    """
    try:
        plan = json.loads(steps)
    except (ValueError, TypeError):
        return "ERROR: steps must be a JSON array, e.g. [{\"tool\":\"decode_all\",\"args\":{\"data\":\"$data\"}}]"

    if not isinstance(plan, list):
        return "ERROR: steps must be a JSON array"
    if not plan or len(plan) > _MAX_STEPS:
        return f"ERROR: pipeline must contain 1..{_MAX_STEPS} steps"

    # Validate all tools exist
    for i, step in enumerate(plan):
        if not isinstance(step, dict) or "tool" not in step:
            return f"ERROR: step {i} must be an object with 'tool' key"
        if step["tool"] not in TOOLS:
            return f"ERROR: unknown tool '{step['tool']}' at step {i}"
        if step["tool"] in _RECURSIVE_TOOLS:
            return f"ERROR: recursive/state-mutating tool '{step['tool']}' is not allowed in a pipeline"

    # Build dependency graph
    dependencies, dependents = _build_dag(plan)
    
    # Get topological levels for parallel execution
    levels = _topological_levels(dependencies, dependents)
    
    results = {}
    all_outputs = []
    
    # Run level by level
    for level_idx, level in enumerate(levels):
        can_parallelize = parallel and len(level) > 1 and all(
            TOOLS[plan[idx]["tool"]].get("parallel_safe", False) for idx in level
        )
        if can_parallelize:
            # Run all steps in this level concurrently
            async def run_level():
                tasks = [_run_step(idx, plan[idx], data, results) for idx in level]
                return await asyncio.gather(*tasks)
            
            level_results = asyncio.run(run_level())
        else:
            # Sequential execution
            level_results = []
            for idx in level:
                prev_output = results.get(f"step_{idx - 1}", "") if idx > 0 else ""
                args = plan[idx].get("args", {})
                resolved_args = {}
                for k, v in args.items():
                    if isinstance(v, str):
                        resolved_args[k] = _resolve(v, prev_output, data, results)
                    else:
                        resolved_args[k] = v
                execution = execute_tool(plan[idx]["tool"], resolved_args)
                output = execution["text"]
                if not execution["ok"]:
                    output = f"[{execution['status']}] {output}"
                level_results.append((idx, output))
        
        # Collect results
        for step_idx, output in level_results:
            results[f"step_{step_idx}"] = output
            all_outputs.append(f"=== STEP {step_idx} ({plan[step_idx]['tool']}) ===\n{output}")

    return "\n\n".join(all_outputs)


@tool(category="misc")
def chain_tools_sequential(steps: str, data: str = "") -> str:
    """Legacy sequential-only chain_tools (for backward compatibility)."""
    return chain_tools(steps, data, parallel=False)
