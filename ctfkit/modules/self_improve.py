"""Self-improvement engine — makes the agent smarter after every challenge.

The engine runs automatically after each solve (hooked into remember_challenge)
and can also be triggered manually. It:

1. Analyzes solved challenges to extract reusable patterns & shortcuts
2. Ranks tools by success rate per category → smarter tool selection
3. Detects recurring failure patterns → auto-generates avoidance rules
4. Updates category playbooks with real techniques that worked
5. Generates "fast-path" shortcuts for common challenge types
6. Self-diagnoses tool health and suggests fixes

All learning is persisted to memory/self_improve_state.json and injected
into detect_challenge / recall_knowledge / select_tools at runtime.
"""

import json
import hashlib
import re
import shutil
import time
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ..logging import log
from ..registry import tool, TOOLS, run_tool

ROOT = Path(__file__).resolve().parent.parent.parent
STATE_FILE = ROOT / "memory" / "self_improve_state.json"
PATTERNS_FILE = ROOT / "memory" / "learned_patterns.json"
FAST_PATHS_FILE = ROOT / "memory" / "fast_paths.json"
STATE_VERSION = 2
VALID_CATEGORIES = {"encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint", "misc"}


def _empty_state() -> dict:
    """Return a clean provenance-aware state.

    Fixture solves are recorded for evaluation visibility, but only verified
    solves are allowed to change rankings, patterns, or fast paths.
    """
    return {
        "version": STATE_VERSION,
        "total_solves": 0,
        "verified_solves": 0,
        "fixture_solves": 0,
        "rejected_solves": 0,
        "total_improvements": 0,
        "tool_rankings": {},
        "technique_patterns": [],
        "failure_rules": [],
        "fast_paths": {},
        "playbook_overrides": {},
        "improvement_log": [],
        "tool_pair_synergy": {},
        "category_stats": {},
        "provenance": {},
        "rejections": [],
    }


# ─── Persistent State ────────────────────────────────────────────────────

def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if state.get("version") == STATE_VERSION:
                base = _empty_state()
                base.update(state)
                return base
            # Never silently consume untraceable v1 aggregates.
            return _empty_state()
        except Exception:
            pass
    return _empty_state()


def _save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Cap arrays to prevent unbounded growth
    state["improvement_log"] = state["improvement_log"][-200:]
    state["technique_patterns"] = state["technique_patterns"][-100:]
    state["failure_rules"] = state["failure_rules"][-50:]
    state["rejections"] = state.get("rejections", [])[-100:]
    state["version"] = STATE_VERSION
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _log_improvement(state: dict, imp_type: str, desc: str):
    state["improvement_log"].append({
        "date": date.today().isoformat(),
        "time": time.strftime("%H:%M:%S"),
        "type": imp_type,
        "description": desc,
    })
    state["total_improvements"] += 1


# ─── Core Self-Improvement Functions ─────────────────────────────────────

def _update_tool_rankings(state: dict, category: str, tools_used: list[str],
                          success: bool):
    """Update per-category tool rankings based on solve outcomes."""
    if category not in state["tool_rankings"]:
        state["tool_rankings"][category] = {}

    for t in tools_used:
        if t not in state["tool_rankings"][category]:
            state["tool_rankings"][category][t] = {
                "score": 50.0, "wins": 0, "losses": 0, "total": 0,
            }
        entry = state["tool_rankings"][category][t]
        entry["total"] += 1
        if success:
            entry["wins"] += 1
            # ELO-like: more wins = higher score, diminishing returns
            entry["score"] = min(100, entry["score"] + max(1, 10 - entry["wins"] * 0.5))
        else:
            entry["losses"] += 1
            entry["score"] = max(0, entry["score"] - 3)


def _detect_technique_pattern(state: dict, category: str, tools_used: list[str],
                              note: str, problem: str):
    """Extract reusable technique patterns from solved challenges."""
    # Build a signature from keywords
    text = f"{note} {problem}".lower()
    keywords = set()

    # Extract meaningful keywords
    keyword_patterns = [
        r'\b(symlink|lfi|rce|sqli|xss|csrf|ssrf|ssti|jwt|cookie|session|upload|'
        r'path.?traversal|command.?injection|deserialization|xxe|idor|'
        r'buffer.?overflow|format.?string|rop|ret2|heap|use.?after.?free|'
        r'base64|xor|rsa|aes|cbc|ecb|padding|wiener|fermat|hastad|'
        r'lsb|steghide|binwalk|pcap|exif|dns.?exfil|carve|entropy|'
        r'git.?leak|zip|symlink|template|filter.?chain|nonce.?reuse)\b',
    ]
    for pat in keyword_patterns:
        keywords.update(re.findall(pat, text))

    if not keywords or not tools_used:
        return

    sig = "+".join(sorted(keywords)[:5])

    # Check if pattern already exists
    for existing in state["technique_patterns"]:
        if existing["pattern"] == sig:
            existing["count"] += 1
            existing["success_rate"] = (
                existing["success_rate"] * (existing["count"] - 1) + 1.0
            ) / existing["count"]
            # Merge new tools
            for t in tools_used:
                if t not in existing["tools"]:
                    existing["tools"].append(t)
            return

    # New pattern
    state["technique_patterns"].append({
        "pattern": sig,
        "keywords": list(keywords),
        "tools": tools_used[:6],
        "category": category,
        "success_rate": 1.0,
        "count": 1,
        "first_seen": date.today().isoformat(),
    })
    _log_improvement(state, "pattern_learned",
                     f"New technique pattern: {sig} → {', '.join(tools_used[:3])}")


def _detect_tool_synergy(state: dict, tools_used: list[str], category: str):
    """Track which tool combinations work well together."""
    if len(tools_used) < 2:
        return
    # Record all pairs
    for i, a in enumerate(tools_used):
        for b in tools_used[i + 1:]:
            pair_key = "+".join(sorted([a, b]))
            if pair_key not in state["tool_pair_synergy"]:
                state["tool_pair_synergy"][pair_key] = {
                    "count": 0, "category": category,
                }
            state["tool_pair_synergy"][pair_key]["count"] += 1


def _update_category_stats(state: dict, category: str, tools_used: list[str]):
    """Track per-category statistics for smarter future solves."""
    if category not in state["category_stats"]:
        state["category_stats"][category] = {
            "total": 0, "solved": 0, "avg_tools": 0,
            "tool_frequency": {},
        }
    stats = state["category_stats"][category]
    stats["total"] += 1
    stats["solved"] += 1
    # Running average of tools used
    stats["avg_tools"] = (
        stats["avg_tools"] * (stats["total"] - 1) + len(tools_used)
    ) / stats["total"]
    for t in tools_used:
        stats["tool_frequency"][t] = stats["tool_frequency"].get(t, 0) + 1


def _generate_fast_path(state: dict, category: str, tools_used: list[str],
                        note: str, problem: str):
    """Generate fast-path shortcuts for common challenge types."""
    text = f"{note} {problem}".lower()

    # Detect common challenge archetypes
    archetypes = {
        "web_sqli_login": ["sql", "login", "bypass", "auth"],
        "web_jwt_forge": ["jwt", "token", "forge", "none"],
        "web_ssti": ["ssti", "template", "jinja", "{{"],
        "web_lfi": ["lfi", "traversal", "include", "file"],
        "web_upload": ["upload", "shell", "webshell", "php"],
        "crypto_rsa_close_primes": ["rsa", "close", "prime", "fermat"],
        "crypto_rsa_small_e": ["rsa", "small", "cube", "e=3"],
        "crypto_xor_single": ["xor", "single", "byte", "brute"],
        "crypto_base_decode": ["base64", "base", "decode", "encode"],
        "stego_lsb": ["lsb", "pixel", "bit", "plane"],
        "stego_metadata": ["exif", "metadata", "comment", "text"],
        "forensics_pcap": ["pcap", "capture", "wireshark", "http"],
        "forensics_carve": ["carve", "hidden", "embedded", "binwalk"],
        "pwn_bof_ret2win": ["overflow", "ret2win", "buffer", "bof"],
        "pwn_format_string": ["format", "string", "printf", "fmtstr"],
        "rev_strings": ["strings", "flag", "hidden", "binary"],
    }

    for archetype, keywords in archetypes.items():
        archetype_category = archetype.split("_", 1)[0]
        if archetype_category != category:
            continue
        if sum(1 for k in keywords if k in text) >= 2:
            if archetype not in state["fast_paths"]:
                state["fast_paths"][archetype] = {
                    "tools": tools_used[:5],
                    "count": 0,
                    "category": category,
                    "last_used": date.today().isoformat(),
                }
            fp = state["fast_paths"][archetype]
            fp["count"] += 1
            fp["last_used"] = date.today().isoformat()
            # Merge tools (keep most-used first)
            for t in tools_used:
                if t not in fp["tools"]:
                    fp["tools"].append(t)
            fp["tools"] = fp["tools"][:8]
            _log_improvement(state, "fast_path_updated",
                             f"Fast path '{archetype}' updated ({fp['count']} solves)")
            return archetype
    return None


def _learn_from_failures(state: dict, category: str, note: str):
    """Extract failure avoidance rules from lessons learned."""
    text = note.lower()

    # Common failure patterns to learn from
    failure_indicators = [
        (r"not (\w+)", "avoid_technique"),
        (r"don'?t use (\w+)", "avoid_tool"),
        (r"(\w+) (didn'?t|does ?n'?t|won'?t) work", "avoid_tool"),
        (r"wrong (approach|technique|tool)", "general_warning"),
        (r"(timeout|too slow|hang)", "performance_issue"),
        (r"(false positive|noise|not a flag)", "false_positive"),
    ]

    for pattern, rule_type in failure_indicators:
        matches = re.findall(pattern, text)
        if matches:
            rule = {
                "condition": f"{category}: {matches[0] if isinstance(matches[0], str) else ' '.join(matches[0])}",
                "type": rule_type,
                "category": category,
                "reason": note[:200],
                "count": 1,
                "date": date.today().isoformat(),
            }
            # Check for existing similar rule
            found = False
            for existing in state["failure_rules"]:
                if existing["condition"] == rule["condition"]:
                    existing["count"] += 1
                    found = True
                    break
            if not found:
                state["failure_rules"].append(rule)
                _log_improvement(state, "failure_rule",
                                 f"New avoidance rule: {rule['condition']}")


# ─── Main Self-Improvement Entry Point ────────────────────────────────────

def _solve_id(title: str, problem: str, flag: str) -> str:
    canonical = "\n".join((title.strip().lower(), problem.strip(), flag.strip()))
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:24]


def validate_solve_evidence(*, title: str, category: str, tools_used: list[str],
                            flag: str, problem: str = "", commands: str = "",
                            evidence: str = "", source: str = "manual") -> tuple[bool, str, float]:
    """Validate whether a solve is trustworthy enough to train recommendations."""
    from ..flagmeta import extract_flag_candidates

    if not title.strip():
        return False, "missing title", 0.0
    if category not in VALID_CATEGORIES:
        return False, "invalid category", 0.0
    known_tools = [name for name in dict.fromkeys(tools_used) if name in TOOLS]
    if not known_tools:
        return False, "no registered tool evidence", 0.0
    candidates = extract_flag_candidates(f"flag: {flag}\n{evidence}")
    exact = next((c for c in candidates if c["value"] == flag), None)
    if not exact or exact["confidence"] < 0.75:
        return False, "flag candidate is missing or low-confidence", float(exact["confidence"] if exact else 0)
    if source == "fixture":
        return True, "fixture evidence (excluded from rankings)", float(exact["confidence"])
    if not problem.strip():
        return False, "missing problem statement", float(exact["confidence"])
    if not (commands.strip() or evidence.strip()):
        return False, "missing commands or captured evidence", float(exact["confidence"])
    return True, "verified solve evidence", float(exact["confidence"])


def archive_legacy_state() -> Path | None:
    """Preserve a legacy state once before rebuilding v2."""
    if not STATE_FILE.exists():
        return None
    try:
        current = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    if current.get("version") == STATE_VERSION:
        return None
    backup = STATE_FILE.with_name("self_improve_state.v1.json")
    if not backup.exists():
        shutil.copy2(STATE_FILE, backup)
    return backup


def self_improve_after_solve(title: str, category: str, tools_used: list[str],
                             flag: str, note: str, problem: str = "",
                             commands: str = "", evidence: str = "",
                             source: str = "manual", challenge_id: str = "") -> dict:
    """Called automatically after every successful solve to learn and improve.

    This is the main hook — it runs ALL improvement sub-routines.
    """
    archive_legacy_state()
    state = _load_state()
    solve_id = challenge_id or _solve_id(title, problem, flag)
    if solve_id in state["provenance"]:
        return {"learned": False, "reason": "duplicate solve", "challenge_id": solve_id}

    valid, reason, confidence = validate_solve_evidence(
        title=title, category=category, tools_used=tools_used, flag=flag,
        problem=problem, commands=commands, evidence=evidence, source=source,
    )
    record = {
        "title": title, "category": category, "source": source,
        "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest() if evidence else "",
        "confidence": confidence, "accepted": valid, "reason": reason,
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "tools": [t for t in dict.fromkeys(tools_used) if t in TOOLS],
    }
    state["provenance"][solve_id] = record
    state["total_solves"] += 1

    if not valid:
        state["rejected_solves"] += 1
        state["rejections"].append({"challenge_id": solve_id, "title": title, "reason": reason})
        _save_state(state)
        return {"learned": False, "reason": reason, "challenge_id": solve_id}

    if source == "fixture":
        state["fixture_solves"] += 1
        _save_state(state)
        return {"learned": False, "reason": reason, "challenge_id": solve_id}

    state["verified_solves"] += 1
    tools_used = record["tools"]

    # 1. Update tool rankings
    _update_tool_rankings(state, category, tools_used, success=True)

    # 2. Detect technique patterns
    _detect_technique_pattern(state, category, tools_used, note, problem)

    # 3. Track tool synergy
    _detect_tool_synergy(state, tools_used, category)

    # 4. Update category stats
    _update_category_stats(state, category, tools_used)

    # 5. Generate fast-path shortcuts
    _generate_fast_path(state, category, tools_used, note, problem)

    # 6. Learn from failure mentions in notes
    _learn_from_failures(state, category, note)

    # 7. Auto-update playbook overrides based on what actually worked
    _update_playbook_override(state, category, tools_used, note)

    _save_state(state)
    log.info("[self-improve] Learned from '%s' (%s) — %d total improvements",
             title, category, state["total_improvements"])
    return {"learned": True, "reason": reason, "challenge_id": solve_id}


def _update_playbook_override(state: dict, category: str, tools_used: list[str],
                              note: str):
    """When real solves differ from playbook, record the override."""
    if category not in state["playbook_overrides"]:
        state["playbook_overrides"][category] = []

    overrides = state["playbook_overrides"][category]

    # Only record if we have meaningful tool usage
    if len(tools_used) >= 2:
        # Check if this combination is already known
        combo = ",".join(sorted(tools_used[:5]))
        for existing in overrides:
            if existing.get("tools_combo") == combo:
                existing["count"] = existing.get("count", 1) + 1
                return

        overrides.append({
            "tools_combo": combo,
            "tools": tools_used[:5],
            "note": note[:200],
            "count": 1,
            "date": date.today().isoformat(),
        })
        # Keep only top 20 overrides per category
        state["playbook_overrides"][category] = sorted(
            overrides, key=lambda x: -x.get("count", 0)
        )[:20]


# ─── MCP Tools (exposed to the agent) ─────────────────────────────────────

@tool(category="misc")
def self_improve_report() -> str:
    """Show self-improvement status: what the agent has learned, tool rankings, patterns, and fast-paths.

    Call this to see how the agent has evolved and what shortcuts it knows.
    """
    state = _load_state()
    lines = [
        "=" * 60,
        "🧠 SELF-IMPROVEMENT ENGINE — STATUS REPORT",
        "=" * 60,
        f"Total solves analyzed  : {state['total_solves']}",
        f"Verified training solves: {state['verified_solves']}",
        f"Fixture solves (held out): {state['fixture_solves']}",
        f"Rejected solves        : {state['rejected_solves']}",
        f"Total improvements     : {state['total_improvements']}",
        f"Technique patterns     : {len(state['technique_patterns'])}",
        f"Failure rules          : {len(state['failure_rules'])}",
        f"Fast-path shortcuts    : {len(state['fast_paths'])}",
        f"Tool synergy pairs     : {len(state['tool_pair_synergy'])}",
        "",
    ]

    # Top tools per category
    lines.append("📊 TOP TOOLS PER CATEGORY:")
    for cat, rankings in sorted(state["tool_rankings"].items()):
        top = sorted(rankings.items(), key=lambda x: -x[1]["score"])[:5]
        if top:
            tools_str = ", ".join(f"{t}({d['score']:.0f})" for t, d in top)
            lines.append(f"  {cat}: {tools_str}")

    # Technique patterns
    if state["technique_patterns"]:
        lines.append("")
        lines.append("🔍 LEARNED TECHNIQUE PATTERNS:")
        for p in sorted(state["technique_patterns"],
                        key=lambda x: -x["count"])[:10]:
            lines.append(
                f"  [{p['category']}] {p['pattern']} → "
                f"{', '.join(p['tools'][:3])} "
                f"(used {p['count']}x, {p['success_rate']:.0%} success)"
            )

    # Fast paths
    if state["fast_paths"]:
        lines.append("")
        lines.append("⚡ FAST-PATH SHORTCUTS:")
        for name, fp in sorted(state["fast_paths"].items(),
                                key=lambda x: -x[1]["count"]):
            lines.append(
                f"  {name}: {', '.join(fp['tools'][:4])} "
                f"(used {fp['count']}x)"
            )

    # Tool synergy
    if state["tool_pair_synergy"]:
        lines.append("")
        lines.append("🤝 TOOL SYNERGY (best pairs):")
        top_pairs = sorted(state["tool_pair_synergy"].items(),
                           key=lambda x: -x[1]["count"])[:8]
        for pair, data in top_pairs:
            lines.append(f"  {pair} → {data['count']} combined uses ({data['category']})")

    # Failure rules
    if state["failure_rules"]:
        lines.append("")
        lines.append("⚠️ FAILURE AVOIDANCE RULES:")
        for rule in state["failure_rules"][:5]:
            lines.append(f"  [{rule['category']}] {rule['condition']} (×{rule['count']})")

    # Recent improvements
    if state["improvement_log"]:
        lines.append("")
        lines.append("📈 RECENT IMPROVEMENTS:")
        for entry in state["improvement_log"][-8:]:
            lines.append(f"  [{entry['date']}] {entry['type']}: {entry['description'][:80]}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


@tool(category="misc")
def smart_tool_recommend(challenge_description: str, category: str = "") -> str:
    """AI-powered tool recommendation based on learned patterns and historical success rates.

    Uses accumulated experience to recommend the BEST tools for a challenge,
    not just keyword matching. Considers: tool rankings, technique patterns,
    fast-paths, and tool synergy.

    :param challenge_description: Challenge problem statement or description
    :param category: Category hint (auto-detected if empty)
    """
    from ..flagmeta import detect_ctf, CATEGORY_KEYWORDS, suggested_tools

    state = _load_state()
    text = challenge_description.lower()

    # 1. Auto-detect category if not provided
    if not category:
        _, detected_cat = detect_ctf(challenge_description)
        category = detected_cat or "misc"

    lines = [
        "=" * 60,
        f"🎯 SMART TOOL RECOMMENDATION ({category.upper()})",
        "=" * 60,
        "",
    ]

    # 2. Check fast-paths first (fastest solve)
    matched_fp = None
    best_fp_score = 0
    for fp_name, fp_data in state.get("fast_paths", {}).items():
        if fp_data.get("category") != category:
            continue
        # Count keyword matches
        fp_keywords = fp_name.replace("_", " ").split()
        score = sum(1 for k in fp_keywords if k in text)
        if score > best_fp_score and score >= 2:
            best_fp_score = score
            matched_fp = (fp_name, fp_data)

    if matched_fp:
        fp_name, fp_data = matched_fp
        lines.append(f"⚡ FAST-PATH MATCH: {fp_name}")
        lines.append(f"   Proven tools: {', '.join(fp_data['tools'][:5])}")
        lines.append(f"   Solved {fp_data['count']}x before")
        lines.append(f"   → Start with these tools first!")
        lines.append("")

    # 3. Check technique patterns
    matched_patterns = []
    for pattern in state.get("technique_patterns", []):
        if pattern.get("category") != category:
            continue
        kw_matches = sum(1 for k in pattern.get("keywords", []) if k in text)
        if kw_matches >= 2:
            matched_patterns.append((kw_matches, pattern))

    if matched_patterns:
        matched_patterns.sort(key=lambda x: -x[0])
        lines.append("🔍 MATCHING TECHNIQUE PATTERNS:")
        for score, pat in matched_patterns[:3]:
            lines.append(
                f"   Pattern: {pat['pattern']}")
            lines.append(
                f"   Tools: {', '.join(pat['tools'][:4])} "
                f"({pat['success_rate']:.0%} success, {pat['count']}x)")
        lines.append("")

    # 4. Category-ranked tools (by historical success)
    ranked_tools = state.get("tool_rankings", {}).get(category, {})
    if ranked_tools:
        top = sorted(ranked_tools.items(), key=lambda x: -x[1]["score"])[:10]
        lines.append(f"📊 TOP RANKED TOOLS FOR {category.upper()} (by success):")
        for t, d in top:
            win_rate = d["wins"] / max(1, d["total"]) * 100
            lines.append(f"   {t}: score={d['score']:.0f} "
                         f"({d['wins']}/{d['total']} wins, {win_rate:.0f}%)")
        lines.append("")

    # 5. Tool synergy suggestions
    synergy = state.get("tool_pair_synergy", {})
    if synergy:
        relevant = [(pair, d) for pair, d in synergy.items()
                     if d.get("category") == category]
        relevant.sort(key=lambda x: -x[1]["count"])
        if relevant:
            lines.append("🤝 RECOMMENDED TOOL PAIRS:")
            for pair, d in relevant[:5]:
                lines.append(f"   {pair} (used together {d['count']}x)")
            lines.append("")

    # 6. Failure avoidance warnings
    warnings = [r for r in state.get("failure_rules", [])
                if r.get("category") == category]
    if warnings:
        lines.append("⚠️ AVOID (learned from past failures):")
        for w in warnings[:3]:
            lines.append(f"   {w['condition']}: {w['reason'][:60]}")
        lines.append("")

    # 7. Fallback: default suggested tools
    default_tools = suggested_tools(category)
    lines.append(f"📋 DEFAULT TOOLKIT ({category}):")
    lines.append(f"   {', '.join(default_tools[:8])}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


@tool(category="misc")
def self_diagnose() -> str:
    """Run self-diagnostics: check tool health, identify weak areas, and suggest improvements.

    Analyzes the execution log to find:
    - Tools with high failure rates that need fixing
    - Categories with low solve rates
    - Missing tool coverage
    - Performance bottlenecks
    """
    state = _load_state()
    lines = [
        "=" * 60,
        "🔧 SELF-DIAGNOSTICS REPORT",
        "=" * 60,
        "",
    ]

    # 1. Load execution log for tool health
    exec_log_path = ROOT / "memory" / "execution_log.json"
    exec_data = {}
    if exec_log_path.exists():
        try:
            exec_data = json.loads(exec_log_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 2. Tools with high failure rates
    problem_tools = []
    runs = {name: data for name, data in exec_data.get("runs", {}).items() if name in TOOLS}
    for tool_name, data in runs.items():
        total = data.get("total", 0)
        failures = data.get("failure", 0)
        if total >= 3 and failures / total > 0.5:
            problem_tools.append((tool_name, total, failures))

    if problem_tools:
        lines.append("❌ TOOLS WITH HIGH FAILURE RATES (>50%):")
        for t, total, fail in sorted(problem_tools, key=lambda x: -x[2]):
            rate = fail / total * 100
            lines.append(f"  {t}: {fail}/{total} failures ({rate:.0f}%)")
            # Suggest fix
            if rate > 80:
                lines.append(f"    → Consider: review tool implementation or improve arg inference")
        lines.append("")
    else:
        lines.append("✅ No tools with critically high failure rates")
        lines.append("")

    # 3. Category coverage analysis
    cat_tools = {}
    for name, meta in TOOLS.items():
        cat = meta.get("category", "misc")
        if cat not in cat_tools:
            cat_tools[cat] = 0
        cat_tools[cat] += 1

    lines.append("📦 CATEGORY COVERAGE:")
    for cat, count in sorted(cat_tools.items()):
        solves = state.get("category_stats", {}).get(cat, {}).get("solved", 0)
        status = "✅" if count >= 10 else "⚠️" if count >= 5 else "❌"
        lines.append(f"  {status} {cat}: {count} tools, {solves} solves")
    lines.append("")

    verified_memories = len(list((ROOT / "memory").glob("*.md"))) - int((ROOT / "memory" / "_index.md").exists())
    if state.get("version", 1) < 2 or state.get("total_solves", 0) > verified_memories:
        lines.append("⚠️ LEARNING DATA QUALITY: legacy aggregate state does not match verified memories;")
        lines.append("  learned fast-paths are disabled by default until a provenance-aware v2 rebuild.")
        lines.append("")

    # 4. Improvement suggestions
    lines.append("💡 IMPROVEMENT SUGGESTIONS:")
    suggestions = []

    # Check if patterns are being learned
    if state["total_solves"] > 5 and len(state["technique_patterns"]) < 3:
        suggestions.append("Learn more technique patterns — solve more diverse challenges")

    # Check tool synergy data
    if state["total_solves"] > 10 and len(state["tool_pair_synergy"]) < 5:
        suggestions.append("Build more tool synergy data — use multi-tool approaches")

    # Check fast paths
    if state["total_solves"] > 8 and len(state["fast_paths"]) < 3:
        suggestions.append("Generate more fast-paths — keep solving common archetypes")

    # Check for stale tools
    never_used = [name for name, meta in TOOLS.items()
                  if name not in runs and meta["category"] not in ("misc",)]
    if len(never_used) > 20:
        suggestions.append(f"{len(never_used)} tools never used — explore: {', '.join(never_used[:5])}")

    if not suggestions:
        suggestions.append("Agent is performing well! Keep solving to accumulate more data.")

    for s in suggestions:
        lines.append(f"  • {s}")

    # 5. Overall health score
    total_tools = len(TOOLS)
    used_tools = len(runs)
    coverage = used_tools / max(1, total_tools) * 100
    total_runs = sum(d.get("total", 0) for d in runs.values())
    total_success = sum(d.get("success", 0) for d in runs.values())
    success_rate = total_success / max(1, total_runs) * 100

    lines.append("")
    lines.append("📈 OVERALL HEALTH SCORE:")
    lines.append(f"  Tool coverage    : {coverage:.0f}% ({used_tools}/{total_tools} tools used)")
    lines.append(f"  Success rate     : {success_rate:.0f}% ({total_success}/{total_runs})")
    lines.append(f"  Patterns learned : {len(state['technique_patterns'])}")
    lines.append(f"  Fast-paths       : {len(state['fast_paths'])}")

    health = min(100, (coverage * 0.2 + success_rate * 0.4 +
                       min(100, len(state['technique_patterns']) * 10) * 0.2 +
                       min(100, len(state['fast_paths']) * 15) * 0.2))
    emoji = "🟢" if health > 70 else "🟡" if health > 40 else "🔴"
    lines.append(f"  Overall          : {emoji} {health:.0f}/100")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


@tool(category="misc")
def optimize_workflow(category: str = "") -> str:
    """Analyze past solves and generate an optimized workflow for a category.

    Returns the most efficient tool order based on real success data,
    not generic playbooks. Includes timing estimates and common pitfalls.

    :param category: CTF category to optimize (e.g. 'web', 'crypto', 'pwn')
    """
    state = _load_state()

    if not category:
        return "ERROR: Specify a category (web, crypto, stego, forensics, rev, pwn, osint, misc)"

    lines = [
        "=" * 60,
        f"⚡ OPTIMIZED WORKFLOW: {category.upper()}",
        "=" * 60,
        "",
    ]

    # Get category stats
    cat_stats = state.get("category_stats", {}).get(category, {})
    if not cat_stats or cat_stats.get("total", 0) < 1:
        lines.append(f"Not enough data for {category} — solve more challenges first.")
        lines.append(f"Current solves: {cat_stats.get('total', 0)}")
        lines.append("")
        lines.append("Using default playbook for now. After 3+ solves,")
        lines.append("this will generate a data-driven workflow.")
        return "\n".join(lines)

    # 1. Most effective tools (sorted by frequency)
    tool_freq = cat_stats.get("tool_frequency", {})
    ranked = sorted(tool_freq.items(), key=lambda x: -x[1])

    lines.append(f"Based on {cat_stats['total']} solved challenges:")
    lines.append(f"Average tools per solve: {cat_stats['avg_tools']:.1f}")
    lines.append("")

    # 2. Build optimized step order
    lines.append("📋 OPTIMIZED STEP ORDER:")
    lines.append("")

    # Phase 1: Always start with recon/detection
    recon_tools = [t for t, _ in ranked if t in (
        "detect_challenge", "recall_knowledge", "triage_file",
        "file_type", "strings_extract", "http_request", "browser_agent",
    )]
    if recon_tools:
        lines.append("  Phase 1 — Recon (always first):")
        for i, t in enumerate(recon_tools[:3], 1):
            lines.append(f"    {i}. {t} (used {tool_freq[t]}x)")

    # Phase 2: Analysis tools
    analysis_tools = [t for t, _ in ranked if t not in recon_tools and t not in (
        "extract_flags_tool", "remember_challenge",
    )]
    if analysis_tools:
        lines.append("  Phase 2 — Solve:")
        for i, t in enumerate(analysis_tools[:6], 1):
            lines.append(f"    {i}. {t} (used {tool_freq[t]}x)")

    # Phase 3: Always end with extraction
    lines.append("  Phase 3 — Extract & Save:")
    lines.append("    1. extract_flags_tool")
    lines.append("    2. remember_challenge (with problem= and commands=)")
    lines.append("")

    # 3. Fast-path shortcuts for this category
    fps = [(n, d) for n, d in state.get("fast_paths", {}).items()
           if d.get("category") == category]
    if fps:
        lines.append("⚡ KNOWN FAST-PATHS:")
        for name, fp in sorted(fps, key=lambda x: -x[1]["count"]):
            lines.append(f"  {name}: {', '.join(fp['tools'][:4])} (×{fp['count']})")
        lines.append("")

    # 4. Avoidance rules
    avoid = [r for r in state.get("failure_rules", [])
             if r.get("category") == category]
    if avoid:
        lines.append("⚠️ PITFALLS TO AVOID:")
        for r in avoid[:3]:
            lines.append(f"  • {r['condition']}")
        lines.append("")

    # 5. Playbook overrides
    overrides = state.get("playbook_overrides", {}).get(category, [])
    if overrides:
        lines.append("🔄 PROVEN TOOL COMBOS (override default playbook):")
        for ov in overrides[:5]:
            lines.append(f"  {', '.join(ov['tools'][:4])} (×{ov.get('count', 1)})")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
