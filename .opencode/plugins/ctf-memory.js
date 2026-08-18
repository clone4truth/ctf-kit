// CTF Memory plugin — auto-saves memory + generates skills for every CTF session.
//
// What it does:
//  - Detects the CTF platform + category from session text (problem statement,
//    tool output) using ctfkit/flagformats.json (shared with Python).
//  - Records every ctf-tools MCP run per session (tool, args, ok).
//  - When a flag appears in ANY tool output -> writes a solved-challenge
//    memory file, generates a reusable skill, rebuilds memory/_index.md.
//  - Flag detection adapts: detected platform's prefixes first, then all known
//    platforms, then generic flag{}/CTF{} + unknown-prefix braces + flag-XYZ.
//  - On session.idle with runs but no flag -> writes a work-in-progress memory.
//  - On compaction -> injects the memory digest into the continuation context.
//
// No external deps (node:fs/path/os). Runs in opencode's bun runtime.

import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs"
import { join, basename } from "node:path"
import { homedir } from "node:os"

const ROOT = process.cwd()
const MEM_DIR = join(ROOT, "memory")
const INDEX = join(MEM_DIR, "_index.md")
const SKILL_DIRS = [
  join(homedir(), ".agents", "skills"),
  join(homedir(), ".claude", "skills"),
]
const FLAGS_FILE = join(ROOT, "ctfkit", "flagformats.json")
const MCP_TOOL_RE = /^ctf-tools[_.]/ // MCP tools surface as ctf-tools_<name>

const FLAGS = JSON.parse(readFileSync(FLAGS_FILE, "utf8"))

// name -> compiled regex for each platform prefix
const PLATFORM_RE = {}
const ALL_RE = []
for (const p of FLAGS.platforms) {
  for (const prefix of p.prefixes) {
    const re = new RegExp(escapeRe(prefix) + "[^}\\n]{1,200}\\}")
    ALL_RE.push({ name: p.name, re })
    PLATFORM_RE[p.name] = PLATFORM_RE[p.name] ?? re
  }
}
const GENERIC_RE = FLAGS.generic_prefixes.map((prefix) => new RegExp(escapeRe(prefix) + "[^}\\n]{1,200}\\}", "i"))
const UNKNOWN_BRACE_RE = /[A-Za-z0-9_]{2,16}\{[^}\n]{6,200}\}/

// keyword (lowercased) -> platform name, for problem-statement detection
const PLATFORM_KEYWORDS = {}
for (const p of FLAGS.platforms) {
  for (const kw of p.keywords) PLATFORM_KEYWORDS[kw] = p.name
}

// category keywords (lowercased): word -> category
const CATEGORY_KEYWORDS = {
  web: ["sql", "injection", "xss", "ssrf", "csrf", "cookie", "jwt", "api", "php", "login", "deserialization", "lfi", "rce"],
  crypto: ["cipher", "encrypt", "decrypt", "xor", "rsa", "aes", "hash", "vigenere", "caesar", "base64", "rot", "otp", "padding"],
  pwn: ["buffer overflow", "bof", "shellcode", "rop", "ret2", "format string", "heap", "gadget"],
  rev: ["decompile", "disassembl", "assembly", "crackme", "obfuscation", "unpack"],
  forensics: ["pcap", "wireshark", "memory dump", "disk image", "carve", "metadata", "volatility", "exif"],
  stego: ["steganograph", "lsb", "pixels", "qrcode", "embedded"],
  osint: ["geolocat", "social media", "recon", "twitter", "instagram"],
  misc: ["jail", "brainfuck", "esolang", "sanity"],
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function ensureDir(p) {
  mkdirSync(p, { recursive: true })
}

function textOf(output) {
  const o = output?.output
  if (typeof o === "string") return o
  if (o && typeof o === "object") return o.content ?? JSON.stringify(o)
  return ""
}

function argsOf(output) {
  try {
    return JSON.stringify(output?.args ?? {})
  } catch {
    return "{}"
  }
}

function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "").slice(0, 60)
}

function dateStamp() {
  return new Date().toISOString().slice(0, 10)
}

function timeStamp() {
  return new Date().toISOString().slice(11, 19)
}

function detectCtf(text) {
  const t = String(text ?? "").toLowerCase()
  let platform = null
  let best = 0
  for (const [kw, name] of Object.entries(PLATFORM_KEYWORDS)) {
    if (t.includes(kw) && kw.length > best) {
      best = kw.length
      platform = name
    }
  }
  let category = null
  best = 0
  for (const [cat, words] of Object.entries(CATEGORY_KEYWORDS)) {
    for (const w of words) {
      if (t.includes(w) && w.length > best) {
        best = w.length
        category = cat
      }
    }
  }
  return { platform, category }
}

// adaptive flag match: detected platform first, then all known, then generic,
// then ANY flag shape: word{...}, flag: xxx / flag = xxx / FLAG-xxx, hex near "flag"
function matchFlag(text, ctf) {
  const candidates = flagCandidates(text, ctf)
  for (const f of candidates) {
    if (f.startsWith("flag") || f.startsWith("FLAG") || f.includes("{") || f.length >= 12) return f
  }
  return candidates[0] ?? null
}

function flagCandidates(text, ctf) {
  const out = []
  if (ctf?.platform && PLATFORM_RE[ctf.platform]) {
    out.push(...(text.match(new RegExp(PLATFORM_RE[ctf.platform].source, "g")) ?? []))
  }
  for (const { re } of ALL_RE) {
    out.push(...(text.match(new RegExp(re.source, "g")) ?? []))
  }
  for (const re of GENERIC_RE) {
    out.push(...(text.match(new RegExp(re.source, "gi")) ?? []))
  }
  out.push(...(text.match(new RegExp(UNKNOWN_BRACE_RE.source, "g")) ?? []))
  out.push(...(text.match(/flag[^\w]?[=:\-]?[^\w]?[A-Za-z0-9_\-+./=]{6,200}/gi) ?? []))
  const hexNear = text.match(/flag.{0,300}?([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})/i)
  if (hexNear) out.push(hexNear[1])
  return [...new Set(out)]
}

function techniqueFromRuns(runs) {
  const byTool = {}
  for (const r of runs) byTool[r.tool] = (byTool[r.tool] ?? 0) + 1
  const top = Object.entries(byTool).sort((a, b) => b[1] - a[1])
  return top.length ? top[0][0] : "analysis"
}

function rebuildIndex() {
  if (!existsSync(MEM_DIR)) return
  const files = readdirSync(MEM_DIR).filter((f) => f.endsWith(".md") && f !== "_index.md").sort().reverse()
  const lines = [
    "# CTF Memory Index",
    "",
    "Auto-maintained by the ctf-memory plugin. Newest first. One entry per challenge.",
    "Before starting a challenge: run `python scripts/recall.py <problem keywords>`.",
    "",
  ]
  for (const f of files) {
    const raw = readFileSync(join(MEM_DIR, f), "utf8").split("\n")
    const title = (raw.find((l) => l.startsWith("# ")) ?? `# ${f}`).slice(2)
    const get = (k) => raw.find((l) => l.ltrim?.startsWith(k))?.split(":", 1)[1]?.trim?.() ?? ""
    const status = get("status:") || "wip"
    const platform = get("platform:")
    const tools = get("tools:")
    const flag = get("flag:")
    lines.push(`- [${status.toUpperCase()}] **${title}** — ${f}${platform ? ` — ${platform}` : ""}${tools ? ` — tools: ${tools}` : ""}${flag && flag !== "-" ? ` — ${flag}` : ""}`)
  }
  writeFileSync(INDEX, lines.join("\n") + "\n")
}

function writeMemory({ sessionID, title, status, runs, flag, snippet, ctf }) {
  ensureDir(MEM_DIR)
  const stamp = `${dateStamp()}_${slug(title || techniqueFromRuns(runs))}`
  let file = join(MEM_DIR, `${stamp}.md`)
  let i = 1
  while (existsSync(file)) {
    file = join(MEM_DIR, `${stamp}_${i++}.md`)
  }
  const body = [
    `# ${title || "CTF challenge"}`,
    "",
    `- session: ${sessionID}`,
    `- date: ${dateStamp()}`,
    `- status: ${status}`,
    ...(ctf?.platform ? [`- platform: ${ctf.platform}`] : []),
    ...(ctf?.category ? [`- category: ${ctf.category}`] : []),
    `- tools: ${runs.map((r) => r.tool).join(", ") || "-"}`,
    ...(flag ? [`- flag: ${flag}`] : []),
    "",
    "## Approach",
    "",
    ...runs.map((r) => `- \`${r.tool}\` ${r.args ? `(${r.args})` : ""} → ${r.ok ? "ok" : "failed"}`),
    "",
    ...(flag ? ["## Result", "", `Flag recovered: \`${flag}\``, ""] : []),
    ...(snippet ? ["## Evidence snippet", "", "```", snippet.slice(0, 800), "```", ""] : []),
    "## What worked / lessons",
    "",
    "_(auto-captured; refine next session)_",
    "",
  ].join("\n")
  writeFileSync(file, body)
  rebuildIndex()
  return file
}

function writeSkill(technique, runs, flag, memoryFile, ctf) {
  // skill name includes category + technique so recall matches the right lab type
  const name = `ctf-${slug(ctf?.category || "misc")}-${slug(technique)}`
  const desc = `CTF technique: ${technique}${ctf?.category ? ` (category: ${ctf.category})` : ""}. Use when a challenge involves ${runs.map((r) => r.tool).join(", ")} or similar analysis${ctf?.platform ? `, especially ${ctf.platform}` : ""}.`
  const body = `---
name: ${name}
description: ${desc}
---

# ${technique}

Reusable technique auto-extracted from a solved CTF challenge (${memoryFile}).

## Context

- Platform: ${ctf?.platform ?? "unknown"}
- Category: ${ctf?.category ?? "unknown"}

## Tools that worked

${runs.map((r) => `- \`${r.tool}\` ${r.args ? `(${r.args})` : ""}`).join("\n")}

## Steps

1. Identify the category from the problem statement.
2. Run the tools above via the ctf-tools MCP server or \`python -c "import ctfkit.modules; from ctfkit.registry import run_tool; print(run_tool('${runs[0]?.tool}', {...}))"\`.
3. Validate the recovered text — flags look like \`${(ctf?.platform && PLATFORM_RE[ctf.platform]) || "flag"}{...}\` for ${ctf?.platform ?? "the detected platform"}.

## Check the memory

Full details: \`memory/${basename(memoryFile)}\`
`
  for (const dir of SKILL_DIRS) {
    const target = join(dir, name, "SKILL.md")
    if (existsSync(target)) continue // first-wins; avoid churn
    ensureDir(join(dir, name))
    writeFileSync(target, body)
  }
}

export const CtfMemory = async ({ client, $ }) => {
  const runsBySession = new Map()
  const solvedBySession = new Map()
  const ctfBySession = new Map()

  const recordRun = (sessionID, tool, args, ok) => {
    if (!runsBySession.has(sessionID)) runsBySession.set(sessionID, [])
    runsBySession.get(sessionID).push({ ts: timeStamp(), tool, args, ok })
  }

  const ctfFor = (sessionID) => ctfBySession.get(sessionID) ?? { platform: null, category: null }

  const saveSolved = async (sessionID, flag, snippet, runs) => {
    if (solvedBySession.get(sessionID)) return
    solvedBySession.set(sessionID, true)
    const technique = techniqueFromRuns(runs)
    const ctf = ctfFor(sessionID)
    const file = writeMemory({ sessionID, title: `Solved: ${technique}`, status: "solved", runs, flag, snippet, ctf })
    writeSkill(technique, runs, flag, file, ctf)
    try {
      // auto writeup/POC per category (scripts/writeup.py)
      await $({ cwd: ROOT })`python scripts/writeup.py --memory ${file}`
    } catch (e) {
      try { await client.app.log({ body: { service: "ctf-memory", level: "warn", message: `writeup failed: ${e.message}` } }) } catch {}
    }
    try {
      await client.app.log({ body: { service: "ctf-memory", level: "info", message: `flag saved: ${flag}`, extra: { file, platform: ctf.platform } } })
    } catch {}
  }

  return {
    "tool.execute.after": async (input, output) => {
      const { tool, sessionID } = input
      if (!sessionID) return
      const isMCP = MCP_TOOL_RE.test(tool)
      if (isMCP) recordRun(sessionID, tool.replace(MCP_TOOL_RE, ""), argsOf(output), !output?.output?.startsWith?.("ERROR"))
      const text = textOf(output)
      if (text) {
        const detected = detectCtf(text)
        if (detected.platform || detected.category) {
          const cur = ctfFor(sessionID)
          ctfBySession.set(sessionID, {
            platform: detected.platform ?? cur.platform,
            category: detected.category ?? cur.category,
          })
        }
        const flag = matchFlag(text, ctfFor(sessionID))
        if (flag) {
          const runs = runsBySession.get(sessionID) ?? []
          if (!runs.length && isMCP) recordRun(sessionID, tool.replace(MCP_TOOL_RE, ""), argsOf(output), true)
          await saveSolved(sessionID, flag, text, runsBySession.get(sessionID) ?? [])
        }
      }
    },

    event: async ({ event }) => {
      const props = event?.properties ?? {}
      const sessionID = props.sessionID ?? props.session?.id ?? "default"
      if (event.type.startsWith("message.") && (props.info || props.part)) {
        const text = JSON.stringify(props)
        const detected = detectCtf(text)
        if (detected.platform || detected.category) {
          const cur = ctfFor(sessionID)
          ctfBySession.set(sessionID, {
            platform: detected.platform ?? cur.platform,
            category: detected.category ?? cur.category,
          })
        }
      }
      if (event.type !== "session.idle") return
      const runs = runsBySession.get(sessionID)
      if (runs?.length && !solvedBySession.get(sessionID)) {
        const technique = techniqueFromRuns(runs)
        writeMemory({ sessionID, title: `WIP: ${technique}`, status: "wip", runs, ctf: ctfFor(sessionID) })
      }
    },

    "experimental.session.compacting": async (_input, output) => {
      let digest = []
      try {
        if (existsSync(INDEX)) digest = readFileSync(INDEX, "utf8").split("\n").filter((l) => l.startsWith("- [")).slice(0, 8)
      } catch {}
      if (digest.length) {
        output.context.push(`## CTF memory (auto)\n${digest.join("\n")}\nFull index: memory/_index.md`)
      }
    },
  }
}

export default CtfMemory