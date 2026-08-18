/* CTF KIT — frontend logic: categories, grid, dynamic forms, animated run, SSE logs, toasts, history. */
"use strict";

const state = {
  categories: {},
  activeCat: null,
  search: "",
  currentTool: null,
  running: 0,
  history: JSON.parse(localStorage.getItem("ctfkit_history") || "[]"),
};

const $ = (sel) => document.querySelector(sel);

/* ---------- init ---------- */
async function init() {
  const res = await fetch("/api/tools");
  const data = await res.json();
  state.categories = data.categories;
  $("#pill-tools").textContent = `${data.total} tools`;
  renderCatnav();
  renderGrid();
  connectLogs();
}

/* ---------- sidebar ---------- */
function renderCatnav() {
  const nav = $("#catnav");
  nav.innerHTML = "";
  const all = { label: "ALL CATEGORIES", tools: Object.values(state.categories).flatMap(c => c.tools) };
  const cats = [{ category: null, ...all }, ...Object.entries(state.categories).map(([k, v]) => ({ category: k, ...v }))];
  cats.forEach((c, i) => {
    const el = document.createElement("div");
    el.className = "cat-item" + (state.activeCat === c.category ? " active" : "");
    el.style.animationDelay = `${i * 0.05}s`;
    el.innerHTML = `<span>${c.label}</span><span class="cat-count">${c.tools.length}</span>`;
    el.onclick = () => {
      state.activeCat = c.category;
      document.querySelectorAll(".cat-item").forEach(x => x.classList.remove("active"));
      el.classList.add("active");
      renderGrid();
    };
    nav.appendChild(el);
  });
}

/* ---------- tool grid ---------- */
function renderGrid() {
  const grid = $("#toolgrid");
  grid.innerHTML = "";
  let tools = Object.values(state.categories).flatMap(c => c.tools);
  if (state.activeCat) tools = tools.filter(t => t.category === state.activeCat);
  if (state.search) {
    const q = state.search.toLowerCase();
    tools = tools.filter(t => t.name.toLowerCase().includes(q) || t.summary.toLowerCase().includes(q));
  }
  if (!tools.length) {
    grid.innerHTML = `<div class="empty-state">no tool matches<span class="cursor">▍</span></div>`;
    return;
  }
  tools.forEach((t, i) => {
    const card = document.createElement("div");
    card.className = "tool-card";
    card.style.animationDelay = `${Math.min(i * 0.03, 0.6)}s`;
    card.innerHTML = `
      <span class="badge ${t.category}">${t.category}</span>
      <h3>${t.name}</h3>
      <div class="desc">${escapeHtml(t.summary)}</div>`;
    card.onclick = () => openDetail(t);
    grid.appendChild(card);
  });
}

/* ---------- detail panel ---------- */
function openDetail(tool) {
  state.currentTool = tool;
  $("#toolgrid").classList.add("hidden");
  const detail = $("#detail");
  detail.classList.remove("hidden");
  const body = document.createElement("div");
  body.className = "detail-body";

  const form = document.createElement("div");
  form.className = "form-grid";
  tool.params.forEach(p => {
    const field = document.createElement("div");
    field.className = "field";
    const label = document.createElement("label");
    label.innerHTML = `${p.name}${p.required ? ' <span class="req">*</span>' : ""}${p.desc ? ` <span class="hint">— ${escapeHtml(p.desc)}</span>` : ""}`;
    field.appendChild(label);
    let input;
    if (p.type === "bool") {
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = !!p.default;
      input.dataset.field = p.name;
    } else if (p.type === "int") {
      input = document.createElement("input");
      input.type = "number";
      input.dataset.field = p.name;
      if (p.default !== null && p.default !== undefined) input.value = p.default;
    } else {
      input = document.createElement("input");
      input.type = "text";
      input.dataset.field = p.name;
      if (p.default !== null && p.default !== undefined) input.value = p.default;
    }
    field.appendChild(input);
    form.appendChild(field);
  });

  const runBtn = document.createElement("button");
  runBtn.className = "btn-run";
  runBtn.innerHTML = `<span class="btn-label">RUN</span>`;
  runBtn.onclick = () => runTool(runBtn);

  const result = document.createElement("div");
  result.className = "result hidden";
  const resultHead = document.createElement("div");
  resultHead.className = "result-head";
  const resultMeta = document.createElement("span");
  const copyBtn = document.createElement("button");
  copyBtn.className = "copy-btn";
  copyBtn.textContent = "copy";
  const tabs = document.createElement("div");
  tabs.className = "result-tabs";
  const resultBody = document.createElement("div");
  resultBody.className = "result-body";
  result.append(resultHead, tabs, resultBody);
  resultHead.append(resultMeta, copyBtn);

  detail.innerHTML = "";
  detail.appendChild(detailHead(tool));
  body.appendChild(form);
  body.appendChild(runBtn);
  body.appendChild(result);
  detail.appendChild(body);

  function runTool(btn) {
    const args = {};
    let missing = false;
    form.querySelectorAll("input[data-field]").forEach(inp => {
      const name = inp.dataset.field;
      const p = tool.params.find(x => x.name === name);
      let val;
      if (p.type === "bool") val = inp.checked;
      else if (p.type === "int") val = inp.value === "" ? (p.default ?? 0) : parseInt(inp.value, 10);
      else val = inp.value;
      if (p.required && (val === "" || val === null || val === undefined)) { missing = true; inp.style.borderColor = "var(--danger)"; }
      else if (val !== "" && val !== null && val !== undefined) args[name] = val;
    });
    if (missing) { toast("Fill required fields (*)", "err"); return; }

    btn.disabled = true;
    btn.classList.add("loading");
    btn.innerHTML = `<span class="spinner"></span><span>PROCESSING</span>`;
    result.classList.add("hidden");

    const start = performance.now();
    fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: tool.name, args }),
    })
      .then(r => r.json())
      .then(data => {
        const ms = Math.round(performance.now() - start);
        showResult(data.result, ms, resultBody, resultMeta, tabs, copyBtn);
        pushHistory(tool.name, args, ms, !data.result.startsWith("ERROR"));
        toast(`✔ ${tool.name} finished in ${data.elapsed_ms}ms`, "ok");
      })
      .catch(err => {
        toast(`✘ ${err.message}`, "err");
        pushHistory(tool.name, args, 0, false);
      })
      .finally(() => {
        btn.disabled = false;
        btn.classList.remove("loading");
        btn.innerHTML = `<span class="btn-label">RUN</span>`;
      });
  }
}

function detailHead(tool) {
  const head = document.createElement("div");
  head.className = "detail-head";
  head.innerHTML = `
    <div>
      <span class="badge ${tool.category}">${tool.category}</span>
      <h2>${tool.name}</h2>
    </div>
    <button class="close" title="close">✕</button>`;
  head.querySelector(".close").onclick = () => {
    $("#detail").classList.add("hidden");
    $("#toolgrid").classList.remove("hidden");
    state.currentTool = null;
  };
  return head;
}

/* ---------- result rendering ---------- */
function showResult(text, ms, body, meta, tabs, copyBtn) {
  const result = body.closest(".result");
  result.classList.remove("hidden");
  meta.textContent = `${ms}ms · ${text.length} chars`;
  tabs.innerHTML = `
    <button class="tab-btn active" data-tab="out">OUTPUT</button>
    <button class="tab-btn" data-tab="hex">HEX</button>
    <button class="tab-btn" data-tab="ascii">ASCII</button>`;
  body.textContent = text;
  tabs.querySelectorAll(".tab-btn").forEach(btn => {
    btn.onclick = () => {
      tabs.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      if (btn.dataset.tab === "out") body.textContent = text;
      else if (btn.dataset.tab === "hex") body.textContent = toHex(text);
      else body.textContent = toAscii(text);
    };
  });
  copyBtn.onclick = () => {
    navigator.clipboard.writeText(body.textContent);
    toast("✔ copied to clipboard", "ok");
  };
}

function toHex(s) {
  return Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, "0")).join(" ");
}

function toAscii(s) {
  return s.split("").map(c => (c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127) ? c : ".").join("");
}

/* ---------- history (localStorage) ---------- */
function pushHistory(name, args, ms, ok) {
  state.history.unshift({ t: new Date().toLocaleTimeString(), name, ms, ok });
  state.history = state.history.slice(0, 30);
  localStorage.setItem("ctfkit_history", JSON.stringify(state.history));
}

/* ---------- log console (SSE) ---------- */
function connectLogs() {
  const es = new EventSource("/api/logs");
  const body = $("#logbody");
  es.onmessage = (ev) => {
    if (!ev.data.trim()) return;
    const r = JSON.parse(ev.data);
    addLogLine(body, r);
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
  $("#btn-clear-log").onclick = () => { body.innerHTML = ""; };
  $("#btn-toggle-log").onclick = () => {
    const dock = document.querySelector(".logdock");
    dock.classList.toggle("collapsed");
    $("#btn-toggle-log").textContent = dock.classList.contains("collapsed") ? "▢" : "_";
  };
}

function addLogLine(body, r) {
  const line = document.createElement("div");
  line.className = `logline lvl-${r.level}`;

  const catMatch = r.msg.match(/^\[(\w+)\]\s+(.+)$/);
  let msg = r.msg;
  let chip = "";
  if (catMatch) {
    chip = `<span class="chip">${catMatch[1]}</span>`;
    msg = catMatch[2];
  }

  if (/running:/.test(msg)) {
    line.classList.add("running");
    const nameMatch = msg.match(/^(\w+)\s+running:/);
    if (nameMatch) setRunning(nameMatch[1]);
    line.innerHTML = `<span class="spinner-mini"></span>${chip}<span class="ts">${r.ts}</span>${escapeHtml(msg)}`;
  } else {
    if (/done in/.test(msg)) setRunning(null);
    line.innerHTML = `${chip}<span class="ts">${r.ts}</span><span class="lvl">${r.level}</span>${escapeHtml(msg)}`;
  }

  body.appendChild(line);
  while (body.children.length > 400) body.removeChild(body.firstChild);
  if (!document.querySelector(".logdock.collapsed")) body.scrollTo({ top: body.scrollHeight, behavior: "smooth" });
}

function setRunning(toolName) {
  const pill = $("#pill-running");
  if (toolName) {
    state.running += 1;
    pill.querySelector(".run-name").textContent = toolName;
    pill.classList.remove("hidden");
  } else {
    state.running = Math.max(0, state.running - 1);
    if (state.running === 0) pill.classList.add("hidden");
  }
}

/* ---------- toast ---------- */
function toast(msg, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 300);
  }, 2600);
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------- search ---------- */
$("#search").addEventListener("input", (e) => {
  state.search = e.target.value.trim();
  renderGrid();
});

init();