/* =========================================================
   CTF KIT — PRO CYBERPUNK APPLICATION LOGIC
   ========================================================= */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const CATEGORY_META = {
  all: { icon: "✨", label: "All Tools", desc: "Browse and execute 90 competitive tools across cryptography, forensics, steganography, web, and binary exploitation." },
  encoding: { icon: "🔤", label: "Encoding", desc: "Multi-layer recursive unpackers, Zero-Width Unicode stego, Base45/91, Morse, Brainfuck, Hex, URL & HTML.", tags: ["chain", "zero_width", "base", "morse", "brainfuck"] },
  crypto: { icon: "🔐", label: "Crypto", desc: "Attacks on RSA (Wiener, Fermat, Hastad, Common Modulus), AES CBC bitflip, XOR crib drag, LCG solver, and classic ciphers.", tags: ["rsa", "xor", "aes", "hash", "lcg", "vigenere", "caesar"] },
  stego: { icon: "🖼️", label: "Stego", desc: "PNG IHDR CRC dimension recovery, WAV PCM audio LSB, DTMF tone decoding, image bit planes, and frame diffs.", tags: ["png", "ihdr", "audio", "wav", "dtmf", "lsb", "gif"] },
  forensics: { icon: "🔍", label: "Forensics", desc: "Universal PCAP/PCAPNG network extractors, DNS exfiltration reassembly, USB HID keystroke parsing, pseudo-ZIP repair, and carving.", tags: ["pcap", "dns", "usb", "zip", "carve", "zlib", "exif"] },
  web: { icon: "🌐", label: "Web", desc: "SSTI RCE generators (Jinja2, Twig, SpEL), reverse shells, PHP filter wrappers, SSRF obfuscators, and JWT key confusion.", tags: ["ssti", "shell", "jwt", "ssrf", "php", "sql"] },
  rev: { icon: "⚙️", label: "Rev", desc: "Windows PE header & mitigation analysis, Linux ELF structure inspection, and Python PYC magic bytecode verifiers.", tags: ["pe", "elf", "pyc", "disasm"] },
  pwn: { icon: "💥", label: "Pwn", desc: "Format string write calculator, pwntools template generators, multi-arch shellcode repository, checksec, and De Bruijn patterns.", tags: ["fmtstr", "pwn_template", "shellcode", "checksec", "rop", "debruijn"] },
  osint: { icon: "🛰️", label: "OSINT", desc: "DNS reconnaissance, reverse IP lookups, and SSL Certificate Transparency subdomain discovery.", tags: ["dns", "subdomain", "ip"] },
  misc: { icon: "⚡", label: "Master & Misc", desc: "Instant automated challenge triage, category auto-detection, and universal flag extractors.", tags: ["triage", "detect", "flag"] }
};

const state = {
  tools: [],
  categories: [],
  activeCat: "all",
  activeTag: null,
  activeTool: null,
  search: "",
  running: 0,
  autoscroll: true,
  logFilter: "all",
  lastOutput: ""
};

/* ---------- Initialization ---------- */
async function init() {
  setupKeybinds();
  setupTriageModal();
  setupLogFilters();
  connectLogs();
  updateContentHeader();
  
  // Show skeleton loading cards
  renderLoadingSkeleton();
  
  try {
    const res = await fetch("/api/tools");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.tools = data.tools || [];
    state.categories = data.categories || [];

    const pillTools = $("#pill-tools");
    if (pillTools) pillTools.textContent = `${state.tools.length} Tools`;
    const sideTotal = $("#sidebar-total");
    if (sideTotal) sideTotal.textContent = state.tools.length;

    renderSidebar();
    renderGrid();
  } catch (err) {
    const grid = $("#toolgrid");
    if (grid) {
      grid.innerHTML = `
        <div class="empty-state">
          <div style="color:var(--accent-rose);font-weight:700;margin-bottom:8px;">⚠️ Failed to auto-load tools (${escapeHtml(err.message)})</div>
          <button class="mini-action-btn" onclick="init()" style="margin-top:10px;">🔄 Retry Auto-Load</button>
        </div>`;
    }
    toast(`Failed to load tools: ${err.message}`, "err");
  }
}

function renderLoadingSkeleton() {
  const grid = $("#toolgrid");
  if (!grid) return;
  let cards = "";
  for (let i = 0; i < 9; i++) {
    cards += `
      <div class="tool-card skeleton" style="opacity:0.6;pointer-events:none;">
        <div class="tool-card-head">
          <span class="cat-pill" style="background:rgba(255,255,255,0.06);color:transparent;">LOADING</span>
        </div>
        <h3 style="background:rgba(255,255,255,0.08);color:transparent;border-radius:4px;width:70%;">Loading tool...</h3>
        <p class="desc" style="background:rgba(255,255,255,0.04);color:transparent;border-radius:4px;margin-top:8px;">Analyzing competitive toolkit definitions...</p>
      </div>`;
  }
  grid.innerHTML = cards;
}

/* ---------- Keyboard Shortcuts ---------- */
function setupKeybinds() {
  window.addEventListener("keydown", (e) => {
    // Focus search with '/' or 'Ctrl+K'
    if ((e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") ||
        (e.ctrlKey && e.key.toLowerCase() === "k")) {
      e.preventDefault();
      $("#global-search").focus();
    }
    // Close modal / detail with Escape
    if (e.key === "Escape") {
      closeTriageModal();
      if (!$("#detail").classList.contains("hidden")) closeDetail();
    }
    // Run tool with Ctrl+Enter when detail view is active
    if (e.ctrlKey && e.key === "Enter" && state.activeTool && !$("#detail").classList.contains("hidden")) {
      e.preventDefault();
      const runBtn = $("#btn-run-tool");
      if (runBtn && !runBtn.disabled) runBtn.click();
    }
  });

  $("#global-search").addEventListener("input", (e) => {
    state.search = e.target.value.trim().toLowerCase();
    renderGrid();
  });
}

/* ---------- Sidebar Rendering ---------- */
function renderSidebar() {
  const nav = $("#catnav");
  nav.innerHTML = "";

  const counts = { all: state.tools.length };
  state.tools.forEach(t => {
    counts[t.category] = (counts[t.category] || 0) + 1;
  });

  const catList = ["all", "encoding", "crypto", "stego", "forensics", "web", "rev", "pwn", "osint", "misc"];

  catList.forEach(cat => {
    const meta = CATEGORY_META[cat] || { icon: "📦", label: cat };
    const count = counts[cat] || 0;
    if (cat !== "all" && count === 0) return;

    const item = document.createElement("div");
    item.className = `cat-item ${state.activeCat === cat ? "active" : ""}`;
    item.innerHTML = `
      <div class="cat-item-left">
        <span class="cat-icon">${meta.icon}</span>
        <span class="cat-label">${meta.label}</span>
      </div>
      <span class="cat-count">${count}</span>
    `;

    item.onclick = () => {
      state.activeCat = cat;
      state.activeTag = null;
      $$(".cat-item").forEach(el => el.classList.remove("active"));
      item.classList.add("active");
      updateContentHeader();
      renderGrid();
      closeDetail();
    };

    nav.appendChild(item);
  });
}

/* ---------- Header & Tag Filter Rendering ---------- */
function updateContentHeader() {
  const meta = CATEGORY_META[state.activeCat] || { label: state.activeCat, desc: "" };
  $("#active-cat-title").textContent = meta.label;
  $("#active-cat-desc").textContent = meta.desc || "Competitive CTF tools.";

  const tagWrap = $("#quick-tags");
  tagWrap.innerHTML = "";

  if (meta.tags && meta.tags.length) {
    meta.tags.forEach(tag => {
      const btn = document.createElement("button");
      btn.className = `tag-btn ${state.activeTag === tag ? "active" : ""}`;
      btn.textContent = `#${tag}`;
      btn.onclick = () => {
        state.activeTag = state.activeTag === tag ? null : tag;
        updateContentHeader();
        renderGrid();
      };
      tagWrap.appendChild(btn);
    });
  }
}

/* ---------- Tool Grid Rendering ---------- */
function renderGrid() {
  const grid = $("#toolgrid");
  grid.innerHTML = "";

  let list = state.tools;

  if (state.activeCat !== "all") {
    list = list.filter(t => t.category === state.activeCat);
  }

  if (state.activeTag) {
    list = list.filter(t => t.name.toLowerCase().includes(state.activeTag) || (t.summary || "").toLowerCase().includes(state.activeTag));
  }

  if (state.search) {
    const q = state.search;
    list = list.filter(t =>
      t.name.toLowerCase().includes(q) ||
      (t.summary || "").toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q)
    );
  }

  if (!list.length) {
    grid.innerHTML = `<div class="empty-state">⚡ No tools found matching query. Try another search keyword.</div>`;
    return;
  }

  list.forEach(tool => {
    const card = document.createElement("div");
    card.className = "tool-card";
    const paramCount = tool.parameters ? tool.parameters.length : 0;

    card.innerHTML = `
      <div class="tool-card-head">
        <span class="cat-pill ${tool.category}">${tool.category}</span>
        <span class="tool-params-count">${paramCount} param${paramCount === 1 ? '' : 's'}</span>
      </div>
      <h3>${tool.name}</h3>
      <p class="desc">${escapeHtml(tool.summary || "No description provided.")}</p>
      <div class="tool-card-footer">
        <span class="card-run-btn">Open Tool ➔</span>
      </div>
    `;

    card.onclick = () => openDetail(tool);
    grid.appendChild(card);
  });
}

/* ---------- Detail & Execution Workspace ---------- */
function openDetail(tool) {
  state.activeTool = tool;
  const detail = $("#detail");
  const grid = $("#toolgrid");
  const header = $("#content-header");

  grid.classList.add("hidden");
  header.classList.add("hidden");
  detail.classList.remove("hidden");

  detail.innerHTML = `
    <div class="detail-head">
      <div class="detail-title-wrap">
        <div style="display:flex;align-items:center;gap:10px;">
          <span class="cat-pill ${tool.category}">${tool.category}</span>
          <h2>${tool.name}</h2>
        </div>
        <p class="detail-doc">${escapeHtml(tool.summary || "")}</p>
      </div>
      <button class="close-btn" id="btn-close-detail" title="Close Workspace (Esc)">✕</button>
    </div>

    <div class="studio-grid">
      <!-- Input Section -->
      <div class="input-section">
        <div class="section-label">⚙️ Execution Parameters</div>
        <form id="tool-form" class="form-grid"></form>
        <button id="btn-run-tool" class="btn-run">
          <span>⚡</span> RUN TOOL <span style="font-size:11px;opacity:0.8;font-weight:400;">(Ctrl+Enter)</span>
        </button>
      </div>

      <!-- Output Studio Section -->
      <div class="output-section">
        <div class="section-label">📊 Result & Inspection Studio</div>
        <div class="output-panel">
          <div class="output-head">
            <span class="output-meta" id="output-meta">Ready to execute</span>
            <div class="output-actions">
              <button class="mini-action-btn" id="btn-copy-out" title="Copy Output to Clipboard">📋 Copy</button>
              <button class="mini-action-btn" id="btn-save-out" title="Download Output">💾 Download</button>
            </div>
          </div>
          <div id="flag-detector-bar" class="flag-banner hidden"></div>
          <div class="output-tabs">
            <button class="output-tab active" data-tab="formatted">Output</button>
            <button class="output-tab" data-tab="hex">Hex View</button>
            <button class="output-tab" data-tab="ascii">ASCII Clean</button>
          </div>
          <pre class="output-body" id="output-body">Output will appear here after execution...</pre>
        </div>
      </div>
    </div>
  `;

  $("#btn-close-detail").onclick = closeDetail;

  // Build form fields
  buildForm(tool);

  // Bind Run button
  $("#btn-run-tool").onclick = () => runTool(tool);

  // Bind output copy and download
  $("#btn-copy-out").onclick = () => {
    if (!state.lastOutput) return;
    navigator.clipboard.writeText(state.lastOutput);
    toast("✔ Output copied to clipboard!", "ok");
  };

  $("#btn-save-out").onclick = () => {
    if (!state.lastOutput) return;
    const blob = new Blob([state.lastOutput], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${tool.name}_output.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast("✔ Saved output file", "ok");
  };

  // Bind tabs
  $$(".output-tab").forEach(tab => {
    tab.onclick = () => {
      $$(".output-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      renderOutputTab(tab.dataset.tab);
    };
  });
}

function closeDetail() {
  state.activeTool = null;
  $("#detail").classList.add("hidden");
  $("#toolgrid").classList.remove("hidden");
  $("#content-header").classList.remove("hidden");
}

/* ---------- Form Builder ---------- */
function buildForm(tool) {
  const form = $("#tool-form");
  form.innerHTML = "";

  (tool.parameters || []).forEach(p => {
    const field = document.createElement("div");
    field.className = "field";

    const label = document.createElement("label");
    label.innerHTML = `<span>${p.name} ${p.required ? '<span class="req">*</span>' : ''}</span><span class="hint">${escapeHtml(p.doc || p.type)}</span>`;
    field.appendChild(label);

    let input;

    if (p.type === "bool" || p.type === "boolean") {
      field.className = "field checkbox-field";
      input = document.createElement("input");
      input.type = "checkbox";
      input.dataset.field = p.name;
      input.checked = Boolean(p.default);
      field.appendChild(input);
      form.appendChild(field);
      return;
    }

    if (p.type === "int" || p.type === "float" || p.type === "number") {
      input = document.createElement("input");
      input.type = "number";
      input.dataset.field = p.name;
      if (p.default !== null && p.default !== undefined) input.value = p.default;
      field.appendChild(input);
      form.appendChild(field);
      return;
    }

    // For file path parameters, create text input with Browse & Drop button
    if (/path|file|image|pcap|zip|wav|gif|blob/i.test(p.name)) {
      const fileWrap = document.createElement("div");
      fileWrap.className = "file-upload-wrap";

      input = document.createElement("input");
      input.type = "text";
      input.dataset.field = p.name;
      if (p.default !== null && p.default !== undefined) input.value = p.default;
      input.placeholder = "Path or drop file here...";

      const filePicker = document.createElement("input");
      filePicker.type = "file";
      filePicker.style.display = "none";

      const uploadBtn = document.createElement("button");
      uploadBtn.type = "button";
      uploadBtn.className = "upload-btn";
      uploadBtn.innerHTML = `<span>📁</span> Browse File`;
      uploadBtn.onclick = () => filePicker.click();

      filePicker.onchange = async () => {
        if (!filePicker.files.length) return;
        uploadFileToField(filePicker.files[0], input, uploadBtn);
      };

      // Drag & drop on text field
      input.ondragover = (e) => { e.preventDefault(); input.style.borderColor = "var(--accent-cyan)"; };
      input.ondragleave = () => { input.style.borderColor = ""; };
      input.ondrop = (e) => {
        e.preventDefault();
        input.style.borderColor = "";
        if (e.dataTransfer.files.length) {
          uploadFileToField(e.dataTransfer.files[0], input, uploadBtn);
        }
      };

      fileWrap.append(input, uploadBtn, filePicker);
      field.appendChild(fileWrap);
      form.appendChild(field);
      return;
    }

    // For long strings / payloads / ciphertexts, use textarea
    if (/text|data|code|payload|ciphertext|key|original|states|ciphertexts|moduli/i.test(p.name)) {
      input = document.createElement("textarea");
      input.dataset.field = p.name;
      if (p.default !== null && p.default !== undefined) input.value = p.default;
      input.placeholder = `Enter ${p.name}...`;
      field.appendChild(input);
      form.appendChild(field);
      return;
    }

    input = document.createElement("input");
    input.type = "text";
    input.dataset.field = p.name;
    if (p.default !== null && p.default !== undefined) input.value = p.default;
    field.appendChild(input);
    form.appendChild(field);
  });
}

async function uploadFileToField(file, inputElement, btnElement) {
  const fd = new FormData();
  fd.append("file", file);
  btnElement.innerHTML = `<span>⏳</span> Uploading...`;
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await res.json();
    if (data.ok) {
      inputElement.value = data.path;
      btnElement.innerHTML = `<span>✔</span> ${data.filename} (${Math.round(data.size / 1024)} KB)`;
      toast(`Uploaded: ${data.filename}`, "ok");
    }
  } catch (err) {
    btnElement.innerHTML = `<span>📁</span> Browse File`;
    toast(`Upload failed: ${err.message}`, "err");
  }
}

/* ---------- Tool Execution ---------- */
async function runTool(tool) {
  const form = $("#tool-form");
  const args = {};

  (tool.parameters || []).forEach(p => {
    const el = form.querySelector(`[data-field="${p.name}"]`);
    if (!el) return;
    if (el.type === "checkbox") {
      args[p.name] = el.checked;
    } else if (el.type === "number") {
      args[p.name] = el.value === "" ? (p.default ?? 0) : Number(el.value);
    } else {
      args[p.name] = el.value;
    }
  });

  const runBtn = $("#btn-run-tool");
  const outBody = $("#output-body");
  const outMeta = $("#output-meta");
  const flagBar = $("#flag-detector-bar");

  runBtn.disabled = true;
  runBtn.innerHTML = `<span class="spinner-dot"></span> EXECUTING...`;
  outMeta.textContent = "Running operation on engine...";
  flagBar.classList.add("hidden");

  const startT = performance.now();
  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: tool.name, arguments: args })
    });

    const data = await res.json();
    const duration = Math.round(performance.now() - startT);

    if (data.ok) {
      state.lastOutput = data.result || "";
      outMeta.textContent = `Completed in ${duration}ms · ${state.lastOutput.length} characters`;
      renderOutputTab("formatted");
      detectFlagsInOutput(state.lastOutput);
      toast(`✔ ${tool.name} executed successfully`, "ok");
    } else {
      state.lastOutput = `[ERROR]: ${data.error || "Unknown execution failure."}`;
      outMeta.textContent = `Failed in ${duration}ms`;
      outBody.textContent = state.lastOutput;
      toast(`Execution error: ${data.error}`, "err");
    }
  } catch (err) {
    state.lastOutput = `[NETWORK ERROR]: ${err.message}`;
    outMeta.textContent = "Network error";
    outBody.textContent = state.lastOutput;
    toast(`Network request failed: ${err.message}`, "err");
  } finally {
    runBtn.disabled = false;
    runBtn.innerHTML = `<span>⚡</span> RUN TOOL <span style="font-size:11px;opacity:0.8;font-weight:400;">(Ctrl+Enter)</span>`;
  }
}

/* ---------- Output Tab Views ---------- */
function renderOutputTab(tab) {
  const body = $("#output-body");
  const text = state.lastOutput || "";

  if (tab === "formatted") {
    body.textContent = text;
  } else if (tab === "hex") {
    body.textContent = formatHexDump(text);
  } else if (tab === "ascii") {
    body.textContent = text.split("").map(c => (c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127) ? c : ".").join("");
  }
}

function formatHexDump(text) {
  const bytes = new TextEncoder().encode(text);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = Array.from(bytes.slice(i, i + 16));
    const hex = chunk.map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(48, " ");
    const ascii = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    const offset = i.toString(16).padStart(8, "0");
    lines.push(`${offset}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

/* ---------- Automatic Flag Detection ---------- */
function detectFlagsInOutput(text) {
  const flagBar = $("#flag-detector-bar");
  const match = text.match(/([a-zA-Z0-9_\-]+{[^}\n\r]+}|flag:[^\s\n\r]+|FLAG-[^\s\n\r]+)/i);
  if (match) {
    const flagVal = match[0];
    flagBar.innerHTML = `
      <div class="flag-banner-left">
        <span>🏆 FLAG DETECTED:</span>
        <span class="flag-string">${escapeHtml(flagVal)}</span>
      </div>
      <button class="flag-copy-btn" id="btn-copy-flag">Copy Flag</button>
    `;
    flagBar.classList.remove("hidden");
    $("#btn-copy-flag").onclick = () => {
      navigator.clipboard.writeText(flagVal);
      toast("🏆 Flag copied to clipboard!", "ok");
    };
  } else {
    flagBar.classList.add("hidden");
  }
}

/* ---------- Quick Auto-Triage Modal ---------- */
function setupTriageModal() {
  const modal = $("#triage-modal");
  const btnOpen = $("#btn-triage-modal");
  const btnClose = $("#btn-close-triage");
  const dropzone = $("#triage-dropzone");
  const fileInput = $("#triage-file-input");

  btnOpen.onclick = () => modal.classList.remove("hidden");
  btnClose.onclick = closeTriageModal;
  modal.onclick = (e) => { if (e.target === modal) closeTriageModal(); };

  dropzone.onclick = () => fileInput.click();
  fileInput.onchange = () => {
    if (fileInput.files.length) handleTriageFile(fileInput.files[0]);
  };

  dropzone.ondragover = (e) => { e.preventDefault(); dropzone.style.borderColor = "var(--accent-emerald)"; };
  dropzone.ondragleave = () => { dropzone.style.borderColor = ""; };
  dropzone.ondrop = (e) => {
    e.preventDefault();
    dropzone.style.borderColor = "";
    if (e.dataTransfer.files.length) handleTriageFile(e.dataTransfer.files[0]);
  };
}

function closeTriageModal() {
  $("#triage-modal").classList.add("hidden");
  $("#triage-status").classList.add("hidden");
}

async function handleTriageFile(file) {
  const status = $("#triage-status");
  status.classList.remove("hidden");
  status.innerHTML = `<span class="spinner-dot"></span> Uploading & triaging <strong>${escapeHtml(file.name)}</strong>...`;

  const fd = new FormData();
  fd.append("file", file);

  try {
    const upRes = await fetch("/api/upload", { method: "POST", body: fd });
    const upData = await upRes.json();
    if (!upData.ok) throw new Error(upData.error || "Upload failed");

    // Locate triage_file tool and open with this path
    const triageTool = state.tools.find(t => t.name === "triage_file");
    if (triageTool) {
      closeTriageModal();
      openDetail(triageTool);
      const input = $(`#tool-form [data-field="path"]`);
      if (input) input.value = upData.path;
      // Auto-run triage
      runTool(triageTool);
    }
  } catch (err) {
    status.innerHTML = `[ERROR]: ${err.message}`;
  }
}

/* ---------- Live Log Console (SSE) ---------- */
function connectLogs() {
  const es = new EventSource("/api/logs");
  const body = $("#logbody");

  es.onmessage = (ev) => {
    if (!ev.data.trim()) return;
    try {
      const r = JSON.parse(ev.data);
      addLogLine(body, r);
    } catch (e) {}
  };

  $("#btn-clear-log").onclick = () => { body.innerHTML = ""; };
  $("#btn-toggle-log").onclick = () => {
    const dock = $("#logdock");
    dock.classList.toggle("collapsed");
    $("#btn-toggle-log").textContent = dock.classList.contains("collapsed") ? "▢" : "_";
  };
  $("#btn-autoscroll").onclick = () => {
    state.autoscroll = !state.autoscroll;
    const btn = $("#btn-autoscroll");
    btn.textContent = `Scroll: ${state.autoscroll ? 'ON' : 'OFF'}`;
    btn.classList.toggle("active", state.autoscroll);
  };
}

function setupLogFilters() {
  $$(".log-filter-btn").forEach(btn => {
    btn.onclick = () => {
      $$(".log-filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.logFilter = btn.dataset.filter;
      filterLogs();
    };
  });
}

function filterLogs() {
  const lines = $$(".logline");
  lines.forEach(line => {
    if (state.logFilter === "all") {
      line.style.display = "";
    } else if (state.logFilter === "INFO") {
      line.style.display = line.classList.contains("lvl-INFO") ? "" : "none";
    } else if (state.logFilter === "ERROR") {
      line.style.display = line.classList.contains("lvl-ERROR") ? "" : "none";
    }
  });
}

function addLogLine(body, r) {
  const line = document.createElement("div");
  line.className = `logline lvl-${r.level}`;
  line.dataset.level = r.level;

  let msg = r.msg;
  let chip = "";
  const catMatch = r.msg.match(/^\[(\w+)\]\s+(.+)$/);
  if (catMatch) {
    chip = `<span class="chip">${catMatch[1]}</span>`;
    msg = catMatch[2];
  }

  if (/running:/.test(msg)) {
    line.classList.add("running");
    const nameMatch = msg.match(/^(\w+)\s+running:/);
    if (nameMatch) setRunning(nameMatch[1]);
  } else if (/done in/.test(msg)) {
    setRunning(null);
  }

  line.innerHTML = `${chip}<span class="ts">${r.ts}</span><span>${escapeHtml(msg)}</span>`;

  if (state.logFilter !== "all" && state.logFilter !== r.level) {
    line.style.display = "none";
  }

  body.appendChild(line);
  while (body.children.length > 500) body.removeChild(body.firstChild);

  if (state.autoscroll && !$("#logdock").classList.contains("collapsed")) {
    body.scrollTop = body.scrollHeight;
  }
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

/* ---------- Toast Notifications ---------- */
function toast(msg, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${kind === 'ok' ? '⚡' : '⚠️'}</span><span>${escapeHtml(msg)}</span>`;
  $("#toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 260);
  }, 2800);
}

function escapeHtml(s) {
  if (typeof s !== "string") return String(s);
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}