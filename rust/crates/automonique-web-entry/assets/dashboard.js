// SPDX-License-Identifier: Elastic-2.0

"use strict";

const byId = (id) => document.getElementById(id);
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "—";
const words = (value) => typeof value === "string" ? value.replaceAll("_", " ") : "—";
const yesNo = (value) => value === true ? "YES" : value === false ? "NO" : "—";
const safeMetric = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const statusHistory = [];
let memorySnapshot = null;
let memoryKind = "all";
let memoryQuery = null;
let operationsSnapshot = null;
let ticketFilter = "all";
let lastObservedMs = null;
let lastStatusKey = null;
let lastPulseChangeAt = null;
let chatBusy = false;
let newChatArmed = false;
let newChatTimer = null;
const themeNames = {
  system: "System",
  dark: "Carbon",
  light: "Paper",
  midnight: "Midnight",
  ocean: "Ocean",
  forest: "Forest",
  monokai: "Monokai",
  dracula: "Dracula",
  nord: "Nord",
  sand: "Sand",
  rose: "Rose",
  contrast: "High contrast",
};
const themeColors = {
  dark: "#0b0d10",
  light: "#f7f7f5",
  midnight: "#090a14",
  ocean: "#061116",
  forest: "#0a110d",
  monokai: "#272822",
  dracula: "#282a36",
  nord: "#2e3440",
  sand: "#f5efe5",
  rose: "#faf2f4",
  contrast: "#000000",
};
const themes = Object.keys(themeNames);
const textScaleNames = {
  compact: "Compact",
  standard: "Standard",
  comfortable: "Comfortable",
  large: "Large",
  "extra-large": "Extra large",
};
const textScales = Object.keys(textScaleNames);
const sidebarStates = ["expanded", "collapsed"];
const densityNames = { compact: "Compact", comfortable: "Comfortable", spacious: "Spacious" };
const densities = Object.keys(densityNames);
const motionModes = ["full", "reduce"];
const startupViews = ["chat", "overview", "operations", "tickets"];

function storedPreference(key, allowed, fallback) {
  try {
    const value = window.localStorage.getItem(key);
    return allowed.includes(value) ? value : fallback;
  } catch (_error) {
    return fallback;
  }
}

function savePreference(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch (_error) {
    // Private browsing and hardened storage policies may refuse persistence.
  }
}

function resolvedTheme(theme) {
  return theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : theme;
}

function applyTheme(theme, persist = true) {
  if (!themes.includes(theme)) theme = "system";
  document.documentElement.dataset.theme = theme;
  byId("theme-select").value = theme;
  const resolved = resolvedTheme(theme);
  byId("theme-cycle").dataset.theme = theme;
  byId("theme-cycle").setAttribute("aria-label", `Appearance. Current theme: ${themeNames[theme]}`);
  byId("theme-cycle").title = `Appearance · ${themeNames[theme]}`;
  byId("sidebar-theme-name").textContent = themeNames[theme];
  byId("theme-color").content = themeColors[resolved] || themeColors.dark;
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    const active = button.dataset.themeChoice === theme;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) savePreference("monique-theme", theme);
}

function applyTextScale(scale, persist = true) {
  if (!textScales.includes(scale)) scale = "comfortable";
  document.documentElement.dataset.textScale = scale;
  byId("text-scale-cycle").dataset.scale = scale;
  byId("text-scale-cycle").setAttribute("aria-label", `Text size: ${textScaleNames[scale]}. Increase text size`);
  byId("text-scale-name").textContent = textScaleNames[scale];
  byId("text-scale-input").value = String(textScales.indexOf(scale));
  if (persist) savePreference("monique-text-scale", scale);
}

function applySidebar(state, persist = true) {
  if (!sidebarStates.includes(state)) state = "expanded";
  document.documentElement.dataset.sidebar = state;
  const expanded = state === "expanded";
  byId("sidebar-toggle").setAttribute("aria-expanded", String(expanded));
  byId("sidebar-collapse").setAttribute("aria-label", expanded ? "Collapse sidebar" : "Expand sidebar");
  byId("sidebar-collapse").title = expanded ? "Collapse sidebar" : "Expand sidebar";
  byId("sidebar-collapse").firstElementChild.textContent = expanded ? "‹" : "›";
  if (persist) savePreference("monique-sidebar", state);
}

function applyDensity(density, persist = true) {
  if (!densities.includes(density)) density = "comfortable";
  document.documentElement.dataset.density = density;
  document.querySelectorAll("[data-density-choice]").forEach((button) => {
    const active = button.dataset.densityChoice === density;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) savePreference("monique-density", density);
}

function applyMotion(mode, persist = true) {
  if (!motionModes.includes(mode)) mode = "full";
  document.documentElement.dataset.motion = mode;
  byId("reduce-motion").checked = mode === "reduce";
  if (persist) savePreference("monique-motion", mode);
}

function applyStartupView(view, persist = true) {
  if (!startupViews.includes(view)) view = "chat";
  byId("startup-view").value = view;
  if (persist) savePreference("monique-start-view", view);
}

applyTheme(storedPreference("monique-theme", themes, "system"), false);
applyTextScale(storedPreference("monique-text-scale", textScales, "comfortable"), false);
applySidebar(storedPreference("monique-sidebar", sidebarStates, "expanded"), false);
applyDensity(storedPreference("monique-density", densities, "comfortable"), false);
applyMotion(storedPreference("monique-motion", motionModes, "full"), false);
applyStartupView(storedPreference("monique-start-view", startupViews, "chat"), false);

byId("theme-select").addEventListener("change", (event) => applyTheme(event.target.value));
document.querySelectorAll("[data-theme-choice]").forEach((button) => button.addEventListener("click", () => applyTheme(button.dataset.themeChoice)));
byId("text-scale-cycle").addEventListener("click", () => {
  const current = document.documentElement.dataset.textScale || "comfortable";
  applyTextScale(textScales[(textScales.indexOf(current) + 1) % textScales.length]);
});
byId("text-scale-input").addEventListener("input", (event) => applyTextScale(textScales[Number(event.target.value)]));
byId("text-scale-down").addEventListener("click", () => {
  const current = textScales.indexOf(document.documentElement.dataset.textScale || "comfortable");
  applyTextScale(textScales[Math.max(0, current - 1)]);
});
byId("text-scale-up").addEventListener("click", () => {
  const current = textScales.indexOf(document.documentElement.dataset.textScale || "comfortable");
  applyTextScale(textScales[Math.min(textScales.length - 1, current + 1)]);
});
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
  if (document.documentElement.dataset.theme === "system") applyTheme("system", false);
});

function appearanceOpen(open) {
  byId("appearance-panel").hidden = !open;
  byId("theme-cycle").setAttribute("aria-expanded", String(open));
  byId("sidebar-appearance").setAttribute("aria-expanded", String(open));
  if (open) byId("appearance-close").focus();
}

function mobileSidebarOpen(open) {
  if (open) document.documentElement.dataset.mobileSidebar = "open";
  else delete document.documentElement.dataset.mobileSidebar;
  byId("sidebar-backdrop").hidden = !open;
  byId("sidebar-toggle").setAttribute("aria-expanded", String(open));
}

[byId("theme-cycle"), byId("sidebar-appearance")].forEach((button) => button.addEventListener("click", () => {
  appearanceOpen(byId("appearance-panel").hidden);
}));
byId("appearance-close").addEventListener("click", () => appearanceOpen(false));
byId("sidebar-collapse").addEventListener("click", () => {
  const current = document.documentElement.dataset.sidebar || "expanded";
  applySidebar(current === "expanded" ? "collapsed" : "expanded");
});
byId("sidebar-toggle").addEventListener("click", () => {
  if (window.matchMedia("(max-width: 760px)").matches) {
    mobileSidebarOpen(document.documentElement.dataset.mobileSidebar !== "open");
  } else {
    const current = document.documentElement.dataset.sidebar || "expanded";
    applySidebar(current === "expanded" ? "collapsed" : "expanded");
  }
});
byId("sidebar-backdrop").addEventListener("click", () => mobileSidebarOpen(false));
document.querySelectorAll("[data-density-choice]").forEach((button) => button.addEventListener("click", () => applyDensity(button.dataset.densityChoice)));
byId("reduce-motion").addEventListener("change", (event) => applyMotion(event.target.checked ? "reduce" : "full"));
byId("startup-view").addEventListener("change", (event) => applyStartupView(event.target.value));
byId("reset-appearance").addEventListener("click", () => {
  applyTheme("system");
  applyTextScale("comfortable");
  applyDensity("comfortable");
  applyMotion("full");
  applyStartupView("chat");
  toast("Appearance settings reset.");
});
document.addEventListener("pointerdown", (event) => {
  if (byId("appearance-panel").hidden) return;
  if (event.target.closest("#appearance-panel, #theme-cycle, #sidebar-appearance")) return;
  appearanceOpen(false);
});

async function api(path, options = {}) {
  const request = () => fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  let response = await request();
  // The authenticated document response mints the HttpOnly API session. Some
  // browsers can start a deferred script's first fetch before that cookie has
  // finished committing, so retry that one bootstrap race exactly once.
  if (response.status === 401) {
    await new Promise((resolve) => window.setTimeout(resolve, 50));
    response = await request();
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function toast(message, kind = "info") {
  const item = document.createElement("div");
  item.className = `toast ${kind === "error" ? "error" : ""}`;
  item.textContent = message;
  byId("toast-region").append(item);
  window.setTimeout(() => item.remove(), 4200);
}

function attention(status) {
  const issues = [];
  if (status.health !== "operational") issues.push("runtime health");
  if (status.stale) issues.push("stale snapshot");
  if ((status.reconciliation_pending || 0) > 0) issues.push("reconciliation");
  if ((status.outbox_ambiguous || 0) > 0) issues.push("ambiguous effects");
  if (status.provider_available === false) issues.push("provider lane");
  if (status.accepting_intake === false) issues.push("intake closed");
  return [...new Set(issues)];
}

function pipelineState(value, danger = false) {
  if (!Number.isSafeInteger(value)) return "WAIT";
  if (danger && value > 0) return "REVIEW";
  return value > 0 ? "ACTIVE" : "CLEAR";
}

function relativeDuration(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "unknown";
  if (milliseconds < 1000) return "just now";
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

function updateObservedAge() {
  if (!Number.isSafeInteger(lastObservedMs)) {
    byId("global-observed").textContent = "No snapshot";
    byId("global-observed").removeAttribute("title");
    return;
  }
  const observed = new Date(lastObservedMs);
  byId("global-observed").textContent = `Updated ${relativeDuration(Date.now() - lastObservedMs)}`;
  byId("global-observed").title = observed.toLocaleString();
}

function recordStatus(status) {
  if (!Number.isSafeInteger(status.observed_ms) || status.observed_ms === lastObservedMs) return;
  lastObservedMs = status.observed_ms;
  const sample = {
    at: Date.now(),
    running: safeMetric(status.running),
    inbox: safeMetric(status.inbox_pending),
    outbox: safeMetric(status.outbox_pending),
  };
  const key = `${sample.running}:${sample.inbox}:${sample.outbox}`;
  if (lastStatusKey !== null && key !== lastStatusKey) lastPulseChangeAt = sample.at;
  if (lastPulseChangeAt === null) lastPulseChangeAt = sample.at;
  lastStatusKey = key;
  statusHistory.push(sample);
  if (statusHistory.length > 30) statusHistory.shift();
  renderPulse();
}

function pulsePoints(field, maximum) {
  if (statusHistory.length === 0) return "";
  return statusHistory.map((sample, index) => {
    const x = statusHistory.length === 1 ? 0 : (index / (statusHistory.length - 1)) * 720;
    const y = 140 - (sample[field] / maximum) * 118;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

function renderPulse() {
  const maximum = Math.max(1, ...statusHistory.flatMap((sample) => [sample.running, sample.inbox, sample.outbox]));
  ["running", "inbox", "outbox"].forEach((field) => {
    byId(`pulse-${field}`).setAttribute("points", pulsePoints(field, maximum));
  });
  byId("pulse-samples").textContent = count(statusHistory.length);
  const windowMs = statusHistory.length > 1 ? statusHistory.at(-1).at - statusHistory[0].at : 0;
  byId("pulse-window").textContent = windowMs < 1000 ? "Just started" : `${Math.max(1, Math.round(windowMs / 1000))} seconds`;
  byId("pulse-change").textContent = lastPulseChangeAt === null ? "Waiting" : relativeDuration(Date.now() - lastPulseChangeAt);
  byId("pulse-tag").textContent = statusHistory.length > 1 ? "LIVE" : "COLLECTING";
}

function renderStatus(status) {
  const health = ["operational", "degraded", "unavailable"].includes(status.health) ? status.health : "unavailable";
  document.documentElement.dataset.health = health;
  const issues = attention(status);
  byId("global-health").textContent = health;
  byId("generation").textContent = `GEN ${count(status.generation)}`;
  byId("footer-state").textContent = `${health.toUpperCase()} / GEN ${count(status.generation)}`;
  byId("attention-title").textContent = issues.length === 0 ? "All operational invariants hold" : `${issues.length} invariant${issues.length === 1 ? "" : "s"} need attention`;
  byId("attention-detail").textContent = issues.length === 0 ? "Provider, intake, delivery certainty and reconciliation are clear." : issues.join(" · ");
  byId("metric-running").textContent = count(status.running);
  byId("metric-inbox").textContent = count(status.inbox_pending);
  byId("metric-outbox").textContent = count(status.outbox_pending);
  byId("metric-reconciliation").textContent = count(status.reconciliation_pending);
  byId("metric-ambiguous").textContent = count(status.outbox_ambiguous);
  byId("metric-attention").textContent = count(issues.length);
  byId("runtime-daemon").textContent = words(status.state);
  byId("runtime-provider").textContent = status.provider_available === true ? "AVAILABLE" : status.provider_available === false ? "UNAVAILABLE" : "—";
  byId("runtime-intake").textContent = yesNo(status.accepting_intake);
  byId("runtime-execution").textContent = words(status.execution_state);
  byId("runtime-telegram").textContent = words(status.telegram_state);
  byId("runtime-snapshot").textContent = status.stale ? "STALE" : "CURRENT";
  byId("runtime-tag").textContent = issues.length === 0 ? "CLEAR" : "REVIEW";
  const pipeline = [
    ["inbox", status.inbox_pending, false],
    ["running", status.running, false],
    ["outbox", status.outbox_pending, false],
    ["reconcile", status.reconciliation_pending, true],
  ];
  pipeline.forEach(([name, value, danger]) => {
    byId(`pipe-${name}`).textContent = `${count(value)} ${name === "running" ? "active" : "pending"}`;
    byId(`pipe-${name}-state`).textContent = pipelineState(value, danger);
  });
  recordStatus(status);
  updateObservedAge();
}

async function refreshStatus({ announce = false } = {}) {
  const button = byId("status-refresh");
  button.disabled = true;
  try {
    renderStatus(await api("/api/status"));
    if (announce) toast("Operational status refreshed.");
  } catch (_error) {
    renderStatus({ health: "unavailable", stale: true });
    if (announce) toast("The operational snapshot is unavailable.", "error");
  } finally {
    button.disabled = false;
  }
}

function showView(name) {
  const allowed = ["overview", "chat", "operations", "tickets", "memory", "configuration"];
  if (!allowed.includes(name)) name = "overview";
  document.querySelectorAll("[data-panel]").forEach((node) => node.classList.toggle("is-visible", node.dataset.panel === name));
  document.querySelectorAll("[data-view]").forEach((node) => {
    const active = node.dataset.view === name;
    node.classList.toggle("is-active", active);
    if (active) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current");
  });
  byId("current-view").textContent = name.toUpperCase();
  if (window.location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  if (name === "memory") loadMemory(memoryQuery);
  if (name === "operations" || name === "tickets") loadOperations();
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
  if (window.matchMedia("(max-width: 760px)").matches) mobileSidebarOpen(false);
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
window.addEventListener("hashchange", () => showView(window.location.hash.slice(1)));
byId("status-refresh").addEventListener("click", () => refreshStatus({ announce: true }));

function selectedMemoryEntries() {
  const entries = memorySnapshot?.entries || [];
  return memoryKind === "all" ? entries : entries.filter((entry) => entry.kind === memoryKind);
}

function updateMemoryKinds(entries) {
  const select = byId("memory-kind");
  const kinds = [...new Set(entries.map((entry) => entry.kind).filter((kind) => typeof kind === "string"))].sort();
  const previous = memoryKind;
  select.replaceChildren();
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "All evidence";
  select.append(all);
  kinds.forEach((kind) => {
    const option = document.createElement("option");
    option.value = kind;
    option.textContent = label(kind);
    select.append(option);
  });
  memoryKind = kinds.includes(previous) ? previous : "all";
  select.value = memoryKind;
}

function renderMemory(view) {
  memorySnapshot = view;
  byId("memory-active").textContent = count(view.counts?.active);
  byId("memory-candidates").textContent = count(view.counts?.candidates);
  byId("memory-superseded").textContent = count(view.counts?.superseded);
  byId("memory-messages").textContent = count(view.counts?.messages);
  updateMemoryKinds(view.entries || []);
  renderSelectedMemory();
}

function renderSelectedMemory() {
  const entries = selectedMemoryEntries();
  const scope = memoryKind === "all" ? "evidence" : words(memoryKind);
  const query = memoryQuery ? ` for “${memoryQuery}”` : "";
  byId("memory-result-label").textContent = `${count(entries.length)} ${scope} record${entries.length === 1 ? "" : "s"}${query}`;
  renderMemoryList(entries);
  renderMemoryGraph(entries);
}

function memoryEmpty(message) {
  const empty = document.createElement("div");
  empty.className = "memory-empty";
  empty.textContent = message;
  return empty;
}

function renderMemoryList(entries) {
  const root = byId("memory-list");
  root.replaceChildren();
  if (entries.length === 0) {
    root.append(memoryEmpty("No memory evidence matches this view."));
    return;
  }
  entries.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "memory-record";
    const ref = document.createElement("strong");
    ref.textContent = entry.reference;
    const text = document.createElement("p");
    text.textContent = entry.content;
    const meta = document.createElement("div");
    meta.className = "record-meta";
    meta.textContent = `${words(entry.kind)} · ${entry.confidence / 10}% confidence\n${entry.visibility} · rev ${entry.revision}`;
    card.append(ref, text, meta);
    root.append(card);
  });
}

function renderMemoryGraph(entries) {
  const graph = byId("memory-graph");
  graph.replaceChildren();
  const core = document.createElement("div");
  core.className = "graph-core";
  core.textContent = "MONIQUE";
  graph.append(core);
  if (entries.length === 0) {
    const empty = memoryEmpty("No evidence nodes to display.");
    empty.classList.add("graph-empty");
    graph.append(empty);
    return;
  }
  entries.slice(0, 14).forEach((entry, index) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = `graph-node slot-${index}`;
    node.setAttribute("aria-label", `Open ${entry.reference} in the record list`);
    const reference = document.createElement("span");
    reference.textContent = `${entry.reference} / ${words(entry.kind).toUpperCase()}`;
    const content = document.createElement("strong");
    content.textContent = entry.content;
    const metadata = document.createElement("small");
    metadata.textContent = `${entry.confidence / 10}% · ${entry.provenance} · R${entry.revision}`;
    node.append(reference, content, metadata);
    node.addEventListener("click", () => {
      document.querySelector("[data-memory-mode='list']").click();
      const match = [...byId("memory-list").children].find((card) => card.firstChild?.textContent === entry.reference);
      match?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    graph.append(node);
  });
}

async function loadMemory(query = null) {
  memoryQuery = query?.trim() || null;
  byId("memory-clear").hidden = memoryQuery === null;
  byId("memory-result-label").textContent = memoryQuery ? "Searching canonical memory…" : "Loading canonical memory…";
  try {
    const view = memoryQuery === null
      ? await api("/api/memory")
      : await api("/api/memory/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: memoryQuery }) });
    renderMemory(view);
  } catch (error) {
    byId("memory-result-label").textContent = `Memory unavailable · ${error.message}`;
    toast("Memory retrieval is unavailable.", "error");
  }
}

byId("memory-search").addEventListener("submit", (event) => {
  event.preventDefault();
  loadMemory(byId("memory-query").value);
});
byId("memory-clear").addEventListener("click", () => {
  byId("memory-query").value = "";
  loadMemory(null);
  byId("memory-query").focus();
});
byId("memory-query").addEventListener("input", (event) => {
  byId("memory-clear").hidden = event.target.value.length === 0;
});
byId("memory-kind").addEventListener("change", (event) => {
  memoryKind = event.target.value;
  renderSelectedMemory();
});
document.querySelectorAll("[data-memory-mode]").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll("[data-memory-mode]").forEach((item) => item.classList.toggle("is-active", item === button));
  const graphMode = button.dataset.memoryMode === "graph";
  byId("memory-graph").hidden = !graphMode;
  byId("memory-list").hidden = graphMode;
}));

function operationLabel(value) {
  return String(value || "operation").replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function operationsMessage(health) {
  const messages = {
    attached: ["AI Operations connected", "Live tools are discovered from the authenticated control plane."],
    not_attached: ["AI Operations is not attached", "Configure one same-origin Manage MCP server to enable live capabilities."],
    unavailable: ["AI Operations is unavailable", "The configured control plane did not return a valid capability catalog."],
    busy: ["AI Operations is busy", "Another contained request is using the live tool connection. Try again shortly."],
  };
  return messages[health] || ["AI Operations state unknown", "Refresh to discover the current control-plane state."];
}

function renderOperationsCatalog(tools) {
  const root = byId("operations-tool-grid");
  root.replaceChildren();
  if (tools.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty";
    empty.textContent = "No AI Operations tools are currently available to this dashboard.";
    root.append(empty);
    return;
  }
  tools.forEach((tool) => {
    const card = document.createElement("article");
    card.className = "tool-card";
    const head = document.createElement("div");
    const category = document.createElement("span");
    category.textContent = operationLabel(tool.category);
    const authority = document.createElement("i");
    authority.className = tool.authority === "read_only" ? "safe" : "approval";
    authority.textContent = tool.authority === "read_only" ? "SAFE READ" : "APPROVAL";
    head.append(category, authority);
    const title = document.createElement("strong");
    title.textContent = operationLabel(tool.name);
    const description = document.createElement("p");
    description.textContent = tool.description || "Live AI Operations capability.";
    const footer = document.createElement("div");
    const input = document.createElement("small");
    input.textContent = tool.requires_input ? "Details required" : "Ready to plan";
    const use = document.createElement("button");
    use.type = "button";
    use.textContent = "Use with Monique →";
    use.dataset.openChat = `Help me use the AI Operations capability “${operationLabel(tool.name)}”. Explain what it does, collect any required details, and stage any mutation for my approval.`;
    footer.append(input, use);
    card.append(head, title, description, footer);
    root.append(card);
  });
}

function ticketStatusLabel(status) {
  const labels = { in_progress: "In progress", triaging: "Triaging", blocked: "Blocked", done: "Done", closed: "Closed", open: "Open", unknown: "Unknown" };
  return labels[status] || operationLabel(status);
}

function filteredTickets() {
  const items = operationsSnapshot?.tickets?.items || [];
  if (ticketFilter === "all") return items;
  if (ticketFilter === "done") return items.filter((ticket) => ticket.status === "done" || ticket.status === "closed");
  return items.filter((ticket) => ticket.status === ticketFilter);
}

function safeTicketLink(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password ? parsed.href : null;
  } catch (_error) {
    return null;
  }
}

function ticketEmptyMessage(health) {
  const messages = {
    empty: "The connected ticket queue is currently empty.",
    no_read_surface: "AI Operations is connected, but it does not advertise a zero-input read-only ticket list.",
    input_required: "The ticket source needs additional scope. Ask Monique to retrieve the exact queue you need.",
    unavailable: "The live ticket source is temporarily unavailable.",
    not_attached: "Attach AI Operations to load the live ticket queue.",
  };
  return messages[health] || "No tickets match this filter.";
}

function renderTickets() {
  const tickets = operationsSnapshot?.tickets?.items || [];
  const open = tickets.filter((ticket) => ticket.status === "open" || ticket.status === "triaging").length;
  byId("tickets-total").textContent = count(tickets.length);
  byId("tickets-open").textContent = count(open);
  byId("tickets-progress").textContent = count(tickets.filter((ticket) => ticket.status === "in_progress").length);
  byId("tickets-blocked").textContent = count(tickets.filter((ticket) => ticket.status === "blocked").length);
  byId("tickets-urgent").textContent = count(tickets.filter((ticket) => ticket.priority === "urgent").length);
  const visible = filteredTickets();
  const health = operationsSnapshot?.tickets?.health || "not_attached";
  byId("tickets-state").textContent = health === "ready"
    ? `${visible.length.toLocaleString()} of ${tickets.length.toLocaleString()} tickets`
    : ticketEmptyMessage(health);
  const root = byId("ticket-list");
  root.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty ticket-empty";
    const title = document.createElement("strong");
    title.textContent = ticketEmptyMessage(health === "ready" ? "filtered" : health);
    const action = document.createElement("button");
    action.type = "button";
    action.textContent = "Ask Monique about tickets";
    action.dataset.openChat = "Inspect the available AI Operations ticket capabilities and help me retrieve or review the right ticket queue.";
    empty.append(title, action);
    root.append(empty);
    return;
  }
  visible.forEach((ticket) => {
    const row = document.createElement("article");
    row.className = `ticket-row priority-${ticket.priority}`;
    const reference = document.createElement("div");
    reference.className = "ticket-reference";
    const dot = document.createElement("i");
    dot.setAttribute("aria-label", `${operationLabel(ticket.priority)} priority`);
    const id = document.createElement("span");
    id.textContent = ticket.id.startsWith("#") ? ticket.id : `#${ticket.id}`;
    reference.append(dot, id);
    const body = document.createElement("div");
    body.className = "ticket-body";
    const title = document.createElement("strong");
    title.textContent = ticket.title;
    const meta = document.createElement("small");
    meta.textContent = [ticket.assignee ? `Assigned to ${ticket.assignee}` : "Unassigned", ticket.updated_at ? `Updated ${ticket.updated_at}` : null].filter(Boolean).join(" · ");
    body.append(title, meta);
    const status = document.createElement("span");
    status.className = `ticket-status status-${ticket.status}`;
    status.textContent = ticketStatusLabel(ticket.status);
    const actions = document.createElement("div");
    actions.className = "ticket-actions";
    const ask = document.createElement("button");
    ask.type = "button";
    ask.textContent = "Ask Monique";
    ask.dataset.openChat = `Review ticket ${ticket.id}: “${ticket.title}”. Summarize its current state and recommend the next action.`;
    actions.append(ask);
    const href = safeTicketLink(ticket.url);
    if (href) {
      const openLink = document.createElement("a");
      openLink.href = href;
      openLink.target = "_blank";
      openLink.rel = "noreferrer";
      openLink.textContent = "Open ↗";
      actions.append(openLink);
    }
    row.append(reference, body, status, actions);
    root.append(row);
  });
}

function renderOperations(view) {
  operationsSnapshot = view;
  const [title, detail] = operationsMessage(view.health);
  byId("operations-banner").dataset.state = view.health;
  byId("operations-health").textContent = title;
  byId("operations-detail").textContent = detail;
  byId("operations-authority").textContent = view.health === "attached" ? "AUTHORITY BOUNDED" : "NOT ATTACHED";
  byId("operations-tools").textContent = count(view.tools_total);
  byId("operations-reads").textContent = count(view.read_only_tools);
  byId("operations-actions").textContent = count(view.approval_tools);
  byId("operations-pending").textContent = count(view.pending_actions);
  byId("operations-catalog-tag").textContent = view.health === "attached" ? `${count(view.tools_total)} LIVE` : "UNAVAILABLE";
  renderOperationsCatalog(view.tools || []);
  renderTickets();
}

async function loadOperations(force = false) {
  if (operationsSnapshot && !force) return;
  [byId("operations-refresh"), byId("tickets-refresh")].forEach((button) => { button.disabled = true; });
  try {
    renderOperations(await api("/api/operations"));
    if (force) toast("AI Operations and tickets refreshed.");
  } catch (error) {
    byId("operations-banner").dataset.state = "unavailable";
    byId("operations-health").textContent = "AI Operations unavailable";
    byId("operations-detail").textContent = error.message;
    byId("tickets-state").textContent = "Ticket intake unavailable";
    toast("AI Operations could not be refreshed.", "error");
  } finally {
    [byId("operations-refresh"), byId("tickets-refresh")].forEach((button) => { button.disabled = false; });
  }
}

byId("operations-refresh").addEventListener("click", () => loadOperations(true));
byId("tickets-refresh").addEventListener("click", () => loadOperations(true));
document.querySelectorAll("[data-ticket-filter]").forEach((button) => button.addEventListener("click", () => {
  ticketFilter = button.dataset.ticketFilter;
  document.querySelectorAll("[data-ticket-filter]").forEach((item) => item.classList.toggle("is-active", item === button));
  renderTickets();
}));

function label(value) {
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderConfigSection(title, values) {
  const card = document.createElement("article");
  card.className = "panel config-card";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const list = document.createElement("dl");
  list.className = "config-list";
  Object.entries(values || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    term.textContent = label(key);
    const detail = document.createElement("dd");
    detail.textContent = typeof value === "boolean" ? (value ? "CONFIGURED" : "OFF") : String(value ?? "—");
    if (typeof value === "boolean") detail.className = value ? "boolean-true" : "boolean-false";
    row.append(term, detail);
    list.append(row);
  });
  card.append(heading, list);
  return card;
}

function syncManageIntegration(manage) {
  const configuredUrl = typeof manage?.console_url === "string" ? manage.console_url : null;
  let safeUrl = null;
  if (configuredUrl) {
    try {
      const parsed = new URL(configuredUrl);
      if (parsed.protocol === "https:") safeUrl = parsed.href;
    } catch (_error) {
      safeUrl = null;
    }
  }
  document.querySelectorAll("[data-manage-link]").forEach((link) => {
    if (safeUrl) {
      link.href = safeUrl;
      link.hidden = false;
    } else {
      link.removeAttribute("href");
      link.hidden = true;
    }
  });
  byId("chat-manage-state").hidden = manage?.dashboard_authority !== "discovered tools / explicit approval";
}

async function loadConfiguration(force = false) {
  const root = byId("configuration-grid");
  if (!force && root.dataset.loaded === "true") return;
  root.dataset.loaded = "false";
  try {
    const config = await api("/api/configuration");
    root.replaceChildren();
    const core = { ...config };
    delete core.schema;
    delete core.memory;
    delete core.providers;
    delete core.connectors;
    delete core.manage;
    syncManageIntegration(config.manage);
    const manage = { ...config.manage };
    delete manage.console_url;
    manage.console = config.manage?.console_url ? "AVAILABLE" : "OFF";
    root.append(
      renderConfigSection("Web boundary", core),
      renderConfigSection("Memory", config.memory),
      renderConfigSection("Providers", config.providers),
      renderConfigSection("Connectors", config.connectors),
      renderConfigSection("Manage AI Operations", manage),
    );
    root.dataset.loaded = "true";
    if (force) toast("Effective configuration refreshed.");
  } catch (error) {
    root.replaceChildren(renderConfigSection("Configuration unavailable", { category: error.message }));
    toast("Configuration projection is unavailable.", "error");
  }
}

byId("configuration-refresh").addEventListener("click", () => loadConfiguration(true));

function appendMessage(role, content, createdAt = Date.now(), details = {}) {
  byId("chat-empty")?.remove();
  const item = document.createElement("article");
  item.className = `message ${role === "user" ? "user" : "assistant"}${details.error ? " error" : ""}`;
  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = role === "user" ? "YOU" : "M";
  const body = document.createElement("div");
  body.className = "message-content";
  String(content).split(/\n{2,}/).forEach((paragraph) => {
    const p = document.createElement("p");
    p.textContent = paragraph;
    body.append(p);
  });
  if (role !== "user" && details.action) body.append(createActionCard(details.action));
  const meta = document.createElement("div");
  meta.className = "message-meta";
  const duration = Number.isSafeInteger(details.durationMs) ? ` · ${details.durationMs.toLocaleString()}ms` : "";
  meta.textContent = `${role === "user" ? "OPERATOR" : "MONIQUE"} · ${new Date(createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${duration}`;
  body.append(meta);
  if (role !== "user") {
    const tools = document.createElement("div");
    tools.className = "message-tools";
    (details.sources || []).forEach((source) => {
      const chip = document.createElement("span");
      chip.className = "source-chip";
      chip.textContent = `LIVE · ${words(source)}`;
      tools.append(chip);
    });
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-message";
    copy.textContent = "COPY";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(String(content));
        copy.textContent = "COPIED";
        window.setTimeout(() => { copy.textContent = "COPY"; }, 1800);
      } catch (_error) {
        toast("Copy is unavailable in this browser.", "error");
      }
    });
    tools.append(copy);
    body.append(tools);
  }
  if (role === "user") item.append(body, avatar); else item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
  return item;
}

function createActionCard(action) {
  const card = document.createElement("section");
  card.className = "action-card";
  card.dataset.actionId = String(action.id || "");
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "APPROVAL REQUIRED";
  const title = document.createElement("strong");
  title.textContent = String(action.title || "Review Manage action");
  const detail = document.createElement("p");
  detail.textContent = String(action.detail || "Review this action before it runs.");
  const impact = document.createElement("small");
  impact.textContent = String(action.impact || "This action can change external state.");
  const controls = document.createElement("div");
  controls.className = "action-controls";
  const deny = document.createElement("button");
  deny.type = "button";
  deny.className = "action-deny";
  deny.textContent = "Deny";
  const approve = document.createElement("button");
  approve.type = "button";
  approve.className = "action-approve";
  approve.textContent = "Approve and run";
  [deny, approve].forEach((button) => button.addEventListener("click", () => {
    resolveChatAction(card, button === approve ? "approve" : "deny");
  }));
  controls.append(deny, approve);
  card.append(eyebrow, title, detail, impact, controls);
  return card;
}

async function resolveChatAction(card, decision) {
  if (chatBusy || card.dataset.state) return;
  chatBusy = true;
  card.dataset.state = "working";
  card.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  const pending = appendPendingMessage();
  byId("chat-state").textContent = decision === "approve" ? "Running approved action…" : "Recording denial…";
  try {
    const answer = await api("/api/chat/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: card.dataset.actionId, decision }),
    });
    pending.remove();
    card.dataset.state = decision === "approve" ? "approved" : "denied";
    const sources = Array.isArray(answer.live_sources) ? answer.live_sources : [];
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action });
    byId("chat-source-count").textContent = count(sources.length);
    byId("chat-latency").textContent = Number.isSafeInteger(answer.duration_ms) ? `${answer.duration_ms.toLocaleString()} ms` : "—";
    byId("chat-state").textContent = decision === "approve" ? "Action completed" : "Action denied";
    toast(decision === "approve" ? "The approved action returned a result." : "The action was denied.");
  } catch (error) {
    pending.remove();
    card.removeAttribute("data-state");
    card.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    appendMessage("assistant", humanChatError(error.message), Date.now(), { error: true });
    byId("chat-state").textContent = "Action refused";
    toast("The action was not completed.", "error");
  } finally {
    chatBusy = false;
  }
}

function appendPendingMessage() {
  byId("chat-empty")?.remove();
  const item = document.createElement("article");
  item.className = "message assistant pending";
  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = "M";
  const body = document.createElement("div");
  body.className = "message-content";
  const dots = document.createElement("span");
  dots.className = "thinking-dots";
  dots.setAttribute("aria-label", "Monique is working");
  dots.append(document.createElement("i"), document.createElement("i"), document.createElement("i"));
  body.append(dots);
  item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
  return item;
}

function createWelcome(title = "How can I help?", text = "Ask naturally. I can use reviewed memory, live sources, and prepare actions for your approval.") {
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.id = "chat-empty";
  const mark = document.createElement("span");
  mark.textContent = "M";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.textContent = text;
  const starters = document.createElement("div");
  starters.className = "starter-grid";
  [
    ["Explain system health", "Review live status and surface risks", "Explain the current operational health and any risks."],
    ["Catch me up", "Read recent configured Slack context", "Summarize the latest relevant Slack messages."],
    ["Explore memory", "Use reviewed durable evidence", "What do you remember that is most relevant right now? Cite memory references."],
    ["Work in Manage", "Prepare a reviewable AI Operations action", "Show me the useful actions available in Manage AI Operations and help me choose the right one."],
  ].forEach(([caption, description, prompt]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.chatPrompt = prompt;
    const label = document.createElement("strong");
    label.textContent = caption;
    const detail = document.createElement("small");
    detail.textContent = description;
    button.append(label, detail);
    starters.append(button);
  });
  empty.append(mark, heading, copy, starters);
  return empty;
}

async function loadChatHistory() {
  const thread = byId("chat-thread");
  if (thread.dataset.loaded === "true") return;
  try {
    const history = await api("/api/chat/history");
    if ((history.messages || []).length > 0) {
      thread.replaceChildren();
      history.messages.forEach((message) => appendMessage(message.role, message.content, message.created_at_ms));
    }
    (history.pending_actions || []).forEach((action) => {
      appendMessage("assistant", "This Manage action is still awaiting your decision.", Date.now(), { action });
    });
    thread.dataset.loaded = "true";
  } catch (_error) {
    byId("chat-state").textContent = "History unavailable";
    toast("Durable chat history is unavailable.", "error");
  }
}

function humanChatError(category) {
  const messages = {
    chat_lane_busy: "Monique is finishing another contained turn. Try again in a moment.",
    slack_read_unavailable: "The configured Slack read is temporarily unavailable.",
    slack_tool_unavailable: "The Slack read surface is temporarily busy.",
    memory_unavailable: "Durable memory is temporarily unavailable.",
    memory_write_refused: "This turn could not be retained safely, so it was not run.",
    manage_tool_unavailable: "Manage AI Operations is temporarily unavailable. No action was run.",
    manage_action_not_pending: "That Manage action is no longer pending. Nothing was run.",
    manage_action_expired: "That Manage action expired. Ask Monique to prepare it again.",
    manage_action_additional_approval_refused: "Manage requested another approval step, so execution stopped.",
  };
  return messages[category] || `The contained conversation lane refused this turn (${category}).`;
}

byId("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (chatBusy) return;
  const input = byId("chat-input");
  const message = input.value.trim();
  if (!message) return;
  chatBusy = true;
  appendMessage("user", message);
  input.value = "";
  byId("chat-count").textContent = "0";
  byId("chat-send").disabled = true;
  const pending = appendPendingMessage();
  const started = performance.now();
  const timer = window.setInterval(() => {
    byId("chat-state").textContent = `Monique is working · ${Math.max(1, Math.round((performance.now() - started) / 1000))}s`;
  }, 1000);
  byId("chat-state").textContent = "Monique is working…";
  try {
    const answer = await api("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, profile: byId("chat-profile").value }),
    });
    pending.remove();
    const sources = Array.isArray(answer.live_sources) ? answer.live_sources : [];
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action });
    byId("chat-memory-count").textContent = count(answer.memory_evidence);
    byId("chat-source-count").textContent = count(sources.length);
    byId("chat-latency").textContent = Number.isSafeInteger(answer.duration_ms) ? `${answer.duration_ms.toLocaleString()} ms` : `${Math.round(performance.now() - started).toLocaleString()} ms`;
    byId("chat-state").textContent = `${words(answer.profile)} · retained`;
  } catch (error) {
    pending.remove();
    appendMessage("assistant", humanChatError(error.message), Date.now(), { error: true });
    byId("chat-state").textContent = "Turn refused";
    toast("Monique could not complete that turn.", "error");
  } finally {
    window.clearInterval(timer);
    chatBusy = false;
    byId("chat-send").disabled = false;
    input.focus();
  }
});

byId("chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    byId("chat-form").requestSubmit();
  }
});
byId("chat-input").addEventListener("input", (event) => {
  byId("chat-count").textContent = event.target.value.length.toLocaleString();
});

function resetNewChatButton() {
  window.clearTimeout(newChatTimer);
  newChatArmed = false;
  byId("new-chat").textContent = "New conversation";
  byId("new-chat").removeAttribute("data-armed");
  byId("sidebar-new-chat-label").textContent = "New conversation";
  byId("sidebar-new-chat").removeAttribute("data-armed");
}

byId("new-chat").addEventListener("click", async () => {
  if (chatBusy) {
    toast("Wait for the current turn to finish before starting a new conversation.");
    return;
  }
  if (!newChatArmed) {
    newChatArmed = true;
    byId("new-chat").textContent = "Confirm new conversation";
    byId("new-chat").dataset.armed = "true";
    byId("sidebar-new-chat-label").textContent = "Confirm new conversation";
    byId("sidebar-new-chat").dataset.armed = "true";
    newChatTimer = window.setTimeout(resetNewChatButton, 5000);
    return;
  }
  byId("new-chat").disabled = true;
  try {
    await api("/api/chat/new", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    byId("chat-thread").replaceChildren(createWelcome("New conversation", "The previous durable conversation was archived. Long-term memory remains available."));
    byId("chat-state").textContent = "New durable session";
    byId("chat-memory-count").textContent = "—";
    byId("chat-source-count").textContent = "0";
    byId("chat-latency").textContent = "—";
    toast("A new durable conversation is ready.");
  } catch (error) {
    byId("chat-state").textContent = `New chat refused · ${error.message}`;
    toast("The current conversation was not changed.", "error");
  } finally {
    byId("new-chat").disabled = false;
    resetNewChatButton();
  }
});

byId("sidebar-new-chat").addEventListener("click", () => {
  showView("chat");
  byId("new-chat").click();
});

function seedChatPrompt(prompt) {
  showView("chat");
  const input = byId("chat-input");
  input.value = prompt;
  byId("chat-count").textContent = prompt.length.toLocaleString();
  input.focus();
}

document.addEventListener("click", (event) => {
  const prompt = event.target.closest("[data-chat-prompt]")?.dataset.chatPrompt;
  if (prompt) seedChatPrompt(prompt);
  const overviewPrompt = event.target.closest("[data-open-chat]")?.dataset.openChat;
  if (overviewPrompt) seedChatPrompt(overviewPrompt);
});

document.addEventListener("keydown", (event) => {
  const editing = event.target.matches("input, textarea, select, [contenteditable='true']");
  if (!editing && event.key === "/") {
    event.preventDefault();
    showView("chat");
    byId("chat-input").focus();
  } else if (!editing && event.key.toLowerCase() === "r") {
    event.preventDefault();
    refreshStatus({ announce: true });
  } else if (!editing && event.key.toLowerCase() === "n") {
    event.preventDefault();
    showView("chat");
    byId("new-chat").click();
  } else if (event.key === "Escape" && newChatArmed) {
    resetNewChatButton();
  } else if (event.key === "Escape" && !byId("appearance-panel").hidden) {
    appearanceOpen(false);
    byId("theme-cycle").focus();
  } else if (event.key === "Escape" && document.documentElement.dataset.mobileSidebar === "open") {
    mobileSidebarOpen(false);
    byId("sidebar-toggle").focus();
  }
});

refreshStatus();
loadConfiguration();
showView(window.location.hash.slice(1) || storedPreference("monique-start-view", startupViews, "chat"));
window.setInterval(() => { if (!document.hidden) refreshStatus(); }, 10_000);
window.setInterval(updateObservedAge, 1_000);
window.setInterval(renderPulse, 1_000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
