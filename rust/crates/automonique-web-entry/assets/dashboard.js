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
let lastObservedMs = null;
let lastStatusKey = null;
let lastPulseChangeAt = null;
let chatBusy = false;
let newChatArmed = false;
let newChatTimer = null;

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
  const allowed = ["overview", "chat", "memory", "configuration"];
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
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
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
  const link = byId("manage-link");
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
  if (safeUrl) {
    link.href = safeUrl;
    link.hidden = false;
  } else {
    link.removeAttribute("href");
    link.hidden = true;
  }
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
  } else if (event.key === "Escape" && newChatArmed) {
    resetNewChatButton();
  }
});

refreshStatus();
loadConfiguration();
showView(window.location.hash.slice(1) || "chat");
window.setInterval(() => { if (!document.hidden) refreshStatus(); }, 10_000);
window.setInterval(updateObservedAge, 1_000);
window.setInterval(renderPulse, 1_000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
