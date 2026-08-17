// SPDX-License-Identifier: Elastic-2.0

"use strict";

const byId = (id) => document.getElementById(id);
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "—";
const words = (value) => typeof value === "string" ? value.replaceAll("_", " ") : "—";
const yesNo = (value) => value === true ? "YES" : value === false ? "NO" : "—";
let memorySnapshot = null;

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
  if (Number.isSafeInteger(status.observed_ms)) {
    const observed = new Date(status.observed_ms);
    byId("global-observed").textContent = observed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } else {
    byId("global-observed").textContent = "No snapshot";
  }
}

async function refreshStatus() {
  try { renderStatus(await api("/api/status")); }
  catch (_error) { renderStatus({ health: "unavailable", stale: true }); }
}

function showView(name) {
  const allowed = ["overview", "chat", "memory", "configuration"];
  if (!allowed.includes(name)) name = "overview";
  document.querySelectorAll("[data-panel]").forEach((node) => node.classList.toggle("is-visible", node.dataset.panel === name));
  document.querySelectorAll("[data-view]").forEach((node) => node.classList.toggle("is-active", node.dataset.view === name));
  byId("current-view").textContent = name.toUpperCase();
  if (window.location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  if (name === "memory") loadMemory();
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
window.addEventListener("hashchange", () => showView(window.location.hash.slice(1)));

function renderMemory(view) {
  memorySnapshot = view;
  byId("memory-active").textContent = count(view.counts?.active);
  byId("memory-candidates").textContent = count(view.counts?.candidates);
  byId("memory-superseded").textContent = count(view.counts?.superseded);
  byId("memory-messages").textContent = count(view.counts?.messages);
  byId("memory-result-label").textContent = `${count(view.entries?.length)} evidence records · FTS5 canonical retrieval`;
  renderMemoryList(view.entries || []);
  renderMemoryGraph(view.entries || []);
}

function renderMemoryList(entries) {
  const root = byId("memory-list");
  root.replaceChildren();
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
  const width = Math.max(graph.clientWidth, 320);
  const height = Math.max(graph.clientHeight, 510);
  const centerX = width / 2;
  const centerY = height / 2;
  core.style.left = `${centerX - 44}px`;
  core.style.top = `${centerY - 44}px`;
  graph.append(core);
  entries.slice(0, width < 600 ? 8 : 14).forEach((entry, index, visible) => {
    const angle = (Math.PI * 2 * index / Math.max(visible.length, 1)) - Math.PI / 2;
    const radiusX = Math.max(90, Math.min(width * .36, 410));
    const radiusY = Math.max(140, Math.min(height * .36, 190));
    const nodeX = centerX + Math.cos(angle) * radiusX;
    const nodeY = centerY + Math.sin(angle) * radiusY;
    const edgeLength = Math.hypot(nodeX - centerX, nodeY - centerY);
    const edge = document.createElement("span");
    edge.className = "graph-edge";
    edge.style.left = `${centerX}px`;
    edge.style.top = `${centerY}px`;
    edge.style.width = `${edgeLength}px`;
    edge.style.transform = `rotate(${Math.atan2(nodeY - centerY, nodeX - centerX)}rad)`;
    const node = document.createElement("button");
    node.type = "button";
    node.className = "graph-node";
    node.style.left = `${Math.max(6, Math.min(width - (width < 600 ? 134 : 170), nodeX - (width < 600 ? 64 : 82)))}px`;
    node.style.top = `${Math.max(6, Math.min(height - 80, nodeY - 34))}px`;
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
    graph.append(edge, node);
  });
}

async function loadMemory(query = null) {
  try {
    const view = query === null
      ? await api("/api/memory")
      : await api("/api/memory/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query }) });
    renderMemory(view);
  } catch (error) {
    byId("memory-result-label").textContent = `Memory unavailable · ${error.message}`;
  }
}

byId("memory-search").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = byId("memory-query").value.trim();
  loadMemory(query || null);
});
document.querySelectorAll("[data-memory-mode]").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll("[data-memory-mode]").forEach((item) => item.classList.toggle("is-active", item === button));
  const graphMode = button.dataset.memoryMode === "graph";
  byId("memory-graph").hidden = !graphMode;
  byId("memory-list").hidden = graphMode;
}));
window.addEventListener("resize", () => {
  if (memorySnapshot && !byId("memory-graph").hidden) renderMemoryGraph(memorySnapshot.entries || []);
});

function label(value) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderConfigSection(title, values) {
  const card = document.createElement("article");
  card.className = "panel config-card";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const list = document.createElement("dl");
  list.className = "config-list";
  Object.entries(values).forEach(([key, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    term.textContent = label(key);
    const detail = document.createElement("dd");
    detail.textContent = typeof value === "boolean" ? (value ? "CONFIGURED" : "OFF") : String(value);
    if (typeof value === "boolean") detail.className = value ? "boolean-true" : "boolean-false";
    row.append(term, detail);
    list.append(row);
  });
  card.append(heading, list);
  return card;
}

async function loadConfiguration() {
  const root = byId("configuration-grid");
  if (root.dataset.loaded === "true") return;
  try {
    const config = await api("/api/configuration");
    root.replaceChildren();
    const core = { ...config };
    delete core.schema;
    delete core.memory;
    delete core.providers;
    delete core.connectors;
    root.append(
      renderConfigSection("Web boundary", core),
      renderConfigSection("Memory", config.memory),
      renderConfigSection("Providers", config.providers),
      renderConfigSection("Connectors", config.connectors),
    );
    root.dataset.loaded = "true";
  } catch (error) {
    root.replaceChildren(renderConfigSection("Configuration unavailable", { category: error.message }));
  }
}

function appendMessage(role, content, createdAt = Date.now()) {
  byId("chat-empty")?.remove();
  const item = document.createElement("article");
  item.className = `message ${role === "user" ? "user" : "assistant"}`;
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
  const meta = document.createElement("div");
  meta.className = "message-meta";
  meta.textContent = `${role === "user" ? "OPERATOR" : "MONIQUE"} · ${new Date(createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  body.append(meta);
  if (role === "user") item.append(body, avatar); else item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
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
    thread.dataset.loaded = "true";
  } catch (error) {
    byId("chat-state").textContent = `History unavailable · ${error.message}`;
  }
}

byId("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = byId("chat-input");
  const message = input.value.trim();
  if (!message) return;
  appendMessage("user", message);
  input.value = "";
  byId("chat-send").disabled = true;
  byId("chat-state").textContent = "Monique is working…";
  try {
    const answer = await api("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, profile: byId("chat-profile").value }),
    });
    appendMessage("assistant", answer.answer);
    byId("chat-memory-count").textContent = count(answer.memory_evidence);
    byId("chat-state").textContent = `${words(answer.profile)} · retained`;
  } catch (error) {
    appendMessage("assistant", `The contained conversation lane refused this turn (${error.message}).`);
    byId("chat-state").textContent = "Turn refused";
  } finally {
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
byId("new-chat").addEventListener("click", async () => {
  byId("new-chat").disabled = true;
  try {
    await api("/api/chat/new", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    byId("chat-thread").replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.id = "chat-empty";
    const mark = document.createElement("span"); mark.textContent = "M";
    const heading = document.createElement("h2"); heading.textContent = "New conversation";
    const text = document.createElement("p"); text.textContent = "The previous durable conversation was archived. Long-term memory remains available.";
    empty.append(mark, heading, text);
    byId("chat-thread").append(empty);
    byId("chat-state").textContent = "New durable session";
  } catch (error) {
    byId("chat-state").textContent = `New chat refused · ${error.message}`;
  } finally { byId("new-chat").disabled = false; }
});

refreshStatus();
showView(window.location.hash.slice(1) || "overview");
window.setInterval(() => { if (!document.hidden) refreshStatus(); }, 10_000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
