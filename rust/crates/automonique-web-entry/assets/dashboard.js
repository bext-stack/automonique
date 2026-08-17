// SPDX-License-Identifier: Elastic-2.0

"use strict";

const byId = (id) => document.getElementById(id);
const nodes = {
  statusLabel: byId("status-label"),
  statusDetail: byId("status-detail"),
  refreshLabel: byId("refresh-label"),
  lastUpdated: byId("last-updated"),
  generationKicker: byId("generation-kicker"),
  running: byId("metric-running"),
  inbox: byId("metric-inbox"),
  outbox: byId("metric-outbox"),
  reconciliation: byId("metric-reconciliation"),
  runtimeBadge: byId("runtime-badge"),
  daemon: byId("runtime-daemon"),
  provider: byId("runtime-provider"),
  intake: byId("runtime-intake"),
  execution: byId("runtime-execution"),
  telegram: byId("runtime-telegram"),
  generation: byId("runtime-generation"),
  flowIntake: byId("flow-intake"),
  flowRunning: byId("flow-running"),
  flowOutbox: byId("flow-outbox"),
  flowReconciliation: byId("flow-reconciliation"),
  footerState: byId("footer-state"),
};

const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "—";
const words = (value) => typeof value === "string" ? value.replaceAll("_", " ") : "—";
const yesNo = (value) => value === true ? "Yes" : value === false ? "No" : "—";

function render(status) {
  const health = ["operational", "degraded", "unavailable"].includes(status.health)
    ? status.health
    : "unavailable";
  document.documentElement.dataset.health = health;

  const labels = {
    operational: ["Operational", "All verified paths are clear"],
    degraded: ["Attention", status.stale ? "Showing the last verified snapshot" : "A runtime invariant needs review"],
    unavailable: ["Unavailable", "No verified runtime snapshot"],
  };
  nodes.statusLabel.textContent = labels[health][0];
  nodes.statusDetail.textContent = labels[health][1];
  nodes.runtimeBadge.textContent = status.stale ? "Snapshot stale" : labels[health][0];

  nodes.running.textContent = count(status.running);
  nodes.inbox.textContent = count(status.inbox_pending);
  nodes.outbox.textContent = count(status.outbox_pending);
  nodes.reconciliation.textContent = count(status.reconciliation_pending);
  nodes.daemon.textContent = words(status.state);
  nodes.provider.textContent = status.provider_available === true ? "Available" : status.provider_available === false ? "Unavailable" : "—";
  nodes.intake.textContent = yesNo(status.accepting_intake);
  nodes.execution.textContent = words(status.execution_state);
  nodes.telegram.textContent = words(status.telegram_state);
  nodes.generation.textContent = count(status.generation);
  nodes.generationKicker.textContent = `GEN ${count(status.generation)}`;
  nodes.flowIntake.textContent = `${count(status.inbox_pending)} pending`;
  nodes.flowRunning.textContent = `${count(status.running)} active`;
  nodes.flowOutbox.textContent = `${count(status.outbox_pending)} pending`;
  nodes.flowReconciliation.textContent = `${count(status.reconciliation_pending)} pending`;
  nodes.footerState.textContent = `${labels[health][0].toUpperCase()} / GEN ${count(status.generation)}`;

  if (Number.isSafeInteger(status.observed_ms)) {
    const observed = new Date(status.observed_ms);
    nodes.lastUpdated.dateTime = observed.toISOString();
    nodes.lastUpdated.textContent = `Observed ${observed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
  } else {
    nodes.lastUpdated.removeAttribute("datetime");
    nodes.lastUpdated.textContent = "Not yet observed";
  }
  nodes.refreshLabel.textContent = status.stale ? "Live feed interrupted" : "Live feed · 10 second refresh";
}

async function refresh() {
  try {
    const response = await fetch("/api/status", {
      cache: "no-store",
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error("status unavailable");
    render(await response.json());
  } catch (_error) {
    render({ health: "unavailable", stale: true });
  }
}

refresh();
window.setInterval(() => {
  if (!document.hidden) refresh();
}, 10_000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
});
