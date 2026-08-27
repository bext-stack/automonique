// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "bun:test";
import "./platform-cockpit-core.js";

const cockpit = globalThis.AutomoniquePlatformCockpit;

const fixture = {
  schema: "automonique.dashboard.cockpit/v2",
  mode: "v2",
  actions: {
    lifecycle: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
    review: { available: false, category: "platform_v2_review_adapter_pending" },
  },
  projects: [{ id: "project-1", label: "Automonique" }],
  hosts: [{ id: "host-1", label: "Hosted runner" }],
  workspaces: [{
    id: "workspace-1",
    project_id: "project-1",
    host_id: "host-1",
    session_id: "session-1",
    label: "Cockpit shell",
    attention: "needs_you",
    revision: "9007199254740995",
  }],
  review: { state: "available", document: { files: [], checks: [], review: { decision: "pending" }, delivery: { state: "pending" } } },
};

test("decimal fences stay exact beyond Number.MAX_SAFE_INTEGER", () => {
  expect(cockpit.validDecimal("9007199254740995", false)).toBe(true);
  expect(cockpit.decimalGreater("9007199254740996", "9007199254740995")).toBe(true);
  expect(cockpit.decimalGreater("9007199254740995", "9007199254740996")).toBe(false);
  expect(cockpit.validDecimal("09007199254740995", false)).toBe(false);
  expect(cockpit.validDecimal(9007199254740995, false)).toBe(false);
});

test("uncertain receipts reconcile without replay and known refusals settle", () => {
  expect(cockpit.receiptDirective({ state: "ambiguous" })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "pending" } })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "completed" } })).toBe("revision_fence");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "conflict" } })).toBe("settled");
  expect(cockpit.receiptDirective({ state: "refused", outcome: "conflict" })).toBe("settled");
});

test("v1 degrades explicitly and never infers workspace state from summaries", () => {
  const view = cockpit.derivePresentation({ sessions: [{ summary: "Working on branch secret with 9 unread" }] });
  expect(view.mode).toBe("v1");
  expect(view.degradation).toContain("Platform v1");
  expect(view.workspaces).toEqual([]);
  expect(view.attention.working).toBe(0);
  expect(view.resume.available).toBe(false);
});

test("malformed structured collections fail closed to unavailable presentation state", () => {
  const view = cockpit.derivePresentation({
    schema: "automonique.platform/v2",
    projects: {},
    hosts: "host/path",
    workspaces: { summary: "working" },
    activities: { label: "done" },
  });
  expect(view.projects).toEqual([]);
  expect(view.hosts).toEqual([]);
  expect(view.workspaces).toEqual([]);
  expect(view.activities).toEqual([]);
  expect(view.create.available).toBe(false);
});

test("server-owned structured fixture exposes exact selected workspace and review", () => {
  const view = cockpit.derivePresentation(fixture, { workspace: "workspace-1" });
  expect(view.mode).toBe("v2");
  expect(view.selectedWorkspace.id).toBe("workspace-1");
  expect(view.selectedWorkspace.revision).toBe("9007199254740995");
  expect(view.attention.needs_you).toBe(1);
  expect(view.readModels.files).toEqual([]);
  expect(view.readModels.review).toEqual({ decision: "pending" });
});

test("lifecycle actions remain honestly disabled at the missing host adapter seam", () => {
  const view = cockpit.derivePresentation(fixture);
  expect(view.create).toEqual({ available: false, reason: "platform_v2_lifecycle_adapter_pending" });
  expect(view.resume).toEqual({ available: false, reason: "platform_v2_lifecycle_adapter_pending" });
});

test("reducer cannot manufacture a preview from an unavailable server action", () => {
  let state = cockpit.initialState({ workspace: "workspace-1" });
  state = cockpit.reduce(state, { type: "preview", action: "resume", capability: cockpit.derivePresentation(fixture).resume });
  expect(state.preview).toBe(null);
  state = cockpit.reduce(state, { type: "receipt", receipt: { state: "pending", id: "receipt-2" } });
  expect(state.receipt.state).toBe("pending");
  state = cockpit.reduce(state, { type: "receipt", receipt: { state: "refused", message: "stale revision" } });
  expect(state.receipt.state).toBe("refused");
  state = cockpit.reduce(state, { type: "receipt", receipt: { state: "ambiguous", message: "lookup only" } });
  expect(state.receipt.state).toBe("ambiguous");
});

test("deep links preserve exact workspace session pane and complete review anchors", () => {
  const hash = cockpit.buildDeepLink({ view: "sessions", workspace: "ws/opaque", session: "s:1", pane: "pane-2", file: "file-4", hunk: "hunk-7", side: "head", line: "9007199254740995" });
  expect(hash).toBe("#sessions?workspace=ws%2Fopaque&session=s%3A1&pane=pane-2&file=file-4&hunk=hunk-7&side=head&line=9007199254740995");
  expect(cockpit.parseDeepLink(hash)).toEqual({ view: "sessions", workspace: "ws/opaque", session: "s:1", pane: "pane-2", file: "file-4", hunk: "hunk-7", side: "head", line: "9007199254740995" });
  expect(cockpit.parseDeepLink("#sessions?workspace=ws&file=f&line=3")).toEqual({ view: "sessions", workspace: "ws" });
  expect(cockpit.buildDeepLink({ view: "sessions", workspace: "ws", file: "f", line: "3" })).toBe("#sessions?workspace=ws");
});

test("desktop and mobile profiles expose deterministic keyboard and focus order", () => {
  expect(cockpit.browserProfile(1280)).toEqual({ layout: "desktop", focusOrder: ["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"], shortcuts: { workspace: "w", conversation: "c", activity: "a" } });
  expect(cockpit.browserProfile(390)).toEqual({ layout: "mobile", focusOrder: ["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"], shortcuts: { workspace: "w", conversation: "c", activity: "a" } });
});
