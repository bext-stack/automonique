// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "bun:test";
import "./platform-cockpit-core.js";

const cockpit = globalThis.AutomoniquePlatformCockpit;

const fixture = {
  schema: "automonique.cockpit/presentation/v1",
  capabilities: {
    workspace_context: true,
    workspace_actions: [{ action: "resume", workspace_id: "workspace-1", authority: "tenant.example", exact_revision: "9007199254740995" }],
  },
  projects: [{ id: "project-1", label: "Automonique" }],
  hosts: [{ id: "host-1", label: "Hosted runner" }],
  workspaces: [{
    id: "workspace-1",
    project_id: "project-1",
    host_id: "host-1",
    session_id: "session-1",
    label: "Cockpit shell",
    task: "Adapt the hosted shell",
    branch: "feat/cockpit",
    attention: "needs_you",
    revision: "9007199254740995",
    external_work: { state: "in_review", freshness: "fresh", unread: 3, reference: "issue-170" },
    internal_agent: { state: "waiting", freshness: "stale", unread: 1 },
  }],
  activities: [
    { id: "later", at: "2026-08-27T10:05:00Z", kind: "check", label: "Checks completed", source: "checks" },
    { id: "earlier", at: "2026-08-27T10:00:00Z", kind: "agent", label: "Agent paused", source: "agent", link: { workspace: "workspace-1", session: "session-1", pane: "pane-1", file: "file-1", hunk: "hunk-1", side: "head", line: "42" } },
  ],
  receipt: { state: "ambiguous", id: "receipt-1", message: "Lookup required" },
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
    capabilities: { workspace_context: true, workspace_actions: {} },
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

test("structured fixtures keep external work and internal agent signals distinct", () => {
  const view = cockpit.derivePresentation(fixture, { workspace: "workspace-1" });
  expect(view.mode).toBe("v2");
  expect(view.selectedWorkspace.external_work).toEqual({ state: "in_review", freshness: "fresh", unread: 3, observed_at: null, reference: "issue-170" });
  expect(view.selectedWorkspace.internal_agent).toEqual({ state: "waiting", freshness: "stale", unread: 1, observed_at: null, reference: null });
  expect(view.selectedWorkspace.task).toBe("Adapt the hosted shell");
  expect(view.attention.needs_you).toBe(1);
  expect(view.activities.map((item) => item.id)).toEqual(["earlier", "later"]);
  expect(view.activities[0].deep_link).toBe("#sessions?workspace=workspace-1&session=session-1&pane=pane-1&file=file-1&hunk=hunk-1&side=head&line=42");
  expect(view.receipt.state).toBe("ambiguous");
});

test("action previews require a fresh exact revision, matching action, workspace, and authority", () => {
  const view = cockpit.derivePresentation(fixture);
  expect(view.create).toEqual({ available: false, reason: "not_advertised" });
  expect(view.resume).toEqual({ available: true, action: "resume", authority: "tenant.example", exact_revision: "9007199254740995", workspace_id: "workspace-1" });
  expect(cockpit.derivePresentation({ ...fixture, stale: true }).resume).toEqual({ available: false, reason: "stale" });
  expect(cockpit.derivePresentation({ ...fixture, capabilities: { ...fixture.capabilities, workspace_actions: [{ action: "resume", workspace_id: "workspace-1", exact_revision: "2" }] } }).resume.reason).toBe("incomplete_capability");
  expect(cockpit.derivePresentation({ ...fixture, capabilities: { ...fixture.capabilities, workspace_actions: [{ action: "resume", workspace_id: "workspace-1", authority: "tenant.example", exact_revision: "9007199254740996" }] } }).resume.reason).toBe("incomplete_capability");
});

test("reducer exposes preview and typed receipt states without performing mutations", () => {
  const capability = cockpit.derivePresentation(fixture).resume;
  let state = cockpit.initialState({ workspace: "workspace-1" });
  state = cockpit.reduce(state, { type: "preview", action: "resume", capability });
  expect(state.preview).toEqual({ action: "resume", workspace_id: "workspace-1", authority: "tenant.example", exact_revision: "9007199254740995" });
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
