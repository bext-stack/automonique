// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "bun:test";
import "./platform-cockpit-core.js";

const cockpit = globalThis.AutomoniquePlatformCockpit;
const renderCorpus = JSON.parse(await Bun.file(new URL(
  "../../automonique-protocol/fixtures/platform-v2-render-conformance-v1.json",
  import.meta.url,
)).text());

const completeCollection = (items, sources) => ({
  state: "complete",
  items,
  total: String(items.length),
  omitted: "0",
  sources: Object.fromEntries(sources.map((name) => [name, { state: "available" }])),
});

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
    attempts: [{
      id: "attempt-1", label: "Attempt 1", revision: "2", lifecycle: "running",
      sessions: [{
        id: "runtime-session-1", label: "Session 1", revision: "3", lifecycle: "active",
        platform_session_id: "session-1",
        panes: [{ id: "pane-1", label: "Pane 1", revision: "4", lifecycle: "active" }],
      }],
    }],
    label: "Cockpit shell",
    attention: "needs_you",
    revision: "9007199254740995",
  }],
  lineage: { state: "available", document: { value: { external_work_items: [], orchestration: [] } } },
  review: { state: "available", document: {
    revision: "9007199254740995",
    attention: { state: "needs_you", reason: "review_requested", unread: "1", source_revision: "7" },
    files: [],
    checks: [{ id: "check-1", state: "passed", required: true, freshness: { state: "fresh", observed_revision: "7" } }],
    review: { decision: "pending", freshness: { state: "fresh", observed_revision: "8" } },
    pull_request: { state: "open", readiness: "ready", freshness: { state: "fresh", observed_revision: "8" } },
    delivery: { state: "pending", freshness: { state: "fresh", observed_revision: "7" } },
  } },
  attention: { state: "available", known_workspaces: "1", total_workspaces: "1" },
  activities: completeCollection([], ["lineage", "review"]),
  inbox: completeCollection([], ["attention"]),
};

test("decimal fences stay exact beyond Number.MAX_SAFE_INTEGER", () => {
  expect(cockpit.validDecimal("9007199254740995", false)).toBe(true);
  expect(cockpit.decimalGreater("9007199254740996", "9007199254740995")).toBe(true);
  expect(cockpit.decimalGreater("9007199254740995", "9007199254740996")).toBe(false);
  expect(cockpit.validDecimal("09007199254740995", false)).toBe(false);
  expect(cockpit.validDecimal(9007199254740995, false)).toBe(false);
});

test("shared render corpus projects every exact hosted semantic without revision loss", () => {
  expect(renderCorpus.schema).toBe("automonique.render-conformance/v1");
  expect(renderCorpus.cases.map(({ id }) => id)).toEqual(["idle", "needs_you", "working", "blocked", "done"]);
  for (const fixtureCase of renderCorpus.cases) {
    expect(cockpit.projectReviewSemantics(fixtureCase.input)).toEqual(fixtureCase.expected);
    expect(cockpit.projectReviewSemantics(fixtureCase.input).source_revision).toBe(fixtureCase.input.revision);
  }
});

test("semantic projector refuses numeric, future, and unknown review truth", () => {
  const baseline = structuredClone(renderCorpus.cases[1].input);
  expect(cockpit.projectReviewSemantics({ ...baseline, revision: 9007199254741011 })).toBeNull();
  expect(cockpit.projectReviewSemantics({
    ...baseline,
    review: { ...baseline.review, freshness: { ...baseline.review.freshness, observed_revision: "9007199254741012" } },
  })).toBeNull();
  expect(cockpit.projectReviewSemantics({
    ...baseline,
    pull_request: { ...baseline.pull_request, state: "secret_provider_state" },
  })).toBeNull();
});

test("uncertain receipts reconcile without replay and known refusals settle", () => {
  expect(cockpit.receiptDirective({ state: "ambiguous" })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "pending" } })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "completed" } })).toBe("revision_fence");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "conflict" } })).toBe("settled");
  expect(cockpit.receiptDirective({ state: "refused", outcome: "conflict" })).toBe("settled");
});

test("durable cockpit handles are persisted before send and reload is lookup-only", () => {
  const capability = {
    available: true,
    family: "workspace_intent",
    project_id: "project-1",
    workspace_id: "workspace-1",
  };
  const handle = cockpit.prepareControlHandle(capability, "create", "intent-1");
  expect(handle).toEqual({
    version: 1,
    family: "workspace_intent",
    action: "create",
    project_id: "project-1",
    workspace_id: "workspace-1",
    receipt_id: "intent-1",
  });
  const restored = cockpit.parseControlHandle(cockpit.serializeControlHandle(handle));
  expect(restored).toEqual(handle);
  expect(cockpit.controlRecoveryDirective(restored)).toBe("lookup_only");
  expect(cockpit.controlRecoveryDirective(null)).toBe("may_submit");
});

test("malformed or cross-field-expanded durable handles fail closed", () => {
  expect(cockpit.parseControlHandle('{"family":"workspace_intent"}')).toBeNull();
  expect(cockpit.parseControlHandle(JSON.stringify({
    family: "generic_execute",
    action: "shell",
    project_id: "project-1",
    workspace_id: "workspace-1",
    receipt_id: "receipt-1",
  }))).toBeNull();
  expect(cockpit.prepareControlHandle({ available: false }, "create", "intent-1")).toBeNull();
});

test("typed workspace and review controls require exact server operations and fresh complete mode", () => {
  const controlled = structuredClone(fixture);
  controlled.actions.lifecycle.operations = {
    create_attempt_workspace: {
      available: true,
      submit_operation: "submit_workspace_intent",
      receipt_operation: "get_workspace_intent",
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "9007199254740995",
      task_id: "task-1",
      external_work: { provider: "github", authority: "github.com", scope: "owner/repo", key: "42" },
    },
    resume_attempt_workspace: {
      available: true,
      submit_operation: "submit_workspace_intent",
      receipt_operation: "get_workspace_intent",
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "9007199254740995",
      task_id: "task-1",
    },
  };
  controlled.actions.review = { operations: {
    add_comment: {
      available: true,
      execute_operation: "execute_review_action",
      receipt_operation: "get_review_receipt",
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "7",
    },
    approve_review: {
      available: true,
      execute_operation: "execute_review_action",
      receipt_operation: "get_review_receipt",
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "7",
      exact_review_revision: "6",
    },
    rerun_check: {
      available: true,
      execute_operation: "rerun_check",
      receipt_operation: "get_review_receipt",
      targets: [{
        project_id: "project-1",
        workspace_id: "workspace-1",
        exact_revision: "7",
        check_id: "check-ci-1",
        exact_check_revision: "5",
        confirmation_digest: "ab".repeat(32),
        receipt_correlation_digest: "cd".repeat(32),
      }],
    },
  } };
  const view = cockpit.derivePresentation(controlled);
  expect(view.create.available).toBe(true);
  expect(view.create.project_id).toBe("project-1");
  expect(view.resume.available).toBe(true);
  expect(view.reviewActions.addComment.available).toBe(true);
  expect(view.reviewActions.approveReview.exact_review_revision).toBe("6");
  expect(view.reviewActions.rerunCheck.available).toBe(true);
  expect(view.reviewActions.rerunCheck.targets[0].check_id).toBe("check-ci-1");
  expect(view.reviewActions.rerunCheck.targets[0].confirmation_digest).toBe("ab".repeat(32));
  expect(view.reviewActions.rerunCheck.targets[0].receipt_correlation_digest).toBe("cd".repeat(32));

  const rerunHandle = cockpit.prepareControlHandle(
    view.reviewActions.rerunCheck,
    "rerunCheck",
    "receipt-rerun-1",
    view.reviewActions.rerunCheck.targets[0].receipt_correlation_digest,
  );
  expect(cockpit.parseControlHandle(cockpit.serializeControlHandle(rerunHandle))).toEqual(rerunHandle);
  expect(rerunHandle.receipt_correlation_digest).toBe("cd".repeat(32));
  expect(cockpit.prepareControlHandle(
    view.reviewActions.rerunCheck,
    "rerunCheck",
    "receipt-rerun-2",
  )).toBeNull();

  const substitutedCheckRevision = structuredClone(controlled);
  substitutedCheckRevision.actions.review.operations.rerun_check.targets.push({
    ...substitutedCheckRevision.actions.review.operations.rerun_check.targets[0],
    exact_check_revision: "6",
  });
  expect(cockpit.derivePresentation(substitutedCheckRevision).reviewActions.rerunCheck.available).toBe(false);
  const malformedConfirmation = structuredClone(controlled);
  malformedConfirmation.actions.review.operations.rerun_check.targets[0].confirmation_digest = "forged";
  expect(cockpit.derivePresentation(malformedConfirmation).reviewActions.rerunCheck.available).toBe(false);
  const missingCorrelation = structuredClone(controlled);
  delete missingCorrelation.actions.review.operations.rerun_check.targets[0].receipt_correlation_digest;
  expect(cockpit.derivePresentation(missingCorrelation).reviewActions.rerunCheck.available).toBe(false);

  const missingExternal = structuredClone(controlled);
  delete missingExternal.actions.lifecycle.operations.create_attempt_workspace.external_work;
  expect(cockpit.derivePresentation(missingExternal).create.available).toBe(false);
  const missingTask = structuredClone(controlled);
  delete missingTask.actions.lifecycle.operations.resume_attempt_workspace.task_id;
  expect(cockpit.derivePresentation(missingTask).resume.available).toBe(false);

  controlled.review.document.review.freshness.state = "stale";
  const stale = cockpit.derivePresentation(controlled);
  expect(stale.create.available).toBe(false);
  expect(stale.reviewActions.approveReview.available).toBe(false);
  expect(stale.create.reason).toBe("platform_cockpit_projection_incomplete_or_stale");
});

// The other half of issue #224. The server no longer projects a family this
// browser cannot execute; this holds the client to the same rule from its own
// side, so a projection that regrew one could still not conjure a control.
test("the browser review surface stays closed against families it has no reader for", () => {
  const controlled = structuredClone(fixture);
  controlled.actions.review = {
    available: true,
    operations: {
      add_comment: {
        available: true,
        execute_operation: "execute_review_action",
        receipt_operation: "get_review_receipt",
        project_id: "project-1",
        workspace_id: "workspace-1",
        exact_revision: "7",
      },
    },
    families_without_browser_command: [
      "send_comment_to_agent", "batch_send_comments_to_agent", "stage", "unstage",
      "commit", "resolve_conflict", "open_pull_request", "update_pull_request",
      "merge_pull_request",
    ],
  };
  const commanded = Object.keys(cockpit.derivePresentation(controlled).reviewActions);
  expect(commanded).toContain("addComment");

  // A server advertising the uncommanded families anyway - the projection this
  // cockpit carried until #224 - changes nothing here: no control appears, and
  // no confirmation it could never spend reaches the read model.
  const advertised = structuredClone(controlled);
  advertised.actions.review.families_without_browser_command = [];
  advertised.actions.review.operations.merge_pull_request = {
    available: true,
    execute_operation: "merge_pull_request",
    receipt_operation: "get_review_receipt",
    targets: [{
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "7",
      pull_request_id: "pr-1",
      expected_head_revision: "0123456789abcdef",
      readiness: "ready",
      confirmation_digest: "ef".repeat(32),
      receipt_correlation_digest: "ba".repeat(32),
    }],
  };
  advertised.actions.review.operations.send_comment_to_agent = {
    available: true,
    execute_operation: "send_comment_to_agent",
    receipt_operation: "get_review_receipt",
    targets: [{
      project_id: "project-1",
      workspace_id: "workspace-1",
      exact_revision: "7",
      comment_id: "comment-1",
      exact_comment_revision: "2",
    }],
  };
  const view = cockpit.derivePresentation(advertised);
  expect(Object.keys(view.reviewActions)).toEqual(commanded);
  const rendered = JSON.stringify(view);
  expect(rendered).not.toContain("merge_pull_request");
  expect(rendered).not.toContain("send_comment_to_agent");
  expect(rendered).not.toContain("ef".repeat(32));
});

test("v1 degrades explicitly and never infers workspace state from summaries", () => {
  const view = cockpit.derivePresentation({ sessions: [{ summary: "Working on branch secret with 9 unread" }] });
  expect(view.mode).toBe("v1");
  expect(view.degradation).toContain("Platform v1");
  expect(view.workspaces).toEqual([]);
  expect(view.attention.working).toBe(null);
  expect(view.activityCoverage.state).toBe("unavailable");
  expect(view.inboxCoverage.state).toBe("unavailable");
  expect(view.resume.available).toBe(false);
});

test("negotiated v2 unavailability stays partial and never masquerades as v1", () => {
  const view = cockpit.derivePresentation({
    schema: "automonique.dashboard.cockpit/v2",
    mode: "partial",
    degradation: { platform: "v2", state: "unavailable", category: "platform_v2_inventory_resync_required" },
    retained_v1: { sessions: [{ summary: "retained only" }] },
    projects: [], hosts: [], workspaces: [],
    attention: { state: "unavailable", category: "platform_v2_unavailable" },
    actions: { lifecycle: { available: false }, review: { available: false } },
  });
  expect(view.mode).toBe("partial");
  expect(view.degradation).toContain("platform_v2_inventory_resync_required");
  expect(view.workspaces).toEqual([]);
  expect(view.create.available).toBe(false);
});

test("attempt session and pane hierarchy preserves siblings without overwrite", () => {
  const nested = structuredClone(fixture);
  nested.workspaces[0].attempts[0].sessions.push({
    id: "runtime-session-2", label: "Session 2", revision: "5", lifecycle: "active",
    platform_session_id: "session-2",
    panes: [
      { id: "pane-2", label: "Pane 2", revision: "6", lifecycle: "active" },
      { id: "pane-3", label: "Pane 3", revision: "7", lifecycle: "closed" },
    ],
  });
  const view = cockpit.derivePresentation(nested, { session: "session-2", pane: "pane-3" });
  expect(view.selectedWorkspace.id).toBe("workspace-1");
  expect(view.selectedWorkspace.session_id).toBeNull();
  expect(view.selectedWorkspace.session_ids).toEqual(["session-1", "session-2"]);
  expect(view.selectedWorkspace.attempts[0].sessions[1].panes.map((pane) => pane.id)).toEqual(["pane-2", "pane-3"]);
});

test("workspace lineage preserves exact external moves, origin, and orchestration parent meaning", () => {
  const lineage = structuredClone(fixture);
  const origin = { workspace: "workspace-1", attempt: "attempt-1", session: "runtime-session-1", pane: "pane-1" };
  lineage.workspaces[0].lineage = {
    external_work_items: [{
      identity: { provider: "github", authority: "github.com", scope: "owner/repo", key: "41" },
      moved_to: { provider: "github", authority: "github.com", scope: "owner/repo", key: "42" },
      state: "moved", freshness: "fresh", origin, revision: "8", observed_at: "100", latest_message: "Moved",
    }],
    orchestration: [{
      kind: "task", id: "task-42", status: "blocked", status_message: "Awaiting review",
      freshness: "fresh", origin, parent: { kind: "run", id: "run-1" },
      external_work: { provider: "github", authority: "github.com", scope: "owner/repo", key: "42" },
      revision: "9", observed_at: "101", latest_message: null,
    }],
  };
  const view = cockpit.derivePresentation(lineage, { pane: "pane-1" });
  expect(view.selectedWorkspace.lineage.external_work_items[0].moved_to.key).toBe("42");
  expect(view.selectedWorkspace.lineage.external_work_items[0].origin.pane).toBe("pane-1");
  expect(view.selectedWorkspace.lineage.orchestration[0].parent).toEqual({ kind: "run", id: "run-1" });
  expect(view.selectedWorkspace.lineage.orchestration[0].status_message).toBe("Awaiting review");

  lineage.workspaces[0].lineage.orchestration = Array.from({ length: 129 }, () => lineage.workspaces[0].lineage.orchestration[0]);
  expect(cockpit.derivePresentation(lineage).selectedWorkspace.lineage).toBeNull();
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
  expect(view.inbox).toEqual([]);
  expect(view.activityCoverage.state).toBe("unavailable");
  expect(view.inboxCoverage.state).toBe("unavailable");
  expect(view.create.available).toBe(false);
});

test("activity and inbox keep lossless chronology and exact deep links", () => {
  const view = cockpit.derivePresentation({
    ...fixture,
    activities: completeCollection([
      {
        id: "older",
        at: "9007199254740995",
        kind: "task",
        label: "Task working",
        source: "orchestration",
        freshness: "fresh",
        source_revision: "8",
        link: { workspace: "workspace-1", session: "runtime-session-1", pane: "pane-1" },
      },
      {
        id: "newer",
        at: "9007199254740997",
        kind: "review",
        label: "Review pending",
        source: "review",
        freshness: "stale",
        source_revision: "9",
        link: { workspace: "workspace-1" },
      },
    ], ["lineage", "review"]),
    inbox: completeCollection([
      {
        id: "attention-comment",
        state: "needs_you",
        reason: "comment_reply",
        source_kind: "review",
        source_id: "workspace-1",
        item_revision: "7",
        observed_at_ms: "9007199254740997",
        source_revision: "2",
        unread: "1",
        link: { workspace: "workspace-1" },
      },
      {
        id: "older-independent-source",
        state: "blocked",
        reason: "external_blocker",
        source_kind: "orchestration",
        source_id: "workspace-1",
        item_revision: "9007199254740996",
        observed_at_ms: "1",
        source_revision: "9007199254740996",
        unread: "0",
        link: { workspace: "workspace-1" },
      },
    ], ["attention"]),
  });
  expect(view.activities.map(({ id }) => id)).toEqual(["newer", "older"]);
  expect(view.activities[1].deep_link).toBe(
    "#sessions?workspace=workspace-1&session=runtime-session-1&pane=pane-1",
  );
  expect(view.inbox[0].id).toBe("attention-comment");
  expect(view.inbox[0].source_revision).toBe("2");
  expect(view.inbox[0].deep_link).toBe("#sessions?workspace=workspace-1");

  const fullInbox = Array.from({ length: 256 }, (_, index) => ({
    id: `attention-${index}`,
    state: "needs_you",
    reason: "comment_reply",
    source_kind: "review",
    source_id: "workspace-1",
    item_revision: String(index + 1),
    observed_at_ms: String(index + 1),
    source_revision: String(index + 1),
    unread: "1",
    link: { workspace: "workspace-1" },
  }));
  const bounded = cockpit.derivePresentation({
    ...fixture,
    activities: {
      state: "partial",
      items: Array.from({ length: 256 }, (_, index) => ({
        id: `activity-${index}`,
        at: "1",
        kind: "review",
        freshness: "fresh",
        source_revision: "1",
        link: { workspace: "workspace-1" },
      })),
      total: "259",
      omitted: "3",
      sources: { lineage: { state: "available" }, review: { state: "available" } },
    },
    inbox: completeCollection(fullInbox, ["attention"]),
  });
  expect(bounded.activities).toHaveLength(256);
  expect(bounded.activityCoverage).toMatchObject({ state: "partial", total: "259", omitted: "3" });
  expect(bounded.inbox).toHaveLength(256);
  expect(bounded.inboxCoverage).toMatchObject({ state: "complete", total: "256", omitted: "0" });

  const unavailable = cockpit.derivePresentation({
    ...fixture,
    activities: {
      state: "partial", items: [], total: "0", omitted: "0",
      sources: { lineage: { state: "available" }, review: { state: "refused", category: "review_refused" } },
    },
    inbox: {
      state: "unavailable", items: [], total: "0", omitted: "0",
      sources: { attention: { state: "refused", category: "attention_refused" } },
    },
  });
  expect(unavailable.activityCoverage.state).toBe("partial");
  expect(unavailable.activityCoverage.sources.review.category).toBe("review_refused");
  expect(unavailable.inboxCoverage.state).toBe("unavailable");
});

test("server-owned structured fixture exposes exact selected workspace and review", () => {
  const view = cockpit.derivePresentation(fixture, { workspace: "workspace-1" });
  expect(view.mode).toBe("v2");
  expect(view.selectedWorkspace.id).toBe("workspace-1");
  expect(view.selectedWorkspace.revision).toBe("9007199254740995");
  expect(view.attention.needs_you).toBe(1);
  expect(view.readModels.files).toEqual([]);
  expect(view.readModels.review.decision).toBe("pending");
});

test("attention counts remain inventory-wide across several structured workspaces", () => {
  const view = cockpit.derivePresentation({
    ...fixture,
    workspaces: [
      ...fixture.workspaces,
      { id: "workspace-2", label: "Blocked work", revision: "2", attention: "blocked" },
      { id: "workspace-3", label: "Background work", revision: "3", attention: "working" },
      { id: "workspace-4", label: "Quiet work", revision: "4", attention: "idle" },
    ],
    attention: { state: "available", known_workspaces: "4", total_workspaces: "4" },
  });
  expect(view.mode).toBe("v2");
  expect(view.attention).toEqual({ needs_you: 1, working: 1, blocked: 1, done: 0 });
  expect(view.workspaces.find((workspace) => workspace.id === "workspace-4").attention).toBe("idle");
});

test("partial lineage or review refusal never claims complete v2 capability", () => {
  const lineageRefused = cockpit.derivePresentation({
    ...fixture,
    lineage: { state: "refused", category: "lineage_authority_refused" },
  });
  expect(lineageRefused.mode).toBe("partial");
  expect(lineageRefused.degradation).toContain("lineage_authority_refused");

  const reviewRefused = cockpit.derivePresentation({
    ...fixture,
    review: { state: "refused", category: "review_authority_refused" },
    attention: { state: "partial", category: "platform_v2_attention_partial" },
  });
  expect(reviewRefused.mode).toBe("partial");
  expect(reviewRefused.degradation).toContain("review_authority_refused");
  expect(reviewRefused.degradation).toContain("platform_v2_attention_partial");
  expect(reviewRefused.attentionAvailable).toBe(false);
  expect(reviewRefused.attention.needs_you).toBe(null);
});

test("stale canonical subprojections make the cockpit explicitly stale and read-only", () => {
  const view = cockpit.derivePresentation({
    ...fixture,
    review: {
      state: "available",
      document: {
        ...fixture.review.document,
        review: { decision: "pending", freshness: { state: "stale" } },
      },
    },
  });
  expect(view.mode).toBe("v2");
  expect(view.stale).toBe(true);
  expect(view.create.available).toBe(false);
  expect(view.resume.available).toBe(false);
});

test("lifecycle actions remain honestly disabled at the missing host adapter seam", () => {
  const view = cockpit.derivePresentation(fixture);
  expect(view.create.available).toBe(false);
  expect(view.create.reason).toBe("platform_v2_lifecycle_adapter_pending");
  expect(view.resume.available).toBe(false);
  expect(view.localLifecycle.createHostSetup.available).toBe(false);
  expect(view.localLifecycle.createCheckout.available).toBe(false);
});

test("installed adapter exposes only local host and checkout preview/receipt operations", () => {
  const view = cockpit.derivePresentation({
    ...fixture,
    actions: {
      ...fixture.actions,
      lifecycle: {
        available: true,
        operations: {
          create_host_setup: { available: true, scope: "local", preview_operation: "prepare_mutation", receipt_operation: "get_mutation_receipt" },
          create_checkout: { available: true, scope: "local", preview_operation: "prepare_mutation", receipt_operation: "get_mutation_receipt" },
          create_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
          resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
          resume_session: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
        },
      },
    },
  });
  expect(view.localLifecycle.createHostSetup).toEqual({
    available: true,
    reason: null,
    scope: "local",
    preview_operation: "prepare_mutation",
    receipt_operation: "get_mutation_receipt",
  });
  expect(view.localLifecycle.createCheckout.available).toBe(true);
  expect(view.create.available).toBe(false);
  expect(view.resume.available).toBe(false);
});

test("lifecycle status preserves each exact daemon-issued unavailable category", () => {
  const view = cockpit.derivePresentation({
    ...fixture,
    actions: {
      ...fixture.actions,
      lifecycle: {
        available: false,
        operations: {
          create_host_setup: { available: false, category: "platform_v2_lifecycle_path_insecure" },
          create_checkout: { available: false, category: "platform_v2_local_checkout_selector_unavailable" },
          create_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
          resume_attempt_workspace: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
          resume_session: { available: false, category: "platform_v2_lifecycle_adapter_pending" },
        },
      },
    },
  });
  expect(cockpit.lifecycleStatus(view.localLifecycle)).toEqual({
    state: "unavailable",
    message: "Task create and resume remain unavailable. Local host setup unavailable (platform_v2_lifecycle_path_insecure). Local checkout unavailable (platform_v2_local_checkout_selector_unavailable).",
  });
});

test("partial lifecycle status names only the unavailable action's fenced registry category", () => {
  const status = cockpit.lifecycleStatus({
    createHostSetup: { available: true, reason: null },
    createCheckout: { available: false, reason: "platform_v2_lifecycle_registry_changed" },
  });
  expect(status.state).toBe("partial");
  expect(status.message).toContain("Local host setup supports typed preview and receipt operations.");
  expect(status.message).toContain("Local checkout unavailable (platform_v2_lifecycle_registry_changed).");
  expect(status.message).not.toContain("adapter is not installed");
  expect(status.message).not.toContain("platform_v2_lifecycle_adapter_pending");
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
  const hash = cockpit.buildDeepLink({ view: "sessions", workspace: "ws/opaque", session: "s:1", pane: "pane-2", file: "file-4", hunk: "hunk-7", side: "new", line: "9007199254740995" });
  expect(hash).toBe("#sessions?workspace=ws%2Fopaque&session=s%3A1&pane=pane-2&file=file-4&hunk=hunk-7&side=new&line=9007199254740995");
  expect(cockpit.parseDeepLink(hash)).toEqual({ view: "sessions", workspace: "ws/opaque", session: "s:1", pane: "pane-2", file: "file-4", hunk: "hunk-7", side: "new", line: "9007199254740995" });
  expect(cockpit.parseDeepLink("#sessions?workspace=ws&file=f&hunk=h&side=head&line=3")).toEqual({ view: "sessions", workspace: "ws" });
  expect(cockpit.parseDeepLink("#sessions?workspace=ws&file=f&line=3")).toEqual({ view: "sessions", workspace: "ws" });
  expect(cockpit.buildDeepLink({ view: "sessions", workspace: "ws", file: "f", line: "3" })).toBe("#sessions?workspace=ws");
});

test("desktop and mobile profiles expose deterministic keyboard and focus order", () => {
  expect(cockpit.browserProfile(1280)).toEqual({ layout: "desktop", focusOrder: ["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"], shortcuts: { workspace: "w", conversation: "c", activity: "a" } });
  expect(cockpit.browserProfile(390)).toEqual({ layout: "mobile", focusOrder: ["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"], shortcuts: { workspace: "w", conversation: "c", activity: "a" } });
});
