// SPDX-License-Identifier: Elastic-2.0

"use strict";

((root) => {
  const ATTENTION_STATES = Object.freeze(["needs_you", "working", "blocked", "done"]);
  const SURFACES = Object.freeze(["conversation", "files", "activity"]);
  const RECEIPT_STATES = Object.freeze(["idle", "pending", "refused", "ambiguous", "completed"]);
  const LINK_KEYS = Object.freeze(["workspace", "session", "pane", "file", "hunk", "side", "line"]);

  function validDecimal(value, allowZero = true) {
    return typeof value === "string"
      && /^(0|[1-9][0-9]*)$/.test(value)
      && (allowZero || value !== "0");
  }

  function decimalGreater(left, right) {
    if (!validDecimal(left) || !validDecimal(right)) return false;
    return left.length !== right.length ? left.length > right.length : left > right;
  }

  function boundedText(value, maximum = 256) {
    return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : null;
  }

  function explicitEnum(value, values) {
    return values.includes(value) ? value : null;
  }

  function receiptDirective(view) {
    if (!view || view.state === "ambiguous") return "reconcile";
    if (view.state === "refused") return "settled";
    if (view.state !== "receipt") return "invalid";
    const receipt = view.receipt || {};
    if (receipt.lifecycle === "ambiguous" || receipt.lifecycle === "pending") return "reconcile";
    if (receipt.lifecycle === "refused" || ["rejected", "conflict"].includes(receipt.outcome)) return "settled";
    return receipt.lifecycle === "terminal" ? "revision_fence" : "invalid";
  }

  function normalizeReceipt(value) {
    const state = explicitEnum(value?.state, RECEIPT_STATES) || "idle";
    return Object.freeze({
      state,
      id: boundedText(value?.id, 256),
      message: boundedText(value?.message, 512),
      outcome: boundedText(value?.outcome, 64),
    });
  }

  function normalizeSignal(value, states) {
    if (!value || typeof value !== "object") return null;
    const state = explicitEnum(value.state, states);
    const freshness = explicitEnum(value.freshness, ["fresh", "stale", "unknown"]);
    if (!state || !freshness) return null;
    return Object.freeze({
      state,
      freshness,
      unread: Number.isSafeInteger(value.unread) && value.unread >= 0 ? value.unread : null,
      observed_at: boundedText(value.observed_at, 64),
      reference: boundedText(value.reference, 256),
    });
  }

  function normalizeWorkspace(value) {
    if (!value || typeof value !== "object") return null;
    const id = boundedText(value.id, 256);
    if (!id) return null;
    return Object.freeze({
      id,
      project_id: boundedText(value.project_id, 256),
      host_id: boundedText(value.host_id, 256),
      session_id: boundedText(value.session_id, 256),
      label: boundedText(value.label, 256) || id,
      task: boundedText(value.task, 2048),
      branch: boundedText(value.branch, 512),
      attention: explicitEnum(value.attention, ATTENTION_STATES),
      external_work: normalizeSignal(value.external_work, ["open", "in_review", "merged", "closed", "unknown"]),
      internal_agent: normalizeSignal(value.internal_agent, ["idle", "queued", "running", "waiting", "failed", "completed", "unknown"]),
      revision: validDecimal(value.revision, false) ? value.revision : null,
    });
  }

  function normalizeNamed(value) {
    const id = boundedText(value?.id, 256);
    return id ? Object.freeze({ id, label: boundedText(value?.label, 256) || id }) : null;
  }

  function normalizeActivity(value) {
    const id = boundedText(value?.id, 256);
    const at = boundedText(value?.at, 64);
    const kind = boundedText(value?.kind, 64);
    if (!id || !at || !kind) return null;
    const linkedWorkspace = boundedText(value?.link?.workspace, 256);
    return Object.freeze({
      id,
      at,
      kind,
      label: boundedText(value?.label, 512) || kind,
      source: boundedText(value?.source, 64),
      deep_link: linkedWorkspace ? buildDeepLink({ view: "sessions", ...value.link }) : null,
    });
  }

  function mutationCapability(document) {
    const lifecycle = document?.actions?.lifecycle;
    return Object.freeze({
      available: false,
      reason: boundedText(lifecycle?.category, 128) || "platform_v2_lifecycle_adapter_pending",
    });
  }

  function derivePresentation(document, selection = {}) {
    // Only the authenticated server-owned cockpit projection is accepted.
    // Raw Platform v2 documents and retained-session summaries never become
    // browser-inferred workspaces.
    const structured = document?.schema === "automonique.dashboard.cockpit/v2";
    const projects = structured && Array.isArray(document.projects) ? document.projects.map(normalizeNamed).filter(Boolean) : [];
    const hosts = structured && Array.isArray(document.hosts) ? document.hosts.map(normalizeNamed).filter(Boolean) : [];
    const workspaces = structured && Array.isArray(document.workspaces) ? document.workspaces.map(normalizeWorkspace).filter(Boolean) : [];
    const workspaceId = boundedText(selection.workspace, 256) || boundedText(document?.selected?.workspace, 256);
    const sessionId = boundedText(selection.session, 256) || boundedText(document?.selected?.session, 256);
    const selectedWorkspace = workspaces.find((item) => item.id === workspaceId)
      || workspaces.find((item) => item.session_id === sessionId)
      || workspaces[0]
      || null;
    const mode = structured && document.mode === "v2" ? "v2" : "v1";
    const degradation = mode === "v2"
      ? null
      : `Platform v1: workspace context is unavailable (${boundedText(document?.degradation?.category, 128) || "Platform v2 unavailable"}). Retained sessions remain available.`;
    const activities = structured && Array.isArray(document.activities)
      ? document.activities.map(normalizeActivity).filter(Boolean).sort((left, right) => left.at.localeCompare(right.at) || left.id.localeCompare(right.id))
      : [];
    return Object.freeze({
      mode,
      degradation,
      stale: false,
      projects: Object.freeze(projects),
      hosts: Object.freeze(hosts),
      workspaces: Object.freeze(workspaces),
      selectedWorkspace,
      attention: Object.freeze(Object.fromEntries(ATTENTION_STATES.map((state) => [state, workspaces.filter((item) => item.attention === state).length]))),
      activities: Object.freeze(activities),
      receipt: normalizeReceipt(document?.receipt),
      create: mutationCapability(document),
      resume: mutationCapability(document),
      readModels: Object.freeze({
        files: Array.isArray(document?.review?.document?.files) ? document.review.document.files : null,
        review: document?.review?.document?.review && typeof document.review.document.review === "object" ? document.review.document.review : null,
        checks: Array.isArray(document?.review?.document?.checks) ? document.review.document.checks : null,
        delivery: document?.review?.document?.delivery && typeof document.review.document.delivery === "object" ? document.review.document.delivery : null,
      }),
    });
  }

  function cleanLinkValue(value, maximum = 512) {
    return typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value) ? value : null;
  }

  function parseDeepLink(hash) {
    const source = typeof hash === "string" ? hash.replace(/^#/, "") : "";
    const [rawView, rawQuery = ""] = source.split("?", 2);
    const allowed = ["overview", "sessions", "chat", "operations", "tickets", "memory", "configuration"];
    const result = { view: allowed.includes(rawView) ? rawView : "sessions" };
    const params = new URLSearchParams(rawQuery);
    LINK_KEYS.forEach((key) => {
      const value = cleanLinkValue(params.get(key));
      if (value) result[key] = value;
    });
    const anchorComplete = result.file && result.hunk && ["base", "head"].includes(result.side) && validDecimal(result.line, false);
    if (!anchorComplete) ["file", "hunk", "side", "line"].forEach((key) => delete result[key]);
    return Object.freeze(result);
  }

  function buildDeepLink(link) {
    const params = new URLSearchParams();
    ["workspace", "session", "pane"].forEach((key) => {
      const value = cleanLinkValue(link?.[key]);
      if (value) params.set(key, value);
    });
    const anchorComplete = cleanLinkValue(link?.file) && cleanLinkValue(link?.hunk)
      && ["base", "head"].includes(link?.side) && validDecimal(link?.line, false);
    if (anchorComplete) ["file", "hunk", "side", "line"].forEach((key) => params.set(key, link[key]));
    const query = params.toString();
    return `#sessions${query ? `?${query}` : ""}`;
  }

  function initialState(link = {}) {
    return Object.freeze({
      selection: Object.freeze({
        workspace: boundedText(link.workspace, 256),
        session: boundedText(link.session, 256),
        pane: boundedText(link.pane, 256),
      }),
      surface: explicitEnum(link.surface, SURFACES) || "conversation",
      attentionFilter: "all",
      receipt: normalizeReceipt(null),
      preview: null,
    });
  }

  function reduce(state, event) {
    const current = state || initialState();
    if (!event || typeof event !== "object") return current;
    if (event.type === "select_workspace" && boundedText(event.workspace, 256)) {
      return Object.freeze({ ...current, selection: Object.freeze({ ...current.selection, workspace: event.workspace }), preview: null });
    }
    if (event.type === "select_session" && boundedText(event.session, 256)) {
      return Object.freeze({ ...current, selection: Object.freeze({ ...current.selection, session: event.session }) });
    }
    if (event.type === "show_surface" && SURFACES.includes(event.surface)) return Object.freeze({ ...current, surface: event.surface });
    if (event.type === "filter_attention" && (event.attention === "all" || ATTENTION_STATES.includes(event.attention))) {
      return Object.freeze({ ...current, attentionFilter: event.attention });
    }
    if (event.type === "preview" && ["create", "resume"].includes(event.action) && event.capability?.available === true) {
      return Object.freeze({ ...current, preview: Object.freeze({
        action: event.action,
        workspace_id: event.capability.workspace_id,
        authority: event.capability.authority,
        exact_revision: event.capability.exact_revision,
      }) });
    }
    if (event.type === "receipt") return Object.freeze({ ...current, receipt: normalizeReceipt(event.receipt) });
    return current;
  }

  function browserProfile(width) {
    const mobile = Number.isFinite(width) && width <= 760;
    return Object.freeze({
      layout: mobile ? "mobile" : "desktop",
      focusOrder: Object.freeze(["workspace-navigation", "workspace-summary", "workspace-inspector", "conversation"]),
      shortcuts: Object.freeze({ workspace: "w", conversation: "c", activity: "a" }),
    });
  }

  root.AutomoniquePlatformCockpit = Object.freeze({
    ATTENTION_STATES,
    browserProfile,
    buildDeepLink,
    decimalGreater,
    derivePresentation,
    initialState,
    parseDeepLink,
    receiptDirective,
    reduce,
    validDecimal,
  });
})(globalThis);
