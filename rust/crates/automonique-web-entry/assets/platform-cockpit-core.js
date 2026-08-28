// SPDX-License-Identifier: Elastic-2.0

"use strict";

((root) => {
  const ATTENTION_STATES = Object.freeze(["needs_you", "working", "blocked", "done"]);
  const WORKSPACE_ATTENTION_STATES = Object.freeze(["idle", ...ATTENTION_STATES]);
  const SURFACES = Object.freeze(["conversation", "files", "activity"]);
  const RECEIPT_STATES = Object.freeze(["idle", "pending", "refused", "ambiguous", "completed"]);
  const CONTROL_FAMILIES = Object.freeze(["workspace_intent", "review_action"]);
  const LINK_KEYS = Object.freeze(["workspace", "session", "pane", "file", "hunk", "side", "line"]);
  const MAX_LINEAGE_RECORDS = 128;
  const MAX_ACTIVITIES = 256;
  const MAX_INBOX_ITEMS = 256;
  const COLLECTION_STATES = Object.freeze(["complete", "partial", "unavailable"]);
  const SOURCE_STATES = Object.freeze(["available", "refused", "unavailable"]);
  const REVIEW_DECISIONS = Object.freeze(["pending", "approved", "changes_requested", "dismissed"]);
  const CHECK_STATES = Object.freeze(["queued", "running", "passed", "failed", "cancelled", "unavailable"]);
  const PULL_REQUEST_STATES = Object.freeze(["absent", "draft", "open", "closed", "merged"]);
  const MERGE_READINESS_STATES = Object.freeze(["unknown", "blocked", "ready", "stale"]);
  const DELIVERY_STATES = Object.freeze(["not_delivered", "pending", "delivered", "failed"]);
  const PREVIEW_KINDS = Object.freeze(["none", "text", "binary", "image", "html"]);
  const FRESHNESS_STATES = Object.freeze(["fresh", "stale", "unknown"]);
  const ATTENTION_REASON_STATES = Object.freeze({
    review_requested: "needs_you", comment_reply: "needs_you", approval_required: "needs_you",
    check_running: "working", delivery_pending: "working",
    check_failed: "blocked", conflict: "blocked", external_blocker: "blocked",
    complete: "done",
  });

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

  function semanticFreshness(value, rootRevision) {
    const state = explicitEnum(value?.state, FRESHNESS_STATES);
    const sourceRevision = validDecimal(value?.observed_revision, false) ? value.observed_revision : null;
    if (!state || !sourceRevision || decimalGreater(sourceRevision, rootRevision)) return null;
    return Object.freeze({ freshness_key: `freshness.${state}`, source_revision: sourceRevision });
  }

  /** Pure, lossless projection from the server-owned review document to render semantics. */
  function projectReviewSemantics(document) {
    const rootRevision = validDecimal(document?.revision, false) ? document.revision : null;
    if (!rootRevision || !Array.isArray(document?.checks) || document.checks.length > 128
      || !Array.isArray(document?.files) || document.files.length > 128) return null;

    const attentionState = explicitEnum(document?.attention?.state, WORKSPACE_ATTENTION_STATES);
    const attentionReason = document?.attention?.reason === null ? null : boundedText(document?.attention?.reason, 64);
    const attentionSource = document?.attention?.source_revision === null
      ? null : (validDecimal(document?.attention?.source_revision, false) ? document.attention.source_revision : null);
    const unread = validDecimal(document?.attention?.unread) ? document.attention.unread : null;
    const idleAttention = attentionState === "idle" && attentionReason === null && attentionSource === null && unread === "0";
    const activeAttention = attentionState && attentionState !== "idle" && attentionReason
      && ATTENTION_REASON_STATES[attentionReason] === attentionState && attentionSource
      && !decimalGreater(attentionSource, rootRevision) && unread !== null;
    if (!idleAttention && !activeAttention) return null;
    const attention = Object.freeze({
      semantic_key: `attention.${attentionState}`,
      reason_key: attentionReason ? `attention_reason.${attentionReason}` : null,
      source_revision: attentionSource,
    });

    const reviewState = explicitEnum(document?.review?.decision, REVIEW_DECISIONS);
    const reviewFreshness = semanticFreshness(document?.review?.freshness, rootRevision);
    if (!reviewState || !reviewFreshness) return null;
    const review = Object.freeze({ semantic_key: `review.${reviewState}`, ...reviewFreshness });

    const checkIds = new Set();
    const checks = document.checks.map((value) => {
      const id = boundedText(value?.id, 256);
      const state = explicitEnum(value?.state, CHECK_STATES);
      const freshness = semanticFreshness(value?.freshness, rootRevision);
      if (!id || checkIds.has(id) || !state || typeof value?.required !== "boolean" || !freshness) return null;
      checkIds.add(id);
      return Object.freeze({
        id,
        semantic_key: `check.${state}.${value.required ? "required" : "optional"}`,
        ...freshness,
      });
    });
    if (checks.some((value) => value === null)) return null;

    const pullRequestState = explicitEnum(document?.pull_request?.state, PULL_REQUEST_STATES);
    const readiness = explicitEnum(document?.pull_request?.readiness, MERGE_READINESS_STATES);
    const pullRequestFreshness = semanticFreshness(document?.pull_request?.freshness, rootRevision);
    if (!pullRequestState || !readiness || !pullRequestFreshness) return null;
    const pullRequest = Object.freeze({
      semantic_key: `pull_request.${pullRequestState}.${readiness}`,
      ...pullRequestFreshness,
    });

    const deliveryState = explicitEnum(document?.delivery?.state, DELIVERY_STATES);
    const deliveryFreshness = semanticFreshness(document?.delivery?.freshness, rootRevision);
    if (!deliveryState || !deliveryFreshness) return null;
    const delivery = Object.freeze({ semantic_key: `delivery.${deliveryState}`, ...deliveryFreshness });

    const fileIds = new Set();
    const previews = document.files.map((value) => {
      const id = boundedText(value?.id, 256);
      const kind = explicitEnum(value?.preview?.kind, PREVIEW_KINDS);
      const sanitized = value?.preview?.sanitized;
      const coherent = kind === "none" || kind === "binary" ? sanitized === false : sanitized === true;
      if (!id || fileIds.has(id) || !kind || !coherent) return null;
      fileIds.add(id);
      return Object.freeze({
        id,
        semantic_key: `preview.${kind}.${sanitized ? "sanitized" : "raw"}`,
        source_revision: rootRevision,
      });
    });
    if (previews.some((value) => value === null)) return null;

    return Object.freeze({
      source_revision: rootRevision,
      attention,
      review,
      checks: Object.freeze(checks),
      pull_request: pullRequest,
      delivery,
      previews: Object.freeze(previews),
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
      reference: normalizeReference(value.reference),
    });
  }

  function normalizeReference(value) {
    if (typeof value === "string") return boundedText(value, 256);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const entries = Object.entries(value);
    if (entries.length === 0 || entries.length > 8) return null;
    const normalized = {};
    for (const [key, item] of entries) {
      if (!/^[a-z_]{1,32}$/.test(key)) return null;
      const text = boundedText(item, 256);
      if (!text) return null;
      normalized[key] = text;
    }
    return Object.freeze(normalized);
  }

  function normalizeExternalIdentity(value) {
    const provider = explicitEnum(value?.provider, ["github", "gitlab", "linear", "jira_compatible"]);
    const authority = boundedText(value?.authority, 256);
    const scope = boundedText(value?.scope, 256);
    const key = boundedText(value?.key, 256);
    return provider && authority && scope && key
      ? Object.freeze({ provider, authority, scope, key }) : null;
  }

  function normalizeOrigin(value) {
    const workspace = boundedText(value?.workspace, 256);
    const attempt = boundedText(value?.attempt, 256);
    const session = boundedText(value?.session, 256);
    const pane = boundedText(value?.pane, 256);
    if (!workspace || (session && !attempt) || (pane && !session)) return null;
    return Object.freeze({ workspace, attempt, session, pane });
  }

  function normalizeExternalWorkItem(value) {
    const identity = normalizeExternalIdentity(value?.identity);
    const movedTo = normalizeExternalIdentity(value?.moved_to);
    const state = explicitEnum(value?.state, ["open", "moved", "closed"]);
    const freshness = explicitEnum(value?.freshness, ["fresh", "stale"]);
    const origin = normalizeOrigin(value?.origin);
    if (!identity || !state || !freshness || !origin || !validDecimal(value?.revision, false)
      || !validDecimal(value?.observed_at, false) || (state === "moved") !== Boolean(movedTo)) return null;
    return Object.freeze({
      identity, moved_to: movedTo, state, freshness, origin,
      revision: value.revision,
      observed_at: value.observed_at,
      latest_message: boundedText(value.latest_message, 2048),
    });
  }

  function normalizeOrchestrationRecord(value) {
    const kind = explicitEnum(value?.kind, ["run", "task", "dispatch", "worker", "heartbeat", "question", "decision_gate"]);
    const id = boundedText(value?.id, 256);
    const status = explicitEnum(value?.status, ["working", "blocked", "waiting", "done"]);
    const freshness = explicitEnum(value?.freshness, ["fresh", "stale"]);
    const origin = normalizeOrigin(value?.origin);
    const parent = value?.parent == null ? null : normalizeReference(value.parent);
    const externalWork = value?.external_work == null ? null : normalizeExternalIdentity(value.external_work);
    const statusMessage = boundedText(value?.status_message, 2048);
    if (!kind || !id || !status || !freshness || !origin || !validDecimal(value?.revision, false)
      || !validDecimal(value?.observed_at, false) || (value?.parent != null && !parent)
      || (value?.external_work != null && !externalWork)
      || (status === "working" ? statusMessage !== null : statusMessage === null)) return null;
    return Object.freeze({
      kind, id, status, status_message: statusMessage, freshness, origin,
      parent, external_work: externalWork,
      revision: value.revision,
      observed_at: value.observed_at,
      latest_message: boundedText(value.latest_message, 2048),
    });
  }

  function normalizeLineage(value) {
    if (!value || typeof value !== "object" || !Array.isArray(value.external_work_items)
      || !Array.isArray(value.orchestration)
      || value.external_work_items.length + value.orchestration.length > MAX_LINEAGE_RECORDS) return null;
    const externalWorkItems = value.external_work_items.map(normalizeExternalWorkItem);
    const orchestration = value.orchestration.map(normalizeOrchestrationRecord);
    if (externalWorkItems.some((item) => !item) || orchestration.some((item) => !item)) return null;
    return Object.freeze({
      external_work_items: Object.freeze(externalWorkItems),
      orchestration: Object.freeze(orchestration),
    });
  }

  function normalizePane(value) {
    const id = boundedText(value?.id, 256);
    return id ? Object.freeze({
      id,
      label: boundedText(value.label, 256) || id,
      revision: validDecimal(value.revision, false) ? value.revision : null,
      lifecycle: boundedText(value.lifecycle, 32),
    }) : null;
  }

  function normalizeSession(value) {
    const id = boundedText(value?.id, 256);
    if (!id) return null;
    const panes = Array.isArray(value.panes) ? value.panes.map(normalizePane).filter(Boolean) : [];
    return Object.freeze({
      id,
      label: boundedText(value.label, 256) || id,
      revision: validDecimal(value.revision, false) ? value.revision : null,
      lifecycle: boundedText(value.lifecycle, 32),
      platform_session_id: boundedText(value.platform_session_id, 256),
      panes: Object.freeze(panes),
    });
  }

  function normalizeAttempt(value) {
    const id = boundedText(value?.id, 256);
    if (!id) return null;
    const sessions = Array.isArray(value.sessions) ? value.sessions.map(normalizeSession).filter(Boolean) : [];
    return Object.freeze({
      id,
      label: boundedText(value.label, 256) || id,
      revision: validDecimal(value.revision, false) ? value.revision : null,
      lifecycle: boundedText(value.lifecycle, 32),
      sessions: Object.freeze(sessions),
    });
  }

  function normalizeWorkspace(value) {
    if (!value || typeof value !== "object") return null;
    const id = boundedText(value.id, 256);
    if (!id) return null;
    const attempts = Array.isArray(value.attempts) ? value.attempts.map(normalizeAttempt).filter(Boolean) : [];
    const sessionIds = attempts.flatMap((attempt) => attempt.sessions.map((session) => session.platform_session_id).filter(Boolean));
    return Object.freeze({
      id,
      project_id: boundedText(value.project_id, 256),
      host_id: boundedText(value.host_id, 256),
      session_id: sessionIds.length === 1 ? sessionIds[0] : null,
      session_ids: Object.freeze(sessionIds),
      attempts: Object.freeze(attempts),
      label: boundedText(value.label, 256) || id,
      task: boundedText(value.task, 2048),
      branch: boundedText(value.branch, 512),
      attention: explicitEnum(value.attention, WORKSPACE_ATTENTION_STATES),
      external_work: normalizeSignal(value.external_work, ["open", "moved", "closed"]),
      internal_agent: normalizeSignal(value.internal_agent, ["working", "blocked", "waiting", "done"]),
      lineage: normalizeLineage(value.lineage),
      revision: validDecimal(value.revision, false) ? value.revision : null,
    });
  }

  function normalizeNamed(value) {
    const id = boundedText(value?.id, 256);
    return id ? Object.freeze({ id, label: boundedText(value?.label, 256) || id }) : null;
  }

  function normalizeActivity(value) {
    const id = boundedText(value?.id, 256);
    const at = validDecimal(value?.at) ? value.at : null;
    const kind = boundedText(value?.kind, 64);
    const freshness = explicitEnum(value?.freshness, FRESHNESS_STATES);
    const sourceRevision = validDecimal(value?.source_revision, false) ? value.source_revision : null;
    if (!id || !at || !kind || !freshness || !sourceRevision) return null;
    const linkedWorkspace = boundedText(value?.link?.workspace, 256);
    return Object.freeze({
      id,
      at,
      kind,
      label: boundedText(value?.label, 512) || kind,
      source: boundedText(value?.source, 64),
      freshness,
      source_revision: sourceRevision,
      deep_link: linkedWorkspace ? buildDeepLink({ view: "sessions", ...value.link }) : null,
    });
  }

  function normalizeInbox(value) {
    const id = boundedText(value?.id, 256);
    const state = explicitEnum(value?.state, ATTENTION_STATES);
    const reason = boundedText(value?.reason, 64);
    const originKind = boundedText(value?.origin_kind, 64);
    const sourceRevision = validDecimal(value?.source_revision, false) ? value.source_revision : null;
    const unread = validDecimal(value?.unread) ? value.unread : null;
    const linkedWorkspace = boundedText(value?.link?.workspace, 256);
    if (!id || !state || !reason || !originKind || !sourceRevision || unread === null || !linkedWorkspace) return null;
    return Object.freeze({
      id,
      state,
      reason,
      origin_kind: originKind,
      source_revision: sourceRevision,
      unread,
      deep_link: buildDeepLink({ view: "sessions", ...value.link }),
    });
  }

  function unavailableCollection(sourceNames, category = "platform_cockpit_collection_invalid") {
    return Object.freeze({
      state: "unavailable",
      items: Object.freeze([]),
      total: "0",
      omitted: "0",
      sources: Object.freeze(Object.fromEntries(sourceNames.map((name) => [name, Object.freeze({ state: "unavailable", category })]))),
    });
  }

  function normalizeCollection(value, normalizeItem, maximum, sourceNames) {
    if (!value || typeof value !== "object" || !Array.isArray(value.items)
      || value.items.length > maximum || !validDecimal(value.total) || !validDecimal(value.omitted)) {
      return unavailableCollection(sourceNames);
    }
    const items = value.items.map(normalizeItem);
    if (items.some((item) => !item)
      || BigInt(value.total) !== BigInt(items.length) + BigInt(value.omitted)) {
      return unavailableCollection(sourceNames);
    }
    const sources = {};
    for (const name of sourceNames) {
      const source = value.sources?.[name];
      const state = explicitEnum(source?.state, SOURCE_STATES);
      if (!state) return unavailableCollection(sourceNames);
      sources[name] = Object.freeze({
        state,
        category: boundedText(source?.category, 128),
      });
    }
    const available = Object.values(sources).filter((source) => source.state === "available").length;
    const expectedState = available === sourceNames.length && value.omitted === "0"
      ? "complete"
      : available === 0 ? "unavailable" : "partial";
    if (explicitEnum(value.state, COLLECTION_STATES) !== expectedState) {
      return unavailableCollection(sourceNames);
    }
    return Object.freeze({
      state: expectedState,
      items: Object.freeze(items),
      total: value.total,
      omitted: value.omitted,
      sources: Object.freeze(sources),
    });
  }

  function mutationCapability(document, operation) {
    const lifecycle = document?.actions?.lifecycle;
    const capability = lifecycle?.operations?.[operation];
    const available = capability?.available === true
      && capability?.preview_operation === "prepare_mutation"
      && capability?.receipt_operation === "get_mutation_receipt";
    return Object.freeze({
      available,
      reason: available ? null : boundedText(capability?.category, 128)
        || boundedText(lifecycle?.category, 128)
        || "platform_v2_lifecycle_adapter_pending",
      scope: available && capability?.scope === "local" ? "local" : null,
      preview_operation: available ? "prepare_mutation" : null,
      receipt_operation: available ? "get_mutation_receipt" : null,
    });
  }

  function controlCapability(document, family, operation) {
    const capability = family === "workspace_intent"
      ? document?.actions?.lifecycle?.operations?.[operation]
      : document?.actions?.review?.operations?.[operation];
    const taskId = family === "workspace_intent" ? boundedText(capability?.task_id, 256) : null;
    const externalWork = family === "workspace_intent" && operation === "create_attempt_workspace"
      ? normalizeExternalIdentity(capability?.external_work) : null;
    const available = capability?.available === true
      && (family === "workspace_intent"
        ? capability.submit_operation === "submit_workspace_intent"
          && capability.receipt_operation === "get_workspace_intent"
        : capability.execute_operation === "execute_review_action"
          && capability.receipt_operation === "get_review_receipt")
      && boundedText(capability.project_id, 256)
      && boundedText(capability.workspace_id, 256)
      && validDecimal(capability.exact_revision, false)
      && (family !== "workspace_intent" || Boolean(taskId))
      && (operation !== "create_attempt_workspace" || Boolean(externalWork));
    return Object.freeze({
      available: available === true,
      reason: available ? null : boundedText(capability?.category, 128)
        || boundedText(family === "workspace_intent" ? document?.actions?.lifecycle?.category : document?.actions?.review?.category, 128)
        || "platform_cockpit_control_unavailable",
      family,
      operation,
      project_id: available ? capability.project_id : null,
      workspace_id: available ? capability.workspace_id : null,
      exact_revision: available ? capability.exact_revision : null,
      exact_review_revision: available && validDecimal(capability.exact_review_revision, false)
        ? capability.exact_review_revision : null,
      task_id: available ? taskId : null,
      external_work: available ? externalWork : null,
    });
  }

  function rerunCapability(document) {
    const capability = document?.actions?.review?.operations?.rerun_check;
    const rawTargets = Array.isArray(capability?.targets) && capability.targets.length <= 512
      ? capability.targets : [];
    const targets = rawTargets.map((target) => {
      const projectId = boundedText(target?.project_id, 256);
      const workspaceId = boundedText(target?.workspace_id, 256);
      const checkId = boundedText(target?.check_id, 256);
      const confirmationDigest = typeof target?.confirmation_digest === "string"
        && /^[0-9a-f]{64}$/.test(target.confirmation_digest) ? target.confirmation_digest : null;
      if (!projectId || !workspaceId || !checkId
        || !confirmationDigest
        || !validDecimal(target?.exact_revision, false)
        || !validDecimal(target?.exact_check_revision, false)) return null;
      return Object.freeze({
        project_id: projectId,
        workspace_id: workspaceId,
        exact_revision: target.exact_revision,
        check_id: checkId,
        exact_check_revision: target.exact_check_revision,
        confirmation_digest: confirmationDigest,
      });
    });
    const unique = new Set(targets.filter(Boolean).map((target) => target.check_id));
    const available = capability?.available === true
      && capability?.execute_operation === "rerun_check"
      && capability?.receipt_operation === "get_review_receipt"
      && targets.length > 0
      && targets.every(Boolean)
      && unique.size === targets.length
      && targets.every((target) => target.project_id === targets[0].project_id
        && target.workspace_id === targets[0].workspace_id
        && target.exact_revision === targets[0].exact_revision);
    return Object.freeze({
      available,
      reason: available ? null : boundedText(capability?.category, 128)
        || "platform_cockpit_ci_family_unavailable",
      family: "review_action",
      operation: "rerun_check",
      project_id: available ? targets[0].project_id : null,
      workspace_id: available ? targets[0].workspace_id : null,
      exact_revision: available ? targets[0].exact_revision : null,
      targets: Object.freeze(available ? targets : []),
    });
  }

  function disabledCapability(capability, reason) {
    return Object.freeze({ ...capability, available: false, reason });
  }

  function lifecycleStatus(localLifecycle) {
    const host = localLifecycle?.createHostSetup || {};
    const checkout = localLifecycle?.createCheckout || {};
    const hostAvailable = host.available === true;
    const checkoutAvailable = checkout.available === true;
    if (hostAvailable && checkoutAvailable) {
      return Object.freeze({
        state: "available",
        message: "Task create and resume remain unavailable. Local host setup and checkout support typed preview and receipt operations.",
      });
    }
    const describe = (label, capability) => capability.available === true
      ? `${label} supports typed preview and receipt operations.`
      : `${label} unavailable (${boundedText(capability.reason, 128) || "platform_v2_lifecycle_adapter_pending"}).`;
    return Object.freeze({
      state: hostAvailable || checkoutAvailable ? "partial" : "unavailable",
      message: `Task create and resume remain unavailable. ${describe("Local host setup", host)} ${describe("Local checkout", checkout)}`,
    });
  }

  function freshnessStates(document) {
    const lineage = document?.lineage?.document?.value || document?.lineage?.document || {};
    const review = document?.review?.document || {};
    return [
      ...(Array.isArray(lineage.external_work_items) ? lineage.external_work_items : []),
      ...(Array.isArray(lineage.orchestration) ? lineage.orchestration : []),
      ...(Array.isArray(review.checks) ? review.checks : []),
      review.review,
      review.pull_request,
      review.delivery,
    ].map((value) => value?.freshness?.state).filter((value) => typeof value === "string");
  }

  function partialReasons(document, selectedWorkspace) {
    if (!["v2", "partial"].includes(document?.mode)) return [];
    const reasons = [];
    if (document.mode === "partial") {
      reasons.push(boundedText(document?.degradation?.category, 128) || "platform_v2_unavailable");
    }
    if (selectedWorkspace) {
      ["lineage", "review"].forEach((name) => {
        const projection = document?.[name];
        if (projection?.state !== "available") {
          reasons.push(boundedText(projection?.category, 128) || `${name}_unavailable`);
        }
      });
    }
    if (document?.attention?.state !== "available") {
      reasons.push(boundedText(document?.attention?.category, 128) || "attention_inventory_unavailable");
    }
    if (freshnessStates(document).includes("unknown")) reasons.push("freshness_unknown");
    return [...new Set(reasons)];
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
    const paneId = boundedText(selection.pane, 256);
    const selectedWorkspace = workspaces.find((item) => item.id === workspaceId)
      || workspaces.find((item) => sessionId && item.session_ids.includes(sessionId))
      || workspaces.find((item) => paneId && item.attempts.some((attempt) => attempt.sessions.some((session) => session.panes.some((pane) => pane.id === paneId))))
      || workspaces[0]
      || null;
    const reasons = partialReasons(document, selectedWorkspace);
    const v2 = structured && ["v2", "partial"].includes(document.mode);
    const attentionAvailable = v2 && document?.attention?.state === "available";
    const mode = v2 ? (document.mode === "partial" || reasons.length > 0 ? "partial" : "v2") : "v1";
    const degradation = mode === "v1"
      ? `Platform v1: workspace context is unavailable (${boundedText(document?.degradation?.category, 128) || "Platform v2 unavailable"}). Retained sessions remain available.`
      : mode === "partial"
        ? `Platform v2 is partial (${reasons.join(", ")}). Unavailable context is not inferred and workspace actions remain read-only.`
        : null;
    const activityCollection = structured
      ? normalizeCollection(document.activities, normalizeActivity, MAX_ACTIVITIES, ["lineage", "review"])
      : unavailableCollection(["lineage", "review"], "platform_v2_unavailable");
    const activities = [...activityCollection.items].sort((left, right) => {
        if (left.at !== right.at) return decimalGreater(left.at, right.at) ? -1 : 1;
        return left.id.localeCompare(right.id);
      });
    const inboxCollection = structured
      ? normalizeCollection(document.inbox, normalizeInbox, MAX_INBOX_ITEMS, ["review"])
      : unavailableCollection(["review"], "platform_v2_unavailable");
    const inbox = [...inboxCollection.items].sort((left, right) => {
        if (left.source_revision !== right.source_revision) {
          return decimalGreater(left.source_revision, right.source_revision) ? -1 : 1;
        }
        return left.id.localeCompare(right.id);
      });
    const writesAvailable = mode === "v2" && !freshnessStates(document).includes("stale");
    const create = controlCapability(document, "workspace_intent", "create_attempt_workspace");
    const resume = controlCapability(document, "workspace_intent", "resume_attempt_workspace");
    const addComment = controlCapability(document, "review_action", "add_comment");
    const approveReview = controlCapability(document, "review_action", "approve_review");
    const rerunCheck = rerunCapability(document);
    const reviewDocument = document?.review?.state === "available" ? document?.review?.document : null;
    const reviewSemantics = projectReviewSemantics(reviewDocument);
    return Object.freeze({
      mode,
      degradation,
      stale: v2 && freshnessStates(document).includes("stale"),
      projects: Object.freeze(projects),
      hosts: Object.freeze(hosts),
      workspaces: Object.freeze(workspaces),
      selectedWorkspace,
      attentionAvailable,
      attention: Object.freeze(Object.fromEntries(ATTENTION_STATES.map((state) => [state, attentionAvailable ? workspaces.filter((item) => item.attention === state).length : null]))),
      activities: Object.freeze(activities),
      activityCoverage: activityCollection,
      inbox: Object.freeze(inbox),
      inboxCoverage: inboxCollection,
      receipt: normalizeReceipt(document?.receipt),
      create: writesAvailable ? create : disabledCapability(create, "platform_cockpit_projection_incomplete_or_stale"),
      resume: writesAvailable ? resume : disabledCapability(resume, "platform_cockpit_projection_incomplete_or_stale"),
      reviewActions: Object.freeze({
        addComment: writesAvailable ? addComment : disabledCapability(addComment, "platform_cockpit_projection_incomplete_or_stale"),
        approveReview: writesAvailable ? approveReview : disabledCapability(approveReview, "platform_cockpit_projection_incomplete_or_stale"),
        rerunCheck: writesAvailable ? rerunCheck : disabledCapability(rerunCheck, "platform_cockpit_projection_incomplete_or_stale"),
      }),
      localLifecycle: Object.freeze({
        createHostSetup: mutationCapability(document, "create_host_setup"),
        createCheckout: mutationCapability(document, "create_checkout"),
      }),
      readModels: Object.freeze({
        files: Array.isArray(document?.review?.document?.files) ? document.review.document.files : null,
        review: document?.review?.document?.review && typeof document.review.document.review === "object" ? document.review.document.review : null,
        checks: Array.isArray(document?.review?.document?.checks) ? document.review.document.checks : null,
        pullRequest: document?.review?.document?.pull_request && typeof document.review.document.pull_request === "object" ? document.review.document.pull_request : null,
        delivery: document?.review?.document?.delivery && typeof document.review.document.delivery === "object" ? document.review.document.delivery : null,
        semantics: reviewSemantics,
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
    const anchorComplete = result.file && result.hunk && ["old", "new"].includes(result.side) && validDecimal(result.line, false);
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
      && ["old", "new"].includes(link?.side) && validDecimal(link?.line, false);
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

  function validControlHandle(value) {
    if (!value || typeof value !== "object" || !CONTROL_FAMILIES.includes(value.family)) return null;
    const action = boundedText(value.action, 64);
    const projectId = boundedText(value.project_id, 256);
    const workspaceId = boundedText(value.workspace_id, 256);
    const receiptId = boundedText(value.receipt_id, 256);
    if (!action || !projectId || !workspaceId || !receiptId) return null;
    return Object.freeze({
      version: 1,
      family: value.family,
      action,
      project_id: projectId,
      workspace_id: workspaceId,
      receipt_id: receiptId,
    });
  }

  function prepareControlHandle(capability, action, receiptId) {
    if (capability?.available !== true || !CONTROL_FAMILIES.includes(capability.family)) return null;
    return validControlHandle({
      family: capability.family,
      action,
      project_id: capability.project_id,
      workspace_id: capability.workspace_id,
      receipt_id: receiptId,
    });
  }

  function serializeControlHandle(value) {
    const handle = validControlHandle(value);
    return handle ? JSON.stringify(handle) : null;
  }

  function parseControlHandle(value) {
    if (typeof value !== "string" || value.length > 2048) return null;
    try {
      return validControlHandle(JSON.parse(value));
    } catch (_error) {
      return null;
    }
  }

  function controlRecoveryDirective(handle) {
    return validControlHandle(handle) ? "lookup_only" : "may_submit";
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
    controlRecoveryDirective,
    decimalGreater,
    derivePresentation,
    initialState,
    lifecycleStatus,
    parseControlHandle,
    parseDeepLink,
    projectReviewSemantics,
    receiptDirective,
    prepareControlHandle,
    reduce,
    serializeControlHandle,
    validDecimal,
  });
})(globalThis);
