// SPDX-License-Identifier: Apache-2.0

import {
  ProjectId,
  UserWorkspaceId,
  WorkContextRevision,
  type AttentionItem,
  type AttentionSource,
  type AttentionSourceSnapshot,
} from "../../protocol/src/index.js";

/**
 * The shared attention succession corpus.
 *
 * `automonique.platform/attention/v1` is `atomic_replace`, so a single snapshot
 * proves nothing about what a client must conclude after a sequence of reads.
 * This corpus fixes that sequence: each case replays reads against one source
 * and records the outcome a retaining client must reach, including the
 * retention gap, the refusal, and the never-observed cases where the honest
 * answer is "hidden" rather than "empty".
 *
 * Revisions are carried as canonical decimal strings and normalized to BigInt.
 * The values sit above 2^53 on purpose: a client that routes one through a
 * JavaScript number loses the corpus.
 */

export type AttentionConformanceMode = "baseline" | "continuous";

export type AttentionConformanceOutcome =
  | "inserted"
  | "replaced"
  | "exact_replay"
  | "availability_restored"
  | "initial_revision_required"
  | "invalid_successor"
  | "conflicting_replay"
  | "baseline_invalid";

export type AttentionConformanceUnavailableReason =
  | "transport"
  | "inventory_incomplete"
  | "retired";

export interface AttentionConformanceSnapshotRead {
  readonly kind: "snapshot";
  readonly mode: AttentionConformanceMode;
  readonly outcome: AttentionConformanceOutcome;
  readonly snapshot: AttentionSourceSnapshot;
}

export interface AttentionConformanceRefusal {
  readonly kind: "refusal";
  readonly category: string;
}

export interface AttentionConformanceUnavailable {
  readonly kind: "unavailable";
  readonly reason: AttentionConformanceUnavailableReason;
}

export type AttentionConformanceRead =
  | AttentionConformanceSnapshotRead
  | AttentionConformanceRefusal
  | AttentionConformanceUnavailable;

export interface AttentionConformanceExpectation {
  /** False whenever the source is hidden, whether refused, lost, or unread. */
  readonly available: boolean;
  /** Exactly the item ids a client may render, in the wire's own order. */
  readonly visible_items: readonly string[];
}

export interface AttentionConformanceCase {
  readonly id: string;
  readonly source: AttentionSource;
  readonly reads: readonly AttentionConformanceRead[];
  readonly expected: AttentionConformanceExpectation;
}

export interface AttentionConformanceTarget {
  readonly project: string;
  readonly user_workspace: string;
}

export interface AttentionConformanceCorpus {
  readonly schema: "automonique.attention-conformance/v1";
  readonly version: "1";
  readonly target: AttentionConformanceTarget;
  readonly cases: readonly AttentionConformanceCase[];
}

const OUTCOMES: readonly AttentionConformanceOutcome[] = [
  "inserted",
  "replaced",
  "exact_replay",
  "availability_restored",
  "initial_revision_required",
  "invalid_successor",
  "conflicting_replay",
  "baseline_invalid",
];

const UNAVAILABLE_REASONS: readonly AttentionConformanceUnavailableReason[] = [
  "transport",
  "inventory_incomplete",
  "retired",
];

const SOURCE_KINDS = ["review", "orchestration", "provider_session"] as const;

function object(value: unknown, where: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`attention conformance ${where} is not an object`);
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, where: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`attention conformance ${where} is not text`);
  }
  return value;
}

/** A revision is only ever a canonical decimal string; never a number. */
function revision(value: unknown, where: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`attention conformance ${where} is not a canonical revision`);
  }
  return BigInt(value);
}

function source(value: unknown): AttentionSource {
  const body = object(value, "source");
  const kind = text(body.kind, "source kind");
  if (!SOURCE_KINDS.includes(kind as (typeof SOURCE_KINDS)[number])) {
    throw new TypeError("attention conformance source kind is unknown");
  }
  return Object.freeze({
    id: text(body.id, "source id"),
    kind: kind as (typeof SOURCE_KINDS)[number],
  });
}

function item(value: unknown): AttentionItem {
  const body = object(value, "item");
  const path = body.nested_agent_path;
  if (!Array.isArray(path)) {
    throw new TypeError("attention conformance nested agent path is not an array");
  }
  const session = body.platform_session === null
    ? null
    : (() => {
        const coordinate = object(body.platform_session, "platform session");
        if (coordinate.kind !== "session") {
          throw new TypeError("attention conformance platform session kind is unknown");
        }
        return Object.freeze({
          authority: text(coordinate.authority, "platform session authority"),
          id: text(coordinate.id, "platform session id"),
          kind: "session",
        });
      })();
  if (typeof body.unread !== "boolean") {
    throw new TypeError("attention conformance unread is not a boolean");
  }
  return Object.freeze({
    id: text(body.id, "item id"),
    nested_agent_path: Object.freeze(path.map((entry) => text(entry, "nested agent id"))),
    observed_at_ms: revision(body.observed_at_ms, "item observation"),
    platform_session: session,
    reason: text(body.reason, "item reason"),
    revision: WorkContextRevision(revision(body.revision, "item revision")),
    state: text(body.state, "item state"),
    unread: body.unread,
  }) as AttentionItem;
}

function snapshot(value: unknown): AttentionSourceSnapshot {
  const body = object(value, "snapshot");
  if (
    body.schema !== "automonique.platform/attention/v1"
    || body.semantics !== "atomic_replace"
  ) {
    throw new TypeError("attention conformance snapshot is not the v1 contract");
  }
  const entries = body.items;
  if (!Array.isArray(entries)) {
    throw new TypeError("attention conformance items is not an array");
  }
  return Object.freeze({
    items: Object.freeze(entries.map(item)),
    observed_at_ms: revision(body.observed_at_ms, "snapshot observation"),
    previous_revision: body.previous_revision === null
      ? null
      : WorkContextRevision(revision(body.previous_revision, "previous revision")),
    project: ProjectId(text(body.project, "snapshot project")),
    revision: WorkContextRevision(revision(body.revision, "snapshot revision")),
    schema: "automonique.platform/attention/v1",
    semantics: "atomic_replace",
    source: source(body.source),
    user_workspace: UserWorkspaceId(text(body.user_workspace, "snapshot workspace")),
  }) as AttentionSourceSnapshot;
}

function read(value: unknown): AttentionConformanceRead {
  const body = object(value, "read");
  switch (body.kind) {
    case "snapshot": {
      const mode = text(body.mode, "read mode");
      const outcome = text(body.outcome, "read outcome");
      if (mode !== "baseline" && mode !== "continuous") {
        throw new TypeError("attention conformance read mode is unknown");
      }
      if (!OUTCOMES.includes(outcome as AttentionConformanceOutcome)) {
        throw new TypeError("attention conformance read outcome is unknown");
      }
      return Object.freeze({
        kind: "snapshot",
        mode,
        outcome: outcome as AttentionConformanceOutcome,
        snapshot: snapshot(body.snapshot),
      });
    }
    case "refusal":
      return Object.freeze({
        category: text(body.category, "refusal category"),
        kind: "refusal",
      });
    case "unavailable": {
      const reason = text(body.reason, "unavailable reason");
      if (!UNAVAILABLE_REASONS.includes(reason as AttentionConformanceUnavailableReason)) {
        throw new TypeError("attention conformance unavailable reason is unknown");
      }
      return Object.freeze({
        kind: "unavailable",
        reason: reason as AttentionConformanceUnavailableReason,
      });
    }
    default:
      throw new TypeError("attention conformance read kind is unknown");
  }
}

/**
 * Converts the checked-in corpus to immutable testing values without ever
 * passing a protocol revision through JavaScript `number`.
 */
export function normalizeAttentionConformanceCorpus(value: unknown): AttentionConformanceCorpus {
  const body = object(value, "corpus");
  if (body.schema !== "automonique.attention-conformance/v1" || body.version !== "1") {
    throw new TypeError("attention conformance corpus is not the v1 corpus");
  }
  const target = object(body.target, "target");
  const cases = body.cases;
  if (!Array.isArray(cases) || cases.length === 0) {
    throw new TypeError("attention conformance corpus has no cases");
  }
  const identities = new Set<string>();
  const normalized = cases.map((entry): AttentionConformanceCase => {
    const record = object(entry, "case");
    const id = text(record.id, "case id");
    if (identities.has(id)) {
      throw new TypeError("attention conformance case identity is duplicated");
    }
    identities.add(id);
    const reads = record.reads;
    if (!Array.isArray(reads)) {
      throw new TypeError("attention conformance reads is not an array");
    }
    const expected = object(record.expected, "expectation");
    if (typeof expected.available !== "boolean" || !Array.isArray(expected.visible_items)) {
      throw new TypeError("attention conformance expectation is incomplete");
    }
    if (!expected.available && expected.visible_items.length > 0) {
      throw new TypeError("attention conformance hides a source while rendering its items");
    }
    return Object.freeze({
      expected: Object.freeze({
        available: expected.available,
        visible_items: Object.freeze(
          expected.visible_items.map((visible) => text(visible, "visible item id")),
        ),
      }),
      id,
      reads: Object.freeze(reads.map(read)),
      source: source(record.source),
    });
  });
  return Object.freeze({
    cases: Object.freeze(normalized),
    schema: "automonique.attention-conformance/v1",
    target: Object.freeze({
      project: text(target.project, "target project"),
      user_workspace: text(target.user_workspace, "target workspace"),
    }),
    version: "1",
  });
}

const rawAttentionConformanceCorpus = {
    "cases": [
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "continuous-first-read-requires-revision-one",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "initial_revision_required",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9007199254741102",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": "9007199254741101",
              "project": "project-conformance",
              "revision": "9007199254741102",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a", "item-b"]},
        "id": "continuous-successor-replaces-atomically",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "replaced",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "2000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "2",
                  "state": "needs_you",
                  "unread": true,
                },
                {
                  "id": "item-b",
                  "nested_agent_path": [],
                  "observed_at_ms": "2000",
                  "platform_session": null,
                  "reason": "agent_working",
                  "revision": "2",
                  "state": "working",
                  "unread": true,
                },
              ],
              "observed_at_ms": "2000",
              "previous_revision": "1",
              "project": "project-conformance",
              "revision": "2",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "exact-replay-changes-nothing",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "exact_replay",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "conflicting-replay-is-refused",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "conflicting_replay",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": false,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": false, "visible_items": []},
        "id": "retention-gap-refuses-and-hides-the-source",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "invalid_successor",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "3000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "3",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "3000",
              "previous_revision": "2",
              "project": "project-conformance",
              "revision": "3",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {"kind": "unavailable", "reason": "inventory_incomplete"},
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-c"]},
        "id": "authenticated-baseline-bridges-a-gap",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {"kind": "unavailable", "reason": "inventory_incomplete"},
          {
            "kind": "snapshot",
            "mode": "baseline",
            "outcome": "replaced",
            "snapshot": {
              "items": [
                {
                  "id": "item-c",
                  "nested_agent_path": [],
                  "observed_at_ms": "9000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "9000",
              "previous_revision": "8",
              "project": "project-conformance",
              "revision": "9",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "baseline-rollback-is-refused",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "baseline",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "5000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9007199254741105",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "5000",
              "previous_revision": "9007199254741104",
              "project": "project-conformance",
              "revision": "9007199254741105",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "baseline",
            "outcome": "baseline_invalid",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "4000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9007199254741104",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "4000",
              "previous_revision": "9007199254741103",
              "project": "project-conformance",
              "revision": "9007199254741104",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "item-revision-regression-is-refused",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "baseline",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "5000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9007199254741105",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "5000",
              "previous_revision": "9007199254741104",
              "project": "project-conformance",
              "revision": "9007199254741105",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "invalid_successor",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "6000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "9007199254741104",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "6000",
              "previous_revision": "9007199254741105",
              "project": "project-conformance",
              "revision": "9007199254741106",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": false, "visible_items": []},
        "id": "refusal-hides-the-projection-and-keeps-the-chain",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {"category": "unauthorized", "kind": "refusal"},
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-a"]},
        "id": "exact-replay-restores-availability",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
          {"category": "unauthorized", "kind": "refusal"},
          {
            "kind": "snapshot",
            "mode": "continuous",
            "outcome": "availability_restored",
            "snapshot": {
              "items": [
                {
                  "id": "item-a",
                  "nested_agent_path": [],
                  "observed_at_ms": "1000",
                  "platform_session": null,
                  "reason": "review_requested",
                  "revision": "1",
                  "state": "needs_you",
                  "unread": true,
                },
              ],
              "observed_at_ms": "1000",
              "previous_revision": null,
              "project": "project-conformance",
              "revision": "1",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "workspace-conformance", "kind": "review"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": false, "visible_items": []},
        "id": "never-read-source-is-unobserved",
        "reads": [],
        "source": {"id": "workspace-conformance", "kind": "review"},
      },
      {
        "expected": {"available": true, "visible_items": ["item-nested", "item-root"]},
        "id": "provider-source-retains-its-published-session",
        "reads": [
          {
            "kind": "snapshot",
            "mode": "baseline",
            "outcome": "inserted",
            "snapshot": {
              "items": [
                {
                  "id": "item-nested",
                  "nested_agent_path": ["item-root"],
                  "observed_at_ms": "7000",
                  "platform_session": {
                    "authority": "automonique",
                    "id": "platform-session-conformance",
                    "kind": "session",
                  },
                  "reason": "agent_working",
                  "revision": "9007199254741107",
                  "state": "working",
                  "unread": true,
                },
                {
                  "id": "item-root",
                  "nested_agent_path": [],
                  "observed_at_ms": "7000",
                  "platform_session": {
                    "authority": "automonique",
                    "id": "platform-session-conformance",
                    "kind": "session",
                  },
                  "reason": "agent_working",
                  "revision": "9007199254741107",
                  "state": "working",
                  "unread": true,
                },
              ],
              "observed_at_ms": "7000",
              "previous_revision": "9007199254741106",
              "project": "project-conformance",
              "revision": "9007199254741107",
              "schema": "automonique.platform/attention/v1",
              "semantics": "atomic_replace",
              "source": {"id": "session-conformance", "kind": "provider_session"},
              "user_workspace": "workspace-conformance",
            },
          },
        ],
        "source": {"id": "session-conformance", "kind": "provider_session"},
      },
    ],
    "schema": "automonique.attention-conformance/v1",
    "target": {"project": "project-conformance", "user_workspace": "workspace-conformance"},
    "version": "1",
  };

/** Returns a fresh immutable copy of the versioned canonical attention corpus. */
export function createAttentionConformanceCorpus(): AttentionConformanceCorpus {
  return normalizeAttentionConformanceCorpus(rawAttentionConformanceCorpus);
}
