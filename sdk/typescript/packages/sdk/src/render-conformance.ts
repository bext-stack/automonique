// SPDX-License-Identifier: Apache-2.0

export type RenderAttentionState = "idle" | "needs_you" | "working" | "blocked" | "done";
export type RenderFreshnessState = "fresh" | "stale" | "unknown";
export type RenderReviewDecision = "pending" | "approved" | "changes_requested" | "dismissed";
export type RenderCheckState = "queued" | "running" | "passed" | "failed" | "cancelled" | "unavailable";
export type RenderPullRequestState = "absent" | "draft" | "open" | "closed" | "merged";
export type RenderMergeReadiness = "unknown" | "blocked" | "ready" | "stale";
export type RenderDeliveryState = "not_delivered" | "pending" | "delivered" | "failed";
export type RenderPreviewKind = "none" | "text" | "binary" | "image" | "html";

export interface RenderConformanceFreshness {
  readonly state: RenderFreshnessState;
  readonly observed_revision: bigint;
}

export interface RenderConformanceSemantic {
  readonly semantic_key: string;
  readonly source_revision: bigint;
}

export interface RenderConformanceFreshSemantic extends RenderConformanceSemantic {
  readonly freshness_key: `freshness.${RenderFreshnessState}`;
}

export interface RenderConformanceInput {
  readonly revision: bigint;
  readonly attention: {
    readonly state: RenderAttentionState;
    readonly reason: string | null;
    readonly unread: string;
    readonly source_revision: bigint | null;
  };
  readonly review: {readonly decision: RenderReviewDecision; readonly freshness: RenderConformanceFreshness};
  readonly checks: readonly {
    readonly id: string;
    readonly state: RenderCheckState;
    readonly required: boolean;
    readonly freshness: RenderConformanceFreshness;
  }[];
  readonly pull_request: {
    readonly state: RenderPullRequestState;
    readonly readiness: RenderMergeReadiness;
    readonly freshness: RenderConformanceFreshness;
  };
  readonly delivery: {readonly state: RenderDeliveryState; readonly freshness: RenderConformanceFreshness};
  readonly files: readonly {
    readonly id: string;
    readonly preview: {readonly kind: RenderPreviewKind; readonly sanitized: boolean};
  }[];
}

export interface RenderConformanceExpected {
  readonly source_revision: bigint;
  readonly attention: {
    readonly semantic_key: `attention.${RenderAttentionState}`;
    readonly reason_key: `attention_reason.${string}` | null;
    readonly source_revision: bigint | null;
  };
  readonly review: RenderConformanceFreshSemantic;
  readonly checks: readonly (RenderConformanceFreshSemantic & {readonly id: string})[];
  readonly pull_request: RenderConformanceFreshSemantic;
  readonly delivery: RenderConformanceFreshSemantic;
  readonly previews: readonly (RenderConformanceSemantic & {readonly id: string})[];
}

export interface RenderConformanceCase {
  readonly id: RenderAttentionState;
  readonly input: RenderConformanceInput;
  readonly expected: RenderConformanceExpected;
}

export interface RenderConformanceCorpus {
  readonly schema: "automonique.render-conformance/v1";
  readonly version: "1";
  readonly cases: readonly RenderConformanceCase[];
}

const REVISION_FIELDS = new Set(["revision", "source_revision", "observed_revision"]);

function canonicalRevision(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  return BigInt(value);
}

function normalizeValue(value: unknown, key: string | null = null): unknown {
  if (key !== null && REVISION_FIELDS.has(key)) {
    if (value === null && key === "source_revision") return null;
    const revision = canonicalRevision(value);
    if (revision === null) throw new TypeError(`render conformance ${key} is not a canonical revision`);
    return revision;
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" || typeof value === "bigint") {
    throw new TypeError("render conformance numbers are not lossless decimal strings");
  }
  if (Array.isArray(value)) return Object.freeze(value.map((item) => normalizeValue(item)));
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("render conformance value is not plain data");
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(value).map(([name, item]) => [name, normalizeValue(item, name)]),
  ));
}

function stableComparable(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(stableComparable);
  if (value !== null && typeof value === "object") return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => [key, stableComparable(item)]),
  );
  return value;
}

/**
 * Converts the checked-in JSON corpus to immutable testing values without ever
 * passing a protocol revision through JavaScript `number`.
 */
export function normalizeRenderConformanceCorpus(value: unknown): RenderConformanceCorpus {
  const normalized = normalizeValue(value);
  if (normalized === null || typeof normalized !== "object" || Array.isArray(normalized)) {
    throw new TypeError("render conformance corpus is not an object");
  }
  const candidate = normalized as Readonly<Record<string, unknown>>;
  if (candidate.schema !== "automonique.render-conformance/v1" || candidate.version !== "1"
    || !Array.isArray(candidate.cases) || candidate.cases.length === 0) {
    throw new TypeError("render conformance corpus version is unsupported");
  }
  for (const item of candidate.cases) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new TypeError("render conformance case is invalid");
    }
    const fixture = item as Readonly<Record<string, unknown>>;
    if (!(typeof fixture.id === "string" && fixture.input && fixture.expected)) {
      throw new TypeError("render conformance case is incomplete");
    }
  }
  const canonical = normalizeValue(rawRenderConformanceCorpus);
  if (JSON.stringify(stableComparable(normalized)) !== JSON.stringify(stableComparable(canonical))) {
    throw new TypeError("render conformance corpus does not match canonical v1 semantics");
  }
  return normalized as RenderConformanceCorpus;
}

const rawRenderConformanceCorpus = {
  schema: "automonique.render-conformance/v1",
  version: "1",
  cases: [
    {
      id: "idle",
      input: {
        revision: "9007199254741001",
        attention: {state: "idle", reason: null, unread: "0", source_revision: null},
        review: {decision: "dismissed", freshness: {state: "unknown", observed_revision: "9007199254740993"}},
        checks: [
          {id: "check-cancelled", state: "cancelled", required: false, freshness: {state: "unknown", observed_revision: "9007199254740994"}},
          {id: "check-unavailable", state: "unavailable", required: true, freshness: {state: "stale", observed_revision: "9007199254740995"}},
        ],
        pull_request: {state: "absent", readiness: "unknown", freshness: {state: "unknown", observed_revision: "9007199254740996"}},
        delivery: {state: "not_delivered", freshness: {state: "unknown", observed_revision: "9007199254740997"}},
        files: [{id: "file-none", preview: {kind: "none", sanitized: false}}],
      },
      expected: {
        source_revision: "9007199254741001",
        attention: {semantic_key: "attention.idle", reason_key: null, source_revision: null},
        review: {semantic_key: "review.dismissed", freshness_key: "freshness.unknown", source_revision: "9007199254740993"},
        checks: [
          {id: "check-cancelled", semantic_key: "check.cancelled.optional", freshness_key: "freshness.unknown", source_revision: "9007199254740994"},
          {id: "check-unavailable", semantic_key: "check.unavailable.required", freshness_key: "freshness.stale", source_revision: "9007199254740995"},
        ],
        pull_request: {semantic_key: "pull_request.absent.unknown", freshness_key: "freshness.unknown", source_revision: "9007199254740996"},
        delivery: {semantic_key: "delivery.not_delivered", freshness_key: "freshness.unknown", source_revision: "9007199254740997"},
        previews: [{id: "file-none", semantic_key: "preview.none.raw", source_revision: "9007199254741001"}],
      },
    },
    {
      id: "needs_you",
      input: {
        revision: "9007199254741011",
        attention: {state: "needs_you", reason: "review_requested", unread: "2", source_revision: "9007199254741002"},
        review: {decision: "pending", freshness: {state: "fresh", observed_revision: "9007199254741003"}},
        checks: [{id: "check-failed", state: "failed", required: true, freshness: {state: "stale", observed_revision: "9007199254741004"}}],
        pull_request: {state: "open", readiness: "blocked", freshness: {state: "fresh", observed_revision: "9007199254741005"}},
        delivery: {state: "pending", freshness: {state: "fresh", observed_revision: "9007199254741006"}},
        files: [{id: "file-text", preview: {kind: "text", sanitized: true}}],
      },
      expected: {
        source_revision: "9007199254741011",
        attention: {semantic_key: "attention.needs_you", reason_key: "attention_reason.review_requested", source_revision: "9007199254741002"},
        review: {semantic_key: "review.pending", freshness_key: "freshness.fresh", source_revision: "9007199254741003"},
        checks: [{id: "check-failed", semantic_key: "check.failed.required", freshness_key: "freshness.stale", source_revision: "9007199254741004"}],
        pull_request: {semantic_key: "pull_request.open.blocked", freshness_key: "freshness.fresh", source_revision: "9007199254741005"},
        delivery: {semantic_key: "delivery.pending", freshness_key: "freshness.fresh", source_revision: "9007199254741006"},
        previews: [{id: "file-text", semantic_key: "preview.text.sanitized", source_revision: "9007199254741011"}],
      },
    },
    {
      id: "working",
      input: {
        revision: "9007199254741021",
        attention: {state: "working", reason: "check_running", unread: "0", source_revision: "9007199254741012"},
        review: {decision: "pending", freshness: {state: "fresh", observed_revision: "9007199254741013"}},
        checks: [
          {id: "check-queued", state: "queued", required: false, freshness: {state: "fresh", observed_revision: "9007199254741014"}},
          {id: "check-running", state: "running", required: true, freshness: {state: "fresh", observed_revision: "9007199254741015"}},
        ],
        pull_request: {state: "draft", readiness: "stale", freshness: {state: "stale", observed_revision: "9007199254741016"}},
        delivery: {state: "pending", freshness: {state: "fresh", observed_revision: "9007199254741017"}},
        files: [{id: "file-image", preview: {kind: "image", sanitized: true}}],
      },
      expected: {
        source_revision: "9007199254741021",
        attention: {semantic_key: "attention.working", reason_key: "attention_reason.check_running", source_revision: "9007199254741012"},
        review: {semantic_key: "review.pending", freshness_key: "freshness.fresh", source_revision: "9007199254741013"},
        checks: [
          {id: "check-queued", semantic_key: "check.queued.optional", freshness_key: "freshness.fresh", source_revision: "9007199254741014"},
          {id: "check-running", semantic_key: "check.running.required", freshness_key: "freshness.fresh", source_revision: "9007199254741015"},
        ],
        pull_request: {semantic_key: "pull_request.draft.stale", freshness_key: "freshness.stale", source_revision: "9007199254741016"},
        delivery: {semantic_key: "delivery.pending", freshness_key: "freshness.fresh", source_revision: "9007199254741017"},
        previews: [{id: "file-image", semantic_key: "preview.image.sanitized", source_revision: "9007199254741021"}],
      },
    },
    {
      id: "blocked",
      input: {
        revision: "9007199254741031",
        attention: {state: "blocked", reason: "external_blocker", unread: "1", source_revision: "9007199254741022"},
        review: {decision: "changes_requested", freshness: {state: "stale", observed_revision: "9007199254741023"}},
        checks: [{id: "check-blocked-failed", state: "failed", required: true, freshness: {state: "stale", observed_revision: "9007199254741024"}}],
        pull_request: {state: "closed", readiness: "blocked", freshness: {state: "stale", observed_revision: "9007199254741025"}},
        delivery: {state: "failed", freshness: {state: "stale", observed_revision: "9007199254741026"}},
        files: [{id: "file-binary", preview: {kind: "binary", sanitized: false}}],
      },
      expected: {
        source_revision: "9007199254741031",
        attention: {semantic_key: "attention.blocked", reason_key: "attention_reason.external_blocker", source_revision: "9007199254741022"},
        review: {semantic_key: "review.changes_requested", freshness_key: "freshness.stale", source_revision: "9007199254741023"},
        checks: [{id: "check-blocked-failed", semantic_key: "check.failed.required", freshness_key: "freshness.stale", source_revision: "9007199254741024"}],
        pull_request: {semantic_key: "pull_request.closed.blocked", freshness_key: "freshness.stale", source_revision: "9007199254741025"},
        delivery: {semantic_key: "delivery.failed", freshness_key: "freshness.stale", source_revision: "9007199254741026"},
        previews: [{id: "file-binary", semantic_key: "preview.binary.raw", source_revision: "9007199254741031"}],
      },
    },
    {
      id: "done",
      input: {
        revision: "9007199254741041",
        attention: {state: "done", reason: "complete", unread: "0", source_revision: "9007199254741032"},
        review: {decision: "approved", freshness: {state: "fresh", observed_revision: "9007199254741033"}},
        checks: [{id: "check-passed", state: "passed", required: true, freshness: {state: "fresh", observed_revision: "9007199254741034"}}],
        pull_request: {state: "merged", readiness: "ready", freshness: {state: "fresh", observed_revision: "9007199254741035"}},
        delivery: {state: "delivered", freshness: {state: "fresh", observed_revision: "9007199254741036"}},
        files: [{id: "file-html", preview: {kind: "html", sanitized: true}}],
      },
      expected: {
        source_revision: "9007199254741041",
        attention: {semantic_key: "attention.done", reason_key: "attention_reason.complete", source_revision: "9007199254741032"},
        review: {semantic_key: "review.approved", freshness_key: "freshness.fresh", source_revision: "9007199254741033"},
        checks: [{id: "check-passed", semantic_key: "check.passed.required", freshness_key: "freshness.fresh", source_revision: "9007199254741034"}],
        pull_request: {semantic_key: "pull_request.merged.ready", freshness_key: "freshness.fresh", source_revision: "9007199254741035"},
        delivery: {semantic_key: "delivery.delivered", freshness_key: "freshness.fresh", source_revision: "9007199254741036"},
        previews: [{id: "file-html", semantic_key: "preview.html.sanitized", source_revision: "9007199254741041"}],
      },
    },
  ],
};

/** Returns a fresh immutable copy of the versioned canonical render corpus. */
export function createRenderConformanceCorpus(): RenderConformanceCorpus {
  return normalizeRenderConformanceCorpus(rawRenderConformanceCorpus);
}
