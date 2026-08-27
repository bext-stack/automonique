// SPDX-License-Identifier: Apache-2.0

import {
  CursorTopic,
  MobileActor,
  MobileCredentialId,
  MobileEpochMillis,
  MobileFollowUpBytes,
  MobilePageEvents,
  MobileRevision,
  MobileServerIdentity,
  MobileSessionId,
  PlatformEpochMillis,
  PlatformRequestId,
  PlatformRevision,
  PlatformText,
  ReceiptId,
  ResourceId,
  SessionHistoryCursor,
  SessionHistoryLimit,
  MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
  PLATFORM_NEGOTIATION_MAJOR,
  PLATFORM_NEGOTIATION_PROTOCOL,
  PLATFORM_PROTOCOL,
  PLATFORM_SCHEMA_V2,
  PLATFORM_V2_MAJOR,
  SupportedPlatformVersionNumber,
  decodeMessage,
  decodePlatformNegotiationRequest,
  encodeLineageProjection,
  encodeMessage,
  encodeNegotiatedPlatform,
  encodePlatformV2Request as encodePlatformV2FixtureRequest,
  encodeReviewActionReceipt,
  encodeReviewSnapshot,
  encodeWorkContextMutationPreview,
  encodeWorkContextMutationRefusal,
  encodeWorkContextPage,
  encodeWorkContextResync,
  encodeWorkspaceIntentOutcome,
  parseCanonical,
  validateWorkContextRecord,
  type ActionReceipt,
  type MobileAuthorization,
  type PlatformCursor,
  type PlatformRequest,
  type PlatformNegotiationResponse,
  type NegotiatedPlatform,
  type PlatformV2Request,
  type PlatformV2Response,
  type PlatformVersionOffer,
  type ResourceCoordinate,
  type ResourceRecord,
  type Snapshot,
  type Subscription,
  type JsonValue,
} from "../../protocol/src/index.js";
import type {
  MobileFollowUpRequest,
  MobileReceiptLookup,
} from "./mobile-session-client.js";
import type {
  PlatformAdapter,
  PlatformClientResponse,
  SessionHistoryPage,
} from "./platform-client.js";
import {
  platformV2Exchange,
  type InternalPlatformV2Transport,
  type PlatformV2Lane,
} from "./platform-v2-internal.js";

export class DeterministicFixtureError extends Error {
  readonly category: "aborted" | "script_exhausted" | "unexpected_request";

  constructor(
    category: "aborted" | "script_exhausted" | "unexpected_request",
    options?: ErrorOptions,
  ) {
    super(`deterministic SDK fixture refused: ${category}`, options);
    this.name = "DeterministicFixtureError";
    this.category = category;
  }
}

/** A transport failure after a mutation may have reached the authority. */
export class AmbiguousMutationFixtureError extends Error {
  constructor() {
    super("deterministic mutation outcome is ambiguous");
    this.name = "AmbiguousMutationFixtureError";
  }
}

export interface DeterministicPlatformStep {
  readonly method: PlatformRequest["method"];
  readonly result:
    | {readonly kind: "response"; readonly value: PlatformClientResponse}
    | {readonly kind: "error"; readonly value: Error};
}

/**
 * Runtime-neutral, exact-order Platform adapter for SDK and application tests.
 *
 * It deliberately has no timers, random values, filesystem access, or test
 * runner dependency. Requests are retained so callers can assert exact
 * receipt lookup and idempotency behavior with their test framework of choice.
 */
export class DeterministicPlatformAdapter implements PlatformAdapter {
  readonly requests: PlatformRequest[] = [];
  readonly #steps: DeterministicPlatformStep[];

  constructor(steps: readonly DeterministicPlatformStep[]) {
    this.#steps = [...steps];
  }

  get pendingSteps(): number {
    return this.#steps.length;
  }

  request(request: PlatformRequest, signal?: AbortSignal): Promise<PlatformClientResponse> {
    if (signal?.aborted === true) {
      return Promise.reject(new DeterministicFixtureError("aborted", {cause: signal.reason}));
    }
    const step = this.#steps.shift();
    if (step === undefined) {
      return Promise.reject(new DeterministicFixtureError("script_exhausted"));
    }
    if (step.method !== request.method) {
      return Promise.reject(new DeterministicFixtureError("unexpected_request", {
        cause: new Error(`expected ${step.method}; received ${request.method}`),
      }));
    }
    this.requests.push(request);
    return step.result.kind === "response"
      ? Promise.resolve(step.result.value)
      : Promise.reject(step.result.value);
  }
}

export type DeterministicPlatformV2Step =
  | {readonly lane: "negotiation"; readonly result: PlatformNegotiationResponse}
  | {readonly lane: "v2"; readonly request: PlatformV2Request; readonly result: PlatformV2Response}
  | {readonly lane: "error"; readonly error: Error};

/** Exact-order typed Platform v2 adapter with retained request coordinates. */
export class DeterministicPlatformV2Adapter implements InternalPlatformV2Transport {
  readonly negotiations: PlatformVersionOffer[] = [];
  readonly requests: PlatformV2Request[] = [];
  readonly #steps: DeterministicPlatformV2Step[];

  constructor(steps: readonly DeterministicPlatformV2Step[]) {
    this.#steps = [...steps];
  }

  get pendingSteps(): number {
    return this.#steps.length;
  }

  async [platformV2Exchange](lane: PlatformV2Lane, payload: Uint8Array, signal?: AbortSignal): Promise<{readonly payload: Uint8Array; readonly status: number}> {
    if (signal?.aborted === true) {
      throw new DeterministicFixtureError("aborted", {cause: signal.reason});
    }
    const step = this.#steps.shift();
    if (step === undefined) throw new DeterministicFixtureError("script_exhausted");
    if (step.lane === "error") throw step.error;
    if (step.lane !== lane) throw new DeterministicFixtureError("unexpected_request");
    if (lane === "negotiation" && step.lane === "negotiation") {
      const decoded = decodePlatformNegotiationRequest(payload);
      this.negotiations.push(decoded.request.offer);
      return {payload: encodeNegotiationFixtureResponse(decoded.request_id, step.result), status: 200};
    }
    if (lane === "v2" && step.lane === "v2") {
      if (payload.length > MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES) {
        throw new DeterministicFixtureError("unexpected_request");
      }
      const envelope = decodeMessage(payload).envelope;
      const expected = encodePlatformV2FixtureRequest(PlatformRequestId(envelope.requestId), step.request);
      if (!bytesEqual(payload, expected)) throw new DeterministicFixtureError("unexpected_request");
      this.requests.push(step.request);
      return {payload: encodeV2FixtureResponse(envelope.requestId, step.result), status: 200};
    }
    throw new DeterministicFixtureError("unexpected_request");
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function json(value: unknown): JsonValue {
  if (value === null) return {kind: "null"};
  if (typeof value === "boolean") return {kind: "bool", value};
  if (typeof value === "bigint") return {kind: "integer", value};
  if (typeof value === "string") return {kind: "string", value};
  if (value instanceof Uint8Array) return parseCanonical(value);
  if (Array.isArray(value)) return {kind: "array", items: value.map(json)};
  if (typeof value === "object") return {kind: "object", entries: Object.entries(value as Readonly<Record<string, unknown>>).map(([key, item]) => [key, json(item)] as const)};
  throw new DeterministicFixtureError("unexpected_request");
}

function fixtureMessage(protocol: string, version: number, requestId: string, kind: string, body: JsonValue): Uint8Array {
  return encodeMessage({envelope: {protocol, version, requestId, kind}, body});
}

function encodeNegotiationFixtureResponse(requestId: string, response: PlatformNegotiationResponse): Uint8Array {
  const body = response.kind === "negotiated"
    ? parseCanonical(encodeNegotiatedPlatform(response.negotiated))
    : json(response.refusal);
  return fixtureMessage(PLATFORM_NEGOTIATION_PROTOCOL, PLATFORM_NEGOTIATION_MAJOR, requestId, response.kind, body);
}

const negotiatedV2: NegotiatedPlatform = {
  schema: PLATFORM_SCHEMA_V2,
  version: SupportedPlatformVersionNumber(2n),
  work_context: "v2_structured" as const,
};

function encodeV2FixtureResponse(requestId: string, response: PlatformV2Response): Uint8Array {
  let body: JsonValue;
  switch (response.kind) {
    case "work_context_page": body = parseCanonical(encodeWorkContextPage(response.page)); break;
    case "work_context_resync": body = parseCanonical(encodeWorkContextResync(response.resync)); break;
    case "work_context_record": body = json(validateWorkContextRecord(response.record)); break;
    case "mutation_preview": body = parseCanonical(encodeWorkContextMutationPreview(response.preview)); break;
    case "mutation_approval": case "mutation_receipt": body = parseCanonical(response.kind === "mutation_approval" ? response.approval.canonical : response.receipt.canonical); break;
    case "mutation_refused": body = parseCanonical(encodeWorkContextMutationRefusal(response.refusal)); break;
    case "lineage_result": body = parseCanonical(encodeLineageProjection(negotiatedV2, response.lineage)); break;
    case "workspace_intent_result": body = parseCanonical(encodeWorkspaceIntentOutcome(negotiatedV2, response.result)); break;
    case "review_result": body = parseCanonical(encodeReviewSnapshot(response.review)); break;
    case "review_receipt": body = parseCanonical(encodeReviewActionReceipt(response.receipt)); break;
    case "platform_v2_refused": body = json(response.refusal); break;
  }
  return fixtureMessage(PLATFORM_PROTOCOL, PLATFORM_V2_MAJOR, requestId, response.kind, body);
}


export interface DeterministicSdkFixture {
  readonly now: number;
  readonly serverIdentity: ReturnType<typeof MobileServerIdentity>;
  readonly authorization: MobileAuthorization;
  readonly coordinates: {
    readonly session: ResourceCoordinate;
    readonly run: ResourceCoordinate;
  };
  readonly projection: {
    readonly snapshot: Snapshot;
    readonly duplicate: Subscription;
    readonly conflictingDuplicate: Subscription;
    readonly gap: Subscription;
    readonly staleRevision: Subscription;
  };
  readonly history: {
    readonly unknownEvent: SessionHistoryPage;
    readonly cursorExpired: Extract<PlatformClientResponse, {readonly kind: "session_history_resync"}>;
  };
  readonly mutation: {
    readonly followUp: MobileFollowUpRequest;
    readonly unknownReceipt: ActionReceipt;
    readonly reconciledReceipt: ActionReceipt;
    readonly receiptLookup: MobileReceiptLookup;
    readonly ambiguousThenReconciled: readonly DeterministicPlatformStep[];
  };
}

const NOW = 1_700_000_000_000;

function coordinate(kind: "run" | "session", id: string): ResourceCoordinate {
  return {authority: "automonique", id: ResourceId(id), kind};
}

function cursor(sequence: bigint): PlatformCursor {
  return {
    authority: "automonique",
    sequence: PlatformRevision(sequence),
    topic: CursorTopic("sessions"),
  };
}

function record(run: ResourceCoordinate, revision: bigint, summary: string): ResourceRecord {
  return {
    freshness: {
      observed_at: PlatformEpochMillis(BigInt(NOW) + revision),
      revision: PlatformRevision(revision),
      state: "fresh",
    },
    resource: run,
    summary: PlatformText(summary),
  };
}

function event(sequence: bigint, value: ResourceRecord): Subscription["events"][number] {
  return {cursor: cursor(sequence), resource: value};
}

function receipt(
  outcome: ActionReceipt["outcome"],
  revision: bigint,
  session: ResourceCoordinate,
): ActionReceipt {
  return {
    action: "follow_up",
    explanation: outcome === "unknown" ? PlatformText("delivery interrupted") : null,
    id: ReceiptId("fixture-receipt"),
    outcome,
    recorded_at: PlatformEpochMillis(BigInt(NOW) + revision),
    revision: PlatformRevision(revision),
    target: session,
  };
}

/**
 * One stable fixture matrix covering the mobile SDK's recovery edge cases.
 * Repeated calls return equivalent values without sharing mutable arrays.
 */
export function createDeterministicSdkFixture(): DeterministicSdkFixture {
  const session = coordinate("session", "fixture-session");
  const run = coordinate("run", "fixture-run");
  const baseline = record(run, 10n, "running");
  const duplicate: Subscription = {
    cursor: cursor(10n),
    events: [event(10n, baseline)],
  };
  const unknownReceipt = receipt("unknown", 1n, session);
  const reconciledReceipt = receipt("completed", 2n, session);
  const followUp: MobileFollowUpRequest = {
    expectedSessionRevision: 10n,
    idempotencyKey: "fixture-follow-up",
    session,
    text: "Continue deterministically.",
  };
  const receiptLookup: MobileReceiptLookup = {
    expectedAction: "follow_up",
    expectedTarget: session,
    idempotencyKey: followUp.idempotencyKey,
    session,
  };
  const unknownEvent: SessionHistoryPage = {
    applied_limit: SessionHistoryLimit(1n),
    events: [{
      at: PlatformEpochMillis(BigInt(NOW)),
      cursor: SessionHistoryCursor(21n),
      kind: "unknown",
      source: "adapter_event",
    }],
    from_cursor: SessionHistoryCursor(20n),
    has_more: false,
    requested_limit: SessionHistoryLimit(1n),
    session,
    terminal_cursor: SessionHistoryCursor(21n),
  };

  return {
    now: NOW,
    serverIdentity: MobileServerIdentity(`sha256:${"a".repeat(64)}`),
    authorization: {
      actions: ["attach", "follow_up"],
      actor: MobileActor("operator:fixture"),
      authorization_revision: MobileRevision(1n),
      credential_id: MobileCredentialId(`mc_${"F".repeat(43)}`),
      credential_revision: MobileRevision(1n),
      expires_at_ms: MobileEpochMillis(BigInt(NOW + 60_000)),
      issued_at_ms: MobileEpochMillis(BigInt(NOW - 1_000)),
      limits: {
        max_follow_up_bytes: MobileFollowUpBytes(128n),
        max_page_events: MobilePageEvents(16n),
      },
      schema: "automonique.mobile-auth/v1",
      server_identity: MobileServerIdentity(`sha256:${"a".repeat(64)}`),
      session_scope: [MobileSessionId("fixture-session")],
    },
    coordinates: {run, session},
    projection: {
      snapshot: {cursor: cursor(10n), resources: [baseline]},
      duplicate,
      conflictingDuplicate: {
        cursor: cursor(10n),
        events: [event(10n, record(run, 10n, "conflicting replay"))],
      },
      gap: {
        cursor: cursor(12n),
        events: [event(12n, record(run, 12n, "gap"))],
      },
      staleRevision: {
        cursor: cursor(11n),
        events: [event(11n, record(run, 9n, "stale"))],
      },
    },
    history: {
      unknownEvent,
      cursorExpired: {
        kind: "session_history_resync",
        session,
        snapshotFrom: SessionHistoryCursor(20n),
        snapshotTo: SessionHistoryCursor(24n),
      },
    },
    mutation: {
      followUp,
      unknownReceipt,
      reconciledReceipt,
      receiptLookup,
      ambiguousThenReconciled: [
        {
          method: "session_follow_up",
          result: {kind: "error", value: new AmbiguousMutationFixtureError()},
        },
        {
          method: "get_receipt",
          result: {kind: "response", value: {kind: "receipt", value: reconciledReceipt}},
        },
      ],
    },
  };
}
