// SPDX-License-Identifier: Apache-2.0

export const LAB_PROTOCOL = "automonique.lab-scenario/v1" as const;

export const CAPABILITIES = [
  "approval",
  "cancel",
  "create",
  "model",
  "observe",
  "reconnect",
  "resume",
  "steer",
  "usage",
] as const;

export type Capability = (typeof CAPABILITIES)[number];
export type CapabilitySupport =
  | "advertised"
  | "observed"
  | "unknown"
  | "unavailable";

export interface LabBudget {
  readonly maxWallMs: number;
  readonly maxCpuMs: number;
  readonly maxDiskBytes: number;
  readonly maxOutputBytes: number;
  readonly maxPids: number;
  readonly maxModelCalls: number;
  readonly maxCostMicrounits: number;
  readonly enforcement: "synthetic_in_process" | "host_broker_required";
}

export interface SyntheticProviderPolicy {
  readonly kind: "synthetic";
  readonly driver: "in_process_fixture";
  readonly network: "deny";
  readonly authentication: "none";
  readonly maxModelCalls: 0;
  readonly maxCostMicrounits: 0;
}

export interface InventoryProviderPolicy {
  readonly kind: "inventory";
  readonly provider: string;
  readonly mode: string;
  readonly inventoryDigest: string;
  readonly surfaceDigest: string;
  readonly requiredCapabilities: readonly Capability[];
  readonly minimumEvidence: "advertised" | "observed";
  readonly explicitFallbackModes: readonly string[];
}

export type ProviderPolicy =
  | SyntheticProviderPolicy
  | InventoryProviderPolicy;

interface RequestBase {
  readonly protocol: typeof LAB_PROTOCOL;
  readonly requestId: string;
}

export interface SelectRequest extends RequestBase {
  readonly op: "select";
  readonly objectiveId: string;
  readonly expectedBase: string;
  readonly synthetic: true;
  readonly providerPolicy: SyntheticProviderPolicy;
  readonly budget: LabBudget;
}

export interface ObserveRequest extends RequestBase {
  readonly op: "observe";
  readonly unitId: string;
  readonly afterSequence: number;
  readonly limit: number;
}

export interface ResumeRequest extends RequestBase {
  readonly op: "resume";
  readonly unitId: string;
  readonly checkpointId: string;
  readonly expectedRevision: number;
  readonly idempotencyKey: string;
}

export type CancelReason =
  | "operator_request"
  | "budget_exhausted"
  | "policy_denied";

export interface CancelRequest extends RequestBase {
  readonly op: "cancel";
  readonly unitId: string;
  readonly expectedRevision: number;
  readonly idempotencyKey: string;
  readonly reason: CancelReason;
}

export type LabRequest =
  | SelectRequest
  | ObserveRequest
  | ResumeRequest
  | CancelRequest;

export type UnitState =
  | "queued"
  | "selected"
  | "running"
  | "paused"
  | "cancel_requested"
  | "cancelled"
  | "succeeded"
  | "failed"
  | "blocked";

export interface UnitSnapshot {
  readonly unitId: string;
  readonly objectiveId: string;
  readonly state: UnitState;
  readonly revision: number;
  readonly checkpointId: string | null;
  readonly lastSequence: number;
}

export type KnownEventType =
  | "unit.selected"
  | "unit.resumed"
  | "unit.cancel_requested"
  | "unit.cancelled"
  | "unit.terminal";

export interface KnownLabEvent {
  readonly type: KnownEventType;
  readonly sequence: number;
  readonly revision: number;
}

export interface UnknownLabEvent {
  readonly type: "unknown";
  readonly rawType: string;
  readonly sequence: number;
  readonly revision: number;
}

export type LabEvent = KnownLabEvent | UnknownLabEvent;

interface ResponseBase {
  readonly protocol: typeof LAB_PROTOCOL;
  readonly requestId: string;
}

export interface SelectedResponse extends ResponseBase {
  readonly kind: "selected";
  readonly unit: UnitSnapshot;
}

export interface ObservedResponse extends ResponseBase {
  readonly kind: "observed";
  readonly unit: UnitSnapshot;
  readonly events: readonly LabEvent[];
  readonly nextSequence: number;
}

export type ActionStatus =
  | "accepted"
  | "already_applied"
  | "conflict"
  | "denied";

export interface ActionReceipt {
  readonly actionId: string;
  readonly idempotencyKey: string;
  readonly status: ActionStatus;
  readonly effectCount: number;
  readonly reason: string | null;
}

export interface ActionResponse extends ResponseBase {
  readonly kind: "action";
  readonly receipt: ActionReceipt;
  readonly unit: UnitSnapshot;
}

export interface DeniedResponse extends ResponseBase {
  readonly kind: "denied";
  readonly code: string;
  readonly reason: string;
}

export type SelectResult = SelectedResponse | DeniedResponse;
export type ObserveResult = ObservedResponse | DeniedResponse;
export type ActionResult = ActionResponse | DeniedResponse;
export type LabResponse =
  | SelectedResponse
  | ObservedResponse
  | ActionResponse
  | DeniedResponse;

const UNIT_STATES = new Set<string>([
  "queued",
  "selected",
  "running",
  "paused",
  "cancel_requested",
  "cancelled",
  "succeeded",
  "failed",
  "blocked",
]);

const KNOWN_EVENTS = new Set<string>([
  "unit.selected",
  "unit.resumed",
  "unit.cancel_requested",
  "unit.cancelled",
  "unit.terminal",
]);

const ACTION_STATUSES = new Set<string>([
  "accepted",
  "already_applied",
  "conflict",
  "denied",
]);

type JsonRecord = Record<string, unknown>;

function record(value: unknown, context: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, keys: readonly string[], context: string): void {
  const expected = new Set(keys);
  if (
    Object.keys(value).length !== expected.size ||
    Object.keys(value).some((key) => !expected.has(key))
  ) {
    throw new TypeError(`${context} has unexpected or missing fields`);
  }
}

function text(value: unknown, context: string, maxLength = 256): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    throw new TypeError(`${context} must be a bounded non-empty string`);
  }
  return value;
}

function integer(value: unknown, context: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${context} must be a non-negative safe integer`);
  }
  return value as number;
}

function nullableText(value: unknown, context: string): string | null {
  return value === null ? null : text(value, context);
}

function decodeUnit(value: unknown): UnitSnapshot {
  const unit = record(value, "unit");
  exactKeys(
    unit,
    [
      "unitId",
      "objectiveId",
      "state",
      "revision",
      "checkpointId",
      "lastSequence",
    ],
    "unit",
  );
  const state = text(unit.state, "unit.state");
  if (!UNIT_STATES.has(state)) {
    throw new TypeError("unit.state is unknown");
  }
  return {
    unitId: text(unit.unitId, "unit.unitId"),
    objectiveId: text(unit.objectiveId, "unit.objectiveId"),
    state: state as UnitState,
    revision: integer(unit.revision, "unit.revision"),
    checkpointId: nullableText(unit.checkpointId, "unit.checkpointId"),
    lastSequence: integer(unit.lastSequence, "unit.lastSequence"),
  };
}

function decodeEvent(value: unknown): LabEvent {
  const event = record(value, "event");
  const rawType = text(event.type, "event.type", 128);
  const sequence = integer(event.sequence, "event.sequence");
  const revision = integer(event.revision, "event.revision");
  if (KNOWN_EVENTS.has(rawType)) {
    exactKeys(event, ["type", "sequence", "revision"], "known event");
    return {type: rawType as KnownEventType, sequence, revision};
  }
  return {type: "unknown", rawType, sequence, revision};
}

function decodeReceipt(value: unknown): ActionReceipt {
  const receipt = record(value, "receipt");
  exactKeys(
    receipt,
    ["actionId", "idempotencyKey", "status", "effectCount", "reason"],
    "receipt",
  );
  const status = text(receipt.status, "receipt.status");
  if (!ACTION_STATUSES.has(status)) {
    throw new TypeError("receipt.status is unknown");
  }
  const effectCount = integer(receipt.effectCount, "receipt.effectCount");
  if (
    ((status === "accepted" || status === "already_applied") && effectCount !== 1) ||
    ((status === "conflict" || status === "denied") && effectCount !== 0)
  ) {
    throw new TypeError("receipt effect count contradicts its status");
  }
  return {
    actionId: text(receipt.actionId, "receipt.actionId"),
    idempotencyKey: text(receipt.idempotencyKey, "receipt.idempotencyKey"),
    status: status as ActionStatus,
    effectCount,
    reason: nullableText(receipt.reason, "receipt.reason"),
  };
}

function decodeBase(value: JsonRecord): {requestId: string; kind: string} {
  if (value.protocol !== LAB_PROTOCOL) {
    throw new TypeError("response protocol is unsupported");
  }
  return {
    requestId: text(value.requestId, "response.requestId"),
    kind: text(value.kind, "response.kind"),
  };
}

export function decodeLabResponse(
  value: unknown,
  expectedOp: LabRequest["op"],
  expectedRequestId: string,
): LabResponse {
  const response = record(value, "response");
  const base = decodeBase(response);
  if (base.requestId !== expectedRequestId) {
    throw new TypeError("response requestId does not match the request");
  }

  if (base.kind === "denied") {
    exactKeys(response, ["protocol", "requestId", "kind", "code", "reason"], "denied response");
    return {
      protocol: LAB_PROTOCOL,
      requestId: base.requestId,
      kind: "denied",
      code: text(response.code, "response.code"),
      reason: text(response.reason, "response.reason", 1024),
    };
  }

  if (expectedOp === "select" && base.kind === "selected") {
    exactKeys(response, ["protocol", "requestId", "kind", "unit"], "selected response");
    return {
      protocol: LAB_PROTOCOL,
      requestId: base.requestId,
      kind: "selected",
      unit: decodeUnit(response.unit),
    };
  }

  if (expectedOp === "observe" && base.kind === "observed") {
    exactKeys(
      response,
      ["protocol", "requestId", "kind", "unit", "events", "nextSequence"],
      "observed response",
    );
    if (!Array.isArray(response.events) || response.events.length > 1000) {
      throw new TypeError("response.events must be a bounded array");
    }
    return {
      protocol: LAB_PROTOCOL,
      requestId: base.requestId,
      kind: "observed",
      unit: decodeUnit(response.unit),
      events: response.events.map(decodeEvent),
      nextSequence: integer(response.nextSequence, "response.nextSequence"),
    };
  }

  if (
    (expectedOp === "resume" || expectedOp === "cancel") &&
    base.kind === "action"
  ) {
    exactKeys(
      response,
      ["protocol", "requestId", "kind", "receipt", "unit"],
      "action response",
    );
    return {
      protocol: LAB_PROTOCOL,
      requestId: base.requestId,
      kind: "action",
      receipt: decodeReceipt(response.receipt),
      unit: decodeUnit(response.unit),
    };
  }

  throw new TypeError(`response kind ${base.kind} is invalid for ${expectedOp}`);
}
