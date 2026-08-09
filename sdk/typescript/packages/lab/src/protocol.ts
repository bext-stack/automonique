// SPDX-License-Identifier: Apache-2.0

export const LAB_PROTOCOL = "automonique.lab-scenario/v1" as const;
export const CAPABILITIES = [
  "approval", "cancel", "create", "model", "observe",
  "reconnect", "resume", "steer", "usage",
] as const;

export type Capability = (typeof CAPABILITIES)[number];
export type CapabilitySupport = "advertised" | "observed" | "unknown" | "unavailable";
export type EvidenceLevel = "advertised" | "observed";

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

export interface ExplicitFallback {
  readonly mode: string;
  readonly acceptedLostGuarantees: readonly string[];
}

/** Wire policy. Digests are added only from a validated provider projection. */
export interface InventoryProviderPolicy {
  readonly kind: "inventory";
  readonly provider: string;
  readonly mode: string;
  readonly inventoryDigest: string;
  readonly surfaceDigest: string;
  readonly requiredCapabilities: readonly Capability[];
  readonly minimumEvidence: EvidenceLevel;
  readonly explicitFallbacks: readonly ExplicitFallback[];
}

/** Caller selection. It deliberately contains no caller-supplied digest. */
export interface InventoryProviderSelection {
  readonly kind: "inventory";
  readonly provider: string;
  readonly mode: string;
  readonly requiredCapabilities: readonly Capability[];
  readonly minimumEvidence: EvidenceLevel;
  readonly explicitFallbacks: readonly ExplicitFallback[];
}

export type ProviderPolicy = SyntheticProviderPolicy | InventoryProviderPolicy;
export type ProviderSelection = SyntheticProviderPolicy | InventoryProviderSelection;

interface RequestBase {
  readonly protocol: typeof LAB_PROTOCOL;
  readonly requestId: string;
}

export interface SelectRequest extends RequestBase {
  readonly op: "select";
  readonly objectiveId: string;
  readonly expectedBase: string;
  readonly execution: "synthetic" | "inventory";
  readonly providerPolicy: ProviderPolicy;
  readonly budget: LabBudget;
}

export interface ObserveRequest extends RequestBase {
  readonly op: "observe";
  readonly objectiveId: string;
  readonly unitId: string;
  readonly afterSequence: number;
  readonly limit: number;
}

export interface ResumeRequest extends RequestBase {
  readonly op: "resume";
  readonly objectiveId: string;
  readonly unitId: string;
  readonly checkpointId: string;
  readonly expectedRevision: number;
  readonly idempotencyKey: string;
}

export type CancelReason = "operator_request" | "budget_exhausted" | "policy_denied";
export interface CancelRequest extends RequestBase {
  readonly op: "cancel";
  readonly objectiveId: string;
  readonly unitId: string;
  readonly expectedRevision: number;
  readonly idempotencyKey: string;
  readonly reason: CancelReason;
}

export type LabRequest = SelectRequest | ObserveRequest | ResumeRequest | CancelRequest;
export type UnitState = "queued" | "selected" | "running" | "paused" |
  "cancel_requested" | "cancelled" | "succeeded" | "failed" | "blocked";

export interface UnitSnapshot {
  readonly unitId: string;
  readonly objectiveId: string;
  readonly state: UnitState;
  readonly revision: number;
  readonly checkpointId: string | null;
  readonly lastSequence: number;
}

export type KnownEventType = "unit.selected" | "unit.resumed" |
  "unit.cancel_requested" | "unit.cancelled" | "unit.terminal";
export interface KnownLabEvent {
  readonly type: KnownEventType;
  readonly objectiveId: string;
  readonly unitId: string;
  readonly sequence: number;
  readonly revision: number;
}
export interface UnknownLabEvent {
  readonly type: "unknown";
  readonly rawType: string;
  readonly objectiveId: string;
  readonly unitId: string;
  readonly sequence: number;
  readonly revision: number;
}
export type LabEvent = KnownLabEvent | UnknownLabEvent;

interface ResponseBase { readonly protocol: typeof LAB_PROTOCOL; readonly requestId: string; }
export interface SelectedResponse extends ResponseBase { readonly kind: "selected"; readonly unit: UnitSnapshot; }
export interface ObservedResponse extends ResponseBase {
  readonly kind: "observed";
  readonly unit: UnitSnapshot;
  readonly events: readonly LabEvent[];
  readonly nextSequence: number;
}
export type ActionStatus = "accepted" | "already_applied" | "conflict" | "denied";
export interface ActionReceipt {
  readonly actionId: string;
  readonly operation: "resume" | "cancel";
  readonly objectiveId: string;
  readonly unitId: string;
  readonly checkpointId: string | null;
  readonly expectedRevision: number;
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
export type LabResponse = SelectedResponse | ObservedResponse | ActionResponse | DeniedResponse;

type JsonRecord = Record<string, unknown>;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UNIT_STATES = new Set<string>(["queued", "selected", "running", "paused", "cancel_requested", "cancelled", "succeeded", "failed", "blocked"]);
const KNOWN_EVENTS = new Set<string>(["unit.selected", "unit.resumed", "unit.cancel_requested", "unit.cancelled", "unit.terminal"]);
const ACTION_STATUSES = new Set<string>(["accepted", "already_applied", "conflict", "denied"]);
const CAPABILITY_SET = new Set<string>(CAPABILITIES);

function record(value: unknown, context: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${context} must be an object`);
  return value as JsonRecord;
}
function exactKeys(value: JsonRecord, keys: readonly string[], context: string): void {
  const expected = new Set(keys);
  if (Object.keys(value).length !== expected.size || Object.keys(value).some((key) => !expected.has(key))) {
    throw new TypeError(`${context} has unexpected or missing fields`);
  }
}
function text(value: unknown, context: string, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError(`${context} must be bounded text without control characters`);
  }
  return value;
}
function id(value: unknown, context: string): string {
  const result = text(value, context, 128);
  if (!IDENTIFIER.test(result)) throw new TypeError(`${context} must be a bounded identifier`);
  return result;
}
function integer(value: unknown, context: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new TypeError(`${context} must be a safe integer >= ${minimum}`);
  return value as number;
}
function nullableId(value: unknown, context: string): string | null { return value === null ? null : id(value, context); }

export function validateBudget(value: unknown): asserts value is LabBudget {
  const budget = record(value, "budget");
  exactKeys(budget, ["maxWallMs", "maxCpuMs", "maxDiskBytes", "maxOutputBytes", "maxPids", "maxModelCalls", "maxCostMicrounits", "enforcement"], "budget");
  for (const field of ["maxWallMs", "maxCpuMs", "maxDiskBytes", "maxOutputBytes", "maxPids"] as const) integer(budget[field], `budget.${field}`, 1);
  integer(budget.maxModelCalls, "budget.maxModelCalls");
  integer(budget.maxCostMicrounits, "budget.maxCostMicrounits");
  if (budget.enforcement !== "synthetic_in_process" && budget.enforcement !== "host_broker_required") throw new TypeError("budget.enforcement is unknown");
}

function validateCapabilities(value: unknown, context: string): asserts value is readonly Capability[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > CAPABILITIES.length) throw new TypeError(`${context} must be a bounded capability array`);
  const seen = new Set<string>();
  for (const capability of value) {
    if (typeof capability !== "string" || !CAPABILITY_SET.has(capability) || seen.has(capability)) throw new TypeError(`${context} contains an unknown or duplicate capability`);
    seen.add(capability);
  }
}
function validateFallbacks(value: unknown, context: string): asserts value is readonly ExplicitFallback[] {
  if (!Array.isArray(value) || value.length > 16) throw new TypeError(`${context} must be a bounded array`);
  const seen = new Set<string>();
  for (const raw of value) {
    const fallback = record(raw, `${context} entry`);
    exactKeys(fallback, ["mode", "acceptedLostGuarantees"], `${context} entry`);
    const mode = id(fallback.mode, `${context}.mode`);
    if (seen.has(mode)) throw new TypeError(`${context} contains a duplicate mode`);
    seen.add(mode);
    if (!Array.isArray(fallback.acceptedLostGuarantees) || fallback.acceptedLostGuarantees.length > 32) throw new TypeError(`${context}.acceptedLostGuarantees must be bounded`);
    for (const loss of fallback.acceptedLostGuarantees) text(loss, `${context}.acceptedLostGuarantees`, 512);
  }
}
function validatePolicy(value: unknown): asserts value is ProviderPolicy {
  const policy = record(value, "providerPolicy");
  if (policy.kind === "synthetic") {
    exactKeys(policy, ["kind", "driver", "network", "authentication", "maxModelCalls", "maxCostMicrounits"], "synthetic providerPolicy");
    if (policy.driver !== "in_process_fixture" || policy.network !== "deny" || policy.authentication !== "none" || policy.maxModelCalls !== 0 || policy.maxCostMicrounits !== 0) throw new TypeError("synthetic providerPolicy is unsafe");
    return;
  }
  if (policy.kind !== "inventory") throw new TypeError("providerPolicy.kind is unknown");
  exactKeys(policy, ["kind", "provider", "mode", "inventoryDigest", "surfaceDigest", "requiredCapabilities", "minimumEvidence", "explicitFallbacks"], "inventory providerPolicy");
  id(policy.provider, "providerPolicy.provider"); id(policy.mode, "providerPolicy.mode");
  if (typeof policy.inventoryDigest !== "string" || !SHA256.test(policy.inventoryDigest) || typeof policy.surfaceDigest !== "string" || !SHA256.test(policy.surfaceDigest)) throw new TypeError("providerPolicy digests must be full SHA-256 values");
  validateCapabilities(policy.requiredCapabilities, "providerPolicy.requiredCapabilities");
  if (policy.minimumEvidence !== "advertised" && policy.minimumEvidence !== "observed") throw new TypeError("providerPolicy.minimumEvidence is unknown");
  validateFallbacks(policy.explicitFallbacks, "providerPolicy.explicitFallbacks");
}

export function validateLabRequest(value: unknown): asserts value is LabRequest {
  const request = record(value, "request");
  if (request.protocol !== LAB_PROTOCOL) throw new TypeError("request protocol is unsupported");
  id(request.requestId, "request.requestId");
  if (request.op === "select") {
    exactKeys(request, ["protocol", "requestId", "op", "objectiveId", "expectedBase", "execution", "providerPolicy", "budget"], "select request");
    id(request.objectiveId, "request.objectiveId");
    if (typeof request.expectedBase !== "string" || !SHA1.test(request.expectedBase)) throw new TypeError("request.expectedBase must be a full SHA-1 object ID");
    validatePolicy(request.providerPolicy); validateBudget(request.budget);
    const policy = request.providerPolicy as ProviderPolicy;
    if ((request.execution === "synthetic") !== (policy.kind === "synthetic")) throw new TypeError("request execution and provider policy disagree");
    if (request.execution !== "synthetic" && request.execution !== "inventory") throw new TypeError("request.execution is unknown");
    return;
  }
  if (request.op === "observe") {
    exactKeys(request, ["protocol", "requestId", "op", "objectiveId", "unitId", "afterSequence", "limit"], "observe request");
    id(request.objectiveId, "request.objectiveId"); id(request.unitId, "request.unitId"); integer(request.afterSequence, "request.afterSequence"); integer(request.limit, "request.limit", 1);
    if ((request.limit as number) > 1000) throw new TypeError("request.limit must be <= 1000");
    return;
  }
  if (request.op === "resume") {
    exactKeys(request, ["protocol", "requestId", "op", "objectiveId", "unitId", "checkpointId", "expectedRevision", "idempotencyKey"], "resume request");
    id(request.objectiveId, "request.objectiveId"); id(request.unitId, "request.unitId"); id(request.checkpointId, "request.checkpointId"); integer(request.expectedRevision, "request.expectedRevision"); id(request.idempotencyKey, "request.idempotencyKey");
    return;
  }
  if (request.op === "cancel") {
    exactKeys(request, ["protocol", "requestId", "op", "objectiveId", "unitId", "expectedRevision", "idempotencyKey", "reason"], "cancel request");
    id(request.objectiveId, "request.objectiveId"); id(request.unitId, "request.unitId"); integer(request.expectedRevision, "request.expectedRevision"); id(request.idempotencyKey, "request.idempotencyKey");
    if (!new Set(["operator_request", "budget_exhausted", "policy_denied"]).has(String(request.reason))) throw new TypeError("request.reason is unknown");
    return;
  }
  throw new TypeError("request.op is unknown");
}

function decodeUnit(value: unknown): UnitSnapshot {
  const unit = record(value, "unit");
  exactKeys(unit, ["unitId", "objectiveId", "state", "revision", "checkpointId", "lastSequence"], "unit");
  const state = text(unit.state, "unit.state"); if (!UNIT_STATES.has(state)) throw new TypeError("unit.state is unknown");
  return {unitId: id(unit.unitId, "unit.unitId"), objectiveId: id(unit.objectiveId, "unit.objectiveId"), state: state as UnitState, revision: integer(unit.revision, "unit.revision"), checkpointId: nullableId(unit.checkpointId, "unit.checkpointId"), lastSequence: integer(unit.lastSequence, "unit.lastSequence")};
}
function decodeEvent(value: unknown): LabEvent {
  const event = record(value, "event");
  exactKeys(event, ["type", "objectiveId", "unitId", "sequence", "revision"], "event");
  const rawType = text(event.type, "event.type", 128);
  const common = {objectiveId: id(event.objectiveId, "event.objectiveId"), unitId: id(event.unitId, "event.unitId"), sequence: integer(event.sequence, "event.sequence"), revision: integer(event.revision, "event.revision")};
  return KNOWN_EVENTS.has(rawType) ? {type: rawType as KnownEventType, ...common} : {type: "unknown", rawType, ...common};
}
function decodeReceipt(value: unknown): ActionReceipt {
  const receipt = record(value, "receipt");
  exactKeys(receipt, ["actionId", "operation", "objectiveId", "unitId", "checkpointId", "expectedRevision", "idempotencyKey", "status", "effectCount", "reason"], "receipt");
  if (receipt.operation !== "resume" && receipt.operation !== "cancel") throw new TypeError("receipt.operation is unknown");
  const status = text(receipt.status, "receipt.status"); if (!ACTION_STATUSES.has(status)) throw new TypeError("receipt.status is unknown");
  const effectCount = integer(receipt.effectCount, "receipt.effectCount");
  const reason = receipt.reason === null ? null : text(receipt.reason, "receipt.reason", 1024);
  const applied = status === "accepted" || status === "already_applied";
  if ((applied && (effectCount !== 1 || reason !== null)) || (!applied && (effectCount !== 0 || reason === null))) throw new TypeError("receipt status, effect count and reason are inconsistent");
  return {actionId: id(receipt.actionId, "receipt.actionId"), operation: receipt.operation, objectiveId: id(receipt.objectiveId, "receipt.objectiveId"), unitId: id(receipt.unitId, "receipt.unitId"), checkpointId: nullableId(receipt.checkpointId, "receipt.checkpointId"), expectedRevision: integer(receipt.expectedRevision, "receipt.expectedRevision"), idempotencyKey: id(receipt.idempotencyKey, "receipt.idempotencyKey"), status: status as ActionStatus, effectCount, reason};
}

export function decodeLabResponse(value: unknown, request: LabRequest): LabResponse {
  const response = record(value, "response");
  if (response.protocol !== LAB_PROTOCOL || response.requestId !== request.requestId) throw new TypeError("response protocol or request coordinate does not match");
  if (response.kind === "denied") {
    exactKeys(response, ["protocol", "requestId", "kind", "code", "reason"], "denied response");
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "denied", code: id(response.code, "response.code"), reason: text(response.reason, "response.reason", 1024)};
  }
  if (request.op === "select" && response.kind === "selected") {
    exactKeys(response, ["protocol", "requestId", "kind", "unit"], "selected response");
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "selected", unit: decodeUnit(response.unit)};
  }
  if (request.op === "observe" && response.kind === "observed") {
    exactKeys(response, ["protocol", "requestId", "kind", "unit", "events", "nextSequence"], "observed response");
    if (!Array.isArray(response.events) || response.events.length > 1000) throw new TypeError("response.events must be bounded");
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "observed", unit: decodeUnit(response.unit), events: response.events.map(decodeEvent), nextSequence: integer(response.nextSequence, "response.nextSequence")};
  }
  if ((request.op === "resume" || request.op === "cancel") && response.kind === "action") {
    exactKeys(response, ["protocol", "requestId", "kind", "receipt", "unit"], "action response");
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action", receipt: decodeReceipt(response.receipt), unit: decodeUnit(response.unit)};
  }
  throw new TypeError(`response kind ${String(response.kind)} is invalid for ${request.op}`);
}
