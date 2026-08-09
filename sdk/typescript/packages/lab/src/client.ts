// SPDX-License-Identifier: Apache-2.0

import {
  LAB_PROTOCOL,
  decodeLabResponse,
  type ActionResult,
  type CancelRequest,
  type LabBudget,
  type LabRequest,
  type ObserveRequest,
  type ObserveResult,
  type ProviderPolicy,
  type ResumeRequest,
  type SelectRequest,
  type SelectResult,
} from "./protocol.ts";
import {evaluateProviderPolicy} from "./provider-policy.ts";

export interface LabTransport {
  request(request: LabRequest, options?: {readonly signal?: AbortSignal}): Promise<unknown>;
}

function boundedId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError(`${label} must be a bounded identifier`);
  }
}

function nonNegativeInteger(value: unknown, label: string): void {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
}

function validateRequest(request: LabRequest): void {
  boundedId(request.requestId, "requestId");
  if (request.op === "select") {
    boundedId(request.objectiveId, "objectiveId");
    if (!/^[0-9a-f]{40}$/.test(request.expectedBase) || request.synthetic !== true) {
      throw new TypeError("select requires a synthetic unit at a full immutable base");
    }
  } else {
    boundedId(request.unitId, "unitId");
  }
  if (request.op === "observe") {
    nonNegativeInteger(request.afterSequence, "afterSequence");
    if (!Number.isSafeInteger(request.limit) || request.limit < 1 || request.limit > 1000) {
      throw new TypeError("observe limit must be between 1 and 1000");
    }
  }
  if (request.op === "resume" || request.op === "cancel") {
    nonNegativeInteger(request.expectedRevision, "expectedRevision");
    boundedId(request.idempotencyKey, "idempotencyKey");
  }
  if (request.op === "resume") boundedId(request.checkpointId, "checkpointId");
}

type WithoutEnvelope<T extends LabRequest> = Omit<T, "protocol" | "op">;

export class LabClient {
  constructor(private readonly transport: LabTransport) {}

  async select(
    input: WithoutEnvelope<SelectRequest>,
    options?: {readonly signal?: AbortSignal},
  ): Promise<SelectResult> {
    const decision = evaluateProviderPolicy(input.providerPolicy, input.budget);
    if (!decision.allowed) throw new TypeError(`selection policy denied: ${decision.code}`);
    return this.call({protocol: LAB_PROTOCOL, op: "select", ...input}, options) as Promise<SelectResult>;
  }

  async observe(
    input: WithoutEnvelope<ObserveRequest>,
    options?: {readonly signal?: AbortSignal},
  ): Promise<ObserveResult> {
    return this.call({protocol: LAB_PROTOCOL, op: "observe", ...input}, options) as Promise<ObserveResult>;
  }

  async resume(
    input: WithoutEnvelope<ResumeRequest>,
    options?: {readonly signal?: AbortSignal},
  ): Promise<ActionResult> {
    return this.call({protocol: LAB_PROTOCOL, op: "resume", ...input}, options) as Promise<ActionResult>;
  }

  async cancel(
    input: WithoutEnvelope<CancelRequest>,
    options?: {readonly signal?: AbortSignal},
  ): Promise<ActionResult> {
    return this.call({protocol: LAB_PROTOCOL, op: "cancel", ...input}, options) as Promise<ActionResult>;
  }

  private async call(
    request: LabRequest,
    options?: {readonly signal?: AbortSignal},
  ) {
    validateRequest(request);
    const raw = await this.transport.request(request, options);
    const response = decodeLabResponse(raw, request.op, request.requestId);
    if (response.kind === "denied") return response;
    if (request.op === "select") {
      if (response.kind !== "selected" || response.unit.objectiveId !== request.objectiveId) {
        throw new TypeError("selected response objective does not match the request");
      }
    } else if (response.unit.unitId !== request.unitId) {
      throw new TypeError("response unit does not match the request");
    }
    if (request.op === "observe" && response.kind === "observed") {
      if (response.events.length > request.limit) throw new TypeError("observe page exceeds its request limit");
      let sequence = request.afterSequence;
      for (const event of response.events) {
        if (event.sequence !== sequence + 1) throw new TypeError("observe page has a sequence gap or duplicate");
        sequence = event.sequence;
      }
      if (response.nextSequence !== sequence || response.unit.lastSequence < sequence) {
        throw new TypeError("observe cursors are inconsistent");
      }
    }
    if (
      (request.op === "resume" || request.op === "cancel") &&
      response.kind === "action" &&
      response.receipt.idempotencyKey !== request.idempotencyKey
    ) {
      throw new TypeError("action receipt does not match the idempotency key");
    }
    return response;
  }
}

export type {LabBudget, ProviderPolicy};
