// SPDX-License-Identifier: Apache-2.0

import {
  LAB_PROTOCOL,
  decodeLabResponse,
  validateLabRequest,
  type ActionResult,
  type CancelReason,
  type CancelRequest,
  type InventoryProviderSelection,
  type LabBudget,
  type LabRequest,
  type ObserveRequest,
  type ObserveResult,
  type ResumeRequest,
  type SelectRequest,
  type SelectResult,
  type SyntheticProviderPolicy,
} from "./protocol.ts";
import {
  evaluateProviderPolicy,
  type ProviderInventoryProjection,
} from "./provider-policy.ts";

export interface LabTransport {
  request(request: LabRequest, options?: {readonly signal?: AbortSignal}): Promise<unknown>;
}

interface SelectBase {
  readonly requestId: string;
  readonly objectiveId: string;
  readonly expectedBase: string;
  readonly budget: LabBudget;
}
export type SelectInput = SelectBase & (
  | {readonly execution: "synthetic"; readonly providerPolicy: SyntheticProviderPolicy; readonly providerProjection?: never}
  | {readonly execution: "inventory"; readonly providerPolicy: InventoryProviderSelection; readonly providerProjection: ProviderInventoryProjection}
);
export interface ObserveInput { readonly requestId: string; readonly objectiveId: string; readonly unitId: string; readonly afterSequence: number; readonly limit: number; }
export interface ResumeInput { readonly requestId: string; readonly objectiveId: string; readonly unitId: string; readonly checkpointId: string; readonly expectedRevision: number; readonly idempotencyKey: string; }
export interface CancelInput { readonly requestId: string; readonly objectiveId: string; readonly unitId: string; readonly expectedRevision: number; readonly idempotencyKey: string; readonly reason: CancelReason; }

export class LabClient {
  constructor(private readonly transport: LabTransport) {}

  async select(input: SelectInput, options?: {readonly signal?: AbortSignal}): Promise<SelectResult> {
    const decision = evaluateProviderPolicy(input.providerPolicy, input.budget, input.execution === "inventory" ? input.providerProjection : undefined);
    if (!decision.allowed) throw new TypeError(`selection policy denied: ${decision.code}: ${decision.reason}`);
    const request: SelectRequest = {
      protocol: LAB_PROTOCOL,
      requestId: input.requestId,
      op: "select",
      objectiveId: input.objectiveId,
      expectedBase: input.expectedBase,
      execution: input.execution,
      providerPolicy: decision.policy,
      budget: input.budget,
    };
    return this.call(request, options) as Promise<SelectResult>;
  }

  async observe(input: ObserveInput, options?: {readonly signal?: AbortSignal}): Promise<ObserveResult> {
    const request: ObserveRequest = {protocol: LAB_PROTOCOL, op: "observe", ...input};
    return this.call(request, options) as Promise<ObserveResult>;
  }
  async resume(input: ResumeInput, options?: {readonly signal?: AbortSignal}): Promise<ActionResult> {
    const request: ResumeRequest = {protocol: LAB_PROTOCOL, op: "resume", ...input};
    return this.call(request, options) as Promise<ActionResult>;
  }
  async cancel(input: CancelInput, options?: {readonly signal?: AbortSignal}): Promise<ActionResult> {
    const request: CancelRequest = {protocol: LAB_PROTOCOL, op: "cancel", ...input};
    return this.call(request, options) as Promise<ActionResult>;
  }

  private async call(request: LabRequest, options?: {readonly signal?: AbortSignal}) {
    validateLabRequest(request);
    const raw = await this.transport.request(request, options);
    const response = decodeLabResponse(raw, request);
    if (response.kind === "denied") return response;

    if (response.unit.objectiveId !== request.objectiveId) throw new TypeError("response objective does not match the request");
    if (request.op === "select") return response;
    if (response.unit.unitId !== request.unitId) throw new TypeError("response unit does not match the request");

    if (request.op === "observe" && response.kind === "observed") {
      if (response.events.length > request.limit) throw new TypeError("observe page exceeds its request limit");
      if (response.unit.lastSequence < request.afterSequence) throw new TypeError("observe snapshot is behind the request cursor");
      let sequence = request.afterSequence;
      let revision = -1;
      for (const event of response.events) {
        if (event.objectiveId !== request.objectiveId || event.unitId !== request.unitId) throw new TypeError("observe event coordinates do not match the request");
        if (event.sequence !== sequence + 1) throw new TypeError("observe page has a sequence gap or duplicate");
        if (event.revision < revision || event.revision > response.unit.revision) throw new TypeError("observe event revision is incoherent");
        sequence = event.sequence; revision = event.revision;
      }
      if (response.nextSequence !== sequence || response.nextSequence > response.unit.lastSequence) throw new TypeError("observe cursors are inconsistent");
      return response;
    }

    if ((request.op === "resume" || request.op === "cancel") && response.kind === "action") {
      const receipt = response.receipt;
      const checkpoint = request.op === "resume" ? request.checkpointId : null;
      if (receipt.operation !== request.op || receipt.objectiveId !== request.objectiveId || receipt.unitId !== request.unitId || receipt.checkpointId !== checkpoint || receipt.expectedRevision !== request.expectedRevision || receipt.idempotencyKey !== request.idempotencyKey) throw new TypeError("action receipt coordinates do not match the request");
      if ((receipt.status === "accepted" || receipt.status === "already_applied") && response.unit.revision < request.expectedRevision + 1) throw new TypeError("applied action did not advance the unit revision");
      if (receipt.status === "accepted" && request.op === "resume" && (response.unit.state !== "running" || response.unit.checkpointId !== null)) throw new TypeError("accepted resume has an incoherent snapshot");
      if (receipt.status === "accepted" && request.op === "cancel" && response.unit.state !== "cancel_requested" && response.unit.state !== "cancelled") throw new TypeError("accepted cancel has an incoherent snapshot");
      return response;
    }
    throw new TypeError(`response kind is incoherent for ${request.op}`);
  }
}

export type {LabBudget};
