// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";
import {LAB_PROTOCOL, LabClient, type LabRequest, type LabTransport, type UnitSnapshot} from "../src/index.ts";

const objectiveId = "R0-19-synthetic";
const syntheticPolicy = {kind: "synthetic", driver: "in_process_fixture", network: "deny", authentication: "none", maxModelCalls: 0, maxCostMicrounits: 0} as const;
const budget = {maxWallMs: 1_000, maxCpuMs: 500, maxDiskBytes: 16_384, maxOutputBytes: 4_096, maxPids: 1, maxModelCalls: 0, maxCostMicrounits: 0, enforcement: "synthetic_in_process"} as const;
const selectInput = {requestId: "select", objectiveId, expectedBase: "1".repeat(40), execution: "synthetic", providerPolicy: syntheticPolicy, budget} as const;

class DurableFake implements LabTransport {
  unit: UnitSnapshot = {unitId: "unit-1", objectiveId, state: "queued", revision: 0, checkpointId: null, lastSequence: 0};
  events: Array<Record<string, unknown>> = [];
  effects = {resume: 0, cancel: 0};
  calls = 0;
  private receipts = new Map<string, Record<string, unknown>>();

  pause(checkpointId = "checkpoint-1") { this.unit = {...this.unit, state: "paused", revision: this.unit.revision + 1, checkpointId}; }
  async request(request: LabRequest, options?: {readonly signal?: AbortSignal}) {
    this.calls += 1;
    if (options?.signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (request.op === "select") {
      this.unit = {...this.unit, state: "selected", revision: 1, lastSequence: 1};
      this.events.push({type: "unit.selected", objectiveId, unitId: "unit-1", sequence: 1, revision: 1});
      return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "selected", unit: this.unit};
    }
    if (request.op === "observe") {
      const events = this.events.filter((event) => Number(event.sequence) > request.afterSequence).slice(0, request.limit);
      return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "observed", unit: this.unit, events, nextSequence: events.length ? Number(events.at(-1)?.sequence) : request.afterSequence};
    }
    const checkpointId = request.op === "resume" ? request.checkpointId : null;
    const prior = this.receipts.get(request.idempotencyKey);
    if (prior) return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action", receipt: {...prior, status: "already_applied"}, unit: this.unit};
    if (request.expectedRevision !== this.unit.revision) return {
      protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action",
      receipt: {actionId: `action-${request.op}-conflict`, operation: request.op, objectiveId: request.objectiveId, unitId: request.unitId, checkpointId, expectedRevision: request.expectedRevision, idempotencyKey: request.idempotencyKey, status: "conflict", effectCount: 0, reason: "stale revision"}, unit: this.unit,
    };
    const sequence = this.unit.lastSequence + 1;
    if (request.op === "resume") {
      this.effects.resume += 1;
      this.unit = {...this.unit, state: "running", revision: this.unit.revision + 1, checkpointId: null, lastSequence: sequence};
      this.events.push({type: "unit.resumed", objectiveId, unitId: request.unitId, sequence, revision: this.unit.revision});
    } else {
      this.effects.cancel += 1;
      this.unit = {...this.unit, state: "cancelled", revision: this.unit.revision + 1, lastSequence: sequence};
      this.events.push({type: "unit.cancelled", objectiveId, unitId: request.unitId, sequence, revision: this.unit.revision});
    }
    const receipt = {actionId: `action-${request.op}`, operation: request.op, objectiveId: request.objectiveId, unitId: request.unitId, checkpointId, expectedRevision: request.expectedRevision, idempotencyKey: request.idempotencyKey, status: "accepted", effectCount: 1, reason: null};
    this.receipts.set(request.idempotencyKey, receipt);
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action", receipt, unit: this.unit};
  }
}

function actionResponse(request: LabRequest, overrides: Record<string, unknown> = {}) {
  if (request.op !== "cancel" && request.op !== "resume") throw new Error("action request required");
  return {
    protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action",
    receipt: {actionId: "action", operation: request.op, objectiveId: request.objectiveId, unitId: request.unitId, checkpointId: request.op === "resume" ? request.checkpointId : null, expectedRevision: request.expectedRevision, idempotencyKey: request.idempotencyKey, status: "accepted", effectCount: 1, reason: null, ...overrides},
    unit: {unitId: request.unitId, objectiveId: request.objectiveId, state: request.op === "resume" ? "running" : "cancelled", revision: request.expectedRevision + 1, checkpointId: null, lastSequence: 1},
  };
}

describe("LabClient boundary", () => {
  test("selects, observes, resumes and deduplicates one synthetic unit", async () => {
    const transport = new DurableFake(); const client = new LabClient(transport);
    expect((await client.select(selectInput)).kind).toBe("selected");
    const observed = await client.observe({requestId: "observe", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 10});
    expect(observed.kind === "observed" && observed.events.map((event) => event.type)).toEqual(["unit.selected"]);
    transport.pause(); const revision = transport.unit.revision;
    const first = await client.resume({requestId: "resume-1", objectiveId, unitId: "unit-1", checkpointId: "checkpoint-1", expectedRevision: revision, idempotencyKey: "resume-key"});
    const second = await new LabClient(transport).resume({requestId: "resume-2", objectiveId, unitId: "unit-1", checkpointId: "checkpoint-1", expectedRevision: revision, idempotencyKey: "resume-key"});
    expect(first.kind === "action" && first.receipt.status).toBe("accepted");
    expect(second.kind === "action" && second.receipt.status).toBe("already_applied");
    expect(transport.effects.resume).toBe(1);
  });

  test("AbortSignal stops waiting but only explicit cancel changes the unit", async () => {
    const transport = new DurableFake(); const client = new LabClient(transport); await client.select(selectInput);
    const abort = new AbortController(); abort.abort();
    await expect(client.observe({requestId: "observe", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 10}, {signal: abort.signal})).rejects.toMatchObject({name: "AbortError"});
    expect(transport.effects.cancel).toBe(0);
    const result = await client.cancel({requestId: "cancel", objectiveId, unitId: "unit-1", expectedRevision: transport.unit.revision, idempotencyKey: "cancel-key", reason: "operator_request"});
    expect(result.kind === "action" && result.receipt.status).toBe("accepted");
    expect(transport.effects.cancel).toBe(1);
  });

  test("runtime-validates all request coordinates and budgets before transport", async () => {
    const transport = new DurableFake(); const client = new LabClient(transport);
    await expect(client.select({...selectInput, requestId: "bad/id"} as never)).rejects.toThrow("identifier");
    await expect(client.select({...selectInput, expectedBase: "abc"} as never)).rejects.toThrow("full SHA-1");
    await expect(client.select({...selectInput, budget: {...budget, maxCpuMs: Infinity}} as never)).rejects.toThrow("selection policy denied");
    await expect(client.select({...selectInput, budget: {...budget, extra: 1}} as never)).rejects.toThrow("unexpected");
    await expect(client.observe({requestId: "observe", objectiveId, unitId: "unit-1", afterSequence: -1, limit: 1})).rejects.toThrow("safe integer");
    await expect(client.observe({requestId: "observe", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 1001})).rejects.toThrow("<= 1000");
    await expect(client.cancel({requestId: "cancel", objectiveId, unitId: "unit-1", expectedRevision: -1, idempotencyKey: "key", reason: "operator_request"})).rejects.toThrow("safe integer");
    await expect(client.resume({requestId: "resume", objectiveId, unitId: "unit-1", checkpointId: "bad/id", expectedRevision: 0, idempotencyKey: "key"})).rejects.toThrow("identifier");
    expect(transport.calls).toBe(0);
  });

  test("requires the execution discriminator to match its provider policy", async () => {
    const transport = new DurableFake(); const client = new LabClient(transport);
    await expect(client.select({...selectInput, execution: "inventory", providerProjection: {} as never} as never)).rejects.toThrow("execution and provider policy disagree");
    expect(transport.calls).toBe(0);
  });

  test("binds action response objective, unit, checkpoint, revision and idempotency", async () => {
    for (const [field, value] of [["objectiveId", "other"], ["unitId", "other"], ["checkpointId", "wrong"], ["expectedRevision", 9], ["idempotencyKey", "wrong"]] as const) {
      const client = new LabClient({request: async (request) => actionResponse(request, {[field]: value})});
      await expect(client.resume({requestId: `resume-${field}`, objectiveId, unitId: "unit-1", checkpointId: "checkpoint-1", expectedRevision: 1, idempotencyKey: "key"})).rejects.toThrow("coordinates");
    }
  });

  test("rejects incoherent event coordinates, sequence, revision, cursor and page limit", async () => {
    const cases = [
      {events: [{type: "unit.selected", objectiveId: "other", unitId: "unit-1", sequence: 1, revision: 1}], nextSequence: 1, error: "coordinates"},
      {events: [{type: "unit.selected", objectiveId, unitId: "unit-1", sequence: 2, revision: 1}], nextSequence: 2, error: "sequence gap"},
      {events: [{type: "unit.selected", objectiveId, unitId: "unit-1", sequence: 1, revision: 9}], nextSequence: 1, error: "revision"},
      {events: [], nextSequence: 1, error: "cursors"},
    ];
    for (const [index, entry] of cases.entries()) {
      const client = new LabClient({request: async (request) => ({protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "observed", unit: {unitId: "unit-1", objectiveId, state: "selected", revision: 1, checkpointId: null, lastSequence: 2}, events: entry.events, nextSequence: entry.nextSequence})});
      await expect(client.observe({requestId: `observe-${index}`, objectiveId, unitId: "unit-1", afterSequence: 0, limit: 1})).rejects.toThrow(entry.error);
    }
    const overLimit = new DurableFake(); overLimit.events.push({type: "unit.selected", objectiveId, unitId: "unit-1", sequence: 1, revision: 1}, {type: "unit.resumed", objectiveId, unitId: "unit-1", sequence: 2, revision: 1}); overLimit.unit = {...overLimit.unit, revision: 1, lastSequence: 2};
    const unboundedTransport = {request: async (request: LabRequest) => ({protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "observed", unit: overLimit.unit, events: overLimit.events, nextSequence: 2})};
    await expect(new LabClient(unboundedTransport).observe({requestId: "over", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 1})).rejects.toThrow("exceeds");
  });

  test("enforces action status/effect/reason and accepted-state invariants", async () => {
    for (const overrides of [
      {status: "conflict", effectCount: 1, reason: "stale"},
      {status: "accepted", effectCount: 1, reason: "not-null"},
      {status: "denied", effectCount: 0, reason: null},
    ]) {
      const client = new LabClient({request: async (request) => actionResponse(request, overrides)});
      await expect(client.cancel({requestId: "cancel", objectiveId, unitId: "unit-1", expectedRevision: 1, idempotencyKey: "key", reason: "operator_request"})).rejects.toThrow("inconsistent");
    }
    const staleSnapshot = new LabClient({request: async (request) => ({...actionResponse(request), unit: {unitId: "unit-1", objectiveId, state: "cancelled", revision: 1, checkpointId: null, lastSequence: 1}})});
    await expect(staleSnapshot.cancel({requestId: "cancel", objectiveId, unitId: "unit-1", expectedRevision: 1, idempotencyKey: "key", reason: "operator_request"})).rejects.toThrow("advance");
  });
});
