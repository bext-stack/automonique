// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";
import {
  LAB_PROTOCOL,
  LabClient,
  type LabRequest,
  type LabTransport,
  type UnitSnapshot,
} from "../src/index.ts";

const syntheticPolicy = {
  kind: "synthetic",
  driver: "in_process_fixture",
  network: "deny",
  authentication: "none",
  maxModelCalls: 0,
  maxCostMicrounits: 0,
} as const;

const budget = {
  maxWallMs: 1_000,
  maxCpuMs: 500,
  maxDiskBytes: 16_384,
  maxOutputBytes: 4_096,
  maxPids: 1,
  maxModelCalls: 0,
  maxCostMicrounits: 0,
  enforcement: "synthetic_in_process",
} as const;

class DurableFake implements LabTransport {
  unit: UnitSnapshot = {
    unitId: "unit-1",
    objectiveId: "R0-19-synthetic",
    state: "queued",
    revision: 0,
    checkpointId: null,
    lastSequence: 0,
  };
  events: Array<Record<string, unknown>> = [];
  effects = {resume: 0, cancel: 0};
  private receipts = new Map<string, Record<string, unknown>>();

  pause(checkpointId = "checkpoint-1") {
    this.unit = {...this.unit, state: "paused", revision: this.unit.revision + 1, checkpointId};
  }

  async request(request: LabRequest, options?: {readonly signal?: AbortSignal}) {
    if (options?.signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (request.op === "select") {
      this.unit = {...this.unit, state: "selected", revision: 1, lastSequence: 1};
      this.events.push({type: "unit.selected", sequence: 1, revision: 1});
      return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "selected", unit: this.unit};
    }
    if (request.op === "observe") {
      const events = this.events
        .filter((event) => Number(event.sequence) > request.afterSequence)
        .slice(0, request.limit);
      return {
        protocol: LAB_PROTOCOL,
        requestId: request.requestId,
        kind: "observed",
        unit: this.unit,
        events,
        nextSequence: events.length ? Number(events.at(-1)?.sequence) : request.afterSequence,
      };
    }

    const prior = this.receipts.get(request.idempotencyKey);
    if (prior) {
      return {
        protocol: LAB_PROTOCOL,
        requestId: request.requestId,
        kind: "action",
        receipt: {...prior, status: "already_applied"},
        unit: this.unit,
      };
    }
    if (request.expectedRevision !== this.unit.revision) {
      return {
        protocol: LAB_PROTOCOL,
        requestId: request.requestId,
        kind: "action",
        receipt: {
          actionId: `action-${request.op}-conflict`,
          idempotencyKey: request.idempotencyKey,
          status: "conflict",
          effectCount: 0,
          reason: "stale revision",
        },
        unit: this.unit,
      };
    }

    const sequence = this.unit.lastSequence + 1;
    if (request.op === "resume") {
      if (request.checkpointId !== this.unit.checkpointId) throw new Error("checkpoint mismatch");
      this.effects.resume += 1;
      this.unit = {
        ...this.unit,
        state: "running",
        revision: this.unit.revision + 1,
        checkpointId: null,
        lastSequence: sequence,
      };
      this.events.push({type: "unit.resumed", sequence, revision: this.unit.revision});
    } else {
      this.effects.cancel += 1;
      this.unit = {
        ...this.unit,
        state: "cancelled",
        revision: this.unit.revision + 1,
        lastSequence: sequence,
      };
      this.events.push({type: "unit.cancelled", sequence, revision: this.unit.revision});
    }
    const receipt = {
      actionId: `action-${request.op}`,
      idempotencyKey: request.idempotencyKey,
      status: "accepted",
      effectCount: 1,
      reason: null,
    };
    this.receipts.set(request.idempotencyKey, receipt);
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "action", receipt, unit: this.unit};
  }
}

describe("LabClient synthetic scenario", () => {
  test("selects and observes a bounded synthetic unit", async () => {
    const transport = new DurableFake();
    const client = new LabClient(transport);
    const selected = await client.select({
      requestId: "request-select",
      objectiveId: "R0-19-synthetic",
      expectedBase: "1".repeat(40),
      synthetic: true,
      providerPolicy: syntheticPolicy,
      budget,
    });
    expect(selected.kind).toBe("selected");

    const observed = await client.observe({requestId: "request-observe", unitId: "unit-1", afterSequence: 0, limit: 10});
    expect(observed.kind).toBe("observed");
    if (observed.kind === "observed") {
      expect(observed.events.map((event) => event.type)).toEqual(["unit.selected"]);
      expect(observed.nextSequence).toBe(1);
    }
  });

  test("resumes durably and deduplicates the action across client instances", async () => {
    const transport = new DurableFake();
    await new LabClient(transport).select({
      requestId: "select",
      objectiveId: "R0-19-synthetic",
      expectedBase: "2".repeat(40),
      synthetic: true,
      providerPolicy: syntheticPolicy,
      budget,
    });
    transport.pause();
    const revision = transport.unit.revision;
    const first = await new LabClient(transport).resume({
      requestId: "resume-1",
      unitId: "unit-1",
      checkpointId: "checkpoint-1",
      expectedRevision: revision,
      idempotencyKey: "resume-key",
    });
    const second = await new LabClient(transport).resume({
      requestId: "resume-2",
      unitId: "unit-1",
      checkpointId: "checkpoint-1",
      expectedRevision: revision,
      idempotencyKey: "resume-key",
    });
    expect(first.kind === "action" && first.receipt.status).toBe("accepted");
    expect(second.kind === "action" && second.receipt.status).toBe("already_applied");
    expect(transport.effects.resume).toBe(1);
  });

  test("uses explicit revisioned cancellation; aborting a wait does not cancel", async () => {
    const transport = new DurableFake();
    const client = new LabClient(transport);
    await client.select({
      requestId: "select",
      objectiveId: "R0-19-synthetic",
      expectedBase: "3".repeat(40),
      synthetic: true,
      providerPolicy: syntheticPolicy,
      budget,
    });
    const abort = new AbortController();
    abort.abort();
    await expect(client.observe(
      {requestId: "observe", unitId: "unit-1", afterSequence: 0, limit: 10},
      {signal: abort.signal},
    )).rejects.toMatchObject({name: "AbortError"});
    expect(transport.unit.state).toBe("selected");
    expect(transport.effects.cancel).toBe(0);

    const stale = await client.cancel({
      requestId: "cancel-stale",
      unitId: "unit-1",
      expectedRevision: 0,
      idempotencyKey: "stale-key",
      reason: "operator_request",
    });
    expect(stale.kind === "action" && stale.receipt.status).toBe("conflict");
    const cancelled = await client.cancel({
      requestId: "cancel",
      unitId: "unit-1",
      expectedRevision: transport.unit.revision,
      idempotencyKey: "cancel-key",
      reason: "operator_request",
    });
    expect(cancelled.kind === "action" && cancelled.receipt.status).toBe("accepted");
    expect(transport.effects.cancel).toBe(1);
  });

  test("bounds unknown read events and rejects unknown mutation responses", async () => {
    const transport = new DurableFake();
    transport.events.push({type: "future.read.event", sequence: 1, revision: 0, privatePayload: "discarded"});
    transport.unit = {...transport.unit, lastSequence: 1};
    const observed = await new LabClient(transport).observe({requestId: "observe", unitId: "unit-1", afterSequence: 0, limit: 10});
    expect(observed.kind === "observed" && observed.events[0]).toEqual({
      type: "unknown",
      rawType: "future.read.event",
      sequence: 1,
      revision: 0,
    });

    const malformed = new LabClient({request: async (request) => ({
      protocol: LAB_PROTOCOL,
      requestId: request.requestId,
      kind: "future_mutation",
    })});
    await expect(malformed.cancel({
      requestId: "bad",
      unitId: "unit-1",
      expectedRevision: 0,
      idempotencyKey: "bad-key",
      reason: "operator_request",
    })).rejects.toThrow("invalid for cancel");
  });

  test("rejects cross-unit effects and invalid observe cursors", async () => {
    const crossUnit = new LabClient({request: async (request) => ({
      protocol: LAB_PROTOCOL,
      requestId: request.requestId,
      kind: "action",
      receipt: {actionId: "action", idempotencyKey: "wrong", status: "accepted", effectCount: 1, reason: null},
      unit: {unitId: "other", objectiveId: "objective", state: "cancelled", revision: 1, checkpointId: null, lastSequence: 1},
    })});
    await expect(crossUnit.cancel({requestId: "cross", unitId: "unit-1", expectedRevision: 0, idempotencyKey: "right", reason: "operator_request"})).rejects.toThrow("unit does not match");

    const gapped = new DurableFake();
    gapped.events.push({type: "unit.selected", sequence: 2, revision: 1});
    gapped.unit = {...gapped.unit, lastSequence: 2};
    await expect(new LabClient(gapped).observe({requestId: "gap", unitId: "unit-1", afterSequence: 0, limit: 10})).rejects.toThrow("sequence gap");

    const falseEffect = new LabClient({request: async (request) => ({
      protocol: LAB_PROTOCOL,
      requestId: request.requestId,
      kind: "action",
      receipt: {actionId: "action", idempotencyKey: "false-effect", status: "conflict", effectCount: 1, reason: "stale"},
      unit: {unitId: "unit-1", objectiveId: "objective", state: "selected", revision: 1, checkpointId: null, lastSequence: 1},
    })});
    await expect(falseEffect.cancel({requestId: "effect", unitId: "unit-1", expectedRevision: 0, idempotencyKey: "false-effect", reason: "operator_request"})).rejects.toThrow("effect count");
  });

  test("rejects unbounded JavaScript requests before transport", async () => {
    let calls = 0;
    const client = new LabClient({request: async () => { calls += 1; return {}; }});
    await expect(client.observe({requestId: "observe", unitId: "unit-1", afterSequence: 0, limit: 1001})).rejects.toThrow("between 1 and 1000");
    await expect(client.cancel({requestId: "cancel", unitId: "unit-1", expectedRevision: -1, idempotencyKey: "key", reason: "operator_request"})).rejects.toThrow("non-negative");
    expect(calls).toBe(0);
  });
});
