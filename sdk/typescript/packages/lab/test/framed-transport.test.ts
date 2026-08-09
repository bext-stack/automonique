// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";
import {
  FrameProtocolError,
  FrameTimeoutError,
  FramedLabTransport,
  LAB_PROTOCOL,
  LabClient,
  type FrameChannel,
  type FrameCloseReason,
  type FrameConnector,
  type LabRequest,
} from "../src/index.ts";

const objectiveId = "R0-19-synthetic";
const budget = {maxWallMs: 1_000, maxCpuMs: 500, maxDiskBytes: 16_384, maxOutputBytes: 4_096, maxPids: 1, maxModelCalls: 0, maxCostMicrounits: 0, enforcement: "synthetic_in_process"} as const;
const policy = {kind: "synthetic", driver: "in_process_fixture", network: "deny", authentication: "none", maxModelCalls: 0, maxCostMicrounits: 0} as const;
const request: LabRequest = {protocol: LAB_PROTOCOL, requestId: "request", op: "observe", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 10};

function frame(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  const result = new Uint8Array(payload.length + 4);
  new DataView(result.buffer).setUint32(0, payload.length, false);
  result.set(payload, 4);
  return result;
}
function prefix(length: number): Uint8Array {
  const result = new Uint8Array(4); new DataView(result.buffer).setUint32(0, length, false); return result;
}
function concatenate(...chunks: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0; for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; } return result;
}
function body(chunk: Uint8Array): string {
  const length = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getUint32(0, false);
  return new TextDecoder().decode(chunk.slice(4, 4 + length));
}

class ScriptedChannel implements FrameChannel {
  readonly writes: Uint8Array[] = [];
  readonly closes: FrameCloseReason[] = [];
  constructor(private readonly reads: Array<Uint8Array | null | Error>) {}
  async write(chunk: Uint8Array) { this.writes.push(chunk.slice()); }
  async read() {
    const next = this.reads.shift();
    if (next instanceof Error) throw next;
    return next ?? null;
  }
  close(reason: FrameCloseReason) { this.closes.push(reason); }
}
function connector(channel: FrameChannel): FrameConnector { return {open: async () => channel}; }

describe("FramedLabTransport framing", () => {
  test("canonically encodes one request and decodes one response", async () => {
    const channel = new ScriptedChannel([frame({answer: true}), null]);
    expect(await new FramedLabTransport(connector(channel)).request(request)).toEqual({answer: true});
    expect(body(channel.writes[0]!)).toBe('{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}');
    expect(channel.closes).toEqual(["complete"]);
  });

  test("reassembles partial prefix and payload chunks", async () => {
    const encoded = frame({chunked: true});
    const channel = new ScriptedChannel([encoded.slice(0, 2), encoded.slice(2, 4), encoded.slice(4, 7), encoded.slice(7), null]);
    expect(await new FramedLabTransport(connector(channel)).request(request)).toEqual({chunked: true});
  });

  test("refuses partial prefixes and payloads", async () => {
    const partialPrefix = new ScriptedChannel([new Uint8Array([0, 0]), null]);
    await expect(new FramedLabTransport(connector(partialPrefix)).request(request)).rejects.toThrow("partial prefix");
    const partialPayload = new ScriptedChannel([prefix(5), new Uint8Array([1, 2]), null]);
    await expect(new FramedLabTransport(connector(partialPayload)).request(request)).rejects.toThrow("partial payload");
    expect(partialPrefix.closes).toEqual(["protocol_error"]);
    expect(partialPayload.closes).toEqual(["protocol_error"]);
  });

  test("refuses oversized request and response frames", async () => {
    let opened = 0;
    const never = {open: async () => { opened += 1; return new ScriptedChannel([]); }};
    await expect(new FramedLabTransport(never, {maxFrameBytes: 8}).request(request)).rejects.toBeInstanceOf(FrameProtocolError);
    expect(opened).toBe(0);
    const oversized = new ScriptedChannel([prefix(201)]);
    await expect(new FramedLabTransport(connector(oversized), {maxFrameBytes: 200}).request(request)).rejects.toThrow("length 201");
  });

  test("refuses trailing bytes and a second response frame", async () => {
    const first = frame({one: 1});
    const trailing = new ScriptedChannel([concatenate(first, new Uint8Array([1])), null]);
    await expect(new FramedLabTransport(connector(trailing)).request(request)).rejects.toThrow("trailing data");
    const secondFrame = new ScriptedChannel([first, frame({two: 2}), null]);
    await expect(new FramedLabTransport(connector(secondFrame)).request(request)).rejects.toThrow("second frame");
  });

  test("refuses malformed UTF-8 and JSON payloads", async () => {
    const utf8 = new ScriptedChannel([concatenate(prefix(1), new Uint8Array([0xff])), null]);
    await expect(new FramedLabTransport(connector(utf8)).request(request)).rejects.toThrow("UTF-8");
    const malformed = new TextEncoder().encode("{");
    const json = new ScriptedChannel([concatenate(prefix(malformed.length), malformed), null]);
    await expect(new FramedLabTransport(connector(json)).request(request)).rejects.toThrow("valid JSON");
  });

  test("propagates connector and channel errors", async () => {
    const connectionError = new Error("connector failed");
    await expect(new FramedLabTransport({open: async () => { throw connectionError; }}).request(request)).rejects.toBe(connectionError);
    const readError = new Error("channel failed");
    const channel = new ScriptedChannel([readError]);
    await expect(new FramedLabTransport(connector(channel)).request(request)).rejects.toBe(readError);
    expect(channel.closes).toEqual(["protocol_error"]);
  });
});

class WaitingChannel implements FrameChannel {
  readonly writes: Uint8Array[] = [];
  readonly closes: FrameCloseReason[] = [];
  async write(chunk: Uint8Array) { this.writes.push(chunk.slice()); }
  read() { return new Promise<Uint8Array | null>(() => undefined); }
  close(reason: FrameCloseReason) { this.closes.push(reason); }
}

describe("FramedLabTransport cancellation", () => {
  test("abort closes only the client channel and never writes cancel", async () => {
    const channel = new WaitingChannel(); const abort = new AbortController();
    const pending = new FramedLabTransport(connector(channel)).request(request, {signal: abort.signal});
    await Promise.resolve(); abort.abort();
    await expect(pending).rejects.toMatchObject({name: "AbortError"});
    expect(channel.closes).toEqual(["aborted"]);
    expect(channel.writes).toHaveLength(1);
    expect(JSON.parse(body(channel.writes[0]!).toString())).toMatchObject({op: "observe"});
    expect(body(channel.writes[0]!)).not.toContain('"op":"cancel"');
  });

  test("bounded timeout closes the channel without a protocol cancel", async () => {
    const channel = new WaitingChannel();
    await expect(new FramedLabTransport(connector(channel), {timeoutMs: 5}).request(request)).rejects.toBeInstanceOf(FrameTimeoutError);
    expect(channel.closes).toEqual(["aborted"]);
    expect(body(channel.writes[0]!)).not.toContain('"op":"cancel"');
  });
});

class DurablePeer {
  private unit = {unitId: "unit-1", objectiveId, state: "queued", revision: 0, checkpointId: null, lastSequence: 0};
  private events: Array<Record<string, unknown>> = [];

  connector: FrameConnector = {open: async () => new PeerChannel((request) => this.handle(request))};
  private handle(request: Record<string, unknown>) {
    if (request.op === "select") {
      this.unit = {...this.unit, state: "selected", revision: 1, lastSequence: 1};
      this.events = [{type: "unit.selected", objectiveId, unitId: "unit-1", sequence: 1, revision: 1}];
      return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "selected", unit: this.unit};
    }
    const after = Number(request.afterSequence);
    const events = this.events.filter((event) => Number(event.sequence) > after).slice(0, Number(request.limit));
    return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "observed", unit: this.unit, events, nextSequence: events.length ? Number(events.at(-1)?.sequence) : after};
  }
}

class PeerChannel implements FrameChannel {
  private reads: Array<Uint8Array | null> = [];
  constructor(private readonly handler: (request: Record<string, unknown>) => unknown) {}
  async write(chunk: Uint8Array) {
    const response = frame(this.handler(JSON.parse(body(chunk)) as Record<string, unknown>));
    this.reads = [response.slice(0, 1), response.slice(1, 6), response.slice(6), null];
  }
  async read() { return this.reads.shift() ?? null; }
  close() {}
}

test("LabClient selects and observes through a durable framed peer", async () => {
  const peer = new DurablePeer(); const client = new LabClient(new FramedLabTransport(peer.connector));
  const selected = await client.select({requestId: "select", objectiveId, expectedBase: "1".repeat(40), execution: "synthetic", providerPolicy: policy, budget});
  expect(selected.kind).toBe("selected");
  const observed = await client.observe({requestId: "observe", objectiveId, unitId: "unit-1", afterSequence: 0, limit: 10});
  expect(observed.kind === "observed" && observed.events.map((event) => event.type)).toEqual(["unit.selected"]);
});
