// SPDX-License-Identifier: Elastic-2.0

import {afterEach, describe, expect, test} from "bun:test";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {
  NATIVE_ADAPTER_SCHEMA,
  ProductionPlatformAuthority,
  nativeRunIdFor,
  translateNativeStream,
  type AdmittedRunInput,
  type NativeAdapterEvent,
} from "../src/index.ts";

const servers: Array<{stop(closeActiveConnections?: boolean): void}> = [];
const directories: string[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
  for (const directory of directories.splice(0)) rmSync(directory, {recursive: true, force: true});
});

describe("production Platform authority", () => {
  test("uses the peer-authenticated canonical Platform socket in production", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automonique-platform-"));
    directories.push(directory);
    const path = join(directory, "admin.sock");
    const server = Bun.listen({
      unix: path,
      socket: {
        data(socket, data) {
          const request = JSON.parse(new TextDecoder().decode(data.slice(4))) as {request_id: string};
          socket.write(wire({
            protocol: "automonique.platform",
            version: 1,
            request_id: request.request_id,
            kind: "capabilities_result",
            body: {protocol: "automonique.platform", schema: "automonique.platform/v1", methods: [], transports: ["local_unix"]},
          }));
        },
      },
    });
    servers.push(server);
    const authority = new ProductionPlatformAuthority({
      platformSocket: path,
      progressSocket: join(directory, "progress.sock"),
      nodeId: "node-fixture",
    });
    expect(await authority.ready()).toBe(true);
  });

  test("projects one durable run with stable sub-sequences and an exclusive reconnect cursor", async () => {
    const runId = "public-run-1";
    const platform = fakePlatform();
    const frames = [
      progress(nativeRunIdFor(runId), 1, "turn_started"),
      progress(nativeRunIdFor(runId), 2, "assistant_message_delta", "AGUI-"),
      progress(nativeRunIdFor(runId), 3, "assistant_message_delta", "LIVE-OK"),
      progress(nativeRunIdFor(runId), 4, "turn_completed"),
      progress(nativeRunIdFor(runId), 5, "run_terminal"),
    ];
    const socket = progressSocket(nativeRunIdFor(runId), frames);
    const authority = production(socket, platform.fetcher);
    const input = admitted(runId);

    const opened = await authority.open({input, cursor: null});
    expect(opened.kind).toBe("stream");
    if (opened.kind !== "stream") return;
    const events = await collect(opened.events);
    expect(events.map((event) => [event.sequence, event.kind])).toEqual([
      [9, "run_started"],
      [17, "assistant_message_preview"],
      [25, "assistant_message_preview"],
      [33, "assistant_message_completed"],
      [47, "run_finished"],
    ]);
    expect(events[2]).toMatchObject({text: "LIVE-OK", replace: false});
    expect(events[3]).toMatchObject({text: "AGUI-LIVE-OK"});
    expect(translateNativeStream(events).at(-1)).toMatchObject({type: "RUN_FINISHED"});

    const retainedAuthority = production(progressSocket(nativeRunIdFor(runId), frames, true, 2), platform.fetcher);
    const reconnected = await retainedAuthority.open({input, cursor: events[2]!.cursor});
    expect(reconnected.kind).toBe("stream");
    if (reconnected.kind !== "stream") return;
    expect(reconnected.replay.map((event) => event.sequence)).toEqual([17, 18, 25]);
    expect((await collect(reconnected.events)).map((event) => event.sequence)).toEqual([33, 47]);
  });

  test("checkpoints and projects a pending tool approval as one terminal interrupt", async () => {
    const runId = "public-run-approval";
    const native = nativeRunIdFor(runId);
    const approval = "apr-0123456789abcdef";
    const platform = fakePlatform(approval);
    const socket = progressSocket(native, [
      progress(native, 1, "turn_started"),
      progress(native, 2, "tool_call_started", "shell"),
      progress(native, 3, "approval_requested", `approval ${approval}: shell — inspect status`),
    ], false);
    const authority = production(socket, platform.fetcher);
    const opened = await authority.open({input: admitted(runId), cursor: null});
    expect(opened.kind).toBe("stream");
    if (opened.kind !== "stream") return;
    const events = await collect(opened.events);
    expect(events.map((event) => event.kind)).toEqual([
      "run_started",
      "tool_call_started",
      "tool_call_ended",
      "state_snapshot",
      "messages_snapshot",
      "approval_requested",
    ]);
    expect(events.map((event) => event.sequence)).toEqual([9, 17, 25, 26, 27, 28]);
    expect(translateNativeStream(events).at(-1)).toMatchObject({
      type: "RUN_FINISHED",
      outcome: {type: "interrupt"},
    });
  });

  test("resumes and cancels the paused parent native run", async () => {
    const parentRunId = "public-parent";
    const resumedRunId = "public-resume";
    const native = nativeRunIdFor(parentRunId);
    const approval = "apr-fedcba9876543210";
    const platform = fakePlatform(approval);
    const frames = [
      progress(native, 1, "turn_started"),
      progress(native, 2, "tool_call_started", "shell"),
      progress(native, 3, "approval_requested", `approval ${approval}: shell — inspect status`),
      progress(native, 4, "tool_call_completed", "done"),
      progress(native, 5, "assistant_message_completed", "continued"),
      progress(native, 6, "run_terminal"),
    ];
    const socket = progressSocket(native, frames);
    const authority = production(socket, platform.fetcher);
    const input: AdmittedRunInput = {
      threadId: "thread-1",
      runId: resumedRunId,
      parentRunId,
      resume: [{interruptId: approval, status: "resolved", payload: {approved: true}}],
    };
    const opened = await authority.open({input, cursor: null});
    expect(opened.kind).toBe("stream");
    if (opened.kind !== "stream") return;
    const events = await collect(opened.events);
    expect(events.map((event) => event.kind)).toEqual([
      "run_started",
      "assistant_message_completed",
      "run_finished",
    ]);
    expect(events[0]).toMatchObject({parentRunId});
    expect(translateNativeStream(events).at(-1)).toMatchObject({type: "RUN_FINISHED"});

    await authority.cancel({threadId: "thread-1", runId: resumedRunId, expectedRevision: 4, idempotencyKey: "cancel-resume"});
    expect(platform.stopTargets).toEqual([native]);
    expect(platform.approvalTargets).toEqual([approval]);
  });
});

function admitted(runId: string): AdmittedRunInput {
  return {threadId: "thread-1", runId, prompt: "Status, please.", resume: []};
}

function production(progressSocket: string, fetcher: typeof fetch): ProductionPlatformAuthority {
  return new ProductionPlatformAuthority({
    platformEndpoint: "http://localhost:18082/api/platform",
    platformToken: () => "fixture-token-that-is-long-enough-0001",
    progressSocket,
    nodeId: "node-fixture",
    fetcher,
  });
}

function fakePlatform(approvalId?: string): {
  fetcher: typeof fetch;
  stopTargets: string[];
  approvalTargets: string[];
} {
  const stopTargets: string[] = [];
  const approvalTargets: string[] = [];
  const fetcher = (async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = JSON.parse(String(init?.body)) as {request_id: string; kind: string; body: Record<string, any>};
    let kind = "receipt_result";
    let body: Record<string, unknown>;
    if (request.kind === "capabilities") {
      kind = "capabilities_result";
      body = {protocol: "automonique.platform", schema: "automonique.platform/v1", methods: [], transports: []};
    } else if (request.kind === "snapshot") {
      kind = "snapshot_result";
      const requested = request.body.resources?.[0];
      body = {cursor: {authority: "automonique", topic: "resources", sequence: 1}, resources: requested?.kind === "approval" && approvalId !== undefined
        ? [{resource: {authority: "automonique", kind: "approval", id: approvalId}, freshness: {state: "fresh", revision: 7, observed_at: 1}, summary: "state=pending;expires_at=9999999999999"}]
        : [{resource: {authority: "automonique", kind: "node", id: "node-fixture"}, freshness: {state: "fresh", revision: 1, observed_at: 1}, summary: "daemon ready"}]};
    } else if (request.kind === "get_receipt") {
      body = receipt("completed");
    } else {
      const action = request.body.action;
      if (action === "stop_run") stopTargets.push(request.body.target.id);
      if (action === "decide_approval") approvalTargets.push(request.body.target.id);
      body = receipt(action === "submit_request" ? "accepted" : "completed");
    }
    return new Response(JSON.stringify({protocol: "automonique.platform", version: 1, request_id: request.request_id, kind, body}), {status: 200});
  }) as typeof fetch;
  return {fetcher, stopTargets, approvalTargets};
}

function receipt(outcome: string): Record<string, unknown> {
  return {id: `receipt-${outcome}`, outcome, explanation: null, revision: 1};
}

function progress(run_id: string, sequence: number, kind: string, text: string | null = null): Record<string, unknown> {
  return {run_id, sequence, kind, at_ms: 1_000 + sequence, authority: "authoritative", body: {text, step: null, retry: null}};
}

function progressSocket(runId: string, frames: readonly Record<string, unknown>[], retire = true, retainedFrom = 1): string {
  const directory = mkdtempSync(join(tmpdir(), "automonique-agui-"));
  directories.push(directory);
  const path = join(directory, "progress.sock");
  const server = Bun.listen({
    unix: path,
    socket: {
      open(socket) { socket.write(wire({kind: "greeting", body: {capability: 1}})); },
      data(socket, data) {
        const request = JSON.parse(new TextDecoder().decode(data.slice(4))) as {run_id: string; cursor: number};
        if (request.run_id !== runId || request.cursor < 0) return socket.end();
        if (request.cursor < retainedFrom - 1) {
          socket.write(wire({kind: "resync_required", body: {snapshot_from: retainedFrom, snapshot_to: frames.at(-1)?.sequence ?? 0}}));
          return;
        }
        socket.write(wire({kind: "live", body: {from: request.cursor + 1}}));
        for (const value of frames) if (Number(value.sequence) > request.cursor) socket.write(wire({kind: "frame", body: value}));
        if (retire) socket.write(wire({kind: "retired", body: {delivered_through: frames.at(-1)?.sequence ?? 0}}));
      },
    },
  });
  servers.push(server);
  return path;
}

function wire(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  const output = new Uint8Array(payload.byteLength + 4);
  new DataView(output.buffer).setUint32(0, payload.byteLength, false);
  output.set(payload, 4);
  return output;
}

async function collect(source: AsyncIterable<NativeAdapterEvent>): Promise<NativeAdapterEvent[]> {
  const output: NativeAdapterEvent[] = [];
  for await (const event of source) {
    expect(event.schema).toBe(NATIVE_ADAPTER_SCHEMA);
    output.push(event);
  }
  return output;
}
