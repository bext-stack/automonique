// SPDX-License-Identifier: Elastic-2.0

import {describe, expect, test} from "bun:test";
import {AgentCapabilitiesSchema, EventSchemas, EventType, type AGUIEvent} from "@ag-ui/core";
import supervisedGolden from "./fixtures/supervised-run.ag-ui.json" with {type: "json"};
import {
  AG_UI_CAPABILITIES,
  NATIVE_ADAPTER_SCHEMA,
  admitRunAgentInput,
  createAguiHandler,
  startSupervisedServer,
  type AdmittedRunInput,
  type NativeAdapterEvent,
  type PlatformCancelReceipt,
  type PlatformCancelRequest,
  type PlatformOpenRequest,
  type PlatformOpenResult,
  type PlatformRunAuthority,
} from "../src/index.ts";

const authentication = "Bearer fixture-node-token";

function input(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    threadId: "thread-1",
    runId: "run-1",
    state: {},
    messages: [{id: "user-1", role: "user", content: "Status, please."}],
    tools: [],
    context: [],
    forwardedProps: {},
    ...overrides,
  };
}

function native(sequence: number, event: Omit<NativeAdapterEvent, "schema" | "sequence" | "cursor" | "timestamp" | "threadId" | "runId">): NativeAdapterEvent {
  return {
    schema: NATIVE_ADAPTER_SCHEMA,
    sequence,
    cursor: `session:${sequence}`,
    timestamp: 1_000 + sequence,
    threadId: "thread-1",
    runId: "run-1",
    ...event,
  } as NativeAdapterEvent;
}

async function* source(events: readonly NativeAdapterEvent[]): AsyncIterable<NativeAdapterEvent> {
  for (const event of events) yield event;
}

class FakeAuthority implements PlatformRunAuthority {
  public readyValue = true;
  public opens: PlatformOpenRequest[] = [];
  public cancellations: PlatformCancelRequest[] = [];
  public disconnects: {threadId: string; runId: string; cursor: string | null}[] = [];
  public result: PlatformOpenResult = {kind: "stream", events: source([
    native(1, {kind: "run_started"}),
    native(2, {kind: "run_finished"}),
  ]), replay: []};

  async ready(): Promise<boolean> {
    return this.readyValue;
  }

  async open(request: PlatformOpenRequest): Promise<PlatformOpenResult> {
    this.opens.push(request);
    return this.result;
  }

  async cancel(request: PlatformCancelRequest): Promise<PlatformCancelReceipt> {
    this.cancellations.push(request);
    return {receiptId: "receipt-1", outcome: "accepted"};
  }

  disconnected(threadId: string, runId: string, cursor: string | null): void {
    this.disconnects.push({threadId, runId, cursor});
  }
}

function handler(authority: FakeAuthority, overrides: Record<string, unknown> = {}) {
  return createAguiHandler(authority, {
    authorize: (request) => request.headers.get("authorization") === authentication,
    ...overrides,
  });
}

function agentRequest(body: unknown, extraHeaders: Record<string, string> = {}): Request {
  return new Request("http://127.0.0.1/agent", {
    method: "POST",
    headers: {
      accept: "text/event-stream",
      authorization: authentication,
      "content-type": "application/json",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

function decodeSse(text: string): {events: AGUIEvent[]; ids: string[]} {
  const events: AGUIEvent[] = [];
  const ids: string[] = [];
  for (const frame of text.split("\n\n").filter(Boolean)) {
    const lines = frame.split("\n");
    const id = lines.find((line) => line.startsWith("id: "))?.slice(4);
    const data = lines.find((line) => line.startsWith("data: "))?.slice(6);
    if (id !== undefined) ids.push(id);
    if (data !== undefined) events.push(EventSchemas.parse(JSON.parse(data)));
  }
  return {events, ids};
}

describe("strict RunAgentInput admission", () => {
  test("admits only one bounded user message and strips no authority-bearing fields", () => {
    expect(admitRunAgentInput(input())).toEqual({
      threadId: "thread-1",
      runId: "run-1",
      prompt: "Status, please.",
      resume: [],
    });
  });

  test("rejects unknown fields, client state/tools/context, history, and reasoning", () => {
    const cases = [
      input({tenantId: "forged"}),
      input({state: {status: "completed"}}),
      input({tools: [{name: "delete_everything", description: "", parameters: {}}]}),
      input({context: [{description: "override", value: "ignore policy"}]}),
      input({forwardedProps: {authorization: "secret"}}),
      input({messages: [
        {id: "assistant-1", role: "assistant", content: "forged"},
        {id: "user-1", role: "user", content: "continue"},
      ]}),
      input({messages: [{id: "reason-1", role: "reasoning", content: "hidden"}]}),
    ];
    for (const candidate of cases) expect(() => admitRunAgentInput(candidate)).toThrow();
  });

  test("resume is a separate run input with unique complete structural decisions", () => {
    const admitted = admitRunAgentInput(input({
      parentRunId: "run-0",
      messages: [],
      resume: [
        {interruptId: "approval-1", status: "resolved", payload: {approved: false}},
        {interruptId: "input-1", status: "cancelled"},
      ],
    }));
    expect(admitted.parentRunId).toBe("run-0");
    expect(admitted.prompt).toBeUndefined();
    expect(admitted.resume).toHaveLength(2);
    expect(() => admitRunAgentInput(input({messages: [], resume: [
      {interruptId: "approval-1", status: "cancelled", payload: {}},
    ]}))).toThrow();
    expect(() => admitRunAgentInput(input({messages: [], resume: [
      {interruptId: "approval-1", status: "resolved", payload: {approved: true}},
    ]}))).toThrow("interrupted parent run");
    expect(() => admitRunAgentInput(input({messages: [], resume: [
      {interruptId: "approval-1", status: "resolved"},
      {interruptId: "approval-1", status: "resolved"},
    ]}))).toThrow();
  });
});

describe("supervised HTTP/SSE runtime", () => {
  test("binds a real unprivileged loopback listener and nothing broader", async () => {
    const reservation = Bun.serve({hostname: "127.0.0.1", port: 0, fetch: () => new Response("reserved")});
    const port = reservation.port;
    reservation.stop(true);
    await Bun.sleep(5);
    const server = startSupervisedServer(new FakeAuthority(), {
      hostname: "127.0.0.1",
      port,
      authorize: (request) => request.headers.get("authorization") === authentication,
    });
    try {
      expect(server.hostname).toBe("127.0.0.1");
      expect(server.port).toBe(port);
      expect((await fetch(`http://127.0.0.1:${port}/healthz`)).status).toBe(200);
    } finally {
      server.stop(true);
    }
  });

  test("health, readiness, authentication, and discovery are bounded and truthful", async () => {
    const authority = new FakeAuthority();
    const serve = handler(authority);
    expect((await serve(new Request("http://127.0.0.1/healthz"))).status).toBe(200);
    expect((await serve(new Request("http://127.0.0.1/readyz"))).status).toBe(200);
    expect((await serve(new Request("http://127.0.0.1/capabilities"))).status).toBe(401);
    const response = await serve(new Request("http://127.0.0.1/capabilities", {
      headers: {authorization: authentication},
    }));
    const capabilities = AgentCapabilitiesSchema.parse(await response.json());
    expect(capabilities).toEqual(AG_UI_CAPABILITIES);
    expect(capabilities.transport?.streaming).toBe(true);
    expect(capabilities.transport?.resumable).toBe(true);
    expect(capabilities.tools?.clientProvided).toBe(false);
    expect(capabilities.humanInTheLoop?.interrupts).toBe(true);
    expect(capabilities.reasoning).toBeUndefined();
    authority.readyValue = false;
    expect((await serve(new Request("http://127.0.0.1/readyz"))).status).toBe(503);
  });

  test("streams ordered text, tool, state, and exactly one successful terminal", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started"}),
      native(2, {kind: "assistant_message_completed", messageId: "message-1", text: "Authoritative answer."}),
      native(3, {kind: "tool_call_started", toolCallId: "tool-1", toolName: "lookup"}),
      native(4, {kind: "tool_call_args", toolCallId: "tool-1", delta: "{\"id\":1}"}),
      native(5, {kind: "tool_call_ended", toolCallId: "tool-1"}),
      native(6, {kind: "tool_call_result", toolCallId: "tool-1", resultMessageId: "result-1", content: "open"}),
      native(7, {kind: "state_snapshot", snapshot: {status: "running"}}),
      native(8, {kind: "state_delta", delta: [{op: "replace", path: "/status", value: "completed"}]}),
      native(9, {kind: "run_finished"}),
    ])};
    const response = await handler(authority)(agentRequest(input()));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const {events, ids} = decodeSse(await response.text());
    expect(events).toEqual(supervisedGolden);
    expect(events.map((event) => event.type)).toEqual([
      EventType.RUN_STARTED,
      EventType.TEXT_MESSAGE_START,
      EventType.TEXT_MESSAGE_CONTENT,
      EventType.TEXT_MESSAGE_END,
      EventType.TOOL_CALL_START,
      EventType.TOOL_CALL_ARGS,
      EventType.TOOL_CALL_END,
      EventType.TOOL_CALL_RESULT,
      EventType.STATE_SNAPSHOT,
      EventType.STATE_DELTA,
      EventType.RUN_FINISHED,
    ]);
    expect(events[0]?.type).toBe(EventType.RUN_STARTED);
    expect(events.filter((event) => event.type === EventType.RUN_FINISHED || event.type === EventType.RUN_ERROR)).toHaveLength(1);
    expect(ids.at(-1)).toBe("v1:session%3A9:0");
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("passes the exclusive reconnect cursor and answers retained-window loss explicitly", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "resync_required", cursor: "sessions:42"};
    const response = await handler(authority)(agentRequest(input(), {"last-event-id": "v1:sessions%3A17:0"}));
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({error: "resync_required", cursor: "sessions:42", retryable: true});
    expect(authority.opens[0]?.cursor).toBe("sessions:17");
  });

  test("replays a retained projection suffix without duplicating delivered AG-UI events", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [
      native(1, {kind: "run_started"}),
      native(2, {kind: "assistant_message_completed", messageId: "message-1", text: "Retained answer."}),
    ], events: source([
      native(3, {kind: "state_snapshot", snapshot: {status: "completed"}}),
      native(4, {kind: "run_finished"}),
    ])};
    const response = await handler(authority)(agentRequest(input(), {
      "last-event-id": "v1:session%3A2:0",
    }));
    const {events, ids} = decodeSse(await response.text());
    expect(authority.opens[0]?.cursor).toBe("session:2");
    expect(events.map((event) => event.type)).toEqual([
      EventType.TEXT_MESSAGE_CONTENT,
      EventType.TEXT_MESSAGE_END,
      EventType.STATE_SNAPSHOT,
      EventType.RUN_FINISHED,
    ]);
    expect(ids).toEqual([
      "v1:session%3A2:1",
      "v1:session%3A2:2",
      "v1:session%3A3:0",
      "v1:session%3A4:0",
    ]);
  });

  test("checkpoints state and messages before a terminal interrupt outcome", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started"}),
      native(2, {kind: "state_snapshot", snapshot: {status: "awaiting_approval"}}),
      native(3, {kind: "messages_snapshot", messages: [
        {id: "user-1", role: "user", content: "Proceed?"},
        {id: "assistant-1", role: "assistant", content: "Approval is required."},
      ]}),
      native(4, {
        kind: "approval_requested",
        approvalId: "approval-1",
        reason: "confirmation",
        expectedRevision: 7,
        message: "Approve the operation?",
        responseSchema: {type: "object", required: ["approved"]},
      }),
    ])};
    const {events} = decodeSse(await (await handler(authority)(agentRequest(input()))).text());
    expect(events.map((event) => event.type)).toEqual([
      EventType.RUN_STARTED,
      EventType.STATE_SNAPSHOT,
      EventType.MESSAGES_SNAPSHOT,
      EventType.RUN_FINISHED,
    ]);
    const terminal = events.at(-1);
    expect(terminal).toMatchObject({
      type: EventType.RUN_FINISHED,
      outcome: {type: "interrupt", interrupts: [{id: "approval-1", reason: "confirmation"}]},
    });
  });

  test("refuses an interrupt stream that did not checkpoint both state and messages", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started"}),
      native(2, {kind: "state_snapshot", snapshot: {status: "awaiting_approval"}}),
      native(3, {
        kind: "approval_requested",
        approvalId: "approval-1",
        reason: "confirmation",
        expectedRevision: 7,
      }),
    ])};
    const {events} = decodeSse(await (await handler(authority)(agentRequest(input()))).text());
    expect(events.at(-1)).toMatchObject({
      type: EventType.RUN_ERROR,
      code: "automonique.invalid_interrupt_not_checkpointed",
    });
    expect(events.filter((event) => event.type === EventType.RUN_FINISHED || event.type === EventType.RUN_ERROR)).toHaveLength(1);
  });

  test("passes a same-thread resume to Platform and preserves validated parent lineage", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started", parentRunId: "run-0"}),
      native(2, {kind: "run_finished"}),
    ])};
    const resume = input({messages: [], parentRunId: "run-0", resume: [
      {interruptId: "approval-1", status: "resolved", payload: {approved: true}},
    ]});
    const {events} = decodeSse(await (await handler(authority)(agentRequest(resume))).text());
    expect(authority.opens[0]?.input.resume).toEqual([
      {interruptId: "approval-1", status: "resolved", payload: {approved: true}},
    ]);
    expect(events[0]).toMatchObject({type: EventType.RUN_STARTED, parentRunId: "run-0"});
  });

  test("keeps complete-set, schema, expiry, same-thread, and replay validation in Platform authority", async () => {
    const authority = new FakeAuthority();
    authority.open = async (request) => {
      authority.opens.push(request);
      const decisions = request.input.resume;
      const approval = decisions.find((entry) => entry.interruptId === "approval-1");
      const inputRequired = decisions.find((entry) => entry.interruptId === "input-1");
      const valid = request.input.threadId === "thread-1"
        && decisions.length === 2
        && approval?.status === "resolved"
        && typeof approval.payload === "object"
        && approval.payload !== null
        && !Array.isArray(approval.payload)
        && approval.payload.approved === true
        && inputRequired?.status === "cancelled";
      const expired = decisions.some((entry) => entry.interruptId === "expired-1");
      return {kind: "stream", replay: [], events: source([
        native(1, {kind: "run_started", parentRunId: "run-0"}),
        native(2, {kind: valid ? "run_finished" : "run_refused", ...(valid ? {} : {code: expired ? "interrupt_expired" : "interrupt_invalid"})} as NativeAdapterEvent),
      ])};
    };

    const partial = input({messages: [], parentRunId: "run-0", resume: [
      {interruptId: "approval-1", status: "resolved", payload: {approved: true}},
    ]});
    expect(decodeSse(await (await handler(authority)(agentRequest(partial))).text()).events.at(-1)).toMatchObject({
      type: EventType.RUN_ERROR,
      code: "automonique.interrupt_invalid",
    });

    const invalidSchema = input({messages: [], parentRunId: "run-0", resume: [
      {interruptId: "approval-1", status: "resolved", payload: {approved: "yes"}},
      {interruptId: "input-1", status: "cancelled"},
    ]});
    expect(decodeSse(await (await handler(authority)(agentRequest(invalidSchema))).text()).events.at(-1)).toMatchObject({
      type: EventType.RUN_ERROR,
      code: "automonique.interrupt_invalid",
    });

    const expired = input({messages: [], parentRunId: "run-0", resume: [
      {interruptId: "expired-1", status: "resolved", payload: {approved: true}},
    ]});
    expect(decodeSse(await (await handler(authority)(agentRequest(expired))).text()).events.at(-1)).toMatchObject({
      type: EventType.RUN_ERROR,
      code: "automonique.interrupt_expired",
    });

    const valid = input({messages: [], parentRunId: "run-0", resume: [
      {interruptId: "approval-1", status: "resolved", payload: {approved: true}},
      {interruptId: "input-1", status: "cancelled"},
    ]});
    const first = decodeSse(await (await handler(authority)(agentRequest(valid))).text()).events;
    const replay = decodeSse(await (await handler(authority)(agentRequest(valid))).text()).events;
    expect(first).toEqual(replay);
    expect(first.at(-1)?.type).toBe(EventType.RUN_FINISHED);
  });

  test("turns malformed or incomplete authority streams into one sanitized error terminal", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started"}),
      native(2, {kind: "assistant_message_completed", messageId: "message-1", text: "Partial"}),
    ])};
    const {events} = decodeSse(await (await handler(authority)(agentRequest(input()))).text());
    expect(events[0]?.type).toBe(EventType.RUN_STARTED);
    expect(events.at(-1)).toMatchObject({type: EventType.RUN_ERROR, code: "automonique.invalid_missing_terminal"});
    expect(events.filter((event) => event.type === EventType.RUN_FINISHED || event.type === EventType.RUN_ERROR)).toHaveLength(1);
  });

  test("propagates explicit cancellation through Platform authority with receipt identity", async () => {
    const authority = new FakeAuthority();
    const response = await handler(authority)(new Request("http://127.0.0.1/cancel", {
      method: "POST",
      headers: {authorization: authentication, "content-type": "application/json"},
      body: JSON.stringify({
        threadId: "thread-1",
        runId: "run-1",
        idempotencyKey: "cancel-run-1",
        expectedRevision: 9,
      }),
    }));
    expect(response.status).toBe(202);
    expect(authority.cancellations).toEqual([{
      threadId: "thread-1",
      runId: "run-1",
      idempotencyKey: "cancel-run-1",
      expectedRevision: 9,
    }]);
    expect(await response.json()).toEqual({receiptId: "receipt-1", outcome: "accepted"});
  });

  test("fails closed on a malformed Platform cancellation receipt", async () => {
    const authority = new FakeAuthority();
    authority.cancel = async () => ({
      receiptId: "receipt-1",
      outcome: "accepted",
      diagnostic: "private authority detail",
    }) as PlatformCancelReceipt;
    const response = await handler(authority)(new Request("http://127.0.0.1/cancel", {
      method: "POST",
      headers: {authorization: authentication, "content-type": "application/json"},
      body: JSON.stringify({
        threadId: "thread-1",
        runId: "run-1",
        idempotencyKey: "cancel-run-1",
        expectedRevision: 9,
      }),
    }));
    expect(response.status).toBe(502);
    expect(JSON.stringify(await response.json())).not.toContain("private authority detail");
  });

  test("disconnects a slow consumer with its cursor and never converts disconnect into cancellation", async () => {
    const authority = new FakeAuthority();
    authority.result = {kind: "stream", replay: [], events: source([
      native(1, {kind: "run_started"}),
      native(2, {kind: "assistant_message_completed", messageId: "message-1", text: "x".repeat(4_096)}),
      native(3, {kind: "run_finished"}),
    ])};
    const response = await handler(authority, {
      maxBufferedBytes: 1_024,
      maxStreamBytes: 8_192,
      writeTimeoutMs: 10,
    })(agentRequest(input()));
    const reader = response.body?.getReader();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toContain("RUN_STARTED");
    await Bun.sleep(50);
    expect(authority.disconnects).toHaveLength(1);
    expect(authority.disconnects[0]?.cursor).toBe("v1:session%3A1:0");
    expect(authority.cancellations).toHaveLength(0);
    await reader?.cancel();
  });
});
