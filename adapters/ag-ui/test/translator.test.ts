// SPDX-License-Identifier: Elastic-2.0

import {describe, expect, test} from "bun:test";
import {EventSchemas} from "@ag-ui/core";
import manifest from "../package.json" with {type: "json"};
import golden from "./fixtures/authoritative-turn.ag-ui.json" with {type: "json"};
import native from "./fixtures/authoritative-turn.native.json" with {type: "json"};
import {
  AG_UI_CORE_VERSION,
  NATIVE_ADAPTER_SCHEMA,
  TranslationError,
  translateNativeEvent,
  translateNativeStream,
  type NativeAdapterEvent,
} from "../src/index.ts";

const base = {
  schema: NATIVE_ADAPTER_SCHEMA,
  cursor: "session:1",
  timestamp: 1_000,
  threadId: "thread-public-1",
  runId: "turn-public-1",
} as const;

describe("native event to AG-UI translation", () => {
  test("keeps the declared canonical package at the translator pin", () => {
    expect(manifest.dependencies["@ag-ui/core"]).toBe(AG_UI_CORE_VERSION);
  });

  test("matches the authoritative golden stream and the pinned runtime schemas", () => {
    const translated = translateNativeStream(native as NativeAdapterEvent[]);
    expect(translated).toEqual(golden);
    for (const event of translated) expect(EventSchemas.parse(event)).toEqual(event);
  });

  test("is deterministic and never promotes replaceable preview text", () => {
    const first = translateNativeStream(native as NativeAdapterEvent[]);
    const second = translateNativeStream(structuredClone(native) as NativeAdapterEvent[]);
    expect(first).toEqual(second);
    expect(first.filter((event) => event.type === "TEXT_MESSAGE_CONTENT")).toHaveLength(1);
    expect(first.find((event) => event.type === "CUSTOM")).toMatchObject({name: "automonique.preview"});
  });

  test("projects an approval as a terminal interrupt with its native revision", () => {
    const output = translateNativeStream([
      {...base, sequence: 1, kind: "run_started"},
      {...base, sequence: 2, cursor: "session:2", kind: "tool_call_started", toolCallId: "tool-1", toolName: "bounded_lookup"},
      {...base, sequence: 3, cursor: "session:3", kind: "tool_call_args", toolCallId: "tool-1", delta: "{}"},
      {...base, sequence: 4, cursor: "session:4", kind: "tool_call_ended", toolCallId: "tool-1"},
      {
        ...base,
        sequence: 5,
        cursor: "session:5",
        kind: "approval_requested",
        approvalId: "approval-1",
        reason: "tool_call",
        expectedRevision: 3,
        message: "Allow the bounded lookup?",
        toolCallId: "tool-1",
        responseSchema: {type: "object", additionalProperties: false},
        expiresAt: "2026-08-24T15:00:00Z",
      },
    ]);
    expect(output.at(-1)).toMatchObject({
      type: "RUN_FINISHED",
      outcome: {
        type: "interrupt",
        interrupts: [{id: "approval-1", metadata: {automonique: {expectedRevision: 3}}}],
      },
    });
  });

  test("correlates a resumed tool result without replaying its proposal", () => {
    const output = translateNativeStream([
      {...base, sequence: 1, kind: "run_started", resumedToolCallIds: ["tool-previous"]},
      {
        ...base,
        sequence: 2,
        cursor: "session:2",
        kind: "tool_call_result",
        toolCallId: "tool-previous",
        resultMessageId: "tool-result-previous",
        content: "approved and completed",
      },
      {...base, sequence: 3, cursor: "session:3", kind: "run_finished"},
    ]);
    expect(output.map((event) => event.type)).toEqual(["RUN_STARTED", "TOOL_CALL_RESULT", "RUN_FINISHED"]);
  });

  test("uses fixed public refusal text and drops undeclared provider fields", () => {
    const hostile = {
      ...base,
      sequence: 2,
      cursor: "session:2",
      kind: "run_refused",
      code: "authorization_lost",
      message: "secret upstream diagnostic",
      rawProviderEvent: {credential: "do-not-emit"},
    } as unknown as NativeAdapterEvent;
    const output = translateNativeStream([{...base, sequence: 1, kind: "run_started"}, hostile]);
    expect(output.at(-1)).toMatchObject({
      type: "RUN_ERROR",
      code: "automonique.authorization_lost",
      message: "Authorization was lost before the run could continue.",
    });
    expect(JSON.stringify(output)).not.toContain("secret upstream");
    expect(JSON.stringify(output)).not.toContain("credential");
  });
});

describe("closed ordering and bounds", () => {
  test("rejects duplicate, missing, and post-terminal lifecycle events", () => {
    const started = {...base, sequence: 1, kind: "run_started"} as const;
    expect(() => translateNativeStream([])).toThrow(TranslationError);
    expect(() => translateNativeStream([started])).toThrow("exactly one terminal");
    expect(() => translateNativeStream([started, {...base, sequence: 1, kind: "run_finished"}])).toThrow("strictly increase");
    expect(() => translateNativeStream([
      started,
      {...base, sequence: 2, kind: "run_finished"},
      {...base, sequence: 3, kind: "control_lost", reason: "lease_expired"},
    ])).toThrow("followed a terminal");
  });

  test("rejects incomplete and misordered tool calls", () => {
    const started = {...base, sequence: 1, kind: "run_started"} as const;
    expect(() => translateNativeStream([
      started,
      {...base, sequence: 2, kind: "tool_call_args", toolCallId: "tool-1", delta: "{}"},
      {...base, sequence: 3, kind: "run_finished"},
    ])).toThrow("require an open call");
    expect(() => translateNativeStream([
      started,
      {...base, sequence: 2, kind: "tool_call_started", toolCallId: "tool-1", toolName: "lookup"},
      {...base, sequence: 3, kind: "run_finished"},
    ])).toThrow("cannot strand a tool call");
  });

  test("rejects unknown schemas, event kinds, and oversized public text", () => {
    expect(() => translateNativeEvent({...base, sequence: 1, kind: "run_finished", schema: "future"} as never)).toThrow("unsupported native adapter schema");
    expect(() => translateNativeEvent({...base, sequence: 1, kind: "provider_raw"} as never)).toThrow("unsupported native event");
    expect(() => translateNativeEvent({
      ...base,
      sequence: 1,
      kind: "assistant_message_completed",
      messageId: "message-1",
      text: "x".repeat(65_537),
    })).toThrow("text is empty, oversized");
  });
});
