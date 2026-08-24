// SPDX-License-Identifier: Elastic-2.0

import {EventSchemas, EventType, type AGUIEvent} from "@ag-ui/core";
import {NATIVE_ADAPTER_SCHEMA, type JsonValue, type NativeAdapterEvent, type RefusalCode} from "./contract.ts";

export const AG_UI_CORE_VERSION = "0.0.58" as const;
export const EVENT_METADATA_SCHEMA = "automonique.ag-ui-event-meta/v1" as const;

const MAX_EVENTS = 4_096;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_CURSOR_BYTES = 512;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_STATE_BYTES = 128 * 1024;

const refusalMessages: Readonly<Record<RefusalCode, string>> = {
  authorization_lost: "Authorization was lost before the run could continue.",
  capability_unsupported: "The requested capability is not supported.",
  internal_failure: "The run could not continue.",
  policy_refused: "The requested action was refused by policy.",
  resync_required: "The retained event cursor expired; resynchronization is required.",
  stale_revision: "The requested action targeted a stale resource revision.",
};

export class TranslationError extends Error {
  public constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "TranslationError";
  }
}

/** Translate one already-sanitized native projection without retaining state. */
export function translateNativeEvent(event: NativeAdapterEvent): readonly AGUIEvent[] {
  validateEvent(event);
  const common = {
    timestamp: event.timestamp,
    automonique: {
      schema: EVENT_METADATA_SCHEMA,
      cursor: event.cursor,
      sequence: event.sequence,
    },
  };
  const emit = (value: Record<string, unknown>): AGUIEvent => EventSchemas.parse({...common, ...value});

  switch (event.kind) {
    case "run_started":
      return [emit({type: EventType.RUN_STARTED, threadId: event.threadId, runId: event.runId})];
    case "assistant_message_preview":
      return [emit({
        type: EventType.CUSTOM,
        name: "automonique.preview",
        value: {messageId: event.messageId, text: event.text, replace: event.replace},
      })];
    case "assistant_message_completed":
      return [
        emit({type: EventType.TEXT_MESSAGE_START, messageId: event.messageId, role: "assistant"}),
        emit({type: EventType.TEXT_MESSAGE_CONTENT, messageId: event.messageId, delta: event.text}),
        emit({type: EventType.TEXT_MESSAGE_END, messageId: event.messageId}),
      ];
    case "tool_call_started":
      return [emit({
        type: EventType.TOOL_CALL_START,
        toolCallId: event.toolCallId,
        toolCallName: event.toolName,
        ...(event.parentMessageId === undefined ? {} : {parentMessageId: event.parentMessageId}),
      })];
    case "tool_call_args":
      return [emit({type: EventType.TOOL_CALL_ARGS, toolCallId: event.toolCallId, delta: event.delta})];
    case "tool_call_ended":
      return [emit({type: EventType.TOOL_CALL_END, toolCallId: event.toolCallId})];
    case "tool_call_result":
      return [emit({
        type: EventType.TOOL_CALL_RESULT,
        messageId: event.resultMessageId,
        toolCallId: event.toolCallId,
        content: event.content,
        role: "tool",
      })];
    case "state_snapshot":
      return [emit({type: EventType.STATE_SNAPSHOT, snapshot: event.snapshot})];
    case "state_delta":
      return [emit({type: EventType.STATE_DELTA, delta: event.delta})];
    case "step_started":
      return [emit({type: EventType.STEP_STARTED, stepName: event.stepName})];
    case "step_finished":
      return [emit({type: EventType.STEP_FINISHED, stepName: event.stepName})];
    case "approval_requested": {
      const interrupt: Record<string, unknown> = {
        id: event.approvalId,
        reason: event.reason,
        metadata: {automonique: {expectedRevision: event.expectedRevision}},
      };
      if (event.message !== undefined) interrupt.message = event.message;
      if (event.toolCallId !== undefined) interrupt.toolCallId = event.toolCallId;
      if (event.responseSchema !== undefined) interrupt.responseSchema = event.responseSchema;
      if (event.expiresAt !== undefined) interrupt.expiresAt = event.expiresAt;
      return [emit({
        type: EventType.RUN_FINISHED,
        threadId: event.threadId,
        runId: event.runId,
        outcome: {type: "interrupt", interrupts: [interrupt]},
      })];
    }
    case "control_lost":
      return [emit({
        type: EventType.CUSTOM,
        name: "automonique.control_lost",
        value: {reason: event.reason},
      })];
    case "run_finished":
      return [emit({
        type: EventType.RUN_FINISHED,
        threadId: event.threadId,
        runId: event.runId,
        outcome: {type: "success"},
      })];
    case "run_refused":
      return [emit({
        type: EventType.RUN_ERROR,
        code: `automonique.${event.code}`,
        message: refusalMessages[event.code],
      })];
    default:
      return assertNever(event);
  }
}

/**
 * Translate one complete retained run page and enforce ordering before any
 * caller can stream it. Reconnect pages that do not begin at run start must be
 * checkpointed by the future stream layer before entering this function.
 */
export function translateNativeStream(events: readonly NativeAdapterEvent[]): readonly AGUIEvent[] {
  if (events.length === 0) throw new TranslationError("empty_stream", "a run stream cannot be empty");
  if (events.length > MAX_EVENTS) throw new TranslationError("too_many_events", "native event page exceeds its bound");

  const first = events[0];
  if (first?.kind !== "run_started") {
    throw new TranslationError("missing_run_start", "the first retained event must start the run");
  }

  let lastSequence = 0;
  let terminal = false;
  const openTools = new Set<string>();
  const awaitingToolResults = new Set(first.resumedToolCallIds ?? []);
  const output: AGUIEvent[] = [];

  for (const event of events) {
    if (event.threadId !== first.threadId || event.runId !== first.runId) {
      throw new TranslationError("mixed_run", "one stream page cannot mix native runs");
    }
    if (event.sequence <= lastSequence) {
      throw new TranslationError("sequence_not_increasing", "native event sequences must strictly increase");
    }
    if (terminal) throw new TranslationError("event_after_terminal", "a native event followed a terminal event");
    if (event !== first && event.kind === "run_started") {
      throw new TranslationError("duplicate_run_start", "a run may start exactly once");
    }

    switch (event.kind) {
      case "tool_call_started":
        if (openTools.has(event.toolCallId)) throw new TranslationError("duplicate_tool_start", "tool call is already open");
        openTools.add(event.toolCallId);
        break;
      case "tool_call_args":
        if (!openTools.has(event.toolCallId)) throw new TranslationError("tool_not_open", "tool arguments require an open call");
        break;
      case "tool_call_ended":
        if (!openTools.delete(event.toolCallId)) throw new TranslationError("tool_not_open", "tool end requires an open call");
        awaitingToolResults.add(event.toolCallId);
        break;
      case "tool_call_result":
        if (!awaitingToolResults.delete(event.toolCallId)) throw new TranslationError("tool_not_pending", "tool result requires an ended call or resumed proposal");
        break;
      case "approval_requested":
        if (openTools.size !== 0) throw new TranslationError("tool_still_open", "an interrupt requires ended tool arguments");
        if (event.toolCallId === undefined) {
          if (awaitingToolResults.size !== 0) throw new TranslationError("tool_result_pending", "a non-tool interrupt cannot strand a tool result");
        } else if (awaitingToolResults.size !== 1 || !awaitingToolResults.has(event.toolCallId)) {
          throw new TranslationError("interrupt_tool_mismatch", "tool interrupt must identify the one pending proposal");
        }
        terminal = true;
        break;
      case "run_finished":
      case "run_refused":
        if (openTools.size !== 0 || awaitingToolResults.size !== 0) {
          throw new TranslationError("tool_still_open", "a successful or refused run cannot strand a tool call");
        }
        terminal = true;
        break;
      default:
        break;
    }

    output.push(...translateNativeEvent(event));
    lastSequence = event.sequence;
  }

  if (!terminal) throw new TranslationError("missing_terminal", "a complete run stream needs exactly one terminal event");
  return output;
}

function validateEvent(event: NativeAdapterEvent): void {
  if (event.schema !== NATIVE_ADAPTER_SCHEMA) throw new TranslationError("schema_mismatch", "unsupported native adapter schema");
  if (!Number.isSafeInteger(event.sequence) || event.sequence <= 0) throw new TranslationError("invalid_sequence", "sequence must be a positive safe integer");
  if (!Number.isSafeInteger(event.timestamp) || event.timestamp < 0) throw new TranslationError("invalid_timestamp", "timestamp must be epoch milliseconds");
  bounded(event.cursor, MAX_CURSOR_BYTES, "cursor");
  bounded(event.threadId, MAX_IDENTIFIER_BYTES, "threadId");
  bounded(event.runId, MAX_IDENTIFIER_BYTES, "runId");

  for (const value of eventStrings(event)) bounded(value.value, value.max, value.field);
  if (event.kind === "state_snapshot") boundedJson(event.snapshot, "snapshot");
  if (event.kind === "state_delta") boundedJson(event.delta, "delta");
  if (event.kind === "approval_requested") {
    if (!Number.isSafeInteger(event.expectedRevision) || event.expectedRevision <= 0) {
      throw new TranslationError("invalid_revision", "approval revision must be a positive safe integer");
    }
    if (event.responseSchema !== undefined) boundedJson(event.responseSchema, "responseSchema");
  }
  if (event.kind === "run_refused" && !Object.hasOwn(refusalMessages, event.code)) {
    throw new TranslationError("unknown_refusal", "unsupported native refusal code");
  }
  if (event.kind === "run_started" && event.resumedToolCallIds !== undefined) {
    if (event.resumedToolCallIds.length > 64 || new Set(event.resumedToolCallIds).size !== event.resumedToolCallIds.length) {
      throw new TranslationError("invalid_resumed_tools", "resumed tool calls must be bounded and unique");
    }
    for (const toolCallId of event.resumedToolCallIds) bounded(toolCallId, MAX_IDENTIFIER_BYTES, "resumedToolCallId");
  }
}

function eventStrings(event: NativeAdapterEvent): readonly {field: string; max: number; value: string}[] {
  switch (event.kind) {
    case "assistant_message_preview":
    case "assistant_message_completed":
      return [{field: "messageId", max: MAX_IDENTIFIER_BYTES, value: event.messageId}, {field: "text", max: MAX_TEXT_BYTES, value: event.text}];
    case "tool_call_started":
      return [
        {field: "toolCallId", max: MAX_IDENTIFIER_BYTES, value: event.toolCallId},
        {field: "toolName", max: MAX_IDENTIFIER_BYTES, value: event.toolName},
        ...(event.parentMessageId === undefined ? [] : [{field: "parentMessageId", max: MAX_IDENTIFIER_BYTES, value: event.parentMessageId}]),
      ];
    case "tool_call_args":
      return [{field: "toolCallId", max: MAX_IDENTIFIER_BYTES, value: event.toolCallId}, {field: "delta", max: MAX_TEXT_BYTES, value: event.delta}];
    case "tool_call_ended":
      return [{field: "toolCallId", max: MAX_IDENTIFIER_BYTES, value: event.toolCallId}];
    case "tool_call_result":
      return [
        {field: "toolCallId", max: MAX_IDENTIFIER_BYTES, value: event.toolCallId},
        {field: "resultMessageId", max: MAX_IDENTIFIER_BYTES, value: event.resultMessageId},
        {field: "content", max: MAX_TEXT_BYTES, value: event.content},
      ];
    case "step_started":
    case "step_finished":
      return [{field: "stepName", max: MAX_IDENTIFIER_BYTES, value: event.stepName}];
    case "approval_requested":
      return [
        {field: "approvalId", max: MAX_IDENTIFIER_BYTES, value: event.approvalId},
        {field: "reason", max: MAX_IDENTIFIER_BYTES, value: event.reason},
        ...(event.message === undefined ? [] : [{field: "message", max: MAX_TEXT_BYTES, value: event.message}]),
        ...(event.toolCallId === undefined ? [] : [{field: "toolCallId", max: MAX_IDENTIFIER_BYTES, value: event.toolCallId}]),
        ...(event.expiresAt === undefined ? [] : [{field: "expiresAt", max: MAX_IDENTIFIER_BYTES, value: event.expiresAt}]),
      ];
    case "control_lost":
      return [{field: "reason", max: MAX_TEXT_BYTES, value: event.reason}];
    case "run_started":
    case "run_finished":
    case "run_refused":
    case "state_snapshot":
    case "state_delta":
      return [];
    default:
      return assertNever(event);
  }
}

function bounded(value: string, maxBytes: number, field: string): void {
  const bytes = new TextEncoder().encode(value).byteLength;
  if (bytes === 0 || bytes > maxBytes || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    throw new TranslationError("invalid_field", `${field} is empty, oversized, or contains a control character`);
  }
}

function boundedJson(value: JsonValue | readonly unknown[], field: string): void {
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new TranslationError("invalid_json", `${field} is not JSON serializable`);
  }
  if (new TextEncoder().encode(encoded).byteLength > MAX_STATE_BYTES) {
    throw new TranslationError("state_too_large", `${field} exceeds the derived-state bound`);
  }
}

function assertNever(value: never): never {
  throw new TranslationError("unsupported_event", `unsupported native event: ${String((value as {kind?: unknown}).kind)}`);
}
