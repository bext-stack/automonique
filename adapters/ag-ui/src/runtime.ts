// SPDX-License-Identifier: Elastic-2.0

import {
  AgentCapabilitiesSchema,
  EventSchemas,
  EventType,
  type AgentCapabilities,
  type AGUIEvent,
} from "@ag-ui/core";
import {AdmissionError, MAX_RUN_INPUT_BYTES, admitRunAgentInput} from "./admission.ts";
import type {PlatformCancelRequest, PlatformRunAuthority} from "./authority.ts";
import {NativeStreamTranslator, TranslationError} from "./translator.ts";

const JSON_CONTENT_TYPE = "application/json";
const SSE_CONTENT_TYPE = "text/event-stream";
const MAX_NATIVE_CURSOR_BYTES = 512;
const MAX_LAST_EVENT_ID_BYTES = 2_048;
const MAX_PROJECTION_INDEX = 64;
const MAX_CANCEL_BYTES = 16 * 1024;
const MAX_CANCEL_IDENTIFIER_BYTES = 256;
const encoder = new TextEncoder();

export const AG_UI_CAPABILITIES: AgentCapabilities = AgentCapabilitiesSchema.parse({
  identity: {
    name: "Automonique",
    type: "automonique-platform-v1",
    description: "A projection-only AG-UI adapter over Automonique Platform authority.",
    version: "0.1.0",
    provider: "Automonique",
  },
  transport: {streaming: true, resumable: true},
  tools: {supported: true, parallelCalls: false, clientProvided: false},
  state: {snapshots: true, deltas: true, persistentState: true},
  humanInTheLoop: {
    supported: true,
    approvals: true,
    interrupts: true,
  },
  custom: {
    "automonique.platform": {
      authority: "automonique.platform/v1",
      cursorHeader: "Last-Event-ID",
      cancellationPath: "/cancel",
      clientStateAuthority: false,
      clientToolAuthority: false,
      reasoningExposed: false,
    },
  },
});

export interface RuntimeConfig {
  readonly authorize: (request: Request) => boolean | Promise<boolean>;
  readonly maxBufferedBytes?: number;
  readonly maxStreamBytes?: number;
  readonly writeTimeoutMs?: number;
}

export type AguiHandler = (request: Request) => Promise<Response>;

export function createAguiHandler(authority: PlatformRunAuthority, config: RuntimeConfig): AguiHandler {
  const maxBufferedBytes = config.maxBufferedBytes ?? 128 * 1024;
  const maxStreamBytes = config.maxStreamBytes ?? 4 * 1024 * 1024;
  const writeTimeoutMs = config.writeTimeoutMs ?? 5_000;
  if (!Number.isSafeInteger(maxBufferedBytes) || maxBufferedBytes < 1024 || maxBufferedBytes > 1024 * 1024) {
    throw new RangeError("maxBufferedBytes is outside the supervised runtime bound");
  }
  if (!Number.isSafeInteger(maxStreamBytes) || maxStreamBytes < maxBufferedBytes || maxStreamBytes > 16 * 1024 * 1024) {
    throw new RangeError("maxStreamBytes is outside the supervised runtime bound");
  }
  if (!Number.isSafeInteger(writeTimeoutMs) || writeTimeoutMs < 10 || writeTimeoutMs > 30_000) {
    throw new RangeError("writeTimeoutMs is outside the supervised runtime bound");
  }

  return async (request) => {
    const url = new URL(request.url);
    if (url.search !== "") return problem(400, "query_refused", "Query parameters are not accepted.");
    if (request.method === "GET" && url.pathname === "/healthz") {
      return json(200, {ok: true, service: "automonique-agui-adapter"});
    }
    if (request.method === "GET" && url.pathname === "/readyz") {
      const ready = await boundedReady(authority, request.signal);
      return json(ready ? 200 : 503, {ok: ready, ready});
    }
    let authorized = false;
    try {
      authorized = await config.authorize(request);
    } catch {
      authorized = false;
    }
    if (!authorized) return problem(401, "unauthorized", "Authentication is required.");
    if (request.method === "GET" && url.pathname === "/capabilities") {
      return json(200, AG_UI_CAPABILITIES);
    }
    if (request.method === "POST" && url.pathname === "/agent") {
      return handleAgent(request, authority, {maxBufferedBytes, maxStreamBytes, writeTimeoutMs});
    }
    if (request.method === "POST" && url.pathname === "/cancel") {
      return handleCancel(request, authority);
    }
    return problem(404, "not_found", "The requested adapter route does not exist.");
  };
}

async function handleAgent(
  request: Request,
  authority: PlatformRunAuthority,
  limits: Required<Pick<RuntimeConfig, "maxBufferedBytes" | "maxStreamBytes" | "writeTimeoutMs">>,
): Promise<Response> {
  if (!mediaType(request.headers.get("content-type"), JSON_CONTENT_TYPE)) {
    return problem(415, "content_type_required", "Run input must use application/json.");
  }
  if (!accepts(request.headers.get("accept"), SSE_CONTENT_TYPE)) {
    return problem(406, "sse_required", "Run output requires text/event-stream.");
  }
  let input;
  try {
    input = admitRunAgentInput(await readJson(request, MAX_RUN_INPUT_BYTES));
  } catch (error) {
    return publicError(error);
  }
  let cursor: DeliveryCursor | null;
  try {
    cursor = admitLastEventId(request.headers.get("last-event-id"));
  } catch (error) {
    return publicError(error);
  }

  let opened;
  try {
    opened = await authority.open({input, cursor: cursor?.nativeCursor ?? null}, request.signal);
  } catch {
    return problem(503, "platform_unavailable", "Platform authority is unavailable.");
  }
  if (opened.kind === "resync_required") {
    let snapshotCursor: string;
    try {
      snapshotCursor = admitNativeCursor(opened.cursor) ?? "";
      if (snapshotCursor === "") throw new AdmissionError("invalid_cursor", "resync cursor is empty");
    } catch {
      return problem(502, "platform_response_invalid", "Platform returned an invalid resync cursor.");
    }
    return json(409, {error: "resync_required", cursor: snapshotCursor, retryable: true});
  }

  const stream = new TransformStream<Uint8Array, Uint8Array>(undefined, {
    highWaterMark: limits.maxBufferedBytes,
    size: (chunk) => chunk?.byteLength ?? 0,
  });
  const writer = stream.writable.getWriter();
  void pumpRun(opened.replay, opened.events, input.threadId, input.runId, cursor, authority, writer, request.signal, limits);
  return new Response(stream.readable, {
    status: 200,
    headers: {
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "content-type": `${SSE_CONTENT_TYPE}; charset=utf-8`,
      "x-accel-buffering": "no",
      "x-content-type-options": "nosniff",
    },
  });
}

async function pumpRun(
  replay: readonly import("./contract.ts").NativeAdapterEvent[],
  events: AsyncIterable<import("./contract.ts").NativeAdapterEvent>,
  threadId: string,
  runId: string,
  initialCursor: DeliveryCursor | null,
  authority: PlatformRunAuthority,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  signal: AbortSignal,
  limits: Required<Pick<RuntimeConfig, "maxBufferedBytes" | "maxStreamBytes" | "writeTimeoutMs">>,
): Promise<void> {
  const translator = new NativeStreamTranslator();
  let lastDeliveredId = initialCursor === null ? null : formatLastEventId(initialCursor);
  let written = 0;
  let emitted = 0;
  let terminalWritten = false;
  let transportLost = false;
  try {
    let replayTail: readonly AGUIEvent[] = [];
    if (initialCursor === null && replay.length !== 0) {
      throw new RuntimeStreamError("invalid_replay", "A fresh stream cannot carry a replay prefix.");
    }
    for (const nativeEvent of replay) replayTail = translator.push(nativeEvent);
    if (initialCursor !== null) {
      const replayCursor = translator.lastCursor;
      if (replayCursor !== initialCursor.nativeCursor || replayTail.length <= initialCursor.projectionIndex) {
        throw new RuntimeStreamError("invalid_replay", "The retained prefix does not match Last-Event-ID.");
      }
      for (let index = initialCursor.projectionIndex + 1; index < replayTail.length; index += 1) {
        const event = replayTail[index];
        if (event === undefined) throw new RuntimeStreamError("invalid_replay", "The retained projection is incomplete.");
        const delivery = {nativeCursor: initialCursor.nativeCursor, projectionIndex: index};
        const chunk = sse(event, delivery);
        written += chunk.byteLength;
        if (written > limits.maxStreamBytes) throw new RuntimeStreamError("stream_limit", "The event stream exceeded its bound.");
        await boundedWrite(writer, chunk, limits.writeTimeoutMs);
        lastDeliveredId = formatLastEventId(delivery);
        emitted += 1;
        if (event.type === EventType.RUN_FINISHED || event.type === EventType.RUN_ERROR) terminalWritten = true;
      }
    }
    for await (const nativeEvent of events) {
      if (signal.aborted) throw new StreamDisconnected();
      const translated = translator.push(nativeEvent);
      for (const [index, event] of translated.entries()) {
        const delivery = {nativeCursor: nativeEvent.cursor, projectionIndex: index};
        const chunk = sse(event, delivery);
        written += chunk.byteLength;
        if (written > limits.maxStreamBytes) throw new RuntimeStreamError("stream_limit", "The event stream exceeded its bound.");
        await boundedWrite(writer, chunk, limits.writeTimeoutMs);
        lastDeliveredId = formatLastEventId(delivery);
        emitted += 1;
        if (event.type === EventType.RUN_FINISHED || event.type === EventType.RUN_ERROR) terminalWritten = true;
      }
    }
    translator.finish();
  } catch (error) {
    if (error instanceof StreamDisconnected || error instanceof SlowConsumerError || signal.aborted) {
      transportLost = true;
    } else if (!terminalWritten) {
      try {
        if (emitted === 0 && initialCursor === null) {
          await boundedWrite(writer, sse(EventSchemas.parse({type: EventType.RUN_STARTED, threadId, runId}), null), limits.writeTimeoutMs);
        }
        const code = error instanceof RuntimeStreamError ? error.code
          : error instanceof TranslationError ? `invalid_${error.code}`
            : "platform_stream_failed";
        await boundedWrite(writer, sse(EventSchemas.parse({
          type: EventType.RUN_ERROR,
          code: `automonique.${code}`,
          message: "The run stream could not continue.",
        }), null), limits.writeTimeoutMs);
      } catch {
        transportLost = true;
      }
    }
  } finally {
    if (transportLost) {
      try {
        await authority.disconnected?.(threadId, runId, lastDeliveredId);
      } catch {
        // Disconnect reporting is advisory and never changes native run state.
      }
    }
    try {
      await writer.close();
    } catch {
      // The consumer already disconnected.
    }
  }
}

async function handleCancel(request: Request, authority: PlatformRunAuthority): Promise<Response> {
  if (!mediaType(request.headers.get("content-type"), JSON_CONTENT_TYPE)) {
    return problem(415, "content_type_required", "Cancellation input must use application/json.");
  }
  let cancellation: PlatformCancelRequest;
  try {
    const body = plainRecord(await readJson(request, MAX_CANCEL_BYTES));
    exactKeys(body, ["expectedRevision", "idempotencyKey", "runId", "threadId"]);
    cancellation = {
      threadId: cancelIdentifier(body.threadId, "threadId"),
      runId: cancelIdentifier(body.runId, "runId"),
      idempotencyKey: cancelIdentifier(body.idempotencyKey, "idempotencyKey"),
      expectedRevision: positiveInteger(body.expectedRevision, "expectedRevision"),
    };
  } catch (error) {
    return publicError(error);
  }
  let rawReceipt: unknown;
  try {
    rawReceipt = await authority.cancel(cancellation, request.signal);
  } catch {
    return problem(503, "platform_unavailable", "Platform authority is unavailable.");
  }
  let receipt: import("./authority.ts").PlatformCancelReceipt;
  try {
    receipt = admitCancelReceipt(rawReceipt);
  } catch {
    return problem(502, "platform_response_invalid", "Platform returned an invalid cancellation receipt.");
  }
  return json(receipt.outcome === "accepted" || receipt.outcome === "already_applied" ? 202 : 409, receipt);
}

async function boundedReady(authority: PlatformRunAuthority, signal: AbortSignal): Promise<boolean> {
  try {
    return await authority.ready(signal);
  } catch {
    return false;
  }
}

function sse(event: AGUIEvent, cursor: DeliveryCursor | null): Uint8Array {
  const id = cursor === null ? "" : `id: ${formatLastEventId(cursor)}\n`;
  return encoder.encode(`${id}data: ${JSON.stringify(event)}\n\n`);
}

async function boundedWrite(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  chunk: Uint8Array,
  timeoutMs: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      writer.write(chunk),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new SlowConsumerError()), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

interface DeliveryCursor {
  readonly nativeCursor: string;
  readonly projectionIndex: number;
}

function formatLastEventId(cursor: DeliveryCursor): string {
  return `v1:${encodeURIComponent(cursor.nativeCursor)}:${cursor.projectionIndex}`;
}

function admitLastEventId(value: string | null): DeliveryCursor | null {
  if (value === null) return null;
  const bytes = encoder.encode(value).byteLength;
  if (bytes === 0 || bytes > MAX_LAST_EVENT_ID_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new AdmissionError("invalid_cursor", "Last-Event-ID is outside the adapter cursor bound");
  }
  const match = /^v1:(.*):(0|[1-9][0-9]*)$/u.exec(value);
  if (match === null) throw new AdmissionError("invalid_cursor", "Last-Event-ID is not a canonical adapter cursor");
  const encodedCursor = match[1];
  const rawIndex = match[2];
  if (encodedCursor === undefined || rawIndex === undefined) throw new AdmissionError("invalid_cursor", "Last-Event-ID is incomplete");
  let nativeCursor: string;
  try {
    nativeCursor = decodeURIComponent(encodedCursor);
  } catch {
    throw new AdmissionError("invalid_cursor", "Last-Event-ID contains invalid cursor encoding");
  }
  if (encodeURIComponent(nativeCursor) !== encodedCursor) {
    throw new AdmissionError("invalid_cursor", "Last-Event-ID is not canonically encoded");
  }
  const projectionIndex = Number(rawIndex);
  if (!Number.isSafeInteger(projectionIndex) || projectionIndex < 0 || projectionIndex > MAX_PROJECTION_INDEX) {
    throw new AdmissionError("invalid_cursor", "Last-Event-ID projection is outside its bound");
  }
  const admitted = admitNativeCursor(nativeCursor);
  if (admitted === null) throw new AdmissionError("invalid_cursor", "Last-Event-ID has no native cursor");
  return {nativeCursor: admitted, projectionIndex};
}

function admitNativeCursor(value: string | null): string | null {
  if (value === null) return null;
  const bytes = encoder.encode(value).byteLength;
  if (bytes === 0 || bytes > MAX_NATIVE_CURSOR_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new AdmissionError("invalid_cursor", "native cursor is outside its bound");
  }
  return value;
}

async function readJson(request: Request, maxBytes: number): Promise<unknown> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maxBytes)) {
    throw new AdmissionError("request_too_large", "request exceeds its byte limit");
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) {
    throw new AdmissionError("request_too_large", "request exceeds its byte limit");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
  } catch {
    throw new AdmissionError("invalid_json", "request body is not canonical UTF-8 JSON");
  }
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new AdmissionError("invalid_input", "expected a plain object");
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((entry, index) => entry !== canonical[index])) {
    throw new AdmissionError("invalid_fields", "request fields do not match the cancellation contract");
  }
}

function cancelIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)) {
    throw new AdmissionError("invalid_identifier", `${field} is outside the identifier grammar`);
  }
  const bytes = encoder.encode(value).byteLength;
  if (bytes === 0 || bytes > MAX_CANCEL_IDENTIFIER_BYTES) {
    throw new AdmissionError("invalid_identifier", `${field} exceeds its bound`);
  }
  return value;
}

function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new AdmissionError("invalid_revision", `${field} must be a positive safe integer`);
  }
  return value;
}

function admitCancelReceipt(value: unknown): import("./authority.ts").PlatformCancelReceipt {
  const receipt = plainRecord(value);
  exactKeys(receipt, ["outcome", "receiptId"]);
  const receiptId = cancelIdentifier(receipt.receiptId, "receiptId");
  if (receipt.outcome !== "accepted" && receipt.outcome !== "already_applied" && receipt.outcome !== "conflict" && receipt.outcome !== "rejected") {
    throw new AdmissionError("invalid_receipt", "Platform returned an invalid cancellation outcome");
  }
  return {receiptId, outcome: receipt.outcome};
}

function mediaType(value: string | null, expected: string): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === expected;
}

function accepts(value: string | null, expected: string): boolean {
  return value?.split(",").some((entry) => entry.split(";", 1)[0]?.trim().toLowerCase() === expected) ?? false;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {"content-type": `${JSON_CONTENT_TYPE}; charset=utf-8`, "x-content-type-options": "nosniff"},
  });
}

function problem(status: number, code: string, message: string): Response {
  return json(status, {error: code, message});
}

function publicError(error: unknown): Response {
  if (error instanceof AdmissionError) return problem(400, error.code, error.message);
  return problem(400, "invalid_input", "Input was refused.");
}

class StreamDisconnected extends Error {}
class SlowConsumerError extends Error {}
class RuntimeStreamError extends Error {
  public constructor(public readonly code: string, message: string) {
    super(message);
  }
}
