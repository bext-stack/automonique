// SPDX-License-Identifier: Apache-2.0

import type {LabTransport} from "./client.ts";
import {validateLabRequest, type LabRequest} from "./protocol.ts";

export type FrameCloseReason = "complete" | "aborted" | "protocol_error";

export interface FrameChannel {
  write(chunk: Uint8Array, options?: {readonly signal?: AbortSignal}): Promise<void>;
  read(options?: {readonly signal?: AbortSignal}): Promise<Uint8Array | null>;
  close(reason: FrameCloseReason): void | Promise<void>;
}

export interface FrameConnector {
  open(options?: {readonly signal?: AbortSignal}): Promise<FrameChannel>;
}

export interface FramedTransportOptions {
  readonly maxFrameBytes?: number;
  readonly maxChunks?: number;
  readonly timeoutMs?: number;
}

export class FrameProtocolError extends Error {
  override readonly name = "FrameProtocolError";
}

export class FrameTimeoutError extends Error {
  override readonly name = "FrameTimeoutError";
}

const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024;
const ABSOLUTE_MAX_FRAME_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_CHUNKS = 4096;

function boundedPositive(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} must be a positive safe integer no greater than ${maximum}`);
  }
  return value;
}

function canonicalJson(value: unknown, ancestors = new Set<object>()): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new TypeError("canonical JSON rejects unsupported values");
  }
  if (ancestors.has(value)) throw new TypeError("canonical JSON rejects cycles");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalJson(entry, ancestors)).join(",")}]`;
    }
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], ancestors)}`).join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function encodeFrame(value: unknown, maximum: number): Uint8Array {
  const payload = new TextEncoder().encode(canonicalJson(value));
  if (payload.byteLength === 0 || payload.byteLength > maximum) {
    throw new FrameProtocolError(`request frame length ${payload.byteLength} exceeds the configured bound`);
  }
  const frame = new Uint8Array(4 + payload.byteLength);
  new DataView(frame.buffer).setUint32(0, payload.byteLength, false);
  frame.set(payload, 4);
  return frame;
}

function append(left: Uint8Array, right: Uint8Array): Uint8Array {
  const joined = new Uint8Array(left.byteLength + right.byteLength);
  joined.set(left); joined.set(right, left.byteLength);
  return joined;
}

function abortedError(): DOMException {
  return new DOMException("The framed request was aborted", "AbortError");
}

function operationSignal(external: AbortSignal | undefined, timeoutMs: number | undefined) {
  const controller = new AbortController();
  const onAbort = () => controller.abort(abortedError());
  if (external?.aborted) onAbort();
  else external?.addEventListener("abort", onAbort, {once: true});
  const timer = timeoutMs === undefined ? undefined : setTimeout(
    () => controller.abort(new FrameTimeoutError(`framed request exceeded ${timeoutMs}ms`)),
    timeoutMs,
  );
  return {
    signal: controller.signal,
    dispose() {
      external?.removeEventListener("abort", onAbort);
      if (timer !== undefined) clearTimeout(timer);
    },
  };
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof FrameTimeoutError ? signal.reason : abortedError();
}

function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(abortReason(signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, {once: true});
    operation.then(
      (value) => { signal.removeEventListener("abort", onAbort); resolve(value); },
      (error: unknown) => { signal.removeEventListener("abort", onAbort); reject(error); },
    );
  });
}

async function decodeOneFrame(
  channel: FrameChannel,
  signal: AbortSignal,
  maximum: number,
  maxChunks: number,
): Promise<unknown> {
  let buffer: Uint8Array = new Uint8Array();
  let expected: number | undefined;
  let decoded: unknown;
  let complete = false;
  for (let chunks = 0; chunks < maxChunks; chunks += 1) {
    const chunk = await abortable(channel.read({signal}), signal);
    if (chunk === null) {
      if (!complete) {
        const part = expected === undefined ? "prefix" : "payload";
        throw new FrameProtocolError(`response ended with a partial ${part}`);
      }
      return decoded;
    }
    if (!(chunk instanceof Uint8Array)) throw new FrameProtocolError("channel returned a non-byte chunk");
    if (complete && chunk.byteLength > 0) throw new FrameProtocolError("response contains trailing data or a second frame");
    if (chunk.byteLength === 0) continue;
    buffer = append(buffer, chunk);
    if (expected === undefined && buffer.byteLength >= 4) {
      expected = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(0, false);
      if (expected === 0 || expected > maximum) throw new FrameProtocolError(`response frame length ${expected} exceeds the configured bound`);
      buffer = buffer.slice(4);
    }
    if (expected !== undefined) {
      if (buffer.byteLength > expected) throw new FrameProtocolError("response contains trailing data or a second frame");
      if (buffer.byteLength === expected) {
        let body: string;
        try { body = new TextDecoder("utf-8", {fatal: true}).decode(buffer); }
        catch { throw new FrameProtocolError("response payload is not valid UTF-8"); }
        try { decoded = JSON.parse(body) as unknown; }
        catch { throw new FrameProtocolError("response payload is not valid JSON"); }
        complete = true;
        buffer = new Uint8Array();
      }
    }
  }
  throw new FrameProtocolError(`response exceeded the ${maxChunks}-chunk bound`);
}

export class FramedLabTransport implements LabTransport {
  private readonly maxFrameBytes: number;
  private readonly maxChunks: number;
  private readonly timeoutMs: number | undefined;

  constructor(private readonly connector: FrameConnector, options: FramedTransportOptions = {}) {
    this.maxFrameBytes = boundedPositive(options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES, "maxFrameBytes", ABSOLUTE_MAX_FRAME_BYTES);
    this.maxChunks = boundedPositive(options.maxChunks ?? DEFAULT_MAX_CHUNKS, "maxChunks", 1_000_000);
    this.timeoutMs = options.timeoutMs === undefined ? undefined : boundedPositive(options.timeoutMs, "timeoutMs", 86_400_000);
  }

  async request(request: LabRequest, options?: {readonly signal?: AbortSignal}): Promise<unknown> {
    validateLabRequest(request);
    const frame = encodeFrame(request, this.maxFrameBytes);
    const operation = operationSignal(options?.signal, this.timeoutMs);
    let channel: FrameChannel | undefined;
    let closeReason: FrameCloseReason = "protocol_error";
    try {
      const opening = this.connector.open({signal: operation.signal});
      void opening.then(
        (opened) => { if (operation.signal.aborted && channel === undefined) void opened.close("aborted"); },
        () => undefined,
      );
      channel = await abortable(opening, operation.signal);
      await abortable(channel.write(frame, {signal: operation.signal}), operation.signal);
      const response = await decodeOneFrame(channel, operation.signal, this.maxFrameBytes, this.maxChunks);
      closeReason = "complete";
      return response;
    } catch (error) {
      if (operation.signal.aborted) closeReason = "aborted";
      throw error;
    } finally {
      operation.dispose();
      if (channel !== undefined) await channel.close(closeReason);
    }
  }
}
