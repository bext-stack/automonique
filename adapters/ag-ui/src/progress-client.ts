// SPDX-License-Identifier: Elastic-2.0

import {createConnection, type Socket} from "node:net";

const MAX_FRAME_BYTES = 41_216;
const MAX_BUFFER_BYTES = 128 * 1024;

export interface ProgressFrame {
  readonly at_ms: number;
  readonly authority: "authoritative" | "synthetic";
  readonly body: {
    readonly retry: null | {readonly retryable: boolean};
    readonly step: null | "pending" | "in_progress" | "completed" | "error";
    readonly text: string | null;
  };
  readonly kind: string;
  readonly run_id: string;
  readonly sequence: number;
}

type ProgressMessage =
  | {readonly kind: "greeting"; readonly body: {readonly capability: number}}
  | {readonly kind: "live"; readonly body: {readonly from: number}}
  | {readonly kind: "resync_required"; readonly body: {readonly snapshot_from: number; readonly snapshot_to: number}}
  | {readonly kind: "frame"; readonly body: ProgressFrame}
  | {readonly kind: "lagged" | "retired"; readonly body: {readonly delivered_through: number}}
  | {readonly kind: "refused"; readonly body: {readonly category: string}};

export class ProgressResyncRequired extends Error {
  constructor(readonly from: number, readonly to: number) {
    super("native progress replay is outside retention");
    this.name = "ProgressResyncRequired";
  }
}

/** One peer-authenticated, length-prefixed subscription to progress.sock. */
export async function* progressFrames(
  socketPath: string,
  runId: string,
  cursor = 0,
  signal?: AbortSignal,
  onLive?: () => void,
): AsyncIterable<ProgressFrame> {
  const channel = await ProgressChannel.connect(socketPath, signal);
  try {
    const greeting = await channel.message(signal);
    if (greeting.kind !== "greeting" || !Number.isSafeInteger(greeting.body.capability)) {
      throw new Error("progress greeting refused");
    }
    if (!Number.isSafeInteger(cursor) || cursor < 0) throw new Error("invalid progress cursor");
    await channel.write(frame(new TextEncoder().encode(JSON.stringify({cursor, run_id: runId}))), signal);
    const start = await channel.message(signal);
    if (start.kind === "resync_required") {
      throw new ProgressResyncRequired(start.body.snapshot_from, start.body.snapshot_to);
    }
    if (start.kind !== "live" || start.body.from !== cursor + 1) throw new Error("progress start refused");
    onLive?.();
    while (true) {
      const message = await channel.message(signal);
      if (message.kind === "frame") {
        validateFrame(message.body, runId);
        yield message.body;
        continue;
      }
      if (message.kind === "retired") return;
      if (message.kind === "lagged") {
        throw new ProgressResyncRequired(message.body.delivered_through, message.body.delivered_through);
      }
      throw new Error("progress stream refused");
    }
  } finally {
    channel.close();
  }
}

class ProgressChannel {
  private chunks = new Uint8Array();
  private readonly waiting: Array<() => void> = [];
  private ended = false;
  private failed = false;

  private constructor(private readonly socket: Socket) {
    socket.on("data", (chunk) => {
      if (this.failed || this.ended || chunk.byteLength === 0) return;
      if (this.chunks.byteLength + chunk.byteLength > MAX_BUFFER_BYTES) {
        this.fail();
        return;
      }
      const joined = new Uint8Array(this.chunks.byteLength + chunk.byteLength);
      joined.set(this.chunks);
      joined.set(chunk, this.chunks.byteLength);
      this.chunks = joined;
      this.wake();
    });
    socket.on("end", () => { this.ended = true; this.wake(); });
    socket.on("close", () => { this.ended = true; this.wake(); });
    socket.on("error", () => this.fail());
  }

  static connect(path: string, signal?: AbortSignal): Promise<ProgressChannel> {
    if (!path.startsWith("/") || path.includes("\0") || new TextEncoder().encode(path).byteLength > 100) {
      return Promise.reject(new Error("invalid progress socket path"));
    }
    if (signal?.aborted) return Promise.reject(new DOMException("aborted", "AbortError"));
    return new Promise((resolve, reject) => {
      const socket = createConnection({path, allowHalfOpen: true});
      const timer = setTimeout(() => finish(new Error("progress connect timeout")), 5_000);
      const onAbort = () => finish(new DOMException("aborted", "AbortError"));
      const onConnect = () => finish();
      const onError = () => finish(new Error("progress connection failed"));
      let done = false;
      const finish = (error?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        socket.removeListener("connect", onConnect);
        socket.removeListener("error", onError);
        if (error !== undefined) {
          socket.destroy();
          reject(error);
        } else {
          resolve(new ProgressChannel(socket));
        }
      };
      socket.once("connect", onConnect);
      socket.once("error", onError);
      signal?.addEventListener("abort", onAbort, {once: true});
    });
  }

  async message(signal?: AbortSignal): Promise<ProgressMessage> {
    while (true) {
      if (this.chunks.byteLength >= 4) {
        const view = new DataView(this.chunks.buffer, this.chunks.byteOffset, this.chunks.byteLength);
        const length = view.getUint32(0, false);
        if (length === 0 || length > MAX_FRAME_BYTES) throw new Error("progress frame bound refused");
        if (this.chunks.byteLength >= length + 4) {
          const payload = this.chunks.slice(4, length + 4);
          this.chunks = this.chunks.slice(length + 4);
          const value: unknown = JSON.parse(new TextDecoder().decode(payload));
          return validateMessage(value);
        }
      }
      if (this.failed || this.ended) throw new Error("progress stream ended unexpectedly");
      await this.wait(signal);
    }
  }

  write(bytes: Uint8Array, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(new DOMException("aborted", "AbortError"));
    return new Promise((resolve, reject) => {
      const onAbort = () => { this.socket.destroy(); reject(new DOMException("aborted", "AbortError")); };
      signal?.addEventListener("abort", onAbort, {once: true});
      this.socket.write(bytes, (error) => {
        signal?.removeEventListener("abort", onAbort);
        if (error) reject(new Error("progress write failed")); else resolve();
      });
    });
  }

  close(): void { this.socket.destroy(); }
  private fail(): void { this.failed = true; this.socket.destroy(); this.wake(); }
  private wake(): void { for (const wake of this.waiting.splice(0)) wake(); }
  private wait(signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const onAbort = () => { cleanup(); reject(new DOMException("aborted", "AbortError")); };
      const wake = () => { cleanup(); resolve(); };
      const cleanup = () => {
        signal?.removeEventListener("abort", onAbort);
        const index = this.waiting.indexOf(wake);
        if (index >= 0) this.waiting.splice(index, 1);
      };
      this.waiting.push(wake);
      signal?.addEventListener("abort", onAbort, {once: true});
    });
  }
}

function frame(payload: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(payload.byteLength + 4);
  new DataView(bytes.buffer).setUint32(0, payload.byteLength, false);
  bytes.set(payload, 4);
  return bytes;
}

function validateMessage(value: unknown): ProgressMessage {
  if (!plain(value) || typeof value.kind !== "string" || !plain(value.body)) throw new Error("invalid progress message");
  return value as ProgressMessage;
}

function validateFrame(value: ProgressFrame, runId: string): void {
  if (!plain(value) || value.run_id !== runId || !Number.isSafeInteger(value.sequence) || value.sequence < 1
    || !Number.isSafeInteger(value.at_ms) || typeof value.kind !== "string" || !plain(value.body)) {
    throw new Error("invalid progress frame");
  }
}

function plain(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
