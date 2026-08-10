// SPDX-License-Identifier: Apache-2.0

import {createConnection, type Socket} from "node:net";
import type {
  FrameChannel,
  FrameCloseReason,
  FrameConnector,
} from "./framed-transport.ts";

const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 1024 * 1024 + 4;
const DEFAULT_MAX_CHUNKS = 4096;
const ABSOLUTE_MAX_BYTES = 64 * 1024 * 1024 + 4;
const MAX_UNIX_PATH_BYTES = 100;

export interface BunUnixSocketConnectorOptions {
  readonly connectTimeoutMs?: number;
  readonly maxBufferedBytes?: number;
  readonly maxQueuedChunks?: number;
  readonly maxWriteBytes?: number;
}

export class BunUnixSocketError extends Error {
  override readonly name = "BunUnixSocketError";
}

function boundedPositive(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} must be a positive safe integer no greater than ${maximum}`);
  }
  return value;
}

function validatedSocketPath(value: string): string {
  const segments = value.split("/");
  if (
    value.length === 0
    || !value.startsWith("/")
    || /[\u0000-\u001f\u007f]/.test(value)
    || segments.slice(1).some((segment) => segment.length === 0 || segment === "." || segment === "..")
    || new TextEncoder().encode(value).byteLength > MAX_UNIX_PATH_BYTES
  ) {
    throw new TypeError("socketPath must be a bounded canonical absolute Unix socket path");
  }
  return value;
}

function abortError(): DOMException {
  return new DOMException("The Unix socket operation was aborted", "AbortError");
}

interface PendingRead {
  readonly resolve: (value: Uint8Array | null) => void;
  readonly reject: (error: Error) => void;
  readonly dispose: () => void;
}

interface PendingWrite {
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly dispose: () => void;
}

class BunUnixFrameChannel implements FrameChannel {
  private readonly chunks: Uint8Array[] = [];
  private bufferedBytes = 0;
  private ended = false;
  private closed = false;
  private wroteRequest = false;
  private failure: Error | undefined;
  private pendingRead: PendingRead | undefined;
  private pendingWrite: PendingWrite | undefined;

  constructor(
    private readonly socket: Socket,
    private readonly maxBufferedBytes: number,
    private readonly maxQueuedChunks: number,
    private readonly maxWriteBytes: number,
  ) {
    socket.on("data", (data) => this.receive(data));
    socket.on("end", () => this.finish());
    socket.on("close", () => this.finish());
    socket.on("error", (error) => this.fail(error));
  }

  private receive(data: Uint8Array): void {
    if (this.closed || this.ended || this.failure !== undefined || data.byteLength === 0) return;
    if (data.byteLength > this.maxBufferedBytes) {
      this.fail(new BunUnixSocketError("Unix socket response exceeded its buffer bound"));
      return;
    }
    const copy = data.slice();
    const pending = this.pendingRead;
    if (pending !== undefined) {
      this.pendingRead = undefined;
      pending.dispose();
      pending.resolve(copy);
      return;
    }
    if (
      this.chunks.length >= this.maxQueuedChunks
      || copy.byteLength > this.maxBufferedBytes - this.bufferedBytes
    ) {
      this.fail(new BunUnixSocketError("Unix socket response exceeded its buffer bound"));
      return;
    }
    this.chunks.push(copy);
    this.bufferedBytes += copy.byteLength;
  }

  private finish(): void {
    if (this.closed || this.failure !== undefined || this.ended) return;
    this.ended = true;
    const pending = this.pendingRead;
    if (pending !== undefined) {
      this.pendingRead = undefined;
      pending.dispose();
      pending.resolve(null);
    }
  }

  private fail(_cause: unknown): void {
    if (this.failure !== undefined || this.closed) return;
    this.failure = new BunUnixSocketError("Unix socket I/O failed");
    this.chunks.length = 0;
    this.bufferedBytes = 0;
    const read = this.pendingRead;
    if (read !== undefined) {
      this.pendingRead = undefined;
      read.dispose();
      read.reject(this.failure);
    }
    const write = this.pendingWrite;
    if (write !== undefined) {
      this.pendingWrite = undefined;
      write.dispose();
      write.reject(this.failure);
    }
    this.socket.destroy();
  }

  read(options?: {readonly signal?: AbortSignal}): Promise<Uint8Array | null> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    const chunk = this.chunks.shift();
    if (chunk !== undefined) {
      this.bufferedBytes -= chunk.byteLength;
      return Promise.resolve(chunk);
    }
    if (this.ended || this.closed) return Promise.resolve(null);
    if (this.pendingRead !== undefined) {
      return Promise.reject(new BunUnixSocketError("Concurrent Unix socket reads are not supported"));
    }
    const signal = options?.signal;
    if (signal?.aborted) return Promise.reject(abortError());
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        if (this.pendingRead === pending) this.pendingRead = undefined;
        pending.dispose();
        reject(abortError());
      };
      const pending: PendingRead = {
        resolve,
        reject,
        dispose: () => signal?.removeEventListener("abort", onAbort),
      };
      this.pendingRead = pending;
      signal?.addEventListener("abort", onAbort, {once: true});
    });
  }

  write(chunk: Uint8Array, options?: {readonly signal?: AbortSignal}): Promise<void> {
    if (chunk.byteLength === 0 || chunk.byteLength > this.maxWriteBytes) {
      return Promise.reject(new BunUnixSocketError("Unix socket request exceeded its write bound"));
    }
    if (this.closed || this.ended || this.wroteRequest || this.failure !== undefined) {
      return Promise.reject(this.failure ?? new BunUnixSocketError("Unix socket is not writable"));
    }
    if (this.pendingWrite !== undefined) {
      return Promise.reject(new BunUnixSocketError("Concurrent Unix socket writes are not supported"));
    }
    const signal = options?.signal;
    if (signal?.aborted) return Promise.reject(abortError());
    this.wroteRequest = true;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        if (this.pendingWrite === pending) this.pendingWrite = undefined;
        pending.dispose();
        reject(abortError());
      };
      const pending: PendingWrite = {
        resolve,
        reject,
        dispose: () => signal?.removeEventListener("abort", onAbort),
      };
      this.pendingWrite = pending;
      signal?.addEventListener("abort", onAbort, {once: true});
      this.socket.write(chunk.slice(), (error) => {
        if (this.pendingWrite !== pending) return;
        if (error !== undefined && error !== null) {
          this.fail(error);
          return;
        }
        this.pendingWrite = undefined;
        pending.dispose();
        pending.resolve();
      });
    });
  }

  close(_reason: FrameCloseReason): void {
    if (this.closed) return;
    this.closed = true;
    const error = abortError();
    const read = this.pendingRead;
    if (read !== undefined) {
      this.pendingRead = undefined;
      read.dispose();
      read.reject(error);
    }
    const write = this.pendingWrite;
    if (write !== undefined) {
      this.pendingWrite = undefined;
      write.dispose();
      write.reject(error);
    }
    this.socket.destroy();
  }
}

/** A local-only Bun connector. It accepts a Unix path, never a host, port, or credential. */
export class BunUnixSocketConnector implements FrameConnector {
  private readonly socketPath: string;
  private readonly connectTimeoutMs: number;
  private readonly maxBufferedBytes: number;
  private readonly maxQueuedChunks: number;
  private readonly maxWriteBytes: number;

  constructor(socketPath: string, options: BunUnixSocketConnectorOptions = {}) {
    this.socketPath = validatedSocketPath(socketPath);
    this.connectTimeoutMs = boundedPositive(options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS, "connectTimeoutMs", 60_000);
    this.maxBufferedBytes = boundedPositive(options.maxBufferedBytes ?? DEFAULT_MAX_BYTES, "maxBufferedBytes", ABSOLUTE_MAX_BYTES);
    this.maxQueuedChunks = boundedPositive(options.maxQueuedChunks ?? DEFAULT_MAX_CHUNKS, "maxQueuedChunks", 1_000_000);
    this.maxWriteBytes = boundedPositive(options.maxWriteBytes ?? DEFAULT_MAX_BYTES, "maxWriteBytes", ABSOLUTE_MAX_BYTES);
  }

  open(options?: {readonly signal?: AbortSignal}): Promise<FrameChannel> {
    const external = options?.signal;
    if (external?.aborted) return Promise.reject(abortError());
    return new Promise((resolve, reject) => {
      const socket = createConnection({path: this.socketPath, allowHalfOpen: true});
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        external?.removeEventListener("abort", onAbort);
        socket.removeListener("connect", onConnect);
        if (error === undefined) socket.removeListener("error", onError);
        if (error === undefined) {
          resolve(new BunUnixFrameChannel(socket, this.maxBufferedBytes, this.maxQueuedChunks, this.maxWriteBytes));
        } else {
          socket.destroy();
          reject(error);
        }
      };
      const onConnect = () => finish();
      const onError = () => finish(new BunUnixSocketError("Unix socket connection failed"));
      const onAbort = () => finish(abortError());
      const timer = setTimeout(
        () => finish(new BunUnixSocketError("Unix socket connect deadline exceeded")),
        this.connectTimeoutMs,
      );
      socket.once("connect", onConnect);
      socket.once("error", onError);
      external?.addEventListener("abort", onAbort, {once: true});
    });
  }
}
