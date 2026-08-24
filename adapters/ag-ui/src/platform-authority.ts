// SPDX-License-Identifier: Elastic-2.0

import {createHash} from "node:crypto";
import {createConnection} from "node:net";
import type {AdmittedRunInput} from "./admission.ts";
import type {
  PlatformCancelReceipt,
  PlatformCancelRequest,
  PlatformOpenRequest,
  PlatformOpenResult,
  PlatformRunAuthority,
} from "./authority.ts";
import {NATIVE_ADAPTER_SCHEMA, type NativeAdapterEvent} from "./contract.ts";
import {ProgressResyncRequired, progressFrames, type ProgressFrame} from "./progress-client.ts";

const PLATFORM_MEDIA_TYPE = "application/vnd.automonique.platform.v1+json";
const TERMINAL_POLL_MS = 50;
const TERMINAL_POLLS = 2_400;
const NATIVE_SEQUENCE_STRIDE = 8;
const MAX_REMEMBERED_RUNS = 4_096;
const MAX_PLATFORM_RESPONSE_BYTES = 512 * 1024;

export interface ProductionAuthorityConfig {
  readonly platformEndpoint?: string;
  readonly platformToken?: () => string | Promise<string>;
  readonly platformSocket?: string;
  readonly progressSocket: string;
  readonly nodeId: string;
  readonly fetcher?: typeof fetch;
}

interface Coordinate {readonly authority: string; readonly id: string; readonly kind: string}
interface Receipt {
  readonly id: string;
  readonly outcome: string;
  readonly explanation: string | null;
  readonly revision: number;
}

/** Production projection over canonical Platform v1 plus the native progress socket. */
export class ProductionPlatformAuthority implements PlatformRunAuthority {
  private readonly platform: CanonicalPlatformClient;
  private readonly nativeRuns = new Map<string, string>();

  constructor(private readonly config: ProductionAuthorityConfig) {
    this.platform = new CanonicalPlatformClient(config);
  }

  async ready(signal?: AbortSignal): Promise<boolean> {
    try {
      const response = await this.platform.request("capabilities", {}, signal);
      return response.kind === "capabilities_result"
        && response.body.protocol === "automonique.platform"
        && response.body.schema === "automonique.platform/v1";
    } catch {
      return false;
    }
  }

  async open(request: PlatformOpenRequest, signal?: AbortSignal): Promise<PlatformOpenResult> {
    const resuming = request.input.resume.length !== 0;
    const nativeRunId = resuming
      ? nativeRunIdFor(request.input.parentRunId!)
      : nativeRunIdFor(request.input.runId);
    this.rememberRun(request.input.runId, nativeRunId);
    const requested = cursorCoordinate(request.cursor, nativeRunId);
    const requestedSequence = requested.nativeSequence;
    let subscription: ProgressSubscription;
    try {
      subscription = await subscribeProgress(this.config.progressSocket, nativeRunId, 0, signal);
    } catch (error) {
      if (!(error instanceof ProgressResyncRequired)) throw error;
      if (request.cursor === null || error.from < 1 || requested.progressSequence < error.from) {
        return {kind: "resync_required", cursor: nativeCursor(nativeRunId, error.to)};
      }
      try {
        subscription = await subscribeProgress(this.config.progressSocket, nativeRunId, error.from - 1, signal);
      } catch (retryError) {
        if (retryError instanceof ProgressResyncRequired) {
          return {kind: "resync_required", cursor: nativeCursor(nativeRunId, retryError.to)};
        }
        throw retryError;
      }
    }
    const stream = subscription.stream;
    const replay: NativeAdapterEvent[] = [];
    let first: IteratorResult<ProgressFrame>;
    const firstFrame = subscription.firstFrame;
    let submissionError: unknown;
    const execute = (resuming
      ? this.resolveInterrupts(request.input, signal).then(() => null)
      : this.submit(request.input, signal)).catch((error: unknown) => {
          submissionError = error;
          return null;
        });
    const terminalAbort = new AbortController();
    const terminalSignal = signal === undefined
      ? terminalAbort.signal
      : AbortSignal.any([signal, terminalAbort.signal]);
    const terminal = execute.then((accepted) => accepted === null
      ? null
      : this.terminalReceipt(executionKey(request.input.runId), accepted, terminalSignal))
      .catch((error: unknown) => {
        if (terminalAbort.signal.aborted) return null;
        throw error;
      });
    const executionFailure = execute.then<IteratorResult<ProgressFrame>>(() => {
      if (submissionError !== undefined) throw submissionError;
      return new Promise<IteratorResult<ProgressFrame>>(() => {});
    });
    const noProgressTerminal = resuming || request.cursor !== null
      ? new Promise<IteratorResult<ProgressFrame>>(() => {})
      : terminal.then(async (): Promise<IteratorResult<ProgressFrame>> => {
          await delay(100, signal);
          return {done: true, value: undefined};
        });
    try {
      first = await Promise.race([firstFrame, executionFailure, noProgressTerminal]);
    } catch (error) {
      if (error instanceof ProgressResyncRequired) {
        return {kind: "resync_required", cursor: nativeCursor(nativeRunId, error.to)};
      }
      throw error;
    }
    if (first.done && request.cursor !== null) {
      terminalAbort.abort();
      return {kind: "resync_required", cursor: nativeCursor(nativeRunId, 0)};
    }

    const events = this.events(request.input, nativeRunId, requestedSequence, first, stream, terminal, replay, () => submissionError, resuming, () => terminalAbort.abort(), signal);
    try {
      await events.prime();
    } catch (error) {
      if (error instanceof ProgressResyncRequired) {
        return {kind: "resync_required", cursor: nativeCursor(nativeRunId, error.to)};
      }
      throw error;
    }
    return {kind: "stream", replay, events};
  }

  async cancel(request: PlatformCancelRequest, signal?: AbortSignal): Promise<PlatformCancelReceipt> {
    const response = await this.platform.request("execute", {
      action: "stop_run",
      expected_revision: request.expectedRevision,
      idempotency_key: request.idempotencyKey,
      parameter: null,
      target: {authority: "automonique", id: this.nativeRuns.get(request.runId) ?? nativeRunIdFor(request.runId), kind: "run"},
    }, signal);
    if (response.kind === "refused") return {receiptId: "refused", outcome: response.body.outcome === "conflict" ? "conflict" : "rejected"};
    const receipt = receiptBody(response);
    return {
      receiptId: receipt.id,
      outcome: receipt.outcome === "accepted" ? "accepted"
        : receipt.outcome === "completed" ? "already_applied"
          : receipt.outcome === "conflict" ? "conflict" : "rejected",
    };
  }

  private async submit(input: AdmittedRunInput, signal?: AbortSignal): Promise<Receipt> {
    const target = input.parentRunId === undefined
      ? await this.nodeTarget(signal)
      : await this.sessionTarget(input.parentRunId, signal);
    const response = await this.platform.request("execute", {
      action: input.parentRunId === undefined ? "submit_request" : "follow_up",
      expected_revision: target.revision,
      idempotency_key: executionKey(input.runId),
      parameter: input.prompt ?? null,
      target: target.coordinate,
    }, signal);
    return receiptBody(response);
  }

  private async nodeTarget(signal?: AbortSignal): Promise<{coordinate: Coordinate; revision: number | null}> {
    const response = await this.platform.request("snapshot", {resources: [
      {authority: "automonique", id: this.config.nodeId, kind: "node"},
    ]}, signal);
    if (response.kind !== "snapshot_result" || !Array.isArray(response.body.resources)) throw new Error("platform node snapshot unavailable");
    const records = response.body.resources.filter((value): value is Record<string, unknown> => plain(value))
      .filter((record) => plain(record.resource)
        && ["ai_operations", "automonique"].includes(String(record.resource.authority))
        && record.resource.kind === "node")
      .sort((left, right) => observed(right) - observed(left));
    const record = records[0];
    if (record === undefined || !plain(record.resource) || !plain(record.freshness)) throw new Error("platform node unavailable");
    const projected = coordinate(record.resource);
    return {coordinate: {...projected, authority: "automonique"}, revision: null};
  }

  private async sessionTarget(parentRunId: string, signal?: AbortSignal): Promise<{coordinate: Coordinate; revision: number | null}> {
    const response = await this.platform.request("list_sessions", {authority: "automonique", cursor: null}, signal);
    if (response.kind !== "sessions_result" || !Array.isArray(response.body.sessions)) throw new Error("platform sessions unavailable");
    const nativeParent = nativeRunIdFor(parentRunId);
    for (const candidate of response.body.sessions) {
      if (!plain(candidate) || !plain(candidate.run) || candidate.run.id !== nativeParent || !plain(candidate.session)) continue;
      const sessionRecord = candidate.session;
      if (!plain(sessionRecord.resource) || !plain(sessionRecord.freshness)) continue;
      return {coordinate: coordinate(sessionRecord.resource), revision: positive(sessionRecord.freshness.revision)};
    }
    throw new Error("parent session is not resumable");
  }

  private async resolveInterrupts(input: AdmittedRunInput, signal?: AbortSignal): Promise<void> {
    for (const decision of input.resume) {
      const payload = decision.payload;
      const approved = decision.status === "resolved"
        && plain(payload)
        && (payload as Record<string, unknown>).approved === true;
      const response = await this.platform.request("execute", {
        action: "decide_approval",
        expected_revision: null,
        idempotency_key: decisionKey(input.runId, decision.interruptId),
        parameter: approved ? "grant" : "deny",
        target: {authority: "automonique", id: decision.interruptId, kind: "approval"},
      }, signal);
      const receipt = receiptBody(response);
      if (!["accepted", "completed"].includes(receipt.outcome)) throw new Error("approval decision refused");
    }
  }

  private events(
    input: AdmittedRunInput,
    nativeRunId: string,
    requestedSequence: number,
    first: IteratorResult<ProgressFrame>,
    stream: AsyncIterator<ProgressFrame>,
    terminal: Promise<Receipt | null>,
    replay: NativeAdapterEvent[],
    submissionError: () => unknown,
    resuming: boolean,
    stopTerminal: () => void,
    signal?: AbortSignal,
  ): PrimedIterable<NativeAdapterEvent> {
    let initial = first;
    const source = async function* (owner: ProductionPlatformAuthority): AsyncIterable<NativeAdapterEvent> {
      let started = false;
      let assistant = "";
      let messageCompleted = false;
      let deltaMode: "unknown" | "snapshot" | "fragment" = "unknown";
      let lastProgressSequence = 0;
      let currentTool: {id: string; name: string} | null = null;
      let refusalCode: "internal_failure" | "policy_refused" | null = null;
      const resumeMarkers = new Set(input.resume.map((decision) => decision.interruptId));
      let resumeStarted = !resuming;
      while (!initial.done) {
        const frame = initial.value;
        lastProgressSequence = frame.sequence;
        if (!resumeStarted) {
          const marker = approvalId(frame);
          if (marker !== null) resumeMarkers.delete(marker);
          if (resumeMarkers.size !== 0) {
            initial = await stream.next();
            continue;
          }
          resumeStarted = true;
          started = true;
          const event = base(input, nativeRunId, frame.sequence, 1, frame.at_ms, {
            kind: "run_started",
            parentRunId: input.parentRunId!,
          });
          if (event.sequence <= requestedSequence) replay.push(event); else yield event;
          initial = await stream.next();
          continue;
        }
        const projected = await owner.project(frame, input, {started, assistant, messageCompleted, deltaMode, currentTool, refusalCode}, signal);
        if (!started && projected.events.length !== 0 && frame.kind !== "turn_started") {
          const event = base(input, nativeRunId, frame.sequence, 1, frame.at_ms, {
            kind: "run_started",
            ...(input.parentRunId ? {parentRunId: input.parentRunId} : {}),
          });
          if (event.sequence <= requestedSequence) replay.push(event); else yield event;
          started = true;
        }
        started = projected.started || started;
        assistant = projected.assistant;
        messageCompleted = projected.messageCompleted;
        deltaMode = projected.deltaMode;
        currentTool = projected.currentTool;
        refusalCode = projected.refusalCode;
        for (const event of projected.events) {
          if (event.sequence <= requestedSequence) replay.push(event); else yield event;
        }
        if (projected.interrupted) {
          stopTerminal();
          return;
        }
        initial = await stream.next();
      }
      const receipt = await terminal;
      if (submissionError() !== undefined) throw submissionError();
      if (!started) {
        const event = base(input, nativeRunId, lastProgressSequence, 1, Date.now(), {kind: "run_started", ...(input.parentRunId ? {parentRunId: input.parentRunId} : {})});
        if (event.sequence <= requestedSequence) replay.push(event); else yield event;
      }
      const terminalEvent = refusalCode !== null
        ? {kind: "run_refused" as const, code: refusalCode}
        : receipt === null || receipt.outcome === "completed"
          ? {kind: "run_finished" as const}
          : {kind: "run_refused" as const, code: "policy_refused" as const};
      const event = base(input, nativeRunId, lastProgressSequence, 7, Date.now(), terminalEvent);
      if (event.sequence <= requestedSequence) replay.push(event); else yield event;
    };
    return new PrimedIterable(source(this));
  }

  private async project(
    frame: ProgressFrame,
    input: AdmittedRunInput,
    state: ProjectionState,
    signal?: AbortSignal,
  ): Promise<ProjectedFrame> {
    const approval = approvalId(frame);
    const approvalRecord = approval === null ? null : await this.approval(approval, signal);
    return project(frame, input, state, approvalRecord);
  }

  private async approval(id: string, signal?: AbortSignal): Promise<{id: string; revision: number; summary: string}> {
    const response = await this.platform.request("snapshot", {resources: [
      {authority: "automonique", id, kind: "approval"},
    ]}, signal);
    if (response.kind !== "snapshot_result" || !Array.isArray(response.body.resources)) throw new Error("platform approval snapshot unavailable");
    for (const candidate of response.body.resources) {
      if (!plain(candidate) || !plain(candidate.resource) || !plain(candidate.freshness)) continue;
      if (candidate.resource.authority !== "automonique" || candidate.resource.kind !== "approval" || candidate.resource.id !== id) continue;
      if (candidate.freshness.state !== "fresh" || typeof candidate.summary !== "string") break;
      return {id, revision: positive(candidate.freshness.revision), summary: candidate.summary};
    }
    throw new Error("platform approval is not pending");
  }

  private rememberRun(publicRunId: string, nativeRunId: string): void {
    this.nativeRuns.delete(publicRunId);
    this.nativeRuns.set(publicRunId, nativeRunId);
    while (this.nativeRuns.size > MAX_REMEMBERED_RUNS) {
      const oldest = this.nativeRuns.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.nativeRuns.delete(oldest);
    }
  }

  private async terminalReceipt(key: string, initial: Receipt, signal?: AbortSignal): Promise<Receipt> {
    let receipt = initial;
    for (let count = 0; count < TERMINAL_POLLS && receipt.outcome === "accepted"; count += 1) {
      await delay(TERMINAL_POLL_MS, signal);
      receipt = receiptBody(await this.platform.request("get_receipt", {id: null, idempotency_key: key}, signal));
    }
    if (receipt.outcome === "accepted") throw new Error("platform receipt deadline exceeded");
    return receipt;
  }
}

class PrimedIterable<T> implements AsyncIterable<T> {
  private readonly iterator: AsyncIterator<T>;
  private primed: IteratorResult<T> | undefined;
  constructor(iterable: AsyncIterable<T>) { this.iterator = iterable[Symbol.asyncIterator](); }
  async prime(): Promise<void> { this.primed = await this.iterator.next(); }
  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    if (this.primed !== undefined) {
      const value = this.primed;
      this.primed = undefined;
      if (!value.done) yield value.value;
    }
    while (true) { const next = await this.iterator.next(); if (next.done) return; yield next.value; }
  }
}

class CanonicalPlatformClient {
  private counter = 0;
  private readonly fetcher: typeof fetch;
  private readonly endpoint: string | undefined;
  private readonly token: (() => string | Promise<string>) | undefined;
  private readonly socket: string | undefined;
  constructor(config: ProductionAuthorityConfig) {
    if ((config.platformEndpoint === undefined) === (config.platformSocket === undefined)) throw new Error("exactly one canonical Platform transport is required");
    if (config.platformEndpoint !== undefined) {
      const url = new URL(config.platformEndpoint);
      if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname))) throw new Error("canonical Platform endpoint requires HTTPS");
      if (config.platformToken === undefined) throw new Error("canonical HTTPS Platform token is required");
    } else if (!validSocketPath(config.platformSocket!)) {
      throw new Error("canonical Platform socket path is invalid");
    }
    this.endpoint = config.platformEndpoint;
    this.token = config.platformToken;
    this.socket = config.platformSocket;
    this.fetcher = config.fetcher ?? fetch;
  }
  async request(kind: string, body: Record<string, unknown>, signal?: AbortSignal): Promise<{kind: string; body: Record<string, unknown>}> {
    this.counter += 1;
    const requestId = `agui-${Date.now()}-${this.counter}`;
    const payload = canonical({body, kind, protocol: "automonique.platform", request_id: requestId, version: 1});
    const text = this.socket === undefined
      ? await this.https(payload, signal)
      : await unixPlatformRequest(this.socket, payload, signal);
    const value: unknown = JSON.parse(text);
    if (!plain(value) || value.protocol !== "automonique.platform" || value.request_id !== requestId || value.version !== 1
      || typeof value.kind !== "string" || !plain(value.body)) throw new Error("invalid canonical Platform response");
    return {kind: value.kind, body: value.body};
  }

  private async https(payload: string, signal?: AbortSignal): Promise<string> {
    const response = await this.fetcher(this.endpoint!, {
      method: "POST",
      headers: {accept: PLATFORM_MEDIA_TYPE, authorization: `Bearer ${await this.token!()}`, "content-type": PLATFORM_MEDIA_TYPE},
      body: payload,
      ...(signal === undefined ? {} : {signal}),
    });
    if (!response.ok) throw new Error("canonical Platform request refused");
    return response.text();
  }
}

function unixPlatformRequest(path: string, payload: string, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted) return Promise.reject(new DOMException("aborted", "AbortError"));
  const encoded = new TextEncoder().encode(payload);
  if (encoded.byteLength === 0 || encoded.byteLength > 64 * 1024) return Promise.reject(new Error("canonical Platform request is outside bounds"));
  const request = new Uint8Array(encoded.byteLength + 4);
  new DataView(request.buffer).setUint32(0, encoded.byteLength, false);
  request.set(encoded, 4);
  return new Promise((resolve, reject) => {
    const socket = createConnection({path, allowHalfOpen: true});
    let chunks = new Uint8Array();
    let done = false;
    const timer = setTimeout(() => finish(undefined, new Error("canonical Platform request timed out")), 10_000);
    const onAbort = () => finish(undefined, new DOMException("aborted", "AbortError"));
    const finish = (value?: string, error?: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
      if (error !== undefined) reject(error); else resolve(value!);
    };
    socket.once("connect", () => {
      socket.write(request, (error) => { if (error) finish(undefined, new Error("canonical Platform write failed")); });
    });
    socket.on("data", (chunk) => {
      if (done || chunk.byteLength === 0) return;
      if (chunks.byteLength + chunk.byteLength > MAX_PLATFORM_RESPONSE_BYTES + 4) return finish(undefined, new Error("canonical Platform response is outside bounds"));
      const joined = new Uint8Array(chunks.byteLength + chunk.byteLength);
      joined.set(chunks); joined.set(chunk, chunks.byteLength); chunks = joined;
      if (chunks.byteLength < 4) return;
      const length = new DataView(chunks.buffer, chunks.byteOffset, chunks.byteLength).getUint32(0, false);
      if (length === 0 || length > MAX_PLATFORM_RESPONSE_BYTES) return finish(undefined, new Error("canonical Platform response is outside bounds"));
      if (chunks.byteLength < length + 4) return;
      if (chunks.byteLength !== length + 4) return finish(undefined, new Error("canonical Platform response has trailing bytes"));
      finish(new TextDecoder().decode(chunks.slice(4)));
    });
    socket.on("end", () => finish(undefined, new Error("canonical Platform response ended early")));
    socket.on("close", () => finish(undefined, new Error("canonical Platform response ended early")));
    socket.on("error", () => finish(undefined, new Error("canonical Platform connection failed")));
    signal?.addEventListener("abort", onAbort, {once: true});
  });
}

function validSocketPath(path: string): boolean {
  return path.startsWith("/") && !path.includes("\0") && new TextEncoder().encode(path).byteLength <= 100;
}

interface ProjectionState {
  readonly started: boolean;
  readonly assistant: string;
  readonly messageCompleted: boolean;
  readonly deltaMode: "unknown" | "snapshot" | "fragment";
  readonly currentTool: {id: string; name: string} | null;
  readonly refusalCode: "internal_failure" | "policy_refused" | null;
}
interface ProjectedFrame extends ProjectionState {readonly events: NativeAdapterEvent[]; readonly interrupted: boolean}

function project(
  frame: ProgressFrame,
  input: AdmittedRunInput,
  state: ProjectionState,
  approval: {id: string; revision: number; summary: string} | null,
): ProjectedFrame {
  const events: NativeAdapterEvent[] = [];
  const offset = !state.started && frame.kind !== "turn_started" ? 1 : 0;
  const make = (event: any) => base(input, frame.run_id, frame.sequence, events.length + offset + 1, frame.at_ms, event);
  let {started, assistant, messageCompleted, deltaMode, currentTool, refusalCode} = state;
  let interrupted = false;
  if (frame.kind === "turn_started") { events.push(make({kind: "run_started", ...(input.parentRunId ? {parentRunId: input.parentRunId} : {})})); started = true; }
  else if (frame.kind === "assistant_message_delta" && frame.body.text !== null) {
    if (deltaMode === "unknown" && assistant.length !== 0) deltaMode = frame.body.text.startsWith(assistant) ? "snapshot" : "fragment";
    if (deltaMode === "fragment") assistant += frame.body.text; else assistant = frame.body.text;
    events.push(make({kind: "assistant_message_preview", messageId: `assistant-${input.runId}`, text: deltaMode === "fragment" ? frame.body.text : assistant, replace: deltaMode !== "fragment"}));
  }
  else if (frame.kind === "assistant_message_completed" && frame.body.text !== null) { assistant = frame.body.text; messageCompleted = true; events.push(make({kind: "assistant_message_completed", messageId: `assistant-${input.runId}`, text: assistant})); }
  else if (frame.kind === "turn_completed" && assistant.length !== 0 && !messageCompleted) { messageCompleted = true; events.push(make({kind: "assistant_message_completed", messageId: `assistant-${input.runId}`, text: assistant})); }
  else if (frame.kind === "tool_call_started") { const name = frame.body.text ?? "tool"; currentTool = {id: toolId(input.runId, name), name}; events.push(make({kind: "tool_call_started", toolCallId: currentTool.id, toolName: name})); }
  else if (frame.kind === "tool_call_updated" && currentTool !== null && frame.body.text !== null) { events.push(make({kind: "tool_call_args", toolCallId: currentTool.id, delta: JSON.stringify({progress: frame.body.text})})); }
  else if (frame.kind === "tool_call_completed" && currentTool !== null) {
    events.push(make({kind: "tool_call_ended", toolCallId: currentTool.id}));
    if (frame.body.text !== null) events.push(make({kind: "tool_call_result", toolCallId: currentTool.id, resultMessageId: `result-${currentTool.id}`, content: frame.body.text}));
    currentTool = null;
  }
  else if (frame.kind === "subagent_started" && frame.body.text !== null) events.push(make({kind: "step_started", stepName: frame.body.text}));
  else if (frame.kind === "subagent_completed" && frame.body.text !== null) events.push(make({kind: "step_finished", stepName: frame.body.text}));
  else if (frame.kind === "approval_requested" && approval !== null) {
    const proposedTool = currentTool;
    if (proposedTool !== null) {
      events.push(make({kind: "tool_call_ended", toolCallId: proposedTool.id}));
      currentTool = null;
    }
    events.push(make({kind: "state_snapshot", snapshot: {automonique: {approvalId: approval.id, status: "pending"}}}));
    const messages: Array<{id: string; role: "user" | "assistant"; content: string}> = [];
    if (input.prompt !== undefined) messages.push({id: `user-${input.runId}`, role: "user", content: input.prompt});
    if (assistant.length !== 0) messages.push({id: `assistant-${input.runId}`, role: "assistant", content: assistant});
    events.push(make({kind: "messages_snapshot", messages}));
    events.push(make({
      kind: "approval_requested",
      approvalId: approval.id,
      reason: "tool_approval_required",
      expectedRevision: approval.revision,
      message: frame.body.text ?? approval.summary,
      ...(proposedTool === null ? {} : {toolCallId: proposedTool.id}),
      responseSchema: {type: "object", properties: {approved: {type: "boolean"}}, required: ["approved"]},
    }));
    interrupted = true;
  }
  else if (frame.kind === "provider_fault") refusalCode = frame.body.retry?.retryable ? "internal_failure" : "policy_refused";
  return {events, started, assistant, messageCompleted, deltaMode, currentTool, refusalCode, interrupted};
}

function base(input: AdmittedRunInput, nativeRunId: string, progressSequence: number, ordinal: number, timestamp: number, event: any): NativeAdapterEvent {
  const sequence = nativeSequence(progressSequence, ordinal);
  return {schema: NATIVE_ADAPTER_SCHEMA, sequence, cursor: nativeCursor(nativeRunId, progressSequence, ordinal), timestamp, threadId: input.threadId, runId: input.runId, ...event} as NativeAdapterEvent;
}
function nativeSequence(progressSequence: number, ordinal: number): number {
  const sequence = progressSequence * NATIVE_SEQUENCE_STRIDE + ordinal;
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal >= NATIVE_SEQUENCE_STRIDE) throw new Error("native sequence is outside bounds");
  return sequence;
}
function nativeCursor(runId: string, progressSequence: number, ordinal = 7): string { return `${runId}:${progressSequence}:${ordinal}`; }
function cursorCoordinate(cursor: string | null, runId: string): {nativeSequence: number; progressSequence: number} {
  if (cursor === null) return {nativeSequence: 0, progressSequence: 0};
  const prefix = `${runId}:`; if (!cursor.startsWith(prefix)) throw new Error("cursor does not belong to this run");
  const parts = cursor.slice(prefix.length).split(":");
  if (parts.length !== 2) throw new Error("invalid native cursor");
  const progressSequence = Number(parts[0]); const ordinal = Number(parts[1]);
  if (!Number.isSafeInteger(progressSequence) || progressSequence < 0 || !Number.isSafeInteger(ordinal)) throw new Error("invalid native cursor");
  return {nativeSequence: nativeSequence(progressSequence, ordinal), progressSequence};
}
function approvalId(frame: ProgressFrame): string | null {
  if (frame.kind !== "approval_requested" || frame.body.text === null) return null;
  return /^approval ([A-Za-z0-9][A-Za-z0-9._:-]{0,255}):/u.exec(frame.body.text)?.[1] ?? null;
}
interface ProgressSubscription {
  readonly stream: AsyncIterator<ProgressFrame>;
  readonly firstFrame: Promise<IteratorResult<ProgressFrame>>;
}
async function subscribeProgress(socketPath: string, runId: string, cursor: number, signal?: AbortSignal): Promise<ProgressSubscription> {
  let markLive: () => void = () => {};
  const live = new Promise<void>((resolve) => { markLive = resolve; });
  const stream = progressFrames(socketPath, runId, cursor, signal, markLive)[Symbol.asyncIterator]();
  const firstFrame = stream.next();
  await Promise.race([live, firstFrame.then(() => undefined)]);
  return {stream, firstFrame};
}
function executionKey(runId: string): string { return `agui-run-${digest(runId).slice(0, 40)}`; }
function decisionKey(runId: string, interruptId: string): string { return `agui-decision-${digest(`${runId}\0${interruptId}`).slice(0, 36)}`; }
export function nativeRunIdFor(runId: string): string { return `tui-${digest(`automonique.managed-tui.run.v1\0${executionKey(runId)}`).slice(0, 24)}`; }
function toolId(runId: string, name: string): string { return `tool-${digest(`${runId}\0${name}`).slice(0, 24)}`; }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function coordinate(value: Record<string, unknown>): Coordinate { if (typeof value.authority !== "string" || typeof value.id !== "string" || typeof value.kind !== "string") throw new Error("invalid coordinate"); return {authority: value.authority, id: value.id, kind: value.kind}; }
function observed(record: Record<string, unknown>): number { return plain(record.freshness) && Number.isSafeInteger(record.freshness.observed_at) ? Number(record.freshness.observed_at) : 0; }
function positive(value: unknown): number { if (!Number.isSafeInteger(value) || Number(value) < 1) throw new Error("invalid revision"); return Number(value); }
function receiptBody(response: {kind: string; body: Record<string, unknown>}): Receipt { if (response.kind !== "receipt_result" || typeof response.body.id !== "string" || typeof response.body.outcome !== "string") throw new Error("Platform receipt refused"); return {id: response.body.id, outcome: response.body.outcome, explanation: typeof response.body.explanation === "string" ? response.body.explanation : null, revision: positive(response.body.revision)}; }
function plain(value: unknown): value is Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (plain(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`; return JSON.stringify(value); }
function delay(ms: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const timer = setTimeout(resolve, ms); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new DOMException("aborted", "AbortError")); }, {once: true}); }); }
