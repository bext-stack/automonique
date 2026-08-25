// SPDX-License-Identifier: Apache-2.0

import {
  MOBILE_SESSION_MEDIA_TYPE,
  MobileHistoryCursor,
  MobileHistoryOperation,
  MobileHistoryRequestedLimit,
  MobileHistorySessionId,
  RefusalError,
  ValidationError,
  WireError,
  decodeMobileHistoryError,
  decodeMobileHistoryPage,
  decodeMobileHistoryResync,
  encodeMobileHistoryRequest,
  parseCanonical,
  toCanonicalBytes,
  type MobileHistoryEvent,
  type MobileHistoryPage,
  type MobileHistoryResync,
} from "../../protocol/src/index.js";

const MAX_HISTORY_RESPONSE_BYTES = 17 * 1024 * 1024;

export type PublicMobileHistoryEvent =
  | {
      readonly kind: "message";
      readonly cursor: string;
      readonly atMs: string;
      readonly runId: string;
      readonly role: "assistant";
      readonly text: string;
    }
  | {
      readonly kind: "tool_state";
      readonly cursor: string;
      readonly atMs: string;
      readonly runId: string;
      readonly state: "pending" | "running" | "succeeded" | "failed" | "cancelled";
    }
  | {
      readonly kind: "run_state";
      readonly cursor: string;
      readonly atMs: string;
      readonly runId: string;
      readonly state: "running" | "completed" | "failed" | "cancelled" | "timed_out";
    }
  | {
      readonly kind: "unknown";
      readonly cursor: string;
      readonly atMs: string;
      readonly runId: string;
      readonly eventKind: string;
    };

export interface PublicMobileHistoryPage {
  readonly appliedLimit: number;
  readonly events: readonly PublicMobileHistoryEvent[];
  readonly exclusiveCursor: string;
  readonly hasMore: boolean;
  readonly requestedLimit: number;
  readonly sessionId: string;
  readonly terminalCursor: string;
}

export class MobileHistoryTransportError extends Error {
  readonly status: number;
  readonly category: string;

  constructor(status: number, category: string, options?: ErrorOptions) {
    super(`mobile session history refused: ${category}`, options);
    this.name = "MobileHistoryTransportError";
    this.status = status;
    this.category = category;
  }
}

/** A typed signal that the caller must discard its cursor and request a snapshot. */
export class MobileHistoryResyncError extends Error {
  readonly resync: MobileHistoryResync;

  constructor(resync: MobileHistoryResync) {
    super(`mobile session history requires resync: ${resync.reason}`);
    this.name = "MobileHistoryResyncError";
    this.resync = resync;
  }
}

function bearer(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 4096
    || !/^[\x21-\x7e]+$/u.test(value)
  ) {
    throw new MobileHistoryTransportError(0, "authorization_invalid");
  }
  return value;
}

async function boundedBody(response: Response): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^[0-9]+$/u.test(declared) || BigInt(declared) > BigInt(MAX_HISTORY_RESPONSE_BYTES))) {
    void response.body?.cancel().catch(() => undefined);
    throw new MobileHistoryTransportError(response.status, "frame_too_large");
  }
  const body = response.body as ReadableStream<Uint8Array> | null | undefined;
  if (body === null) return new Uint8Array();
  if (body === undefined || typeof body.getReader !== "function") {
    throw new MobileHistoryTransportError(response.status, "response_stream_unavailable");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (value.byteLength > MAX_HISTORY_RESPONSE_BYTES - length) {
        try {
          await reader.cancel();
        } catch {
          // The bound remains authoritative if cancellation itself fails.
        }
        throw new MobileHistoryTransportError(response.status, "frame_too_large");
      }
      chunks.push(value);
      length += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const payload = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return payload;
}

function publicEvent(event: MobileHistoryEvent): PublicMobileHistoryEvent {
  const common = {
    cursor: event.cursor,
    atMs: event.at_ms,
    runId: event.run_id,
  };
  switch (event.kind) {
    case "message":
      if (
        event.message_role !== "assistant"
        || event.message_text === null
        || event.tool_state !== null
        || event.run_state !== null
        || event.unknown_kind !== null
      ) throw new MobileHistoryTransportError(502, "event_shape_invalid");
      return {...common, kind: "message", role: "assistant", text: event.message_text};
    case "tool_state":
      if (
        event.tool_state === null
        || event.message_role !== null
        || event.message_text !== null
        || event.run_state !== null
        || event.unknown_kind !== null
      ) throw new MobileHistoryTransportError(502, "event_shape_invalid");
      return {...common, kind: "tool_state", state: publicToolState(event.tool_state)};
    case "run_state":
      if (
        event.run_state === null
        || event.message_role !== null
        || event.message_text !== null
        || event.tool_state !== null
        || event.unknown_kind !== null
      ) throw new MobileHistoryTransportError(502, "event_shape_invalid");
      return {...common, kind: "run_state", state: publicRunState(event.run_state)};
    case "unknown":
      if (
        event.unknown_kind === null
        || event.message_role !== null
        || event.message_text !== null
        || event.tool_state !== null
        || event.run_state !== null
      ) throw new MobileHistoryTransportError(502, "event_shape_invalid");
      return {...common, kind: "unknown", eventKind: event.unknown_kind};
    default:
      throw new MobileHistoryTransportError(502, "event_kind_invalid");
  }
}

function publicToolState(
  state: string,
): "pending" | "running" | "succeeded" | "failed" | "cancelled" {
  switch (state) {
    case "pending":
    case "running":
    case "succeeded":
    case "failed":
    case "cancelled":
      return state;
    default:
      throw new MobileHistoryTransportError(502, "tool_state_invalid");
  }
}

function publicRunState(
  state: string,
): "running" | "completed" | "failed" | "cancelled" | "timed_out" {
  switch (state) {
    case "running":
    case "completed":
    case "failed":
    case "cancelled":
    case "timed_out":
      return state;
    default:
      throw new MobileHistoryTransportError(502, "run_state_invalid");
  }
}

function publicPage(page: MobileHistoryPage, expectedSession: string): PublicMobileHistoryPage {
  if (page.session_id !== expectedSession || page.applied_limit > page.requested_limit) {
    throw new MobileHistoryTransportError(502, "page_shape_invalid");
  }
  const exclusive = BigInt(page.exclusive_cursor);
  const terminal = BigInt(page.terminal_cursor);
  let previous = exclusive;
  for (const event of page.events) {
    const cursor = BigInt(event.cursor);
    if (cursor !== previous + 1n || cursor > terminal) {
      throw new MobileHistoryTransportError(502, "page_gap");
    }
    previous = cursor;
  }
  if (
    page.events.length > Number(page.applied_limit)
    || (page.has_more && (page.events.length === 0 || previous >= terminal))
    || (!page.has_more && previous !== terminal)
  ) {
    throw new MobileHistoryTransportError(502, "page_shape_invalid");
  }
  return {
    appliedLimit: Number(page.applied_limit),
    events: page.events.map(publicEvent),
    exclusiveCursor: page.exclusive_cursor,
    hasMore: page.has_more,
    requestedLimit: Number(page.requested_limit),
    sessionId: page.session_id,
    terminalCursor: page.terminal_cursor,
  };
}

/** Browser and React Native safe client for one credential-scoped history endpoint. */
export class MobileSessionHistoryClient {
  readonly endpoint: string;
  readonly token: () => string | Promise<string>;
  readonly fetcher: typeof fetch;

  constructor(
    endpoint: string,
    token: () => string | Promise<string>,
    fetcher: typeof fetch = fetch,
  ) {
    const parsed = new URL(endpoint);
    const localHttp = parsed.protocol === "http:"
      && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
    if (
      (parsed.protocol !== "https:" && !localHttp)
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.search !== ""
      || parsed.hash !== ""
      || !parsed.pathname.endsWith("/api/mobile/session-history")
    ) throw new MobileHistoryTransportError(0, "https_endpoint_invalid");
    this.endpoint = parsed.toString();
    this.token = token;
    this.fetcher = fetcher;
  }

  snapshot(sessionId: string, limit: number, signal?: AbortSignal): Promise<PublicMobileHistoryPage> {
    return this.request(sessionId, null, limit, signal);
  }

  page(
    sessionId: string,
    exclusiveCursor: string,
    limit: number,
    signal?: AbortSignal,
  ): Promise<PublicMobileHistoryPage> {
    return this.request(sessionId, exclusiveCursor, limit, signal);
  }

  /** Iterate a stable sequence of bounded pages until the current terminal cursor. */
  async *events(
    sessionId: string,
    limit: number,
    exclusiveCursor: string | null = null,
    signal?: AbortSignal,
  ): AsyncGenerator<PublicMobileHistoryEvent, void, void> {
    let cursor = exclusiveCursor;
    while (true) {
      const page = await this.request(sessionId, cursor, limit, signal);
      for (const event of page.events) yield event;
      if (!page.hasMore) return;
      const last = page.events.at(-1);
      if (last === undefined) throw new MobileHistoryTransportError(502, "page_shape_invalid");
      cursor = last.cursor;
    }
  }

  private async request(
    sessionId: string,
    exclusiveCursor: string | null,
    limit: number,
    signal?: AbortSignal,
  ): Promise<PublicMobileHistoryPage> {
    let body: Uint8Array;
    try {
      body = toCanonicalBytes(encodeMobileHistoryRequest({
        cursor: exclusiveCursor === null ? null : MobileHistoryCursor(exclusiveCursor),
        limit: MobileHistoryRequestedLimit(BigInt(limit)),
        operation: MobileHistoryOperation(exclusiveCursor === null ? "snapshot" : "page"),
        session_id: MobileHistorySessionId(sessionId),
      }));
    } catch (error) {
      const category = error instanceof RefusalError
        ? error.category
        : error instanceof WireError
          ? error.category
          : error instanceof ValidationError
            ? "mobile_history_value_invalid"
            : "mobile_history_request_invalid";
      throw new MobileHistoryTransportError(0, category, {cause: error});
    }
    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      credentials: "omit",
      headers: {
        accept: MOBILE_SESSION_MEDIA_TYPE,
        authorization: `Bearer ${bearer(await this.token())}`,
        "content-type": MOBILE_SESSION_MEDIA_TYPE,
      },
      body: new TextDecoder().decode(body),
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    if (typeof response.url === "string" && response.url !== "" && response.url !== this.endpoint) {
      throw new MobileHistoryTransportError(response.status, "response_url_mismatch");
    }
    if (response.headers.get("content-type")?.trim() !== MOBILE_SESSION_MEDIA_TYPE) {
      throw new MobileHistoryTransportError(response.status, "content_type_mismatch");
    }
    const cacheControl = response.headers.get("cache-control")
      ?.split(",")
      .map((value) => value.trim().toLowerCase());
    if (!cacheControl?.includes("no-store")) {
      throw new MobileHistoryTransportError(response.status, "cache_control_mismatch");
    }
    const payload = await boundedBody(response);
    try {
      const value = parseCanonical(payload);
      if (response.status === 409) {
        const resync = decodeMobileHistoryResync(value);
        if (resync.session_id !== sessionId) {
          throw new MobileHistoryTransportError(502, "session_mismatch");
        }
        throw new MobileHistoryResyncError(resync);
      }
      if (!response.ok) {
        const refusal = decodeMobileHistoryError(value);
        throw new MobileHistoryTransportError(response.status, refusal.error);
      }
      return publicPage(decodeMobileHistoryPage(value), sessionId);
    } catch (error) {
      if (error instanceof MobileHistoryTransportError || error instanceof MobileHistoryResyncError) {
        throw error;
      }
      const category = error instanceof RefusalError
        ? error.category
        : error instanceof WireError
          ? error.category
          : error instanceof ValidationError
            ? "mobile_history_value_invalid"
            : "mobile_history_invalid_body";
      throw new MobileHistoryTransportError(response.status, category, {cause: error});
    }
  }
}
