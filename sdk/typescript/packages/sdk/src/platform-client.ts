// SPDX-License-Identifier: Apache-2.0

import {
  MAX_PLATFORM_CANONICAL_BYTES,
  PlatformRequestId,
  SessionHistoryCursor,
  SessionHistoryLimit,
  RefusalError,
  ValidationError,
  WireError,
  decodePlatformResponse,
  encodePlatformRequestMessage,
  expectedPlatformResponseKind,
  type ActionReceipt,
  type Attachment,
  type Capabilities,
  type ClientId as ClientIdType,
  type ControlLease,
  type ControlLeaseId as ControlLeaseIdType,
  type ExecuteRequest,
  type PlatformEpochMillis,
  type IdempotencyKey as IdempotencyKeyType,
  type PlatformCursor,
  type PlatformRequest,
  type PlatformResponse as DecodedPlatformResponse,
  type ReceiptId as ReceiptIdType,
  type ReceiptOutcome,
  type ResourceAuthority,
  type ResourceCoordinate,
  type SessionHistoryEvidence,
  type SessionHistoryRole,
  type SessionHistoryRunState,
  type SessionHistoryText,
  type SessionHistoryToolState,
  type SessionHistoryUnknownSource,
  type SessionCommandState,
  type SessionList,
  type Snapshot,
  type Subscription,
} from "../../protocol/src/index.js";

export const PLATFORM_MEDIA_TYPE = "application/vnd.automonique.platform.v1+json";

export type {PlatformRequest};

export type SessionHistoryEvent =
  | {readonly kind: "message"; readonly at: PlatformEpochMillis; readonly cursor: ReturnType<typeof SessionHistoryCursor>; readonly evidence: SessionHistoryEvidence; readonly role: SessionHistoryRole; readonly text: SessionHistoryText; readonly truncated: boolean}
  | {readonly kind: "tool_state"; readonly at: PlatformEpochMillis; readonly cursor: ReturnType<typeof SessionHistoryCursor>; readonly evidence: SessionHistoryEvidence; readonly label: SessionHistoryText | null; readonly state: SessionHistoryToolState; readonly truncated: boolean}
  | {readonly kind: "run_state"; readonly at: PlatformEpochMillis; readonly cursor: ReturnType<typeof SessionHistoryCursor>; readonly state: SessionHistoryRunState}
  | {readonly kind: "unknown"; readonly at: PlatformEpochMillis; readonly cursor: ReturnType<typeof SessionHistoryCursor>; readonly source: SessionHistoryUnknownSource};

export interface SessionHistoryPage {
  readonly session: ResourceCoordinate;
  readonly requested_limit: ReturnType<typeof SessionHistoryLimit>;
  readonly applied_limit: ReturnType<typeof SessionHistoryLimit>;
  readonly from_cursor: ReturnType<typeof SessionHistoryCursor>;
  readonly terminal_cursor: ReturnType<typeof SessionHistoryCursor>;
  readonly has_more: boolean;
  readonly events: readonly SessionHistoryEvent[];
}

export type PlatformClientResponse =
  | {readonly kind: "capabilities"; readonly value: Capabilities}
  | {readonly kind: "snapshot"; readonly value: Snapshot}
  | {readonly kind: "subscription"; readonly value: Subscription}
  | {readonly kind: "receipt"; readonly value: ActionReceipt}
  | {readonly kind: "sessions"; readonly value: SessionList}
  | {readonly kind: "attached"; readonly value: Attachment}
  | {readonly kind: "detached"; readonly session: ResourceCoordinate; readonly client: ClientIdType}
  | {readonly kind: "control_claimed"; readonly value: ControlLease}
  | {readonly kind: "control_released"; readonly session: ResourceCoordinate; readonly client: ClientIdType; readonly lease: ControlLeaseIdType}
  | {readonly kind: "session_command_state"; readonly value: SessionCommandState}
  | {readonly kind: "session_history"; readonly value: SessionHistoryPage}
  | {readonly kind: "session_history_resync"; readonly session: ResourceCoordinate; readonly snapshotFrom: ReturnType<typeof SessionHistoryCursor>; readonly snapshotTo: ReturnType<typeof SessionHistoryCursor>}
  | {readonly kind: "refused"; readonly outcome: ReceiptOutcome; readonly explanation: string};

export interface PlatformAdapter {
  request(request: PlatformRequest, signal?: AbortSignal): Promise<PlatformClientResponse>;
}

export class PlatformTransportError extends Error {
  readonly status: number;
  readonly category: string;

  constructor(status: number, category: string, options?: ErrorOptions) {
    super(`platform transport refused: ${category}`, options);
    this.name = "PlatformTransportError";
    this.status = status;
    this.category = category;
  }
}

export class SessionHistoryResyncError extends Error {
  readonly session: ResourceCoordinate;
  readonly snapshotFrom: ReturnType<typeof SessionHistoryCursor>;
  readonly snapshotTo: ReturnType<typeof SessionHistoryCursor>;

  constructor(session: ResourceCoordinate, snapshotFrom: ReturnType<typeof SessionHistoryCursor>, snapshotTo: ReturnType<typeof SessionHistoryCursor>) {
    super("session history retention requires a fresh snapshot");
    this.name = "SessionHistoryResyncError";
    this.session = session;
    this.snapshotFrom = snapshotFrom;
    this.snapshotTo = snapshotTo;
  }
}

function projectHistory(response: Extract<DecodedPlatformResponse, {readonly kind: "session_history_result"}>["value"]): SessionHistoryPage {
  const events: SessionHistoryEvent[] = [
    ...response.messages.map((event) => ({kind: "message" as const, ...event})),
    ...response.tool_states.map((event) => ({kind: "tool_state" as const, ...event})),
    ...response.run_states.map((event) => ({kind: "run_state" as const, ...event})),
    ...response.unknown_events.map((event) => ({kind: "unknown" as const, ...event})),
  ].sort((left, right) => left.cursor < right.cursor ? -1 : left.cursor > right.cursor ? 1 : 0);
  if (events.length > Number(response.applied_limit)) throw new PlatformTransportError(502, "history_page_invalid");
  let expected = response.from_cursor;
  for (const event of events) {
    expected = SessionHistoryCursor(expected + 1n);
    if (event.cursor !== expected) throw new PlatformTransportError(502, "history_gap_or_duplicate");
  }
  if (expected !== response.terminal_cursor) throw new PlatformTransportError(502, "history_terminal_mismatch");
  return {
    session: response.session,
    requested_limit: response.requested_limit,
    applied_limit: response.applied_limit,
    from_cursor: response.from_cursor,
    terminal_cursor: response.terminal_cursor,
    has_more: response.has_more,
    events,
  };
}

function bearerToken(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 4096
    || !/^[\x21-\x7e]+$/u.test(value)
  ) {
    throw new PlatformTransportError(0, "authorization_invalid");
  }
  return value;
}

function projectResponse(response: DecodedPlatformResponse): PlatformClientResponse {
  switch (response.kind) {
    case "capabilities_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "capabilities", value};
    }
    case "snapshot_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "snapshot", value};
    }
    case "subscription_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "subscription", value};
    }
    case "receipt_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "receipt", value};
    }
    case "sessions_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "sessions", value};
    }
    case "attached": {
      const {request_id: _, ...value} = response.value;
      return {kind: "attached", value};
    }
    case "detached":
      return {kind: "detached", session: response.value.session, client: response.value.client};
    case "control_claimed": {
      const {request_id: _, ...value} = response.value;
      return {kind: "control_claimed", value};
    }
    case "control_released":
      return {kind: "control_released", session: response.value.session, client: response.value.client, lease: response.value.lease};
    case "session_command_state_result": {
      const {request_id: _, ...value} = response.value;
      return {kind: "session_command_state", value};
    }
    case "session_history_result":
      return {kind: "session_history", value: projectHistory(response.value)};
    case "session_history_resync":
      return {kind: "session_history_resync", session: response.value.session, snapshotFrom: response.value.snapshot_from, snapshotTo: response.value.snapshot_to};
    case "refused":
      return {kind: "refused", outcome: response.value.outcome, explanation: response.value.explanation};
    case "undecoded":
      throw new PlatformTransportError(502, "response_kind_undecoded");
  }
}

let nextRequestSequence = 0;

function defaultRequestId(): string {
  nextRequestSequence = (nextRequestSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `platform-${Date.now()}-${nextRequestSequence}`;
}

async function readBoundedResponse(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^[0-9]+$/u.test(declaredLength)) {
      void response.body?.cancel().catch(() => undefined);
      throw new PlatformTransportError(response.status, "invalid_response");
    }
    if (BigInt(declaredLength) > BigInt(maximumBytes)) {
      void response.body?.cancel().catch(() => undefined);
      throw new PlatformTransportError(response.status, "frame_too_large");
    }
  }

  const body = response.body as ReadableStream<Uint8Array> | null | undefined;
  if (body === null) return new Uint8Array();
  if (body === undefined || typeof body.getReader !== "function") {
    throw new PlatformTransportError(response.status, "response_stream_unavailable");
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (value.byteLength > maximumBytes - length) {
        try {
          await reader.cancel();
        } catch {
          // The size refusal is authoritative even if the transport cannot cancel cleanly.
        }
        throw new PlatformTransportError(response.status, "frame_too_large");
      }
      chunks.push(value);
      length += value.byteLength;
    }
  } catch (error) {
    if (error instanceof PlatformTransportError) throw error;
    throw new PlatformTransportError(response.status, "response_read_failed", {cause: error});
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

/** HTTPS projection used by browsers, PWAs, React Native, and server-side clients. */
export class HttpsPlatformTransport implements PlatformAdapter {
  readonly endpoint: string;
  readonly token: () => string | Promise<string>;
  readonly fetcher: typeof fetch;
  readonly requestId: () => string;

  constructor(
    endpoint: string,
    token: () => string | Promise<string>,
    fetcher: typeof fetch = fetch,
    requestId: () => string = defaultRequestId,
  ) {
    const parsed = new URL(endpoint);
    const localHttp = parsed.protocol === "http:"
      && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
    if (
      (parsed.protocol !== "https:" && !localHttp)
      || parsed.username !== ""
      || parsed.password !== ""
    ) {
      throw new PlatformTransportError(0, "https_required");
    }
    this.endpoint = parsed.toString();
    this.token = token;
    this.fetcher = fetcher;
    this.requestId = requestId;
  }

  async request(request: PlatformRequest, signal?: AbortSignal): Promise<PlatformClientResponse> {
    let requestId: ReturnType<typeof PlatformRequestId>;
    let payload: Uint8Array;
    try {
      requestId = PlatformRequestId(this.requestId());
      payload = encodePlatformRequestMessage(requestId, request);
    } catch (error) {
      if (error instanceof PlatformTransportError) throw error;
      const category = error instanceof RefusalError
        ? error.category
        : error instanceof WireError
          ? error.category
          : error instanceof ValidationError
            ? "platform_value_invalid"
            : "request_invalid";
      throw new PlatformTransportError(0, category, {cause: error});
    }

    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      credentials: "omit",
      headers: {
        accept: PLATFORM_MEDIA_TYPE,
        authorization: `Bearer ${bearerToken(await this.token())}`,
        "content-type": PLATFORM_MEDIA_TYPE,
      },
      body: new TextDecoder().decode(payload),
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    if (typeof response.url === "string" && response.url !== "" && response.url !== this.endpoint) {
      throw new PlatformTransportError(response.status, "response_url_mismatch");
    }
    if (!response.ok) throw new PlatformTransportError(response.status, "remote_refusal");
    if (response.headers.get("content-type")?.trim() !== PLATFORM_MEDIA_TYPE) {
      throw new PlatformTransportError(response.status, "content_type_mismatch");
    }
    const cacheControl = response.headers.get("cache-control")
      ?.split(",")
      .map((value) => value.trim().toLowerCase());
    if (!cacheControl?.includes("no-store")) {
      throw new PlatformTransportError(response.status, "cache_control_mismatch");
    }
    const responsePayload = await readBoundedResponse(response, MAX_PLATFORM_CANONICAL_BYTES);

    try {
      const decoded = decodePlatformResponse(responsePayload);
      const decodedRequestId = decoded.kind === "undecoded" ? decoded.request_id : decoded.value.request_id;
      if (decodedRequestId !== requestId) throw new PlatformTransportError(response.status, "request_id_mismatch");
      const expected = expectedPlatformResponseKind(request.method);
      const historyResync = (request.method === "session_history_snapshot" || request.method === "session_history_page")
        && decoded.kind === "session_history_resync";
      if (decoded.kind !== "refused" && decoded.kind !== expected && !historyResync) {
        throw new PlatformTransportError(response.status, "response_kind_mismatch");
      }
      return projectResponse(decoded);
    } catch (error) {
      if (error instanceof PlatformTransportError) throw error;
      const category = error instanceof RefusalError
        ? error.category
        : error instanceof WireError
          ? error.category
          : error instanceof ValidationError
            ? "platform_value_invalid"
            : "invalid_response";
      throw new PlatformTransportError(response.status, category, {cause: error});
    }
  }
}

export class PlatformClient {
  readonly transport: PlatformAdapter;

  constructor(transport: PlatformAdapter) {
    this.transport = transport;
  }

  capabilities(signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "capabilities"}, signal);
  }

  snapshot(resources: readonly ResourceCoordinate[] = [], signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "snapshot", request: {resources}}, signal);
  }

  subscribe(cursor: PlatformCursor | null, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "subscribe", request: {cursor}}, signal);
  }

  execute(request: ExecuteRequest, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "execute", request}, signal);
  }

  getReceipt(request: {readonly client: ClientIdType | null; readonly id: ReceiptIdType | null; readonly idempotency_key: IdempotencyKeyType | null}, signal?: AbortSignal): Promise<PlatformClientResponse> {
    if ((request.id === null) === (request.idempotency_key === null)) throw new PlatformTransportError(0, "receipt_lookup_invalid");
    return this.transport.request({method: "get_receipt", request}, signal);
  }

  listSessions(authority: ResourceAuthority, cursor: PlatformCursor | null, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "list_sessions", request: {authority, cursor}}, signal);
  }

  attach(session: ResourceCoordinate, client: ClientIdType, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "attach", request: {session, client}}, signal);
  }

  detach(session: ResourceCoordinate, client: ClientIdType, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "detach", request: {session, client}}, signal);
  }

  claimControl(session: ResourceCoordinate, client: ClientIdType, idempotency_key: IdempotencyKeyType, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "claim_control", request: {session, client, idempotency_key}}, signal);
  }

  releaseControl(session: ResourceCoordinate, client: ClientIdType, lease: ControlLeaseIdType, idempotency_key: IdempotencyKeyType, signal?: AbortSignal): Promise<PlatformClientResponse> {
    return this.transport.request({method: "release_control", request: {session, client, lease, idempotency_key}}, signal);
  }

  async sessionHistorySnapshot(session: ResourceCoordinate, limit: bigint, signal?: AbortSignal): Promise<SessionHistoryPage> {
    return this.requireHistory(await this.transport.request({method: "session_history_snapshot", request: {session, limit: SessionHistoryLimit(limit)}}, signal));
  }

  async sessionHistoryPage(session: ResourceCoordinate, afterExclusive: bigint, limit: bigint, signal?: AbortSignal): Promise<SessionHistoryPage> {
    return this.requireHistory(await this.transport.request({method: "session_history_page", request: {session, after: SessionHistoryCursor(afterExclusive), limit: SessionHistoryLimit(limit)}}, signal));
  }

  async *iterateSessionHistory(session: ResourceCoordinate, limit: bigint, signal?: AbortSignal): AsyncGenerator<SessionHistoryEvent, void, void> {
    let page = await this.sessionHistorySnapshot(session, limit, signal);
    while (true) {
      for (const event of page.events) yield event;
      if (!page.has_more) return;
      page = await this.sessionHistoryPage(session, page.terminal_cursor, limit, signal);
    }
  }

  private requireHistory(response: PlatformClientResponse): SessionHistoryPage {
    if (response.kind === "session_history") return response.value;
    if (response.kind === "session_history_resync") {
      throw new SessionHistoryResyncError(response.session, response.snapshotFrom, response.snapshotTo);
    }
    if (response.kind === "refused") throw new PlatformTransportError(403, response.explanation);
    throw new PlatformTransportError(502, "response_kind_mismatch");
  }
}
