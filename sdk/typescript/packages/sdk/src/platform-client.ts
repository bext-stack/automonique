// SPDX-License-Identifier: Apache-2.0

import {
  ClientId,
  ControlLeaseId,
  CursorTopic,
  IdempotencyKey,
  MAX_PLATFORM_CANONICAL_BYTES,
  MAX_PLATFORM_REQUEST_CANONICAL_BYTES,
  MAX_SNAPSHOT_RESOURCES,
  PLATFORM_PROTOCOL,
  PLATFORM_PROTOCOL_VERSION,
  PlatformParameter,
  PlatformRequestId,
  PlatformRevision,
  ReceiptId,
  ResourceId,
  RefusalError,
  ValidationError,
  WireError,
  decodePlatformAction,
  decodePlatformMethod,
  decodePlatformResponse,
  decodeResourceAuthority,
  decodeResourceKind,
  encodeMessage,
  type ActionReceipt,
  type Attachment,
  type Capabilities,
  type ClientId as ClientIdType,
  type ControlLease,
  type ControlLeaseId as ControlLeaseIdType,
  type ExecuteRequest,
  type IdempotencyKey as IdempotencyKeyType,
  type JsonValue,
  type PlatformAction,
  type PlatformCursor,
  type PlatformResponse as DecodedPlatformResponse,
  type ReceiptId as ReceiptIdType,
  type ReceiptOutcome,
  type ResourceAuthority,
  type ResourceCoordinate,
  type SessionList,
  type Snapshot,
  type Subscription,
} from "../../protocol/src/index.js";

export const PLATFORM_MEDIA_TYPE = "application/vnd.automonique.platform.v1+json";

export type PlatformRequest =
  | {readonly method: "capabilities"}
  | {readonly method: "snapshot"; readonly request: {readonly resources: readonly ResourceCoordinate[]}}
  | {readonly method: "subscribe"; readonly request: {readonly cursor: PlatformCursor | null}}
  | {readonly method: "execute"; readonly request: ExecuteRequest}
  | {readonly method: "get_receipt"; readonly request: {readonly id: ReceiptIdType | null; readonly idempotency_key: IdempotencyKeyType | null}}
  | {readonly method: "list_sessions"; readonly request: {readonly authority: ResourceAuthority; readonly cursor: PlatformCursor | null}}
  | {readonly method: "attach"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientIdType}}
  | {readonly method: "detach"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientIdType}}
  | {readonly method: "claim_control"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientIdType; readonly idempotency_key: IdempotencyKeyType}}
  | {readonly method: "release_control"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientIdType; readonly lease: ControlLeaseIdType; readonly idempotency_key: IdempotencyKeyType}};

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

type UnknownRecord = Readonly<Record<string, unknown>>;

function strictRecord(value: unknown, fields: readonly string[], category = "request_invalid"): UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new PlatformTransportError(0, category);
  }
  const record = value as UnknownRecord;
  const keys = Object.keys(record);
  if (keys.length !== fields.length || fields.some((field) => !Object.hasOwn(record, field))) {
    throw new PlatformTransportError(0, category);
  }
  return record;
}

const jsonNull: JsonValue = {kind: "null"};

function jsonString(value: string): JsonValue {
  return {kind: "string", value};
}

function jsonInteger(value: bigint): JsonValue {
  return {kind: "integer", value};
}

function jsonArray(items: readonly JsonValue[]): JsonValue {
  return {kind: "array", items};
}

function jsonObject(entries: readonly (readonly [string, JsonValue])[]): JsonValue {
  return {kind: "object", entries};
}

function stringValue(value: unknown): string {
  if (typeof value !== "string") throw new PlatformTransportError(0, "request_invalid");
  return value;
}

function bigintValue(value: unknown): bigint {
  if (typeof value !== "bigint") throw new PlatformTransportError(0, "request_invalid");
  return value;
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

function coordinateBody(value: unknown): JsonValue {
  const coordinate = strictRecord(value, ["authority", "id", "kind"]);
  const authority = decodeResourceAuthority(stringValue(coordinate.authority));
  const id = ResourceId(stringValue(coordinate.id));
  const kind = decodeResourceKind(stringValue(coordinate.kind));
  return jsonObject([
    ["authority", jsonString(authority)],
    ["id", jsonString(id)],
    ["kind", jsonString(kind)],
  ]);
}

function cursorBody(value: unknown): JsonValue {
  const cursor = strictRecord(value, ["authority", "sequence", "topic"]);
  const authority = decodeResourceAuthority(stringValue(cursor.authority));
  const sequence = PlatformRevision(bigintValue(cursor.sequence));
  const topic = CursorTopic(stringValue(cursor.topic));
  return jsonObject([
    ["authority", jsonString(authority)],
    ["sequence", jsonInteger(sequence)],
    ["topic", jsonString(topic)],
  ]);
}

function optionalCursor(value: unknown): JsonValue {
  return value === null ? jsonNull : cursorBody(value);
}

function actionAuthority(action: PlatformAction): ResourceAuthority {
  switch (action) {
    case "approve_release":
    case "register_node":
    case "submit_job":
      return "ai_operations";
    case "decide_approval":
    case "follow_up":
    case "start_run":
    case "steer":
    case "stop_run":
    case "submit_request":
      return "automonique";
  }
}

function encodeRequestBody(request: PlatformRequest): {readonly kind: string; readonly body: JsonValue} {
  const top = strictRecord(request, request.method === "capabilities" ? ["method"] : ["method", "request"]);
  const method = decodePlatformMethod(stringValue(top.method));
  if (method !== request.method) throw new PlatformTransportError(0, "request_invalid");
  if (method === "capabilities") return {kind: method, body: jsonObject([])};

  const value = top.request;
  switch (method) {
    case "snapshot": {
      const body = strictRecord(value, ["resources"]);
      if (!Array.isArray(body.resources) || body.resources.length > MAX_SNAPSHOT_RESOURCES) {
        throw new PlatformTransportError(0, "request_invalid");
      }
      return {kind: method, body: jsonObject([["resources", jsonArray(body.resources.map(coordinateBody))]])};
    }
    case "subscribe": {
      const body = strictRecord(value, ["cursor"]);
      return {kind: method, body: jsonObject([["cursor", optionalCursor(body.cursor)]])};
    }
    case "execute": {
      const body = strictRecord(value, ["action", "expected_revision", "idempotency_key", "parameter", "target"]);
      const action = decodePlatformAction(stringValue(body.action));
      const targetRecord = strictRecord(body.target, ["authority", "id", "kind"]);
      const targetAuthority = decodeResourceAuthority(stringValue(targetRecord.authority));
      if (actionAuthority(action) !== targetAuthority) {
        throw new PlatformTransportError(0, "authority_mismatch");
      }
      const expectedRevision = body.expected_revision === null
        ? jsonNull
        : jsonInteger(PlatformRevision(bigintValue(body.expected_revision)));
      const parameter = body.parameter === null
        ? jsonNull
        : jsonString(PlatformParameter(stringValue(body.parameter)));
      return {
        kind: method,
        body: jsonObject([
          ["action", jsonString(action)],
          ["expected_revision", expectedRevision],
          ["idempotency_key", jsonString(IdempotencyKey(stringValue(body.idempotency_key)))],
          ["parameter", parameter],
          ["target", coordinateBody(body.target)],
        ]),
      };
    }
    case "get_receipt": {
      const body = strictRecord(value, ["id", "idempotency_key"]);
      if ((body.id === null) === (body.idempotency_key === null)) {
        throw new PlatformTransportError(0, "receipt_lookup_invalid");
      }
      return {
        kind: method,
        body: jsonObject([
          ["id", body.id === null ? jsonNull : jsonString(ReceiptId(stringValue(body.id)))],
          ["idempotency_key", body.idempotency_key === null ? jsonNull : jsonString(IdempotencyKey(stringValue(body.idempotency_key)))],
        ]),
      };
    }
    case "list_sessions": {
      const body = strictRecord(value, ["authority", "cursor"]);
      return {
        kind: method,
        body: jsonObject([
          ["authority", jsonString(decodeResourceAuthority(stringValue(body.authority)))],
          ["cursor", optionalCursor(body.cursor)],
        ]),
      };
    }
    case "attach":
    case "detach": {
      const body = strictRecord(value, ["client", "session"]);
      return {
        kind: method,
        body: jsonObject([
          ["client", jsonString(ClientId(stringValue(body.client)))],
          ["session", coordinateBody(body.session)],
        ]),
      };
    }
    case "claim_control": {
      const body = strictRecord(value, ["client", "idempotency_key", "session"]);
      return {
        kind: method,
        body: jsonObject([
          ["client", jsonString(ClientId(stringValue(body.client)))],
          ["idempotency_key", jsonString(IdempotencyKey(stringValue(body.idempotency_key)))],
          ["session", coordinateBody(body.session)],
        ]),
      };
    }
    case "release_control": {
      const body = strictRecord(value, ["client", "idempotency_key", "lease", "session"]);
      return {
        kind: method,
        body: jsonObject([
          ["client", jsonString(ClientId(stringValue(body.client)))],
          ["idempotency_key", jsonString(IdempotencyKey(stringValue(body.idempotency_key)))],
          ["lease", jsonString(ControlLeaseId(stringValue(body.lease)))],
          ["session", coordinateBody(body.session)],
        ]),
      };
    }
  }
}

function expectedResponseKind(method: PlatformRequest["method"]): DecodedPlatformResponse["kind"] {
  switch (method) {
    case "capabilities": return "capabilities_result";
    case "snapshot": return "snapshot_result";
    case "subscribe": return "subscription_result";
    case "execute":
    case "get_receipt": return "receipt_result";
    case "list_sessions": return "sessions_result";
    case "attach": return "attached";
    case "detach": return "detached";
    case "claim_control": return "control_claimed";
    case "release_control": return "control_released";
  }
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
      const encoded = encodeRequestBody(request);
      payload = encodeMessage({
        envelope: {protocol: PLATFORM_PROTOCOL, version: PLATFORM_PROTOCOL_VERSION, requestId, kind: encoded.kind},
        body: encoded.body,
      });
      if (payload.byteLength > MAX_PLATFORM_REQUEST_CANONICAL_BYTES) {
        throw new PlatformTransportError(0, "frame_too_large");
      }
    } catch (error) {
      if (error instanceof PlatformTransportError) throw error;
      throw new PlatformTransportError(0, "request_invalid", {cause: error});
    }

    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      headers: {
        accept: PLATFORM_MEDIA_TYPE,
        authorization: `Bearer ${bearerToken(await this.token())}`,
        "content-type": PLATFORM_MEDIA_TYPE,
      },
      body: new TextDecoder().decode(payload),
      ...(signal === undefined ? {} : {signal}),
    });
    if (!response.ok) throw new PlatformTransportError(response.status, "remote_refusal");
    if (response.headers.get("content-type")?.trim() !== PLATFORM_MEDIA_TYPE) {
      throw new PlatformTransportError(response.status, "content_type_mismatch");
    }
    const responsePayload = await readBoundedResponse(response, MAX_PLATFORM_CANONICAL_BYTES);

    try {
      const decoded = decodePlatformResponse(responsePayload);
      const decodedRequestId = decoded.kind === "undecoded" ? decoded.request_id : decoded.value.request_id;
      if (decodedRequestId !== requestId) throw new PlatformTransportError(response.status, "request_id_mismatch");
      const expected = expectedResponseKind(request.method);
      if (decoded.kind !== "refused" && decoded.kind !== expected) {
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

  getReceipt(request: {readonly id: ReceiptIdType | null; readonly idempotency_key: IdempotencyKeyType | null}, signal?: AbortSignal): Promise<PlatformClientResponse> {
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
}
