// SPDX-License-Identifier: Apache-2.0

import {
  PLATFORM_PROTOCOL,
  PLATFORM_SCHEMA_V1,
  type ActionReceipt,
  type Attachment,
  type Capabilities,
  type ClientId,
  type ControlLease,
  type ControlLeaseId,
  type ExecuteRequest,
  type IdempotencyKey,
  type PlatformCursor,
  type ReceiptId,
  type ResourceAuthority,
  type ResourceCoordinate,
  type SessionList,
  type Snapshot,
  type Subscription,
} from "../../protocol/src/index.ts";

export type PlatformRequest =
  | {readonly method: "capabilities"}
  | {readonly method: "snapshot"; readonly request: {readonly resources: readonly ResourceCoordinate[]}}
  | {readonly method: "subscribe"; readonly request: {readonly cursor: PlatformCursor | null}}
  | {readonly method: "execute"; readonly request: ExecuteRequest}
  | {readonly method: "get_receipt"; readonly request: {readonly id: ReceiptId | null; readonly idempotency_key: IdempotencyKey | null}}
  | {readonly method: "list_sessions"; readonly request: {readonly authority: ResourceAuthority; readonly cursor: PlatformCursor | null}}
  | {readonly method: "attach"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientId}}
  | {readonly method: "detach"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientId}}
  | {readonly method: "claim_control"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientId; readonly idempotency_key: IdempotencyKey}}
  | {readonly method: "release_control"; readonly request: {readonly session: ResourceCoordinate; readonly client: ClientId; readonly lease: ControlLeaseId; readonly idempotency_key: IdempotencyKey}};

export type PlatformResponse =
  | {readonly kind: "capabilities"; readonly value: Capabilities}
  | {readonly kind: "snapshot"; readonly value: Snapshot}
  | {readonly kind: "subscription"; readonly value: Subscription}
  | {readonly kind: "receipt"; readonly value: ActionReceipt}
  | {readonly kind: "sessions"; readonly value: SessionList}
  | {readonly kind: "attached"; readonly value: Attachment}
  | {readonly kind: "detached"; readonly session: ResourceCoordinate; readonly client: ClientId}
  | {readonly kind: "control_claimed"; readonly value: ControlLease}
  | {readonly kind: "control_released"; readonly session: ResourceCoordinate; readonly client: ClientId; readonly lease: ControlLeaseId}
  | {readonly kind: "refused"; readonly outcome: "conflict" | "rejected" | "resync_required" | "unknown"; readonly explanation: string};

export interface PlatformAdapter {
  request(request: PlatformRequest, signal?: AbortSignal): Promise<PlatformResponse>;
}

export class PlatformTransportError extends Error {
  readonly status: number;
  readonly category: string;

  constructor(status: number, category: string) {
    super(`platform transport refused: ${category}`);
    this.name = "PlatformTransportError";
    this.status = status;
    this.category = category;
  }
}

function wireJson(value: unknown): unknown {
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
      throw new PlatformTransportError(0, "integer_not_json_safe");
    }
    return Number(value);
  }
  if (Array.isArray(value)) return value.map(wireJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, wireJson(entry)]),
    );
  }
  return value;
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new PlatformTransportError(502, "invalid_response");
  }
  return value as Record<string, unknown>;
}

/** HTTPS projection used by browser, PWA, and server-side TypeScript clients. */
export class HttpsPlatformTransport implements PlatformAdapter {
  readonly endpoint: string;
  readonly token: () => string | Promise<string>;
  readonly fetcher: typeof fetch;

  constructor(endpoint: string, token: () => string | Promise<string>, fetcher: typeof fetch = fetch) {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
      throw new PlatformTransportError(0, "https_required");
    }
    this.endpoint = parsed.toString();
    this.token = token;
    this.fetcher = fetcher;
  }

  async request(request: PlatformRequest, signal?: AbortSignal): Promise<PlatformResponse> {
    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await this.token()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(wireJson(request)),
      ...(signal === undefined ? {} : {signal}),
    });
    const body = object(await response.json());
    if (body.ok !== true && body.receipt === undefined) {
      throw new PlatformTransportError(response.status, typeof body.error === "string" ? body.error : "remote_refusal");
    }
    return decodeRemoteResponse(request.method, body);
  }
}

function decodeRemoteResponse(method: PlatformRequest["method"], body: Record<string, unknown>): PlatformResponse {
  if (body.capabilities !== undefined) {
    const capabilities = object(body.capabilities);
    if (capabilities.protocol !== PLATFORM_PROTOCOL || capabilities.schema !== PLATFORM_SCHEMA_V1) {
      throw new PlatformTransportError(502, "schema_mismatch");
    }
    return {kind: "capabilities", value: capabilities as unknown as Capabilities};
  }
  if (body.snapshot !== undefined) return {kind: "snapshot", value: object(body.snapshot) as unknown as Snapshot};
  if (body.subscription !== undefined) return {kind: "subscription", value: object(body.subscription) as unknown as Subscription};
  if (body.receipt !== undefined) return {kind: "receipt", value: object(body.receipt) as unknown as ActionReceipt};
  if (body.sessions !== undefined) return {kind: "sessions", value: object(body.sessions) as unknown as SessionList};
  if (body.attachment !== undefined) return {kind: "attached", value: object(body.attachment) as unknown as Attachment};
  if (body.lease !== undefined && method === "claim_control") return {kind: "control_claimed", value: object(body.lease) as unknown as ControlLease};
  throw new PlatformTransportError(502, "response_kind_mismatch");
}

export class PlatformClient {
  readonly transport: PlatformAdapter;

  constructor(transport: PlatformAdapter) {
    this.transport = transport;
  }

  capabilities(signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "capabilities"}, signal);
  }

  snapshot(resources: readonly ResourceCoordinate[] = [], signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "snapshot", request: {resources}}, signal);
  }

  subscribe(cursor: PlatformCursor | null, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "subscribe", request: {cursor}}, signal);
  }

  execute(request: ExecuteRequest, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "execute", request}, signal);
  }

  getReceipt(request: {readonly id: ReceiptId | null; readonly idempotency_key: IdempotencyKey | null}, signal?: AbortSignal): Promise<PlatformResponse> {
    if ((request.id === null) === (request.idempotency_key === null)) {
      throw new PlatformTransportError(0, "receipt_lookup_invalid");
    }
    return this.transport.request({method: "get_receipt", request}, signal);
  }

  listSessions(authority: ResourceAuthority, cursor: PlatformCursor | null, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "list_sessions", request: {authority, cursor}}, signal);
  }

  attach(session: ResourceCoordinate, client: ClientId, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "attach", request: {session, client}}, signal);
  }

  detach(session: ResourceCoordinate, client: ClientId, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "detach", request: {session, client}}, signal);
  }

  claimControl(session: ResourceCoordinate, client: ClientId, idempotency_key: IdempotencyKey, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "claim_control", request: {session, client, idempotency_key}}, signal);
  }

  releaseControl(session: ResourceCoordinate, client: ClientId, lease: ControlLeaseId, idempotency_key: IdempotencyKey, signal?: AbortSignal): Promise<PlatformResponse> {
    return this.transport.request({method: "release_control", request: {session, client, lease, idempotency_key}}, signal);
  }
}
