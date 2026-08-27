// SPDX-License-Identifier: Apache-2.0

import {
  MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
  MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
  PLATFORM_SCHEMA_V2,
  PlatformRequestId,
  RefusalError,
  ValidationError,
  WireError,
  decodePlatformNegotiationResponse,
  decodePlatformV2Response,
  encodePlatformNegotiationRequest,
  encodePlatformV2Request,
  type IdempotencyKey,
  type MutationApprovalDecision,
  type MutationApprovalId,
  type MutationPreviewDigest,
  type MutationPreviewRef,
  type NegotiatedPlatform,
  type PlatformNegotiationResponse,
  type PlatformV2Request,
  type PlatformV2Response,
  type PlatformVersionOffer,
  type ProjectId,
  type ReceiptId,
  type ReviewAction,
  type ReviewWorkspaceIdentity,
  type UserWorkspaceId,
  type WorkspaceIntent,
  type WorkspaceIntentId,
  type WorkContextIdentity,
  type WorkContextMutationIntent,
  type WorkContextQuery,
  type WorkContextRevision,
} from "../../protocol/src/index.js";
import {PlatformTransportError} from "./platform-client.js";

export const PLATFORM_NEGOTIATION_MEDIA_TYPE = "application/vnd.automonique.platform.negotiation.v1+json";
export const PLATFORM_V2_MEDIA_TYPE = "application/vnd.automonique.platform.v2+json";

export interface PlatformV2Adapter {
  negotiate(offer: PlatformVersionOffer, signal?: AbortSignal): Promise<PlatformNegotiationResponse>;
  request(request: PlatformV2Request, signal?: AbortSignal): Promise<PlatformV2Response>;
}

let nextV2RequestSequence = 0;
function defaultRequestId(): string {
  nextV2RequestSequence = (nextV2RequestSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `platform-v2-${Date.now()}-${nextV2RequestSequence}`;
}

function bearerToken(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !/^[\x21-\x7e]+$/u.test(value)) {
    throw new PlatformTransportError(0, "authorization_invalid");
  }
  return value;
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
          // The bounded refusal wins over a transport cancellation failure.
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

function endpoint(value: string): string {
  const parsed = new URL(value);
  const localHttp = parsed.protocol === "http:"
    && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]");
  if (
    (parsed.protocol !== "https:" && !localHttp)
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    throw new PlatformTransportError(0, "https_required");
  }
  return parsed.toString();
}

function protocolError(error: unknown, status = 0): PlatformTransportError {
  if (error instanceof PlatformTransportError) return error;
  const category = error instanceof RefusalError || error instanceof WireError
    ? error.category
    : error instanceof ValidationError
      ? "platform_value_invalid"
      : "invalid_response";
  return new PlatformTransportError(status, category, {cause: error});
}

/** Authenticated HTTPS transport with an exact endpoint and no redirect forwarding. */
export class HttpsPlatformV2Transport implements PlatformV2Adapter {
  readonly endpoint: string;
  readonly token: () => string | Promise<string>;
  readonly fetcher: typeof fetch;
  readonly requestId: () => string;

  constructor(
    endpointValue: string,
    token: () => string | Promise<string>,
    fetcher: typeof fetch = fetch,
    requestId: () => string = defaultRequestId,
  ) {
    this.endpoint = endpoint(endpointValue);
    this.token = token;
    this.fetcher = fetcher;
    this.requestId = requestId;
  }

  async negotiate(offer: PlatformVersionOffer, signal?: AbortSignal): Promise<PlatformNegotiationResponse> {
    let requestId: ReturnType<typeof PlatformRequestId>;
    let payload: Uint8Array;
    try {
      requestId = PlatformRequestId(this.requestId());
      payload = encodePlatformNegotiationRequest(requestId, {kind: "negotiate", offer});
    } catch (error) {
      throw protocolError(error);
    }
    const response = await this.exchange(payload, PLATFORM_NEGOTIATION_MEDIA_TYPE, MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES, signal);
    try {
      return decodePlatformNegotiationResponse(response.payload, requestId, offer);
    } catch (error) {
      throw protocolError(error, response.status);
    }
  }

  async request(request: PlatformV2Request, signal?: AbortSignal): Promise<PlatformV2Response> {
    let requestId: ReturnType<typeof PlatformRequestId>;
    let payload: Uint8Array;
    try {
      requestId = PlatformRequestId(this.requestId());
      payload = encodePlatformV2Request(requestId, request);
    } catch (error) {
      throw protocolError(error);
    }
    const response = await this.exchange(payload, PLATFORM_V2_MEDIA_TYPE, MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES, signal);
    try {
      return decodePlatformV2Response(response.payload, requestId, request.kind);
    } catch (error) {
      throw protocolError(error, response.status);
    }
  }

  private async exchange(
    payload: Uint8Array,
    mediaType: string,
    maximumResponseBytes: number,
    signal?: AbortSignal,
  ): Promise<{readonly payload: Uint8Array; readonly status: number}> {
    const response = await this.fetcher(this.endpoint, {
      method: "POST",
      credentials: "omit",
      headers: {
        accept: mediaType,
        authorization: `Bearer ${bearerToken(await this.token())}`,
        "content-type": mediaType,
      },
      body: new TextDecoder().decode(payload),
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    if (typeof response.url === "string" && response.url !== "" && response.url !== this.endpoint) {
      throw new PlatformTransportError(response.status, "response_url_mismatch");
    }
    if (response.status === 401 || response.status === 403) {
      throw new PlatformTransportError(response.status, "unauthorized");
    }
    if (!response.ok) throw new PlatformTransportError(response.status, "remote_refusal");
    if (response.headers.get("content-type")?.trim() !== mediaType) {
      throw new PlatformTransportError(response.status, "content_type_mismatch");
    }
    const cacheControl = response.headers.get("cache-control")
      ?.split(",")
      .map((value) => value.trim().toLowerCase());
    if (!cacheControl?.includes("no-store")) {
      throw new PlatformTransportError(response.status, "cache_control_mismatch");
    }
    return {payload: await readBoundedResponse(response, maximumResponseBytes), status: response.status};
  }
}

function sameIdentity(left: WorkContextIdentity, right: WorkContextIdentity): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === "repository" || left.kind === "platform_session") {
    if (right.kind !== left.kind) return false;
    return left.resource.authority === right.resource.authority
      && left.resource.kind === right.resource.kind
      && left.resource.id === right.resource.id;
  }
  return right.kind !== "repository" && right.kind !== "platform_session" && left.id === right.id;
}

type ResponseOf<K extends PlatformV2Response["kind"]> =
  | Extract<PlatformV2Response, {readonly kind: K}>
  | Extract<PlatformV2Response, {readonly kind: "platform_v2_refused"}>;

function requireResponse<K extends PlatformV2Response["kind"]>(
  response: PlatformV2Response,
  kinds: readonly K[],
): ResponseOf<K> {
  if (response.kind === "platform_v2_refused" || kinds.includes(response.kind as K)) {
    return response as ResponseOf<K>;
  }
  throw new PlatformTransportError(502, "response_kind_mismatch");
}

/** Operation-specific facade. V2 calls fail closed until major two is negotiated. */
export class PlatformV2Client {
  readonly transport: PlatformV2Adapter;
  #negotiated: NegotiatedPlatform | null = null;

  constructor(transport: PlatformV2Adapter) {
    this.transport = transport;
  }

  get negotiated(): NegotiatedPlatform | null {
    return this.#negotiated;
  }

  async negotiate(offer: PlatformVersionOffer, signal?: AbortSignal): Promise<PlatformNegotiationResponse> {
    this.#negotiated = null;
    const response = await this.transport.negotiate(offer, signal);
    if (
      response.kind === "negotiated"
      && response.negotiated.version === 2n
      && response.negotiated.schema === PLATFORM_SCHEMA_V2
      && response.negotiated.work_context === "v2_structured"
    ) {
      this.#negotiated = response.negotiated;
    }
    return response;
  }

  private request(request: PlatformV2Request, signal?: AbortSignal): Promise<PlatformV2Response> {
    if (this.#negotiated === null) {
      return Promise.reject(new PlatformTransportError(0, "platform_v2_not_negotiated"));
    }
    return this.transport.request(request, signal);
  }

  async queryWorkContexts(query: WorkContextQuery & {readonly project: ProjectId}, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "query_work_contexts", query}, signal), ["work_context_page", "work_context_resync"] as const);
  }

  async getWorkContext(identity: WorkContextIdentity, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "get_work_context", identity}, signal), ["work_context_record"] as const);
    if (response.kind === "work_context_record" && !sameIdentity(response.record.identity, identity)) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async prepareMutation(idempotencyKey: IdempotencyKey, intent: WorkContextMutationIntent, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "prepare_mutation", request: {idempotency_key: idempotencyKey, intent}}, signal), ["mutation_preview", "mutation_refused"] as const);
    if (response.kind === "mutation_preview" && response.preview.proposal.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    return response;
  }

  async decideMutation(preview: MutationPreviewRef, previewDigest: MutationPreviewDigest, decision: MutationApprovalDecision, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "decide_mutation", request: {decision, preview, preview_digest: previewDigest}}, signal), ["mutation_approval", "mutation_refused"] as const);
  }

  async submitMutation(preview: MutationPreviewRef, previewDigest: MutationPreviewDigest, approvalId: MutationApprovalId | null, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "submit_mutation", request: {approval_id: approvalId, preview, preview_digest: previewDigest}}, signal), ["mutation_receipt", "mutation_refused"] as const);
  }

  async getMutationReceipt(lookup: {readonly project: ProjectId; readonly receipt_id: ReceiptId} | {readonly project: ProjectId; readonly idempotency_key: IdempotencyKey}, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "get_mutation_receipt", lookup}, signal), ["mutation_receipt", "mutation_refused"] as const);
  }

  async getLineage(project: ProjectId, workspace: UserWorkspaceId, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "get_lineage", request: {project, workspace}}, signal), ["lineage_result"] as const);
    if (response.kind === "lineage_result" && response.lineage.workspace !== workspace) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async submitWorkspaceIntent(project: ProjectId, intent: WorkspaceIntent, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "submit_workspace_intent", request: {project, intent}}, signal), ["workspace_intent_result"] as const);
  }

  async getWorkspaceIntent(project: ProjectId, intentId: WorkspaceIntentId, signal?: AbortSignal) {
    return requireResponse(await this.request({kind: "get_workspace_intent", lookup: {project, intent_id: intentId}}, signal), ["workspace_intent_result"] as const);
  }

  async getReview(project: ProjectId, workspace: ReviewWorkspaceIdentity, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "get_review", request: {project, workspace}}, signal), ["review_result"] as const);
    if (response.kind === "review_result" && !sameIdentity(response.review.workspace, workspace)) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async executeReviewAction(workspace: ReviewWorkspaceIdentity, expectedRevision: WorkContextRevision, action: ReviewAction, idempotencyKey: IdempotencyKey, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "execute_review_action", request: {workspace, expected_revision: expectedRevision, action, idempotency_key: idempotencyKey}}, signal), ["review_receipt"] as const);
    if (response.kind === "review_receipt" && response.receipt.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    return response;
  }

  async getReviewReceipt(project: ProjectId, workspace: ReviewWorkspaceIdentity, idempotencyKey: IdempotencyKey, signal?: AbortSignal) {
    const response = requireResponse(await this.request({kind: "get_review_receipt", lookup: {project, workspace, idempotency_key: idempotencyKey}}, signal), ["review_receipt"] as const);
    if (response.kind === "review_receipt" && response.receipt.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    return response;
  }
}
