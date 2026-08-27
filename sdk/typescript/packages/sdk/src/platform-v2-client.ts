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

type PlatformV2Lane = "negotiation" | "v2";
type PlatformV2Exchange = (
  lane: PlatformV2Lane,
  payload: Uint8Array,
  signal?: AbortSignal,
) => Promise<{readonly payload: Uint8Array; readonly status: number}>;

interface PlatformV2CanonicalTestingHandlers {
  readonly negotiate: (
    requestId: ReturnType<typeof PlatformRequestId>,
    offer: PlatformVersionOffer,
    signal?: AbortSignal,
  ) => Promise<PlatformNegotiationResponse>;
  readonly request: (
    requestId: ReturnType<typeof PlatformRequestId>,
    request: PlatformV2Request,
    signal?: AbortSignal,
  ) => Promise<PlatformV2Response>;
}

const canonicalTestingTransports = new WeakMap<
  PlatformV2CanonicalTestingTransport,
  PlatformV2CanonicalTestingHandlers
>();

/**
 * Testing-only typed registration. Instances expose no request method and
 * cannot receive or recover the authenticated HTTPS bearer capability.
 */
export class PlatformV2CanonicalTestingTransport {
  constructor(
    negotiate: PlatformV2CanonicalTestingHandlers["negotiate"],
    request: PlatformV2CanonicalTestingHandlers["request"],
  ) {
    canonicalTestingTransports.set(this, {negotiate, request});
  }
}

export const PLATFORM_NEGOTIATION_MEDIA_TYPE = "application/vnd.automonique.platform.negotiation.v1+json";
export const PLATFORM_V2_MEDIA_TYPE = "application/vnd.automonique.platform.v2+json";

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

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new PlatformTransportError(0, "aborted", {cause: signal.reason});
  }
}

interface CombinedAbortSignal {
  readonly signal: AbortSignal;
  dispose(): void;
}

function combineAbortSignals(primary: AbortSignal, secondary?: AbortSignal): CombinedAbortSignal {
  if (secondary === undefined) return {signal: primary, dispose() {}};
  const controller = new AbortController();
  const abortPrimary = () => controller.abort(primary.reason);
  const abortSecondary = () => controller.abort(secondary.reason);
  if (primary.aborted) abortPrimary();
  else if (secondary.aborted) abortSecondary();
  else {
    primary.addEventListener("abort", abortPrimary, {once: true});
    secondary.addEventListener("abort", abortSecondary, {once: true});
  }
  return {
    signal: controller.signal,
    dispose() {
      primary.removeEventListener("abort", abortPrimary);
      secondary.removeEventListener("abort", abortSecondary);
    },
  };
}

async function exchangeHttps(
  endpointValue: string,
  credentialProvider: () => string | Promise<string>,
  fetcher: typeof fetch,
  lane: PlatformV2Lane,
  payload: Uint8Array,
  signal?: AbortSignal,
): Promise<{readonly payload: Uint8Array; readonly status: number}> {
  const mediaType = lane === "negotiation" ? PLATFORM_NEGOTIATION_MEDIA_TYPE : PLATFORM_V2_MEDIA_TYPE;
  const maximumResponseBytes = lane === "negotiation"
    ? MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES
    : MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES;
  throwIfAborted(signal);
  const token = await abortableCredential(credentialProvider, signal);
  throwIfAborted(signal);
  const response = await fetcher(endpointValue, {
    method: "POST",
    credentials: "omit",
    headers: {
      accept: mediaType,
      authorization: `Bearer ${bearerToken(token)}`,
      "content-type": mediaType,
    },
    body: new TextDecoder().decode(payload),
    redirect: "error",
    ...(signal === undefined ? {} : {signal}),
  });
  if (typeof response.url === "string" && response.url !== "" && response.url !== endpointValue) {
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

const httpsExchanges = new WeakMap<HttpsPlatformV2Transport, PlatformV2Exchange>();

/** Authenticated HTTPS transport with an exact endpoint and no redirect forwarding. */
export class HttpsPlatformV2Transport {
  readonly #endpoint: string;
  readonly #credentialProvider: () => string | Promise<string>;
  readonly #fetcher: typeof fetch;

  constructor(
    endpointValue: string,
    credentialProvider: () => string | Promise<string>,
    fetcher: typeof fetch = fetch,
  ) {
    const pinnedEndpoint = endpoint(endpointValue);
    this.#endpoint = pinnedEndpoint;
    this.#credentialProvider = credentialProvider;
    this.#fetcher = fetcher;
    httpsExchanges.set(this, (lane, payload, signal) => exchangeHttps(
      this.#endpoint,
      this.#credentialProvider,
      this.#fetcher,
      lane,
      payload,
      signal,
    ));
  }
}

function abortableCredential(
  provider: () => string | Promise<string>,
  signal?: AbortSignal,
): Promise<string> {
  if (signal?.aborted === true) {
    return Promise.reject(new PlatformTransportError(0, "aborted", {cause: signal.reason}));
  }
  let credential: Promise<string>;
  try {
    credential = Promise.resolve(provider());
  } catch (error) {
    return Promise.reject(error);
  }
  if (signal === undefined) return credential;
  return new Promise((resolve, reject) => {
    const aborted = () => reject(new PlatformTransportError(0, "aborted", {cause: signal.reason}));
    signal.addEventListener("abort", aborted, {once: true});
    credential.then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        if (signal.aborted) aborted(); else resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
  });
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

function sameStructuredValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((value, index) => sameStructuredValue(value, right[index]));
  }
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") return false;
  const leftEntries = Object.entries(left as Readonly<Record<string, unknown>>);
  const rightRecord = right as Readonly<Record<string, unknown>>;
  return leftEntries.length === Object.keys(rightRecord).length
    && leftEntries.every(([key, value]) => Object.hasOwn(rightRecord, key) && sameStructuredValue(value, rightRecord[key]));
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
  readonly #exchange: PlatformV2Exchange | null;
  readonly #testingTransport: PlatformV2CanonicalTestingHandlers | null;
  #negotiationGeneration = 0n;
  #generationAbort = new AbortController();
  #negotiated: {readonly generation: bigint; readonly value: NegotiatedPlatform} | null = null;

  constructor(transport: HttpsPlatformV2Transport | PlatformV2CanonicalTestingTransport) {
    const exchange = transport instanceof HttpsPlatformV2Transport
      ? httpsExchanges.get(transport)
      : undefined;
    if (transport instanceof HttpsPlatformV2Transport && exchange === undefined) {
      throw new TypeError("platform v2 transport capability is unavailable");
    }
    const testingTransport = transport instanceof PlatformV2CanonicalTestingTransport
      ? canonicalTestingTransports.get(transport)
      : undefined;
    if (exchange === undefined && testingTransport === undefined) {
      throw new TypeError("platform v2 transport capability is unavailable");
    }
    this.#exchange = exchange ?? null;
    this.#testingTransport = testingTransport ?? null;
  }

  get negotiated(): NegotiatedPlatform | null {
    return this.#negotiated?.value ?? null;
  }

  async negotiate(offer: PlatformVersionOffer, signal?: AbortSignal): Promise<PlatformNegotiationResponse> {
    this.#generationAbort.abort("platform_v2_generation_invalidated");
    this.#generationAbort = new AbortController();
    const generation = ++this.#negotiationGeneration;
    this.#negotiated = null;
    let requestId: ReturnType<typeof PlatformRequestId>;
    let payload: Uint8Array;
    try {
      requestId = PlatformRequestId(defaultRequestId());
      payload = encodePlatformNegotiationRequest(requestId, {kind: "negotiate", offer});
    } catch (error) {
      throw protocolError(error);
    }
    const combined = combineAbortSignals(this.#generationAbort.signal, signal);
    try {
      let response: PlatformNegotiationResponse;
      if (this.#exchange !== null) {
        const exchanged = await this.#exchange("negotiation", payload, combined.signal);
        if (generation !== this.#negotiationGeneration) {
          throw new PlatformTransportError(0, "negotiation_superseded");
        }
        try {
          response = decodePlatformNegotiationResponse(exchanged.payload, requestId, offer);
        } catch (error) {
          throw protocolError(error, exchanged.status);
        }
      } else {
        response = await this.#testingTransport!.negotiate(requestId, offer, combined.signal);
      }
      if (generation !== this.#negotiationGeneration) {
        throw new PlatformTransportError(0, "negotiation_superseded");
      }
      if (
        response.kind === "negotiated"
        && response.negotiated.version === 2n
        && response.negotiated.schema === PLATFORM_SCHEMA_V2
        && response.negotiated.work_context === "v2_structured"
      ) {
        this.#negotiated = {generation, value: response.negotiated};
      }
      return response;
    } catch (error) {
      if (generation !== this.#negotiationGeneration) {
        throw new PlatformTransportError(0, "negotiation_superseded", {cause: error});
      }
      throw error;
    } finally {
      combined.dispose();
    }
  }

  async #request(request: PlatformV2Request, signal?: AbortSignal): Promise<PlatformV2Response> {
    const negotiated = this.#negotiated;
    if (negotiated === null) {
      throw new PlatformTransportError(0, "platform_v2_not_negotiated");
    }
    let requestId: ReturnType<typeof PlatformRequestId>;
    let payload: Uint8Array;
    try {
      requestId = PlatformRequestId(defaultRequestId());
      payload = encodePlatformV2Request(requestId, request);
    } catch (error) {
      throw protocolError(error);
    }
    const combined = combineAbortSignals(this.#generationAbort.signal, signal);
    const invalidated = () => negotiated.generation !== this.#negotiationGeneration
      || this.#negotiated?.generation !== negotiated.generation;
    try {
      let response: PlatformV2Response;
      if (this.#exchange !== null) {
        const exchanged = await this.#exchange("v2", payload, combined.signal);
        if (invalidated()) {
          throw new PlatformTransportError(0, "negotiation_invalidated");
        }
        try {
          response = decodePlatformV2Response(exchanged.payload, requestId, request.kind);
        } catch (error) {
          throw protocolError(error, exchanged.status);
        }
      } else {
        response = await this.#testingTransport!.request(requestId, request, combined.signal);
      }
      if (invalidated()) {
        throw new PlatformTransportError(0, "negotiation_invalidated");
      }
      return response;
    } catch (error) {
      if (invalidated()) {
        throw new PlatformTransportError(0, "negotiation_invalidated", {cause: error});
      }
      throw error;
    } finally {
      combined.dispose();
    }
  }

  async queryWorkContexts(query: WorkContextQuery & {readonly project: ProjectId}, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "query_work_contexts", query}, signal), ["work_context_page", "work_context_resync"] as const);
    if (
      response.kind === "work_context_page"
      && (response.page.requested_limit !== query.limit || response.page.after !== query.after)
    ) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    if (
      response.kind === "work_context_resync"
      && (query.after === null || response.resync.expired_after !== query.after)
    ) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async getWorkContext(identity: WorkContextIdentity, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "get_work_context", identity}, signal), ["work_context_record"] as const);
    if (response.kind === "work_context_record" && !sameIdentity(response.record.identity, identity)) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async prepareMutation(idempotencyKey: IdempotencyKey, intent: WorkContextMutationIntent, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "prepare_mutation", request: {idempotency_key: idempotencyKey, intent}}, signal), ["mutation_preview", "mutation_refused"] as const);
    if (response.kind === "mutation_preview" && response.preview.proposal.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    if (response.kind === "mutation_preview" && !sameStructuredValue(response.preview.proposal.intent, intent)) {
      throw new PlatformTransportError(502, "response_request_mismatch");
    }
    return response;
  }

  async decideMutation(preview: MutationPreviewRef, previewDigest: MutationPreviewDigest, decision: MutationApprovalDecision, signal?: AbortSignal) {
    return requireResponse(await this.#request({kind: "decide_mutation", request: {decision, preview, preview_digest: previewDigest}}, signal), ["mutation_approval", "mutation_refused"] as const);
  }

  async submitMutation(preview: MutationPreviewRef, previewDigest: MutationPreviewDigest, approvalId: MutationApprovalId | null, signal?: AbortSignal) {
    return requireResponse(await this.#request({kind: "submit_mutation", request: {approval_id: approvalId, preview, preview_digest: previewDigest}}, signal), ["mutation_receipt", "mutation_refused"] as const);
  }

  async getMutationReceipt(lookup: {readonly project: ProjectId; readonly receipt_id: ReceiptId} | {readonly project: ProjectId; readonly idempotency_key: IdempotencyKey}, signal?: AbortSignal) {
    return requireResponse(await this.#request({kind: "get_mutation_receipt", lookup}, signal), ["mutation_receipt", "mutation_refused"] as const);
  }

  async getLineage(project: ProjectId, workspace: UserWorkspaceId, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "get_lineage", request: {project, workspace}}, signal), ["lineage_result"] as const);
    if (response.kind === "lineage_result" && response.lineage.workspace !== workspace) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async submitWorkspaceIntent(project: ProjectId, intent: WorkspaceIntent, signal?: AbortSignal) {
    return requireResponse(await this.#request({kind: "submit_workspace_intent", request: {project, intent}}, signal), ["workspace_intent_result"] as const);
  }

  async getWorkspaceIntent(project: ProjectId, intentId: WorkspaceIntentId, signal?: AbortSignal) {
    return requireResponse(await this.#request({kind: "get_workspace_intent", lookup: {project, intent_id: intentId}}, signal), ["workspace_intent_result"] as const);
  }

  async getReview(project: ProjectId, workspace: ReviewWorkspaceIdentity, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "get_review", request: {project, workspace}}, signal), ["review_result"] as const);
    if (response.kind === "review_result" && !sameIdentity(response.review.workspace, workspace)) {
      throw new PlatformTransportError(502, "response_coordinate_mismatch");
    }
    return response;
  }

  async executeReviewAction(workspace: ReviewWorkspaceIdentity, expectedRevision: WorkContextRevision, action: ReviewAction, idempotencyKey: IdempotencyKey, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "execute_review_action", request: {workspace, expected_revision: expectedRevision, action, idempotency_key: idempotencyKey}}, signal), ["review_receipt"] as const);
    if (response.kind === "review_receipt" && response.receipt.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    return response;
  }

  async getReviewReceipt(project: ProjectId, workspace: ReviewWorkspaceIdentity, idempotencyKey: IdempotencyKey, signal?: AbortSignal) {
    const response = requireResponse(await this.#request({kind: "get_review_receipt", lookup: {project, workspace, idempotency_key: idempotencyKey}}, signal), ["review_receipt"] as const);
    if (response.kind === "review_receipt" && response.receipt.idempotency_key !== idempotencyKey) {
      throw new PlatformTransportError(502, "response_idempotency_mismatch");
    }
    return response;
  }
}
