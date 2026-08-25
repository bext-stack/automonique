// SPDX-License-Identifier: Apache-2.0

import {
  MAX_MOBILE_HTTP_BODY_BYTES,
  MOBILE_AUTH_MEDIA_TYPE,
  ClientId,
  MobileAccessToken,
  MobileHttpsOrigin,
  MobileRefreshToken,
  MobileServerIdentity,
  RefusalError,
  ValidationError,
  WireError,
  decodeIssuedMobileCredentials,
  decodeMobileAuthorization,
  decodeMobileDiscovery,
  decodeMobileError,
  decodeMobileRevocation,
  encodeMobileOperatorProvisionRequest,
  encodeMobileRefreshRequest,
  parseCanonical,
  toCanonicalBytes,
  type IssuedMobileCredentials,
  type JsonValue,
  type MobileAuthorization,
  type MobileDiscovery,
  type MobileOperatorProvisionRequest,
  type MobileRevocation,
} from "../../protocol/src/index.js";

export type {
  IssuedMobileCredentials,
  MobileAuthorization,
  MobileDiscovery,
  MobileOperatorProvisionRequest,
  MobileRevocation,
};

export class MobileLifecycleError extends Error {
  readonly status: number;
  readonly category: string;

  constructor(status: number, category: string, options?: ErrorOptions) {
    super(`mobile lifecycle refused: ${category}`, options);
    this.name = "MobileLifecycleError";
    this.status = status;
    this.category = category;
  }
}

/**
 * Derive the only Platform client identity an admitted mobile credential may use.
 * Attach and detach are bound to the credential rather than an app-chosen device label.
 */
export function mobilePlatformClientId(
  authorization: MobileAuthorization,
): ReturnType<typeof ClientId> {
  return ClientId(authorization.credential_id);
}

function strictOrigin(value: string): ReturnType<typeof MobileHttpsOrigin> {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:"
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.pathname !== "/"
      || parsed.search !== ""
      || parsed.hash !== ""
    ) {
      throw new MobileLifecycleError(0, "https_origin_required");
    }
    return MobileHttpsOrigin(parsed.origin);
  } catch (error) {
    if (error instanceof MobileLifecycleError) throw error;
    throw new MobileLifecycleError(0, "https_origin_required", {cause: error});
  }
}

function operatorAuthorization(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 7
    || value.length > 4096
    || !value.startsWith("Basic ")
    || !/^[\x20-\x7e]+$/u.test(value)
  ) {
    throw new MobileLifecycleError(0, "operator_authorization_invalid");
  }
  return value;
}

async function readBounded(response: Response): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    if (!/^[0-9]+$/u.test(declared)) {
      void response.body?.cancel().catch(() => undefined);
      throw new MobileLifecycleError(response.status, "invalid_response");
    }
    if (BigInt(declared) > BigInt(MAX_MOBILE_HTTP_BODY_BYTES)) {
      void response.body?.cancel().catch(() => undefined);
      throw new MobileLifecycleError(response.status, "response_too_large");
    }
  }
  const body = response.body as ReadableStream<Uint8Array> | null | undefined;
  if (body === null) return new Uint8Array();
  if (body === undefined || typeof body.getReader !== "function") {
    throw new MobileLifecycleError(response.status, "response_stream_unavailable");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (value.byteLength > MAX_MOBILE_HTTP_BODY_BYTES - length) {
        try {
          await reader.cancel();
        } catch {
          // The body-size refusal remains authoritative.
        }
        throw new MobileLifecycleError(response.status, "response_too_large");
      }
      chunks.push(value);
      length += value.byteLength;
    }
  } catch (error) {
    if (error instanceof MobileLifecycleError) throw error;
    throw new MobileLifecycleError(response.status, "response_read_failed", {cause: error});
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

function decodeBody<T>(
  response: Response,
  payload: Uint8Array,
  decoder: (value: JsonValue) => T,
): T {
  try {
    return decoder(parseCanonical(payload));
  } catch (error) {
    const category = error instanceof RefusalError
      ? error.category
      : error instanceof WireError
        ? error.category
        : error instanceof ValidationError
          ? "mobile_auth_value_invalid"
          : "invalid_response";
    throw new MobileLifecycleError(response.status, category, {cause: error});
  }
}

function verifyResponseHeaders(response: Response, expectedUrl: string): void {
  if (response.headers.get("content-type")?.trim() !== MOBILE_AUTH_MEDIA_TYPE) {
    throw new MobileLifecycleError(response.status, "content_type_mismatch");
  }
  const cacheControl = response.headers.get("cache-control")
    ?.split(",")
    .map((value) => value.trim().toLowerCase());
  if (!cacheControl?.includes("no-store")) {
    throw new MobileLifecycleError(response.status, "cache_control_mismatch");
  }
  if (
    typeof response.url === "string"
    && response.url !== ""
    && response.url !== expectedUrl
  ) {
    throw new MobileLifecycleError(response.status, "response_url_mismatch");
  }
}

function verifyAuthorization(
  authorization: MobileAuthorization,
  expectedIdentity: MobileServerIdentity,
): void {
  if (authorization.server_identity !== expectedIdentity) {
    throw new MobileLifecycleError(0, "mobile_server_identity_mismatch");
  }
  const now = BigInt(Date.now());
  if (
    authorization.issued_at_ms > now
    || authorization.issued_at_ms >= authorization.expires_at_ms
    || authorization.expires_at_ms <= now
    || authorization.actions.length === 0
    || new Set(authorization.actions).size !== authorization.actions.length
    || new Set(authorization.session_scope).size !== authorization.session_scope.length
  ) {
    throw new MobileLifecycleError(0, "mobile_auth_invalid_body");
  }
}

function verifyIssued(
  issued: IssuedMobileCredentials,
  expectedIdentity: MobileServerIdentity,
): IssuedMobileCredentials {
  verifyAuthorization(issued.authorization, expectedIdentity);
  return issued;
}

/** Browser/React Native-safe client for the server-owned mobile credential lifecycle. */
export class MobileLifecycleClient {
  readonly discovery: MobileDiscovery;
  readonly fetcher: typeof fetch;

  private constructor(discovery: MobileDiscovery, fetcher: typeof fetch) {
    this.discovery = discovery;
    this.fetcher = fetcher;
  }

  static async discover(
    origin: string,
    fetcher: typeof fetch = fetch,
    signal?: AbortSignal,
    expectedServerIdentity?: string,
  ): Promise<MobileLifecycleClient> {
    const expectedOrigin = strictOrigin(origin);
    const response = await fetcher(`${expectedOrigin}/.well-known/automonique-mobile`, {
      method: "GET",
      credentials: "omit",
      headers: {accept: MOBILE_AUTH_MEDIA_TYPE},
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    const discoveryEndpoint = `${expectedOrigin}/.well-known/automonique-mobile`;
    verifyResponseHeaders(response, discoveryEndpoint);
    const payload = await readBounded(response);
    if (!response.ok) {
      const refusal = decodeBody(response, payload, decodeMobileError);
      throw new MobileLifecycleError(response.status, refusal.error);
    }
    if (response.status !== 200) {
      throw new MobileLifecycleError(response.status, "unexpected_success_status");
    }
    const discovery = decodeBody(response, payload, decodeMobileDiscovery);
    let pinnedIdentity: MobileServerIdentity | undefined;
    try {
      pinnedIdentity = expectedServerIdentity === undefined
        ? undefined
        : MobileServerIdentity(expectedServerIdentity);
    } catch (error) {
      throw new MobileLifecycleError(0, "mobile_server_identity_mismatch", {cause: error});
    }
    if (
      discovery.origin !== expectedOrigin
      || discovery.operator_provision_endpoint !== `${expectedOrigin}/api/mobile/operator-provision`
      || discovery.platform_endpoint !== `${expectedOrigin}/api/platform`
      || discovery.supported_versions.length !== 1
      || discovery.supported_versions[0] !== 1n
      || (pinnedIdentity !== undefined && discovery.server_identity !== pinnedIdentity)
    ) {
      throw new MobileLifecycleError(response.status, "mobile_discovery_mismatch");
    }
    return new MobileLifecycleClient(discovery, fetcher);
  }

  async provision(
    request: MobileOperatorProvisionRequest,
    authorization: string | (() => string | Promise<string>),
    signal?: AbortSignal,
  ): Promise<IssuedMobileCredentials> {
    const supplied = typeof authorization === "string" ? authorization : await authorization();
    return this.request(
      this.discovery.operator_provision_endpoint,
      encodeMobileOperatorProvisionRequest(request),
      decodeIssuedMobileCredentials,
      {authorization: operatorAuthorization(supplied)},
      201,
      signal,
    ).then((issued) => verifyIssued(issued, this.discovery.server_identity));
  }

  async refresh(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<IssuedMobileCredentials> {
    const issued = await this.request(
      `${this.discovery.origin}/api/mobile/refresh`,
      encodeMobileRefreshRequest({
        refresh_token: MobileRefreshToken(refreshToken),
        server_identity: this.discovery.server_identity,
      }),
      decodeIssuedMobileCredentials,
      {},
      200,
      signal,
    );
    return verifyIssued(issued, this.discovery.server_identity);
  }

  async revoke(refreshToken: string, signal?: AbortSignal): Promise<MobileRevocation> {
    const revoked = await this.request(
      `${this.discovery.origin}/api/mobile/revoke`,
      encodeMobileRefreshRequest({
        refresh_token: MobileRefreshToken(refreshToken),
        server_identity: this.discovery.server_identity,
      }),
      decodeMobileRevocation,
      {},
      200,
      signal,
    );
    if (!revoked.revoked) throw new MobileLifecycleError(0, "mobile_revocation_incomplete");
    return revoked;
  }

  async authorization(
    accessToken: string,
    signal?: AbortSignal,
  ): Promise<MobileAuthorization> {
    const response = await this.fetcher(`${this.discovery.origin}/api/mobile/authorization`, {
      method: "GET",
      credentials: "omit",
      headers: {
        accept: MOBILE_AUTH_MEDIA_TYPE,
        authorization: `Bearer ${MobileAccessToken(accessToken)}`,
      },
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    const endpoint = `${this.discovery.origin}/api/mobile/authorization`;
    verifyResponseHeaders(response, endpoint);
    const payload = await readBounded(response);
    if (!response.ok) {
      const refusal = decodeBody(response, payload, decodeMobileError);
      throw new MobileLifecycleError(response.status, refusal.error);
    }
    if (response.status !== 200) {
      throw new MobileLifecycleError(response.status, "unexpected_success_status");
    }
    const admitted = decodeBody(response, payload, decodeMobileAuthorization);
    verifyAuthorization(admitted, this.discovery.server_identity);
    return admitted;
  }

  private async request<T>(
    endpoint: string,
    body: JsonValue,
    decoder: (value: JsonValue) => T,
    headers: Readonly<Record<string, string>>,
    expectedStatus: number,
    signal?: AbortSignal,
  ): Promise<T> {
    const payload = toCanonicalBytes(body);
    const response = await this.fetcher(endpoint, {
      method: "POST",
      credentials: "omit",
      headers: {
        accept: MOBILE_AUTH_MEDIA_TYPE,
        "content-type": MOBILE_AUTH_MEDIA_TYPE,
        ...headers,
      },
      body: new TextDecoder().decode(payload),
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    verifyResponseHeaders(response, endpoint);
    const responsePayload = await readBounded(response);
    if (!response.ok) {
      const refusal = decodeBody(response, responsePayload, decodeMobileError);
      throw new MobileLifecycleError(response.status, refusal.error);
    }
    if (response.status !== expectedStatus) {
      throw new MobileLifecycleError(response.status, "unexpected_success_status");
    }
    return decodeBody(response, responsePayload, decoder);
  }
}
