// SPDX-License-Identifier: Apache-2.0

import {
  MAX_MOBILE_HTTP_BODY_BYTES,
  MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION,
  MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION,
  MOBILE_PAIRING_TTL_MILLIS,
  MOBILE_AUTH_MEDIA_TYPE,
  MOBILE_PROTOCOL_UNSUPPORTED,
  ClientId,
  MobileAccessToken,
  MobileHttpsOrigin,
  MobileProtocolVersion,
  MobileRefreshToken,
  MobileServerIdentity,
  RefusalError,
  ValidationError,
  WireError,
  decodeIssuedMobileCredentials,
  decodeMobileCredentialInventory,
  decodeMobileAuthorization,
  decodeMobileDiscovery,
  decodeMobileError,
  decodeMobilePairingOffer,
  decodeMobileRevocation,
  encodeMobileCredentialInventoryRequest,
  encodeMobileCredentialRevokeRequest,
  encodeMobileOperatorProvisionRequest,
  encodeMobilePairingExchangeRequest,
  encodeMobileRefreshRequest,
  parseCanonical,
  toCanonicalBytes,
  type IssuedMobileCredentials,
  type JsonValue,
  type MobileAuthorization,
  type MobileCredentialInventory,
  type MobileCredentialInventoryRequest,
  type MobileCredentialRevokeRequest,
  type MobileDiscovery,
  type MobileOperatorProvisionRequest,
  type MobilePairingExchangeRequest,
  type MobilePairingOffer,
  type MobileRevocation,
} from "../../protocol/src/index.js";
import {
  MOBILE_PLATFORM_V2_ACTIONS,
  MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE,
  decodeMobilePlatformV2Authorization,
  encodeMobilePlatformV2GrantRequest,
  type MobilePlatformV2Authorization,
  type MobilePlatformV2GrantRequest,
} from "./mobile-platform-v2-authorization.js";

export type {
  IssuedMobileCredentials,
  MobileAuthorization,
  MobileCredentialInventory,
  MobileCredentialInventoryRequest,
  MobileCredentialRevokeRequest,
  MobileDiscovery,
  MobileOperatorProvisionRequest,
  MobilePairingExchangeRequest,
  MobilePairingOffer,
  MobileProtocolVersion,
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
 * Every mobile protocol version this build speaks, ascending.
 *
 * Read from the generated surface rather than written here, so a server that
 * widens the protocol and a client rebuilt against it cannot disagree about
 * what "supported" means. This is a *support* set and is deliberately narrower
 * than the `MobileProtocolVersion` value domain, which says only what the wire
 * can carry.
 */
export const SUPPORTED_MOBILE_PROTOCOL_VERSIONS: readonly MobileProtocolVersion[] = Array.from(
  {length: MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION - MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION + 1},
  (_unused, offset) =>
    MobileProtocolVersion(BigInt(MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION + offset)),
);

function renderVersions(versions: readonly MobileProtocolVersion[]): string {
  return versions.length === 0 ? "none" : versions.join(", ");
}

/**
 * The server and this build share no mobile protocol version.
 *
 * Held apart from `mobile_discovery_mismatch` because the two are different
 * operator problems that used to collapse into one refusal: a mismatch says
 * the document is not the one this origin should be serving, while this says
 * both sides are healthy and have nothing in common to speak. It names both
 * sets so the operator can see which side has to move.
 */
export class MobileProtocolUnsupportedError extends MobileLifecycleError {
  /** Exactly what the server advertised, in the order it advertised it. */
  readonly advertised: readonly MobileProtocolVersion[];
  /** Every version this build speaks. */
  readonly supported: readonly MobileProtocolVersion[];

  constructor(
    status: number,
    advertised: readonly MobileProtocolVersion[],
    options?: ErrorOptions,
  ) {
    super(status, MOBILE_PROTOCOL_UNSUPPORTED, options);
    this.name = "MobileProtocolUnsupportedError";
    this.advertised = advertised;
    this.supported = SUPPORTED_MOBILE_PROTOCOL_VERSIONS;
    this.message = `${this.message}: server advertised ${renderVersions(advertised)}, `
      + `this client speaks ${renderVersions(this.supported)}`;
  }
}

/**
 * The highest protocol version the server advertised that this build speaks.
 *
 * Position in the advertised list is not read as preference. The highest
 * shared version is the newest contract both sides implement, whichever order
 * the server listed it in, and a version above this build's ceiling is passed
 * over rather than refused — that is the whole point of advertising a list.
 */
function negotiateProtocolVersion(
  advertised: readonly MobileProtocolVersion[],
  status: number,
): MobileProtocolVersion {
  let selected: MobileProtocolVersion | undefined;
  for (const version of advertised) {
    if (!SUPPORTED_MOBILE_PROTOCOL_VERSIONS.includes(version)) continue;
    if (selected === undefined || version > selected) selected = version;
  }
  if (selected === undefined) throw new MobileProtocolUnsupportedError(status, advertised);
  return selected;
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

function verifyResponseHeaders(
  response: Response,
  expectedUrl: string,
  expectedMediaType = MOBILE_AUTH_MEDIA_TYPE,
): void {
  if (response.headers.get("content-type")?.trim() !== expectedMediaType) {
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
  /** The version admission settled on: the highest both sides speak. */
  readonly protocolVersion: MobileProtocolVersion;

  private constructor(
    discovery: MobileDiscovery,
    fetcher: typeof fetch,
    protocolVersion: MobileProtocolVersion,
  ) {
    this.discovery = discovery;
    this.fetcher = fetcher;
    this.protocolVersion = protocolVersion;
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
      || discovery.credential_inventory_endpoint !== `${expectedOrigin}/api/mobile/credentials/list`
      || discovery.credential_revoke_endpoint !== `${expectedOrigin}/api/mobile/credentials/revoke`
      || discovery.operator_provision_endpoint !== `${expectedOrigin}/api/mobile/operator-provision`
      || discovery.pairing_create_endpoint !== `${expectedOrigin}/api/mobile/pairings`
      || discovery.pairing_exchange_endpoint !== `${expectedOrigin}/api/mobile/pairings/exchange`
      || discovery.platform_endpoint !== `${expectedOrigin}/api/platform`
      // A repeated version is a defect in the document rather than a
      // disagreement about which version to speak, so it stays a mismatch.
      || new Set(discovery.supported_versions).size !== discovery.supported_versions.length
      || (pinnedIdentity !== undefined && discovery.server_identity !== pinnedIdentity)
    ) {
      throw new MobileLifecycleError(response.status, "mobile_discovery_mismatch");
    }
    // Negotiated after the layout is admitted: an unrecognised version is a
    // reason to refuse this server, not evidence that the document is
    // malformed, and an empty advertisement offers nothing to agree on.
    const protocolVersion = negotiateProtocolVersion(
      discovery.supported_versions,
      response.status,
    );
    return new MobileLifecycleClient(discovery, fetcher, protocolVersion);
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

  async createPairing(
    request: MobileOperatorProvisionRequest,
    authorization: string | (() => string | Promise<string>),
    signal?: AbortSignal,
  ): Promise<MobilePairingOffer> {
    const supplied = typeof authorization === "string" ? authorization : await authorization();
    const offer = await this.request(
      this.discovery.pairing_create_endpoint,
      encodeMobileOperatorProvisionRequest(request),
      decodeMobilePairingOffer,
      {authorization: operatorAuthorization(supplied)},
      201,
      signal,
    );
    const now = BigInt(Date.now());
    if (
      offer.origin !== this.discovery.origin
      || offer.server_identity !== this.discovery.server_identity
      || offer.exchange_endpoint !== this.discovery.pairing_exchange_endpoint
      || offer.expires_at_ms <= now
      || offer.expires_at_ms > now + BigInt(MOBILE_PAIRING_TTL_MILLIS)
    ) {
      throw new MobileLifecycleError(0, "mobile_pairing_invalid");
    }
    return offer;
  }

  async exchangePairing(
    request: MobilePairingExchangeRequest,
    signal?: AbortSignal,
  ): Promise<IssuedMobileCredentials> {
    if (request.server_identity !== this.discovery.server_identity) {
      throw new MobileLifecycleError(0, "mobile_server_identity_mismatch");
    }
    const issued = await this.request(
      this.discovery.pairing_exchange_endpoint,
      encodeMobilePairingExchangeRequest(request),
      decodeIssuedMobileCredentials,
      {},
      201,
      signal,
    );
    return verifyIssued(issued, this.discovery.server_identity);
  }

  async credentialInventory(
    request: MobileCredentialInventoryRequest,
    authorization: string | (() => string | Promise<string>),
    signal?: AbortSignal,
  ): Promise<MobileCredentialInventory> {
    const supplied = typeof authorization === "string" ? authorization : await authorization();
    const inventory = await this.request(
      this.discovery.credential_inventory_endpoint,
      encodeMobileCredentialInventoryRequest(request),
      decodeMobileCredentialInventory,
      {authorization: operatorAuthorization(supplied)},
      200,
      signal,
    );
    const now = BigInt(Date.now());
    for (const summary of inventory.credentials) {
      const authorization = summary.authorization;
      if (
        authorization.server_identity !== this.discovery.server_identity
        || authorization.issued_at_ms > now
        || authorization.issued_at_ms >= authorization.expires_at_ms
        || summary.refresh_expires_at_ms < authorization.expires_at_ms
        || new Set(authorization.actions).size !== authorization.actions.length
        || new Set(authorization.session_scope).size !== authorization.session_scope.length
        || (summary.revoked_at_ms !== null
          && (summary.revoked_at_ms < authorization.issued_at_ms || summary.revoked_at_ms > now))
      ) {
        throw new MobileLifecycleError(0, "mobile_auth_invalid_body");
      }
    }
    return inventory;
  }

  async revokeCredential(
    request: MobileCredentialRevokeRequest,
    authorization: string | (() => string | Promise<string>),
    signal?: AbortSignal,
  ): Promise<MobileRevocation> {
    const supplied = typeof authorization === "string" ? authorization : await authorization();
    const revoked = await this.request(
      this.discovery.credential_revoke_endpoint,
      encodeMobileCredentialRevokeRequest(request),
      decodeMobileRevocation,
      {authorization: operatorAuthorization(supplied)},
      200,
      signal,
    );
    if (!revoked.revoked) throw new MobileLifecycleError(0, "mobile_revocation_incomplete");
    return revoked;
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

  async grantPlatformV2(
    request: MobilePlatformV2GrantRequest,
    authorization: string | (() => string | Promise<string>),
    signal?: AbortSignal,
  ): Promise<MobilePlatformV2Authorization> {
    const supplied = typeof authorization === "string" ? authorization : await authorization();
    const endpoint = `${this.discovery.origin}/api/mobile/platform-v2/grants`;
    const payload = toCanonicalBytes(encodeMobilePlatformV2GrantRequest(request));
    const response = await this.fetcher(endpoint, {
      method: "POST",
      credentials: "omit",
      headers: {
        accept: MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE,
        authorization: operatorAuthorization(supplied),
        "content-type": MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE,
      },
      body: new TextDecoder().decode(payload),
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    verifyResponseHeaders(response, endpoint, MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE);
    const responsePayload = await readBounded(response);
    if (!response.ok) {
      const refusal = decodeBody(response, responsePayload, decodeMobileError);
      throw new MobileLifecycleError(response.status, refusal.error);
    }
    if (response.status !== 200) {
      throw new MobileLifecycleError(response.status, "unexpected_success_status");
    }
    const admitted = decodeBody(
      response,
      responsePayload,
      decodeMobilePlatformV2Authorization,
    );
    const expectedActions = [...new Set(request.actions)]
      .sort((left, right) => MOBILE_PLATFORM_V2_ACTIONS.indexOf(left) - MOBILE_PLATFORM_V2_ACTIONS.indexOf(right));
    const expectedRoots = [...new Set(request.project_roots)].sort();
    const now = BigInt(Date.now());
    if (
      admitted.server_identity !== this.discovery.server_identity
      || admitted.credential_id !== request.credential_id
      || admitted.issued_at_ms > now
      || admitted.issued_at_ms >= admitted.expires_at_ms
      || admitted.expires_at_ms <= now
      || admitted.actions.length !== expectedActions.length
      || admitted.actions.some((action, index) => action !== expectedActions[index])
      || admitted.project_roots.length !== expectedRoots.length
      || admitted.project_roots.some((root, index) => root !== expectedRoots[index])
    ) {
      throw new MobileLifecycleError(0, "mobile_v2_authorization_invalid");
    }
    return admitted;
  }

  async platformV2Authorization(
    accessToken: string,
    expected: MobileAuthorization,
    signal?: AbortSignal,
  ): Promise<MobilePlatformV2Authorization> {
    const endpoint = `${this.discovery.origin}/api/mobile/platform-v2/authorization`;
    const response = await this.fetcher(endpoint, {
      method: "GET",
      credentials: "omit",
      headers: {
        accept: MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE,
        authorization: `Bearer ${MobileAccessToken(accessToken)}`,
      },
      redirect: "error",
      ...(signal === undefined ? {} : {signal}),
    });
    verifyResponseHeaders(response, endpoint, MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE);
    const payload = await readBounded(response);
    if (!response.ok) {
      const refusal = decodeBody(response, payload, decodeMobileError);
      throw new MobileLifecycleError(response.status, refusal.error);
    }
    if (response.status !== 200) {
      throw new MobileLifecycleError(response.status, "unexpected_success_status");
    }
    const admitted = decodeBody(response, payload, decodeMobilePlatformV2Authorization);
    const now = BigInt(Date.now());
    if (
      admitted.server_identity !== this.discovery.server_identity
      || admitted.server_identity !== expected.server_identity
      || admitted.credential_id !== expected.credential_id
      || admitted.credential_revision !== expected.credential_revision
      || admitted.authorization_revision !== expected.authorization_revision
      || admitted.issued_at_ms > now
      || admitted.issued_at_ms >= admitted.expires_at_ms
      || admitted.expires_at_ms !== expected.expires_at_ms
      || admitted.expires_at_ms <= now
    ) {
      throw new MobileLifecycleError(0, "mobile_v2_authorization_invalid");
    }
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
