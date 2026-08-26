// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  MAX_MOBILE_PROTOCOL_VERSIONS,
  MOBILE_AUTH_MEDIA_TYPE,
  MobileFollowUpBytes,
  MobileCredentialPageSize,
  MobilePageEvents,
  MobileSessionId,
  parseCanonical,
  toCanonicalBytes,
  type JsonValue,
} from "../../protocol/src/index.ts";
import {
  MobileLifecycleClient,
  MobileLifecycleError,
  MobileProtocolUnsupportedError,
  SUPPORTED_MOBILE_PROTOCOL_VERSIONS,
  mobilePlatformClientId,
} from "../src/mobile-auth-client.ts";

const origin = "https://mobile.example.test";
const identity = `sha256:${"a".repeat(64)}`;
const access = `ma_${"A".repeat(43)}`;
const refresh = `mr_${"B".repeat(43)}`;
const rotatedAccess = `ma_${"C".repeat(43)}`;
const rotatedRefresh = `mr_${"D".repeat(43)}`;

function json(value: unknown): JsonValue {
  if (value === null) return {kind: "null"};
  if (typeof value === "boolean") return {kind: "bool", value};
  if (typeof value === "bigint") return {kind: "integer", value};
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return {kind: "integer", value: BigInt(value)};
  }
  if (typeof value === "string") return {kind: "string", value};
  if (Array.isArray(value)) return {kind: "array", items: value.map(json)};
  if (typeof value === "object") {
    return {
      kind: "object",
      entries: Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, json(entry)] as const),
    };
  }
  throw new Error("unsupported JSON fixture");
}

function response(value: unknown, status = 200): Response {
  return new Response(new TextDecoder().decode(toCanonicalBytes(json(value))), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": MOBILE_AUTH_MEDIA_TYPE,
    },
  });
}

function discovery(extra: Readonly<Record<string, unknown>> = {}): unknown {
  return {
    credential_inventory_endpoint: `${origin}/api/mobile/credentials/list`,
    credential_revoke_endpoint: `${origin}/api/mobile/credentials/revoke`,
    operator_provision_endpoint: `${origin}/api/mobile/operator-provision`,
    origin,
    pairing_create_endpoint: `${origin}/api/mobile/pairings`,
    pairing_exchange_endpoint: `${origin}/api/mobile/pairings/exchange`,
    platform_endpoint: `${origin}/api/platform`,
    protocol: "automonique.mobile-auth",
    schema: "automonique.mobile-auth/v1",
    server_identity: identity,
    supported_versions: [1],
    ...extra,
  };
}

function issued(
  accessToken = access,
  refreshToken = refresh,
  credentialRevision = 1,
  serverIdentity = identity,
  expiresAt = 9_007_199_254_740_991n,
  issuedAt = 1_777_000_000_000n,
): unknown {
  return {
    access_token: accessToken,
    authorization: {
      actions: ["attach", "follow_up"],
      actor: "operator:mobile",
      authorization_revision: 1,
      credential_id: `mc_${"E".repeat(43)}`,
      credential_revision: credentialRevision,
      expires_at_ms: expiresAt,
      issued_at_ms: issuedAt,
      limits: {max_follow_up_bytes: 4096, max_page_events: 128},
      schema: "automonique.mobile-auth/v1",
      server_identity: serverIdentity,
      session_scope: ["session-a"],
    },
    refresh_token: refreshToken,
  };
}

describe("mobile credential lifecycle client", () => {
  test("discovers, provisions, refreshes, authorizes, and revokes with exact contracts", async () => {
    const requests: {url: string; init: RequestInit | undefined}[] = [];
    const responses = [
      response(discovery()),
      response(issued(), 201),
      response(issued(rotatedAccess, rotatedRefresh, 2)),
      response((issued(rotatedAccess, rotatedRefresh, 2) as {authorization: unknown}).authorization),
      response({revoked: true, schema: "automonique.mobile-auth/v1"}),
    ];
    const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({url: input.toString(), init});
      const next = responses.shift();
      if (next === undefined) throw new Error("unexpected request");
      return next;
    }) as typeof fetch;

    const client = await MobileLifecycleClient.discover(origin, fetcher);
    const provisioned = await client.provision({
      actions: ["attach", "follow_up"],
      limits: {
        max_follow_up_bytes: MobileFollowUpBytes(4096n),
        max_page_events: MobilePageEvents(128n),
      },
      session_scope: [MobileSessionId("session-a")],
    }, "Basic fixture-operator");
    expect(provisioned.authorization.expires_at_ms).toBe(9_007_199_254_740_991n);
    expect(mobilePlatformClientId(provisioned.authorization))
      .toBe(provisioned.authorization.credential_id);
    const rotated = await client.refresh(provisioned.refresh_token);
    expect(rotated.authorization.credential_revision).toBe(2n);
    expect(rotated.access_token).toBe(rotatedAccess);
    expect((await client.authorization(rotated.access_token)).credential_revision).toBe(2n);
    expect((await client.revoke(rotated.refresh_token)).revoked).toBe(true);

    expect(requests.map((request) => request.url)).toEqual([
      `${origin}/.well-known/automonique-mobile`,
      `${origin}/api/mobile/operator-provision`,
      `${origin}/api/mobile/refresh`,
      `${origin}/api/mobile/authorization`,
      `${origin}/api/mobile/revoke`,
    ]);
    for (const request of requests) {
      expect(request.init?.redirect).toBe("error");
      expect(request.init?.credentials).toBe("omit");
    }
    expect(new Headers(requests[1]?.init?.headers).get("authorization"))
      .toBe("Basic fixture-operator");
    expect(new Headers(requests[2]?.init?.headers).get("content-type"))
      .toBe(MOBILE_AUTH_MEDIA_TYPE);
    const refreshBody = requests[2]?.init?.body;
    if (typeof refreshBody !== "string") throw new Error("missing refresh body");
    expect(parseCanonical(new TextEncoder().encode(refreshBody))).toEqual(json({
      refresh_token: refresh,
      server_identity: identity,
    }));
  });

  // The versions this build speaks, and the first one above its ceiling.
  // Written from the generated support range rather than from the literal `1`
  // so these stay tests of the rule after a build widens the protocol.
  const highestSupported =
    SUPPORTED_MOBILE_PROTOCOL_VERSIONS[SUPPORTED_MOBILE_PROTOCOL_VERSIONS.length - 1]!;
  const unsupported = highestSupported + 1n;

  function discoveringFetch(versions: readonly bigint[]): typeof fetch {
    return (async () => response(discovery({supported_versions: versions}))) as typeof fetch;
  }

  test("admits a server advertising exactly the versions this build speaks", async () => {
    const client = await MobileLifecycleClient.discover(
      origin,
      discoveringFetch(SUPPORTED_MOBILE_PROTOCOL_VERSIONS),
    );
    expect(client.protocolVersion).toBe(highestSupported);
    expect(client.discovery.supported_versions).toEqual(SUPPORTED_MOBILE_PROTOCOL_VERSIONS);
  });

  test("admits a server advertising a newer version alongside one this build speaks", async () => {
    const client = await MobileLifecycleClient.discover(
      origin,
      discoveringFetch([unsupported, highestSupported]),
    );
    expect(client.protocolVersion).toBe(highestSupported);

    const ascending = await MobileLifecycleClient.discover(
      origin,
      discoveringFetch([highestSupported, unsupported]),
    );
    expect(ascending.protocolVersion).toBe(highestSupported);
  });

  test("refuses a server sharing no version, naming both sets", async () => {
    const refusal = await MobileLifecycleClient.discover(origin, discoveringFetch([unsupported]))
      .then(() => undefined, (error: unknown) => error);
    expect(refusal).toBeInstanceOf(MobileProtocolUnsupportedError);
    const typed = refusal as MobileProtocolUnsupportedError;
    expect(typed.category).toBe("mobile_protocol_unsupported");
    expect(typed.advertised).toEqual([unsupported]);
    expect(typed.supported).toEqual(SUPPORTED_MOBILE_PROTOCOL_VERSIONS);
    expect(typed.message).toContain(String(unsupported));
    expect(typed.message).toContain(String(highestSupported));
  });

  test("refuses an empty advertisement as no shared version", async () => {
    await expect(MobileLifecycleClient.discover(origin, discoveringFetch([])))
      .rejects.toMatchObject({category: "mobile_protocol_unsupported"});
  });

  test("refuses a malformed version value apart from an unsupported one", async () => {
    await expect(MobileLifecycleClient.discover(origin, discoveringFetch([0n])))
      .rejects.toMatchObject({category: "mobile_auth_value_invalid"});
    await expect(MobileLifecycleClient.discover(origin, discoveringFetch([65_536n])))
      .rejects.toMatchObject({category: "mobile_auth_value_invalid"});
  });

  test("refuses a repeated version and an advertisement past the wire ceiling", async () => {
    await expect(MobileLifecycleClient.discover(
      origin,
      discoveringFetch([highestSupported, highestSupported]),
    )).rejects.toMatchObject({category: "mobile_discovery_mismatch"});

    const overCeiling = Array.from({length: MAX_MOBILE_PROTOCOL_VERSIONS + 1}, (_unused, index) =>
      BigInt(index + 1));
    await expect(MobileLifecycleClient.discover(origin, discoveringFetch(overCeiling)))
      .rejects.toMatchObject({category: "mobile_auth_value_invalid"});
  });

  test("fails closed on strict-schema, identity, media, caching, and bearer errors", async () => {
    const extraField = (async () => response(discovery({unexpected: true}))) as typeof fetch;
    await expect(MobileLifecycleClient.discover(origin, extraField))
      .rejects.toMatchObject({category: "mobile_auth_invalid_body"});

    const wrongIdentityResponses = [response(discovery()), response(issued(access, refresh, 1, `sha256:${"b".repeat(64)}`), 201)];
    const wrongIdentity = (async () => wrongIdentityResponses.shift()!) as typeof fetch;
    const client = await MobileLifecycleClient.discover(origin, wrongIdentity);
    await expect(client.provision({
      actions: ["attach"],
      limits: {max_follow_up_bytes: MobileFollowUpBytes(1n), max_page_events: MobilePageEvents(1n)},
      session_scope: [],
    }, "Basic fixture"))
      .rejects.toMatchObject({category: "mobile_server_identity_mismatch"});

    const wrongMedia = (async () => new Response("{}", {
      headers: {"cache-control": "no-store", "content-type": "application/json"},
    })) as typeof fetch;
    await expect(MobileLifecycleClient.discover(origin, wrongMedia))
      .rejects.toMatchObject({category: "content_type_mismatch"});

    const cacheable = (async () => new Response("{}", {
      headers: {"content-type": MOBILE_AUTH_MEDIA_TYPE},
    })) as typeof fetch;
    await expect(MobileLifecycleClient.discover(origin, cacheable))
      .rejects.toMatchObject({category: "cache_control_mismatch"});

    await expect(MobileLifecycleClient.discover("http://mobile.example.test", fetch))
      .rejects.toBeInstanceOf(MobileLifecycleError);
  });

  test("pins identity and rejects expired, redirected, and unexpected-success responses", async () => {
    const pinned = await MobileLifecycleClient.discover(
      origin,
      (async () => response(discovery())) as typeof fetch,
      undefined,
      identity,
    );
    expect(pinned.discovery.server_identity).toBe(identity);

    await expect(MobileLifecycleClient.discover(
      origin,
      (async () => response(discovery())) as typeof fetch,
      undefined,
      `sha256:${"b".repeat(64)}`,
    )).rejects.toMatchObject({category: "mobile_discovery_mismatch"});
    await expect(MobileLifecycleClient.discover(
      origin,
      (async () => response(discovery())) as typeof fetch,
      undefined,
      "not-an-identity",
    )).rejects.toMatchObject({category: "mobile_server_identity_mismatch"});

    await expect(MobileLifecycleClient.discover(
      origin,
      (async () => response(discovery(), 201)) as typeof fetch,
    )).rejects.toMatchObject({category: "unexpected_success_status"});

    const redirected = response(discovery());
    Object.defineProperty(redirected, "url", {value: "https://attacker.example/redirected"});
    await expect(MobileLifecycleClient.discover(
      origin,
      (async () => redirected) as typeof fetch,
    )).rejects.toMatchObject({category: "response_url_mismatch"});

    const expiredResponses = [
      response(discovery()),
      response(issued(access, refresh, 1, identity, BigInt(Date.now() - 1)), 201),
    ];
    const expired = (async () => expiredResponses.shift()!) as typeof fetch;
    const expiredClient = await MobileLifecycleClient.discover(origin, expired);
    await expect(expiredClient.provision({
      actions: ["attach"],
      limits: {max_follow_up_bytes: MobileFollowUpBytes(1n), max_page_events: MobilePageEvents(1n)},
      session_scope: [],
    }, "Basic fixture")).rejects.toMatchObject({category: "mobile_auth_invalid_body"});

    const futureResponses = [
      response(discovery()),
      response(issued(access, refresh, 1, identity, 9_007_199_254_740_991n, BigInt(Date.now() + 60_000)), 201),
    ];
    const future = (async () => futureResponses.shift()!) as typeof fetch;
    const futureClient = await MobileLifecycleClient.discover(origin, future);
    await expect(futureClient.provision({
      actions: ["attach"],
      limits: {max_follow_up_bytes: MobileFollowUpBytes(1n), max_page_events: MobilePageEvents(1n)},
      session_scope: [],
    }, "Basic fixture")).rejects.toMatchObject({category: "mobile_auth_invalid_body"});

    const wrongProvisionStatusResponses = [response(discovery()), response(issued())];
    const wrongProvisionStatus = (async () => wrongProvisionStatusResponses.shift()!) as typeof fetch;
    const wrongStatusClient = await MobileLifecycleClient.discover(origin, wrongProvisionStatus);
    await expect(wrongStatusClient.provision({
      actions: ["attach"],
      limits: {max_follow_up_bytes: MobileFollowUpBytes(1n), max_page_events: MobilePageEvents(1n)},
      session_scope: [],
    }, "Basic fixture")).rejects.toMatchObject({category: "unexpected_success_status"});
  });

  test("creates and exchanges pairings, inventories, and revokes without ambient authority", async () => {
    const offer = {
      exchange_endpoint: `${origin}/api/mobile/pairings/exchange`,
      expires_at_ms: BigInt(Date.now() + 60_000),
      origin,
      pairing_id: `pi_${"P".repeat(43)}`,
      pairing_token: `mp_${"Q".repeat(43)}`,
      schema: "automonique.mobile-auth/v1",
      server_identity: identity,
    };
    const authorization = (issued() as {authorization: unknown}).authorization;
    const requests: {url: string; init: RequestInit | undefined}[] = [];
    const responses = [
      response(discovery()),
      response(offer, 201),
      response(issued(), 201),
      response({
        credentials: [{authorization, refresh_expires_at_ms: 9_007_199_254_740_991n, revoked_at_ms: null}],
        next_cursor: null,
        schema: "automonique.mobile-auth/v1",
      }),
      response({revoked: true, schema: "automonique.mobile-auth/v1"}),
    ];
    const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({url: input.toString(), init});
      const next = responses.shift();
      if (next === undefined) throw new Error("unexpected request");
      return next;
    }) as typeof fetch;
    const client = await MobileLifecycleClient.discover(origin, fetcher, undefined, identity);
    const created = await client.createPairing({
      actions: ["attach"],
      limits: {max_follow_up_bytes: MobileFollowUpBytes(32n), max_page_events: MobilePageEvents(16n)},
      session_scope: [MobileSessionId("session-a")],
    }, "Basic fixture-operator");
    const paired = await client.exchangePairing({
      pairing_id: created.pairing_id,
      pairing_token: created.pairing_token,
      server_identity: created.server_identity,
    });
    const inventory = await client.credentialInventory({
      cursor: null,
      page_size: MobileCredentialPageSize(10n),
    }, "Basic fixture-operator");
    expect(inventory.credentials[0]?.authorization.credential_id)
      .toBe(paired.authorization.credential_id);
    expect(await client.revokeCredential({
      credential_id: paired.authorization.credential_id,
    }, "Basic fixture-operator")).toEqual({revoked: true, schema: "automonique.mobile-auth/v1"});
    expect(requests.map((entry) => entry.url)).toEqual([
      `${origin}/.well-known/automonique-mobile`,
      `${origin}/api/mobile/pairings`,
      `${origin}/api/mobile/pairings/exchange`,
      `${origin}/api/mobile/credentials/list`,
      `${origin}/api/mobile/credentials/revoke`,
    ]);
    for (const request of requests) {
      expect(request.init?.credentials).toBe("omit");
      expect(request.init?.redirect).toBe("error");
    }
    expect(new Headers(requests[2]?.init?.headers).has("authorization")).toBe(false);
    expect(new Headers(requests[1]?.init?.headers).get("authorization"))
      .toBe("Basic fixture-operator");
  });
});
