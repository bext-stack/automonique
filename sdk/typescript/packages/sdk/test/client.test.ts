// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  ClientId,
  ControlLeaseId,
  IdempotencyKey,
  MAX_JSON_STRING_BYTES,
  MAX_PLATFORM_CANONICAL_BYTES,
  PlatformParameter,
  PlatformRevision,
  ReceiptId,
  ResourceId,
  decodeMessage,
  decodePlatformResponse,
  encodeMessage,
  type JsonValue,
  type ResourceCoordinate,
} from "../../protocol/src/index.ts";
import {
  HttpsPlatformTransport,
  PLATFORM_MEDIA_TYPE,
  PlatformClient,
  PlatformTransportError,
  type PlatformClientResponse,
} from "../src/platform-client.ts";

function json(value: unknown): JsonValue {
  if (value === null) return {kind: "null"};
  if (typeof value === "boolean") return {kind: "bool", value};
  if (typeof value === "bigint") return {kind: "integer", value};
  if (typeof value === "string") return {kind: "string", value};
  if (Array.isArray(value)) return {kind: "array", items: value.map(json)};
  if (typeof value === "object") {
    return {kind: "object", entries: Object.entries(value).map(([key, entry]) => [key, json(entry)] as const)};
  }
  throw new Error("unsupported test JSON value");
}

function thrownBy(operation: () => unknown): unknown {
  try {
    operation();
  } catch (error) {
    return error;
  }
  throw new Error("expected operation to throw");
}

const session: ResourceCoordinate = {
  authority: "provider",
  id: ResourceId("session-1"),
  kind: "session",
};
const run: ResourceCoordinate = {
  authority: "automonique",
  id: ResourceId("run-1"),
  kind: "run",
};
const cursor = {authority: "provider" as const, sequence: 9007199254740993n, topic: "sessions"};
const resource = {
  freshness: {observed_at: 9007199254740995n, revision: 9007199254740994n, state: "fresh"},
  resource: session,
  summary: "ready",
};
const receipt = {
  action: "start_run",
  explanation: null,
  id: "receipt-1",
  outcome: "completed",
  recorded_at: 9007199254740996n,
  revision: 9007199254740994n,
  target: run,
};

function canonicalResponse(requestId: string, kind: string, body: unknown, status = 200): Response {
  const bytes = encodeMessage({
    envelope: {protocol: "automonique.platform", version: 1, requestId, kind},
    body: json(body),
  });
  return new Response(new TextDecoder().decode(bytes), {
    status,
    headers: {"cache-control": "no-store", "content-type": PLATFORM_MEDIA_TYPE},
  });
}

function clientFor(
  requestId: string,
  responseKind: string,
  responseBody: unknown,
  observe?: (message: ReturnType<typeof decodeMessage>, headers: Headers, init: RequestInit) => void,
): PlatformClient {
  const fetcher = (async (_input: string | URL | Request, init?: RequestInit) => {
    if (typeof init?.body !== "string") throw new Error("expected canonical request string");
    observe?.(decodeMessage(new TextEncoder().encode(init.body)), new Headers(init.headers), init);
    return canonicalResponse(requestId, responseKind, responseBody);
  }) as typeof fetch;
  return new PlatformClient(new HttpsPlatformTransport(
    "https://manage.example/api/platform",
    () => "token",
    fetcher,
    () => requestId,
  ));
}

describe("canonical HTTPS Platform v1 transport", () => {
  test("sends the exact media type and canonical envelope", async () => {
    let observedKind = "";
    const client = clientFor("request-capabilities", "capabilities_result", {
      methods: ["capabilities"],
      protocol: "automonique.platform",
      schema: "automonique.platform/v1",
      transports: ["remote_https"],
    }, (message, headers, init) => {
      observedKind = message.envelope.kind;
      expect(message.envelope).toEqual({
        protocol: "automonique.platform",
        version: 1,
        requestId: "request-capabilities",
        kind: "capabilities",
      });
      expect(message.body).toEqual(json({}));
      expect(headers.get("authorization")).toBe("Bearer token");
      expect(headers.get("accept")).toBe(PLATFORM_MEDIA_TYPE);
      expect(headers.get("content-type")).toBe(PLATFORM_MEDIA_TYPE);
      expect(init.credentials).toBe("omit");
      expect(init.redirect).toBe("error");
    });
    expect((await client.capabilities()).kind).toBe("capabilities");
    expect(observedKind).toBe("capabilities");
  });

  test("decodes every success result and exercises all ten request methods", async () => {
    const cases: readonly {
      readonly method: string;
      readonly responseKind: string;
      readonly body: unknown;
      readonly expectedKind: PlatformClientResponse["kind"];
      readonly call: (client: PlatformClient) => Promise<PlatformClientResponse>;
    }[] = [
      {
        method: "capabilities",
        responseKind: "capabilities_result",
        body: {methods: ["capabilities"], protocol: "automonique.platform", schema: "automonique.platform/v1", transports: ["remote_https"]},
        expectedKind: "capabilities",
        call: (client) => client.capabilities(),
      },
      {
        method: "snapshot", responseKind: "snapshot_result", body: {cursor, resources: [resource]}, expectedKind: "snapshot",
        call: (client) => client.snapshot([session]),
      },
      {
        method: "subscribe", responseKind: "subscription_result", body: {cursor, events: [{cursor, resource}]}, expectedKind: "subscription",
        call: (client) => client.subscribe(null),
      },
      {
        method: "execute", responseKind: "receipt_result", body: receipt, expectedKind: "receipt",
        call: (client) => client.execute({
          action: "start_run",
          expected_revision: PlatformRevision(9007199254740993n),
          idempotency_key: IdempotencyKey("execute-1"),
          parameter: PlatformParameter("start"),
          target: run,
        }),
      },
      {
        method: "get_receipt", responseKind: "receipt_result", body: receipt, expectedKind: "receipt",
        call: (client) => client.getReceipt({id: ReceiptId("receipt-1"), idempotency_key: null}),
      },
      {
        method: "list_sessions", responseKind: "sessions_result", body: {cursor, sessions: [{attachable: true, controllable: true, run, session: resource}]}, expectedKind: "sessions",
        call: (client) => client.listSessions("provider", null),
      },
      {
        method: "attach", responseKind: "attached", body: {client: "client-1", cursor, session}, expectedKind: "attached",
        call: (client) => client.attach(session, ClientId("client-1")),
      },
      {
        method: "detach", responseKind: "detached", body: {client: "client-1", session}, expectedKind: "detached",
        call: (client) => client.detach(session, ClientId("client-1")),
      },
      {
        method: "claim_control", responseKind: "control_claimed", body: {client: "client-1", expires_at: 9007199254740997n, id: "lease-1", revision: 9007199254740994n, session}, expectedKind: "control_claimed",
        call: (client) => client.claimControl(session, ClientId("client-1"), IdempotencyKey("claim-1")),
      },
      {
        method: "release_control", responseKind: "control_released", body: {client: "client-1", lease: "lease-1", session}, expectedKind: "control_released",
        call: (client) => client.releaseControl(session, ClientId("client-1"), ControlLeaseId("lease-1"), IdempotencyKey("release-1")),
      },
    ];

    for (const entry of cases) {
      const requestId = `request-${entry.method}`;
      let observedMethod = "";
      const client = clientFor(requestId, entry.responseKind, entry.body, (message) => {
        observedMethod = message.envelope.kind;
      });
      const response = await entry.call(client);
      expect(response.kind).toBe(entry.expectedKind);
      expect(observedMethod).toBe(entry.method);
      if (response.kind === "snapshot") {
        expect(response.value.cursor.sequence).toBe(9007199254740993n);
        expect(response.value.resources[0]?.freshness.observed_at).toBe(9007199254740995n);
      }
    }
  });

  test("preserves every refusal outcome without inventing success", async () => {
    const outcomes = ["accepted", "completed", "conflict", "rejected", "resync_required", "unknown"] as const;
    for (const outcome of outcomes) {
      const response = await clientFor(`request-${outcome}`, "refused", {
        outcome,
        explanation: "not completed",
      }).capabilities();
      expect(response).toEqual({kind: "refused", outcome, explanation: "not completed"});
    }
  });

  test("fails closed on malformed, mismatched, or lossy input", async () => {
    const wrongSchema = clientFor("request-schema", "capabilities_result", {
      methods: [], protocol: "automonique.platform", schema: "foreign/v1", transports: [],
    });
    await expect(wrongSchema.capabilities()).rejects.toMatchObject({category: "platform_invalid_body"});

    const wrongKind = clientFor("request-kind", "snapshot_result", {cursor, resources: []});
    await expect(wrongKind.capabilities()).rejects.toMatchObject({category: "response_kind_mismatch"});

    const wrongId = clientFor("different-id", "capabilities_result", {
      methods: [], protocol: "automonique.platform", schema: "automonique.platform/v1", transports: [],
    });
    const transport = new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      (async () => canonicalResponse("different-id", "capabilities_result", {
        methods: [], protocol: "automonique.platform", schema: "automonique.platform/v1", transports: [],
      })) as typeof fetch,
      () => "expected-id",
    );
    await expect(new PlatformClient(transport).capabilities()).rejects.toMatchObject({category: "request_id_mismatch"});

    await expect(clientFor("request-number", "snapshot_result", {cursor, resources: []})
      .subscribe({authority: "provider", sequence: 42 as never, topic: "sessions" as never}))
      .rejects.toMatchObject({category: "platform_invalid_body"});
  });

  test("requires the exact response media type", async () => {
    const fetcher = (async () => new Response("{}", {headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
    }})) as typeof fetch;
    const client = new PlatformClient(new HttpsPlatformTransport("https://manage.example/api/platform", () => "token", fetcher));
    await expect(client.capabilities()).rejects.toBeInstanceOf(PlatformTransportError);
    await expect(client.capabilities()).rejects.toMatchObject({category: "content_type_mismatch"});
  });

  test("rejects cacheable and final-URL-mismatched responses", async () => {
    const cacheable = (async () => new Response("{}", {
      headers: {"content-type": PLATFORM_MEDIA_TYPE},
    })) as typeof fetch;
    const cacheableClient = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      cacheable,
    ));
    await expect(cacheableClient.capabilities()).rejects.toMatchObject({
      category: "cache_control_mismatch",
    });

    const redirectedResponse = canonicalResponse("redirected", "capabilities_result", {
      methods: ["capabilities"],
      protocol: "automonique.platform",
      schema: "automonique.platform/v1",
      transports: ["remote_https"],
    });
    Object.defineProperty(redirectedResponse, "url", {value: "https://attacker.example/platform"});
    const redirected = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      (async () => redirectedResponse) as typeof fetch,
      () => "redirected",
    ));
    await expect(redirected.capabilities()).rejects.toMatchObject({
      category: "response_url_mismatch",
    });
  });

  test("refuses embedded credentials, invalid bearer values, and oversized requests", async () => {
    expect(() => new HttpsPlatformTransport(
      "ftp://localhost/api/platform",
      () => "token",
    )).toThrow(PlatformTransportError);

    expect(() => new HttpsPlatformTransport(
      "https://user:password@manage.example/api/platform",
      () => "token",
    )).toThrow(PlatformTransportError);

    const unusedFetcher = (async () => {
      throw new Error("invalid request reached the network");
    }) as unknown as typeof fetch;
    const invalidBearer = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "contains space",
      unusedFetcher,
    ));
    await expect(invalidBearer.capabilities()).rejects.toMatchObject({category: "authorization_invalid"});

    const largeSession: ResourceCoordinate = {
      authority: "provider",
      id: ResourceId("x".repeat(256)),
      kind: "session",
    };
    const oversized = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      unusedFetcher,
    ));
    await expect(oversized.snapshot(Array.from({length: 512}, () => largeSession)))
      .rejects.toMatchObject({category: "frame_too_large"});
  });

  test("refuses oversized responses before buffering or decoding them", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(300_000));
      },
      cancel() {
        cancelled = true;
      },
    });
    const streamedFetcher = (async () => new Response(body, {
      headers: {"cache-control": "no-store", "content-type": PLATFORM_MEDIA_TYPE},
    })) as typeof fetch;
    const streamed = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      streamedFetcher,
    ));
    await expect(streamed.capabilities()).rejects.toMatchObject({category: "frame_too_large"});
    expect(cancelled).toBe(true);

    const declaredFetcher = (async () => new Response("", {
      headers: {
        "content-length": String(MAX_PLATFORM_CANONICAL_BYTES + 1),
        "cache-control": "no-store",
        "content-type": PLATFORM_MEDIA_TYPE,
      },
    })) as typeof fetch;
    const declared = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      declaredFetcher,
    ));
    await expect(declared.capabilities()).rejects.toMatchObject({category: "frame_too_large"});

    expect(thrownBy(() => decodePlatformResponse(new Uint8Array(MAX_PLATFORM_CANONICAL_BYTES + 1))))
      .toMatchObject({category: "frame_too_large"});

    const nonStreamingFetcher = (async () => ({
      arrayBuffer: async () => new ArrayBuffer(0),
      headers: new Headers({"cache-control": "no-store", "content-type": PLATFORM_MEDIA_TYPE}),
      ok: true,
      status: 200,
    }) as Response) as typeof fetch;
    const nonStreaming = new PlatformClient(new HttpsPlatformTransport(
      "https://manage.example/api/platform",
      () => "token",
      nonStreamingFetcher,
    ));
    await expect(nonStreaming.capabilities()).rejects.toMatchObject({
      category: "response_stream_unavailable",
    });
  });

  test("rejects lossy Unicode and parses near-limit strings in linear time", () => {
    expect(PlatformParameter("mobile 😀")).toBe("mobile 😀");
    expect(thrownBy(() => PlatformParameter("\ud800"))).toMatchObject({violation: "invalid_character"});
    expect(thrownBy(() => PlatformParameter("\udc00"))).toMatchObject({violation: "invalid_character"});
    expect(thrownBy(() => encodeMessage({
      envelope: {protocol: "automonique.platform", version: 1, requestId: "unicode", kind: "execute"},
      body: json("\ud800"),
    }))).toMatchObject({category: "malformed_json"});

    const nearLimit = encodeMessage({
      envelope: {protocol: "automonique.platform", version: 1, requestId: "near-limit", kind: "test"},
      body: json("x".repeat(MAX_JSON_STRING_BYTES)),
    });
    const startedAt = performance.now();
    expect(decodeMessage(nearLimit).body).toEqual(json("x".repeat(MAX_JSON_STRING_BYTES)));
    expect(performance.now() - startedAt).toBeLessThan(5_000);
  });
});
