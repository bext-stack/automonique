// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  IdempotencyKey,
  MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PLATFORM_REVIEW_SCHEMA_V1,
  PLATFORM_SCHEMA_V1,
  PLATFORM_SCHEMA_V2,
  MutationPreviewId,
  MutationApprovalId,
  PlatformVersionNumber,
  ProjectId,
  UserWorkspaceId,
  WorkContextCursor,
  WorkContextLabel,
  WorkContextPageLimit,
  WorkContextRevision,
  decodeMessage,
  encodeMessage,
  encodeWorkContextMutationApproval,
  lifecycleRequestDigest,
  mutationPreviewDigest,
  type JsonValue,
  type PlatformNegotiationResponse,
  type PlatformV2Response,
  type PlatformVersionOffer,
  type MutationPreview,
  type MutationApprovalDecision,
  type WorkContextIdentity,
  type WorkContextMutationIntent,
} from "../../protocol/src/index.ts";
import {
  BasicHttpsPlatformV2Transport,
  HttpsPlatformV2Transport,
  PLATFORM_NEGOTIATION_MEDIA_TYPE,
  PLATFORM_V2_MEDIA_TYPE,
  PlatformV2Client,
  PlatformV2BasicCredential,
} from "../src/platform-v2-client.ts";
import {DeterministicPlatformV2Adapter} from "../src/testing.ts";

function json(value: unknown): JsonValue {
  if (value === null) return {kind: "null"};
  if (typeof value === "boolean") return {kind: "bool", value};
  if (typeof value === "bigint") return {kind: "integer", value};
  if (typeof value === "string") return {kind: "string", value};
  if (Array.isArray(value)) return {kind: "array", items: value.map(json)};
  if (typeof value === "object") {
    return {kind: "object", entries: Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, json(item)] as const)};
  }
  throw new Error("unsupported fixture value");
}

function canonicalResponse(
  requestId: string,
  protocol: string,
  version: number,
  kind: string,
  body: unknown,
  mediaType: string,
): Response {
  return new Response(new TextDecoder().decode(encodeMessage({
    envelope: {protocol, version, requestId, kind},
    body: json(body),
  })), {
    headers: {"cache-control": "no-store", "content-type": mediaType},
  });
}

const offer: PlatformVersionOffer = {
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(1n), PlatformVersionNumber(2n)],
};
const projectA: WorkContextIdentity = {kind: "project", id: ProjectId("project-a")};
const projectB: WorkContextIdentity = {kind: "project", id: ProjectId("project-b")};

function negotiatedBody(version: 1n | 2n) {
  return version === 2n
    ? {schema: PLATFORM_SCHEMA_V2, version, work_context: "v2_structured"}
    : {schema: PLATFORM_SCHEMA_V1, version, work_context: "v1_existing_resources_only"};
}

function record(identity: WorkContextIdentity) {
  return {
    attributes: {checkout: null, host_setup: null},
    identity,
    label: WorkContextLabel("Project"),
    lifecycle: "active",
    relations: [],
    revision: 1n,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => {
    resolve = complete;
  });
  return {promise, resolve};
}

const emptyAuthority = {
  credentials: [], filesystem: [], models: [], network: [], providers: [], tools: [],
} as const;

function mutationPreview(intent: WorkContextMutationIntent, key: ReturnType<typeof IdempotencyKey>): MutationPreview {
  const resulting = {
    ...record({kind: "project", id: ProjectId("created-project")}),
    label: intent.kind === "create_project" ? intent.label : WorkContextLabel("Project"),
  };
  const proposalInput = {
    actor: {id: "operator-1", tenant: "tenant-1"},
    actor_authority: emptyAuthority,
    authority: "automonique" as const,
    idempotency_key: key,
    intent,
  };
  return {
    approval: "not_required",
    current: null,
    effective_authority: emptyAuthority,
    expires_at_ms: 2_000n,
    inherited_authority: emptyAuthority,
    issued_at_ms: 1_000n,
    preview: {id: MutationPreviewId("preview-1"), revision: WorkContextRevision(1n)},
    proposal: {
      ...proposalInput,
      request_digest: lifecycleRequestDigest(proposalInput),
      schema: PLATFORM_SCHEMA_V2,
    },
    resolved_parents: [],
    resulting,
    schema: PLATFORM_SCHEMA_V2,
  };
}

function rawMutationApproval(preview: MutationPreview, decision: MutationApprovalDecision) {
  return {
    canonical: encodeWorkContextMutationApproval({
      decided_at_ms: 1_100n,
      decided_by: {id: "operator-1", tenant: "tenant-1"},
      decision,
      expires_at_ms: 1_900n,
      id: MutationApprovalId("approval-1"),
      idempotency_key: preview.proposal.idempotency_key,
      preview: preview.preview,
      preview_digest: mutationPreviewDigest(preview),
      request_digest: preview.proposal.request_digest,
    }, preview),
  };
}

describe("canonical HTTPS Platform v2 client", () => {
  test("does not expose a generic production request path", () => {
    const transport = new HttpsPlatformV2Transport("https://manage.example/api/platform/v2", () => "token");
    const client = new PlatformV2Client(transport);
    expect("request" in transport).toBe(false);
    expect("negotiate" in transport).toBe(false);
    expect("request" in client).toBe(false);
    expect("transport" in client).toBe(false);
    expect(Reflect.ownKeys(transport)).toEqual([]);
    expect(Reflect.ownKeys(Object.getPrototypeOf(transport))).toEqual(["constructor"]);
    expect(Object.getOwnPropertySymbols(transport)).toEqual([]);
    expect(Object.getOwnPropertySymbols(Object.getPrototypeOf(transport))).toEqual([]);
    expect(Object.getPrototypeOf(Object.getPrototypeOf(transport))).toBe(Object.prototype);
    expect(Reflect.ownKeys(client)).toEqual([]);
  });

  test("pins a credential-free HTTPS endpoint", () => {
    for (const invalid of [
      "http://manage.example/api/platform/v2",
      "https://user:password@manage.example/api/platform/v2",
      "https://manage.example/api/platform/v2?tenant=asserted",
      "https://manage.example/api/platform/v2#fragment",
    ]) {
      expect(() => new HttpsPlatformV2Transport(invalid, () => "token")).toThrow();
    }
    expect(() => new HttpsPlatformV2Transport("http://localhost/api/platform/v2", () => "token"))
      .not.toThrow();
  });

  test("uses explicit opaque Basic credentials without changing the Bearer default", async () => {
    const observed: string[] = [];
    const fetcher = (async (_input: string | URL | Request, init?: RequestInit) => {
      observed.push(new Headers(init?.headers).get("authorization") ?? "");
      const body = typeof init?.body === "string" ? init.body : "";
      const message = decodeMessage(new TextEncoder().encode(body));
      return canonicalResponse(
        message.envelope.requestId,
        "automonique.platform.negotiation",
        1,
        "negotiated",
        negotiatedBody(2n),
        PLATFORM_NEGOTIATION_MEDIA_TYPE,
      );
    }) as typeof fetch;
    const basic = new PlatformV2BasicCredential("ops", "fixture-password");
    expect(Reflect.ownKeys(basic)).toEqual([]);
    expect(Reflect.ownKeys(Object.getPrototypeOf(basic))).toEqual(["constructor"]);
    const basicTransport = new BasicHttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => basic,
      fetcher,
    );
    expect(Reflect.ownKeys(basicTransport)).toEqual([]);
    expect((await new PlatformV2Client(basicTransport).negotiate(offer)).kind).toBe("negotiated");
    expect(observed).toEqual(["Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ="]);

    const bearerTransport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => "fixture-token",
      fetcher,
    );
    expect((await new PlatformV2Client(bearerTransport).negotiate(offer)).kind).toBe("negotiated");
    expect(observed[1]).toBe("Bearer fixture-token");
  });

  test("refuses malformed Basic material and forged credential objects", async () => {
    expect(() => new PlatformV2BasicCredential("", "password")).toThrow();
    expect(() => new PlatformV2BasicCredential("ops:admin", "password")).toThrow();
    expect(() => new PlatformV2BasicCredential("ops", "")).toThrow();
    expect(() => new PlatformV2BasicCredential("ops", "x".repeat(509))).toThrow();
    let fetchCalls = 0;
    const transport = new BasicHttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => Object.create(PlatformV2BasicCredential.prototype) as PlatformV2BasicCredential,
      (async () => {
        fetchCalls += 1;
        return new Response();
      }) as typeof fetch,
    );
    await expect(new PlatformV2Client(transport).negotiate(offer)).rejects.toMatchObject({
      category: "authorization_invalid",
    });
    expect(fetchCalls).toBe(0);
  });

  test("ignores reflective property injection and keeps credentials on the pinned typed path", async () => {
    let originalCredentialCalls = 0;
    let attackerCredentialCalls = 0;
    let attackerFetchCalls = 0;
    let attackerSymbolCalls = 0;
    let observedEndpoint = "";
    const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
      observedEndpoint = String(input);
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer original-token");
      const body = typeof init?.body === "string" ? init.body : "";
      const requestId = decodeMessage(new TextEncoder().encode(body)).envelope.requestId;
      return canonicalResponse(requestId, "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
    }) as typeof fetch;
    const transport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => {
        originalCredentialCalls += 1;
        return "original-token";
      },
      fetcher,
    );
    Object.assign(transport as unknown as Record<string, unknown>, {
      endpoint: "https://attacker.example/arbitrary",
      credentialProvider: () => {
        attackerCredentialCalls += 1;
        return "attacker-token";
      },
      fetcher: async () => {
        attackerFetchCalls += 1;
        return new Response();
      },
    });
    const attackerExchange = Symbol("attacker.exchange");
    Object.defineProperty(transport, attackerExchange, {
      value: async () => {
        attackerSymbolCalls += 1;
        return {payload: new Uint8Array(), status: 200};
      },
    });

    expect((await new PlatformV2Client(transport).negotiate(offer)).kind).toBe("negotiated");
    expect(observedEndpoint).toBe("https://manage.example/api/platform/v2");
    expect(originalCredentialCalls).toBe(1);
    expect(attackerCredentialCalls).toBe(0);
    expect(attackerFetchCalls).toBe(0);
    expect(attackerSymbolCalls).toBe(0);
  });

  test("negotiates and sends an exact typed request without identity assertions", async () => {
    let calls = 0;
    const fetcher = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      const message = decodeMessage(new TextEncoder().encode(body));
      const headers = new Headers(init?.headers);
      expect(init?.credentials).toBe("omit");
      expect(init?.redirect).toBe("error");
      expect(headers.get("authorization")).toBe("Bearer token");
      if (calls++ === 0) {
        expect(headers.get("content-type")).toBe(PLATFORM_NEGOTIATION_MEDIA_TYPE);
        expect(message.envelope.kind).toBe("negotiate");
        return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
      }
      expect(headers.get("content-type")).toBe(PLATFORM_V2_MEDIA_TYPE);
      expect(message.envelope).toMatchObject({kind: "get_work_context", protocol: "automonique.platform", version: 2});
      const encoded = body;
      expect(encoded).not.toContain("actor");
      expect(encoded).not.toContain("tenant");
      expect(encoded).not.toContain("authority_ceiling");
      return canonicalResponse(message.envelope.requestId, "automonique.platform", 2, "work_context_record", record(projectA), PLATFORM_V2_MEDIA_TYPE);
    }) as typeof fetch;
    const transport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => "token",
      fetcher,
    );
    const client = new PlatformV2Client(transport);
    expect((await client.negotiate(offer)).kind).toBe("negotiated");
    expect((await client.getWorkContext(projectA)).kind).toBe("work_context_record");
    expect(calls).toBe(2);
  });

  test("keeps downgrade and refusal explicit and leaves v2 disabled", async () => {
    for (const result of [
      {kind: "negotiated" as const, negotiated: negotiatedBody(1n)},
      {kind: "platform_v2_refused" as const, refusal: {category: "unsupported", explanation: "v2 unavailable", schema: PLATFORM_SCHEMA_V2}},
    ]) {
      const adapter = new DeterministicPlatformV2Adapter([{lane: "negotiation", result}]);
      const client = new PlatformV2Client(adapter);
      expect((await client.negotiate(offer)).kind).toBe(result.kind);
      await expect(client.getWorkContext(projectA)).rejects.toMatchObject({category: "platform_v2_not_negotiated"});
      expect(adapter.pendingSteps).toBe(0);
    }
  });

  test("deterministic negotiation still rejects an unoffered server version", async () => {
    const v1Only: PlatformVersionOffer = {
      schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
      versions: [PlatformVersionNumber(1n)],
    };
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
    ]);
    await expect(new PlatformV2Client(adapter).negotiate(v1Only))
      .rejects.toMatchObject({category: "invalid_json_value"});
  });

  test("refuses malformed, oversized, correlated-to-another-request, and redirected responses", async () => {
    const cases: readonly {readonly response: () => Response; readonly category: string}[] = [
      {
        response: () => new Response("not-json", {headers: {"cache-control": "no-store", "content-type": PLATFORM_NEGOTIATION_MEDIA_TYPE}}),
        category: "malformed_json",
      },
      {
        response: () => new Response("", {headers: {"cache-control": "no-store", "content-length": String(MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES + 1), "content-type": PLATFORM_NEGOTIATION_MEDIA_TYPE}}),
        category: "frame_too_large",
      },
      {
        response: () => canonicalResponse("another-request", "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE),
        category: "invalid_json_value",
      },
      {
        response: () => {
          const response = canonicalResponse("request-1", "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
          Object.defineProperty(response, "url", {value: "https://attacker.example/platform"});
          return response;
        },
        category: "response_url_mismatch",
      },
    ];
    for (const entry of cases) {
      const transport = new HttpsPlatformV2Transport(
        "https://manage.example/api/platform/v2",
        () => "token",
        (async () => entry.response()) as typeof fetch,
      );
      await expect(new PlatformV2Client(transport).negotiate(offer)).rejects.toMatchObject({category: entry.category});
    }
  });

  test("rejects a valid response for another exact coordinate", async () => {
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "get_work_context", identity: projectA}, result: {kind: "work_context_record", record: record(projectB)}},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.getWorkContext(projectA)).rejects.toMatchObject({category: "response_coordinate_mismatch"});
  });

  test("rejects lineage projected for another workspace coordinate", async () => {
    const requested = UserWorkspaceId("workspace-a");
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {
        lane: "v2",
        request: {kind: "get_lineage", request: {project: ProjectId("project-a"), workspace: requested}},
        result: {kind: "lineage_result", lineage: {
          external_work_items: [],
          orchestration: [],
          schema: PLATFORM_SCHEMA_V2,
          workspace: UserWorkspaceId("workspace-b"),
        }},
      },
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.getLineage(ProjectId("project-a"), requested))
      .rejects.toMatchObject({category: "response_coordinate_mismatch"});
  });

  test("preserves the exact idempotency lookup and supports AbortSignal", async () => {
    const key = IdempotencyKey("mutation-1");
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "get_mutation_receipt", lookup: {project: ProjectId("project-a"), idempotency_key: key}}, result: {kind: "platform_v2_refused", refusal: {category: "unavailable", explanation: "pending", schema: PLATFORM_SCHEMA_V2}}},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    expect((await client.getMutationReceipt({project: ProjectId("project-a"), idempotency_key: key})).kind).toBe("platform_v2_refused");
    expect(adapter.requests).toEqual([{
      kind: "get_mutation_receipt",
      lookup: {project: ProjectId("project-a"), idempotency_key: key},
    }]);

    const aborted = new AbortController();
    aborted.abort("cancelled");
    await expect(client.getWorkContext(projectA, aborted.signal)).rejects.toMatchObject({category: "aborted"});
  });

  test("refuses a review receipt bound to another idempotency key", async () => {
    const workspace = {kind: "user_workspace" as const, id: UserWorkspaceId("workspace-a")};
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "get_review_receipt", lookup: {project: ProjectId("project-a"), workspace, idempotency_key: IdempotencyKey("expected-key")}}, result: {kind: "review_receipt", receipt: {
        action_id: "action-1",
        actor: "actor-1",
        current_revision: null,
        idempotency_key: "another-key",
        outcome: "completed",
        platform_version: 2n,
        receipt_id: "receipt-1",
        reconciliation: "final",
        revision: 2n,
        schema: PLATFORM_REVIEW_SCHEMA_V1,
      }}},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.getReviewReceipt(
      ProjectId("project-a"),
      workspace,
      IdempotencyKey("expected-key"),
    )).rejects.toMatchObject({category: "response_idempotency_mismatch"});
  });

  test("binds pages and resyncs to the exact requested cursor and limit", async () => {
    const first = WorkContextCursor("cursor-1");
    const other = WorkContextCursor("cursor-2");
    const query = {
      after: first,
      kinds: ["project" as const],
      lifecycles: [],
      limit: WorkContextPageLimit(10n),
      parent: null,
      project: ProjectId("project-a"),
      schema: PLATFORM_SCHEMA_V2,
    };
    const wrongPage = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "query_work_contexts", query}, result: {kind: "work_context_page", page: {
        after: first, has_more: false, items: [], next_cursor: null,
        requested_limit: WorkContextPageLimit(9n), schema: PLATFORM_SCHEMA_V2,
      }}},
    ]);
    const pageClient = new PlatformV2Client(wrongPage);
    await pageClient.negotiate(offer);
    await expect(pageClient.queryWorkContexts(query)).rejects.toMatchObject({category: "response_coordinate_mismatch"});

    const wrongResync = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "query_work_contexts", query}, result: {kind: "work_context_resync", resync: {
        expired_after: other, outcome: "resync_required", schema: PLATFORM_SCHEMA_V2,
      }}},
    ]);
    const resyncClient = new PlatformV2Client(wrongResync);
    await resyncClient.negotiate(offer);
    await expect(resyncClient.queryWorkContexts(query)).rejects.toMatchObject({category: "response_coordinate_mismatch"});
  });

  test("binds mutation previews to the exact submitted intent", async () => {
    const key = IdempotencyKey("mutation-intent-1");
    const requested: WorkContextMutationIntent = {kind: "create_project", label: WorkContextLabel("Requested"), repositories: []};
    const substituted: WorkContextMutationIntent = {kind: "create_project", label: WorkContextLabel("Substituted"), repositories: []};
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "prepare_mutation", request: {idempotency_key: key, intent: requested}}, result: {
        kind: "mutation_preview", preview: mutationPreview(substituted, key),
      }},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.prepareMutation(key, requested)).rejects.toMatchObject({category: "response_request_mismatch"});
  });

  test("rejects a mutation approval that reverses the requested decision", async () => {
    const key = IdempotencyKey("mutation-decision-1");
    const preview = mutationPreview(
      {kind: "create_project", label: WorkContextLabel("Requested"), repositories: []},
      key,
    );
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {
        lane: "v2",
        request: {
          kind: "decide_mutation",
          request: {decision: "granted", preview: preview.preview, preview_digest: mutationPreviewDigest(preview)},
        },
        result: {kind: "mutation_approval", approval: rawMutationApproval(preview, "denied")},
      },
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.decideMutation(preview.preview, mutationPreviewDigest(preview), "granted"))
      .rejects.toMatchObject({category: "response_decision_mismatch"});
  });

  test("does not let a stale negotiation success overwrite a newer refusal", async () => {
    const stale = deferred<PlatformNegotiationResponse>();
    const newer = deferred<PlatformNegotiationResponse>();
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: stale.promise},
      {lane: "negotiation", result: newer.promise},
    ]);
    const client = new PlatformV2Client(adapter);
    const staleAttempt = client.negotiate(offer);
    const newerAttempt = client.negotiate(offer);

    newer.resolve({kind: "platform_v2_refused", refusal: {category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2}});
    expect((await newerAttempt).kind).toBe("platform_v2_refused");
    expect(client.negotiated).toBeNull();

    stale.resolve({kind: "negotiated", negotiated: negotiatedBody(2n)});
    await expect(staleAttempt).rejects.toMatchObject({category: "negotiation_superseded"});
    expect(client.negotiated).toBeNull();
  });

  test("checks stale negotiation and v2 generations before decoding malformed bytes", async () => {
    const staleNegotiation = deferred<Response>();
    const staleNegotiationStarted = deferred<void>();
    let negotiationFetch = 0;
    const negotiationTransport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => "token",
      (async (_input, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        const requestId = decodeMessage(new TextEncoder().encode(body)).envelope.requestId;
        if (negotiationFetch++ === 0) {
          staleNegotiationStarted.resolve(undefined);
          return staleNegotiation.promise;
        }
        return canonicalResponse(requestId, "automonique.platform.negotiation", 1, "platform_v2_refused", {
          category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2,
        }, PLATFORM_NEGOTIATION_MEDIA_TYPE);
      }) as typeof fetch,
    );
    const negotiationClient = new PlatformV2Client(negotiationTransport);
    const staleAttempt = negotiationClient.negotiate(offer);
    await staleNegotiationStarted.promise;
    expect((await negotiationClient.negotiate(offer)).kind).toBe("platform_v2_refused");
    staleNegotiation.resolve(new Response("not-json", {
      headers: {"cache-control": "no-store", "content-type": PLATFORM_NEGOTIATION_MEDIA_TYPE},
    }));
    await expect(staleAttempt).rejects.toMatchObject({category: "negotiation_superseded"});

    const staleV2 = deferred<Response>();
    const staleV2Started = deferred<void>();
    let v2Fetch = 0;
    const v2Transport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => "token",
      (async (_input, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        const message = decodeMessage(new TextEncoder().encode(body));
        if (v2Fetch++ === 0) {
          return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
        }
        if (message.envelope.kind === "get_work_context") {
          staleV2Started.resolve(undefined);
          return staleV2.promise;
        }
        return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "platform_v2_refused", {
          category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2,
        }, PLATFORM_NEGOTIATION_MEDIA_TYPE);
      }) as typeof fetch,
    );
    const v2Client = new PlatformV2Client(v2Transport);
    await v2Client.negotiate(offer);
    const staleRead = v2Client.getWorkContext(projectA);
    await staleV2Started.promise;
    expect((await v2Client.negotiate(offer)).kind).toBe("platform_v2_refused");
    staleV2.resolve(new Response("not-json", {
      headers: {"cache-control": "no-store", "content-type": PLATFORM_V2_MEDIA_TYPE},
    }));
    await expect(staleRead).rejects.toMatchObject({category: "negotiation_invalidated"});
  });

  test("renegotiation cancels delayed credentials before an old read or mutation can fetch", async () => {
    const operations = [
      (client: PlatformV2Client) => client.getWorkContext(projectA),
      (client: PlatformV2Client) => client.prepareMutation(
        IdempotencyKey("delayed-mutation"),
        {kind: "create_project", label: WorkContextLabel("Delayed"), repositories: []},
      ),
    ];
    for (const operation of operations) {
      const delayedCredential = deferred<string>();
      let credentialCalls = 0;
      const fetchedKinds: string[] = [];
      const fetchedAuthorizations: string[] = [];
      const transport = new HttpsPlatformV2Transport(
        "https://manage.example/api/platform/v2",
        () => {
          credentialCalls += 1;
          if (credentialCalls === 2) return delayedCredential.promise;
          return `token-${credentialCalls}`;
        },
        (async (_input, init) => {
          const body = typeof init?.body === "string" ? init.body : "";
          const message = decodeMessage(new TextEncoder().encode(body));
          fetchedKinds.push(message.envelope.kind);
          fetchedAuthorizations.push(new Headers(init?.headers).get("authorization") ?? "");
          if (fetchedKinds.length === 1) {
            return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
          }
          return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "platform_v2_refused", {
            category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2,
          }, PLATFORM_NEGOTIATION_MEDIA_TYPE);
        }) as typeof fetch,
      );
      const client = new PlatformV2Client(transport);
      await client.negotiate(offer);
      const oldOperation = operation(client);
      expect(credentialCalls).toBe(2);
      expect((await client.negotiate(offer)).kind).toBe("platform_v2_refused");
      await expect(oldOperation).rejects.toMatchObject({category: "negotiation_invalidated"});
      delayedCredential.resolve("stale-token");
      await Promise.resolve();
      expect(fetchedKinds).toEqual(["negotiate", "negotiate"]);
      expect(fetchedAuthorizations).toEqual(["Bearer token-1", "Bearer token-3"]);
    }
  });

  test("renegotiation fences delayed Basic credentials before stale fetch", async () => {
    const delayed = deferred<PlatformV2BasicCredential>();
    let credentialCalls = 0;
    const authorizations: string[] = [];
    const transport = new BasicHttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => {
        credentialCalls += 1;
        if (credentialCalls === 2) return delayed.promise;
        return new PlatformV2BasicCredential("ops", `password-${credentialCalls}`);
      },
      (async (_input, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        const message = decodeMessage(new TextEncoder().encode(body));
        authorizations.push(new Headers(init?.headers).get("authorization") ?? "");
        if (authorizations.length === 1) {
          return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
        }
        return canonicalResponse(message.envelope.requestId, "automonique.platform.negotiation", 1, "platform_v2_refused", {
          category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2,
        }, PLATFORM_NEGOTIATION_MEDIA_TYPE);
      }) as typeof fetch,
    );
    const client = new PlatformV2Client(transport);
    await client.negotiate(offer);
    const stale = client.getWorkContext(projectA);
    expect((await client.negotiate(offer)).kind).toBe("platform_v2_refused");
    await expect(stale).rejects.toMatchObject({category: "negotiation_invalidated"});
    delayed.resolve(new PlatformV2BasicCredential("ops", "stale-password"));
    await Promise.resolve();
    expect(authorizations).toEqual([
      "Basic b3BzOnBhc3N3b3JkLTE=",
      "Basic b3BzOnBhc3N3b3JkLTM=",
    ]);
  });

  test("fences an in-flight v2 response when renegotiation invalidates its generation", async () => {
    const response = deferred<PlatformV2Response>();
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", request: {kind: "get_work_context", identity: projectA}, result: response.promise},
      {lane: "negotiation", result: {kind: "platform_v2_refused", refusal: {category: "unsupported", explanation: "v2 disabled", schema: PLATFORM_SCHEMA_V2}}},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    const pending = client.getWorkContext(projectA);
    expect((await client.negotiate(offer)).kind).toBe("platform_v2_refused");
    response.resolve({kind: "work_context_record", record: record(projectA)});
    await expect(pending).rejects.toMatchObject({category: "negotiation_invalidated"});
    expect(client.negotiated).toBeNull();
  });

  test("aborts before credentials and races a nonresolving credential provider", async () => {
    let credentialCalls = 0;
    let fetchCalls = 0;
    const never = () => {
      credentialCalls += 1;
      return new Promise<string>(() => undefined);
    };
    const fetcher = (async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    }) as unknown as typeof fetch;
    const transport = new HttpsPlatformV2Transport("https://manage.example/api/platform/v2", never, fetcher);

    const already = new AbortController();
    already.abort("already");
    await expect(new PlatformV2Client(transport).negotiate(offer, already.signal)).rejects.toMatchObject({category: "aborted"});
    expect(credentialCalls).toBe(0);

    const later = new AbortController();
    const pending = new PlatformV2Client(transport).negotiate(offer, later.signal);
    later.abort("later");
    await expect(pending).rejects.toMatchObject({category: "aborted"});
    expect(credentialCalls).toBe(1);
    expect(fetchCalls).toBe(0);
  });
});
