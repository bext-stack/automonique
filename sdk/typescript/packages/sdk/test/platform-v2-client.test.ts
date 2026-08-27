// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  IdempotencyKey,
  MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PLATFORM_REVIEW_SCHEMA_V1,
  PLATFORM_SCHEMA_V1,
  PLATFORM_SCHEMA_V2,
  PlatformVersionNumber,
  ProjectId,
  UserWorkspaceId,
  WorkContextLabel,
  decodeMessage,
  encodeMessage,
  type JsonValue,
  type PlatformVersionOffer,
  type WorkContextIdentity,
} from "../../protocol/src/index.ts";
import {
  HttpsPlatformV2Transport,
  PLATFORM_NEGOTIATION_MEDIA_TYPE,
  PLATFORM_V2_MEDIA_TYPE,
  PlatformV2Client,
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

describe("canonical HTTPS Platform v2 client", () => {
  test("pins a credential-free HTTPS endpoint", () => {
    for (const invalid of [
      "http://manage.example/api/platform/v2",
      "https://user:password@manage.example/api/platform/v2",
      "https://manage.example/api/platform/v2?tenant=asserted",
      "https://manage.example/api/platform/v2#fragment",
    ]) {
      expect(() => new HttpsPlatformV2Transport(invalid, () => "token")).toThrow();
    }
    expect(new HttpsPlatformV2Transport("http://localhost/api/platform/v2", () => "token").endpoint)
      .toBe("http://localhost/api/platform/v2");
  });

  test("negotiates and sends an exact typed request without identity assertions", async () => {
    const requestIds = ["negotiation-1", "work-context-1"];
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
        return canonicalResponse("negotiation-1", "automonique.platform.negotiation", 1, "negotiated", negotiatedBody(2n), PLATFORM_NEGOTIATION_MEDIA_TYPE);
      }
      expect(headers.get("content-type")).toBe(PLATFORM_V2_MEDIA_TYPE);
      expect(message.envelope).toMatchObject({kind: "get_work_context", protocol: "automonique.platform", requestId: "work-context-1", version: 2});
      const encoded = body;
      expect(encoded).not.toContain("actor");
      expect(encoded).not.toContain("tenant");
      expect(encoded).not.toContain("authority_ceiling");
      return canonicalResponse("work-context-1", "automonique.platform", 2, "work_context_record", record(projectA), PLATFORM_V2_MEDIA_TYPE);
    }) as typeof fetch;
    const transport = new HttpsPlatformV2Transport(
      "https://manage.example/api/platform/v2",
      () => "token",
      fetcher,
      () => requestIds.shift() ?? "exhausted",
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
        () => "request-1",
      );
      await expect(new PlatformV2Client(transport).negotiate(offer)).rejects.toMatchObject({category: entry.category});
    }
  });

  test("rejects a valid response for another exact coordinate", async () => {
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", result: {kind: "work_context_record", record: record(projectB)}},
    ]);
    const client = new PlatformV2Client(adapter);
    await client.negotiate(offer);
    await expect(client.getWorkContext(projectA)).rejects.toMatchObject({category: "response_coordinate_mismatch"});
  });

  test("preserves the exact idempotency lookup and supports AbortSignal", async () => {
    const key = IdempotencyKey("mutation-1");
    const adapter = new DeterministicPlatformV2Adapter([
      {lane: "negotiation", result: {kind: "negotiated", negotiated: negotiatedBody(2n)}},
      {lane: "v2", result: {kind: "platform_v2_refused", refusal: {category: "unavailable", explanation: "pending", schema: PLATFORM_SCHEMA_V2}}},
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
      {lane: "v2", result: {kind: "review_receipt", receipt: {
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
});
