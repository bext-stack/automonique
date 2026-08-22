// SPDX-License-Identifier: Apache-2.0

import {expect, test} from "bun:test";

import {HttpsPlatformTransport, PlatformClient, PlatformTransportError} from "../src/platform-client.ts";

test("HTTPS transport carries authentication and validates schema", async () => {
  let authorization = "";
  const fetcher = (async (_input: string | URL | Request, init?: RequestInit) => {
    authorization = new Headers(init?.headers).get("authorization") ?? "";
    return new Response(JSON.stringify({
      ok: true,
      capabilities: {
        protocol: "automonique.platform",
        schema: "automonique.platform/v1",
        methods: ["capabilities"],
        transports: ["remote_https"],
      },
    }), {status: 200, headers: {"content-type": "application/json"}});
  }) as unknown as typeof fetch;
  const client = new PlatformClient(new HttpsPlatformTransport("https://manage.example/api/platform", () => "token", fetcher));
  const response = await client.capabilities();
  expect(response.kind).toBe("capabilities");
  expect(authorization).toBe("Bearer token");
});

test("HTTPS transport fails closed on a foreign schema", async () => {
  const fetcher = (async () => new Response(JSON.stringify({
    ok: true,
    capabilities: {protocol: "automonique.platform", schema: "foreign/v1", methods: [], transports: []},
  }))) as unknown as typeof fetch;
  const client = new PlatformClient(new HttpsPlatformTransport("https://manage.example/api/platform", () => "token", fetcher));
  await expect(client.capabilities()).rejects.toBeInstanceOf(PlatformTransportError);
});

test("receipt lookup requires exactly one durable coordinate", () => {
  const transport = {request: async () => { throw new Error("must not call"); }};
  const client = new PlatformClient(transport);
  expect(() => client.getReceipt({id: null, idempotency_key: null})).toThrow(PlatformTransportError);
});

test("HTTPS transport preserves typed remote refusals", async () => {
  const fetcher = (async () => new Response(JSON.stringify({
    ok: true,
    refusal: {outcome: "resync_required", explanation: "cursor_out_of_range"},
  }))) as unknown as typeof fetch;
  const client = new PlatformClient(new HttpsPlatformTransport("https://manage.example/api/platform", () => "token", fetcher));
  expect(await client.subscribe(null)).toEqual({
    kind: "refused",
    outcome: "resync_required",
    explanation: "cursor_out_of_range",
  });
});
