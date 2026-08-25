// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  MOBILE_SESSION_MEDIA_TYPE,
  parseCanonical,
  toCanonicalBytes,
  type JsonValue,
} from "../../protocol/src/index.ts";
import {
  MobileHistoryResyncError,
  MobileSessionHistoryClient,
} from "../src/mobile-session-client.ts";

const endpoint = "https://mobile.example.test/api/mobile/session-history";

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
  throw new Error("unsupported fixture");
}

function response(value: unknown, status = 200): Response {
  return new Response(new TextDecoder().decode(toCanonicalBytes(json(value))), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": MOBILE_SESSION_MEDIA_TYPE,
    },
  });
}

function event(cursor: string, kind: "message" | "tool_state" | "run_state" | "unknown") {
  return {
    at_ms: "9007199254740993",
    cursor,
    kind,
    message_role: kind === "message" ? "assistant" : null,
    message_text: kind === "message" ? `message-${cursor}` : null,
    run_id: "run-1",
    run_state: kind === "run_state" ? "completed" : null,
    tool_state: kind === "tool_state" ? "succeeded" : null,
    unknown_kind: kind === "unknown" ? "future_event" : null,
  };
}

function page(
  exclusiveCursor: string,
  terminalCursor: string,
  events: readonly unknown[],
  hasMore: boolean,
  requestedLimit = 999,
  appliedLimit = 2,
) {
  return {
    applied_limit: appliedLimit,
    events,
    exclusive_cursor: exclusiveCursor,
    has_more: hasMore,
    requested_limit: requestedLimit,
    schema: "automonique.mobile-session/v1",
    session_id: "session-a",
    terminal_cursor: terminalCursor,
  };
}

describe("mobile session history client", () => {
  test("iterates snapshot and resumed pages with clamped limits and lossless cursors", async () => {
    const requests: RequestInit[] = [];
    const responses = [
      response(page("9007199254740991", "9007199254740994", [
        event("9007199254740992", "message"),
        event("9007199254740993", "tool_state"),
      ], true)),
      response(page("9007199254740993", "9007199254740994", [
        event("9007199254740994", "unknown"),
      ], false)),
    ];
    const fetcher = (async (_input: string | URL | Request, init?: RequestInit) => {
      requests.push(init ?? {});
      const next = responses.shift();
      if (next === undefined) throw new Error("unexpected request");
      return next;
    }) as typeof fetch;
    const client = new MobileSessionHistoryClient(endpoint, () => "fixture-token", fetcher);
    const received = [];
    for await (const item of client.events("session-a", 999, "9007199254740991")) {
      received.push(item);
    }
    expect(received.map((item) => [item.cursor, item.kind])).toEqual([
      ["9007199254740992", "message"],
      ["9007199254740993", "tool_state"],
      ["9007199254740994", "unknown"],
    ]);
    expect(received[0]?.atMs).toBe("9007199254740993");
    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.credentials).toBe("omit");
      expect(request.redirect).toBe("error");
      expect(new Headers(request.headers).get("content-type")).toBe(MOBILE_SESSION_MEDIA_TYPE);
    }
    const firstBody = requests[0]?.body;
    if (typeof firstBody !== "string") throw new Error("missing request body");
    expect(parseCanonical(new TextEncoder().encode(firstBody))).toEqual(json({
      cursor: "9007199254740991",
      limit: 999,
      operation: "page",
      session_id: "session-a",
    }));
  });

  test("returns a typed resync error and never yields a partial expired page", async () => {
    const resync = {
      earliest_cursor: "12",
      reason: "retention_expired",
      requested_cursor: "3",
      schema: "automonique.mobile-session/v1",
      session_id: "session-a",
      terminal_cursor: "20",
    };
    const client = new MobileSessionHistoryClient(
      endpoint,
      () => "fixture-token",
      (async () => response(resync, 409)) as typeof fetch,
    );
    await expect(client.page("session-a", "3", 10)).rejects.toBeInstanceOf(MobileHistoryResyncError);
    await expect(client.page("session-a", "3", 10)).rejects.toMatchObject({
      resync: {reason: "retention_expired", earliest_cursor: "12"},
    });
  });

  test("rejects duplicate, gap, and semantically impossible event pages", async () => {
    for (const fixture of [
      page("0", "2", [event("1", "message"), event("1", "message")], false),
      page("0", "2", [event("2", "message")], false),
      page("0", "1", [{...event("1", "message"), tool_state: "running"}], false),
    ]) {
      const client = new MobileSessionHistoryClient(
        endpoint,
        () => "fixture-token",
        (async () => response(fixture)) as typeof fetch,
      );
      await expect(client.snapshot("session-a", 2)).rejects.toMatchObject({status: 502});
    }
  });
});
