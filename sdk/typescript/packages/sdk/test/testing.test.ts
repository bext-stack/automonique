// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {MobileSessionClient} from "../src/mobile-session-client.ts";
import {PlatformClient, SessionHistoryResyncError} from "../src/platform-client.ts";
import {
  emptyPlatformView,
  reduceReceipt,
  reduceSnapshot,
  reduceSubscription,
} from "../src/reducer.ts";
import {
  AmbiguousMutationFixtureError,
  DeterministicFixtureError,
  DeterministicPlatformAdapter,
  createRenderConformanceCorpus,
  createDeterministicSdkFixture,
  normalizeRenderConformanceCorpus,
} from "../src/testing.ts";

describe("deterministic SDK testing fixtures", () => {
  test("exports the shared render corpus with BigInt-safe immutable revisions", async () => {
    const raw = JSON.parse(await Bun.file(new URL(
      "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-render-conformance-v1.json",
      import.meta.url,
    )).text());
    const shared = normalizeRenderConformanceCorpus(raw);
    const exported = createRenderConformanceCorpus();

    expect(exported).toEqual(shared);
    expect(exported.cases.map(({id}) => id)).toEqual([
      "idle", "needs_you", "working", "blocked", "done",
    ]);
    expect(typeof exported.cases[0]?.input.revision).toBe("bigint");
    expect(exported.cases[0]?.input.revision).toBe(9_007_199_254_741_001n);
    expect(Object.isFrozen(exported.cases)).toBe(true);
    expect(() => normalizeRenderConformanceCorpus({
      ...raw,
      cases: [{...raw.cases[0], input: {...raw.cases[0].input, revision: 9_007_199_254_741_001}}],
    })).toThrow("not a canonical revision");
    expect(() => normalizeRenderConformanceCorpus({
      ...raw,
      cases: raw.cases.map((item: typeof raw.cases[number]) => item.id === "done"
        ? {...item, expected: {...item.expected, delivery: {...item.expected.delivery, semantic_key: "delivery.pending"}}}
        : item),
    })).toThrow("does not match canonical v1 semantics");
  });

  test("models exact duplicates, conflicting duplicates, gaps, and stale revisions", () => {
    const fixture = createDeterministicSdkFixture();
    const initial = reduceSnapshot(emptyPlatformView(), fixture.projection.snapshot);

    expect(reduceSubscription(initial, fixture.projection.duplicate).resyncRequired.size).toBe(0);
    for (const invalid of [
      fixture.projection.conflictingDuplicate,
      fixture.projection.gap,
      fixture.projection.staleRevision,
    ]) {
      expect(reduceSubscription(initial, invalid).resyncRequired.size).toBe(1);
    }
  });

  test("models an unknown history event and cursor-expiry resync without partial data", async () => {
    const fixture = createDeterministicSdkFixture();
    const adapter = new DeterministicPlatformAdapter([
      {
        method: "session_history_snapshot",
        result: {kind: "response", value: {kind: "session_history", value: fixture.history.unknownEvent}},
      },
      {
        method: "session_history_page",
        result: {kind: "response", value: fixture.history.cursorExpired},
      },
    ]);
    const client = new PlatformClient(adapter);

    const snapshot = await client.sessionHistorySnapshot(fixture.coordinates.session, 1n);
    expect(snapshot.events).toEqual([expect.objectContaining({kind: "unknown", source: "adapter_event"})]);
    const expired = await client.sessionHistoryPage(
      fixture.coordinates.session,
      snapshot.terminal_cursor,
      1n,
    ).catch((error: unknown) => error);
    expect(expired).toBeInstanceOf(SessionHistoryResyncError);
    expect(expired).toMatchObject({snapshotFrom: 20n, snapshotTo: 24n});
    expect(adapter.pendingSteps).toBe(0);
  });

  test("models an ambiguous mutation and exact idempotency-key reconciliation", async () => {
    const fixture = createDeterministicSdkFixture();
    const adapter = new DeterministicPlatformAdapter(fixture.mutation.ambiguousThenReconciled);
    const client = new MobileSessionClient(
      adapter,
      fixture.authorization,
      fixture.serverIdentity,
      () => fixture.now,
    );

    await expect(client.followUp(fixture.mutation.followUp))
      .rejects.toBeInstanceOf(AmbiguousMutationFixtureError);
    const reconciled = await client.reconcileReceipt(fixture.mutation.receiptLookup);
    expect(reconciled).toEqual(fixture.mutation.reconciledReceipt);
    expect(adapter.requests.map((request) => request.method)).toEqual([
      "session_follow_up",
      "get_receipt",
    ]);
    expect(adapter.requests[1]).toMatchObject({
      request: {id: null, idempotency_key: fixture.mutation.followUp.idempotencyKey},
    });

    const unknown = reduceReceipt(emptyPlatformView(), fixture.mutation.unknownReceipt);
    expect(unknown.receipts.get(fixture.mutation.unknownReceipt.id)?.outcome).toBe("unknown");
    expect(reduceReceipt(unknown, reconciled).receipts.get(reconciled.id)?.outcome).toBe("completed");
  });

  test("fails deterministic scripts closed on wrong order, exhaustion, and abort", async () => {
    const fixture = createDeterministicSdkFixture();
    const wrongOrder = new DeterministicPlatformAdapter([
      {method: "subscribe", result: {kind: "response", value: {kind: "subscription", value: fixture.projection.duplicate}}},
    ]);
    await expect(new PlatformClient(wrongOrder).snapshot())
      .rejects.toMatchObject({category: "unexpected_request"});

    const exhausted = new DeterministicPlatformAdapter([]);
    await expect(new PlatformClient(exhausted).snapshot())
      .rejects.toMatchObject({category: "script_exhausted"});

    const aborted = new AbortController();
    aborted.abort("fixture abort");
    await expect(new PlatformClient(exhausted).snapshot([], aborted.signal))
      .rejects.toBeInstanceOf(DeterministicFixtureError);
  });

  test("returns equivalent fixtures without sharing mutable scripts", () => {
    const first = createDeterministicSdkFixture();
    const second = createDeterministicSdkFixture();
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    expect(first.mutation.ambiguousThenReconciled).not.toBe(second.mutation.ambiguousThenReconciled);
  });
});
