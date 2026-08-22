// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  CursorTopic,
  PlatformEpochMillis,
  PlatformRevision,
  PlatformText,
  ReceiptId,
  ResourceId,
  type ActionReceipt,
  type PlatformCursor,
  type ResourceRecord,
  type Subscription,
} from "../../protocol/src/index.ts";
import {
  emptyPlatformView,
  reduceReceipt,
  reduceSnapshot,
  reduceSubscription,
  resourceKey,
} from "../src/reducer.ts";

function cursor(sequence: bigint): PlatformCursor {
  return {
    authority: "automonique",
    topic: CursorTopic("resources"),
    sequence: PlatformRevision(sequence),
  };
}

function record(revision: bigint, summary: string): ResourceRecord {
  return {
    resource: {authority: "automonique", kind: "run", id: ResourceId("run-1")},
    freshness: {
      state: "fresh",
      observed_at: PlatformEpochMillis(revision),
      revision: PlatformRevision(revision),
    },
    summary: PlatformText(summary),
  };
}

function page(events: Subscription["events"], sequence: bigint): Subscription {
  return {events, cursor: cursor(sequence)};
}

describe("platform presentation reducer", () => {
  test("applies a snapshot and consecutive events", () => {
    const initial = reduceSnapshot(emptyPlatformView(), {
      resources: [record(1n, "ready")],
      cursor: cursor(1n),
    });
    const updated = reduceSubscription(initial, page([
      {cursor: cursor(2n), resource: record(2n, "running")},
      {cursor: cursor(3n), resource: record(3n, "completed")},
    ], 3n));
    expect(updated.resources.get(resourceKey(record(1n, "ignored").resource))?.summary).toBe(PlatformText("completed"));
    expect(updated.resyncRequired.size).toBe(0);
  });

  test("accepts an exact duplicate but rejects a conflicting replay", () => {
    const snapshot = reduceSnapshot(emptyPlatformView(), {resources: [record(2n, "running")], cursor: cursor(2n)});
    const duplicate = reduceSubscription(snapshot, page([
      {cursor: cursor(2n), resource: record(2n, "running")},
    ], 2n));
    expect(duplicate.resyncRequired.size).toBe(0);
    const conflict = reduceSubscription(snapshot, page([
      {cursor: cursor(2n), resource: record(2n, "different")},
    ], 2n));
    expect(conflict.resyncRequired.size).toBe(1);
  });

  test("marks gaps, reordering, stale revisions, and cursor disagreement for resync", () => {
    const snapshot = reduceSnapshot(emptyPlatformView(), {resources: [record(4n, "running")], cursor: cursor(4n)});
    for (const invalid of [
      page([{cursor: cursor(6n), resource: record(6n, "gap")}], 6n),
      page([
        {cursor: cursor(5n), resource: record(5n, "next")},
        {cursor: cursor(4n), resource: record(4n, "old")},
      ], 5n),
      page([{cursor: cursor(5n), resource: record(3n, "stale")}], 5n),
      page([{cursor: cursor(5n), resource: record(5n, "next")}], 6n),
    ]) {
      expect(reduceSubscription(snapshot, invalid).resyncRequired.size).toBe(1);
    }
  });

  test("keeps unknown mutation outcomes distinct and ignores stale receipt updates", () => {
    const unknown: ActionReceipt = {
      action: "stop_run",
      explanation: PlatformText("delivery interrupted"),
      id: ReceiptId("receipt-1"),
      outcome: "unknown",
      recorded_at: PlatformEpochMillis(10n),
      revision: PlatformRevision(2n),
      target: record(1n, "run").resource,
    };
    const state = reduceReceipt(emptyPlatformView(), unknown);
    expect(state.receipts.get(unknown.id)?.outcome).toBe("unknown");
    const stale = {...unknown, outcome: "rejected" as const, revision: PlatformRevision(1n)};
    expect(reduceReceipt(state, stale)).toBe(state);
  });
});
