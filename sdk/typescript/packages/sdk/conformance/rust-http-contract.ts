// SPDX-License-Identifier: Apache-2.0

import {
  ClientId,
  ControlLeaseId,
  IdempotencyKey,
  PlatformParameter,
  PlatformRevision,
  ReceiptId,
  ResourceId,
  type ResourceCoordinate,
} from "../../protocol/src/index.ts";
import {
  HttpsPlatformTransport,
  PlatformClient,
  PlatformTransportError,
  SessionHistoryResyncError,
  emptyPlatformView,
  reduceSnapshot,
  reduceSubscription,
} from "../src/index.ts";

declare const process: {readonly argv: readonly string[]};

const endpoint = process.argv[2];
if (endpoint === undefined) throw new Error("missing Rust Platform HTTP endpoint");

let sequence = 0;
const client = new PlatformClient(new HttpsPlatformTransport(
  endpoint,
  () => "fixture-platform-token",
  fetch,
  () => `typescript-contract-${sequence += 1}`,
));

const session: ResourceCoordinate = {authority: "provider", id: ResourceId("session-1"), kind: "session"};
const historySession: ResourceCoordinate = {authority: "automonique", id: ResourceId("session-history-1"), kind: "session"};
const run: ResourceCoordinate = {authority: "automonique", id: ResourceId("run-1"), kind: "run"};

const capabilities = await client.capabilities();
if (capabilities.kind !== "capabilities") throw new Error("capabilities result mismatch");
if (!capabilities.value.transports.includes("remote_https")) throw new Error("route transport projection missing");

const snapshot = await client.snapshot([session]);
if (snapshot.kind !== "snapshot") throw new Error("snapshot result mismatch");
if (snapshot.value.cursor.sequence !== 9007199254740993n) throw new Error("64-bit cursor was rounded");
if (snapshot.value.resources[0]?.freshness.observed_at !== 9007199254740995n) {
  throw new Error("64-bit epoch was rounded");
}

const subscription = await client.subscribe(snapshot.value.cursor);
if (subscription.kind !== "subscription") throw new Error("subscription result mismatch");
if (subscription.value.cursor.sequence !== 9007199254740994n) throw new Error("subscription cursor mismatch");

const executed = await client.execute({
  action: "start_run",
  client: null,
  expected_revision: PlatformRevision(9007199254740993n),
  idempotency_key: IdempotencyKey("execute-1"),
  parameter: PlatformParameter("start"),
  target: run,
});
if (executed.kind !== "receipt" || executed.value.revision !== 9007199254740994n) {
  throw new Error("execute receipt mismatch");
}

if ((await client.getReceipt({client: null, id: ReceiptId("receipt-1"), idempotency_key: null})).kind !== "receipt") {
  throw new Error("receipt lookup mismatch");
}
if ((await client.listSessions("provider", null)).kind !== "sessions") throw new Error("session list mismatch");
if ((await client.attach(session, ClientId("client-1"))).kind !== "attached") throw new Error("attach mismatch");
if ((await client.detach(session, ClientId("client-1"))).kind !== "detached") throw new Error("detach mismatch");
if ((await client.claimControl(session, ClientId("client-1"), IdempotencyKey("claim-1"))).kind !== "control_claimed") {
  throw new Error("control claim mismatch");
}
if ((await client.releaseControl(
  session,
  ClientId("client-1"),
  ControlLeaseId("lease-1"),
  IdempotencyKey("release-1"),
)).kind !== "control_released") throw new Error("control release mismatch");

const historySnapshot = await client.sessionHistorySnapshot(historySession, 2n);
if (
  historySnapshot.from_cursor !== 9n
  || historySnapshot.terminal_cursor !== 11n
  || !historySnapshot.has_more
  || historySnapshot.events.map((event) => `${event.cursor}:${event.kind}`).join(",")
    !== "10:message,11:tool_state"
) {
  throw new Error("history snapshot ordering or cursor mismatch");
}
const historyPage = await client.sessionHistoryPage(historySession, historySnapshot.terminal_cursor, 2n);
if (
  historyPage.from_cursor !== 11n
  || historyPage.terminal_cursor !== 13n
  || historyPage.has_more
  || historyPage.events.map((event) => `${event.cursor}:${event.kind}`).join(",")
    !== "12:run_state,13:unknown"
) {
  throw new Error("history page resume mismatch");
}
const staleHistory = await client.sessionHistoryPage(historySession, 0n, 2n).catch((error: unknown) => error);
if (
  !(staleHistory instanceof SessionHistoryResyncError)
  || staleHistory.snapshotFrom !== 9n
  || staleHistory.snapshotTo !== 13n
) {
  throw new Error("stale history did not return an exact no-partial resync");
}
const wrongAuthority = await client.sessionHistorySnapshot(session, 2n).catch((error: unknown) => error);
if (!(wrongAuthority instanceof PlatformTransportError) || wrongAuthority.status !== 400) {
  throw new Error("history authority/session boundary did not fail closed");
}

let view = reduceSnapshot(emptyPlatformView(), snapshot.value);
view = reduceSubscription(view, subscription.value);
const duplicate = reduceSubscription(view, subscription.value);
if (duplicate.resyncRequired.size !== 0) throw new Error("exact duplicate required a resync");

const gapSequence = subscription.value.cursor.sequence + 2n;
const gap = reduceSubscription(view, {
  cursor: {...subscription.value.cursor, sequence: gapSequence as typeof subscription.value.cursor.sequence},
  events: [{
    cursor: {...subscription.value.cursor, sequence: gapSequence as typeof subscription.value.cursor.sequence},
    resource: subscription.value.events[0]!.resource,
  }],
});
if (gap.resyncRequired.size !== 1) throw new Error("gap did not require a resync");

const staleSequence = subscription.value.cursor.sequence + 1n;
const stale = reduceSubscription(view, {
  cursor: {...subscription.value.cursor, sequence: staleSequence as typeof subscription.value.cursor.sequence},
  events: [{
    cursor: {...subscription.value.cursor, sequence: staleSequence as typeof subscription.value.cursor.sequence},
    resource: {
      ...subscription.value.events[0]!.resource,
      freshness: {...subscription.value.events[0]!.resource.freshness, revision: PlatformRevision(1n)},
    },
  }],
});
if (stale.resyncRequired.size !== 1) throw new Error("stale revision did not require a resync");

const refusalOutcomes = ["accepted", "completed", "conflict", "rejected", "resync_required", "unknown"] as const;
for (const outcome of refusalOutcomes) {
  const response = await client.capabilities();
  if (response.kind !== "refused" || response.outcome !== outcome) {
    throw new Error(`refusal outcome mismatch: ${outcome}`);
  }
}

console.log("TypeScript SDK passed the live Rust Platform HTTP contract");
