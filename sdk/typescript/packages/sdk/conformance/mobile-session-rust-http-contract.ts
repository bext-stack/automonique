// SPDX-License-Identifier: Apache-2.0

import {
  MobileHistoryResyncError,
  MobileSessionHistoryClient,
} from "../src/mobile-session-client.ts";

declare const process: {readonly argv: readonly string[]};

const endpoint = process.argv[2];
const accessToken = process.argv[3];
if (endpoint === undefined || accessToken === undefined) {
  throw new Error("usage: mobile-session-rust-http-contract.ts ENDPOINT ACCESS_TOKEN");
}

const client = new MobileSessionHistoryClient(endpoint, () => accessToken);
const first = await client.snapshot("session-a", 99);
if (
  first.requestedLimit !== 99
  || first.appliedLimit !== 2
  || !first.hasMore
  || first.exclusiveCursor !== "0"
  || first.terminalCursor !== "3"
  || first.events.length !== 2
) throw new Error("Rust snapshot did not satisfy the generated history contract");

const second = await client.page("session-a", first.events[1]!.cursor, 99);
if (
  second.events.length !== 1
  || second.events[0]!.kind !== "unknown"
  || second.hasMore
  || second.terminalCursor !== "3"
) throw new Error("Rust continuation did not satisfy the generated history contract");

try {
  await client.page("session-a", "99", 1);
  throw new Error("cursor gap was accepted");
} catch (error) {
  if (!(error instanceof MobileHistoryResyncError) || error.resync.reason !== "cursor_gap") {
    throw error;
  }
}

console.log("TypeScript SDK passed the live Rust mobile session-history contract");
