// SPDX-License-Identifier: Apache-2.0

import {
  decodeReviewActionReceipt,
  decodeReviewActionRequest,
  decodeReviewSnapshot,
  encodeReviewActionReceipt,
  encodeReviewActionRequest,
  encodeReviewSnapshot,
  validateReviewActionRequest,
  type ReviewActionReceipt,
  type ReviewActionRequest,
} from "../generated/review-context.ts";
import {RefusalError} from "../generated/runtime.ts";

declare const Bun: {file(path: URL): {bytes(): Promise<Uint8Array>}};

const fixture = await Bun.file(new URL(
  "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-review-v1.json",
  import.meta.url,
)).bytes();
const actionFixture = await Bun.file(new URL(
  "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-review-action-v1.json",
  import.meta.url,
)).bytes();
const receiptFixture = await Bun.file(new URL(
  "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-review-receipt-v1.json",
  import.meta.url,
)).bytes();
const snapshot = decodeReviewSnapshot(fixture);
const roundTrip = encodeReviewSnapshot(snapshot);
if (roundTrip.length !== fixture.length || roundTrip.some((byte, index) => byte !== fixture[index])) {
  throw new Error("TypeScript review snapshot did not preserve Rust canonical bytes");
}
if (snapshot.attention.state !== "needs_you" || snapshot.attention.unread !== 1n || snapshot.comments[0]?.agent_state !== "sent") {
  throw new Error("TypeScript review snapshot changed authoritative meaning");
}

const request: ReviewActionRequest = {
  action: {kind: "rerun_check", payload: {check_id: "check-1", expected_check_revision: 7n}},
  actor: "actor-1",
  authentication: "user_session",
  authority: {id: "authority-1", kind: "ci"},
  expected_revision: 9n,
  idempotency_key: "idem-1",
  platform_version: 2n,
  schema: "automonique.platform/review/v1",
  workspace: snapshot.workspace,
};
const actionBytes = encodeReviewActionRequest(request);
const actionDecoded = decodeReviewActionRequest(actionBytes);
if (actionDecoded.action.kind !== "rerun_check" || actionDecoded.expected_revision !== 9n || actionDecoded.idempotency_key !== "idem-1") {
  throw new Error("typed review action lost exact-revision or idempotency meaning");
}
if (actionBytes.length !== actionFixture.length || actionBytes.some((byte, index) => byte !== actionFixture[index])) {
  throw new Error("TypeScript review action did not preserve Rust canonical bytes");
}

const receipt: ReviewActionReceipt = {
  action_id: "action-1",
  actor: "actor-1",
  current_revision: null,
  idempotency_key: "idem-1",
  outcome: "unknown",
  platform_version: 2n,
  receipt_id: "receipt-1",
  reconciliation: "poll_receipt",
  revision: null,
  schema: "automonique.platform/review/v1",
};
const receiptDecoded = decodeReviewActionReceipt(encodeReviewActionReceipt(receipt));
if (receiptDecoded.outcome !== "unknown" || receiptDecoded.reconciliation !== "poll_receipt") {
  throw new Error("ambiguous write no longer reconciles by receipt");
}
const receiptBytes = encodeReviewActionReceipt(receipt);
if (receiptBytes.length !== receiptFixture.length || receiptBytes.some((byte, index) => byte !== receiptFixture[index])) {
  throw new Error("TypeScript review receipt did not preserve Rust canonical bytes");
}

function category(run: () => unknown): string {
  try { run(); } catch (error) { if (error instanceof RefusalError) return error.category; throw error; }
  throw new Error("expected refusal");
}
const providerCategory = category(() => validateReviewActionRequest({...request, authentication: "provider_session"}));
const authorityCategory = category(() => validateReviewActionRequest({...request, authority: {...request.authority, kind: "pull_request"}}));
const text = new TextDecoder().decode(fixture);
const v1 = new TextEncoder().encode(text.replace("\"platform_version\":2", "\"platform_version\":1"));
const mixedCategory = category(() => decodeReviewSnapshot(v1));
if (providerCategory !== "review_value_invalid" || authorityCategory !== "review_value_invalid" || mixedCategory !== "review_invalid_body") {
  throw new Error("Rust/TypeScript review refusals do not share categories");
}

console.log(JSON.stringify({
  action: actionDecoded.action.kind,
  attention: snapshot.attention.state,
  bytes: fixture.length,
  receipt: receiptDecoded.reconciliation,
  refusals: 3,
  schema: snapshot.schema,
}));
