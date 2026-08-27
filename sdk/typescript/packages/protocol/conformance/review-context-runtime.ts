// SPDX-License-Identifier: Apache-2.0

import {
  decodeReviewActionReceipt,
  decodeReviewActionRequest,
  decodeReviewSnapshot,
  encodeReviewActionReceipt,
  encodeReviewActionRequest,
  encodeReviewSnapshot,
  validateReviewActionRequest,
  validateReviewActionAgainstSnapshot,
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
validateReviewActionAgainstSnapshot(request, snapshot);
const authorityIdentityCategory = category(() => validateReviewActionAgainstSnapshot({...request, authority: {...request.authority, id: "another-ci"}}, snapshot));
const attentionCategory = category(() => encodeReviewSnapshot({...snapshot, attention: {...snapshot.attention, unread: 2n}}));
const maximumU32 = encodeReviewSnapshot({...snapshot, files: [{...snapshot.files[0]!, hunks: [{...snapshot.files[0]!.hunks[0]!, old_start: 4294967295n}]}]});
decodeReviewSnapshot(maximumU32);
const u32Category = category(() => encodeReviewSnapshot({...snapshot, files: [{...snapshot.files[0]!, hunks: [{...snapshot.files[0]!.hunks[0]!, old_start: 4294967296n}]}]}));
const attentionOriginCategory = category(() => encodeReviewSnapshot({...snapshot, attention_events: [{...snapshot.attention_events[0]!, origin: {...snapshot.attention_events[0]!.origin, authority: {...snapshot.attention_events[0]!.origin.authority, id: "forged-review"}}}]}));
const duplicateAttentionCategory = category(() => encodeReviewSnapshot({...snapshot, attention_events: [snapshot.attention_events[0]!, snapshot.attention_events[0]!]}));
const duplicateAttentionOriginCategory = category(() => encodeReviewSnapshot({...snapshot, attention_events: [snapshot.attention_events[0]!, {...snapshot.attention_events[0]!, id: "attention-2"}]}));
const staleAttentionSourceCategory = category(() => encodeReviewSnapshot({...snapshot, review: {...snapshot.review, freshness: {...snapshot.review.freshness, state: "stale"}}}));
const futureProjectionCategory = category(() => encodeReviewSnapshot({...snapshot, checks: [{...snapshot.checks[0]!, freshness: {...snapshot.checks[0]!.freshness, observed_revision: snapshot.revision + 1n}}]}));
const zeroCompletedRevisionCategory = category(() => encodeReviewActionReceipt({...receipt, outcome: "completed", reconciliation: "final", revision: 0n}));
const zeroConflictRevisionCategory = category(() => encodeReviewActionReceipt({...receipt, current_revision: 0n, outcome: "conflict", reconciliation: "final"}));
const text = new TextDecoder().decode(fixture);
const v1 = new TextEncoder().encode(text.replace("\"platform_version\":2", "\"platform_version\":1"));
const mixedCategory = category(() => decodeReviewSnapshot(v1));
if (providerCategory !== "review_value_invalid" || authorityCategory !== "review_value_invalid" || authorityIdentityCategory !== "review_value_invalid" || attentionCategory !== "review_value_invalid" || u32Category !== "review_value_invalid" || attentionOriginCategory !== "review_value_invalid" || duplicateAttentionCategory !== "review_value_invalid" || duplicateAttentionOriginCategory !== "review_value_invalid" || staleAttentionSourceCategory !== "review_value_invalid" || futureProjectionCategory !== "review_value_invalid" || zeroCompletedRevisionCategory !== "review_value_invalid" || zeroConflictRevisionCategory !== "review_value_invalid" || mixedCategory !== "review_invalid_body") {
  throw new Error("Rust/TypeScript review refusals do not share categories");
}

console.log(JSON.stringify({
  action: actionDecoded.action.kind,
  attention: snapshot.attention.state,
  bytes: fixture.length,
  receipt: receiptDecoded.reconciliation,
  refusals: 13,
  schema: snapshot.schema,
}));
