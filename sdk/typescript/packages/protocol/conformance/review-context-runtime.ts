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
  "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-review-v2.json",
  import.meta.url,
)).bytes();
const legacyFixture = await Bun.file(new URL(
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
const legacySnapshot = decodeReviewSnapshot(legacyFixture);
const roundTrip = encodeReviewSnapshot(snapshot);
if (roundTrip.length !== fixture.length || roundTrip.some((byte, index) => byte !== fixture[index])) {
  throw new Error("TypeScript review snapshot did not preserve Rust canonical bytes");
}
const legacyRoundTrip = encodeReviewSnapshot(legacySnapshot);
if (legacySnapshot.schema !== "automonique.platform/review/v1" || "authority" in legacySnapshot.proposals[0]! || legacyRoundTrip.length !== legacyFixture.length || legacyRoundTrip.some((byte, index) => byte !== legacyFixture[index])) {
  throw new Error("TypeScript changed the historical non-actionable review/v1 snapshot");
}
if (snapshot.attention.state !== "needs_you" || snapshot.attention.unread !== 1n || snapshot.comments[0]?.agent_state !== "sent") {
  throw new Error("TypeScript review snapshot changed authoritative meaning");
}
if (snapshot.schema !== "automonique.platform/review/v2") {
  throw new Error("authority-bearing fixture did not decode as review/v2");
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
const zeroCompletedRevisionCategory = category(() => encodeReviewActionReceipt({...receipt, outcome: "completed", reconciliation: "final", revision: 0n}));
const zeroConflictRevisionCategory = category(() => encodeReviewActionReceipt({...receipt, current_revision: 0n, outcome: "conflict", reconciliation: "final"}));
const text = new TextDecoder().decode(fixture);
const mixed = new TextEncoder().encode(text.replace("\"platform_version\":2", "\"platform_version\":1"));
const mixedCategory = category(() => decodeReviewSnapshot(mixed));
const idleSnapshot = decodeReviewSnapshot(encodeReviewSnapshot({
  ...snapshot,
  attention: {reason: null, source_revision: null, state: "idle", unread: 0n},
  attention_events: [],
}));
if (idleSnapshot.attention.state !== "idle" || idleSnapshot.attention_events.length !== 0) {
  throw new Error("empty attention event truth was not preserved as idle");
}

const gitAuthority = snapshot.proposals[0]!.authority;
const gitRequests: readonly ReviewActionRequest[] = [
  {...request, action: {kind: "commit", payload: {proposal_id: "proposal-1"}}, authority: gitAuthority, idempotency_key: "commit-1"},
  {...request, action: {kind: "stage", payload: {proposal_id: "proposal-1"}}, authority: gitAuthority, idempotency_key: "stage-1"},
  {...request, action: {kind: "unstage", payload: {proposal_id: "proposal-1"}}, authority: gitAuthority, idempotency_key: "unstage-1"},
];
const gitSnapshots = [
  snapshot,
  {...idleSnapshot, proposals: [{...snapshot.proposals[0]!, kind: "stage" as const, subject: null}]},
  {...idleSnapshot, proposals: [{...snapshot.proposals[0]!, kind: "unstage" as const, subject: null}]},
] as const;
gitRequests.forEach((gitRequest, index) => {
  validateReviewActionAgainstSnapshot(gitRequest, gitSnapshots[index]!);
  if (decodeReviewActionRequest(encodeReviewActionRequest(gitRequest)).action.kind !== gitRequest.action.kind) {
    throw new Error("typed Git action codec drifted");
  }
});
const legacyActionCategory = category(() => validateReviewActionAgainstSnapshot(gitRequests[0]!, legacySnapshot));

const batchTarget = {comment_id: "comment-1", expected_comment_revision: 2n} as const;
const batchRequest: ReviewActionRequest = {
  ...request,
  action: {kind: "batch_send_comments_to_agent", payload: {comments: [batchTarget]}},
  authority: snapshot.review.authority,
  idempotency_key: "batch-1",
};
validateReviewActionAgainstSnapshot(batchRequest, {...idleSnapshot, comments: [{...snapshot.comments[0]!, agent_state: "not_sent"}]});
const duplicateBatchCategory = category(() => validateReviewActionRequest({
  ...batchRequest,
  action: {kind: "batch_send_comments_to_agent", payload: {comments: [batchTarget, batchTarget]}},
}));

const conflictSnapshot = {
  ...idleSnapshot,
  files: [{...snapshot.files[0]!, conflict: "unresolved" as const}],
  proposals: [{...snapshot.proposals[0]!, kind: "resolve_conflict" as const, subject: null}],
};
const resolveRequest: ReviewActionRequest = {
  ...request,
  action: {kind: "resolve_conflict", payload: {file_id: "file-1", proposal_id: "proposal-1", resolution: "keep_current"}},
  authority: gitAuthority,
  idempotency_key: "resolve-1",
};
validateReviewActionAgainstSnapshot(resolveRequest, conflictSnapshot);
const gitIdentityCategory = category(() => validateReviewActionAgainstSnapshot({...resolveRequest, authority: {...gitAuthority, id: "wrong-git"}}, conflictSnapshot));

if (providerCategory !== "review_value_invalid" || authorityCategory !== "review_value_invalid" || authorityIdentityCategory !== "review_value_invalid" || attentionCategory !== "review_value_invalid" || u32Category !== "review_value_invalid" || attentionOriginCategory !== "review_value_invalid" || duplicateAttentionCategory !== "review_value_invalid" || duplicateAttentionOriginCategory !== "review_value_invalid" || zeroCompletedRevisionCategory !== "review_value_invalid" || zeroConflictRevisionCategory !== "review_value_invalid" || mixedCategory !== "review_invalid_body" || duplicateBatchCategory !== "review_value_invalid" || gitIdentityCategory !== "review_value_invalid" || legacyActionCategory !== "review_value_invalid") {
  throw new Error("Rust/TypeScript review refusals do not share categories");
}

console.log(JSON.stringify({
  action: actionDecoded.action.kind,
  attention: snapshot.attention.state,
  bytes: fixture.length,
  receipt: receiptDecoded.reconciliation,
  refusals: 14,
  schema: snapshot.schema,
}));
