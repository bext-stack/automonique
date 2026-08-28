// SPDX-License-Identifier: Apache-2.0

import {readFileSync} from "node:fs";

import {
  MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
  MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
  PLATFORM_NEGOTIATION_MAJOR,
  PLATFORM_NEGOTIATION_PROTOCOL,
  PLATFORM_V2_MAJOR,
  ReviewConfirmationDigest,
  decodePlatformNegotiationRequest,
  decodePlatformNegotiationResponse,
  decodePlatformNegotiationResponseFrame,
  decodePlatformV2Response,
  decodePlatformV2ResponseFrame,
  encodePlatformNegotiationRequest,
  encodePlatformNegotiationRequestFrame,
  encodePlatformV2Request,
  encodePlatformV2RequestFrame,
} from "../generated/platform-v2-transport.ts";
import {IdempotencyKey, PLATFORM_PROTOCOL, PlatformRequestId} from "../generated/platform.ts";
import {
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PLATFORM_SCHEMA_V2,
  MAX_MUTATION_CANONICAL_BYTES,
  PlatformVersionNumber,
  ProjectId,
  SupportedPlatformVersionNumber,
  UserWorkspaceId,
  WorkContextRevision,
  encodeNegotiatedPlatform,
  type PlatformVersionOffer,
} from "../generated/work-context.ts";
import {
  RefusalError,
  WireError,
  encodeFrameWithLimit,
  encodeMessage,
  parseCanonical,
} from "../generated/runtime.ts";
import {MAX_FRAME_BYTES, encodeFrame} from "../src/canonical.ts";

const encoder = new TextEncoder();

function expectWireRefusal(label: string, action: () => unknown): void {
  try {
    action();
  } catch (error) {
    if (error instanceof WireError) return;
    throw error;
  }
  throw new Error(`${label} was accepted`);
}

function expectReviewRefusal(label: string, action: () => unknown): void {
  try {
    action();
  } catch (error) {
    if (error instanceof RefusalError) return;
    throw error;
  }
  throw new Error(`${label} was accepted`);
}

function responsePayload(requestId: ReturnType<typeof PlatformRequestId>, kind: string, body: Uint8Array): Uint8Array {
  return encodeMessage({
    envelope: {protocol: PLATFORM_PROTOCOL, version: PLATFORM_V2_MAJOR, requestId, kind},
    body: parseCanonical(body),
  });
}

const fixture = readFileSync(
  "../../../../rust/crates/automonique-protocol/fixtures/platform-v2-transport-v1.txt",
  "utf8",
).trimEnd().split("\n");
if (fixture.length !== 4) throw new Error("transport fixture line count");

const offer: PlatformVersionOffer = {
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(1n), PlatformVersionNumber(2n)],
};
const negotiationId = PlatformRequestId("transport-negotiate");
const negotiation = encodePlatformNegotiationRequest(negotiationId, {kind: "negotiate", offer});
if (new TextDecoder().decode(negotiation) !== fixture[0]) throw new Error("negotiation bytes drifted from Rust");
if (decodePlatformNegotiationRequest(negotiation).request_id !== negotiationId) throw new Error("negotiation request correlation");
const negotiationFrame = encodePlatformNegotiationRequestFrame(negotiationId, {kind: "negotiate", offer});
if (negotiationFrame.length !== negotiation.length + 4) throw new Error("negotiation frame bound");

const v2Id = PlatformRequestId("transport-v2");
const v2 = encodePlatformV2Request(v2Id, {
  kind: "get_work_context",
  identity: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
});
if (new TextDecoder().decode(v2) !== fixture[1]) throw new Error("v2 bytes drifted from Rust");
const v2Frame = encodePlatformV2RequestFrame(v2Id, {
  kind: "get_work_context",
  identity: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
});
if (v2Frame.length !== v2.length + 4) throw new Error("v2 frame bound");

const capabilitiesId = PlatformRequestId("transport-capabilities");
const capabilitiesRequest = encodePlatformV2Request(capabilitiesId, {kind: "get_lifecycle_capabilities"});
if (new TextDecoder().decode(capabilitiesRequest) !== fixture[2]) throw new Error("capability bytes drifted from Rust");
const capabilityOperations = [
  "create_attempt_workspace",
  "create_checkout",
  "create_host_setup",
  "resume_attempt_workspace",
  "resume_session",
].map((effect_kind) => ({
  available: effect_kind === "create_checkout" || effect_kind === "create_host_setup",
  category: effect_kind === "create_checkout" || effect_kind === "create_host_setup" ? null : "platform_v2_lifecycle_adapter_pending",
  effect_kind,
  project: "project-1",
}));
const capabilityBody = {operations: capabilityOperations, projects: ["project-1"], schema: PLATFORM_SCHEMA_V2};
const capabilityResponse = responsePayload(
  capabilitiesId,
  "lifecycle_capabilities",
  encoder.encode(JSON.stringify(capabilityBody)),
);
if (new TextDecoder().decode(capabilityResponse) !== fixture[3]) throw new Error("capability response bytes drifted from Rust");
const decodedCapabilities = decodePlatformV2Response(
  capabilityResponse,
  capabilitiesId,
  "get_lifecycle_capabilities",
);
if (decodedCapabilities.kind !== "lifecycle_capabilities" || decodedCapabilities.capabilities.operations.length !== 5) throw new Error("lifecycle capabilities response");
let duplicateProjectsRefused = false;
try {
  decodePlatformV2Response(
    responsePayload(capabilitiesId, "lifecycle_capabilities", encoder.encode(JSON.stringify({...capabilityBody, projects: ["project-1", "project-1"]}))),
    capabilitiesId,
    "get_lifecycle_capabilities",
  );
} catch (error) {
  duplicateProjectsRefused = error instanceof WireError;
}
if (!duplicateProjectsRefused) throw new Error("duplicate lifecycle projects accepted");
for (const [label, body] of [
  ["incomplete lifecycle matrix", {...capabilityBody, operations: capabilityOperations.slice(1)}],
  ["contradictory lifecycle state", {...capabilityBody, operations: capabilityOperations.map((operation, index) => index === 0 ? {...operation, available: true} : operation)}],
  ["foreign lifecycle project", {...capabilityBody, operations: capabilityOperations.map((operation, index) => index === 0 ? {...operation, project: "project-2"} : operation)}],
] as const) {
  expectWireRefusal(label, () => decodePlatformV2Response(
    responsePayload(capabilitiesId, "lifecycle_capabilities", encoder.encode(JSON.stringify(body))),
    capabilitiesId,
    "get_lifecycle_capabilities",
  ));
}

for (const [label, comments] of [
  ["empty review comment batch", []],
  [
    "duplicate review comment batch",
    [
      {comment_id: "comment-1", expected_comment_revision: 1n},
      {comment_id: "comment-1", expected_comment_revision: 1n},
    ],
  ],
] as const) {
  expectReviewRefusal(label, () => encodePlatformV2Request(v2Id, {
    kind: "execute_review_action",
    request: {
      action: {kind: "batch_send_comments_to_agent", payload: {comments}},
      expected_revision: WorkContextRevision(1n),
      idempotency_key: IdempotencyKey("review-action-batch"),
      workspace: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
    },
  }));
}
encodePlatformV2Request(v2Id, {
  kind: "execute_review_action",
  request: {
    action: {
      kind: "batch_send_comments_to_agent",
      payload: {comments: [{comment_id: "comment-1", expected_comment_revision: 1n}]},
    },
    expected_revision: WorkContextRevision(1n),
    idempotency_key: IdempotencyKey("review-action-batch"),
    workspace: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
  },
});
expectWireRefusal("unconfirmed check rerun", () => encodePlatformV2Request(v2Id, {
  kind: "execute_review_action",
  request: {
    action: {kind: "rerun_check", payload: {check_id: "check-1", expected_check_revision: 7n}},
    expected_revision: WorkContextRevision(9n),
    idempotency_key: IdempotencyKey("review-rerun"),
    workspace: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
  },
}));
encodePlatformV2Request(v2Id, {
  kind: "execute_review_action",
  request: {
    action: {kind: "rerun_check", payload: {check_id: "check-1", expected_check_revision: 7n}},
    confirmation_digest: ReviewConfirmationDigest("ab".repeat(32)),
    expected_revision: WorkContextRevision(9n),
    idempotency_key: IdempotencyKey("review-rerun"),
    workspace: {kind: "user_workspace", id: UserWorkspaceId("workspace-1")},
  },
});

const attentionId = PlatformRequestId("transport-attention");
const attentionRequest = encodePlatformV2Request(attentionId, {
  kind: "get_attention_source_snapshot",
  request: {
    source: {kind: "provider_session", id: "provider-feed-1"},
    project: ProjectId("project-1"),
    user_workspace: UserWorkspaceId("workspace-1"),
  },
});
if (!new TextDecoder().decode(attentionRequest).includes('"kind":"get_attention_source_snapshot"')) throw new Error("attention request kind");
const attentionFixture = readFileSync(
  "../../../../rust/crates/automonique-protocol/fixtures/platform-v2-attention-v1.json",
);
const attentionResponse = responsePayload(attentionId, "attention_source_snapshot", attentionFixture);
const decodedAttention = decodePlatformV2Response(
  attentionResponse,
  attentionId,
  "get_attention_source_snapshot",
);
if (decodedAttention.kind !== "attention_source_snapshot"
  || decodedAttention.snapshot.revision !== 7n
  || decodedAttention.snapshot.items[0]?.platform_session?.id !== "session-1") {
  throw new Error("attention response");
}
const attentionText = new TextDecoder().decode(attentionFixture);
for (const [label, hostile] of [
  ["attention unknown local target", attentionText.replace("{", '{"tab_id":"local-tab",')],
  ["attention state reason mismatch", attentionText.replace('"state":"needs_you"', '"state":"done"')],
  ["attention provider session missing", attentionText.replace('{"authority":"automonique","id":"session-1","kind":"session"}', "null")],
  ["attention client coordinate", attentionText.replace('"authority":"automonique"', '"authority":"client"')],
] as const) {
  expectWireRefusal(label, () => decodePlatformV2Response(
    responsePayload(attentionId, "attention_source_snapshot", encoder.encode(hostile)),
    attentionId,
    "get_attention_source_snapshot",
  ));
}

const negotiatedBody = parseCanonical(encodeNegotiatedPlatform({
  schema: PLATFORM_SCHEMA_V2,
  version: SupportedPlatformVersionNumber(2n),
  work_context: "v2_structured",
}));
const negotiatedPayload = encodeMessage({
  envelope: {protocol: PLATFORM_NEGOTIATION_PROTOCOL, version: PLATFORM_NEGOTIATION_MAJOR, requestId: negotiationId, kind: "negotiated"},
  body: negotiatedBody,
});
if (decodePlatformNegotiationResponse(negotiatedPayload, negotiationId, offer).kind !== "negotiated") throw new Error("negotiated response");
const negotiatedFrame = encodeFrameWithLimit(negotiatedPayload, MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES);
if (decodePlatformNegotiationResponseFrame(negotiatedFrame, negotiationId, offer).kind !== "negotiated") throw new Error("negotiated response frame");
let unofferedRefused = false;
try {
  decodePlatformNegotiationResponse(negotiatedPayload, negotiationId, {
    schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
    versions: [PlatformVersionNumber(1n)],
  });
} catch (error) {
  unofferedRefused = error instanceof WireError;
}
if (!unofferedRefused) throw new Error("unoffered selection accepted");

const refusalPayload = encodeMessage({
  envelope: {protocol: PLATFORM_PROTOCOL, version: PLATFORM_V2_MAJOR, requestId: v2Id, kind: "platform_v2_refused"},
  body: parseCanonical(new TextEncoder().encode('{"category":"platform_v2_unavailable","explanation":"host wiring is not available","schema":"automonique.platform/v2"}')),
});
if (decodePlatformV2Response(refusalPayload, v2Id, "get_work_context").kind !== "platform_v2_refused") throw new Error("v2 refusal");
const refusalFrame = encodeFrameWithLimit(refusalPayload, MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES);
if (decodePlatformV2ResponseFrame(refusalFrame, v2Id, "get_work_context").kind !== "platform_v2_refused") throw new Error("v2 refusal frame");

for (const [label, category, explanation] of [
  ["control category", "bad\ncategory", "host wiring is not available"],
  ["control explanation", "platform_v2_unavailable", "bad\texplanation"],
  ["unicode control explanation", "platform_v2_unavailable", "bad\u0085explanation"],
] as const) {
  const payload = responsePayload(
    v2Id,
    "platform_v2_refused",
    encoder.encode(JSON.stringify({category, explanation, schema: PLATFORM_SCHEMA_V2})),
  );
  expectWireRefusal(label, () => decodePlatformV2Response(payload, v2Id, "get_work_context"));
}

const rawReceipt = {
  approval_id: null,
  id: null,
  idempotency_key: null,
  outcome: null,
  preview: null,
  preview_digest: null,
  recorded_at_ms: null,
  request_digest: null,
  resulting_revision: null,
  schema: PLATFORM_SCHEMA_V2,
};
if (decodePlatformV2Response(
  responsePayload(v2Id, "mutation_approval", encoder.encode(JSON.stringify({approval: null, schema: PLATFORM_SCHEMA_V2}))),
  v2Id,
  "decide_mutation",
).kind !== "mutation_approval") throw new Error("structurally valid raw approval was refused");
if (decodePlatformV2Response(
  responsePayload(v2Id, "mutation_receipt", encoder.encode(JSON.stringify(rawReceipt))),
  v2Id,
  "get_mutation_receipt",
).kind !== "mutation_receipt") throw new Error("structurally valid raw receipt was refused");

const oversizedApproval = encoder.encode(JSON.stringify({
  approval: Array.from({length: 5}, () => "x".repeat(60 * 1024)),
  schema: PLATFORM_SCHEMA_V2,
}));
if (oversizedApproval.length <= MAX_MUTATION_CANONICAL_BYTES) throw new Error("oversized approval fixture is not oversized");

const malformedLifecycleResponses = [
  [
    "approval missing field",
    "mutation_approval",
    "decide_mutation",
    encoder.encode(JSON.stringify({schema: PLATFORM_SCHEMA_V2})),
  ],
  [
    "approval extra field",
    "mutation_approval",
    "decide_mutation",
    encoder.encode(JSON.stringify({approval: null, extra: true, schema: PLATFORM_SCHEMA_V2})),
  ],
  [
    "receipt wrong schema",
    "mutation_receipt",
    "get_mutation_receipt",
    encoder.encode(JSON.stringify({
      approval_id: null,
      id: null,
      idempotency_key: null,
      outcome: null,
      preview: null,
      preview_digest: null,
      recorded_at_ms: null,
      request_digest: null,
      resulting_revision: null,
      schema: "automonique.platform/v1",
    })),
  ],
  [
    "oversized approval",
    "mutation_approval",
    "decide_mutation",
    oversizedApproval,
  ],
] as const;
for (const [label, kind, requestKind, body] of malformedLifecycleResponses) {
  const payload = responsePayload(v2Id, kind, body);
  expectWireRefusal(label, () => decodePlatformV2Response(payload, v2Id, requestKind));
}

const maximalResponse = new Uint8Array(MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES);
if (encodeFrameWithLimit(maximalResponse, MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES).length !== maximalResponse.length + 4) throw new Error("maximal response frame");
if (maximalResponse.length <= MAX_FRAME_BYTES) throw new Error("v2 response did not exceed the unchanged v1 ceiling");
let v1CeilingPreserved = false;
try {
  encodeFrame(maximalResponse);
} catch (error) {
  v1CeilingPreserved = error instanceof WireError;
}
if (!v1CeilingPreserved) throw new Error("v1 frame ceiling widened");

console.log(JSON.stringify({capability_bytes: capabilitiesRequest.length, capability_response_bytes: capabilityResponse.length, duplicate_projects_refused: duplicateProjectsRefused, fixture_lines: fixture.length, negotiation_bytes: negotiation.length, unoffered_refused: unofferedRefused, v1_ceiling_preserved: v1CeilingPreserved, v2_bytes: v2.length}));
