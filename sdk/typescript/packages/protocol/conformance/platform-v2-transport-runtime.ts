// SPDX-License-Identifier: Apache-2.0

import {readFileSync} from "node:fs";

import {
  MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
  MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
  PLATFORM_NEGOTIATION_MAJOR,
  PLATFORM_NEGOTIATION_PROTOCOL,
  PLATFORM_V2_MAJOR,
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
import {PLATFORM_PROTOCOL, PlatformRequestId} from "../generated/platform.ts";
import {
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PLATFORM_SCHEMA_V2,
  MAX_MUTATION_CANONICAL_BYTES,
  PlatformVersionNumber,
  SupportedPlatformVersionNumber,
  UserWorkspaceId,
  encodeNegotiatedPlatform,
  type PlatformVersionOffer,
} from "../generated/work-context.ts";
import {
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
if (fixture.length !== 2) throw new Error("transport fixture line count");

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

console.log(JSON.stringify({fixture_lines: fixture.length, negotiation_bytes: negotiation.length, unoffered_refused: unofferedRefused, v1_ceiling_preserved: v1CeilingPreserved, v2_bytes: v2.length}));
