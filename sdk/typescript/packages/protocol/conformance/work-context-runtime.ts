// SPDX-License-Identifier: Apache-2.0

import {
  AttemptWorkspaceId,
  CheckoutId,
  HostSetupId,
  PaneId,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PlatformVersionNumber,
  ProjectId,
  SupportedPlatformVersionNumber,
  UserWorkspaceId,
  WorkContextCursor,
  WorkContextLabel,
  WorkContextPageLimit,
  WorkContextRevision,
  WorkSessionId,
  AuthorityGrantId,
  MutationApprovalId,
  MutationPreviewDigest,
  MutationPreviewId,
  WorkContextRegistrySelector,
  decodeCheckoutKind,
  decodeHostSetupKind,
  decodeWorkContextKind,
  decodeWorkContextLifecycle,
  decodeWorkContextRelationKind,
  decodeWorkContextTargetKind,
  decodeNegotiatedPlatform,
  decodePlatformVersionOffer,
  decodeWorkContextPage,
  decodeWorkContextQuery,
  encodeNegotiatedPlatform,
  encodePlatformVersionOffer,
  encodeWorkContextPage,
  encodeWorkContextQuery,
  decodeWorkContextMutationApproval,
  decodeWorkContextMutationPreview,
  decodeWorkContextMutationProposal,
  decodeWorkContextMutationReceipt,
  decodeWorkContextMutationRefusal,
  decodeWorkContextMutationSubmission,
  encodeWorkContextMutationApproval,
  encodeWorkContextMutationPreview,
  encodeWorkContextMutationProposal,
  encodeWorkContextMutationReceipt,
  encodeWorkContextMutationRefusal,
  encodeWorkContextMutationSubmission,
  lifecycleRequestDigest,
  mutationPreviewDigest,
  negotiatePlatformVersion,
  validateWorkContextIdentity,
  validateWorkContextPage,
  validateWorkContextQuery,
  validateWorkContextRecord,
  verifyPlatformNegotiationTranscript,
  type WorkContextPage,
  type WorkContextQuery,
  type WorkContextRecord,
  type MutationApproval,
  type MutationPreview,
  type MutationReceipt,
  type MutationRefusal,
  type MutationSubmission,
  type WorkContextAuthority,
  type WorkContextMutationProposal,
} from "../generated/work-context.ts";
import {IdempotencyKey, ReceiptId, ResourceId} from "../generated/platform.ts";

const record = (index: number): WorkContextRecord => ({
  attributes: {checkout: null, host_setup: null},
  identity: {id: ProjectId(`project-${index.toString().padStart(4, "0")}`), kind: "project"},
  label: WorkContextLabel("Project"),
  lifecycle: "active",
  // U+E000 sorts before U+1F600 by UTF-8 bytes (Rust String::cmp), while
  // JavaScript's native UTF-16 comparison gives the opposite answer.
  relations: index === 0 ? ["\u{e000}", "😀"].map((id) => ({
    kind: "project_repository" as const,
    target: {
      kind: "repository" as const,
      resource: {authority: "github" as const, id: ResourceId(id), kind: "repository" as const},
    },
  })) : [],
  revision: WorkContextRevision(1n),
});

const pages: WorkContextPage[] = Array.from({length: 5}, (_, pageIndex) => ({
  after: pageIndex === 0 ? null : WorkContextCursor(`page-${pageIndex}`),
  has_more: pageIndex < 4,
  items: Array.from({length: 128}, (_, itemIndex) => record(pageIndex * 128 + itemIndex)),
  next_cursor: pageIndex < 4 ? WorkContextCursor(`page-${pageIndex + 1}`) : null,
  requested_limit: WorkContextPageLimit(128n),
  schema: "automonique.platform/v2",
}));
const query: WorkContextQuery = {
  after: null,
  kinds: ["project"],
  lifecycles: ["active"],
  limit: WorkContextPageLimit(128n),
  parent: null,
  project: null,
  schema: "automonique.platform/v2",
};

const grants = (prefix: string): WorkContextAuthority => ({
  credentials: [AuthorityGrantId(`${prefix}:credential`)],
  filesystem: [AuthorityGrantId(`${prefix}:fs`)],
  models: [AuthorityGrantId(`${prefix}:model`)],
  network: [AuthorityGrantId(`${prefix}:network`)],
  providers: [AuthorityGrantId(`${prefix}:provider`)],
  tools: [AuthorityGrantId(`${prefix}:tool`)],
});
const ceiling: WorkContextAuthority = {
  credentials: [AuthorityGrantId("narrow:credential"), AuthorityGrantId("wide:credential")],
  filesystem: [AuthorityGrantId("narrow:fs"), AuthorityGrantId("wide:fs")],
  models: [AuthorityGrantId("narrow:model"), AuthorityGrantId("wide:model")],
  network: [AuthorityGrantId("narrow:network"), AuthorityGrantId("wide:network")],
  providers: [AuthorityGrantId("narrow:provider"), AuthorityGrantId("wide:provider")],
  tools: [AuthorityGrantId("narrow:tool"), AuthorityGrantId("wide:tool")],
};
const proposalBase = {
  actor: {id: "operator-1", tenant: "tenant-1"},
  actor_authority: ceiling,
  authority: "automonique" as const,
  idempotency_key: IdempotencyKey("idem-lifecycle-1"),
  intent: {
    kind: "resume_attempt_workspace" as const,
    requested_authority: grants("narrow"),
    target: {
      identity: {id: AttemptWorkspaceId("attempt-1"), kind: "attempt_workspace" as const},
      revision: WorkContextRevision(7n),
    },
  },
};
const lifecycleProposal: WorkContextMutationProposal = {
  ...proposalBase,
  request_digest: lifecycleRequestDigest(proposalBase),
  schema: "automonique.platform/v2",
};
const currentAttempt: WorkContextRecord = {
  attributes: {checkout: null, host_setup: null},
  identity: {id: AttemptWorkspaceId("attempt-1"), kind: "attempt_workspace"},
  label: WorkContextLabel("Attempt"),
  lifecycle: "hibernated",
  relations: [{kind: "attempt_user_workspace", target: {id: UserWorkspaceId("workspace-1"), kind: "user_workspace"}}],
  revision: WorkContextRevision(7n),
};
const resultingAttempt: WorkContextRecord = {...currentAttempt, lifecycle: "running", revision: WorkContextRevision(8n)};
const lifecyclePreview: MutationPreview = {
  approval: "required",
  current: currentAttempt,
  effective_authority: grants("narrow"),
  expires_at_ms: 2000n,
  inherited_authority: ceiling,
  issued_at_ms: 1000n,
  preview: {id: MutationPreviewId("preview-1"), revision: WorkContextRevision(3n)},
  proposal: lifecycleProposal,
  resolved_parents: [],
  resulting: resultingAttempt,
  schema: "automonique.platform/v2",
};
const lifecyclePreviewDigest = mutationPreviewDigest(lifecyclePreview);
const lifecycleApproval: MutationApproval = {
  decided_at_ms: 1100n,
  decided_by: {id: "approver-1", tenant: "tenant-1"},
  decision: "granted",
  expires_at_ms: 1900n,
  id: MutationApprovalId("approval-1"),
  idempotency_key: lifecycleProposal.idempotency_key,
  preview: lifecyclePreview.preview,
  preview_digest: lifecyclePreviewDigest,
  request_digest: lifecycleProposal.request_digest,
};
const lifecycleSubmission: MutationSubmission = {
  approval: lifecycleApproval,
  idempotency_key: lifecycleProposal.idempotency_key,
  preview: lifecyclePreview.preview,
  preview_digest: lifecyclePreviewDigest,
  request_digest: lifecycleProposal.request_digest,
  schema: "automonique.platform/v2",
  submitted_at_ms: 1200n,
};
const lifecycleReceipt: MutationReceipt = {
  approval_id: lifecycleApproval.id,
  id: ReceiptId("receipt-1"),
  idempotency_key: lifecycleProposal.idempotency_key,
  outcome: "completed",
  preview: lifecyclePreview.preview,
  preview_digest: lifecyclePreviewDigest,
  recorded_at_ms: 1300n,
  request_digest: lifecycleProposal.request_digest,
  resulting_revision: WorkContextRevision(8n),
  schema: "automonique.platform/v2",
};
const emptyAuthority: WorkContextAuthority = {credentials: [], filesystem: [], models: [], network: [], providers: [], tools: []};
const checkoutProjectIdentity = {id: ProjectId("checkout-project"), kind: "project" as const};
const checkoutOtherProjectIdentity = {id: ProjectId("other-project"), kind: "project" as const};
const checkoutHostIdentity = {id: HostSetupId("checkout-host"), kind: "host_setup" as const};
const checkoutRepositoryIdentity = validateWorkContextIdentity({kind: "repository", resource: {authority: "github", id: ResourceId("checkout-repository"), kind: "repository"}});
const checkoutIntent = {
  checkout_kind: "git_worktree" as const,
  host_setup: {identity: checkoutHostIdentity, revision: WorkContextRevision(1n)},
  kind: "create_checkout" as const,
  label: WorkContextLabel("Checkout"),
  project: {identity: checkoutProjectIdentity, revision: WorkContextRevision(1n)},
  registry: WorkContextRegistrySelector("checkout-registry"),
  repository: {identity: checkoutRepositoryIdentity, revision: WorkContextRevision(1n)},
};
const checkoutProposalBase = {actor: {id: "operator-1", tenant: "tenant-1"}, actor_authority: emptyAuthority, authority: "automonique" as const, idempotency_key: IdempotencyKey("checkout-negative"), intent: checkoutIntent};
const checkoutProposal: WorkContextMutationProposal = {...checkoutProposalBase, request_digest: lifecycleRequestDigest(checkoutProposalBase), schema: "automonique.platform/v2"};
const checkoutProjectRecord = (lifecycle: "active" | "archived"): WorkContextRecord => ({attributes: {checkout: null, host_setup: null}, identity: checkoutProjectIdentity, label: WorkContextLabel("Project"), lifecycle, relations: [{kind: "project_repository", target: checkoutRepositoryIdentity}], revision: WorkContextRevision(1n)});
const checkoutHostRecord = (project: {readonly id: ReturnType<typeof ProjectId>; readonly kind: "project"}): WorkContextRecord => ({attributes: {checkout: null, host_setup: "local"}, identity: checkoutHostIdentity, label: WorkContextLabel("Host"), lifecycle: "active", relations: [{kind: "host_setup_project", target: project}], revision: WorkContextRevision(1n)});
const checkoutResult: WorkContextRecord = {attributes: {checkout: "git_worktree", host_setup: null}, identity: {id: CheckoutId("issued-checkout"), kind: "checkout"}, label: WorkContextLabel("Checkout"), lifecycle: "active", relations: [{kind: "checkout_project", target: checkoutProjectIdentity}, {kind: "checkout_host_setup", target: checkoutHostIdentity}, {kind: "checkout_repository", target: checkoutRepositoryIdentity}], revision: WorkContextRevision(1n)};
const checkoutPreview = (project: WorkContextRecord, host: WorkContextRecord): MutationPreview => ({approval: "not_required", current: null, effective_authority: emptyAuthority, expires_at_ms: 2n, inherited_authority: emptyAuthority, issued_at_ms: 1n, preview: {id: MutationPreviewId("preview-checkout-negative"), revision: WorkContextRevision(1n)}, proposal: checkoutProposal, resolved_parents: [{kind: "work_context", record: project}, {kind: "work_context", record: host}, {identity: checkoutRepositoryIdentity, kind: "external", owning_project: checkoutProjectIdentity.id, resolution: "available", revision: WorkContextRevision(1n)}], resulting: checkoutResult, schema: "automonique.platform/v2"});
const mustRefusePreview = (value: MutationPreview): void => {try { encodeWorkContextMutationPreview(value); } catch { return; } throw new Error("invalid creation parent preview was admitted");};
mustRefusePreview(checkoutPreview(checkoutProjectRecord("archived"), checkoutHostRecord(checkoutProjectIdentity)));
mustRefusePreview(checkoutPreview(checkoutProjectRecord("active"), checkoutHostRecord(checkoutOtherProjectIdentity)));
mustRefusePreview({...lifecyclePreview, expires_at_ms: 9223372036854775808n});
const mustRefuseEncode = (encode: () => Uint8Array): void => {try { encode(); } catch { return; } throw new Error("out-of-range lifecycle epoch was admitted");};
mustRefuseEncode(() => encodeWorkContextMutationApproval({...lifecycleApproval, expires_at_ms: 9223372036854775808n}, lifecyclePreview));
mustRefuseEncode(() => encodeWorkContextMutationSubmission({...lifecycleSubmission, submitted_at_ms: 9223372036854775808n}, lifecyclePreview));
mustRefuseEncode(() => encodeWorkContextMutationReceipt({...lifecycleReceipt, recorded_at_ms: 9223372036854775808n}, lifecycleSubmission, lifecyclePreview));
mustRefuseEncode(() => encodeWorkContextMutationApproval({...lifecycleApproval, preview_digest: MutationPreviewDigest(`sha256:${"0".repeat(64)}`)}, lifecyclePreview));
const lifecycleRefusal: MutationRefusal = {
  category: "stale_revision",
  explanation: "parent_revision_changed",
  request_digest: lifecycleProposal.request_digest,
  schema: "automonique.platform/v2",
};
WorkContextRegistrySelector("registry:checkout_1");

// Exercise every distinct identity constructor so accidental brand collapse is
// caught by the checked conformance source as well as the generated surface.
const identities = [
  AttemptWorkspaceId("attempt-1"),
  CheckoutId("checkout-1"),
  HostSetupId("host-1"),
  PaneId("pane-1"),
  validateWorkContextIdentity({
    kind: "platform_session",
    resource: {authority: "automonique", id: ResourceId("platform-session-1"), kind: "session"},
  }),
  ProjectId("project-1"),
  UserWorkspaceId("user-workspace-1"),
  validateWorkContextIdentity({
    kind: "repository",
    resource: {authority: "github", id: ResourceId("repository-1"), kind: "repository"},
  }),
  WorkSessionId("session-1"),
];

const offer = {
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(1n), PlatformVersionNumber(2n), PlatformVersionNumber(3n)],
} as const;
const negotiated = {
  schema: "automonique.platform/v2",
  version: SupportedPlatformVersionNumber(2n),
  work_context: "v2_structured",
} as const;
const v1Offer = {
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(1n)],
} as const;
const v2Offer = {
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(2n)],
} as const;
const v1Negotiated = {
  schema: "automonique.platform/v1",
  version: SupportedPlatformVersionNumber(1n),
  work_context: "v1_existing_resources_only",
} as const;
if (negotiatePlatformVersion(offer, offer).version !== 2n) throw new Error("v2 was not preferred");
if (negotiatePlatformVersion(offer, v1Offer).version !== 1n) throw new Error("v1-only peer did not downgrade truthfully");
verifyPlatformNegotiationTranscript(offer, offer, negotiated);
decodePlatformVersionOffer(encodePlatformVersionOffer(offer));
decodeNegotiatedPlatform(encodeNegotiatedPlatform(negotiated));
const decodedPages = pages.map((page) => decodeWorkContextPage(encodeWorkContextPage(validateWorkContextPage(page))));
const corpusPage: WorkContextPage = {
  after: null,
  has_more: false,
  items: [record(0)],
  next_cursor: null,
  requested_limit: WorkContextPageLimit(128n),
  schema: "automonique.platform/v2",
};

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const unhex = (value: string): Uint8Array => {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) throw new Error("invalid hex corpus");
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
};
type RefusalDecoder = "offer" | "negotiated" | "query" | "page";
interface RefusalCase {
  readonly decoder: RefusalDecoder;
  readonly category: string;
  readonly payload: Uint8Array;
}
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const canonical = (value: string): Uint8Array => textEncoder.encode(value);
const validQueryText = textDecoder.decode(encodeWorkContextQuery(query));
const validPageText = textDecoder.decode(encodeWorkContextPage(corpusPage));
const refusalCorpus: readonly RefusalCase[] = [
  {decoder: "offer", category: "work_context_value_invalid", payload: canonical('{"schema":"automonique.platform/negotiation/v9","versions":[1,2,3]}')},
  {decoder: "offer", category: "work_context_counter_out_of_range", payload: canonical('{"schema":"automonique.platform/negotiation/v1","versions":[-1,2]}')},
  {decoder: "offer", category: "work_context_counter_out_of_range", payload: canonical('{"schema":"automonique.platform/negotiation/v1","versions":[1,65536]}')},
  {decoder: "offer", category: "work_context_value_invalid", payload: canonical('{"schema":"automonique.platform/negotiation/v1","versions":[0,1]}')},
  {decoder: "negotiated", category: "work_context_value_invalid", payload: canonical('{"schema":"automonique.platform/v9","version":2,"work_context":"v2_structured"}')},
  {decoder: "negotiated", category: "work_context_counter_out_of_range", payload: canonical('{"schema":"automonique.platform/v1","version":-1,"work_context":"v1_existing_resources_only"}')},
  {decoder: "negotiated", category: "work_context_counter_out_of_range", payload: canonical('{"schema":"automonique.platform/v2","version":65536,"work_context":"v2_structured"}')},
  {decoder: "negotiated", category: "work_context_value_invalid", payload: canonical('{"schema":"automonique.platform/v3","version":3,"work_context":"v2_structured"}')},
  {decoder: "query", category: "work_context_value_invalid", payload: canonical(validQueryText.replace('"schema":"automonique.platform/v2"', '"schema":"automonique.platform/v9"'))},
  {decoder: "query", category: "work_context_counter_out_of_range", payload: canonical(validQueryText.replace('"limit":128', '"limit":-1'))},
  {decoder: "query", category: "work_context_counter_out_of_range", payload: canonical(validQueryText.replace('"limit":128', '"limit":65536'))},
  {decoder: "page", category: "work_context_value_invalid", payload: canonical(validPageText.replace('"schema":"automonique.platform/v2"', '"schema":"automonique.platform/v9"'))},
  {decoder: "page", category: "work_context_counter_out_of_range", payload: canonical(validPageText.replace('"requested_limit":128', '"requested_limit":-1'))},
  {decoder: "page", category: "work_context_counter_out_of_range", payload: canonical(validPageText.replace('"requested_limit":128', '"requested_limit":65536'))},
  {decoder: "page", category: "work_context_value_invalid", payload: canonical(validPageText.replace('"authority":"github"', '"authority":"future_authority"'))},
  {decoder: "page", category: "work_context_value_invalid", payload: canonical(validPageText.replace('"kind":"repository"}', '"kind":"future_kind"}'))},
  {decoder: "page", category: "work_context_counter_out_of_range", payload: canonical(validPageText.replace('"revision":1', '"revision":-1'))},
  {decoder: "page", category: "work_context_value_invalid", payload: canonical(validPageText.replace('"revision":1', '"revision":0'))},
  {decoder: "page", category: "integer_out_of_range", payload: canonical(validPageText.replace('"revision":1', '"revision":9223372036854775808'))},
];
const decodeRefusal = (decoder: RefusalDecoder, payload: Uint8Array): unknown => {
  switch (decoder) {
    case "offer": return decodePlatformVersionOffer(payload);
    case "negotiated": return decodeNegotiatedPlatform(payload);
    case "query": return decodeWorkContextQuery(payload);
    case "page": return decodeWorkContextPage(payload);
  }
};
const refusalCategory = (decoder: RefusalDecoder, payload: Uint8Array): string => {
  try {
    decodeRefusal(decoder, payload);
  } catch (error) {
    const category = (error as {category?: unknown}).category;
    if (typeof category === "string") return category;
    throw error;
  }
  throw new Error(`${decoder} admitted a refusal corpus document`);
};
const bunArgs = (globalThis as typeof globalThis & {Bun?: {argv: readonly string[]}}).Bun?.argv ?? [];
const lifecycleDocuments = (): readonly Uint8Array[] => [
  encodeWorkContextMutationProposal(lifecycleProposal),
  encodeWorkContextMutationPreview(lifecyclePreview),
  encodeWorkContextMutationApproval(lifecycleApproval, lifecyclePreview),
  encodeWorkContextMutationSubmission(lifecycleSubmission, lifecyclePreview),
  encodeWorkContextMutationReceipt(lifecycleReceipt, lifecycleSubmission, lifecyclePreview),
  encodeWorkContextMutationRefusal(lifecycleRefusal),
];
if (bunArgs[2] === "encode-lifecycle-corpus") {
  console.log(lifecycleDocuments().map(hex).join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-lifecycle-corpus") {
  const documents = bunArgs.slice(3, 9).map(unhex);
  const proposal = decodeWorkContextMutationProposal(documents[0]!);
  const preview = decodeWorkContextMutationPreview(documents[1]!);
  const approval = decodeWorkContextMutationApproval(documents[2]!, preview);
  const submission = decodeWorkContextMutationSubmission(documents[3]!, preview);
  const receipt = decodeWorkContextMutationReceipt(documents[4]!, submission, preview);
  const refusal = decodeWorkContextMutationRefusal(documents[5]!);
  if (proposal.request_digest !== preview.proposal.request_digest || approval.preview.id !== preview.preview.id || submission.request_digest !== proposal.request_digest || receipt.resulting_revision !== 8n || refusal.category !== "stale_revision") throw new Error("lifecycle value drifted");
  console.log([
    hex(encodeWorkContextMutationProposal(proposal)),
    hex(encodeWorkContextMutationPreview(preview)),
    hex(encodeWorkContextMutationApproval(approval, preview)),
    hex(encodeWorkContextMutationSubmission(submission, preview)),
    hex(encodeWorkContextMutationReceipt(receipt, submission, preview)),
    hex(encodeWorkContextMutationRefusal(refusal)),
  ].join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
type LifecycleRefusalDecoder = "proposal" | "preview" | "refusal";
const lifecycleDecodeCategory = (decoder: LifecycleRefusalDecoder, payload: Uint8Array): string => {
  try {
    if (decoder === "proposal") decodeWorkContextMutationProposal(payload);
    else if (decoder === "preview") decodeWorkContextMutationPreview(payload);
    else decodeWorkContextMutationRefusal(payload);
  } catch (error) {
    const category = (error as {category?: unknown}).category;
    if (typeof category === "string") return category;
    throw error;
  }
  throw new Error(`${decoder} admitted a lifecycle refusal corpus document`);
};
const validLifecycleText = lifecycleDocuments().map((bytes) => textDecoder.decode(bytes));
const lifecycleRefusals: readonly {decoder: LifecycleRefusalDecoder; category: string; payload: Uint8Array}[] = [
  {decoder: "proposal", category: "work_context_value_invalid", payload: canonical(validLifecycleText[0]!.replace(/sha256:[0-9a-f]{64}/, `sha256:${"0".repeat(64)}`))},
  {decoder: "preview", category: "work_context_value_invalid", payload: canonical(validLifecycleText[1]!.replace('["narrow:fs","wide:fs"]', '["wide:fs","narrow:fs"]'))},
  {decoder: "preview", category: "work_context_value_invalid", payload: canonical(validLifecycleText[1]!.replace('"lifecycle":"running"', '"lifecycle":"active"'))},
  {decoder: "refusal", category: "work_context_value_invalid", payload: canonical(validLifecycleText[5]!.replace('"stale_revision"', '"future_refusal"'))},
];
if (bunArgs[2] === "encode-lifecycle-refusal-corpus") {
  console.log(lifecycleRefusals.map((fixture) => `${fixture.decoder}\t${fixture.category}\t${hex(fixture.payload)}`).join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-lifecycle-refusal-corpus") {
  console.log(bunArgs.slice(3).map((argument) => {
    const separator = argument.indexOf(":");
    return lifecycleDecodeCategory(argument.slice(0, separator) as LifecycleRefusalDecoder, unhex(argument.slice(separator + 1)));
  }).join(","));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "encode-corpus") {
  console.log([
    hex(encodePlatformVersionOffer(offer)),
    hex(encodeNegotiatedPlatform(negotiated)),
    hex(encodeWorkContextQuery(query)),
    hex(encodeWorkContextPage(corpusPage)),
  ].join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-corpus") {
  const documents = bunArgs.slice(3, 7).map(unhex);
  const decodedOffer = decodePlatformVersionOffer(documents[0]!);
  const decodedNegotiated = decodeNegotiatedPlatform(documents[1]!);
  const decodedQuery = decodeWorkContextQuery(documents[2]!);
  const decodedPage = decodeWorkContextPage(documents[3]!);
  const decodedRelations = decodedPage.items[0]?.relations ?? [];
  if (decodedOffer.versions.length !== 3 || decodedOffer.versions[0] !== 1n || decodedOffer.versions[1] !== 2n || decodedOffer.versions[2] !== 3n) throw new Error("offer value drifted");
  if (decodedNegotiated.version !== 2n || decodedNegotiated.work_context !== "v2_structured") throw new Error("negotiated value drifted");
  if (decodedQuery.kinds[0] !== "project" || decodedQuery.lifecycles[0] !== "active" || decodedQuery.limit !== 128n) throw new Error("query value drifted");
  if (decodedPage.items.length !== 1 || decodedPage.items[0]?.identity.kind !== "project" || decodedRelations.length !== 2) throw new Error("page value drifted");
  if (decodedRelations[0]?.target.kind !== "repository" || decodedRelations[0].target.resource.id !== "\u{e000}") throw new Error("BMP relation value drifted");
  if (decodedRelations[1]?.target.kind !== "repository" || decodedRelations[1].target.resource.id !== "😀") throw new Error("non-BMP relation value drifted");
  console.log([
    hex(encodePlatformVersionOffer(decodedOffer)),
    hex(encodeNegotiatedPlatform(decodedNegotiated)),
    hex(encodeWorkContextQuery(decodedQuery)),
    hex(encodeWorkContextPage(decodedPage)),
  ].join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-refusal-corpus") {
  const categories = bunArgs.slice(3).map((argument) => {
    const separator = argument.indexOf(":");
    const decoder = argument.slice(0, separator) as RefusalDecoder;
    if (!["offer", "negotiated", "query", "page"].includes(decoder) || separator < 0) throw new Error("invalid refusal corpus argument");
    return refusalCategory(decoder, unhex(argument.slice(separator + 1)));
  });
  console.log(categories.join(","));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "encode-refusal-corpus") {
  console.log(refusalCorpus.map((fixture) => `${fixture.decoder}\t${fixture.category}\t${hex(fixture.payload)}`).join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}

for (const fixture of refusalCorpus) {
  const category = refusalCategory(fixture.decoder, fixture.payload);
  if (category !== fixture.category) throw new Error(`${fixture.decoder} refusal category drifted: ${category} !== ${fixture.category}`);
}

let refusals = 0;
for (const refuse of [
  () => decodePlatformVersionOffer(new TextEncoder().encode('{"schema":"automonique.platform/negotiation/v1","versions":[1,1]}')),
  () => decodeNegotiatedPlatform(new TextEncoder().encode('{"schema":"automonique.platform/v2","version":1,"work_context":"v2_structured"}')),
  () => validateWorkContextIdentity({
    kind: "repository",
    resource: {authority: "github", id: ResourceId("repository-1"), kind: "session"},
  }),
  () => validateWorkContextPage({...pages[0]!, has_more: true, next_cursor: null}),
  () => validateWorkContextQuery({...query, limit: WorkContextPageLimit(129n)}),
  () => validateWorkContextRecord({
    ...record(0),
    relations: [{
      kind: "project_repository",
      target: {
        kind: "repository",
        resource: {authority: "github", id: ResourceId("repository-1"), kind: "session"},
      },
    }],
  }),
  () => validateWorkContextPage({...corpusPage, items: [record(0), record(0)]}),
  () => negotiatePlatformVersion(v1Offer, v2Offer),
  () => verifyPlatformNegotiationTranscript(offer, offer, v1Negotiated),
]) {
  try {
    refuse();
    throw new Error("invalid work-context value was admitted");
  } catch (error) {
    if (error instanceof Error && error.message.includes("was admitted")) throw error;
    refusals += 1;
  }
}

for (const decode of [
  decodeCheckoutKind,
  decodeHostSetupKind,
  decodeWorkContextKind,
  decodeWorkContextLifecycle,
  decodeWorkContextRelationKind,
  decodeWorkContextTargetKind,
]) {
  try {
    decode("undefined_vocabulary" as never);
    throw new Error("security-sensitive work-context enum admitted an unknown spelling");
  } catch (error) {
    if (error instanceof Error && error.message.includes("admitted")) throw error;
  }
}

console.log(JSON.stringify({
  identities: identities.length,
  items: decodedPages.flatMap((page) => page.items).length,
  page_limit: Number(WorkContextPageLimit(128n)),
  schema: pages[0]?.schema,
  refusals,
  version: Number(PlatformVersionNumber(2n)),
}));
