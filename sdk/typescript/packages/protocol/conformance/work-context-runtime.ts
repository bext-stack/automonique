// SPDX-License-Identifier: Apache-2.0

import {
  AttemptWorkspaceId,
  CheckoutId,
  HostSetupId,
  PaneId,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PlatformVersionNumber,
  ProjectId,
  UserWorkspaceId,
  WorkContextCursor,
  WorkContextLabel,
  WorkContextPageLimit,
  WorkContextRevision,
  WorkSessionId,
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
  validateWorkContextIdentity,
  validateWorkContextPage,
  validateWorkContextQuery,
  validateWorkContextRecord,
  type WorkContextPage,
  type WorkContextQuery,
  type WorkContextRecord,
} from "../generated/work-context.ts";
import {ResourceId} from "../generated/platform.ts";

const record = (index: number): WorkContextRecord => ({
  attributes: {checkout: null, host_setup: null},
  identity: {id: ProjectId(`project-${index}`), kind: "project"},
  label: WorkContextLabel("Project"),
  lifecycle: "active",
  relations: index === 0 ? [{
    kind: "project_repository",
    target: {
      kind: "repository",
      resource: {authority: "github", id: ResourceId("repository-1"), kind: "repository"},
    },
  }] : [],
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
  versions: [PlatformVersionNumber(1n), PlatformVersionNumber(2n)],
} as const;
const negotiated = {
  schema: "automonique.platform/v2",
  version: PlatformVersionNumber(2n),
  work_context: "v2_structured",
} as const;
decodePlatformVersionOffer(encodePlatformVersionOffer(offer));
decodeNegotiatedPlatform(encodeNegotiatedPlatform(negotiated));
const decodedPages = pages.map((page) => decodeWorkContextPage(encodeWorkContextPage(validateWorkContextPage(page))));

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const unhex = (value: string): Uint8Array => {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) throw new Error("invalid hex corpus");
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
};
const bunArgs = (globalThis as typeof globalThis & {Bun?: {argv: readonly string[]}}).Bun?.argv ?? [];
if (bunArgs[2] === "encode-corpus") {
  console.log([
    hex(encodePlatformVersionOffer(offer)),
    hex(encodeNegotiatedPlatform(negotiated)),
    hex(encodeWorkContextQuery(query)),
    hex(encodeWorkContextPage(pages[0]!)),
  ].join("\n"));
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-corpus") {
  decodePlatformVersionOffer(unhex(bunArgs[3] ?? ""));
  decodeNegotiatedPlatform(unhex(bunArgs[4] ?? ""));
  decodeWorkContextQuery(unhex(bunArgs[5] ?? ""));
  decodeWorkContextPage(unhex(bunArgs[6] ?? ""));
  console.log("ok");
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
}
if (bunArgs[2] === "decode-refusal-corpus") {
  const decoders = [
    decodePlatformVersionOffer,
    decodeNegotiatedPlatform,
    decodeWorkContextQuery,
    decodeWorkContextPage,
    decodeWorkContextQuery,
    decodeWorkContextPage,
  ] as const;
  let refused = 0;
  for (const [index, decode] of decoders.entries()) {
    try {
      (decode as (payload: Uint8Array) => unknown)(unhex(bunArgs[index + 3] ?? ""));
    } catch {
      refused += 1;
    }
  }
  if (refused !== decoders.length) throw new Error("TypeScript admitted the Rust refusal corpus");
  console.log(`refused:${refused}`);
  (globalThis as typeof globalThis & {process?: {exit(code: number): never}}).process?.exit(0);
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
