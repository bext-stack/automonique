// SPDX-License-Identifier: Apache-2.0

import {
  AttemptWorkspaceId,
  CheckoutId,
  HostSetupId,
  PaneId,
  PlatformSessionId,
  PlatformVersionNumber,
  ProjectId,
  UserWorkspaceId,
  WorkContextCursor,
  WorkContextLabel,
  WorkContextPageLimit,
  WorkContextRepositoryId,
  WorkContextRevision,
  WorkSessionId,
  decodeCheckoutKind,
  decodeHostSetupKind,
  decodeWorkContextKind,
  decodeWorkContextLifecycle,
  decodeWorkContextRelationKind,
  decodeWorkContextTargetKind,
  type WorkContextPage,
  type WorkContextRecord,
} from "../generated/work-context.ts";

const record = (index: number): WorkContextRecord => ({
  attributes: {checkout: null, host_setup: null},
  identity: {id: ProjectId(`project-${index}`), kind: "project"},
  label: WorkContextLabel("Project"),
  lifecycle: "active",
  relations: [],
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

// Exercise every distinct identity constructor so accidental brand collapse is
// caught by the checked conformance source as well as the generated surface.
const identities = [
  AttemptWorkspaceId("attempt-1"),
  CheckoutId("checkout-1"),
  HostSetupId("host-1"),
  PaneId("pane-1"),
  PlatformSessionId("platform-session-1"),
  ProjectId("project-1"),
  UserWorkspaceId("user-workspace-1"),
  WorkContextRepositoryId("repository-1"),
  WorkSessionId("session-1"),
];

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
  items: pages.flatMap((page) => page.items).length,
  page_limit: Number(WorkContextPageLimit(128n)),
  schema: pages[0]?.schema,
  version: Number(PlatformVersionNumber(2n)),
}));
