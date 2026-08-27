// SPDX-License-Identifier: Apache-2.0

import {
  HttpsPlatformV2Transport,
  MOBILE_PLATFORM_V2_AUTHORIZATION_SCHEMA,
  MobileCredentialId,
  MobileLifecycleClient,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PLATFORM_SCHEMA_V2,
  PlatformV2Client,
  PlatformVersionNumber,
  ProjectId,
  UserWorkspaceId,
  WorkContextPageLimit,
} from "../src/index.ts";

declare const process: { readonly argv: readonly string[] };

const transportOrigin = process.argv[2];
const accessToken = process.argv[3];
const credentialId = process.argv[4];
if (
  transportOrigin === undefined ||
  accessToken === undefined ||
  credentialId === undefined
) {
  throw new Error("missing Rust mobile Platform v2 contract arguments");
}

const canonicalOrigin = "https://dashboard.example.invalid";
const routeFetch = (async (
  input: string | URL | Request,
  init?: RequestInit,
) => {
  const requested = new URL(input.toString());
  const headers = new Headers(init?.headers);
  headers.set("host", "dashboard.example.invalid");
  headers.set("x-forwarded-proto", "https");
  const response = await fetch(
    `${transportOrigin}${requested.pathname}${requested.search}`,
    {
      ...init,
      headers,
    },
  );
  Object.defineProperty(response, "url", { value: requested.toString() });
  return response;
}) as typeof fetch;

const lifecycle = await MobileLifecycleClient.discover(
  canonicalOrigin,
  routeFetch,
);
const v1 = await lifecycle.authorization(accessToken);
if (v1.credential_id !== MobileCredentialId(credentialId)) {
  throw new Error("Rust v1 credential identity mismatch");
}
const granted = await lifecycle.grantPlatformV2(
  {
    actions: ["query_work_contexts"],
    credential_id: v1.credential_id,
    project_roots: [ProjectId("project-test")],
  },
  "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=",
);
const delegated = await lifecycle.platformV2Authorization(accessToken, v1);
if (
  delegated.schema !== MOBILE_PLATFORM_V2_AUTHORIZATION_SCHEMA ||
  delegated.delegation_id !== granted.delegation_id ||
  delegated.principal_generation !== granted.principal_generation ||
  delegated.credential_revision !== v1.credential_revision ||
  delegated.authorization_revision !== v1.authorization_revision
) {
  throw new Error("Rust mobile Platform v2 delegation mismatch");
}

const client = new PlatformV2Client(
  new HttpsPlatformV2Transport(
    `${canonicalOrigin}/api/platform/v2`,
    () => accessToken,
    routeFetch,
  ),
);
const negotiation = await client.negotiate({
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(2n)],
});
if (
  negotiation.kind !== "negotiated" ||
  negotiation.negotiated.version !== 2n
) {
  throw new Error("mobile Platform v2 negotiation mismatch");
}
const query = {
  after: null,
  kinds: ["project"] as const,
  lifecycles: [],
  limit: WorkContextPageLimit(1n),
  parent: null,
  project: ProjectId("project-test"),
  schema: PLATFORM_SCHEMA_V2,
} as const;
const allowed = await client.queryWorkContexts(query);
if (
  allowed.kind !== "platform_v2_refused" ||
  allowed.refusal.category !== "fixture_mobile_v2"
) {
  throw new Error("admitted mobile request did not cross the Rust bridge");
}

const wrongRoot = await client.queryWorkContexts({
  ...query,
  project: ProjectId("project-other"),
});
if (
  wrongRoot.kind !== "platform_v2_refused" ||
  wrongRoot.refusal.category !== "platform_v2_mobile_project_denied"
) {
  throw new Error(
    "wrong-root mobile request was not refused before the bridge",
  );
}
const wrongAction = await client.getLineage(
  ProjectId("project-test"),
  UserWorkspaceId("workspace-test"),
);
if (
  wrongAction.kind !== "platform_v2_refused" ||
  wrongAction.refusal.category !== "platform_v2_mobile_action_denied"
) {
  throw new Error(
    "wrong-action mobile request was not refused before the bridge",
  );
}

console.log(
  "TypeScript SDK passed the live Rust mobile Platform v2 bearer contract",
);
