// SPDX-License-Identifier: Apache-2.0

import {
  BasicHttpsPlatformV2Transport,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PlatformV2BasicCredential,
  PlatformV2Client,
  PlatformVersionNumber,
  ProjectId,
} from "../src/index.ts";

declare const process: {readonly argv: readonly string[]};

const endpoint = process.argv[2];
if (endpoint === undefined) throw new Error("missing Rust Platform v2 HTTP endpoint");

const credential = new PlatformV2BasicCredential("ops", "fixture-password");
const client = new PlatformV2Client(new BasicHttpsPlatformV2Transport(
  endpoint,
  () => credential,
  fetch,
));
const negotiation = await client.negotiate({
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(2n)],
});
if (negotiation.kind !== "negotiated" || negotiation.negotiated.version !== 2n) {
  throw new Error("Platform v2 negotiation mismatch");
}
const result = await client.getWorkContext({kind: "project", id: ProjectId("project-test")});
if (result.kind !== "platform_v2_refused" || result.refusal.category !== "fixture_http_refusal") {
  throw new Error("Platform v2 typed refusal mismatch");
}

console.log("TypeScript SDK passed the live Rust Platform v2 HTTP contract");
