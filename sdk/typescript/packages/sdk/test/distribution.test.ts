// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  PLATFORM_V1_SCHEMA_DIGEST,
  SCHEMA_DIGEST,
  SCHEMA_DIGEST_ALGORITHM,
} from "../../protocol/src/index.ts";
import sdkPackage from "../package.json" with {type: "json"};

// The package manifest names the schema digest its distribution was built
// from, and the distribution contract in CI refuses a tarball whose built
// Platform v1 digest disagrees with it. The aggregate digest intentionally
// also covers separately negotiated newer modules. This check runs after `npm pack`, on a
// machine that is not the one the protocol was regenerated on; this one runs
// under `npm test`, so a regeneration that moved the digest is caught beside
// the generated files it moved rather than by the next CI run.
describe("distribution manifest", () => {
  test("the package manifest names the digest the generated protocol carries", () => {
    expect(sdkPackage.automonique.schemaDigest).toBe(
      `${SCHEMA_DIGEST_ALGORITHM}:${PLATFORM_V1_SCHEMA_DIGEST}`,
    );
    expect(sdkPackage.automonique.aggregateSchemaDigest).toBe(
      `${SCHEMA_DIGEST_ALGORITHM}:${SCHEMA_DIGEST}`,
    );
    expect(PLATFORM_V1_SCHEMA_DIGEST).not.toBe(SCHEMA_DIGEST);
  });

  test("the manifest's protocol coordinates are the generated surface's", () => {
    expect(sdkPackage.automonique.protocol).toBe("automonique.platform");
    expect(sdkPackage.automonique.protocolRange).toBe("1-2");
    expect(sdkPackage.automonique.schema).toBe("automonique.platform/v1");
    expect(sdkPackage.automonique.schemas).toEqual([
      "automonique.platform/v1",
      "automonique.platform/v2",
    ]);
  });
});
