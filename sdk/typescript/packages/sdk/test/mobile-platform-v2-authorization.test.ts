// SPDX-License-Identifier: Apache-2.0

import { describe, expect, test } from "bun:test";

import {
  MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE,
  MobileCredentialId,
  ProjectId,
  decodeMobilePlatformV2Authorization,
  encodeMobilePlatformV2GrantRequest,
  parseCanonical,
  toCanonicalBytes,
} from "../src/index.ts";

const descriptor = {
  actions: ["query_work_contexts", "get_lineage"],
  actor_id: "operator:mobile",
  authorization_revision: 7,
  credential_id: `mc_${"A".repeat(43)}`,
  credential_revision: 3,
  delegation_id: `md_${"B".repeat(43)}`,
  expires_at_ms: 1_900_000_000_000,
  issued_at_ms: 1_800_000_000_000,
  principal_generation: 9,
  project_roots: ["project-a", "project-b"],
  schema: "automonique.mobile-platform-v2-authorization/v1",
  server_identity: `sha256:${"c".repeat(64)}`,
  tenant_id: "tenant-a",
} as const;

describe("mobile Platform v2 delegated authorization", () => {
  test("admits the exact bounded sorted server document", () => {
    const admitted = decodeMobilePlatformV2Authorization(
      parseCanonical(new TextEncoder().encode(JSON.stringify(descriptor))),
    );
    expect(admitted.credential_revision).toBe(3n);
    expect(admitted.principal_generation).toBe(9n);
    expect(admitted.project_roots).toEqual(["project-a", "project-b"]);
    expect(MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE).toBe(
      "application/vnd.automonique.mobile-platform-v2-authorization.v1+json",
    );
  });

  test("refuses unsorted, duplicate, unknown, and widened documents", () => {
    for (const hostile of [
      { ...descriptor, project_roots: ["project-b", "project-a"] },
      { ...descriptor, actions: ["get_lineage", "get_lineage"] },
      { ...descriptor, actions: ["execute_review_action"] },
      { ...descriptor, ambient_authority: true },
    ]) {
      expect(() =>
        decodeMobilePlatformV2Authorization(
          parseCanonical(new TextEncoder().encode(JSON.stringify(hostile))),
        ),
      ).toThrow();
    }
  });

  test("operator grant encoding carries project identifiers, never client paths", () => {
    const encoded = new TextDecoder().decode(
      toCanonicalBytes(
        encodeMobilePlatformV2GrantRequest({
          actions: ["submit_mutation", "query_work_contexts"],
          credential_id: MobileCredentialId(`mc_${"A".repeat(43)}`),
          project_roots: [ProjectId("project-b"), ProjectId("project-a")],
        }),
      ),
    );
    expect(encoded).toBe(
      `{"actions":["query_work_contexts","submit_mutation"],"credential_id":"mc_${"A".repeat(43)}","project_roots":["project-a","project-b"]}`,
    );
    expect(encoded).not.toContain("/");
  });
});
