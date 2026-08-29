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
      { ...descriptor, actions: ["generic_execute"] },
      { ...descriptor, ambient_authority: true },
    ]) {
      expect(() =>
        decodeMobilePlatformV2Authorization(
          parseCanonical(new TextEncoder().encode(JSON.stringify(hostile))),
        ),
      ).toThrow();
    }
  });

  test("admits narrowly delegated review execution and receipt lookup", () => {
    const review = {
      ...descriptor,
      actions: ["execute_review_action", "get_review_receipt"],
    } as const;
    expect(
      decodeMobilePlatformV2Authorization(
        parseCanonical(new TextEncoder().encode(JSON.stringify(review))),
      ).actions,
    ).toEqual(["execute_review_action", "get_review_receipt"]);
  });

  test("keeps capability reads and check reruns separate from legacy review execution", () => {
    const review = {
      ...descriptor,
      actions: [
        "get_review_capabilities",
        "execute_review_action",
        "rerun_check",
        "get_review_receipt",
      ],
    } as const;
    expect(
      decodeMobilePlatformV2Authorization(
        parseCanonical(new TextEncoder().encode(JSON.stringify(review))),
      ).actions,
    ).toEqual([
      "get_review_capabilities",
      "execute_review_action",
      "rerun_check",
      "get_review_receipt",
    ]);
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

  test("carries the three pull-request families as separately withheld grants", () => {
    // The proposer delegation: may open and update a pull request, may not
    // land one. This is the state a deployment lands in when it wants
    // proposals from a phone but never a merge, and the client has to be able
    // to both request it and read it back.
    const proposer = {
      ...descriptor,
      actions: ["open_pull_request", "update_pull_request"],
    } as const;
    expect(
      decodeMobilePlatformV2Authorization(
        parseCanonical(new TextEncoder().encode(JSON.stringify(proposer))),
      ).actions,
    ).toEqual(["open_pull_request", "update_pull_request"]);

    // The server sorts by the declaration order of its own action enum, which
    // appends the three families in this order. Reproducing that order is the
    // whole reason the vocabulary is an ordered array rather than a set.
    expect(
      new TextDecoder().decode(
        toCanonicalBytes(
          encodeMobilePlatformV2GrantRequest({
            actions: [
              "merge_pull_request",
              "open_pull_request",
              "execute_review_action",
            ],
            credential_id: MobileCredentialId(`mc_${"A".repeat(43)}`),
            project_roots: [ProjectId("project-a")],
          }),
        ),
      ),
    ).toBe(
      `{"actions":["execute_review_action","open_pull_request","merge_pull_request"],"credential_id":"mc_${"A".repeat(43)}","project_roots":["project-a"]}`,
    );

    // A document out of that order is one no server minted.
    expect(() =>
      decodeMobilePlatformV2Authorization(
        parseCanonical(
          new TextEncoder().encode(
            JSON.stringify({
              ...descriptor,
              actions: ["merge_pull_request", "open_pull_request"],
            }),
          ),
        ),
      ),
    ).toThrow();
  });
});
