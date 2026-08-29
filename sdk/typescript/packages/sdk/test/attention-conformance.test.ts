// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  createAttentionConformanceCorpus,
  normalizeAttentionConformanceCorpus,
} from "../src/testing.ts";

async function sharedCorpus(): Promise<unknown> {
  return JSON.parse(await Bun.file(new URL(
    "../../../../../rust/crates/automonique-protocol/fixtures/platform-v2-attention-conformance-v1.json",
    import.meta.url,
  )).text());
}

describe("shared attention succession corpus", () => {
  test("the exported corpus is the checked-in one, revision for revision", async () => {
    const raw = await sharedCorpus();
    expect(createAttentionConformanceCorpus()).toEqual(
      normalizeAttentionConformanceCorpus(raw),
    );
  });

  test("carries the retention-gap, refusal, and never-observed cases", () => {
    const corpus = createAttentionConformanceCorpus();
    expect(corpus.schema).toBe("automonique.attention-conformance/v1");
    expect(corpus.target).toEqual({
      project: "project-conformance",
      user_workspace: "workspace-conformance",
    });
    const ids = corpus.cases.map(({id}) => id);
    for (const required of [
      "continuous-first-read-requires-revision-one",
      "retention-gap-refuses-and-hides-the-source",
      "authenticated-baseline-bridges-a-gap",
      "refusal-hides-the-projection-and-keeps-the-chain",
      "exact-replay-restores-availability",
      "never-read-source-is-unobserved",
    ]) {
      expect(ids).toContain(required);
    }
    const unread = corpus.cases.find(({id}) => id === "never-read-source-is-unobserved");
    expect(unread?.reads).toHaveLength(0);
    expect(unread?.expected).toEqual({available: false, visible_items: []});
  });

  test("keeps every revision a BigInt above the JavaScript number fence", () => {
    const corpus = createAttentionConformanceCorpus();
    const revisions: bigint[] = [];
    for (const item of corpus.cases) {
      for (const read of item.reads) {
        if (read.kind !== "snapshot") continue;
        revisions.push(read.snapshot.revision);
        for (const entry of read.snapshot.items) revisions.push(entry.revision);
      }
    }
    expect(revisions.every((value) => typeof value === "bigint")).toBe(true);
    expect(revisions.some((value) => value > 9_007_199_254_740_991n)).toBe(true);
    expect(Object.isFrozen(corpus.cases)).toBe(true);
  });

  test("refuses a corpus whose revision arrives as a lossy number", async () => {
    const raw = await sharedCorpus() as {cases: {reads: {snapshot?: {revision: unknown}}[]}[]};
    const lossy = structuredClone(raw);
    const read = lossy.cases[0]?.reads[0];
    if (read?.snapshot === undefined) throw new Error("corpus shape changed");
    read.snapshot.revision = 9_007_199_254_741_102;
    expect(() => normalizeAttentionConformanceCorpus(lossy)).toThrow(
      "not a canonical revision",
    );
  });

  test("refuses a corpus that hides a source while still rendering its items", async () => {
    const raw = await sharedCorpus() as {cases: {id: string; expected: {available: boolean; visible_items: string[]}}[]};
    const incoherent = structuredClone(raw);
    const hidden = incoherent.cases.find((entry) => !entry.expected.available);
    if (hidden === undefined) throw new Error("corpus has no hidden case");
    hidden.expected.visible_items = ["item-a"];
    expect(() => normalizeAttentionConformanceCorpus(incoherent)).toThrow(
      "hides a source while rendering its items",
    );
  });
});
