# ADR 009: Verification economy

- **Status:** accepted, except the commissioning-tier change marked deferred
- **Decision date:** 2026-08-06

## Context

Measured over CORE-001's first lineage and the same day's commissioning
runs, verification consumed roughly 60-70% of total spend: the author used
422k tokens (much of it running gates), the two reviewers 442k more, and
every harness commit triggered a full commissioning (builder gates plus two
provider reviews, ~15 minutes) regardless of delta size. The same
deterministic gates (fmt, clippy, full test suite) executed four to six
times per iteration across author, reviewers, builder and judge.

Two facts constrain any change. First, each independent layer caught a real
defect the layer below missed in its first week: a work-item reviewer
caught an authorization-oracle defect the author's green tests passed, and
a commissioning reviewer caught unsigned commits the operator shipped
confidently. Independent semantic judgment is the product and is not
reduced. Second, a deterministic gate over a pinned tree digest yields
identical results on every honest re-execution; repeated runs add cost, not
evidence. Commissioning review-a already models the alternative: it
declined to re-execute gates and instead reconciled the builder receipt's
inventory against the exact tree statically.

The ratio also reflects the bootstrap phase: verification scaffolding is a
fixed cost per iteration, so small work items skew the ratio. The
steady-state target is roughly 30% verification share, not the minimum
achievable.

## Decision

1. **One trusted execution per gate per tree.** The builder role is the
   sole executor of deterministic gates for a candidate tree; its receipt
   (evidence digest bound to the tree digest in the builds table) is the
   gate evidence. Work-item reviewers audit the receipt — verify its tree
   binding and reconcile its inventory against the tree — and spend their
   budget on semantic review: contract, correctness, failure paths, lease
   compliance, security. They do not re-run cargo. The author runs only
   targeted checks (touched-module tests, clippy); the full suite and
   release build belong to the builder and judge.
2. **Two independent semantic reviewers remain**, per candidate tree, with
   distinct evidence trails. This layer is exempt from all economy
   measures.
3. **Work-item reviewers dispatch in parallel**, as commissioning reviews
   already do. Observation, not sequence, is their independence guarantee:
   each reviews the same frozen tree in an isolated workspace.
4. **Role environments are pre-provisioned**: read-only toolchain
   (rustup/cargo homes) and a shared per-base-revision build cache, so no
   role pays toolchain download or a cold dependency build. Cache keying by
   immutable base revision keeps the evidence sound.
5. **Role prompts carry their context**: the crosswalk-mapped spec
   documents for the work item, and the commissioning-time list of
   sandbox-withheld capabilities with the known environmental test
   failures, so no role re-derives either.
6. **Fix-iteration reviews focus on the delta**: reviewers of iteration
   N+1 receive the prior findings and the diff since the reviewed tree,
   with the full tree still available. Both reviewers still run on every
   iteration.
7. **Harness commits are batched.** Related operator changes land together
   and are commissioned once per batch. Plan documents and implementation
   that will ship together wait for each other rather than paying separate
   commissioning cycles.
8. **Verification share is measured**, not assumed: provider usage now
   carries true role and provider labels, and the observe script gains a
   spend-by-role report so the coding/checking ratio is a number the
   operator can watch.

**Deferred pending owner decision:** tiering commissioning itself (one
review instead of two for deltas touching neither crates/, policy/, nor
scripts/). Commissioning is the trust root; weakening any of its gates
needs its own deliberate decision, not a rider on this one.

## Implementation batches

- **Batch 1 (small, high leverage):** prompt-contract changes in
  autonomy.rs (receipt audit for reviewers, targeted author checks, context
  injection per point 5), findings/diff carry-forward for fix iterations,
  and the observe spend-by-role report. One commissioning cycle.
- **Batch 2 (structural):** parallel reviewer dispatch (separate store
  connections; fencing and lease renewal reviewed for concurrent holders)
  and pre-provisioned toolchain/build caches in the role environments. One
  commissioning cycle.

## Consequences

Redundant deterministic gate runs disappear (roughly three of five
executions per iteration), reviewer output shifts from gate transcripts to
semantic findings, and iteration wall-clock drops by an estimated
one-third to one-half once reviewers run concurrently and builds start
warm. Receipt trust makes the builds-table binding between receipt digest
and tree digest security-critical; a reviewer must treat a receipt that
does not reconcile against the exact tree as a blocking finding, exactly
as commissioning review-a did. The bootstrap-phase ratio stays
verification-heavy by design; the target ratio applies at steady state,
and the new spend-by-role report is what says whether it is being met.
