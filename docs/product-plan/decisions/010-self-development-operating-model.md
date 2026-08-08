# ADR 010: Self-development operating model

- **Status:** accepted
- **Decision date:** 2026-08-06

## Context

Three days after first load, zero product work items have merged. The spine
works — every defect this week was caught before damage — but throughput
has not followed, for four reasons the journal makes measurable: a failed
lineage discarded its verified work and re-authored from scratch; passes
ran only when the operator typed the command; every iteration paid
redundant deterministic gate runs and cold context; and each small harness
fix cost a full commissioning cycle before the loop could run again. A
safety machine with no shipped output is cost, not capability.

## Decision

1. **Resume, never re-author.** Every candidate commit is pinned under
   `refs/automonique/candidates/<work-id>/<tree12>` when it is created, the
   refs migrate across lineage cutovers, and a claimed work item with a
   pinned candidate that applies to the current base seeds its workspace
   from it and goes straight to build and review. A requeue is a
   checkpoint, not a discard.
2. **Build before review.** The trusted builder runs the full deterministic
   gates exactly once per candidate tree, before any reviewer dispatch. A
   candidate that fails its build goes straight to the fixer without paying
   for reviews. Reviewers receive the bounded builder receipt inline, audit
   it against the tree, and spend their budget on semantic review — the
   receipt-trust contract of ADR 009, now implemented.
3. **Continuous operation is the default.** The loop runs as a supervised
   `develop --loop` service; a single explicit pass is a debugging tool,
   not the operating mode. Progress must not require the operator's
   presence.
4. **Division of labor until the loop earns self-hosting.** The autonomous
   loop ships product-plan work items. The operator ships harness
   improvements as signed, batched commits — one commissioning cycle per
   batch, never per fix. Extending the work DAG to harness code (true
   self-hosting of the infrastructure) is deferred until the loop has
   merged three product items; that trigger is measurable, not
   aspirational.
5. **Progress is measured, not felt.** The progress facts are merged work
   items and `scripts/observe --spend` — token and wall-clock spend by
   role with the coding/checking share against ADR 009's ~30% steady-state
   target. Feelings of non-progress get checked against those two numbers,
   and so do claims of progress.
6. **Role prompts carry their contract.** The crosswalk-mapped spec
   documents, the commissioning-verified sandbox-withheld facts, and any
   prior-iteration findings ride in the prompt, so role budget goes to the
   work instead of rediscovery.

## Consequences

A harness failure after verified work now costs one build-plus-review round
on resume (~10 minutes) instead of a full re-author (~30 minutes and the
author's token budget). Broken candidates stop consuming review spend. The
loop can work through ready items overnight within its per-item budget
envelope, and the first merged product item — the immediate milestone —
gates nothing but proves the machine. The remaining ADR 009 batch
(parallel reviewer dispatch, pre-provisioned toolchain and build caches)
lands as the next operator batch, or as early DAG items once the
self-hosting trigger is met. Pinned candidate refs accumulate in the
mirror; they are small, and pruning follows a work item's completion
receipt, never precedes it.
