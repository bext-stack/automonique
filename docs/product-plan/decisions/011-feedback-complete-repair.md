# ADR 011: Feedback-complete autonomous repair and derived gate inventories

- **Status:** accepted for decisions 1 and 2; proposed for decision 3
- **Decision date:** 2026-08-07

## Context

The run that landed CORE-001 exposed two structural frictions that made the
loop look "forever blocked" and cost hours of wall clock.

1. **The build fixer was blind.** The fixed exact-tree verification command
   failed, but the build-fixer prompt carried no builder evidence and no
   sandbox-withheld note. The fixer could not reproduce the failing
   integration test in its provider sandbox (systemd user manager is
   withheld), so it treated every failure as environmental, spent 1h42m
   re-diagnosing three unrelated withheld tests, reverted a correct staged
   fix in its workspace, and returned `blocked` blaming the wrong cause.
   The reviewer path already feeds findings to its fixer; the build path
   fed none.
2. **The builder-test inventory is frozen but its subject is not.** The
   commissioning gate verifies the measured builder receipt's suite
   inventory byte-for-byte against the compiled `spine.rs`
   `EXPECTED_BUILDER_TESTS` contract. Autonomous candidates add tests:
   CORE-001 added 22 product-module tests, raising the lib suite from 69 to
   91 and the inventory from 82 to 104 entries, which invalidated the next
   commissioning until a human regenerated the frozen contract. Every work
   item that grows the suite therefore requires manual intervention before
   the loop can advance — the loop cannot structurally self-continue.

The strict gates themselves earned their keep: the builder caught a real
`verify()` regression that would have silently stalled every future
generation transition, provenance and licence gates held, and no-stub rules
held. The friction is in the *mechanics* of feedback and freezing, not in
the checks.

## Decision

1. **Feed the trusted builder's concrete failures to the build fixer.**
   (accepted, implemented) `build_candidate` now returns the failing gates
   and tests extracted from the builder output
   (`build_failure_findings`), and `build_fixer_prompt` embeds them as
   `<build_findings>…</build_findings>` along with the candidate tree
   digest and the sandbox-withheld note — the same feedback contract the
   reviewer fixer already receives.
2. **The builder-test inventory is a superset, not an exact match.**
   (accepted, implemented) The commissioning and loop review gates compare the
   measured builder receipt inventory against the compiled `spine.rs`
   `EXPECTED_BUILDER_TESTS` contract. Previously the receipt had to match the
   frozen contract exactly, so any autonomous candidate that added tests —
   CORE-001 added 22, CORE-002 added 21 — invalidated the next commissioning
   until a human regenerated the frozen constant. The contract is now a
   minimum: every frozen test and each suite's frozen running count must still
   be present and at least that large, while additional measured tests are
   accepted. Test removal, substitution, duplication and cross-suite movement
   are still rejected.
3. **Let the build fixer run the exact-tree gate in a builder-capable
   sandbox.** (proposed) The provider sandbox withholds systemd and the real
   runtime directory, so the fixer cannot reproduce integration tests even
   when it is told which ones failed. The build-fixer should run in the
   builder's environment, or receive the failing receipt section verbatim,
   closing the reproduce/verify blind spot.

## Consequences

Decision 1 turns a generic "the gate failed" prompt into an exact failing
test list, so a builder regression is repairable in one fixer iteration.
Decision 2 lets autonomous work grow the test suite without invalidating the
next commissioning. Decision 3, once implemented, closes the last reason a
fixer cannot reproduce the failure it is asked to repair.

The strict checks that catch real defects — exact-tree build, provenance,
licence, no-stub/ignore allowances, workload identity — are retained
unchanged.
