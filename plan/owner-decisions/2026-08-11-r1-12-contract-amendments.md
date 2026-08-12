<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — two amendments to the R1-12 journal contract

**Status: ACCEPTED by contemporaneous owner instruction on 2026-08-12.**

| Field | Value |
|---|---|
| Proposed in | `plan/contracts/R1-12.md`, § Amendments |
| Rows blocked | `Replay purity`, `Cursor monotonicity` |
| Decision | accept A1 and A2, including limits L1 and L2 |
| Authority | owner accepted A1/A2 and instructed agents to proceed without further owner confirmations; repository safety and exact-tree controls remain in force |
| Candidate base | `b43b148ae1e4a7fdc5702a6f1aab39877258e821` |
| Effective | only after this decision is integrated, for descendant attempts |

The implementation candidate could not close these itself. `AGENTS.md`: *a candidate is judged by
those rules as they stand at its own admitted base, never by the version it
introduces.* The superseded wording remains quoted in the contract's Amendments
section. `plan/evidence/R1-12.json` answers both rows against the wording at its
own base and remains unchanged. This separately integrated decision makes the
amended wording authoritative only for later attempts.

## Candidate report

| Field | Recorded value |
|---|---|
| Immutable base | `b43b148ae1e4a7fdc5702a6f1aab39877258e821` |
| Allowed paths | `plan/contracts/R1-12.md`, `plan/owner-decisions/2026-08-11-r1-12-contract-amendments.md`, `.automonique/dev/objectives.json` |
| Objective | apply the already-proposed A1/A2 wording after explicit owner acceptance, without implementing product behavior |
| Budget | one bounded policy candidate; one deterministically regenerated objective manifest; no dependency, source, test, graph, metric or baseline changes |
| Checks | `python3 plan/check.py --verify` pass; `python3 tools/program.py --verify` pass; `python3 tools/guides.py --verify` pass; `git diff --check` pass; `python3 -m unittest tools.test_git_broker tools.test_local_integration` pass (16 tests); typed exact-tree integration follows |
| Licence | `Elastic-2.0` |
| Stop conditions | stop on base drift, any changed path outside the three-file lease, any attempt to make the decision retroactive, any weakened unrelated check, or any required check that remains failed after deterministic regeneration |
| Review | first review: 1 reviewer, 4 blocking findings; re-review: 1 reviewer, 0 blocking findings, accepted for typed integration |

## A1 — `Replay purity` asks for something Rust cannot express

The row demands that *no effect, outbox, notification or transport handle is
reachable inside replay, proven by compile-fail coverage*.

No implementation can satisfy that sentence. A projection owns its fields, so a
projection constructed holding a channel or file handle reaches it inside
`apply` — having **brought** it rather than been **given** it. This was measured,
not argued: a projection whose own field is an `std::sync::mpsc::Sender` and
whose `apply` calls `std::fs::write` compiles against the built rlib, and both
effects happen inside `Journal::replay`. "The argument list contains no handle"
and "the callee performs no effect" are different claims, and only the first is
a type.

The amendment states the boundary that does exist — replay hands a projection
nothing it did not already own. Paired cases cover arity and callback
signatures, compile-fail cases cover the named `Outbox` construction routes,
and API inspection confirms there is no other exported constructor. It also
names what is left over:

> **Limit L1.** A projection can smuggle in its own handle. A discipline, not a
> guarantee, and irreducible in safe Rust for every callback interface this
> crate defines. Closing it needs either an effect system the language does not
> have, or enforcement at a boundary that can deny a syscall — the process or
> sandbox boundary modelled elsewhere in this workspace.

**Why accept.** The alternative is a row that can never be closed by anyone,
which makes it worthless as a gate and teaches readers that rows are decorative.
L1 is written so a later item claiming replay purity must say which of the two
routes it took.

## A2 — `Cursor monotonicity` is off by one, and the literal reading livelocks

The row demands that *an out-of-range cursor yields `resync_required`*.

A cursor names the boundary **before** the next position its consumer will
receive, not an event. For a retained window `first ..= last` whose `last` is
below `u64::MAX`, there are `last - first + 2` resumable positions — one more
than the window retains. At `u64::MAX`, the caught-up boundary saturates to
`last`. Read literally in the ordinary non-saturated case, a caught-up consumer
sits at `last + 1`, is told to resync, takes a snapshot
through `last`, returns to `last + 1`, and is told to resync again. **The
literal reading livelocks the ordinary caught-up state.**

The amendment restates the rule in the resumable window
`first ..= last.saturating_add(1)`, below and above alike, conceding one
additional representable position as limit L2 when `last < u64::MAX`.

**This one is not only bookkeeping.** The previous "outside means below" reading
left a hole in the other direction: every position *above* the window resumed
live, so a cursor left ahead of a truncated or rebuilt topic was served live
delivery starting at a position the topic had not reached — **silently skipping
everything written between `last + 1` and the cursor.** The amended window
classifies that as `resync_required`. That is a behaviour change and is
disclosed as one rather than folded in.

**Recorded, not fixed:** `event::resolve_subscription` applies the superseded
"below only" rule to the parallel cursor type in `src/event.rs`, so it still
carries the skipping hole this amendment closes in `journal.rs`. That file was
outside R1-12's lease. The duplication of `JournalCursor`/`RetainedRange`
against `ConsumerCursor`/`resolve_subscription` is the underlying defect and
neither half is fixable from inside R1-12's lease. **It should get its own
item.**

## Effect of acceptance

The amended wording is applied to the check table and § Journal contract while
the superseded wording remains quoted in § Amendments. Earlier evidence and
verdicts remain immutable and are not reinterpreted. A later R1-12 attempt is
judged against the amended wording, must still close every other contract gap,
and may become `done` only through its own exact-tree completion transaction.
The `src/event.rs` cursor duplication and skipping hole remain a separate
follow-up finding.

## Other cross-item defects found this session, each needing its own item

None of these is fixable from inside the lease that found it, and none is
claimed as done anywhere.

1. **`src/event.rs` carries the cursor hole A2 closes.** `resolve_subscription`
   applies the superseded "below only" rule to the parallel cursor type, so a
   cursor left ahead of a truncated topic is still served live delivery from a
   position the topic never reached. `JournalCursor`/`RetainedRange` against
   `ConsumerCursor`/`resolve_subscription` is one concept implemented twice, and
   only one copy now has the fix. The duplication is the underlying defect.

2. **R0-09 and R0-10 never met.** R0-09 publishes
   `plan/inventory/surface/restore-dependencies.json`, schema
   `automonique.restore-dependencies/v1`, carrying `"consumer": "R0-10"` — it
   was written for R0-10 by name. R0-10's consumer declares the path
   `spikes/inventory/restore-dependencies.json` and the schema
   `automonique.recovery.restore-dependencies.v1`, and pointed at R0-09's real
   file it refuses with `unknown_key`, `consumed_entries=0`. Both
   implementations are correct — the consumer declining a document it does not
   understand is the right behaviour. The defect is that **neither contract
   fixed the path or the schema**, so a producer and its named consumer can both
   be complete and still not connect. Whoever resolves it picks one interface
   and writes it into both contracts.

3. **`plan/gate.py --commit` is disabled outright**, and this decision file's
   sibling is wrong about why. `2026-08-11-retroactive-completion-recording.md`
   says completion could not be gated because the files were already committed
   and the lease needs them dirty. That is true but not the binding constraint:
   `--commit` refuses unconditionally with *"disabled until baseline, history,
   done status and regenerated plan artifacts can be included and verified in
   one exact completion tree."* So the gate cannot authorize a completion today
   in **any** state, and that decision's item 5 — "future items go through
   `plan/gate.py --commit` before landing" — is not currently possible. What
   *is* possible, and was done for this batch, is `--dry-run`: a full completion
   preflight that checks readiness, lease, evidence, plan integrity and metric,
   and authorizes nothing. Six of nine items passed it. Enabling `--commit` is
   its own piece of work.

## What stays open regardless

`plan/evidence/R1-12.json` carries adversarial findings D5a and D5b — a mutable
accessor under a different name, and an unchecked cursor `set_position` — both
of which still leave the suite green. Accepting A1 and A2 does not touch them.
