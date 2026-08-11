<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — two amendments to the R1-12 journal contract

**Status: DRAFT. Awaiting owner. Both rows remain open and R1-12 is not done.**

| Field | Value |
|---|---|
| Proposed in | `plan/contracts/R1-12.md`, § Amendments |
| Rows blocked | `Replay purity`, `Cursor monotonicity` |
| Asks for | acceptance of A1 and A2, and of limits L1 and L2 |
| Recommendation | accept both |

The candidate cannot close these itself. `AGENTS.md`: *a candidate is judged by
those rules as they stand at its own admitted base, never by the version it
introduces.* So the superseded wording stays in the check table verbatim,
`plan/evidence/R1-12.json` answers both rows against that superseded wording,
and both are recorded as not passing — even though the work each amendment
describes is implemented and measured. That is the rule working, not a stall.

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
nothing it did not already own, proven by compile-fail coverage paired case for
case with a passing twin — and names what is left over:

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
receive, not an event. For a retained window `first ..= last` there are
`last - first + 2` resumable positions — one more than the window retains — so
the resumable set can never coincide with the retained set. Read literally, a
caught-up consumer sits at `last + 1`, is told to resync, takes a snapshot
through `last`, returns to `last + 1`, and is told to resync again. **The
literal reading livelocks the ordinary caught-up state.**

The amendment restates the rule in the resumable window `first ..= last + 1`,
below and above alike, conceding exactly one position as limit L2.

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

## If both are accepted

1. Apply the amended wording into the check table and § Journal contract,
   keeping the superseded text quoted in § Amendments.
2. Re-answer both rows in `plan/evidence/R1-12.json` against the amended
   wording; the work they describe is already implemented and measured.
3. `R1-12` becomes eligible for `done` under the same Option B recording as its
   siblings.
4. Open an item for the `src/event.rs` cursor duplication and its skipping hole.

## What stays open regardless

`plan/evidence/R1-12.json` carries adversarial findings D5a and D5b — a mutable
accessor under a different name, and an unchecked cursor `set_position` — both
of which still leave the suite green. Accepting A1 and A2 does not touch them.
