<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — wire or delete the automation/approval/batch triad

**Status: DECIDED 2026-08-15 — Option B. Wire the approval lane; keep
automation and batch dormant, and delete nothing.**
The owner delegated this decision to the implementer with the four options
below stated in advance in
[`docs/improvement-plan/implementation/M3-approvals-and-audit.md`](../../docs/improvement-plan/implementation/M3-approvals-and-audit.md)
§ `#17`. The options are kept in full: the point of this record is which was
chosen and why, which is not readable from the outcome alone.

| Field | Value |
|---|---|
| Question | Three control lanes — automation, approval, batch — total 18,004 lines that no consumer reads. Wire them, or delete them? |
| Raised by | audit finding **F-06**, [`docs/improvement-plan/audit-findings.md`](../../docs/improvement-plan/audit-findings.md); improvement-program item 14 = issue **#17** |
| Decided | **Option B.** The approval lane gets its first real consumer in this milestone. Automation and batch stay recorded-only, unconsumed, and undeleted, until their scheduler consumer lands |
| Code changed by this decision | **none.** This record is the deliverable; it gates issues #19–#22 and #24 |
| Deletion performed | **none.** No file, table, protocol variant or test is removed |

## The reframing this decision rests on

F-06's framing is "~16k lines of control surface that nothing reads". The
measurement holds — 18,004 lines across the triad's protocol, store and CLI
modules, before daemon handlers and tests — and so does the claim that nothing
consumes them. The daemon's only accesses to the three stores are two status
counters and the three handlers' own bodies; the execution lane, which is the
one lane that starts real work, consults none of them.

But "nothing reads it" and "it is dead" are different claims, and only the
first one is true here. This is *unconsumed precursor state* for machinery the
roadmap schedules later, and the modules say so themselves rather than
pretending otherwise — each handler's doc comment states its own inertness, and
`approval_ledger.rs` opens by saying it does not enforce the decision it
records.

Two of the three lanes already store exactly the vocabulary the scheduler will
need, in a form that is durable, fenced and tested:

- `automations.enablement IN ('enabled','paused','archived')`
  (`rust/crates/automonique-store/src/automation_store.rs`, `SCHEMA_V1`) is the
  scheduler's pause/cancel axis;
- `batches.concurrency IN ('sequential','bounded_parallel')` with
  `concurrency_max` bounded 1–256
  (`rust/crates/automonique-store/src/batch_registry.rs:288-297`) is the
  scheduler's bounded-parallelism axis.

So the real question is not "is this code worth keeping". It is **which of the
three lanes gets a consumer in M3, and which wait for the scheduler**.

## The four options, as they were put

**Option A — wire all three now.** M3 delivers approval consumers *and* an
automation trigger evaluator *and* a batch executor.
*Cost:* the automation and batch consumers **are** the scheduler (roadmap item
42 / issue #45), built early and without the safety-property specification that
roadmap item 10 produces. *Rejected:* it builds the scheduler out of order and
without its spec.

**Option B — wire approvals; hold automation and batch (chosen).** M3 gives
the approval lane a consumer and leaves automation and batch recorded-only, but
re-labelled: their doc comments stop saying "nothing reads this and there is no
scheduler" and start saying "this is the scheduler's durable input; the
scheduler is issue #45". Nothing is deleted; nothing new is built on them.
*Cost:* 8,752 + 5,203 lines stay unconsumed for the length of M8.

**Option C — wire approvals; delete batch; hold automation.** As B, but the
batch lane (5,203 lines, its 13-variant refusal enum, and two test files) is
deleted on the argument that concurrency policy is a scheduler concern the
scheduler should own rather than inherit.
*Cost:* issue #45 re-derives the concurrency policy, the ordinal/member state
machine and the sequence-coupling refusals from scratch. *Rejected:* defensible
only if the scheduler is to be built around leases and an outbox rather than
around a batch registry, and that is not decided.

**Option D — delete all three; rebuild an approval lane purpose-built.**
*Cost:* ~18k lines and six test files deleted, then a new approval lane written
that would look substantially like the existing one minus its fencing, ceiling
and conflict semantics. *Rejected:* the approval half's design is the strongest
existing asset in this area, and the gap is a consumer, not the code.

## Why Option B

**1. The approval lane's gap is a consumer, not a defect.** Its decision ledger
is write-once, replay-safe and conflict-naming, with the three-way
recorded / already-recorded / conflict discipline every durable module in this
tree uses. Deleting it and rewriting it is the only option that spends 6–8
engineer-days to arrive back at a weaker version of what exists.

**2. Deleting the other two costs the scheduler its substrate.** The pause
lattice and the bounded-parallelism policy are the two axes issue #45 must
implement. They exist, they are STRICT-schema'd, they carry their own
`user_version` ladder, and they have integration tests. Deleting them converts
a design the scheduler can inherit into a design the scheduler must invent
under deadline.

**3. Carrying them is cheap, and the store's discipline is why.** Every store
in this tree is its own SQLite file with its own `user_version` and an
expand-only migration ladder. An unconsumed store costs one file that is never
opened, one schema constant, and its share of the test suite's runtime. It does
not constrain any other module's schema, does not participate in any
transaction, and cannot be a source of coupling — because nothing reads it.
That is the same property that makes the code unconsumed and the property that
makes carrying it nearly free.

**4. Option B is the only option under which #18–#24 is net-new capability.**
Under D, roughly half of #19 is re-implementation of deleted code.

## What this decision does *not* say

- It does **not** authorize building any part of the scheduler in M3. The
  automation and batch lanes stay exactly as inert as they are today. An
  automation registered in M3 still triggers nothing; a batch registered in M3
  still schedules and throttles nothing. Any change that makes either of them
  *act* is out of scope for this milestone and belongs to issue #45.
- It does **not** promise the two dormant lanes survive forever. It defers the
  delete/keep question for them to the point where their consumer is actually
  designed. If issue #45 chooses a lease-and-outbox scheduler that wants
  neither table, deleting them then is a smaller and better-informed decision
  than deleting them now — and it comes back here as a new record rather than
  being argued in a pull request.
- It does **not** change any protocol, table, refusal vocabulary or CLI verb.
  All three lanes are deliberately outside the closed admin command registry,
  so this decision moves nothing in or out of it.

## The third approval concept, named

There are three separate approval notions in the tree, and this record names
which survives so #19 does not have to relitigate it:

| Concept | Where | Disposition |
|---|---|---|
| the durable decision ledger | `automonique-store/src/approval_ledger.rs` | **survives** — it is the lane being wired, and #19 adds a request table beside it rather than changing it |
| `ApprovalPolicy` in the command registry | `automonique-protocol/src/command_registry.rs` | **survives** — it is the per-command annotation, a different axis, and issue #22 is its consumer |
| `automation::decide_unattended` | `automonique-protocol/src/automation.rs:1073` | **dormant with automation.** It is the automation lane's own in-memory gate, its only callers are tests, and it is dormant for exactly the same reason and until exactly the same milestone as the rest of that lane |

A fourth name collision will bite during #19 and is recorded here so it is
expected rather than discovered: `automation::ApprovalRequest` (an in-memory
value), `approval_api::ApprovalRequest` (the wire request enum) and
`connector::ApprovalRequired` are three unrelated types with confusable names.

## What follows from this decision

- **#18** (admin cancel verb) and **#23** (hash-chained audit records) were
  never gated on this: cancellation rides the cancel ledger and dispatcher, and
  the audit chain is a new module. Both proceed independently, and in this
  milestone they land first.
- **#19–#21, #24** are unblocked and take the "wire" column of the plan's
  branch table: a new `approval_requests` table beside the unchanged decision
  ledger, reusing the existing wire types.
- **#22** is a policy-crate change and is triad-independent either way.
- The doc-comment re-labelling Option B calls for — the automation and batch
  handlers and module headers changing from "nothing reads this" to "this is
  the scheduler's durable input, and the scheduler is issue #45" — is a
  documentation change that belongs with the milestone's other prose repairs,
  not with this record. This record deliberately ships no code so that the
  decision is reviewable on its own.

## What would change it

A decision on issue #45's shape. If the scheduler is designed around leases and
an outbox rather than around the batch registry, Option C becomes the better
answer for the batch lane alone, and it is recorded here as an amendment naming
that design. Nothing else reopens this.
