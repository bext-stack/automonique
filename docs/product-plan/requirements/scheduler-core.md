# Scheduler core

**Status.** Drafted 2026-08-15 as part of M2 #13. Authored in this repository —
not transferred planning material, and not derived from legacy source. The
precise semantics below are **owner-confirmable**: this is one of the four
properties `launch-roadmap.md` calls "decisions that cannot be inferred", and
`reference/feature-parity.md:90` calls it "the largest single gap" — the
scheduler core is entirely unpinned by fixtures.

The scheduler conformance suite covers bounded parallelism, per-scope
serialization, and pause/cancel behavior.

## The property

The scheduler admits work under an explicit fence and guarantees three things.

**Bounded parallelism.** Never more than the declared limit runs at once, and
the limit is a real bound rather than a large number.

**Per-scope serialization.** At most one item per scope runs at a time,
regardless of how many slots are free, and a scope's items start in the order
they were submitted.

**Pause and cancel, without losing or duplicating work.** A paused scope starts
nothing new and does not disturb what is already running. Cancelling queued work
means it never runs. Cancelling running work is a *request*: custody stays with
the scheduler until the terminal commit lands.

## Why each of the three is a safety property

**Bounded parallelism** is a resource bound. An unbounded scheduler does not
fail by running too much work; it fails by running exactly as much as the host
can stand and then slightly more, at which point every lease in flight is at
risk rather than the one item that was over budget.

**Per-scope serialization** is a correctness bound. Two agents editing one
workspace at the same time is not slow, it is wrong, and no amount of retrying
fixes an interleaved edit. What a scope *is* — a workspace, a conversation
thread, a tenant — is a deployment decision and *owner-confirmable* per surface;
the property is that whatever it is, two of its items never overlap.

**Pause and cancel** are the operator's stop button. A stop button that silently
drops work is worse than no stop button: the operator believes the work is
stopped, the system believes it never existed, and the two beliefs are only
reconciled by a customer noticing. Hence the asymmetry between queued and
running cancellation below.

## Failure-mode semantics, exactly

| Verb | Precondition | Result |
|---|---|---|
| `submit` | identity not already admitted | queued; nothing starts |
| `submit` | identity already admitted | `duplicate_work` |
| `tick` | the presented fence is the held one | starts what policy allows, and reports exactly what started |
| `tick` | the presented fence is stale | `stale_fence`, and **nothing** starts — a stale tick is not a partial tick |
| `complete` | work holds a slot | terminal: `completed`, or `cancelled` if a stop was requested |
| `complete` | work is queued or terminal | `not_running` |
| `cancel` | work is queued | `never_started`; terminal immediately, and it never runs |
| `cancel` | work is running | `stop_requested`; **the slot stays held** |
| `cancel` | work is terminal | `already_terminal` |
| `pause` / `resume` | any | idempotent; a scope pauses to a state, not by a counter |

Five bindings this table is making explicit:

1. **Admission and starting are separate.** `submit` never starts anything;
   only `tick` does. Collapsing them would make the parallelism bound impossible
   to observe, because there would be no moment at which more work is ready than
   there are slots.
2. **A slot is freed only by a terminal commit.** Not by a stop request, not by
   a pause, not by a timeout. This is what makes "cancel a running item" honest:
   the scheduler is still responsible for that item until its outcome is
   durable, exactly as `automonique_core::DurableScheduler` treats a claim.
3. **Pause is not cancel.** Pausing a scope stops *admission* from it. Work
   already running keeps running and may complete normally. An operator who
   wanted the running work stopped cancels it; conflating the two takes a
   decision away from them.
4. **Resume loses nothing and duplicates nothing.** The queue survives the
   pause in order, and resuming starts the item that was next — not the first,
   and not two of them.
5. **Nothing starts twice.** Across pause, resume, stop requests and completion
   churn, one item starts at most once. A scheduler that restarts work has not
   lost anything a caller can see; it has run the same side effects twice, which
   is what every other property in this corpus exists to prevent.

### The parallelism limit

The conformance band is 2 to 1024 (`MIN_PARALLELISM_LIMIT`,
`MAX_PARALLELISM_LIMIT`), both **owner-confirmable**. Neither is a
recommendation. The ceiling exists to refuse "unbounded, spelled as a big
integer". The floor exists because a scheduler that never runs two things at
once satisfies every parallelism bound by accident, so a suite could not tell a
correct implementation from a serial one — one slot is a valid *operational*
setting and a useless *conformance* subject.

Admission fairness beyond per-scope FIFO — priorities, weights, starvation
control across scopes — is deliberately **not specified here**.
`feature-parity.md:90` says the replacement should "add admission/fairness
policy", and that is a product decision on top of this floor rather than part of
it. What this document fixes is that no fairness policy may break the three
guarantees above.

## Conformance

The suite is `automonique_core::scheduler_conformance`
(`rust/crates/automonique-core/src/scheduler_conformance.rs`), generic over one
trait, `SchedulerCore`. It lives in `automonique-core` rather than beside the
other three safety suites because it is admitted under that crate's
`SchedulerFence`, and a copy of that vocabulary in another crate would be a
second authority rather than a shared one.

The suite takes a **factory** rather than one subject, and builds a fresh
scheduler for every case. Pause state and occupied slots are scheduler-wide: a
case that left a scope paused would silently change the meaning of every case
after it, and the result would be an ordering puzzle rather than a
specification.

| Case | What it pins |
|---|---|
| `the_declared_parallelism_limit_is_bounded` | a limit is a limit; checked before anything else, since it makes the rest vacuous |
| `parallelism_never_exceeds_the_declared_limit` | with more ready work than slots, and freeing one slot admits exactly one item |
| `one_scope_runs_one_item_at_a_time` | the scope, not the limit, is what holds the rest back |
| `a_scope_admits_in_submission_order` | first submitted, first started |
| `a_paused_scope_starts_nothing_new` | including after a slot frees up, and including when paused twice |
| `a_pause_does_not_stop_running_work` | it keeps running, and it can still complete |
| `resume_loses_no_work_and_duplicates_none` | the next item starts, and the rest is still queued |
| `cancelled_queued_work_never_runs` | terminal immediately, and still not started once slots free |
| `cancelled_running_work_keeps_its_slot_until_terminal` | a stop request frees nothing, and commits as cancelled |
| `a_stale_fence_starts_nothing` | authority is a parameter, and the wrong one starts nothing at all |

Every case also checks that nothing started twice within it.

`rust/crates/automonique-core/tests/scheduler_conformance.rs` runs the suite
against the reference model at the band's floor, against a wider scheduler (so
the suite describes schedulers rather than one narrow one), and against six
**mutants**: one that declares a bound it does not enforce, one that never
serializes a scope, one that ignores a pause, one that frees the slot on a stop
request, one that reports a cancellation it did not perform, and one that ticks
under its own fence rather than the presented one. Each must fail, at the case
that names what was broken.

## What this does and does not prove

The reference model still holds rows in vectors and runs nothing. The production
state-machine implementation is
`automonique_store::durable_scheduler::DurableSchedulerStore`: its SQLite
transactions durably preserve admission order, pauses, occupied slots, stop
requests and terminal state; every operation checks the installed generation
fence; and the generic suite runs against that implementation. Generated
operation sequences additionally compare it with the reference model across
reopens.

That binding proves the scheduler core and restart persistence. The daemon
integration (M8 #45) is `automonique_daemon::automation_scheduler`: a worker
that opens the production store above under the generation fence, derives one
occurrence per due instant from the durable automation registry — whose
`RegisterAutomation` now carries a canonical schedule, a scope and a bounded
prompt — admits it as work identified by
`automation:<automation_id>:<instant>`, and submits what `tick` starts as a
normal item on the durable synthetic lane under the same key. The three
properties reach the live surface unchanged: the core's limit bounds how many
occurrences are on the lane at once, the automation's scope is the core's
scope, and an operator's pause or archive on the control lane is answered with
the core's own `cancel` verbs — queued work never starts, running work keeps
its slot until the lane's terminal commit. A committed `running` row is still
never silently requeued after a crash: the worker reads the lane back by key
and either waits on the delivery it finds or hands over the one it never made,
which is how the no-duplicate-start property survives a restart.
`requirements/automation-goals-and-triggers.md` § *The occurrence key and the
fence, as built* states the derivation, the catch-up policy and what still
does not ship (cron, triggers, a provider executor behind the prompt).

The remaining obligations this document does not restate — fencing writes as
well as work (#50), boot- and suspend-aware lease time (#51), and the durable
cancellation ledger (#49) — are tracked on their own issues.
`automonique_protocol::safety_conformance::PENDING_BINDINGS` still names the
live surface, because the conformance suite itself is bound to the store and
not to the worker: the worker is proved by its own deterministic tests under a
fake clock rather than by the generic suite.

## Provenance

`reference/feature-parity.md:90` records the bounded-parallelism /
per-thread-serialization / pause-cancel row as **Replace** with no fixture, and
its evidence column is the "largest single gap" note this document opens with.
`launch-roadmap.md` names the same property as the fourth of the four that must
be deliberately re-specified. This document is that re-specification, written
from the stated requirement rather than reconstructed from the prior
implementation.
