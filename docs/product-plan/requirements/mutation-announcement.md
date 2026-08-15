# Announce the target before mutating it

**Status.** Drafted 2026-08-15 as part of M2 #13. Authored in this repository —
not transferred planning material, and not derived from legacy source. The
precise semantics below are **owner-confirmable**: this is one of the four
properties `launch-roadmap.md` calls "decisions that cannot be inferred". The
one number an owner is most likely to want to change, the stop-check window, is
marked where it appears.

## The property

Before any externally visible mutation, the system writes a **durable
announcement naming the exact target**, and then waits out a **stop-check
window** during which an operator can stop it.

A mutation proceeds only when all five of these hold:

1. the request cites an announcement;
2. that announcement exists;
3. it names the **exact** target being changed;
4. its stop-check window has closed;
5. it has not been stopped, and has not already authorized a mutation.

Any other request is refused, by a reason that says which of the five failed.

## What "externally visible" means here

A mutation is externally visible when someone other than this system can observe
it without reading our logs: a change to a workspace, a message edited or
removed on a chat surface, a state change on an external service, an outbound
message to a person. Reading is not mutation. Writing to our own durable state
is not externally visible on its own; it becomes so when an effect derived from
it leaves the system, and it is that effect the announcement precedes.

The boundary is *owner-confirmable* per surface as surfaces are built. The
default this document sets: if there is doubt about whether an effect is
externally visible, it is, and it gets announced.

## Three things that make this more than a log line

**Durable, not sent.** The announcement is a record written before the window
opens, not a message posted to a channel. A message is a side effect: it can be
lost, delayed, or delivered *after* the mutation it was supposed to precede,
and none of those failures is visible from the sending side. Publishing the
announcement to a human-readable surface is expected and is how the stop-check
becomes usable — but the record is the contract, and the record comes first.

**Exact, not descriptive.** A target names one thing: a scope and a resource
within it, neither of which may be a pattern (`*`, `?`, `%`) or a class word
(`all`, `any`, `each`, `every`, `everything`). "About to update the sites" is
not a target. The test is whether a reader can use the announcement to decide
whether to stop, and a reader cannot decide about a category.

**One announcement, one mutation.** An announcement is consumed by the mutation
it authorizes. Without that rule, the first announcement of a target becomes a
standing permission for every later change to it, and a stop-check quietly
becomes a formality that ran once.

## Failure-mode semantics, exactly

| Request | Refusal | Announcement afterwards |
|---|---|---|
| cites no announcement | `not_announced` | — |
| cites an unknown announcement | `unknown_announcement` | — |
| names a target the announcement does not | `target_mismatch` | still open, **not** consumed |
| arrives inside the stop-check window | `stop_check_window_open`, with the milliseconds left | still open |
| cites a stopped announcement | `stopped` | stopped, terminal |
| cites a consumed announcement | `already_consumed` | consumed, terminal |

Three bindings this table is making explicit:

1. **A refused mutation consumes nothing.** A misdirected request must not burn
   the announcement it misused, or a caller with a bug becomes a caller that can
   cancel other people's announced work.
2. **A stop is terminal.** Waiting does not undo it. A stop that expires into
   permission is the worst possible reading of an operator's intent.
3. **The window is a floor, not a target.** A subject may hold the window open
   longer than the floor; it may not hold it shorter.

### The stop-check window

The module floor is **30 seconds** (`MIN_STOP_CHECK_WINDOW_MILLIS`).
**Owner-confirmable**, and expected to be raised for classes of mutation where
30 seconds is not real notice. The reasoning behind the floor is narrow: it is
the smallest interval in which a human who is *already looking at the
announcement* can act on it. It is not a claim that 30 seconds is adequate
notice for anything in particular. A window nobody can act inside is a delay
dressed up as a check, which is why a subject declaring less than the floor does
not conform.

Stopping is refused once the window has closed (`window_closed`), because at
that point the mutation may already be under way and a stop that might or might
not have taken effect is worse than a clear refusal. Stopping work that has
already started is cancellation, a different property with a different contract
— see `scheduler-core.md`.

## Conformance

The suite is `automonique_protocol::safety_conformance::mutation_announcement`
(`rust/crates/automonique-protocol/src/safety_conformance/mutation_announcement.rs`),
generic over one trait, `AnnouncedMutations`. The trait carries a clock seam so
the suite never sleeps: waits are exact rather than approximately long enough.

| Case | What it pins |
|---|---|
| `an_unannounced_mutation_is_refused` | the whole property, in one case |
| `the_announcement_is_durable_before_the_mutation` | the record exists, names the exact target, and is open |
| `a_mutation_inside_the_stop_check_window_is_refused` | the window is a wait, and the refusal says how much is left |
| `an_announced_mutation_proceeds_after_the_window` | and then it goes through, and is recorded as consumed |
| `an_announcement_authorizes_exactly_one_mutation` | no standing permission |
| `an_announcement_authorizes_only_its_exact_target` | and a refused misuse leaves it open |
| `a_stopped_announcement_never_authorizes_a_mutation` | a stop survives the window elapsing |
| `an_unknown_announcement_authorizes_nothing` | an identifier nobody minted is not an authorization |
| `the_stop_check_window_meets_the_floor` | a fig-leaf window does not conform |

`rust/crates/automonique-protocol/tests/safety_conformance.rs` also runs the
suite against six **mutants**: a subject that mutates unannounced, one that does
not wait, one that reuses announcements, one that accepts a neighbouring target,
one whose stops expire, and one that announces without recording. Each must
fail, at the case that names what was broken.

## What this does not prove

Nothing in the daemon implements `AnnouncedMutations` yet, so passing the suite
says nothing about what the product does today. The binding is the launch
roadmap's Increment 4, which lists this stop-check among the things it builds;
`automonique_protocol::safety_conformance::PENDING_BINDINGS` carries the gap as
checkable data.

Two things this contract deliberately does not decide, both *owner-confirmable*:
which mutations are exempt (if any — the default is none), and who may stop an
announced mutation. The second is an authority question that belongs with the
approval lane rather than here.

## Provenance

`reference/feature-parity.md` records the announce-target-before-action row as
**Replace** with no fixture, noting it as a safety-critical stop-check, and
`launch-roadmap.md` § Increment 4 names it among the four properties that must be
specified and tested for a scope before that scope goes live. This document is
that specification, written from the stated requirement rather than
reconstructed from the prior implementation.
