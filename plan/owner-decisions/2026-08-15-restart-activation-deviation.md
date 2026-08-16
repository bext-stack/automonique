<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Accepted temporary deviation — code releases activate by restart

**Status: ACCEPTED 2026-08-15 as temporary. Retires when generation handoff
(improvement-program issue #46, M8) lands.**
This is a deviation record, not an authorization to build on. It exists
because the corpus contained no statement that restart-based activation was
accepted, and
[`docs/self-improvement-workflow.md`](../../docs/self-improvement-workflow.md)
described the restart as ordinary behaviour — which meant a reader had no way
to tell a known compromise from a settled design.

| Field | Value |
|---|---|
| Deviation | A code or mixed self-improvement release is activated by switching an atomic `current` symlink and issuing `systemctl --user restart` on the configured unit |
| Where | `rust/crates/automonique-daemon/src/release_activation.rs`, `SystemdUserSupervisor` and `CodeReleaseActivator::activate_with`; scheduled out of band by `improvement_worker.rs`'s transient-unit helper |
| Invariant it violates | [`goals-and-invariants.md`](../../docs/product-plan/requirements/goals-and-invariants.md) goals #1 and #22, and their metric target "Interrupted active jobs during reload: 0" |
| What the corpus specifies instead | [`reload-protocol.md`](../../docs/product-plan/requirements/reload-protocol.md): the release path and expected manifest hash go through the active generation's admin endpoint, N+1 proves readiness before N quiesces, leases transfer transactionally, and N stays active on every candidate failure |
| Raised by | audit finding **F-12**; improvement-program issue **#28** |
| Retirement condition | issue **#46** implements generation handoff. Then `ActivationMechanism` gains its second variant, `ActivationMechanism::CURRENT` changes, and this record is superseded |

## The blast radius, stated exactly

Every in-flight turn in the restarted generation is lost: Telegram, Slack and
Support conversations mid-answer, and any provider run in progress. Nothing is
drained, nothing is transferred, and nothing about the loss is recorded on the
conversation the caller was having — from the outside it is a turn that never
answered.

Durable state is not at risk. The improvement journal, the release manifests
and the `current` link are all written before the restart, and the activation
helper re-validates revision, state and manifest digest after it. The loss is
confined to work that was in memory.

## The mitigation that exists, named honestly

`improvement_worker.rs`'s scheduled activation sleeps a fixed, bounded ~2 s
before restarting, so that the Telegram reply announcing the activation has an
opportunity to commit first. That is its entire purpose and its entire effect.

It is a race the sleep usually wins, not a drain. It does not consult in-flight
work, it does not extend for work that is still running, and it does not report
whether anything was lost. Calling it a mitigation of the invariant above would
be false; it mitigates one specific confusing symptom — an activation whose
announcement never arrived — and nothing else.

The plan's optional step 2, replacing the sleep with a bounded drain that
refuses to restart while the daemon reports in-flight work, is **not taken
here**. It would turn a guaranteed interruption into a usually-clean one, which
is worth doing if #46 slips badly, and it would still not be handoff. If it is
ever taken, this record does not soften on its account.

## What this milestone did instead

M4 built no part of the handoff. Building "a little handoff" — a partial reload
path that does not implement the protocol's epochs, readiness proofs, lease
transfer or failure matrix — would produce a second activation path with none
of the guarantees and all of the surface area, and #46 would then have to
delete it before implementing the real one.

What M4 did build is the seam it will land in: `ActivationMechanism`, an
explicit boundary between "this release is approved and chosen" and "how the
new code takes over". It has exactly one variant, `SupervisedRestart`, and it
sits above the transient-unit helper — because needing an out-of-band process
at all is a property of restarting, not of activating. A handoff variant slots
in beside it without moving the release verification, the atomic link switch,
or the rollback discipline, all of which both mechanisms share.

The refactor is behaviour-preserving. The existing activation tests pass
unchanged, and one test pins the restart variant's exact supervisor call
sequence so that adding the second variant cannot quietly alter the first.

## What this record does *not* say

- It does **not** accept restart-based activation as the design. It accepts it
  as the current mechanism, with a named successor and a retirement condition.
- It does **not** apply to skill-only releases. Those switch a digest link that
  every provider run re-reads, activate hot, and restart nothing.
- It does **not** license any new caller of the restart path. The one caller is
  the improvement pipeline's approved-release activation.
