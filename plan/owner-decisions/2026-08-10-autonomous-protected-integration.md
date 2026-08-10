<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — autonomous protected integration

| Field | Decision |
|---|---|
| Status | approved by contemporaneous owner instruction on 2026-08-10 |
| Repository base | `e2b4b60b87502286a9622513902a38b765963da8` |
| Requested | 2026-08-10 through the owner-controlled repository workspace |
| Licence class | `Elastic-2.0` |
| Objective | let the loop write contracts and integrate plan, governance and authority changes without per-revision owner acceptance, so it can unblock its own work and progress unattended |
| Allowed paths | `AGENTS.md`, `plan/authority.toml`, `plan/owner-decisions/2026-08-10-autonomous-protected-integration.md` |
| Budget | one bounded policy reconciliation; no licence, privacy, clean-room, release or production-authority change; no test deleted, skipped or weakened |
| Verification | plan integrity, authority invariant checks, generated-graph reproducibility, generated program and guide/objective verification, and the existing plan self-tests |

## Decision

The repository moves from `owner-supervised-bootstrap` to
**`autonomous-protected-integration`**. The owner was shown that the harness
already created, verified, compare-and-swapped and published every recent commit
on `main` without owner action, and that the only remaining stop was the
requirement for exact-revision owner acceptance on candidates touching the plan
and governance surface. That requirement is withdrawn.

A verified candidate may now be integrated and published by the configured
fast-forward path regardless of which leased paths it touches, including
`plan/contracts/`, `plan/ready.md`, `.automonique/dev/program.yaml`,
`.automonique/dev/objectives.json`, `plan/authority.toml` and `AGENTS.md`. No
class of change is reserved for owner sign-off. Contract preparation in
particular no longer needs a per-contract owner decision, so the loop may
specify unblocked-but-unspecified work items and then select them.

Review depth remains owner-configurable and is not made mandatory by this
decision. Independence is not claimed where it did not occur; evidence continues
to record the actual reviewer count.

## What this decision does not change

Withdrawing the owner-acceptance gate does not withdraw deterministic
verification, and the two are not the same control:

- Integration remains bound to exact-tree verification, expected-tip
  compare-and-swap and fast-forward ancestry. These prevent drift and
  corruption; they are not owner review.
- Generic push, force update, history rewrite, protected-branch merge, remote
  edit, other-ref and other-remote mutation, repository administration, release
  signing, package publication and production deployment remain denied. The
  single configured fast-forward publication capability is unchanged and is
  sufficient for autonomous progress.
- A candidate may still not delete, skip, ignore or weaken a test, add a stub,
  bulk-refresh a golden, or widen an unsafe or lint allowance in order to pass.
  A candidate that edits the checks judging it must still pass those checks as
  they stand at its admitted base.
- The clean-room boundary, licence classification and privacy rules are
  untouched.

## Non-retroactivity

The policy judging a tree remains the policy already integrated at that tree's
admitted base. This decision does not declare any existing candidate correct,
close a gate, alter evidence, or waive a failing check. This decision is itself
integrated under the prior policy, which required a contemporaneous external
owner instruction — that instruction was given before the candidate was built.

## Stop conditions

Stop and request the owner when work would:

- expose or use prior implementation source;
- change the software licence boundary, privacy or retention policy;
- grant a generic push, force, history-rewrite, release, publication or
  production credential;
- weaken or delete a required test or falsify evidence; or
- claim a measurement, review or independence that did not occur.
