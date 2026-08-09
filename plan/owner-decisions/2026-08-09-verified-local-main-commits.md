<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — verified work commits to local main

| Field | Decision |
|---|---|
| Status | approved by the repository owner in the active Codex session |
| Expected local main | `69db4ca85c1ab1aab7ad3fe3e9225bf0f33db055` |
| Existing verified proposal | `735d8b18e6cbd36d75d86a201cd7d3272d932ccd` with tree `724b85e44d4840bce7425533644417abf822d4d0` |
| Objective | make an exact-tree candidate that passes its declared checks commit automatically to local `main`; when a whole work contract passes, include evidence, metric baseline, history, done status and regenerated artifacts in that same commit |
| Allowed paths | `AGENTS.md`, `GOVERNANCE.md`, `.automonique/dev/`, `tools/`, `plan/` |
| Licence class | `Elastic-2.0` |
| Initial remote | `origin` (`https://github.com/bext-stack/automonique.git`) |
| Initial remote branch/tip | `refs/heads/main` at `1a116ee2473cdd6c28f9c206e612e4ed64d54b2b` |
| Initial intended push | local `main` at `735d8b18e6cbd36d75d86a201cd7d3272d932ccd` |
| Budget | one bounded integration-policy correction, the exact initial fast-forward push above, then fast-forward publication of verified automatic commits; no force, history rewrite, other-ref update, remote edit, release, package publication or deployment |
| Checks | broker and harness unit tests, plan integrity/self-tests, generated DAG/guides, scrub tests/scan, exact parent/tree/ref assertions and clean-index reconciliation |
| Recovery | local `main` moves only by compare-and-swap from the expected base; the proposal ref and prior commit remain recoverable |

## Decision

Routine verified work must not wait indefinitely on a second local identity.
After the harness freezes an exact tree and the declared checks pass, its typed
integration operation may compare-and-swap local `main` from the admitted base
to that commit and reconcile the shared index without changing worktree bytes.
It still cannot force, rewrite history, edit remotes, push, merge a divergent
branch, publish, release or deploy.

There are two truthful outcomes:

1. A verified implementation slice may commit with check, review, metric and
   completion-state trailers while its work item remains open.
2. A completed work contract may commit only after every required check passes.
   The gate must write its evidence-linked history record, metric baseline,
   done status and every regenerated plan artifact before creating the commit,
   so the commit contains the complete completion transaction.

Missing or `null` contract results do not authorize completion. Review remains
risk-based, and its actual count and unresolved findings are recorded rather
than invented.

## Non-retroactivity

This policy change cannot use its new rules to certify itself. The owner has
separately accepted the existing proposal named above as a partial R0-19 slice;
integrating it does not mark R0-19 done or claim its nine-check contract has
passed. The policy implementation that follows requires the pre-existing plan
and scrub checks plus an exact-tree review before it can commit.

## Remote publication

The owner explicitly requires verified commits to reach `origin/main` without
an additional manual handoff. Publication is a typed fast-forward-only push of
the exact verified local `main` commit to `refs/heads/main`. The publisher must
observe and record the remote tip, refuse divergence, send no force option, and
verify the resulting remote OID. It cannot push another branch or tag, edit a
remote, rewrite history, publish a package, release or deploy. Ambiguous network
outcomes reconcile by reading the remote ref before any retry.
