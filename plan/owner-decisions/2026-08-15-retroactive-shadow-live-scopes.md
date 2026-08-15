<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — retroactive shadow verification of the live scopes

**Status: PENDING, and cannot be decided yet.** The decision below needs
evidence that does not exist and cannot be manufactured in a repository: a
per-scope shadow-comparison run against production traffic. This memo records
the scopes, the decision each one faces, and what has to be true before the
owner can take it. **Nothing here asserts that any scope has been verified.
Nothing has.**

| Field | Value |
|---|---|
| Question | Five scopes went live without ever being compared against the system they replace. For each: scope back to shadow-only until it passes, or record explicit risk acceptance and keep it primary? |
| Blocked on | issue #10 (the shadow-comparison harness — absent from the tree today) and days-to-weeks of production traffic per scope |
| Not blocked on | GATE-ORACLE, as re-scoped by [`2026-08-15-gate-oracle-scope.md`](2026-08-15-gate-oracle-scope.md) |
| Enumeration | `tools/parity/live_scopes.py`, verified against the code on every CI run |
| Decided by | the owner, per scope, once the evidence exists |

## The scopes

Enumerated from the code, not from
[`launch-roadmap.md`](../../docs/product-plan/reference/launch-roadmap.md),
whose "where we are today" section still describes several of these as unbuilt.
Each is live because its effects pass through a trait with a production
implementation wired into the daemon; `tools/parity/live_scopes.py` checks every
one of those citations by exact string match on each run, so a rename fails the
build rather than leaving this table pointing at nothing.

| Scope | Effect seam(s) | Parity rows | Compared so far |
|---|---|---|---|
| `slack-ticket-routing` | `SlackTicketPoster`, `TicketActionSurface` | 3 | none |
| `slack-conversational-qa` | `SlackApi`, `GitHubSurface` | 2 | none |
| `support-ticket-intake` | `TicketActionSurface` | 3 | none |
| `github-issue-actions` | `GitHubActionSurface` | 1 | none |
| `support-email-send` | `EmailActionSurface` | 1 | none |

"Compared so far: none" is not a summary of a search. It is a structural fact:
the shadow harness of issue #10 does not exist — no `parity.rs` in the protocol
crate, no `shadow_parity.rs` in the store crate, no `shadow.rs` in the daemon —
so there is no envelope to record and nothing to record it against. The checker
derives this rather than repeating it, and refuses any scope that claims
otherwise while those files are absent.

## The decision each scope faces

Once #10 has landed and a scope has accumulated production-representative
comparisons over a stated window, exactly one of two options applies, and which
one depends on a fact this repository cannot supply.

**If the legacy system still serves the scope**, there is a live comparison
target. Run the scope in dual mode (primary keeps executing; every decision is
also recorded as an envelope) or full shadow, accumulate comparisons, compute
the score, and decide on the evidence.

**If the legacy system no longer serves the scope**, there is no comparison
target at all, and no amount of traffic will produce one. That is the case the
owner must decide directly:

- **Option A — scope back.** The legacy system resumes primary for that scope
  and Automonique drops to shadow until it passes. Safest, and reversible.
- **Option B — accept the risk.** The scope stays primary with no parity
  evidence, and the memo names the residual risk in terms of what could go
  wrong and who absorbs it.

**Recommendation: A for any scope without a live comparison target.** B is a
legitimate choice, but it must be a choice — an undecided scope is B by default
and without the record, which is the state all five are in today.

## The input only the owner can supply

Whether the legacy system still serves each scope is not derivable from this
repository, and the checker refuses to record a guess: every scope carries
`owner-input-required` and nothing else is a permitted value. Supplying that
answer per scope is the first step, and it can be taken before #10 lands, since
it needs no harness — only the owner's knowledge of what is still running.

A related fact to establish at the same time: **if both the legacy system and
Automonique currently act on the same scope, that is itself a finding to record
before any comparison is run.** Two systems acting on one scope is a
double-effect hazard, not a comparison setup, and discovering it during a
shadow window would mean the window measured something other than parity.

## What has to be true before this memo can be decided

1. Issue #10 has landed, including the zero-effect tests: a shadow decorator
   that can still perform an effect converts a missing gate into a false one.
2. The owner has answered, per scope, whether the legacy system still serves it.
3. Where it does: the scope has run in dual or shadow mode for a stated window
   and accumulated production-representative comparisons.
4. The score and band from issue #12 are computed, with mismatches triaged —
   each investigated mismatch becoming a fixture (issue #11) or a registered
   known deviation.
5. Where it does not: the owner has chosen A or B explicitly.

Steps 3 and 4 are calendar time, not engineering time. That is why issue #14
stays open after this memo lands, and why capture should start on the first
scope the moment #10 does.

## Why this is not blocked by GATE-ORACLE

GATE-ORACLE blocks archive-differential parity work, as re-scoped on 2026-08-15.
The comparison this memo describes observes only what the legacy system
publishes into shared channels this daemon is already a member of, so it never
crosses the custody boundary. `tools/parity/live_scopes.py` re-checks that
narrowing on every run: if it is ever withdrawn, this enumeration describes work
that is blocked again, and the checker fails rather than letting the memo
quietly describe something nobody may do.

## What happens if this is not decided

The five scopes stay primary with no parity evidence, which is option B taken by
default and without the record — the residual risk unnamed, unassigned, and
carried anyway. The purpose of enumerating them here is that this state is
visible and dated rather than implicit.
