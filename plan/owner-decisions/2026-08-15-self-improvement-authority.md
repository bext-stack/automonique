<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — the authority the self-improvement pipeline operates under

**Status: DECIDED 2026-08-15 — Option B. The self-hosting ladder is the
destination; the shipped pipeline runs as one named, bounded lane until the
promotion path lands.**
The owner delegated this decision to the implementer with the three options
below stated in advance in
[`docs/improvement-plan/implementation/M4-self-improvement-governance.md`](../../docs/improvement-plan/implementation/M4-self-improvement-governance.md)
§ `#27`. The options are kept in full: the point of this record is which was
chosen and why, which is not readable from the outcome alone.

| Field | Value |
|---|---|
| Question | A pipeline ships that merges to public `main` and activates its own release on two chat approvals. [Self-hosting and bootstrap](../../docs/product-plan/requirements/self-hosting-and-bootstrap.md) reserves that integration for an external authority. Which one changes? |
| Raised by | audit finding **F-02** (S0), [`docs/improvement-plan/audit-findings.md`](../../docs/improvement-plan/audit-findings.md); improvement-program issue **#27**; the open deviation M1 recorded in `self-hosting-and-bootstrap.md` § Shipped self-improvement pipeline |
| Decided | **Option B.** Build to the ladder's `development_branch` plus two-step promotion. Until it lands, the shipped pipeline is a named lane with enforced preconditions and a retirement condition, not an unresolved excess |
| Code changed by this decision | **none.** The enforcement this record relies on is issues #25 and #26, which landed alongside it. This record and the requirement amendments are the deliverable |
| Ceiling table changed | **no.** No fourth ceiling is created. See "What this decision does *not* say" |
| Remaining owner action | branch protection on `bext-stack/automonique` `main`. A GitHub-settings change; no code in this repository can perform it |

## Which implementation this decision governs

This has to be settled first, because the milestone would otherwise govern the
wrong artifact. The requirements corpus describes a development harness,
`automonique-lab`. The product imports **one module** from that crate,
`improvement_executor`. The rest — `harness_claim`, `program`, `build`,
`state`, `controller`, `workspace_lease`, `worktree`, roughly 11k lines — has
no product call site at all.

**The governed artifact is the daemon pipeline**: `improvement_executor`,
`improvement_worker`, `improvement_github`, `improvement_publish`,
`release_builder`, `release_activation`, the Telegram improvement handlers and
the `improvements` store. The rest of `automonique-lab` is a proposal-only
control plane, is labelled as such, and no statement in this record or in the
amended requirements may be read as authorizing anything it does. It is not
deleted here; whether it is wired or archived is the same wire-or-delete
conversation as F-06, and it is not this decision.

## What the implementation already gets right

Stating this plainly matters, because the options below trade against it and a
reader who thinks the pipeline is unprincipled will pick wrongly.

The sandboxed candidate holds no GitHub, SSH-agent, deployment or production
credential. It cannot create a commit, and attempting to is a typed refusal,
not a warning. The approved plan is byte-bound by digest: the bytes that run
are the bytes that were approved, or the attempt refuses. Both gates are
single-use challenges bound to actor, chat, state revision and artifact digest,
so an approval cannot be replayed, cannot be transplanted to another chat, and
expires. The merge refuses a head that moved after approval, and the merged
tree is compared against the tested tree. The *credential-isolation* half of
the ladder is substantially honoured already.

What it does not have is the ladder's *authority separation*: no candidate
namespace, no shadow or canary mode, no independent rebuild comparison, no
`owner_verified` / `promotable` distinction, and — the load-bearing one — the
merge into protected `main` is performed by the same process that proposed the
change. Measured against the ceilings, that sits above `production_proposal`.

## The three options, as they were put

**Option A — subordinate to `proposal_only`.** Remove the merge from the
automated path. The pipeline stops at "pull request opened, release built,
evidence attached"; a human merges, and activation becomes a separate operator
action.
*Cost:* 1–2 days, mostly deletion and doc work.
*Rejected*, for a reason that emerged during this milestone rather than before
it. A is the right answer if the alternative to a human merge is an unchecked
one. It is not: #26 makes every required check a precondition of the merge, on
exactly the tested commit, with the evidence recorded. What A removes is
therefore the unattended loop — the feature — and what it buys is a human
clicking merge on a pull request whose checks are already green and already
verified to be green. That is a worse trade than it looked before #26 existed.
Choosing A would also have made #26's merge gate moot on the day it shipped.

**Option B — build to `development_branch` plus explicit promotion (chosen).**
Automation merges into a bot-owned branch; promotion to `main` and activation
become the ladder's `prepare_promotion` / `approve_promotion`, with recorded
evidence. #26's verdict becomes the required-status policy the ladder already
names, and a state the automation cannot write for itself gives the ladder's
"the candidate cannot write `owner_verified`, `promotable` or `promoted` for
itself" an actual mechanism.
*Cost:* 1–2 weeks. Branch-target change, two new states and their transitions,
the promotion verbs.
*Consequence:* keeps the automation and restores the authority separation.
This is the only option under which the shipped design and the corpus agree
without either being weakened.

**Option C — amend the requirements to bless the shipped design.** Add a fourth
ceiling, "owner-gated direct integration", whose preconditions are what the
pipeline enforces, and revise the harness document's sentence to match.
*Cost:* 2–3 days of doc work.
*Rejected.* C is honest about the pipeline's real safety properties, and it is
still wrong to choose now. It converts a temporary accommodation into permanent
policy at the exact moment the repository has two open findings — F-01, private
identifiers reachable in a public repository, and F-03, no parity harness —
that are precisely the failure classes an external integration authority exists
to catch. A ceiling added while the evidence for adding it is weakest is a
ceiling nobody will revisit.

## Why B, and what "B, staged" means

B is 1–2 weeks of mechanism, which is more than this milestone. The honest way
to hold that is not to pretend the pipeline is already subordinate, and not to
leave the deviation open for another milestone. It is to name the lane the
pipeline actually runs in, state what makes it acceptable, and state what
retires it.

**The lane: owner-gated direct integration.** Its preconditions are the
credential isolation and digest binding above, plus the one this milestone
added: every required check must have a completed, successful run on exactly
the tested commit before the merge, recorded as durable evidence. This is not
"GitHub said green" — a check that was deleted, renamed or never triggered
refuses, and an empty check list refuses, because the empty set is the most
restrictive state and not the most permissive one.

**The lane is not a ceiling.** It is a deviation with an expiry. The ceiling
table is unchanged, `production_proposal` remains the highest, and the pipeline
is recorded as operating below the authority separation the ladder requires
rather than as having been granted it.

**What retires it:** the bot-owned branch target and the two-step promotion.
When those land, the pipeline sits at `development_branch` with an explicit
promotion step, the lane disappears, and this record is superseded rather than
amended.

**The residual the implementer cannot close:** `main` carries no branch
protection. Enabling it is an owner action in GitHub repository settings, and
no change in this repository can perform it or verify it from the inside. Until
it is enabled, the "protected" in "protected `main`" is aspirational, and the
separation the ladder requires rests on credential isolation and two human
approvals alone. This is the one thing about this decision that is not done.

## What this decision does *not* say

- It does **not** create a fourth integration ceiling. Anyone reading the lane
  as a new permanent tier is reading it wrong; the ceiling table above it is
  the unchanged one.
- It does **not** authorize the pipeline to act on anything other than an
  administrator's explicit request. The recursive improvement loop, its
  proposal sources and its depth/concurrency/token/cost/time limits remain
  unimplemented, and nothing here starts building them.
- It does **not** relax the harness document's rule that a proposal alone is
  never sufficient. Two single-use human approvals, bound to the exact plan
  digest and the exact tested commit, are what make the pipeline compliant with
  that sentence, and removing either would break the compliance rather than
  merely reducing it.
- It does **not** settle whether the unwired `automonique-lab` control plane is
  wired or archived. It settles only that the control plane is not the product
  path and not what these requirements govern.
- It does **not** revisit the decision precedence table. That was reconciled in
  M1 and is not reopened here; this record slots the self-improvement subsystem
  into the order that table already fixed.

## What would change it

Landing the promotion path supersedes this record. So would a decision to run
this repository under a policy where an unattended merge to `main` is not
wanted at all — in which case Option A becomes correct and this record is
replaced, not amended. Enabling branch protection does not change the decision;
it closes the residual named above, and should be noted here when it happens.
