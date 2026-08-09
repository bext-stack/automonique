# Role doctrine

`AGENTS.md` states what an agent may not do to the repository. This states how
an agent works *inside* one item: what counts as a fix, what counts as cheating,
and what a reviewer hunts for.

It is deliberately specific. A rule like "write good code" cannot be violated
knowingly, so it never is. A rule like "never add `#[allow]` to make a queue
green" can be, which is what makes it useful.

## The one rule everything else serves

> **Evidence must say exactly what was measured and who reviewed it.**

An implementer's output is a candidate: a summary, a file list and an evidence
file. `plan/gate.py` mechanically checks that claim. It does not turn zero
reviewers into independent review, and it does not grant protected integration
authority.

In owner-supervised bootstrap, the implementer should run `plan/gate.py
--dry-run` as a preflight. After the owner accepts the exact candidate, the
worker may use the gate's typed local-commit operation on a candidate branch.
The worker still cannot push, merge or silently mark a gate closed.

## Implementer

1. **Use the gate as a checker, not an authority.** Run a dry preflight after
   producing evidence. Record the real reviewer count, including zero.
2. **Fix causes, not counters.** Find the real contract — the requirement, the
   ledger row, the protocol definition — and make it tell the truth. A change
   that moves a number without changing what is true is a regression that
   happens to score well.
3. **Never silence.** In specification work that means never resolving a
   contradiction by deleting one side, never closing a ledger row by removing
   it, and never downgrading a disposition (`core` → `optional`, `preserve` →
   `retire`) to make it someone else's problem. In code it means no `todo!()`,
   `unimplemented!()`, broad `#[allow]`, widened `unsafe`, deleted test, or
   refreshed golden to make a queue green.
4. **Never weaken a shared contract to satisfy one caller.** If the caller is
   wrong, fix the caller. Relocating an error is not resolving it.
5. **Stay inside the lease.** Your item's `allowed_paths` is the whole of your
   write authority. If the fix genuinely requires a path outside it, stop and
   say so — that is a real finding about the graph, not an obstacle.
6. **Preserve behavior.** Unless the item is explicitly a behavior change,
   nothing observable may differ. If a correctness fix reveals a genuine bug,
   fix it and say so in the summary rather than folding it in silently.
7. **Adversarially review your own diff before finishing.** Read it as someone
   trying to reject it. Fix every credible finding first, then write the
   summary.
8. **A smaller honest unit beats a larger dishonest one.** If part of the item
   cannot be done truthfully, do the rest, leave that part, and record why in
   the evidence `notes`. An honest partial is a good outcome. A complete-looking
   result that hides a compromise is the worst one.

## Reviewer

Review is performed when the work contract or owner requests it; it is not a
universal prerequisite. A self-review is useful but is never labeled
independent.

You receive the diff and the contract. You do not receive the implementer's
reasoning, and you should not ask for it — a persuasive narrative is exactly
what you are the control for.

Hunt for, in this order:

a. **Silenced, not fixed** — a contradiction resolved by deletion, a ledger row
   closed by removal, a disposition quietly downgraded, a suppression added.
b. **Behavior changes hiding inside a "documentation-only" or "type-only"
   edit** — the classes of change reviewers skim.
c. **Weakened shared contracts** that merely move the problem to other callers.
d. **Evidence that does not pin what it claims** — a check whose command could
   not have detected the failure it reports as absent.
e. **Scope creep** — edits outside the item's legitimate boundary, including
   edits inside the lease that have nothing to do with the objective.

Return a verdict promptly. A blocking finding must name a concrete failure: the
input, the state, and what goes wrong. "This seems fragile" is not a finding.

## Fixer

Resolve blocking findings. You may not dismiss one. If you believe a finding is
wrong, that requires new evidence or an explicit human decision recorded in the
item's evidence file — not an argument.

## Evidence

`plan/evidence/<ID>.json`, written once the work is complete:

```json
{
  "item": "BOOT-001",
  "base": "<git sha the work started from>",
  "checks": [
    { "name": "Integrity", "command": "python3 plan/check.py --verify", "result": "pass" },
    { "name": "Drift, forward", "command": "...", "result": "pass" },
    { "name": "Cycle", "result": null, "reason": "harness cannot inject a cycle without editing the generator" }
  ],
  "review": { "reviewers": 0, "blocking_findings": 0 },
  "notes": "what was left undone, and why"
}
```

Every check named in the contract's *Verification contract* table must appear.
The gate refuses a missing one. A check that could not be run is `"result":
null` **with a reason** — never omitted, and never reported as zero or pass.
This is `AGENTS.md`'s "missing evidence is `null` with a reason" made
mechanical.

## What this is modelled on

The structure is taken from a working campaign harness used on another
repository in this workspace — a metric-gated loop where parallel agents repair
a large backlog and a machine decides what lands. The mechanisms that transfer
are the ones above: truthful role records, machine-checked invariants
that include an anti-regression clause, declared-versus-actual file lists,
explicit anti-silencing rules, and honest partial results.

The mechanisms that did **not** transfer are as informative. That harness runs
many agents in parallel on disjoint file sets, because it has thousands of
existing failures to divide among them. This repository begins with little
product code, so parallel dispatch is useful only for contracted units with
isolated leases. Broader compiler/test queues become worthwhile after R1 and
R2; `R0-19` owns that transition.
