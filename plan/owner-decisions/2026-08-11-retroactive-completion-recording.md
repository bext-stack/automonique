<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — how R1 completion gets recorded

**Status: ACCEPTED by the owner on 2026-08-11. Option B executed.**

| Field | Value |
|---|---|
| Question | How does an item reach `status = "done"` when its implementation is already committed? |
| Blocked on | `plan/gate.py` cannot authorise work that is not in the working tree |
| Items affected | 18 with every contract row passing, 7 still partial |
| Decision | Option B |

## What was executed

The 18 items named below are `status = "done"` in `plan/work-graph.toml`, set
through `ITEM_STATUS` in `plan/generate.py` with the reason recorded at the
edit. `plan/check.py --verify` passes and emits 16 warnings reading *"X is done
but never passed through the gate"* — one per item that did not exist in the
gate history. Those warnings are accurate and are deliberately not suppressed.
`plan/baseline.py` was regenerated: 11 → 27 items done, and `contracts_missing`
rose 77 → 91 because completing these items unblocked successors that have no
contract yet. That rise is real debt becoming visible, not a regression.

## The structural problem

`plan/doctrine.md` and `AGENTS.md` agree that only `plan/gate.py` may authorise a
completion. `check_lease` at `plan/gate.py:348` requires every declared file to
be currently dirty:

```python
unknown = [p for p in declared if p not in actually_dirty and p not in deletions]
if unknown: refuse("--files names paths that are not changed: ...")
```

Each R1 item was implemented, verified and pushed as its own commit, under the
`advance_verified_local_main` capability `plan/authority.toml` grants. That was
within authority at the time. The consequence is that the gate can no longer see
the work: the files are clean, so it refuses.

There is no flag for this, and adding one would be a candidate editing the
machinery that judges it — which `AGENTS.md` forbids in the same paragraph that
grants autonomous integration.

## What is measured today

Evidence for all 23 items is checked in under `plan/evidence/`. Each file records
one entry per contract row with the command run and what was observed, and each
records `"review": {"reviewers": 0}` — no independent reviewer read any of it.

**Every row passing (18):** `R1-01`, `R1-02`, `R1-03`, `R1-04`, `R1-07`, `R1-08`,
`R1-09`, `R1-13`, `R1-14`, `R1-15`, `R1-16`, `R1-19`, `R1-20`, `R1-21`, `R1-22`,
`R1-23`, `R1-24`, `R1-25`.

**Still partial (7):** `R1-05` (secret hygiene, field completeness), `R1-06`
(frame, negotiation and enum fixtures absent from the corpus), `R1-10` (no digest
is ever derived from a document), `R1-11` (brand distinctness runtime half),
`R1-12` (cursor monotonicity, replay purity), `R1-17` (nothing is generated from
the registry), `R1-18` (spec completeness, attestation clause).

Five of the eighteen carry an `adversarial_review` block recording findings that
are **still open** — rows where a reviewer proved a mutation survives the suite.
For those, `pass` means measured-and-observed, not fails-if-removed.

## Options

**A. Leave every item `blocked`.** Truthful and useless. The evidence exists but
the plan cannot see it, so `ready.md` keeps offering work that is finished and
`plan/baseline.py` keeps counting it as outstanding.

**B. Record completion from evidence, outside the gate, once — recommended.**
Add the 18 all-rows-passing items to `ITEM_STATUS` in `plan/generate.py`,
regenerate, and let `plan/check.py` enforce that each has evidence. Its warning
*"X is done but never passed through the gate"* stays visible and unsuppressed:
that warning is true, and silencing it would be the dishonest half of this
option. The five with open review findings are recorded but named here so a
reader knows which they are.

**C. Re-run each item through the gate by reverting and re-applying it.** This
would satisfy the letter of the rule by making the tree dirty again. It produces
23 no-op commits, rewrites history that is already pushed, and the gate would be
judging a diff manufactured to satisfy it. That is theatre, and it teaches the
gate to be worked around.

## If Option B is taken

1. `ITEM_STATUS` gains the 18 items; `plan/generate.py` regenerates the graph.
2. `plan/check.py --verify` must pass, warning included.
3. `plan/baseline.py` is regenerated so the counters reflect reality.
4. The seven partial items stay selectable with their gaps in `ready.md`.
5. ~~Future items go through `plan/gate.py --commit` *before* landing, so this
   decision is not needed twice.~~ **Corrected 2026-08-11.** This was written
   without checking, and it is wrong. `--commit` refuses unconditionally:
   *"disabled until baseline, history, done status and regenerated plan
   artifacts can be included and verified in one exact completion tree."* The
   dirty-lease problem described above is real but is not the binding
   constraint — the gate cannot authorize a completion today in any state.
   What is available is `--dry-run`, a full completion preflight that checks
   readiness, lease, evidence, plan integrity and metric and authorizes
   nothing. Running it while the work is still uncommitted is now the standard,
   and the batch that followed this decision did so. Enabling `--commit` is its
   own piece of work; see
   `plan/owner-decisions/2026-08-11-r1-12-contract-amendments.md`.

## What this decision does not do

It does not claim independent review happened. It did not. Three rounds of
automated adversarial agents examined the work and found real defects — including
two live idempotency collisions and a boundary scan that missed a subdirectory —
but an automated reviewer is not a second person, and the evidence says so in
every file.
