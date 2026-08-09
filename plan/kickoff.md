# Buildout kickoff

Paste the block below into a fresh agent session at the repository root. It is
deliberately short: everything it needs is in the repository, and a prompt that
restates the plan competes with the plan.

---

```text
You are implementing Automonique, a durable local-first agent control plane
written in Rust. The repository is specification and plan only — there is no
product source yet, and you are starting the buildout.

Read these four files before doing anything, in order:

  AGENTS.md            what you may and may not do to this repository
  plan/README.md       how work is selected and gated
  plan/doctrine.md     how you work inside one item, and what counts as cheating
  plan/gates.md        the five conditions that block classes of work

Then:

1. Run `python3 plan/check.py` and open `plan/ready.md`. Take one selectable
   item whose contract and required inputs are present.
2. Open its contract in `plan/contracts/<ID>.md`. Work only inside the
   `allowed_paths` recorded for it in `plan/work-graph.toml`.
3. Do the work. Write `plan/evidence/<ID>.json` answering every check the
   contract's "Verification contract" table names. A check you could not run is
   `"result": null` with a `"reason"` — never omitted, never reported as pass.
4. Stop. Report what you changed and what the evidence says.

Run `plan/gate.py --dry-run` after writing evidence. In owner-supervised mode a
PASS means the candidate is mechanically consistent, not that it has been
pushed or merged. Do not claim reviews that did not happen, and do not mark a
gate closed without the evidence its contract requires.

Three rules that matter more than speed:

- A smaller honest result beats a larger one that hides a compromise. If part
  of the item cannot be done truthfully, do the rest and record why in the
  evidence notes.
- Never silence. No suppression, no deleted test, no widened lint allowance, no
  contradiction resolved by deleting one side of it.
- If the work genuinely requires a path outside the item's lease, stop and say
  so. That is a finding about the graph, not an obstacle to route around.

Background you may need but should not re-derive: the system being replaced is
inventoried at docs/product-plan/reference/legacy-inventory.md, and the parity
obligations are in docs/product-plan/reference/feature-parity.md. Do not open
the legacy source tree; the boundary is stated in AGENTS.md.
```

---

## Current bootstrap work

`BOOT-001` is complete. Always use the generated ready set rather than a prompt
that names a supposedly current item. Bootstrap items may be worked in parallel
only in isolated worktrees with non-overlapping concrete file leases.

`R0-02` and `R0-07` wait on `GATE-ORACLE`. Identity hardening is optional and
does not block harness construction or trials.

## Where the risk is

From the legacy inventory: intake, routing and approvals are well tested and
port cleanly. Foreground generation handoff, tenancy, sandboxing, the artifact service,
the domain event journal and workspace isolation **do not exist in the legacy
system at all** and cannot be validated against it. That is where estimates
will be wrong, and it is worth front-loading the portable lifecycle and
execution-backend spikes (`R0-03`, `R0-04`, `R0-14`, `R0-15`) rather than the
ports. A supervisor adapter is not a prerequisite for those spikes.

## A prompt for a review session

When an item comes back and you want it checked before landing:

```text
Review the working tree against plan/contracts/<ID>.md and plan/doctrine.md.

You get the diff and the contract. You do not get the implementer's reasoning,
and you should not ask for it — a persuasive narrative is what you are the
control for.

Hunt in this order: silenced-not-fixed; behavior changes hiding inside a
"documentation-only" edit; weakened shared contracts that relocate a problem;
evidence that does not pin what it claims; scope outside the item's lease.

A blocking finding names a concrete failure — the input, the state, and what
goes wrong. "This seems fragile" is not a finding. Return a verdict.
```
