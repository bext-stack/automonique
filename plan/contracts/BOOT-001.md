# BOOT-001 — Executable plan integrity

| | |
|---|---|
| Epic | `BOOT` — repository readiness gates |
| Track | core |
| Depends on | — (this is the first selectable item) |
| Closes | [`GATE-BASELINE`](../gates.md#gate-baseline) |
| Licence class | `Elastic-2.0` |
| Allowed paths | `plan/`, `.github/workflows/` |
| Hill-climbability | 85 — the objective is a binary CI result with a deterministic reproduction |

## Objective

Make the executable plan self-verifying, so that every later work item can claim
an immutable base and a checkable dependency set.

The measurable objective is: `python3 plan/check.py --verify` runs in CI on every
push and pull request, exits zero on the current tree, and exits non-zero on a
deliberately introduced drift.

## Why this is first

`AGENTS.md` requires an agent to select a ready work ID and record dependency
evidence before implementing. Until the graph is verified, "ready" is an
assertion rather than a derivable fact, and the recorded evidence cannot be
checked by a reviewer. Every other item inherits that weakness.

## Scope

In scope:

- a CI workflow that runs `plan/check.py --verify` and `plan/generate.py --stdout`,
  failing if the generated output differs from the checked-in
  `plan/work-graph.toml`;
- a test fixture proving drift detection in both directions;
- `plan/ready.md` regenerated and committed.

Out of scope — do not do these in this unit:

- editing `docs/product-plan/reference/work-breakdown.md` to make the checker
  pass. If the checker disagrees with the breakdown, the checker or the
  generator is wrong;
- adding, renaming or removing any `R*` ticket;
- closing any other gate.

## Verification contract

Required checks:

| Layer | Check |
|---|---|
| Integrity | `plan/check.py --verify` exits zero |
| Reproducibility | `plan/generate.py --stdout` byte-matches `plan/work-graph.toml` |
| Drift, forward | remove a ticket from the breakdown → CI fails naming that ticket |
| Drift, reverse | add a node to the graph → CI fails naming that node |
| Cycle | introduce `A → B → A` → CI fails naming the cycle |
| Contract | mark an item ready with no contract file → CI fails |

Each drift test must run against a scratch copy and leave the tree unchanged.

## Forbidden shortcuts

- weakening a check so the current tree passes;
- marking `status = "done"` on any item to reduce the ready set;
- adding a suppression list, `# noqa`, or skip flag to `plan/check.py`;
- committing a regenerated `work-graph.toml` whose diff is not explained by a
  breakdown change in the same commit.

## Completion evidence

- CI run URL showing the six checks above passing;
- the four deliberate-failure runs, each showing the expected failure message;
- `plan/ready.md` diff showing the ready set after this item closes.

## Integration and rollback

Integrates directly; it touches no product code. Rollback is reverting the
workflow file — the graph and checker remain useful without CI, they are simply
unenforced.

## Gate closure

On completion, set `GATE-BASELINE` to closed in [`plan/gates.md`](../gates.md)
and set this item's `status` to `done` in `plan/work-graph.toml`. Both edits
belong in the same commit as the passing CI run.
