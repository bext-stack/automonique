# Executable plan

This directory is the machine-readable layer between the product specification
and an implementing agent. The specification says *what to build*; this says
*what may be started, by whom, under which licence, and what must be true
first*.

```text
plan/
├─ work-graph.toml    375 nodes: deps, gates, licence class, allowed paths
├─ ready.md           derived — what is selectable right now
├─ gates.md           blocking conditions and their closing evidence
├─ authority.toml     current worker/integration authority mode
├─ owner-decisions/   exact-base owner policy and contract decisions
├─ doctrine.md        how an agent works inside one item
├─ kickoff.md         paste-ready prompts to start a build or review session
├─ contracts/         one file per item that is ready or nearly ready
├─ evidence/          one file per landed item, written by the gate
├─ baseline.json      current specification-debt counters
├─ history.jsonl      append-only ledger of what landed and when
├─ generate.py        work-breakdown.md → work-graph.toml
├─ check.py           integrity gate; regenerates ready.md
├─ baseline.py        measures specification debt
└─ gate.py            evidence/scope preflight and typed local commit helper
```

## The loop

```text
  check.py          what may I start?          → ready.md
      ↓
  contracts/<ID>.md what does it mean exactly?
      ↓
  doctrine.md       how do I work, what is cheating?
      ↓
  [ do the work ]   produce truthful evidence
      ↓
  gate.py           is the claim consistent?   → history.jsonl, baseline.json
```

1. Read [`ready.md`](ready.md). It lists only items whose dependencies are
   `done` and whose blocking gates are closed.
2. Open `contracts/<ID>.md`. If it does not exist, the item is not workable;
   `check.py` lists it as *unblocked but unspecified* rather than selectable.
3. Read [`doctrine.md`](doctrine.md) before editing anything.
4. Do the work inside the item's `allowed_paths`, then write
   `evidence/<ID>.json` answering every check the contract names.
5. Run the gate as a dry preflight. In owner-supervised mode, the owner may then
   authorize its typed local-commit operation for the exact candidate:

```sh
python3 plan/gate.py --item BOOT-001 \
    --summary "wire plan integrity into CI" \
    --files plan/check.py .github/workflows/plan.yml \
    --dry-run
```

Refusing an item because a gate is open is the correct outcome, not a failure
to make progress.

## The gate

`gate.py` exists to make evidence, scope and plan invariants mechanical. It
does not invent reviewer independence or protected integration authority. It
refuses on any of:

| Refusal | Why it exists |
|---|---|
| dependencies unmet, or a blocking gate open | `ready` must mean something |
| no contract, or no `## Verification contract` section | an item with no checks cannot be verified |
| a contract check missing from evidence | silent omission is the cheapest lie |
| a check with a `null` result and no reason | "missing evidence is `null` with a reason" (`AGENTS.md`) |
| `--files` names a path that did not change | the declared diff must match the real one |
| `--files` touches a path outside `allowed_paths` | lease enforcement |
| `plan/check.py` no longer passes | work may not break the plan it came from |
| **any specification-debt counter increased** | closing one row by opening two is not progress |
| no counter decreased, with no stated reason | flat is allowed, but only on the record |

Files that are dirty but undeclared are left alone and reported — other work
may be in flight, and sweeping it into someone else's commit is a real failure
mode, not a hypothetical one.

With `--commit`, the gate stages exactly the declared files and writes the
attestation trailers from `ai-implementation-harness.md`:

```text
Automonique-Work: BOOT-001
Automonique-Checks: pass
Automonique-Review: 0-pass/0-blocking
Automonique-Metrics: sha256:<counter digest>
```

## The metric

`baseline.py` counts specification debt — the number this repository drives to
zero before there is any code to measure:

| Counter | What it counts |
|---|---|
| `capability_ledger_fields_missing` | `R0-16` requires owner, ticket and fixture per row; the table has no such columns |
| `parity_ledger_fields_missing` | `R0-08` requires fixture and evidence per row; same |
| `contracts_missing` | items one wave from ready with no contract |
| `gates_open` | blocking (not advisory) gates whose closing item is not done |
| `links_broken` | relative markdown links that do not resolve |
| `refs_undefined` | work IDs referenced but never defined |
| `evidence_missing` | items marked done with no gate evidence — an invariant, always 0 |

```sh
python3 plan/baseline.py --explain
```

Item count is recorded as *context*, never as the metric.
`ai-implementation-harness.md` is explicit that commits, lines and item counts
are not rewards, and a plan that scores itself on items closed will close easy
items.

## Sources of truth

| Question | Answered by |
|---|---|
| What is the work? | `docs/product-plan/reference/work-breakdown.md` |
| In what order? | `plan/work-graph.toml` |
| Under which worker/integration authority? | `plan/authority.toml` and its owner decision |
| What must be true before starting? | `plan/gates.md` |
| What does *this* item mean exactly? | `plan/contracts/<ID>.md` |
| Why is it built this way? | `docs/product-plan/requirements/` |

The graph is **generated**. Never hand-edit `work-graph.toml` or `ready.md`;
change the breakdown or `generate.py` and regenerate:

```sh
python3 plan/generate.py    # rebuild the graph
python3 plan/check.py       # verify, rewrite ready.md
```

## What `check.py` enforces

This is the bidirectional-completeness requirement from `R0-17`, made real:

- every breakdown ticket exists as a graph node — work cannot vanish;
- every graph node exists as a breakdown ticket — work cannot be invented;
- no dependency points at an unknown item, and none points at itself;
- no dependency cycle;
- owner-supervised authority explicitly denies push, protected merge,
  repository administration, release signing, publication and deployment;
- every gate named by an item exists in `gates.md`, and no item closes the same
  gate that blocks it;
- no `Apache-2.0` item may write outside `sdk/`, `integrations/` or
  `connectors/`, and commentable source SPDX headers must match that path rule;
- no item is marked `done` without gate-recorded evidence.

Readiness additionally requires a written contract. An item whose dependencies
are satisfied but which nobody has specified is not workable — an agent handed
it would invent the objective, the lease and the checks — so it is held out of
the ready set and listed under *Unblocked but unspecified* instead. Writing
that contract is itself useful work and lowers `contracts_missing`.

It exits non-zero on any of these, so CI can gate on it directly. It caught a
real licence-boundary violation in its own generator on first run.

## Status values

`blocked` → `ready` → `in_progress` → `done`.

Only `done` propagates: an item becomes ready when its dependencies are `done`,
not when they are merely `in_progress`. Marking an item `done` without the
completion evidence named in its contract is the single most damaging edit
available in this directory, because it silently unblocks everything behind it.

## Tracks

| Track | Meaning |
|---|---|
| `core` | blocks production cutover |
| `expansion` | graduates independently; a failure here never rolls back core |
| `research` | independently disableable |

`core` covers `BOOT` and `R0`–`R10`. Everything else is optional breadth, which
is deliberate: `docs/product-plan/README.md` lists "adding product breadth
before the durable autonomy and recovery spine works" as a non-goal.
