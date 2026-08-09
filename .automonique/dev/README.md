<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Development program

`program.yaml` is the generated implementation-harness view of the executable
plan. Its body uses JSON syntax, which is valid YAML 1.2 and can be parsed
without adding a YAML dependency.

Generate and verify it with:

```sh
python3 tools/program.py
python3 tools/program.py --verify
python3 -m unittest tools/test_program.py
```

The program contains every work item, including blocked and unspecified items.
`runnable: true` is derived from completion state, dependencies, gates and
contract presence; it grants no commit, push, integration, release or deploy
authority.

## Codex-driven development loop

`R0-18` adds six generated development guides, typed objectives for every
contracted work item, and a bounded proposal loop. The normal interface is an
interactive Codex session opened at the repository root. Ask it:

```text
Continue the Automonique implementation. Drive the harness and use native
subagents for independent work.
```

`AGENTS.md` instructs the primary session to inspect or claim one ready
objective, launch no more than three native subagents, integrate only disjoint
writes, run the checks, and leave a local candidate. In subsequent sessions,
`continue` is enough.

The underlying admission protocol is available for inspection:

```sh
python3 tools/harness_loop.py next
python3 tools/harness_loop.py status
python3 tools/harness_loop.py claim
python3 tools/harness_loop.py check
python3 tools/harness_loop.py candidate --summary "Describe the bounded slice"
```

The claim command runs admission checks and writes an ignored immutable packet
under `.automonique/state/`. It does not start another Codex process or make a
model call. The outer Codex session reads that packet, uses its native agent
tools, and remains responsible for coordination and verification. `check`
refuses revision, branch and path-lease drift and marks a passing diff only as
`candidate_ready`; it does not commit or change the plan.

After review, `candidate` revalidates that snapshot and asks the typed Git
broker to create a proposal commit under
`refs/automonique/candidates/<run-id>`. The broker uses a private index, leaves
the current branch, `HEAD`, shared index and worktree untouched, and persists
an idempotent intent and receipt for restart reconciliation. It has no generic
Git argument interface and cannot push, merge, force, rewrite history, edit a
remote, tag, release or deploy. A separate authorized merger may inspect and
integrate the proposal later.

## Deterministic local worker

`run` remains an optional lower-level interface for deterministic executables.
It accepts one explicit argument-vector element at a time.
The worker runs in a required Bubblewrap sandbox with no network, hidden home
and Git metadata, and only the objective's leased paths writable. It receives
the immutable objective packet path as its final argument:

```sh
python3 tools/harness_loop.py run --item R0-04 \
  --worker-arg <worker-executable> \
  --worker-arg <worker-mode>
```

The loop refuses a dirty tree, low hill-climbability, stale DAG/contracts,
out-of-lease changes, branch or revision changes, and failing safety checks. It
stops after at most three iterations, one unchanged result, two failures, 30
minutes total, or 20 minutes in one worker invocation. A successful iteration
leaves only a candidate diff for review. The optional typed candidate step may
write a namespaced local proposal ref; neither the worker nor the loop can
change the current branch, push, merge, release or deploy.

Durable claims, counters and packet digests live below ignored
`.automonique/state/`. Worker stdout and stderr remain attached to the invoking
terminal and are not persisted as repository logs. This worker path is not the
Codex session driver and is not used to launch provider-backed agents.
