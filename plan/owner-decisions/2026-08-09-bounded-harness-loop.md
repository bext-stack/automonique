<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — bounded bootstrap harness loop

| Field | Decision |
|---|---|
| Status | approved for local implementation under `R0-18` |
| Expected base | `0ddbc19b48856542d699de912c4471c5bebb0769` |
| Work ID | `R0-18` — development guides and objectives |
| Dependency evidence | `R0-17` is done with evidence; `R0-18` is selectable in `plan/ready.md` and has no blocking gate |
| Objective | generate the six required guide families and typed work objectives, then provide a durable single-worker loop over the executable DAG |
| Allowed paths | `.automonique/dev/`, `tools/`, `plan/` |
| Intended snapshot | guide/objective manifests and schema, deterministic generator, bounded loop runner, regression tests, documentation, evidence and generated plan/DAG state |
| Licence class | `Elastic-2.0` |
| Budget | one Bubblewrap-isolated local worker; maximum three iterations, 1,800 seconds total wall time and 1,200 seconds per worker invocation; one repeated unchanged result or two failures stops the loop; no network, credential, merge, push, release, deployment, branch, service or supervisor action |
| Admission | hill-climbability at least 70; lower scores remain planned but cannot run autonomously |
| Tests | six-guide coverage, objective/schema coverage, low-score refusal, contradiction diagnostics, byte reproducibility, deterministic selection, path-lease rejection, unchanged/failure/budget stops, explicit argv invocation, plan/DAG regression, compilation and hygiene |
| Review | zero independent reviewers; owner-supervised bootstrap |

## Loop authority

The loop defaults to inspection. Execution requires an explicit worker argument
vector and a working `bwrap` binary. It appends one immutable objective-packet
path to that vector and never uses a shell. The worker receives no network,
home directory, environment credentials or Git metadata; the repository is
read-only except for the exact existing lease paths. It may leave a candidate
diff inside that lease, but it cannot stage, commit, change branches, push,
merge, rewrite history, publish, release or deploy.

State contains only work IDs, revisions, counters, timestamps, exit codes and
content digests under the ignored `.automonique/state/` directory. Worker
stdout and stderr remain attached to the invoking terminal and are not stored
as repository logs.

## Stop conditions

Stop on a dirty tree at admission, base or contract drift, an out-of-lease
path, a failed repository safety check, worker timeout, cancellation, wall or
iteration budget, repeated unchanged evidence, repeated worker failure, or a
missing owner policy choice. A zero worker exit creates a candidate for review;
it does not mark the work item done or grant integration authority.

## Publication

This decision authorizes local implementation and a local candidate only. It
does not authorize a push or any other external repository mutation.
