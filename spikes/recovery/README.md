<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Baseline recovery drill (`R0-10`)

This spike takes a consistent online backup of a synthetic control state,
destroys the source, restores the backup into a target directory that did not
exist, and proves the restored state is one coherent point in time rather than
merely present.

It is a **real drill over a real artifact**, and it is **not a clean-host
restore**. Both halves of that sentence matter, and the difference is the first
thing this file has to say.

Two partial mechanisms now make the next integration step explicit:

- `clean_boundary.py` proves a trusted inline worker can run as PID 1 in seven
  fresh Linux namespaces with repository and TCP access denied, capabilities
  zeroed, parent-death cleanup armed and only its report descriptor surviving.
  It is a standalone boundary probe, not yet the restore.
- `recovery_plan.py` validates one typed, hash-chained receipt per canonical
  R0-09 position. It grants no N/A decisions and can never certify completion
  by itself; real execution provenance belongs to the integration step.

## What is measured, and what is not

| | measured here | needed for the contract's claim |
|---|---|---|
| Backup | online SQLite snapshot with transactions committing on a second connection while the copy is in flight | same mechanism, production scale, real writers |
| Restore target | an empty directory on the running host | a provisioned disposable host |
| Runtime | the interpreter already running | installed from the release |
| Service start | none | disconnected recovery mode, before any transport lease |
| Credentials | none exist; none are resolved | each required descriptor resolved through the escrowed key or the external provider |
| RPO | the drill's own pacing between watermark and induced loss | production backup cadence |
| RTO | restore plus verification of a kilobyte-scale fixture | provision, install, restore, start, reconcile |

So the drill measures a genuine backup/restore/verify boundary and reports its
recovery point and recovery time as numbers with units at scope
`local_fixture`. Those numbers are **not** compared to the declared objectives
in `docs/product-plan/requirements/goals-and-invariants.md` (RPO 5 minutes or
less, RTO 30 minutes or less). The comparison is recorded as `out_of_scope`
with `objective_met: null`, and `drill.compare_to_objective` returns `MET` or
`MISSED` only for a `Scope.CLEAN_HOST` measurement, which nothing in this
repository can currently produce. A test holds that door shut.

Reporting a fixture number against a host objective would be the exact failure
this repository exists to prevent, so the door is closed in code rather than in
prose.

## What a real clean-host drill needs that this one does not have

`python3 spikes/recovery/drill.py --procedure` prints the list; it is generated
from the same typed dependency table the drill restores from, so it cannot
drift from the code. In summary: a provisioned disposable host, an installed
release runtime, release manifests, recoverable secret material with an
escrowed key, and a service definition that starts the restored installation in
disconnected recovery mode. Five of the nine restore dependencies are marked
`not_drilled` for exactly this reason, and each one is emitted as a
`dependency_not_exercised` finding on every run.

## Running it

```sh
python3 spikes/recovery/drill.py                       # the drill
python3 spikes/recovery/drill.py --procedure           # procedure only, touches nothing
python3 spikes/recovery/dependencies.py --report       # consume the R0-09 inventory
python3 spikes/recovery/dependencies.py --check        # generated list is current
python3 spikes/recovery/test_recovery_drill.py         # 50 controls
python3 -m unittest -v spikes.recovery.test_dependencies_contract  # 9 controls
python3 -m unittest -v spikes.recovery.test_clean_boundary          # 10 controls
python3 -m unittest -v spikes.recovery.test_recovery_plan           # 12 controls
```

Exit codes: `0` verified, `1` failed, `2` incomplete dependency agreement,
`3` refused, `4` inconsistent, `5` residue left. The current local drill exits
`2`; it cannot certify R0-10 while canonical positions remain unexercised.

## Preconditions, refused rather than assumed

The drill refuses to start unless its workspace is provably disposable fixture
state, and refuses to delete anything that does not carry this run's own
marker. Each refusal names one closed `Refusal` code:

- `workspace_inside_repository` — the workspace is in the live repository;
- `workspace_not_under_temporary_root` — it cannot be shown to be disposable;
- `workspace_is_home_or_root` — it is the home directory or `/`;
- `workspace_not_empty` — it holds state the drill did not create;
- `marker_missing` / `marker_token_mismatch` — a destructive step was asked to
  remove a directory this run did not create.

The source and target are both created by the drill inside that workspace, so
"disposable" is a property it establishes, not one it is told.

## Why the restore is consistent rather than hopeful

The fixture keeps two ordering rules on every transaction:

1. **blob before row** — artifact bytes are durable before the row referencing
   them commits;
2. **config file before setting** — a configuration revision is durable in the
   file before the database records it as current.

The backup then snapshots the database *first* and derives everything else from
that snapshot: the blob set is exactly the rows the snapshot carries, and the
configuration file is copied afterwards, so it can only be ahead. That is what
makes the recovery set one point in time. Events committed after the watermark
belong to the next backup, which is where the measured recovery point window
comes from.

The eight transactions committed during the backup arrive on a second SQLite
connection from inside the copy's own progress callback, not from a second
thread. That is a real online backup — SQLite restarts the copy because the
source changed underneath it — and it is deterministic, which is why the
watermark is 40 on every run rather than something between 32 and 40.

`--fault naive-backup` copies the same components in the wrong order — blobs
first, database second — and the drill reports `artifact_row_has_blob` violated
with exactly the eight rows committed in between. The database itself passes
its integrity check in that run: it is the recovery *set* that is torn, which is
why "the database restored fine" is not evidence of a consistent backup.

## Clean target

The restore reads only the paths the backup manifest lists, and the source is
destroyed before the restore begins, so a hidden dependency on source state
cannot silently satisfy the drill. After the restore, the target's complete file
set and hashes are compared against the manifest: a file present in the target
that the backup did not carry fails `target_matches_manifest`.
`--fault leak-source` copies one file straight from the source into the target
and is caught by that rule.

This is a clean *target*, not a clean *host*. Nothing here proves that a host
carries no leftover installation, because no host is provisioned.

## Dependency agreement with `R0-09`

`dependencies.py` consumes only R0-09's canonical publication at
`plan/inventory/surface/restore-dependencies.json`, schema
`automonique.restore-dependencies/v1`. It validates the complete closed shape,
the named producer and consumer, the two declared objectives, the contiguous
topological order and the source digest. It then invokes R0-09's real renderer
over the actual source inventory and requires byte-for-byte equality. A copied,
stale or threshold-loosened document is refused even if its shape looks valid.

The consumer now records 21 ordered positions, two objectives and one excluded
credential class. It separately reports 8 legacy local-drill IDs missing from
R0-09 and 20 canonical positions the current local drill does not exercise.
Authenticity is therefore a pass while agreement remains an explicit partial
gap; the two claims cannot silently collapse into one another.

## Generated file

`restore-dependencies.json` is generated from
`recovery_set.py:RESTORE_DEPENDENCIES` by
`python3 spikes/recovery/dependencies.py --write`, written atomically through a
staging name, and `--check` fails when the checked-in copy is stale.

This generated file is retained as a description of the old local drill's own
needs. It is not accepted as R0-09 authority, and a test holds that boundary.

## Idempotence and residue

Every run cleans up in a `finally`, after success, after an injected failure and
after an inconsistent verdict alike, and then re-reads the filesystem to confirm
the workspace is gone. `--fault skip-cleanup` proves the residue check can fail:
it reports `residue_left` and exits 5. Two consecutive runs produce identical
`reproducible` blocks — outcome, watermark, event and artifact counts, lost
events, every invariant verdict and every finding code. Wall-clock durations,
the workspace name and the run token are excluded from that block, because a
rerun cannot reproduce them and pretending otherwise would make the check
vacuous.

## Safety properties

No network access, no subprocess, no environment variable read, no credential of
any kind, and no new external runtime dependency. The drill modules use the
standard library; the canonical consumer additionally imports the checked-in
R0-09 renderer by its exact module path. A syntax-tree test asserts that precise
boundary. The drill never touches the live repository, and a test compares Git
status before and after a run to prove it.
