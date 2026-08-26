<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Temporary-storage budget

`sandbox.budgets.temporary_storage` is enforced. It stopped being an
acknowledged `UnenforcedBudget` when the runner gained a per-run FUSE
filesystem with exact byte and object ceilings, served by the supervisor and
granted read-write to the workload's Landlock ruleset. The feasibility of the
mechanism on the runner host is recorded in `spikes/tempfs-quota/README.md`;
this page records the product decisions the integration makes.

**Two mount sites, one filesystem.** A plan that keeps the supervisor's
identity gets a filesystem the supervisor mounts through the host's setuid
`fusermount3`, in the supervisor's own mount namespace — the original
mechanism, unchanged. A plan that separates the workload's identity gets one
the *launch* mounts, inside the user and mount namespaces it creates, and hands
back to the supervisor over the plan channel; a supervisor-mounted filesystem
is unreachable to a process in a child user namespace, so this is not a
preference but the only mount that works for such a workload. The site follows
from the plan (`RunTempfs::provide`), so the wrong one cannot be attached. The
ledger, the exceedance channel, the checkpoint, the containment policy and the
reconcile are the same code in both cases; `docs/operations/workload-identity.md`
records the kernel facts behind the second site and why the supervisor still
serves it.

## What is enforced, and where

| Decision | Where it lives |
| --- | --- |
| A run's budget is `TemporaryStorageBudget { bytes, objects }`. `bytes` is the document's `temporary_storage_bytes`, exact. `objects` is derived: one object per 4 KiB block of the byte ceiling (`bytes / 4096`), so the same number bounds files, directories and symlinks. A wire field for the object count would be a protocol change and is deliberately not made here. | `automonique_runner::tempfs::TemporaryStorageBudget::from_bytes` |
| Admission refuses a byte ceiling that is zero, not a multiple of 4096 (`statfs` reports blocks and the readback must equal the ceiling exactly, not round it), or above `MAX_TEMPORARY_STORAGE_BYTES` (128 MiB, see charging). The refusal is `QuotaRejected("sandbox.budgets.temporary_storage")`. | `automonique_runner::admission::map_temporary_storage` |
| Admission refuses when the host cannot enforce. The context carries `TemporaryStorageEnforcement`: either a `VerifiedFuse` (the supervisor opened `/dev/fuse` read-write and found a setuid-root, executable `fusermount3`) or the typed `PrerequisiteError`, which admission republishes as `TemporaryStorageUnenforceable`. Nothing is admitted with a temporary-storage budget it cannot apply. | `automonique_runner::admission` |
| The mount is created after admission and after the attempt is registered (so a duplicate attempt is refused before any mount is attempted), under the run's private directory (`<state>/runs/<run_id>/tmp`), before any workload exists. Supervisor-mounted: `fusermount3` is invoked by absolute path and explicit argument vector, and the mount is confirmed from the kernel before use — the mount table must show `fuse.automonique-tempfs` at the mountpoint, owned by this uid, and `statvfs` must read back exactly the requested ceilings with zero usage; any mismatch detaches the mount and refuses the run. Launch-mounted: the launch reports the mount table entry it created and the `statvfs` it read *after* becoming the workload, and the supervisor refuses anything but a `fuse.automonique-tempfs` mount at the admitted mountpoint, owned by namespace-root, serving the identity the filesystem's nodes were built for, reading back exactly the requested ceilings with zero usage; any mismatch refuses the launch before the workload runs. | `automonique_runner::tempfs::MountedTempfs::mount`, `automonique_runner::tempfs_namespace` |
| The plan is pointed at the filesystem only through `AdmittedLaunch::with_temporary_storage(&temporary_storage)`, which refuses a budget that is not the admitted one, and which adds exactly one read-write Landlock grant on the mountpoint, binds `TMPDIR` to it, and — for a plan whose launch is what mounts — adds the one `tempfs=` frame line naming the mountpoint and the ceilings. A document that binds `TMPDIR` itself is refused at admission: it would redirect scratch writes away from the budgeted tree. | `automonique_runner::admission::AdmittedLaunch` |
| A workload that exceeds either ceiling is refused by the filesystem at the syscall that asked (`ENOSPC` for bytes, `EDQUOT` for objects), and the supervisor's poll loop reads the first refusal and kills the run cgroup. The outcome is `ExecutionOutcome::TemporaryStorageExceeded { exceedance }`, carrying the refusal exactly as the ledger recorded it. Once the tree is dead the supervisor reads `statvfs` from the mount (bounded by `TEMPORARY_STORAGE_READBACK_DEADLINE`); the `ExecutionReport` carries that readback (`temporary_storage_readback`), and the spool records one synthetic `provider_warning` frame, `TEMPORARY_STORAGE_EXCEEDED_WARNING: <exceedance>; statfs <readback>`, as the last event before the `failed` terminal. The terminal payload itself stays `failed`: a new wire state would be a protocol change and is deliberately not made, so a reader distinguishes a budget kill by that frame. A JCode session run applies the same policy from the daemon's turn loop: the turn is cancelled, the same frame is recorded, and the run ends `failed`. | `automonique_runner::backend`, `automonique_daemon::execute` |
| The ledger is checkpointed to `<state>/runs/<run_id>/tempfs-ledger` while the run lives (on every change, at most every 250 ms, and immediately on an exceedance) and finally at unmount with the outcome. A supervisor that dies keeps the last checkpoint; the reaper reads it back. | `automonique_runner::tempfs_checkpoint` |
| Readback is bounded. Every `statvfs` the supervisor issues against its own mount runs under a deadline; on expiry the supervisor writes `/sys/fs/fuse/connections/<minor>/abort`, which the kernel lets the mount owner do, and the reconciliation continues from the last checkpoint. A stuck server cannot hang the run's end. For a launch-mounted filesystem there is no path to `statvfs` and no round trip to bound: the readback is the server's own `statfs` answer, computed from the ledger by the same call the kernel's `statvfs` would have reached, so it is always available and always the filesystem's own account. The daemon records every reconcile's outcome in the native journal (see below). | `automonique_runner::tempfs::MountedTempfs::reconcile`, `automonique_daemon::execute::Attempt` |
| A dead owner leaves a stale mount (`ENOTCONN`; `auto_unmount` does not clean up a same-uid mount on this host). When the daemon opens its execution lane at start, the reaper walks `/proc/self/mountinfo` for this uid's `fuse.automonique-tempfs` entries under the runs directory, detaches every disconnected one lazily, reads the dead owner's last checkpoint beside it, and reports each one to the native journal. A live entry is left alone: it belongs to a still-running supervisor (a previous generation during handoff). This is the supervisor-mounted site only, and it stays because that site stays: a launch-mounted filesystem leaves nothing to reap, because its mount lives in a mount namespace that dies with the run tree, and its checkpoint is read back the same way either way. | `automonique_runner::tempfs::reap_stale_mounts`, `automonique_daemon::execute::ExecutionLane::open` |

## Where the outcome is recorded

Three records, none of them a configuration claim:

1. **The run's spool.** A run killed for its scratch budget carries one
   synthetic `provider_warning` frame immediately before its `failed`
   terminal event. Its text is `TEMPORARY_STORAGE_EXCEEDED_WARNING`, the
   exceedance as the ledger spelled it (`bytes requested=… used=… ceiling=…
   errno=ENOSPC(28)` or the `objects`/`EDQUOT` form), and the `statvfs` the
   supervisor read after the kill (`statfs bsize=… blocks=… bfree=0 …`), or
   `statfs unavailable: <reason>` when the server did not answer within the
   readback deadline. The frame is appended under the terminal reserve only;
   the run's own last word is never crowded out. The test
   `a_contained_workload_that_overflows_its_budget_is_killed_with_a_typed_outcome`
   pins its position and content.
2. **The ledger checkpoint** at `<state>/runs/<run_id>/tempfs-ledger`: the
   final phase carries the ledger (peaks, refused counts, the first refusals
   verbatim), the mount evidence, `statfs` at mount and before unmount, and
   whether the readback was aborted and the unmount confirmed. The daemon
   test `a_contained_run_answers_through_the_real_lane` reads it back for
   every run.
3. **The native journal** (`journalctl --user -u <unit>`), one structured
   event per reconcile: `temporary_storage_reconciled` with the run id,
   ceilings, peaks, refused counts, the kernel's used bytes before unmount,
   and the abort/unmount-confirmed flags, at priority 6 normally and 4 when a
   ceiling refused anything, the readback was aborted, or the unmount was not
   confirmed; `temporary_storage_unreconciled` with a stable category when
   the unmount itself failed (the mount's own drop still detaches it lazily);
   and `temporary_storage_mount_reaped` for every stale mount the reaper
   detached at lane open. Run identifiers and categories are validated
   before they become fields; no workload content reaches the journal.

The daemon's run index and the status projection still read `failed` for a
budget kill. A distinct wire state would be a protocol change and is not made
here.

## Oversized single writes: all-or-nothing per request

A write that would cross the byte ceiling is refused whole at the granularity
the kernel presents it. A `write(2)` that fits in one FUSE request (up to the
negotiated request size, at most `fuser`'s 16 MiB `max_write`) either lands
entirely or fails with `ENOSPC` and charges nothing: there is no partial
request and no silent truncation inside a request. A `write(2)` larger than one
request is split by the kernel into several; each is admitted or refused whole,
so a program writing sequentially observes each write either land in full or
fail in full, and the file it leaves behind ends exactly on a request (block)
boundary at exactly the bytes the ledger charged. The tests
`an_oversized_single_write_is_refused_whole_and_charges_nothing` and
`sequential_writes_each_land_whole_or_fail_whole` pin both halves.

## Charging policy

The filesystem stores bytes in the supervisor's memory. The store is bounded
by the byte ceiling plus per-object metadata (at most 255 name bytes and a
fixed attribute record per object, and the object ceiling is `bytes / 4096`),
and the byte ceiling is capped at admission by `MAX_TEMPORARY_STORAGE_BYTES`
(128 MiB). With the daemon's `MAX_LIVE_ATTEMPTS` of 8, the supervisor's total
exposure is 1 GiB. The bytes are deliberately **not** charged to the run's
`memory.max`: the server is a supervisor thread, and placing its store inside
the run's cgroup would let the workload's own memory pressure kill the
filesystem that accounts for it. A disk-backed store (an unlinked file under
the run directory) would keep the same ledger, readback and enforcement path
and raise the cap; it is a follow-up, not a change to enforcement.

## Host prerequisites

The runner host must expose `/dev/fuse` as a character device this uid can
open read-write and `/usr/bin/fusermount3` as a setuid-root executable. Both
are verified before every admission. On a host without them every document is
refused (`sandbox_unenforceable` on the wire) rather than run without the
budget. Nothing else is required for the supervisor-mounted site: no user
namespace, no filesystem quota, no capability.

The launch-mounted site needs no `fusermount3` at all — it calls `mount(2)`
directly as namespace-root — but it does need everything the identity switch
needs, listed in `docs/operations/workload-identity.md`: subordinate ranges,
the setuid mapping helpers, and an AppArmor grant where the host restricts
unprivileged user namespaces. Those are prerequisites of the identity request
itself, refused by the feature negotiation before a plan exists, so a document
never reaches a mount it cannot have. The `/dev/fuse` and `fusermount3` gate is
still applied uniformly: one verified prerequisite, checked before every
admission, is what the fail-closed answer is built on.

## What is not enforced here

Artifact accounting (`sandbox.budgets.artifact`) remains an acknowledged
`UnenforcedBudget`. There is no artifact publication subsystem to attach a
byte or count ceiling to, and inventing one for the sake of a check would be
a configuration-only claim.
