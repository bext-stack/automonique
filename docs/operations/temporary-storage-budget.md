<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Temporary-storage budget

`sandbox.budgets.temporary_storage` is enforced. It stopped being an
acknowledged `UnenforcedBudget` when the runner gained a per-run,
supervisor-served FUSE filesystem with exact byte and object ceilings. The
production launch helper mounts it inside the workload's separated user+mount
namespace and grants that private root read-write through Landlock. The earlier
supervisor-visible mount remains as a guarded compatibility primitive. The
feasibility of the mechanism on the runner host is recorded in
`spikes/tempfs-quota/README.md`; this page records the product decisions the
integration makes.

## What is enforced, and where

| Decision | Where it lives |
| --- | --- |
| A run's budget is `TemporaryStorageBudget { bytes, objects }`. `bytes` is the document's `temporary_storage_bytes`, exact. `objects` is derived: one object per 4 KiB block of the byte ceiling (`bytes / 4096`), so the same number bounds files, directories and symlinks. A wire field for the object count would be a protocol change and is deliberately not made here. | `automonique_runner::tempfs::TemporaryStorageBudget::from_bytes` |
| Admission refuses a byte ceiling that is zero, not a multiple of 4096 (`statfs` reports blocks and the readback must equal the ceiling exactly, not round it), or above `MAX_TEMPORARY_STORAGE_BYTES` (128 MiB, see charging). The refusal is `QuotaRejected("sandbox.budgets.temporary_storage")`. | `automonique_runner::admission::map_temporary_storage` |
| Admission refuses when the host cannot enforce. The context carries `TemporaryStorageEnforcement`: either a `VerifiedFuse` (the supervisor opened `/dev/fuse` read-write and found a setuid-root, executable `fusermount3`) or the typed `PrerequisiteError`, which admission republishes as `TemporaryStorageUnenforceable`. Nothing is admitted with a temporary-storage budget it cannot apply. | `automonique_runner::admission` |
| After admission and attempt registration, the helper enters the workload user namespace, unshares a private mount namespace, opens `/dev/fuse`, mounts directly, and transfers the connection descriptor to the supervisor. Exact mountinfo and empty-budget `statfs` readback inside that namespace must succeed before execution. | `automonique_runner::tempfs::mount_in_workload_namespace`, `automonique_runner::launch` |
| `AdmittedLaunch::with_namespaced_temporary_storage` is the production attachment. It requires the exact `uid_separation` feature, adds one read-write Landlock grant, binds `TMPDIR`, and seals the admitted budget and mountpoint into the launch frame. The legacy `with_temporary_storage` keeps its typed identity conflict refusal. | `automonique_runner::admission::AdmittedLaunch` |
| A workload that exceeds either ceiling is refused by the filesystem at the syscall that asked (`ENOSPC` for bytes, `EDQUOT` for objects), and the supervisor's poll loop reads the first refusal and kills/cancels the run. Direct and JCode paths immediately checkpoint it, derive the warning's statfs-shaped readback from the exact ledger, and end `failed` with the typed refusal frame immediately before terminality. | `automonique_runner::backend`, `automonique_daemon::execute` |
| The ledger is checkpointed to `<state>/runs/<run_id>/tempfs-ledger` while the run lives (at intervals no longer than 250 ms and immediately on an exceedance) and finally at unmount with the outcome. A daemon that restarts reads a remaining live private checkpoint, validates its ledger and emits a bounded recovery event; it does not claim the dead FUSE connection was adopted. | `automonique_runner::tempfs_checkpoint`, `automonique_daemon::execute::ExecutionLane::open` |
| Legacy supervisor-visible readback is bounded: every `statvfs` runs under a deadline and may abort the connection through `fusectl`. Private production mounts instead reconcile from the validated filesystem ledger after namespace teardown, so the supervisor never path-walks into another mount namespace. | `automonique_runner::tempfs::MountedTempfs::reconcile`, `automonique_runner::tempfs::NamespacedMountedTempfs::reconcile` |
| The startup stale-mount reaper remains for mounts left by pre-private-path generations. A private mount is absent from the daemon's mount table; its final checkpoint records whether namespace teardown closed the FUSE connection. | `automonique_runner::tempfs::reap_stale_mounts`, `automonique_daemon::execute::ExecutionLane::open` |

## Bounded identity-composed primitive

The runner also exposes a private-mount launch primitive for the identity
separation work. Its helper opens `/dev/fuse` and mounts after entering the
workload user and mount namespaces, passes the FUSE descriptor to the
supervisor, and admits the launch only after exact mountinfo and `statfs`
readback inside that namespace. On namespace teardown the supervisor observes
the FUSE connection close and derives the final statfs-shaped evidence from the
filesystem ledger. `StatfsReadback::from_ledger` rejects impossible usage,
peaks, resource totals or recorded refusals; checkpoint decoding uses the same
validation, so a fresh reader cannot accept internally inconsistent restart
state.

`tests/namespaced_tempfs.rs` is the delegated runner proof. The daemon's direct
and JCode production lanes now use the same private-mount lifecycle; they call
the live checkpoint operation at most every 250 ms, immediately checkpoint an
exceedance, and carry cancellation, timeout and quota outcomes through their
existing terminal mappings. Delegated `run_compose` and `execute_brokered`
proofs require `uid_separation` and reject a checkpoint that does not name the
private namespace-mount schema.

The typed `WorkloadIdentityTemporaryStorageConflict` still guards only the
legacy supervisor-visible attachment. Production private mounts transfer their
FUSE and helper descriptors to `automonique-tempfs-owner.service`, a sibling
outside the daemon service's kill domain. One private same-uid control socket
binds each run to an unguessable adoption token, exact cgroup device/inode,
sealed budget and next durable checkpoint sequence. A restarted daemon can
therefore adopt the live ledger without receiving the FUSE descriptor back.

The owner acquires its singleton lock before inspecting restart state. When the
owner itself restarts, the kernel descriptors are unrecoverable, so it
exhaustively audits the bounded run inventory and converts every valid live
custody record to a monotonic `Final` checkpoint with `aborted=true`. An
unreadable or overfull inventory refuses owner startup before partial mutation;
a second owner cannot alter custody held by the first. Normal reconciliation
removes the token and custody record only after the final checkpoint is durable.
The systemd installation and removal order is documented beside the units.

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
   before they become fields; no workload content reaches the journal. A new
   generation also emits `temporary_storage_checkpoint_recovered` for each
   bounded, validated live private checkpoint found at startup, carrying its
   exact sequence and ledger counters without claiming the mount survived.

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
budget. Nothing else is required: no user namespace, no filesystem quota, no
capability.

## What is not enforced here

Artifact accounting (`sandbox.budgets.artifact`) remains an acknowledged
`UnenforcedBudget`. There is no artifact publication subsystem to attach a
byte or count ceiling to, and inventing one for the sake of a check would be
a configuration-only claim.
