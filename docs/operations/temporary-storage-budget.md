<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Temporary-storage budget

`sandbox.budgets.temporary_storage` is enforced. It stopped being an
acknowledged `UnenforcedBudget` when the runner gained a per-run,
supervisor-owned FUSE filesystem with exact byte and object ceilings, mounted
by the unprivileged supervisor uid through the host's setuid `fusermount3` and
granted read-write to the workload's Landlock ruleset. The feasibility of the
mechanism on the runner host is recorded in `spikes/tempfs-quota/README.md`;
this page records the product decisions the integration makes.

## What is enforced, and where

| Decision | Where it lives |
| --- | --- |
| A run's budget is `TemporaryStorageBudget { bytes, objects }`. `bytes` is the document's `temporary_storage_bytes`, exact. `objects` is derived: one object per 4 KiB block of the byte ceiling (`bytes / 4096`), so the same number bounds files, directories and symlinks. A wire field for the object count would be a protocol change and is deliberately not made here. | `automonique_runner::tempfs::TemporaryStorageBudget::from_bytes` |
| Admission refuses a byte ceiling that is zero, not a multiple of 4096 (`statfs` reports blocks and the readback must equal the ceiling exactly, not round it), or above `MAX_TEMPORARY_STORAGE_BYTES` (128 MiB, see charging). The refusal is `QuotaRejected("sandbox.budgets.temporary_storage")`. | `automonique_runner::admission::map_quotas` |
| Admission refuses when the host cannot enforce. The context carries `TemporaryStorageEnforcement`: either a `VerifiedFuse` (the supervisor opened `/dev/fuse` read-write and found a setuid-root, executable `fusermount3`) or the typed `PrerequisiteError`, which admission republishes as `TemporaryStorageUnenforceable`. Nothing is admitted with a temporary-storage budget it cannot apply. | `automonique_runner::admission` |
| The mount is created by the supervisor after admission, under the run's private directory (`<state>/runs/<run_id>/tmp`), before any workload exists. `fusermount3` is invoked by absolute path and explicit argument vector, and the mount is confirmed from the kernel before use: the mount table must show `fuse.automonique-tempfs` at the mountpoint, owned by this uid, and `statvfs` must read back exactly the requested ceilings with zero usage. Any mismatch detaches the mount and refuses the run. | `automonique_runner::tempfs::MountedTempfs::mount` |
| The plan is pointed at the mount only through `AdmittedLaunch::with_temporary_storage(&mounted)`, which refuses a mount whose kernel-read-back ceilings differ from the admitted budget, and which adds exactly one read-write Landlock grant on the mountpoint and binds `TMPDIR` to it. A document that binds `TMPDIR` itself is refused at admission: it would redirect scratch writes away from the budgeted tree. | `automonique_runner::admission::AdmittedLaunch` |
| A workload that exceeds either ceiling is refused by the filesystem at the syscall that asked (`ENOSPC` for bytes, `EDQUOT` for objects), and the supervisor's poll loop reads the first refusal and kills the run cgroup. The outcome is `ExecutionOutcome::TemporaryStorageExceeded { exceedance }`; the report carries the ledger snapshot and the `statvfs` readback taken before unmount; the spool records a synthetic `provider_warning` frame naming the exceedance and the readback before the `failed` terminal event. | `automonique_runner::backend` |
| The ledger is checkpointed to `<state>/runs/<run_id>/tempfs-ledger` while the run lives (on every change, at most every 250 ms, and immediately on an exceedance) and finally at unmount with the outcome. A supervisor that dies keeps the last checkpoint; the reaper reads it back. | `automonique_runner::tempfs_checkpoint` |
| Readback is bounded. Every `statvfs` the supervisor issues against its own mount runs under a deadline; on expiry the supervisor writes `/sys/fs/fuse/connections/<minor>/abort`, which the kernel lets the mount owner do, and the reconciliation continues from the last checkpoint. A stuck server cannot hang the run's end. | `automonique_runner::tempfs::MountedTempfs::reconcile` |
| A dead owner leaves a stale mount (`ENOTCONN`; `auto_unmount` does not clean up a same-uid mount on this host). At daemon start the reaper walks `/proc/self/mountinfo` for this uid's `fuse.automonique-tempfs` entries under the runs directory, detaches every disconnected one lazily, and attaches its last checkpoint to the report. A live entry is left alone: it belongs to a still-running supervisor (a previous generation during handoff). | `automonique_runner::tempfs::reap_stale_mounts` |

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
