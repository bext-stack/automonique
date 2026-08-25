<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Temporary-storage quota spike

Feasibility spike for issue #111: can the runner enforce the
`sandbox.budgets.temporary_storage` byte ceiling — and an object-count
ceiling beside it — on this host, as the unprivileged supervisor uid, with
kernel readback rather than a configuration claim?

**Answer: yes, through an unprivileged FUSE filesystem.** User namespaces are
refused here, the filesystems carry no quota mount options and the supervisor
holds no capability, but `/dev/fuse` is world-writable and `/usr/bin/fusermount3`
is setuid root. A FUSE filesystem owned by the supervisor uid enforces exact
byte and object ceilings at the syscall that asks (`ENOSPC` / `EDQUOT`),
reports them through `statfs`, works underneath the runner's real composed
containment with an ordinary read-write Landlock grant on the mountpoint, and
leaves a detectable, detachable stale mount when its owner dies. The costs and
the open questions are recorded below.

This is a spike, not product code. Nothing under `rust/` changes; the crate is
its own Cargo workspace like `rust/fuzz`, and `automonique-runner` is a
dev-dependency by path only so the proof drives the real entry helper.

## What is here

| Path | What |
| --- | --- |
| `src/ledger.rs` | Exact accounting: every byte and object is reserved here first; every refusal is a typed `Exceedance` (resource, requested, used, ceiling, errno). |
| `src/filesystem.rs` | The in-memory FUSE filesystem over the ledger (`fuser` 0.18, no libfuse linkage, no writeback cache). |
| `src/mount.rs` | Fail-closed prerequisites, the `fusermount3` handshake by explicit absolute path and argument vector, post-mount readback, unmount, stale-mount detach, and the `auto_unmount` probe. |
| `src/readback.rs` | `/proc/self/mountinfo` and `statvfs(2)` as the kernel answers them; `MountStatus` classification (`NotMounted` / `Live` / `Disconnected` / `Foreign`). |
| `src/main.rs` | `automonique-tempfs-quota serve <mountpoint> <bytes> <objects>`, `inspect`, `detach`, `probe-auto-unmount`. |
| `tests/mount.rs` | Same-uid proofs: prerequisites, exact ceilings, kernel readback, drop-detaches, SIGKILL leaves a stale mount that `detach` clears, `auto_unmount` measurement, write-loop overhead. |
| `tests/contained.rs` | The containment proof: a busybox workload under the runner's real `LaunchPlan` boundary exceeds both ceilings and reads them back; a plan without the mountpoint grant is denied before the server sees a request; overhead of a contained write loop. |

## Running it

Unit and same-uid tests (need `/dev/fuse` and a setuid `fusermount3`; without
them the mounting tests print `NOT PROVEN` and pass vacuously, and
`AUTOMONIQUE_REQUIRE_FUSE=1` turns that into a failure):

```sh
cd spikes/tempfs-quota
cargo test --lib
AUTOMONIQUE_REQUIRE_FUSE=1 cargo test --test mount -- --test-threads=1 --nocapture
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

The containment proof needs a delegated cgroup v2 scope, the runner's entry
helper, and FUSE. It wraps the **test binary**, not cargo, exactly as the
runner's own containment tests do; outside the scope it prints `NOT PROVEN`
and passes vacuously, which is not evidence:

```sh
(cd rust && cargo build -p automonique-runner --bin automonique-launch-enter)
(cd spikes/tempfs-quota && cargo test --test contained --no-run)   # prints the binary path
systemd-run --user --scope -p Delegate=yes --quiet \
  --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u) \
  --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
  --setenv=AUTOMONIQUE_LAUNCH_HELPER=<repo>/rust/target/debug/automonique-launch-enter \
  <repo>/spikes/tempfs-quota/target/debug/deps/contained-<hash> \
  --test-threads=1 --nocapture
```

The licence boundary check covers this directory like any other:
`python3 tools/check_licenses.py` from the repository root.

## Recorded proof

Captured on this host on 2026-08-25. Paths are placeholders: `<tmp>` is a
per-test directory under `/tmp`, `<repo>` the checkout, `<uid>`/`<gid>` the
supervisor's ids. Nothing else was edited.

### Host facts

```text
kernel 6.8.0 (Landlock ABI 4; user namespaces refused; ext4 without quota options)
/dev/fuse            crw-rw-rw- root root 10,229
/usr/bin/fusermount3 -rwsr-xr-x root root   fusermount3 version: 3.14.0
/etc/fuse.conf       comments only (no user_allow_other)
/usr/bin/busybox     statically linked
```

### Mount and readback (same uid, `tests/mount.rs`)

```text
[tempfs] evidence: fstype=fuse.tempfs-quota source=automonique-tempfs options=rw,nosuid,nodev,noexec,relatime super_options=rw,user_id=<uid>,group_id=<gid>,default_permissions
[tempfs] statfs at mount: bsize=4096 frsize=4096 blocks=4 bfree=4 bavail=4 files=3 ffree=3 namelen=255
[tempfs] statfs full: bsize=4096 frsize=4096 blocks=4 bfree=0 bavail=0 files=3 ffree=2 namelen=255
[tempfs] outcome:
ledger.ceiling_bytes=16384
ledger.ceiling_objects=3
ledger.used_bytes=0
ledger.used_objects=2
ledger.peak_bytes=16384
ledger.peak_objects=3
ledger.refused_bytes=1
ledger.refused_objects=2
ledger.exceedance.0=bytes requested=1 used=16384 ceiling=16384 errno=ENOSPC(28)
ledger.exceedance.1=objects requested=1 used=3 ceiling=3 errno=EDQUOT(122)
ledger.exceedance.2=objects requested=1 used=3 ceiling=3 errno=EDQUOT(122)
statfs.before_unmount=bsize=4096 frsize=4096 blocks=4 bfree=4 bavail=4 files=3 ffree=1 namelen=255
unmount.confirmed=true
```

The test wrote exactly 16 384 bytes, was refused the 16 385th with `ENOSPC`
(`raw_os_error 28`), created three objects, was refused a fourth file and a
directory with `EDQUOT` (122), and saw every release return capacity through
`statvfs`. An unlinked-but-open file stayed charged until its last descriptor
closed. After `unmount()` the mount table had no entry and the directory
underneath was empty.

### Contained workload (`tests/contained.rs`, ceilings 1 MiB / 16 objects)

Launched through `automonique-launch-enter` with the plan
`busybox sh -c <script>`, grants `read-execute /usr/bin/busybox`,
`read-write <tmp>/mnt` (the FUSE mountpoint), `read /dev/zero`, `read /proc`,
no socket grant, inside a fresh run cgroup. The workload's stdout:

```text
started=yes
statfs_before=bsize=4096 blocks=256 bfree=256 bavail=256 files=16 ffree=16 namelen=255
Filesystem           1K-blocks      Used Available Use% Mounted on
automonique-tempfs        1024         0      1024   0% <tmp>/mnt
Filesystem              Inodes      Used Available Use% Mounted on
automonique-tempfs          16         0        16   0% <tmp>/mnt
dd_exit=1
fill_bytes=1048576
statfs_full=blocks=256 bfree=0 bavail=0 files=16 ffree=15
create_refused_at=16
mkdir_exit=1
objects=16
statfs_objects=files=16 ffree=0
reuse=ok
statfs_after_release=blocks=256 bfree=256 bavail=256 files=16 ffree=1
mountinfo=<id> <parent> 0:<minor> / <tmp>/mnt rw,nosuid,nodev,noexec,relatime shared:<peer> - fuse.tempfs-quota automonique-tempfs rw,user_id=<uid>,group_id=<gid>,default_permissions
done=yes
```

Its stderr — the typed exceedances as the workload observed them:

```text
dd: error writing '<tmp>/mnt/fill': No space left on device
257+0 records in
256+0 records out
sh: can't create <tmp>/mnt/obj16: Disk quota exceeded
mkdir: can't create directory '<tmp>/mnt/dir': Disk quota exceeded
```

`dd` asked for 300 blocks of 4096 bytes and was stopped at exactly 256; the
file holds exactly the ceiling. The sixteenth object (fifteen files after
`fill`) and a directory were both refused with `EDQUOT`. The filesystem's own
record, read by the supervisor after `containment.dispose()` and
`unmount()`, independent of the transcript:

```text
ledger.ceiling_bytes=1048576
ledger.ceiling_objects=16
ledger.used_bytes=0
ledger.used_objects=15
ledger.peak_bytes=1048576
ledger.peak_objects=16
ledger.refused_bytes=1
ledger.refused_objects=2
ledger.exceedance.0=bytes requested=4096 used=1048576 ceiling=1048576 errno=ENOSPC(28)
ledger.exceedance.1=objects requested=1 used=16 ceiling=16 errno=EDQUOT(122)
ledger.exceedance.2=objects requested=1 used=16 ceiling=16 errno=EDQUOT(122)
mount.evidence=fstype=fuse.tempfs-quota source=automonique-tempfs options=rw,nosuid,nodev,noexec,relatime super_options=rw,user_id=<uid>,group_id=<gid>,default_permissions
statfs.at_mount=bsize=4096 frsize=4096 blocks=256 bfree=256 bavail=256 files=16 ffree=16 namelen=255
statfs.before_unmount=bsize=4096 frsize=4096 blocks=256 bfree=256 bavail=256 files=16 ffree=1 namelen=255
unmount.confirmed=true
```

### Landlock without a grant on the mountpoint

Same mount, a plan granting a sibling directory read-write and the mountpoint
nothing:

```text
started=yes
elsewhere=ok
create_exit=1
ls_exit=1
blocks=1
statfs_exit=0
done=yes
--- stderr ---
sh: can't create <tmp>/mnt/denied: Permission denied
ls: can't open '<tmp>/mnt': Permission denied
--- ledger ---
ledger.peak_objects=0
ledger.refused_objects=0
ledger.refused_bytes=0
```

The denial is Landlock's (`EACCES`, in the workload's own path resolution);
the FUSE server never received a request. `statfs(2)` is not a path access
Landlock governs, so the workload could still read the ceilings of a mount it
cannot touch — a Landlock property, recorded rather than hidden.

### A dead owner leaves a stale mount; the owner uid can always clear it

`serve` in a child process, one file written, then `SIGKILL`:

```text
[tempfs] serve: ready=yes
[tempfs] after SIGKILL: status=disconnected errno=ENOTCONN(107) fstype=fuse.tempfs-quota source=automonique-tempfs options=rw,nosuid,nodev,noexec,relatime super_options=rw,user_id=<uid>,group_id=<gid>,default_permissions
```

Creating a file then failed with `ENOTCONN` (107, "Transport endpoint is not
connected"); the mount table still carried the entry. `detach_stale`
(`fusermount3 -u -q -z -- <tmp>/mnt`, same uid) returned
`status=not-mounted` and the directory was empty and ordinary again.
`SIGTERM` to `serve` instead produced a clean `unmount.confirmed=true` and the
outcome above; dropping a `MountedTempfs` in-process also detaches.

### `auto_unmount` measured

```text
auto_unmount.mounted=true auto_unmount.helper_exit=Some(0) auto_unmount.after_close=status=disconnected errno=ENOTCONN(107) ... auto_unmount.self_cleaning=false
```

`fusermount3 -o auto_unmount` is accepted for a same-uid mount, the helper
stays resident, and when the owner's socket and `/dev/fuse` descriptor close
the helper exits 0 — **without unmounting**. On this host, without
`allow_other`, `auto_unmount` does not clean up. The design below therefore
does not rely on it.

### Overhead of a small write loop

In-process, uncontained, one run each (`tests/mount.rs`):

| Loop | FUSE (release) | ext4 (release) | ratio | FUSE (debug) | ext4 (debug) |
| --- | --- | --- | --- | --- | --- |
| create + write 4 KiB + close, 256 files | 14.3 ms (~56 µs/file) | 6.1 ms (~24 µs/file) | 2.4× | 31.7 ms | 6.7 ms |
| append 4 KiB × 1024 into one file | 13.3 ms (~13 µs/write) | 2.9 ms (~2.8 µs/write) | 4.6× | 35.9 ms | 4.4 ms |

Inside containment (`tests/contained.rs`, debug server, one launch each, the
shell's own `echo` writing 4 KiB into 256 files, wall time of the whole
launch):

```text
                        run 1     run 2     run 3
overhead launch empty:  15.5 ms   30.6 ms   40.6 ms
overhead launch native: 45.8 ms   45.8 ms   40.8 ms
overhead launch fuse:   61.0 ms   71.1 ms   71.1 ms
```

The FUSE round trip adds roughly 15–30 ms over 256 creates — 60–120 µs per
file — on top of what the shell loop itself costs on ext4; the empty launch
alone varies by 25 ms between runs. Single runs on a shared host: order of
magnitude, not a benchmark.

## Design

### Landlock and a FUSE mountpoint grant

The runner's `FilesystemPolicy` opens each grant path with `O_PATH|O_NOFOLLOW`
inside the entry helper, after the supervisor has already mounted, so the
descriptor — and the `PathBeneath` rule built from it — binds to the FUSE
filesystem's root inode, not to the directory underneath. Landlock checks an
access by walking from the accessed dentry up through every ancestor,
crossing mount boundaries upward, and matching each against the rules'
inodes; everything beneath the FUSE root is therefore inside a rule bound to
that root. No new intent or vocabulary is needed: the plan carries
`read-write <mountpoint>` exactly as it would for any directory, and the
proof above shows both directions — granted, the workload creates, writes,
lists, renames and removes inside the mount; ungranted, `EACCES` in the
workload's own path resolution and a ledger that never saw a request.

Three consequences for the runner:

- **Order is load-bearing.** The mount must exist before the helper enforces,
  and the rule is inode-bound: a mount replaced after enforcement (stale,
  detached, remounted) is a different root the domain does not cover. A run's
  mount lives exactly as long as the run; it is created in admission before
  `spawn_sandboxed` and detached after `dispose`.
- **The mountpoint is a canonical path.** The policy refuses symlinked grant
  paths; the mountpoint must be spelled as it resolves.
- **Two execute denials, not one.** `PathIntent::ReadWrite` never grants
  `Execute`, and the mount carries `noexec,nosuid,nodev` besides. A workload
  cannot drop and run a binary from its scratch space by either layer.

What Landlock does not do here: `statfs(2)` on the mountpoint succeeds without
a grant. The ceilings are not secret, so this is harmless, but it is a fact
about the LSM's hook set (`landlock` handles path-based file access rights
only) rather than about the design.

### Mount ownership, and cleanup when the supervisor crashes

The mount is owned by the supervisor uid (`user_id=` in the superblock
options) and is alive exactly as long as the `/dev/fuse` descriptor the
supervisor holds. When the supervisor dies the kernel aborts the connection:
the table entry stays, and every access — including the workload's — answers
`ENOTCONN`. That fails closed for storage (nothing further can be written)
but wedges the workload rather than terminating it; the run cgroup's
`cgroup.kill` is independent of the mount and still ends the tree.

Cleanup is the mount owner's job and is always within its power:
`fusermount3 -u -z` by the same uid detaches a live or disconnected mount,
measured above. `auto_unmount` — libfuse's own answer to a dying owner — was
measured not to clean up for a same-uid mount here, so the design uses it for
nothing. Instead:

- **Stale-mount detection is a readback.** Parse `/proc/self/mountinfo` for
  entries with `fstype == fuse.tempfs-quota` and `user_id == own uid`; for
  each, `statvfs` distinguishes `Live` (a server answers) from `Disconnected`
  (`ENOTCONN`). `readback::inspect` is that classification; the run identity
  belongs in the mountpoint path (`<state>/runs/<run_id>/tmp`) and can be
  repeated in `fsname=` so a table entry names its run without any lookup.
- **A reaper at daemon start and at run reconciliation** detaches every
  `Disconnected` entry it owns and records a typed
  `StaleMountDetached { run_id, mountpoint }` against the run, alongside the
  last checkpointed ledger (see the typed outcome below). A `Live` entry with
  no owning run is a bug worth refusing on, not silently detaching.
- **Process shape.** In the spike the server is a thread of the mounting
  process, so the mount and its owner die together, which is the
  conservative choice: a per-run server process that outlives a crashed
  supervisor would keep the mount live and writable with nobody accounting
  for it. If a per-run process is wanted for isolation of the server's memory,
  it must die with the supervisor (a pipe it reads EOF on, or
  `PR_SET_PDEATHSIG`) and must not be placed in the run's cgroup unless its
  memory is meant to count against the run.
- **Backing store.** The spike stores bytes in the server's memory, bounded
  by the byte ceiling, and that memory is the supervisor's, not the run's. A
  disk-backed store (an unlinked `O_TMPFILE` per file under the daemon's state
  directory) keeps the same ledger and the same readback, moves the bytes off
  the supervisor's heap, and dies with the server as the spike's does. It was
  not built; it changes nothing in the enforcement path.

### Why `allow_other` is unnecessary for a same-uid workload

The FUSE kernel module admits a process to a mount only if all of its uids
equal the mount's `user_id` (and likewise gids), unless the mount carries
`allow_other`. The runner never changes uid — no user namespaces, no setuid —
so the workload is the supervisor's uid by construction and is inside that
set. Every other uid, root included, gets `EACCES` at the mount boundary,
which is an isolation the FUSE layer provides for free. `allow_other` would
widen the mount to every uid, and on this host is refused anyway:
`/etc/fuse.conf` has no `user_allow_other`. The spike also mounts with
`default_permissions`, so the kernel checks mode bits against the
filesystem's attributes; the root directory is `0700` owned by the uid.

### Measured overhead

Recorded above. Per operation the FUSE round trip costs on the order of
10–60 µs in a release build against 3–25 µs on ext4 — 2–5× on small
synchronous writes, dominated by the context switch per request. For a
provider's scratch space (configuration, small artifacts, logs) that is
noise beside the launch itself; for a workload doing sustained I/O in
temporary storage it is a real tax. Two mitigations exist if that matters:
larger writes (each `write(2)` is one round trip up to `fuser`'s 16 MiB
`max_write`), and — on kernels newer than this host's 6.8 — FUSE passthrough,
which the design need not depend on.

### Failing closed when `/dev/fuse` or `fusermount3` is missing

`FusePrerequisites::verify` is the admission gate: `/dev/fuse` must exist, be
a character device and actually open read-write for this uid; the helper must
exist, be a regular file, be setuid root and be executable by this uid. Each
failure is a distinct `PrerequisiteError`, and `tests/mount.rs` exercises the
missing, wrong-type and not-setuid cases. In the runner this maps to an
`AdmissionRefusal` naming `sandbox.budgets.temporary_storage` with the typed
reason, and `UnenforcedBudget::TemporaryStorage` stops existing: a run that
declares a temporary-storage budget on a host that cannot enforce it is
refused, not admitted with an acknowledgement.

The gate does not end at the prerequisites. After `fusermount3` returns, the
mount is confirmed from the kernel before the launch proceeds: the table must
show `fuse.tempfs-quota` at the mountpoint owned by this uid, and `statvfs`
must read back exactly the requested ceilings with zero usage. Any mismatch
(`EvidenceMissing`, `EvidenceMismatch`, `StatfsMismatch`) detaches the mount
and refuses the launch. The same probe belongs in the daemon's measured host
features, next to the containment probe: mount, read back, unmount at start,
so an unmeasured host cannot compose a run that needs the budget.

### Surfacing the outcome as a typed result with readback

The spike's `Outcome` is the shape: the ceilings; the ledger snapshot (used,
peak, refused counts, and the first refusals verbatim, each with resource,
requested, used, ceiling and errno); the mount-table entry observed at mount;
`statvfs` at mount and again before unmount; and whether the table showed no
entry after unmount. Every field is either the filesystem's own refusal record
or a kernel readback; none is copied from the request that created the mount.

In the runner this becomes a spool event at run end — the `Outcome` for the
`temporary_storage` budget — and, because the ledger knows the moment a
ceiling refuses, a live exceedance channel from the server to the supervisor.
Issue #111's acceptance ("a workload exceeding either budget is contained and
terminates with a typed budget outcome") is then a supervisor policy on that
channel: on the first `Exceedance`, `cgroup.kill` the run and record
`BudgetExceeded { budget: TemporaryStorage, exceedance, statfs, evidence }`.
The ceiling holds either way; the policy only decides whether the run
continues past its first `ENOSPC`. For restart and reconciliation the ledger
must be checkpointed into the run's durable record periodically and at
unmount, so a stale-mount detach after a crash can attach the last known
usage to the run instead of losing it. The spike does not checkpoint.

## What the spike does not prove

- No product integration. Admission still acknowledges
  `UnenforcedBudget::TemporaryStorage`; nothing under `rust/` changed.
- Storage is the server's memory, outside the run's cgroup: the byte ceiling
  bounds it, but the bytes are not charged to the run's `memory.max`. The
  disk-backed store above is a sketch, not code.
- No checkpointing, so a supervisor crash loses the ledger; only the stale
  mount and its detach are proven.
- One kernel (6.8.0), one helper (`fusermount3` 3.14.0), one
  `/etc/fuse.conf` (no `user_allow_other`). The `auto_unmount` finding in
  particular is a measurement of this host, which is why it is a probe rather
  than an assumption.
- The Landlock proof grants the mountpoint after mounting. A grant bound to
  the underlying directory before mounting was not tested.
- Writes were 4 KiB and single-threaded; the FUSE loop is one thread behind
  one mutex, and concurrent writers were not benchmarked. Timing numbers are
  single runs on a shared host.
- Not exercised: `mmap(MAP_SHARED)` writes, whose refusal surfaces at
  writeback rather than at `write(2)`; hard links (refused by design);
  extended attributes and file locks (not implemented); a supervisor killed
  mid-write while the workload holds an open descriptor.
- `statfs` is block-granular (4096-byte blocks). Enforcement is exact in
  bytes; a ceiling that is not a multiple of 4096 is refused at construction
  rather than approximated in the readback.
- The containment proof used `ContainmentLimits::none()`; the memory, pids
  and CPU ceilings are orthogonal to this budget and were not set.
- A panic in the server thread ends the session and turns the mount into a
  `Disconnected` one — bounded (the run loses its scratch space, nothing
  else), but the FUSE surface was not fuzzed.

## Licensing

`fuser` 0.18.0 is MIT. Every crate in the spike's graph resolves to MIT,
Apache-2.0, BSD-2-Clause, BSD-3-Clause or Unicode-3.0 — the permissive arm of
each crate's choice, exactly as `rust/deny.toml` takes it (`Unlicense OR MIT`,
`Apache-2.0 WITH LLVM-exception OR ...` and the like resolve to MIT or
Apache-2.0); nothing reciprocal. `fusermount3` and `libfuse` are not linked and no
code from them is copied: the setuid helper is a host-installed executable
invoked as a separate process with an explicit argument vector, and the
`/dev/fuse` protocol is spoken by `fuser`. The spike is outside the product
workspace, so `cargo deny` does not cover it; the graph was checked by hand
from `cargo metadata`.
