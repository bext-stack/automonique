<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Workload identity

The workload used to run as the supervisor's own uid. Any process of that uid
on the host could read the workload's `/proc/<pid>/environ` (its environment,
including any secret placed there) and open `/proc/<pid>/fd/0` (its prompt),
and could trace it. Audit finding F-10 named this the largest real sandbox
gap. This page records how a workload gets a host uid of its own, what that
does and does not close, why the request is per-plan and off by default, and
the kernel limitation that keeps it apart from the temporary-storage mount.

## The mechanism

Per the owner decision on issue #47, the workload's identity is separated
through an **unprivileged user namespace**, with **no setuid binary of ours**.
The request is one launch-plan line — `LaunchPlan::separate_workload_identity`
puts `identity=subordinate` in the frame — and a plan that does not ask
launches exactly as before. When the plan asks, the launch entry helper, which
becomes the workload, does this between the cgroup join and the
Landlock/seccomp installation, single-threaded:

1. It resolves an identity plan from the host's own files: the account's first
   subordinate uid range in `/etc/subuid` and gid range in `/etc/subgid`. The
   workload's host uid is the **top** of the first uid range
   (`start + count - 1`) — rootless container tooling maps upward from the
   start, so the top is the entry least likely to collide. The choice is fixed
   per host; two runs share a host uid, as they shared the supervisor's uid
   before, and different accounts never share one because subordinate ranges do
   not overlap.
2. It spawns a **mapper** — itself, through `/proc/self/exe`, in a private
   argument mode — before it unshares, so the mapper runs outside the new
   namespace as a process of the same host uid.
3. It `unshare(CLONE_NEWUSER)`s, releases the mapper, and waits. The mapper runs
   the distribution's setuid `newuidmap`/`newgidmap` to write the namespace's
   maps: `0 → <supervisor uid>` and `<supervisor uid> → <subordinate uid>` for
   uids, `0 → <supervisor gid>` for gids. Inside the namespace the workload
   still sees itself as the supervisor's uid *number*, so `getpwuid`, `HOME`
   and the account name are unchanged; the kernel's view is the subordinate
   host uid.
4. It reads the kernel's `uid_map`, `gid_map` and `setgroups` back and refuses
   anything but the exact plan.
5. It `setresuid`s to the workload uid and shapes its capabilities: it keeps
   exactly `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` and `CAP_FOWNER` in the
   permitted, effective, inheritable and **ambient** sets (so they survive
   `execve`), drops every other capability from the bounding set, and sets a
   `0o002` umask so files it creates stay group-writable by the supervisor.
6. It reads `/proc/self/status` back and refuses unless the uid, gid and every
   capability set are exactly what it asked for.

The workload's gid is unchanged — it keeps the supervisor's group, which the
namespace sees as its root group. Mapping the account's own gid is what
`newgidmap` permits, and it costs `setgroups`: the kernel writes `deny` to
`/proc/<pid>/setgroups`, so the workload inherits the supervisor's
supplementary groups and can neither add nor drop them. That inheritance is
the same as before this feature existed.

The seccomp filter — installed for every workload, separated or not — denies
`unshare`, `setns`, `clone` with any namespace flag, and answers `clone3` with
`ENOSYS` rather than `EPERM` (the one answer that makes a C library fall back
to `clone`, where the flags are visible). A separated workload therefore
cannot open a nested namespace in which it would be root again.

## What is closed, and where

| Property | Where it lives |
| --- | --- |
| The workload runs as a host uid that is not the supervisor's. From `execve` on, a process of the supervisor's uid gets `EACCES` reading `/proc/<pid>/environ` and opening `/proc/<pid>/fd/0`: the credential change marks the workload non-dumpable, so its `/proc` files become root-owned. The delegated-scope proof `a_same_uid_observer_cannot_read_the_workload_environ_or_stdin` reads both from the supervisor uid and from a same-uid sibling and asserts the refusals; `the_workload_runs_as_a_host_uid_outside_the_supervisor_uid` reads `/proc/<pid>/status` from outside the namespace. | `automonique_runner::identity`, `automonique_runner::launch` |
| Identity separation is **not** discretionary-access separation. The workload keeps `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`/`CAP_FOWNER` over inodes the supervisor owns — the workspace and the provider home — because a workload that could not open them would not be a workload. The Landlock allowlist stays the filesystem boundary. | `automonique_runner::identity` |
| The capability probe exercises the switch, rather than reading a config file: it runs the launch helper in a throwaway probe mode that performs the whole switch on itself and reports its own kernel view. So a host whose subordinate files, mapping helpers or AppArmor policy would refuse the launch refuses the probe the same way, and readiness (`SandboxEnforceableLaneWired` / `SandboxUnavailableLaneWired`) reflects it. | `automonique_runner::capability::WorkloadIdentityFinding`, `automonique_daemon::execute::offered_host_features` |
| Fail-closed, per plan. A plan that asks is refused by the entry helper — before the workload exists — when any prerequisite is missing, with a typed reason. A plan that asks **and** would attach the enforced temporary-storage mount is refused at admission with `WorkloadIdentityTemporaryStorageConflict`, naming the kernel limitation below; each feature works alone. No RunSpec field can request the separation yet, so the daemon lane composes every run without it and `uid_separation` is not in the daemon's `ENFORCED_PROPERTIES`; it joins them when the limitation below is resolved and a document vocabulary exists. | `automonique_runner::admission::refuse_identity_temporary_storage_conflict`, `automonique_runner::launch` |

Signalling is deliberately **not** blocked: the supervisor's uid owns the
workload's user namespace, so it keeps `CAP_KILL` over that namespace, which
the supervisor needs to manage its runs and which the cgroup kill path relies
on. The acceptance is the *read* boundary — the prompt and the environment —
not the ability to end the run.

## Host prerequisites

- `kernel.apparmor_restrict_unprivileged_userns = 1` on Ubuntu 24.04 moves an
  unconfined process that creates a user namespace to the `unprivileged_userns`
  AppArmor profile, which denies every capability inside it, including the
  `CAP_SETUID` the switch needs. `packaging/apparmor/automonique-launch-enter`
  is an unconfined-flags profile that grants the launch helper `userns`; install
  it with `install -m 0644 packaging/apparmor/automonique-launch-enter
  /etc/apparmor.d/automonique-launch-enter && apparmor_parser -r
  /etc/apparmor.d/automonique-launch-enter`. The profile attaches to the release
  helper paths and the development test-build paths. The capability probe
  detects the grant by try-creating a namespace in a throwaway child, so it is
  never trusted from configuration.
- The `uidmap` package must be installed (`/usr/bin/newuidmap`,
  `/usr/bin/newgidmap`, setuid root).
- `/etc/subuid` and `/etc/subgid` must name a range for the account, e.g.
  `<account>:200000:65536`. The distro seeds these when the account is
  created; the runner host already has them.

These are prerequisites for a plan that asks; a host without them runs every
ordinary plan untouched and refuses only the asking ones, typed.

## The kernel limitation: no separated identity with the FUSE tempfs

The identity switch and the per-run FUSE temporary-storage mount (#140) are,
on this kernel, **mutually exclusive**, which is why the combination is a
typed admission refusal (`WorkloadIdentityTemporaryStorageConflict`) and the
separation is not yet the default.

The tempfs is mounted by the supervisor through the setuid `fusermount3`, so
the FUSE connection's owning user namespace (`fc->user_ns`) is the init user
namespace. A switched workload runs in a **child** user namespace. On this
kernel (Ubuntu 6.8.0-124-generic) `fuse_permission` calls
`fuse_allow_current_process`, and — measured directly — a process in a child
user namespace is refused with `EACCES` **regardless of uid or file mode**,
even with `allow_other` on the mount and `user_allow_other` in
`/etc/fuse.conf`. The measurements, taken with throwaway builds on the runner
host:

- `stat`/`getattr` on the mount from the switched workload **succeeds** (the
  server and the mount are reachable), but every `open`/`opendir`/`create`/
  `write` — the operations that pass through `fuse_permission` — is refused;
- the refusal persists when the switched process keeps the supervisor's own
  host uid (skipping the `setresuid`), so it is the **child user namespace
  itself**, not the uid change, that the kernel rejects;
- the refusal persists with the FUSE root node owned by the workload's host
  uid at mode `0700` (owner match) and with `default_permissions` removed,
  confirming it is `fuse_allow_current_process`, not the mode-bit check.

So `allow_other` is necessary but **not sufficient**, and no mount-option or
ownership change on the supervisor's mount can lift the refusal. `#140` is
deliberately untouched: its mount options, prerequisites and every test are
exactly what they were.

**Intended end state.** The mount is performed *inside* the workload's
namespace: the launch helper, which owns the workload's user namespace and can
unshare a mount namespace beside it, performs the FUSE mount itself, so
`fc->user_ns` is the workload's namespace and access is ordinary. That makes
the mount private to the workload's mount namespace, so the supervisor's
`statvfs` reconcile (`temporary_storage_readback`) must move to the ledger the
QuotaFs server already maintains, or read through `/proc/<workload>/root`.
When that lands, the combination refusal is removed, a document vocabulary can
request the separation, and `uid_separation` joins the daemon's enforced
properties. Until then: every #140 delegated proof passes unchanged, the
identity proofs in `tests/workload_identity.rs` pass for plans that ask, and
`a_plan_that_does_not_ask_keeps_the_supervisor_identity` pins the default.
