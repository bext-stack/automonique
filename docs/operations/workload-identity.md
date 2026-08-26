<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Workload identity

The workload used to run as the supervisor's own uid. Any process of that uid
on the host could read the workload's `/proc/<pid>/environ` (its environment,
including any secret placed there) and open `/proc/<pid>/fd/0` (its prompt),
and could trace it. Audit finding F-10 named this the largest real sandbox
gap. This page records how a workload gets a host uid of its own, what that
does and does not close, how a document asks for it, and how it composes with
the enforced temporary-storage mount — which, until the mount moved inside the
workload's own namespaces, it could not.

## The mechanism

Per the owner decision on issue #47, the workload's identity is separated
through an **unprivileged user namespace**, with **no setuid binary of ours**.
The request is one launch-plan line — `LaunchPlan::separate_workload_identity`
puts `identity=subordinate` in the frame — and a plan that does not ask
launches exactly as before. A document asks by requiring the `uid_separation`
feature; see *The document's request* below. When the plan asks, the launch
entry helper, which becomes the workload, does this between the cgroup join and
the Landlock/seccomp installation, single-threaded:

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
5. If the plan also carries a temporary-storage mount, it mounts it **here**,
   while it is still namespace-root: see *Composing with the temporary-storage
   mount* below. This is the one thing that happens between the two halves of
   the switch, which is why `identity::enter_workload_namespace` and
   `identity::assume_workload_identity` are separate calls.
6. It `setresuid`s to the workload uid and shapes its capabilities: it keeps
   exactly `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` and `CAP_FOWNER` in the
   permitted, effective, inheritable and **ambient** sets (so they survive
   `execve`), drops every other capability from the bounding set, and sets a
   `0o002` umask so files it creates stay group-writable by the supervisor.
7. It reads `/proc/self/status` back and refuses unless the uid, gid and every
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
| Fail-closed, per plan. A plan that asks is refused by the entry helper — before the workload exists — when any prerequisite is missing, with a typed reason. A document asks by requiring the `uid_separation` feature, and the feature negotiation refuses it on a host that does not offer it, before any plan is built. `uid_separation` is in the daemon's `ENFORCED_PROPERTIES`, so a host that cannot demonstrate the switch measures as `SandboxUnavailableLaneWired` and offers nothing, rather than quietly running workloads under the supervisor's uid. | `automonique_runner::admission`, `automonique_runner::launch`, `automonique_daemon::execute::ENFORCED_PROPERTIES` |

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

## The document's request

There is no new specification field. A document asks for a separated identity
by **requiring the `uid_separation` feature** in `sandbox.required_features`,
which is the vocabulary a document already uses to name the kernel boundary
properties its launch must really enforce. Three consequences follow from
reusing it rather than inventing a field:

- **The negotiation is the gate.** `SandboxSpec::admit_on` compares required
  features against what the host offered, so a document that requires
  `uid_separation` on a host that cannot provide it is refused before a plan
  exists, with the refusal every other unmet feature gets. Nothing about the
  separation is admitted-and-degraded.
- **Nothing changes for a document that does not ask.** Admission maps the
  requirement onto `LaunchPlan::separate_workload_identity` and leaves every
  other plan exactly as it was.
- **The wire is unchanged.** No new field, no new canonical encoding, no new
  digest, and no cross-language regeneration for a request the negotiation can
  already carry.

`uid_separation` is offered when the capability probe says this host really
separates — the probe runs the launch helper in its throwaway probe mode, so it
is an exercise rather than a configuration read. Because the property is in
`ENFORCED_PROPERTIES`, the daemon's own host observation
(`execute::probe_host`) asks the helper too: a probe without the helper reports
the identity unavailable by design, and a daemon that measured itself that way
would report its whole lane unenforceable.

## Composing with the temporary-storage mount

The identity switch and the per-run FUSE temporary-storage mount (#140, #111)
used to be **mutually exclusive**, and the combination was a typed admission
refusal. The reason was the mount site. The tempfs was mounted by the
supervisor through the setuid `fusermount3`, so the FUSE connection's owning
user namespace (`fc->user_ns`) was the init user namespace, and on this kernel
(Ubuntu 6.8.0-124-generic) `fuse_permission` calls
`fuse_allow_current_process`, which refuses a process in a **child** user
namespace with `EACCES` regardless of uid or file mode — measured directly:
`stat`/`getattr` succeeded from the switched workload while every
`open`/`opendir`/`create`/`write` was refused; the refusal persisted when the
switched process kept the supervisor's own host uid, so it was the child user
namespace itself and not the uid change; and it persisted with the FUSE root
node owned by the workload's host uid at mode `0700` and with
`default_permissions` removed. `allow_other` was necessary but not sufficient,
and no mount option or ownership change on the *supervisor's* mount could lift
it.

**The mount now happens inside the workload's own namespaces.** Between
`enter_workload_namespace` and `assume_workload_identity` the launch helper is
namespace-root: uid 0 in a user namespace it created, holding a full capability
set inside it. There it `unshare(CLONE_NEWNS)`s, cuts propagation
(`mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`, without which the mount
would travel straight back to the supervisor's namespace), opens `/dev/fuse`,
and calls `mount(2)` directly. Three facts make that succeed, and each was a
distinct failure before it was understood:

1. **The `/dev/fuse` descriptor must be opened in the namespace.** The kernel
   requires the opener's user namespace to be the mounter's
   (`file->f_cred->user_ns == sb->s_user_ns`); a descriptor the supervisor
   opened gives `EINVAL` at mount, however it travels.
2. **`user_id`/`group_id` name the mounter, not the workload.** They are read
   in the mount's own user namespace and must be the mounting process's ids
   there — namespace-root's `0`/`0`.
3. **The server's node uid and gid are read in the mount's user namespace.**
   The filesystem's root node must be owned by the workload's *namespace* uid —
   the supervisor's uid number, which the identity map re-uses inside the
   namespace — and not by its host uid. This was the last `EACCES`.

`allow_other` is still required, because the workload is not the mounter: with
it, `fuse_allow_current_process` admits any process inside the mount's user
namespace, and the kernel's `default_permissions` check against the node
ownership above is what actually bounds access.

### Who serves the filesystem, and why

**The supervisor**, over a descriptor the helper passes back with `SCM_RIGHTS`
on the launch's own plan channel. The alternative — serving it from a thread in
the helper before `exec` — cannot work and would not be wanted:

- `execve` destroys every thread but the calling one, so a server thread
  started in the helper would die at the exact instant the workload begins.
- The helper must still be **single-threaded** when it installs Landlock and
  seccomp (`filesystem::require_single_threaded`), which is what keeps a
  sibling thread from escaping either domain.
- Forking a server *process* instead would place the filesystem that accounts
  for the run inside the run's own cgroup — so the workload's memory pressure
  could kill its own accountant — and would give the supervisor a second child
  to reap.

Passing the descriptor keeps the ledger, the checkpoint, the exceedance channel
and the reconcile exactly where #111 already had them, and changes only where
the `mount(2)` happens. Linux credentials are per-thread, which is the property
that makes the whole arrangement possible in the first place.

### The rendezvous

Four steps, each of which can refuse; a refusal on either side closes the socket
and refuses the launch on the other. The plan channel is a socket rather than a
pipe exactly when a mount is expected, and the helper closes it before the
launch verifies its descriptor table.

| Direction | Line |
| --- | --- |
| helper → supervisor | `mounted=<mountinfo>:<namespace uid>:<namespace gid>`, plus the `/dev/fuse` descriptor as ancillary data |
| supervisor → helper | `serving`, once the FUSE session is answering |
| helper → supervisor | `statfs=<statvfs readback>`, taken **after** the helper has become the workload |
| supervisor → helper | `go`, once the readback is exactly the admitted budget |

The supervisor refuses a report whose mount is not `fuse.automonique-tempfs` at
the admitted mountpoint, is not namespace-root's, or names an identity the
filesystem's nodes were not built for. The third step is the proof rather than a
formality: the readback is taken by the process that is about to `execve` the
workload, under the credentials it will run with, so it is the exact operation a
supervisor-mounted filesystem answers `EACCES` to. Both sides bound their reads,
so neither a wedged launch nor a wedged supervisor can hold the other; a launch
that does not complete the handover is killed and reaped before the call
returns.

### What the supervisor gives up, and what replaces it

The mount is private to the workload's mount namespace, so it appears in no
mount table the supervisor can read and there is no path here to `statvfs`.
Two things follow, and both are in `docs/operations/temporary-storage-budget.md`:
the reconcile's readback comes from the filesystem's **own** `statfs` — the same
call the kernel would have reached, computed from the ledger that nothing but
kernel-delivered FUSE requests moves — and there is nothing to unmount, because
the namespace dies with the run tree and takes the mount with it. The kernel
closing the connection is the evidence that it did; a connection still alive
after the deadline is aborted through `fusectl`, after which no writable scratch
space remains for whatever is still holding it.

The mount site is derived from the plan (`RunTempfs::provide`) rather than
chosen beside it, so a workload in a child user namespace cannot be handed a
supervisor-mounted scratch tree it would read `EACCES` from. That used to be the
typed admission refusal `WorkloadIdentityTemporaryStorageConflict`; it is now
unrepresentable, and the refusal is gone. A plan that keeps the supervisor's
identity still gets the supervisor's own mount, through `fusermount3`, exactly
as #140 built it.

Admission still fails closed where the host cannot provide the mount: the
context carries `TemporaryStorageEnforcement`, and a host whose `/dev/fuse` this
uid cannot open, or whose `fusermount3` is not setuid root, refuses every
document with a temporary-storage budget rather than admitting one without it.
The gate is deliberately the same for both mount sites even though the
in-namespace one needs no `fusermount3`: one verified prerequisite, checked
before every admission, is what the fail-closed answer is built on.
