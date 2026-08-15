# M8 — Scheduler, reload & isolation depth (implementation plan)

Completes the durable spine: the scheduler core, generation handoff/reload (the
founding requirement), and the deep isolation and fencing work from the
verified-on-host durable-execution survey (SOTA §6). Grounded at `c2f8b16`;
respects the three standing constraints (no async runtime, `forbid(unsafe_code)`,
11 exact-pinned deps — deviations are flagged as owner decisions). Covers issues
#45–#53.

**Two headline discoveries.** #49 is ~70% already built (durable custody,
dispatcher, and daemon composition exist; only the in-memory default, two
answer-fidelity gaps, and prune wiring remain). The Landlock thread-safety half
of #53 is largely done (the fs policy already refuses multi-threaded callers).
The heavyweights are #46 (reload) and #45 (scheduler); #50/#51 are the substrate
both need and should land first.

## Recommended order
1. **#50 + #51 together** — they share one lease-schema migration (boot identity
   + boottime deadlines). Foundation for everything else.
2. **#48** (sealed exec) — small, self-contained.
3. **#49** (cancel-ledger completion) — small.
4. **#47a** (cpu.max + rlimits, unprivileged), then **#47b** (uid separation,
   owner-gated).
5. **#53a** (broker hardening tests + seccomp + Landlock assertions), then
   **#53b** (sentinel relay).
6. **#52** (journal v2 + replay).
7. **#45** (scheduler — after M2 item 10 spec and M3 #17 wire decision).
8. **#46** (reload, split across three PRs) — the keystone that M4 #28 and M7
   #54 defer to.

## Owner decisions needed before/during M8
1. **#47 uid separation** — pick one of three routes (host re-probed today,
   kernel 6.8.0-124: unprivileged userns is **not** outright blocked, it is
   gated behind AppArmor — a plain `CLONE_NEWUSER` succeeds but `uid_map`/
   `setgroups` are denied under `apparmor_restrict_unprivileged_userns=1`, and
   `bwrap` — not setuid, no file caps — works purely because Ubuntu ships it an
   AppArmor profile granting `userns create`):
   (i) **AppArmor profile for the entry helper** (recommended, cheapest) — a
   root-installed profile file at deploy time, analogous to
   `bwrap-userns-restrict`, granting `userns create`, then
   `CLONE_NEWUSER|NEWPID|NEWNS` + fresh `/proc` inside the existing unsafe-free
   helper; lands naturally with M7 #44's units. Closes the direction F-10 names
   (the workload can no longer reach the supervisor's `/proc/<pid>/environ` or
   fd 0). Does **not** change the workload's host-side uid, so it does not stop a
   supervisor-uid observer from reading the *workload's* environ.
   (ii) **privileged `automonique-sandbox-launcher`** (`cap_setuid,cap_setgid`
   over full setuid) + a dedicated workload uid/group — strictly stronger (a
   genuinely distinct host-side uid, closing both directions) and strictly more
   expensive; anticipated by `requirements/target-architecture.md:145,332` and
   `sandbox-management.md:83,145` (closed schema: policy digest, UID, prepared
   fds, resource values — never argv/paths/shell).
   (iii) delegate to `bwrap` (works today) — but bwrap's argv becomes a second
   policy surface. `newuidmap`/`newgidmap` are not installed, so the
   shadow-utils route is closed.
2. **Dependency policy:** widen the nix pin's features to add `time`
   (CLOCK_BOOTTIME, timerfd) — feature widening of an existing exact-pinned dep,
   not a new dep. Plus a shared decision with M5 #29: `proptest` (dev-dependency
   only, exact-pinned) — #45 wants property tests and M5 wants the same dep.
3. **#45:** cron timezone scope for v1 — recommend Once/Every/UTC-cron computed
   exactly, non-UTC cron **refused** at registration with a typed error
   (refusal-first); a bounded TZif reader as follow-up.
4. **#53:** the egress-broker crate acquires outbound TLS (ureq, already a
   workspace dep) for the sentinel relay — the exact change its own docs say
   "would announce itself". Also verify the pinned provider CLI honors a loopback
   `http://` base-URL override.
5. **#46:** adopt-vs-drain for live attempts across reload — recommend **adopt**
   (acceptance requires a live run continuing), with the honest cost that an
   adopted process's exit *status* is unobservable by a non-parent; terminal
   classification falls back to answer-artifact + spool + cgroup-emptiness
   evidence.

### Issue #50 — Fence writes, not just work
**Current state.** The store is clock-free (callers pass `now_ms`). Most
mutations verify the generation lease inside the same `BEGIN IMMEDIATE` txn via
`require_live_lease` (`automonique-store/src/lib.rs:4552`; 9 call sites) — under
single-connection immediate transactions that is equivalent to a write predicate.
Gaps: (a) row-level epoch binding is missing from some statements even where
authority was checked — e.g. `DELETE FROM work_locks WHERE run_id = ?1`
(`lib.rs:2737, 2951`) and `UPDATE runs … WHERE run_id = ?1` (`lib.rs:2673, 2876`)
carry no `AND lease_epoch = ?`; (b) nothing prevents a second daemon from opening
the same stores; (c) no boot identity on lease rows.

**Approach.** (1) Mechanical rule + audit: every UPDATE/DELETE touching a
lease-bearing row carries `AND lease_epoch = ?` (and holder/generation where
applicable) in the statement itself — belt-and-braces even where
`require_live_lease` ran, so a future refactor can't silently unfence it.
Introduce a small constructor for lease-scoped statements so the predicate can't
be forgotten; classify each sibling-store mutation (automation/journal/run-index/
audit are mostly lease-free registries — document which are deliberately so).
(2) `flock` control lock: `ControlLock::acquire(state_root/daemon.lock)` via
`nix::fcntl::Flock` (feature already enabled), exclusive non-blocking, post-
acquire dev/inode equality check, never on DB/WAL files. `Daemon::open` acquires
before opening any store; typed refusal. Reload interplay: the lock means "may
mutate as the active generation" — N releases it immediately after #46's transfer
txn commits; N+1 acquires before activating transports. SIGKILL releases it
instantly (no stale-lock recovery code, per SOTA). (3) Boot identity: migration
adds `boot_id`, `holder_pid`, `holder_starttime` to lease rows. Startup sweep
(after flock, before any worker): boot_id mismatch → expire exactly; same-boot →
verify `(pid, starttime)` from `/proc/<pid>/stat`; alive holders never touched.
Per SOTA, this migration expires all outstanding leases.

**Testing.** SIGSTOP'd zombie holder's post-expiry write rejected by the
predicate (store-level with controlled clock + process-level under the systemd-run
harness); second daemon refused while first lives (two-process flock test); sweep
never kills a live holder (incl. recycled-pid case).

**Effort.** M. **Dependencies.** none — foundation for #45/#46/#51.

### Issue #51 — Boot- and suspend-aware lease time
**Current state.** Daemon lease deadlines use wall-clock `unix_millis()`
(SystemTime); renewal cadence uses `Instant` (`daemon/src/lib.rs:1040,1078,1090`).
The store compares caller-supplied ms — so the store change is schema + validation
and the daemon supplies the readings.

**Approach.** nix `time` feature (owner decision 2). A new module owns the
lease-time vocabulary: CLOCK_BOOTTIME ms + boot_id pair; lease columns gain
`deadline_boottime_ms` (same migration as #50). Comparisons only ever happen
same-boot (cross-boot rows are dead by the #50 sweep), which is what makes
boottime deadlines always comparable. Suspend self-fence: sample
`CLOCK_BOOTTIME − CLOCK_MONOTONIC` at open; re-check each serve-loop iteration
(the loop already polls at 25 ms); a delta jump ⇒ the holder treats all held
leases as lost, stops work, re-acquires through the normal path, closes the tenure
`expired` (the honest self-claim). `timerfd(CLOCK_BOOTTIME)` only if/when the loop
moves to `poll(2)` — the re-check suffices now. Ban `Instant`/`SystemTime` from
lease/fencing paths: concentrate deadline arithmetic in the new module + a
tools/CI source check in the repo's self-checking style; wall-clock stays for
display/audit timestamps.

**Testing.** Clock-delta injection via a trait seam → self-fence, never silent
continuation; deadline arithmetic unit tests with zero wall-clock inputs.

**Effort.** M. **Dependencies.** shares the #50 migration.

### Issue #49 — Wire the durable cancellation ledger (mostly done)
**Current state.** `CancelLedger` (store) is complete; `StoreCancelCustody`
(`automonique-daemon/src/cancel_custody.rs`), `CancelDispatcher`/`ControlSeat`
(runner dispatch), and `DaemonAttemptHost` (`attempt_host.rs:215`, one dispatcher
over one ledger file) all exist and are wired into the execute lane (`execute.rs`
registers each attempt with a sink over its `CancellationToken`). Replay-across-
rebind is already tested (`daemon/tests/cancel_custody.rs`). Sharper still: no
`ControlServer::bind` exists in non-test source (grep returns only doc comments)
— the durable endpoint is fully built and simply never opened, and the runner
still *defaults* to `InMemoryCancelCustody` (`control.rs:483`, installed at
`:763`) while `bind_with_custody` (`:766`) already takes the durable one. This
drops #49 from a subsystem swap to ~3–5 days and argues for pulling it early
(leaving the two custody stores split answers the same retry differently).

**Approach.** Delete `InMemoryCancelCustody`; `ControlServer::bind` requires
explicit custody (runner tests already have `ScriptedCustody`); update the
divergence notes at `control.rs:99-104`. Close the two divergences the module
names at `control.rs:137-143`: take the wire answer from the dispatcher's single
serialized call (a losing racer must answer `already_delivered`, not `delivered`);
richer `CancelSink` error so a conflict/full-ledger discovered inside the
serialized section answers `cancel_conflict`/`ledger_full` instead of collapsing
to `cancel_unavailable`. Wire `CancelLedger::prune` to attempt terminality
(daemon disposal or periodic) so production never hits `MAX_LEDGER_ENTRIES`.

**Testing.** keep the existing wire-format tests green (byte-identical replay);
add a full daemon-restart (not just server-rebind) replay test.

**Effort.** S. **Dependencies.** none; #46(c) reuses the one-dispatcher rule.

### Issue #48 — Close the exec TOCTOU
**Current state.** The helper `execve`s the path (`launch.rs:855`); the agents
crate prescribes the exact fix in its own docs (`spawn_plan.rs:29-44`).

**Approach.** `LaunchPlan` gains a required `program_sha256=` frame line; the
frame version bumps to `automonique.launch/v2`, no compat shim (supervisor and
helper are release-pinned together — state this in the module docs; every current
caller already computes the digest). The helper, between descriptor-closure
verification and Landlock (path access still available, `memfd_create` needs no
/proc): read the program bounded, hash (sha2), compare to the plan digest, stage
into a sealed memfd (reuse `sealed_prompt_descriptor`'s seal set),
`execveat(fd, "", argv, env, AT_EMPTY_PATH)` (`nix::unistd::execveat`, feature
already enabled). Refuse on any failure — no path-exec fallback. Honest residue
stated in docs: the ELF interpreter and libraries remain path-resolved under
Landlock grants (same class as the existing LD_PRELOAD note); the digest recorded
in the session binding is now the digest of the bytes that ran.

**Testing.** swap-the-binary test in both orders: swap before helper read →
refusal (mismatch); swap after read → original bytes still execute and the
recorded digest matches them. The hash-then-exec window is gone by construction.

**Effort.** S. **Dependencies.** none; composes with #47b's launcher.

### Issue #47 — Sandbox uid separation and resource-budget enforcement
**Current state.** `UnenforcedBudget` = {CgroupCpu, RlimitDescriptors,
TemporaryStorage, Artifact} (`admission.rs:235-248`); `ContainmentLimits` writes
only `pids.max`/`memory.max` (`containment.rs:161`); compose already declares cpu
4000 millicores / 1024 descriptors. Host re-probed today: `cpu` **is** a delegated
controller under `systemd-run --user --scope -p Delegate=yes` (writing
`cpu.max` in the work leaf succeeds), so #47a is real and small (~3 days).
Unprivileged user namespaces are gated behind AppArmor here, not blocked
outright (see owner decision 1) — so uid separation has three routes, not one.

**Approach — two halves.** **(a) Budgets, unprivileged, independent:**
`Controller::Cpu` + `with_cpu_max` writing `cpu.max` (delegation-checked like
pids/memory); the helper applies `RLIMIT_NOFILE` (and `RLIMIT_NPROC`, noting it's
per-uid so only meaningful after (b)) via `nix::sys::resource` between cgroup join
and closure; the frame gains `rlimit_*` lines. `CgroupCpu`/`RlimitDescriptors`
become enforced where the mechanism exists; the acknowledgement machinery keeps
covering hosts where it doesn't. TemporaryStorage/Artifact stay acknowledged.
**(b) `automonique-sandbox-launcher`** (owner-gated): a minimal single-threaded
privileged binary, closed input schema per `sandbox-management.md:145` — no
argv/paths/shell; it receives the target uid/gid (validated against a root-owned
config naming one dedicated workload uid) and prepared descriptors: the plan-frame
pipe, a pre-opened `cgroup.procs` fd (solves the cross-uid cgroup join — the
supervisor opens it, the helper writes its pid through the inherited fd), and the
pinned entry-helper as a sealed fd. It does `setgroups([]) → setresgid →
setresuid → readback verify → execveat(helper_fd)` — composing directly with #48.
Workspace/CODEX_HOME sharing via a dedicated group + setgid dirs. Threat closure:
with a distinct workload uid, supervisor-uid processes can no longer read the
workload's `/proc/<pid>/environ` or fd 0, and the workload cannot trace the
supervisor. Fail-closed: a new `BoundaryProperty::UidSeparation` in the capability
probe; absent launcher + absent userns ⇒ refusal unless the caller explicitly
acknowledges the unenforced boundary (mirror the UnenforcedBudget pattern).

**Testing.** containment suite (gated on
`AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT`): same-uid observer can no longer read
environ/fd0; `cpu.max` readback + throttled-count evidence from `cpu.stat`; NOFILE
ceiling proven inside the workload.

**Effort.** (a) M, (b) L. **Dependencies.** (b) composes with #48; owner
decision 1.

### Issue #53 — Identity-bound egress; Landlock TSYNC and seccomp deny-set hardening
**Current state.** The broker is a CONNECT tunnel, deliberately no TLS
termination — so header substitution is impossible on that lane and the design
needs a second, identity-bound lane. Already correct and mostly test-covered:
allowlist-before-resolve (`broker lib.rs:616`), resolve-once + scope-filter +
dial-only-in-scope (`630-655`), private/CGNAT/link-local rejection incl.
IPv4-mapped IPv6 (`allowlist.rs:76-147`), empty allowlist refuses everything. The
real credential today is a file *inside* the sandbox (session CODEX_HOME copy of
auth.json — `compose.rs:918`).

**Approach.** **Sentinel relay** (new module in the egress-broker crate; acquires
ureq/rustls for outbound — owner decision 4): a loopback HTTP listener; per-session
registration {sentinel (32 random bytes from /dev/urandom), real credential (held
daemon-side, never enters the sandbox), pinned upstream host:port, allowed path
prefixes}. A request must carry exactly the session's sentinel — foreign, absent,
or real-looking keys → 403 + counter; on match, substitute the real credential and
forward over TLS to the pinned upstream (pre-resolve + scope-check; SSE/streaming
pass-through with bounded buffering). The compose lane writes a *sentinel*
auth.json + base-URL override pointing at the relay; the CONNECT allowlist for
provider runs excludes the provider host, so the legit-domain-with-attacker-key
exfiltration path is closed on both lanes. **Broker hardening asserted by tests:**
empty-allowlist-most-restrictive, parse-then-match on malformed heads,
private-range rejection cases, resolve-once (inject a resolver seam). **Landlock:**
the fs policy already refuses multi-threaded callers (`filesystem.rs:209-214`);
mirror that guard in the TCP module if absent; add an explicit `Threads: 1`
assertion in the entry helper before enforcement; child-side enforcement assertion
in the containment suite (out-of-policy open → EACCES from inside the workload,
failing the suite closed under the gate). The host is ABI 4, so TSYNC is
unavailable here — single-thread-refusal is the enforced guarantee; wire the TSYNC
flag opportunistically only if the pinned landlock 0.4.7 exposes it. **Seccomp:**
extend the unconditional deny list (same pattern as `IO_URING_SYSCALLS`,
`seccomp.rs:205-213`) with `ptrace`, `process_vm_readv`, `process_vm_writev`;
recommend adding `pidfd_getfd` as a noted extra.

**Testing.** foreign-credential exfil attempt fails at both lanes;
empty-allowlist lock-in; child-side Landlock/seccomp assertions in the gated suite.

**Effort.** (a) M, (b) M. **Dependencies.** none; owner decision 4 for (b).

### Issue #52 — Journal restructure: step identity, command/notification split, offline replay
**Current state.** provider_journal v1 stores digests, never payloads; requests
have direction + request_key + pending/answered/failed but no step identity, no
version pins, no fork lineage, no replayable inputs.

**Approach.** Schema v2 (STRICT, ladder migration): turns gain write-once
`prompt_version`/`tool_schema_version`/`model_id` pins + `forked_from`; a new
`provider_steps` (turn_id, step_name, occurrence_index, kind ∈ {command,
notification}, correlation_key, input_digest, output_digest) with UNIQUE(turn,
name, index, kind) and a loud recorded-vs-expected mismatch error; a new
content-addressed `provider_blobs` (hard per-entry size cap; oversize stored
digest-only with an explicit `content_retained` flag — honest degradation);
requests gain `canonical_request_digest` (byte-identical crash-retry, exploits
provider prompt caching). Existing v1 turns migrate as `unpinned` and refuse
resume (fail-closed). API: `record_command`/`record_notification` (dispatched and
returned are two records, correlated); cross-version resume refused without an
explicit force flag. `replay(turn_id)`: an offline harness in the agents crate
driving the orchestration (normalize + step sequencing) against recorded
transcripts with a deterministic mock runner — zero process, zero network, zero
tokens; compares (step_name, occurrence_index, input_digest) sequences and names
the first mismatch. CI gate: a small recorded-turn corpus under the agents crate's
tests (neutral-named fixtures) + one negative fixture proving a deliberate step
reorder is caught. Coordinate fixture philosophy/anonymization with M2's
golden-trace work — different layer (parity vs orchestration self-consistency),
same tooling.

**Testing.** replay determinism over the corpus; step-mismatch names the first
divergence; cross-version resume refused; oversize-blob degradation flagged.

**Effort.** L. **Dependencies.** none; underpins offline replay used as a
regression tool across the program.

### Issue #45 — Scheduler core: bounded parallelism, per-scope serialization, pause/cancel
**Current state.** automonique-core is a Stage-A fixture-only tick
(renew→claim→fake-execute→atomic commit); the daemon drives it per loop iteration
under the generation fence (`tick_synthetic`, `daemon lib.rs:1266`). Substrate
ready: `work_locks(scope PRIMARY KEY)` = per-scope serialization; inbox
`UNIQUE(transport, transport_key)` = occurrence dedupe; outbox `available_ms` =
durable timer; the execution lane is bounded at `MAX_LIVE_ATTEMPTS = 8`;
`intake_pauses` exists. Gaps: the automation registry deliberately stores no
schedules; the protocol has `CanonicalSchedule` (Once/Every/Cron+tz+DST) with
render/parse round-trip and `OccurrenceKey::derive` but computes no occurrences,
and there is no tz data handling anywhere. **Fairness bug to fix here:**
`claim_next` (`store/src/lib.rs:2293-2420`) selects the single oldest row across
the whole transport (`ORDER BY i.received_ms, i.inbox_id LIMIT 1`, `:2319`) and
then returns `ScopeLocked` if *that* row's scope is locked (`:2369-2373`), so one
busy scope stalls every other scope's progress. Per-scope serialization exists;
per-scope *progress* does not. Fix: exclude **live**-locked scopes from the
candidate predicate while still stopping on **expired** locks (which must keep
returning `ReconciliationRequired` — skipping a live lock is fairness, skipping an
expired one would silently abandon prior work).

**Approach.** Occurrence computation: exact for Once/Every; five-field cron in UTC
exact; non-UTC cron **refused at registration** with a typed error in v1 (owner
decision 3), a TZif reader as follow-up. Durable schedules: a new scheduler-owned
`automation_schedules` table in the main store (automation_id, canonical rendering
+ digest, overlap policy, scope, next_fire_ms, last_fire_ms, revision), populated
by the daemon at registration (it holds both crates; the render/parse round-trip
guarantee answers the registry's stated objection to persisting schedules; the
registry keeps its spine-only doctrine). Firing path: a due schedule fires by
submitting an inbox row (transport `automation`, transport_key = occurrence key) —
the existing claim→work-lock→run pipeline provides per-scope serialization and
crash-exactly-once via the UNIQUE key, across restarts and generations for free.
Core generalization: extend the trait vocabulary (crate stays IO-free):
claim-due-under-fence, up to (parallel_bound − live) claims per tick; the executor
seam = the daemon execution lane (no async runtime; parallelism = the lane's
bounded worker threads). The synthetic lane keeps the fixture executor.
Pause/cancel: enablement read durably at fire time (registry); global pause via the
existing `intake_pauses` mechanism extended to the automation lane; cancel of a
fired occurrence rides #49's ledger→token path; a `Skip` overlap policy records a
durable skipped-occurrence evidence row.

**Testing.** property tests (shared proptest decision with M5): no two concurrent
runs per scope; pause is a barrier; cancel durable across restart; exactly-one-fire
per occurrence key under crash injection between claim and commit. Acceptance: the
M2-spec conformance suite; an Every-schedule automation fires exactly once across a
mid-window daemon restart under parallelism bounds.

**Effort.** L. **Dependencies.** M2 #13 (pause/cancel spec — the conformance
target), M3 #17 (wire decision; assumes "wire"); builds on #50/#51.

### Issue #46 — Generation handoff and reload: the founding requirement
**Current state.** Single-generation daemon (constant generation id, holder =
instance id, epoch-fenced); generation_audit's own divergence notes name exactly
what's missing: no reload epoch, no cross-generation primitive, `generations.state`
admits only `active`. The execute lane joins all attempt threads before releasing
the generation (`lib.rs:1124`) — no adoption exists; containment kills the tree on
drop; release-verification machinery exists (`release_activation.rs`) to reuse for
step 1. No CLI verbs. Scope note: `reload-protocol.md`'s warm-up list names many
subsystems that don't exist; the implementation covers the live surface (the 16
stores, the four connectors, the execution lane, the egress broker/relay, the
cancel dispatcher, the admin socket).

**Approach (three PRs).** **(a) Store substrate + transfer txn + read verbs:** a
`reload_epochs` table (state machine created→warming→quiescing→transferring→
activating→completed/failed/rolled_back); widen `generations.state`;
`transfer_generation_lease`: one immediate txn verifying N's live lease,
incrementing the epoch to N+1's holder, transferring the telegram poller lease,
recording the reload transition. Quiesce precedes transfer: N stops claiming,
in-flight outbox deliveries settle under a bounded deadline (anything unsettled at
deadline becomes ambiguity → the existing reconcile-only closure). CLI
`generations` + `reload-status` (read side). **(b) Handoff loop:** `reload
<release>` over the admin socket → N verifies the target via the existing
release-trust machinery, creates the reload epoch, spawns N+1 with a socketpair
handoff channel; N+1 candidate mode runs non-mutating warm-up (schema ranges across
all stores, integrity quick-check, config + provider-binary digest + connector
token presence, egress config); `warm` → quiesce → transfer txn → N releases the
#50 flock → N+1 acquires it, takes the admin socket via SCM_RIGHTS over the handoff
channel (zero-drop; M7 #54's socket activation would subsume this later), starts
transports (telegram poller handshake per protocol step 6), proves active
readiness (heartbeat, write/read probe, adoption inventory, offset ownership,
outbox drainer) → reload completed; N drains and exits `released`. Failure before
proof: transfer-back txn to N if alive, else operator/last-compatible-generation
path. `rollback` = same protocol, older target, schema-range compatibility gate
refused up front. Dispatcher ownership: N disposes its cancel dispatcher before the
transfer txn; N+1 opens its own over the same ledger file after — preserving #49's
one-dispatcher rule. **(c) Adoption** (owner decision 5): N records durable host
identity per live attempt (cgroup path, pid, starttime, spool dir), disarms
kill-on-drop via a new deliberate `RunContainment::release_for_adoption()` (Drop
still kills on every non-reload path), lets workers exit without reaping; N+1
adopts by cgroup (polls `cgroup.events` populated=0 — dependency-free) + spool
state; exit status is unobservable to a non-parent, so adopted terminals classify
from answer-artifact + spool + cgroup evidence, with an explicit
`adopted_exit_unobserved` class. Session-scoped provider hosts adopt the same way.

**Testing.** a failure-matrix suite, one test per the 12 rows of
`reload-protocol.md` (target-verify fail; warm-up fail; candidate crash
pre-transfer; N crash pre-transfer → normal crash recovery; transfer conflict;
post-transfer-pre-proof failure → return to N; Slack duplicate suppressed by the
inbox unique key; Telegram poll hang → deadline + offset intact; runner
unavailable during adoption → classify from backend record + spool; refuse-to-drain
→ N self-terminates on deadline once its leases are invalid; DB busy → bounded
retry, lease atomicity kept; schema-breaks-rollback → refused before spawn).

**Effort.** L (three PRs). **Dependencies.** #50 (fenced writes + flock transfer),
#51 (handoff deadlines in boottime), #49 (dispatcher ownership rule). M4 #28
consumes this afterwards.

## Cross-cutting notes
No new runtime deps anywhere (nix `time` is a feature widening; proptest is
dev-only and shared with M5 #29; ureq is already pinned for #53's relay). All
schema work rides the STRICT ladder discipline with migration-replay tests; every
refusal is typed. The privileged launcher (#47b) is the only unsafe-adjacent risk
point and stays `forbid(unsafe_code)` via nix wrappers. Containment-suite additions
all gate on `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT` so a host that cannot prove
enforcement fails loudly rather than reporting a vacuous green. No legacy or client
identifiers appear in any proposed code, fixture, or doc text. Ordering dependency
worth repeating: #50/#51 harden the lease substrate #45/#46 build on, and #52's
journal restructure underpins the offline replay used as a regression tool in M2
and M4.
