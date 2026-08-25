# Reload protocol

## Preconditions

Reload is allowed while work is active. It is refused only when:

- the target release fails signature/checksum or ownership verification;
- protocol/schema ranges are incompatible for durable state, active execution hosts or currently attached clients/connectors;
- database integrity checks fail;
- another reload or migration is active;
- the candidate cannot decode every domain-event/action schema that overlapping generations may emit;
- there is insufficient disk/runtime capacity to start the new generation;
- the active generation cannot establish a safe handoff channel.

The command returns a reload ID immediately or streams progress with `--wait`. Every transition is written to the generation/reload audit tables.

## Normal sequence

### 1. Select and verify

`automonique reload <release>` (or the `legacyctl` compatibility alias) sends the immutable release path and expected manifest hash through the active generation's admin endpoint. An optional supervisor adapter may pre-open that endpoint. Generation N validates opened immutable files without loading credentials into the CLI.

### 2. Create reload epoch

N transactionally creates reload epoch E with source generation N and target N+1. Concurrent reload requests resolve to the same E or fail as already in progress.

### 3. Spawn candidate

N starts the target `automonique` daemon with:

- generation ID N+1;
- reload epoch E;
- database path;
- a one-time readiness/handoff channel and, when supplied by an optional adapter, accepted admin descriptors;
- an explicit foreground lifecycle descriptor identifying the expected parent/controller and shutdown deadline;
- release manifest path.

Secrets are read by N+1 from the same protected process environment or selected credential adapter, never sent over the handoff payload.

### 4. Candidate warm-up

N+1 performs non-mutating readiness first:

- manifest and binary self-check;
- database read compatibility and migration check;
- domain event/action schema decode compatibility and controller-lease fencing check;
- configuration validation;
- execution-host protocol compatibility and active host/run/session inventory;
- workspace registry/isolation and artifact-store read/write/integrity probes;
- active sandbox policy/attestation/cgroup/namespace inventory plus candidate support for every required profile and implementation digest;
- identity/policy compilation and SDK credential-revocation checks;
- agent backend availability plus provider binary/schema/capability compatibility;
- current/previous supported TypeScript SDK protocol and schema compatibility;
- attached Teams/Discord connector protocol ranges, plus non-mutating installation-manifest and credential/permission health diagnostics;
- context-manifest, memory, skill, agent-profile, toolset, extension and MCP schema compatibility for active sessions;
- automation schedule, goal wait/judge, inbound-trigger replay window and durable input-queue ownership checks;
- public protocol adapter ranges, desktop/client minimum versions and enabled connector capability snapshots;
- model catalog/routing revisions, media engine availability and executor capability/attestation compatibility for active allocations;
- dashboard asset validation;
- Slack auth/connectivity probe;
- Fleet and Support configuration validation without mutation.

N remains fully active during warm-up.

An attached connector whose negotiated range cannot overlap N+1 is a compatibility failure. Platform unavailability, an expired optional installation or a credential/permission health failure is reported as connector degradation and does not block the daemon handoff; the unhealthy connector remains unable to send/receive until repaired or disabled.

### 5. Quiesce intake claims

After N+1 reports `warm`, N changes to `quiescing`:

- stop claiming new inbox rows and fleet jobs;
- stop initiating reconciliation passes;
- finish persisting any event currently being ingested;
- allow active handlers to reach a durable boundary;
- keep consuming active execution-host events and draining outboxes.

This phase has a short deadline. A handler that cannot finish is returned to a replayable durable state rather than blocking forever.

### 6. Transfer exclusive leases

In one transaction:

- verify N still owns every lease at its recorded epoch;
- assign scheduler/settings/reconciler/spool leases to N+1 with incremented epochs;
- mark N `draining` and N+1 `active`;
- record the active generation pointer.

Telegram is transferred with an explicit poller handshake: N cancels/finishes its long poll, persists received updates, commits the offset, and releases the poll lease before N+1 begins polling.

### 7. Activate transports and adoption

N+1:

- starts claiming durable inbox rows;
- opens or activates its Slack Socket Mode connection;
- begins Telegram polling after lease ownership;
- adopts every active attempt- or session-scoped execution host by durable host identity and control socket;
- verifies each host's run/workspace/provider instance/session/turn binding and resumes from its normalized event cursor;
- resumes from each committed event sequence/offset;
- begins outbox and fleet work under the new lease epochs;
- resumes automation firings, goal evaluation, trigger ingestion and queued steering from their committed cursors under newly fenced leases;
- activates compatible public protocol, extension, MCP and optional connector workers without transferring their credentials through handoff;
- starts accepting dashboard, TUI and CLI mutations.
- accepts connector SDK reconnects from their last durable domain/action cursor; connectors reconcile pending remote replies before delivery resumes.

Slack overlap is acceptable because event IDs are durable and unique. Dashboard and TUI clients receive/retrieve the active generation ID and reconnect from their last durable event cursor if their connection belonged to N. A TUI reattaches each pane independently by durable run/session identity and revalidates controller leases rather than assuming control survived.

### 8. Prove active readiness

N+1 must demonstrate more than process liveness:

- lease heartbeat succeeds;
- a database write/read probe succeeds;
- execution-host adoption inventory matches active durable runs;
- execution-host lifetime/idle-TTL state, workspace leases and artifact references match durable state;
- sandbox policy/attestation digests, namespace/cgroup identities, resource boundaries and external-daemon enforcement evidence match the adopted hosts;
- provider-session bindings and approval waits match host state;
- Slack connection is established or in a bounded recoverable reconnect state;
- Telegram owns the correct durable offset;
- dashboard health identifies N+1;
- the operator snapshot/subscription API identifies N+1 and reconciles outstanding idempotency keys;
- attached connector clients can negotiate N+1 and resume their cursor without reinstalling a Teams/Discord app; unavailable optional connectors remain explicitly degraded;
- enabled public protocols, extensions, MCP servers, automations and trigger workers report compatible revisions and resume from durable receipts/cursors;
- active remote executor allocations and media/browser workers reconcile to their recorded capability and sandbox attestations;
- identity/authorization probes, controller-lease epochs and global domain-event/action journal writes succeed;
- outbox drainer is operational.

Only then is the durable active-generation pointer committed and readiness
returned on the handoff channel. An optional supervisor adapter may translate
that event into its native readiness notification.

### 9. Drain old generation

N may finish only work already beyond an external side-effect boundary. It cannot claim or schedule anything new. It flushes logs, releases nonexclusive resources, closes transports, marks itself `retired`, and exits.

### 10. Complete

N+1 marks reload E successful. Release retention keeps at least the previous compatible build and its database compatibility metadata.

## Failure behavior

| Failure point | Required behavior |
|---|---|
| Target verification | N stays active; target never starts |
| Candidate warm-up | N stays active; candidate exits; reload marked failed |
| Candidate crashes before lease transfer | N stays active |
| N crashes before transfer | normal crash recovery elects a live generation; candidate may acquire expired leases only after durable checks |
| Transactional lease transfer fails | N resumes; candidate remains non-owning and exits |
| N+1 fails after transfer but before active proof | leases return to N if alive; otherwise the lifecycle owner or operator starts the last compatible generation |
| Slack duplicates during overlap | durable event key suppresses duplicate business work |
| Telegram long poll hangs | cancel at deadline; offset remains at last durable update; N+1 retries from there |
| Runner unavailable during adoption | verify its execution-backend record and status file; mark lost only after both prove terminal/unreachable |
| Old generation refuses to drain | terminate N after all its leases are invalid and active effects are durable |
| Database becomes busy | bounded retry; never break lease atomicity; abort reload on deadline |
| New schema breaks rollback | reject migration/release before spawning target |

### Test coverage of the failure matrix

Two levels of proof exist. The orchestration level drives
`automonique_daemon::reload::execute_reload` with recording hooks and proves
the phase order, the pre-/post-transfer partition and the audit record
(`rust/crates/automonique-daemon/tests/reload_protocol.rs`). The process level
runs a real source daemon, a real candidate process spawned from an installed
release, and the product CLI, and injects one real external fault at a named
point of the handoff through the typed `reload-fault-injection` feature
(`automonique_daemon::reload_faults`, compiled only for the binary crate's
tests). The hook is unreachable from a shipping build: the feature is
activated only through the binary crate's dev-dependency edge, a daemon built
without it refuses to open while `AUTOMONIQUE_RELOAD_FAULT` is set
(`rust/crates/automonique-daemon/tests/reload_fault_refusal.rs`, compiled
only in such a build), and a build with it refuses a script outside the
closed grammar before anything durable exists
(`reload_failure_matrix.rs::a_malformed_fault_script_is_refused_before_the_daemon_opens`).
The positive proof that a live contained
attempt crosses the handoff — the successor's warm-up inventory counts exactly
that attempt, the successor refuses a second attempt for the run and forwards
its cancellation to the source's host, the run finishes exactly once under the
successor's epoch with one durable receipt, the source retires, and a
`rollback --wait` with a still-running attempt hands custody back — is
`rust/crates/automonique/tests/handoff_live_run.rs` (`PROVEN` only inside a
delegated cgroup scope; it prints `NOT PROVEN` elsewhere).

| Failure point | Orchestration-level test | Process-level test |
|---|---|---|
| Target verification | `reload_protocol.rs::target_verification_failure_never_creates_an_epoch` | `reload_failure_matrix.rs::an_unverifiable_target_is_refused_before_any_epoch_exists` — an uninstalled digest is refused `release_verification_failed`; `reload-status` answers `reload_not_found`; the lease row is unchanged |
| Candidate warm-up | `reload_protocol.rs::every_pre_transfer_failure_resumes_source_and_stops_candidate` (`candidate_warmup_failed`) | `reload_failure_matrix.rs::a_schema_the_candidate_cannot_read_is_refused_at_warm_up` — the candidate reports its own category over the channel and exits; N keeps serving and hands off later. The warm path itself: `candidate_handoff.rs::exact_release_candidate_proves_transfer_and_clean_lease_return` |
| Candidate crashes before lease transfer | same test (`candidate_spawn_failed`) | `reload_failure_matrix.rs::a_candidate_that_dies_before_transfer_leaves_the_source_active` — `SIGKILL` after warm; the transfer refuses `candidate_exited` before the lease names a dead process; holder, epoch and revision unchanged |
| N crashes before transfer | none — the orchestrator cannot model its own death | `reload_failure_matrix.rs::a_source_that_dies_before_transfer_is_succeeded_by_ordinary_startup` — `daemon --foreground` aborts after the candidate warmed; the candidate exits owning nothing; ordinary startup expires the dead owner under durable checks, takes the next epoch and closes the orphaned epoch as `source_generation_lost` |
| Transactional lease transfer fails | same test (`lease_transfer_failed`) | `reload_failure_matrix.rs::a_refused_lease_transfer_leaves_the_source_serving_and_the_candidate_gone` — a live poller lease under the source's authority makes the transfer transaction refuse `handoff_blocked`; nothing partial is written; N resumes and the candidate is gone. Store-level: `automonique-store/tests/store.rs::cooperative_transfer_refuses_live_transport_or_effect_ownership` |
| N+1 fails after transfer but before active proof | `reload_protocol.rs::every_post_transfer_failure_returns_authority_before_resuming_source`, `failed_lease_return_never_claims_that_the_source_resumed`, `failed_source_resume_never_records_a_clean_rollback` | `reload_failure_matrix.rs::a_candidate_that_dies_after_transfer_returns_authority_to_the_source` — `SIGKILL` after the lease moved; authority returns to the same live process two epochs on and the epoch is `rolled_back` |
| Slack duplicates during overlap | none at reload level | none at reload level: no Slack transport runs in a process test. The durable event key is proven at the store: `automonique-store/tests/slack_ingress.rs::a_fresh_disposition_is_recorded_exactly_once_and_survives_a_reopen`, `a_full_log_refuses_a_new_disposition_but_still_answers_a_replay` |
| Telegram long poll hangs | none at reload level | none at reload level: no live poll runs in a process test. The transfer refuses while a poll lease is live (the injection in the transactional-failure row above); the offset and lease fencing are proven at the store: `automonique-store/tests/store.rs::telegram_poller_lease_is_fenced_across_connections_restart_and_authority_epochs`, `telegram_poller_commit_is_atomic_exact_and_deadline_fenced`, `telegram_offset_regression_gap_and_unaccounted_advance_refuse` |
| Runner unavailable during adoption | none | partial: `reload_failure_matrix.rs::a_successor_forwards_cancellation_to_the_source_hosted_attempt_exactly_once` proves the successor adopts by route, delivers exactly once through the source's custody, and reports `no_live_attempt` only once the source's route is provably gone. The probe itself fails closed — `automonique-daemon/src/adopted_attempts_tests.rs` stands up one source route per failure class (timeout, mis-pinned answer, refusal, absent socket, refused socket, live endpoint) and proves that only the two connect failures spend the adopted inventory, while every other one refuses `execute` and `cancel` with `source_route_unavailable` and keeps it. Verification against an execution-backend record and a status file is not implemented: attempts are hosted in-process by the source until they finish, so there is no separate runner whose availability could be checked |
| Old generation refuses to drain | none | `reload_failure_matrix.rs::a_source_that_refuses_to_drain_does_not_hold_the_active_successor` — the source hangs in its drain after N+1 proved active; N+1 owns the lease and answers every operator surface; the source is terminated; N+1 keeps serving, closes the epoch as `source_generation_lost`, and shuts down cleanly. The `current` release link is read back unchanged before and after the termination: activation is the source's step after its drain, which it never reached, and the successor does not move the link on its behalf. **Scope of the proof:** "N+1 keeps serving after the source vanishes" is proven with the test process as the lifecycle owner, which terminates the source and nothing else. Under the shipped unit (`packaging/systemd/automonique.service`: `Type=notify-reload`, `NotifyAccess=main`, the default `KillMode=control-group`, and no `MAINPID=` handoff to the successor) systemd stops the whole unit when the main PID — the source — exits, successor included. That gap predates this work and is not closed by it |
| Database becomes busy | none | `reload_failure_matrix.rs::a_busy_database_aborts_the_transfer_within_its_bound_without_moving_the_lease` — another connection holds `BEGIN IMMEDIATE` across the transfer; the transfer fails on the store's busy deadline (`sqlite`) rather than waiting out the lock, the lease row's holder, epoch and revision are unchanged (the fields a transfer moves; the row's renewal timestamps keep advancing under the live source, so the whole row is not what is compared), and N resumes |
| New schema breaks rollback | none | `reload_failure_matrix.rs::a_schema_the_candidate_cannot_read_is_refused_at_warm_up` — proven at candidate warm-up, not before spawn: the release manifest declares no schema range, so the source has nothing to check before spawning and the candidate's read-only warm-up is the first point that can refuse. The *channel* schema is judged at the same point: `a_candidate_speaking_another_channel_schema_is_refused_at_warm_up` spawns a candidate whose warm-up identity carries the previous channel schema and proves the source refuses it `candidate_channel_schema_mismatch`, with the lease unchanged, and hands off to a compatible release afterwards |

Two properties of the reload identifier follow from these proofs and are
worth knowing at the operator surface: it is derived from the source epoch
and the target digest, so an exact retry after a failed attempt from the same
epoch is answered with the recorded outcome rather than started again (a new
target, or a source at a new epoch, starts a new one); and the successor keeps
its copy of the source's live-attempt inventory until the source's route is
*provably* gone — its socket removed, which the source does only after its
last hosted worker has finished, or refused, which means the source process
is — so `execute` on the successor refuses a second attempt for a
source-hosted run exactly as long as the source could still be running it. A
route that merely fails to answer (the two-second I/O timeout, a malformed or
mis-pinned reply, a refusal from the source's host) is not read as a
retirement: `execute` and `cancel` for such a run answer
`source_route_unavailable`, the inventory is kept, and the next request
probes again. `cancel` answers `no_live_attempt` only once the route is gone.

### Channel schema compatibility across this release

The private source-to-candidate channel is versioned
(`automonique.reload-candidate/v7` in this release; `v6` before the handoff
carried the source's attempt inventory). The two sides of a handoff must
speak the same version, and neither side negotiates:

- A running `v6` daemon cannot `reload` into a `v7` release. The `v6` source
  judges the `v7` candidate's warm-up identity under its own vocabulary and
  refuses `candidate_protocol` at warm-up; the source resumes and nothing
  durable moves.
- A `v7` daemon cannot `rollback` (or `reload`) to a `v6` release. The `v6`
  candidate's warm-up identity is refused `candidate_channel_schema_mismatch`
  at warm-up — its own category, distinct from the durable-schema refusal —
  and the source resumes. The candidate side refuses an authority or return
  message in another schema under the same category.

The first deployment of a `v7` release, and any rollback across the `v6`/`v7`
boundary, must therefore be restart-based: stop the unit, move the `current`
release link, start it. The zero-downtime `reload`/`rollback` verbs apply
within a channel version, and a version change is a restart-based deployment
by design rather than a negotiated one.

## Service-manager adoption

Under `Type=notify-reload` with `NotifyAccess=main`, the source is the
unit's main process. Once the candidate holds authority and before it starts
serving, the source sends `MAINPID=<candidate>`; the candidate's own
`READY=1` and `WATCHDOG=1` are then the unit's, and the source's exit is a
completed handoff rather than the unit stopping. The candidate is spawned
without `WATCHDOG_PID` (the manager set it to the source's pid) so it keeps
the `WATCHDOG_USEC` cadence from the start. A source that cannot deliver the
main-pid message refuses activation and the reload rolls back: without it the
manager kills the candidate at `TimeoutStopSec` and restarts the unit, which is
a delayed restart, not a reload.

## Crash recovery without a cooperative old generation

On ordinary startup or candidate takeover:

1. Open the database and validate integrity/schema range.
2. Register a new generation as `starting`.
3. Inspect active generation heartbeat and process liveness.
4. Acquire expired leases through epoch-incrementing CAS only.
5. Enumerate active execution-backend hosts and host/attempt manifests.
6. Reconcile durable `running` attempts, host lifetime state, workspace locks and provider sessions with host/provider evidence.
7. Adopt live hosts/runs; finalize terminal attempts; classify missing local sessions as resumable, hibernated, interrupted or reconciliation-required.
8. Requeue expired inbox claims and outbox sends.
9. Restore pending approvals without replacing their reviewed action revision.
10. Verify artifact references and replay-safe action receipts, then connect transports and become active.

Transport intake and outbox draining remain disabled in disconnected-recovery mode until a clean-host restore has verified database/event cursors, artifact manifests, workspace metadata, credential descriptors and remote action receipts.

Unlike the current boot behavior, persisted running work is not automatically converted to an error.

## Self-hosting candidate reload

Development self-hosting applies the same generation protocol inside a candidate namespace, with an additional stable observer:

1. Stable verifies the candidate source/build fingerprint, immutable release directory, candidate-only state and credential audience.
2. Candidate C0 persists self-development session context, provider turn, background build/test IDs, todos, findings, metrics and cursors.
3. Stable launches C1 on candidate-only sockets and cloned/synthetic data; C1 cannot acquire any stable or production lease.
4. C1 runs normal warm-readiness plus bootstrap-manifest, work-DAG, Git/build-broker, evidence-schema and candidate-authority checks.
5. C0 transfers candidate leases to C1, while stable records the transition from outside both generations.
6. Each client/session/build reconnects by durable candidate ID and inspects surviving background work before retrying a command.
7. C1 performs the bounded self-host fixture and reports evidence to stable through the development protocol.
8. On failed readiness, missing evidence, crash or timeout, stable restores the previous candidate generation or abandons the namespace without affecting stable development or production state.

A candidate's success report is not promotion authority. Stable observation,
the configured reproducibility checks and owner verification remain required
before `promotable`. The complete state machine is in [Self-hosting and bootstrap](self-hosting-and-bootstrap.md).

## Rollback

Rollback is exactly the same protocol with an older target release. It is permitted only when:

- the old release manifest supports the current runner protocol;
- its schema read/write range includes the current database schema;
- no completed migration has crossed a declared compatibility barrier.

If compatibility is unavailable, Automonique reports that rollback requires an offline migration rather than pretending the operation is safe.

## Operator surface

```text
automonique reload [release] [--wait]
automonique rollback [--wait]
automonique generations
automonique reload-status <reload-id>
automonique doctor --reload
automonique runs
automonique attach <run-id>
automonique tui
automonique tui [--attach <run-or-session-id>] [--workspace <name>]
```

The legacy `legacyctl` and `legacy-tui` commands forward to the same socket and implementation during the compatibility window. `automonique doctor --reload` runs all non-mutating compatibility/readiness checks without starting a candidate, including the published TypeScript SDK compatibility range and schema digest.
