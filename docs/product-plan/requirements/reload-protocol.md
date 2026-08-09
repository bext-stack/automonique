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
