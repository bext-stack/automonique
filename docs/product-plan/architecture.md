# Current target architecture

## Process topology

```text
operator or optional supervisor adapter
├─ automonique bootstrap        small installer/verifier and rollback root
├─ automonique lab --foreground durable development control plane
│  ├─ work DAG and evidence journal
│  ├─ lease, Git, build and credential brokers
│  ├─ author, reviewer, fixer and builder execution hosts
│  └─ stable/candidate comparison and merge reconciliation
├─ automonique daemon --foreground  product control-plane generation
├─ execution hosts              session- or attempt-scoped provider processes
└─ connector processes          separately credentialed SDK applications

optional adapters: systemd user units, launchd, containers, desktop/session launchers
```

Bootstrap, development and product state are separate SQLite databases with
separate runtime directories, sockets, credentials, leases, artifacts and
outboxes. A candidate receives neither stable credentials nor stable endpoint
names. Optional connectors cannot prevent the core from entering a safe mode.

## Durable spine

The canonical domain contains actors and tenants, accepted inputs, work graphs,
attempts, execution hosts, sessions, approvals, workspaces, artifacts, provider
records, domain events, action receipts, outbox effects, automations, budgets,
generations and candidates.

Every accepted transition appends a versioned domain event in the same
transaction. Every mutation has an idempotency key and expected revision.
Every external effect records intent before execution and reconciles remote
state before retrying an unknown outcome. Consumer, provider and transport
cursors remain distinct.

## Generation lifecycle

The portable baseline is foreground execution without self-daemonization.
Product upgrades use a supervisor-neutral generation handoff:

1. verify the immutable candidate source, build, signatures and compatibility;
2. start generation N+1 without stopping N;
3. prove readiness and recovery contracts;
4. transfer exclusive leases with fencing epochs;
5. let N drain while N+1 adopts durable work and surviving execution hosts;
6. retire N only after transfer evidence is durable;
7. return ownership to N automatically if readiness or transfer fails.

Active provider processes have explicit lifecycle ownership independent of the
control-plane generation and emit sequenced records. Generation replacement
cannot erase their session identity. A deployment adapter may map this contract
to cgroups or service units, but core correctness does not require one.

## Workspace and execution boundary

Mutating attempts run in disposable named worktrees at immutable bases. A
durable lease defines canonical allowed paths and rejects symlink/path escape.
Model and repository text are untrusted. The trusted adapter exposes typed
tools and fixed executable/argv recipes; there is no generic model-to-shell
string boundary.

Sandbox policy combines workspace scope, mount view, Landlock where available,
process/cgroup limits, credential audience and destination-aware network
policy. Effective enforcement is attested. Missing required enforcement fails
closed rather than silently degrading.

## Client and extension boundary

CLI, TUI, dashboard, desktop clients, SDKs, public agent protocols and channel
connectors consume generated contracts over authenticated local or remote
transports. They never read SQLite or provider sockets directly and cannot
invent a private approval or retry path.

The Rust domain schema is authoritative. SDKs and integrations are generated or
implemented under `sdk/` and `integrations/` and therefore use Apache-2.0;
product code remains Elastic-2.0.

## Recovery posture

Correctness wins over availability. Ambiguous effects block and reconcile.
Backups bind database, WAL-consistent metadata, artifacts, configuration,
credential recovery descriptors, release manifest and workspace metadata.
Restore occurs disconnected and proves cursors and idempotency before enabling
transports or outboxes.
