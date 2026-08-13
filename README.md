# Automonique

Automonique is a durable, local-first agent control plane that accepts work,
executes it through multiple model and tool providers, preserves state across
failures and upgrades, and exposes the same authority through every client.

Linux-first and built primarily in Rust, it aims to make every state change and
external effect typed, revision-checked, journaled, and reconcilable.

## Repository status

Automonique is in early implementation. Its first runnable control-plane slice
now includes a foreground daemon, peer-authenticated local administration,
durable SQLite state, a fenced FIFO scheduler, a deterministic no-effect
execution lane, a bounded process-runner foundation, and fail-closed sandbox
admission planning. It also has a strict Telegram update parser with atomic
durable dispositions/offsets, fail-only reconciliation over the authenticated
local admin endpoint, and a read-only Codex invocation normalizer. Provider
execution and transport networking are not connected yet. Delivery intents now
have durable FIFO leases, exact provider receipts, retry/dead-letter outcomes,
and explicit ambiguity reconciliation through redacted operator commands. A
side-effect-free Telegram polling orchestrator binds parsed batches to the real
SQLite store through a renewable per-bot lease, fenced deadline, and content
digest. A no-client lifecycle coordinator can acquire, renew, reconcile, and
release that lease without enabling HTTP, while the foreground daemon reports
Telegram as explicitly disabled. Store-derived operational snapshots classify
ready, delayed, live, ambiguous, delivered, and dead-lettered work without
inventing runtime health. The authenticated status command exposes those
measurements while keeping provider readiness, sandbox launch authority, and
Telegram offset lag explicitly unavailable until they are integrated. A
direct, TLS-verified Telegram `getUpdates` HTTPS client now exists behind the
poller interface, but the daemon still has no token/configuration loader and
does not start it. Large historical
planning and development-harness surfaces remain in the tree, but they are no
longer prerequisites for product development.

```text
docs/product-plan/       product goals, requirements, architecture, migration
rust/crates/             Rust product crates and tests
sdk/                     Apache-2.0 client SDKs
integrations/            Apache-2.0 integration libraries
connectors/              Apache-2.0 connector libraries
plan/                    optional roadmap and historical evidence
tools/                   development and optional historical harness tools

AGENTS.md                direct development and safety policy
GOVERNANCE.md            authority boundaries
LICENSE-POLICY.md        Elastic-2.0 / Apache-2.0 directory boundary
PROVENANCE.md            clean-room provenance
```

## Start developing

1. Read [`AGENTS.md`](AGENTS.md) and the relevant documents under
   [`docs/product-plan/`](docs/product-plan/).
2. Inspect the current implementation and tests for the area being changed.
3. Make a coherent change directly; use parallel agents when their write paths
   can be kept disjoint.
4. Run the affected tests, formatting, linting, development scrub, and source
   licence check.
5. Commit normally and non-force-push when requested.

No work claim, packet, lease, ready ID, per-item evidence file, or harness
completion transaction is required. The former workflow remains documented in
[`plan/README.md`](plan/README.md) for historical context and optional use.

Useful checks include:

```sh
python3 tools/check_licenses.py
python3 tools/scrub/scan.py
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo test --manifest-path rust/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --locked -- -D warnings
```

The runner's containment proofs need a delegated cgroup v2 subtree, which an
interactive login session does not have. Outside one they assert the fail-closed
refusal instead. To actually exercise the boundary, run them in a delegated
scope and require enforcement, so a host that cannot prove it fails loudly
rather than reporting a green but vacuous run:

```sh
systemd-run --user --scope -p Delegate=yes \
  --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
  cargo test --manifest-path rust/Cargo.toml -p automonique-runner --test containment
```

Choose checks relevant to the changed area. Product CI remains authoritative
for actual failures; the archived plan's self-consistency is not a product
gate.

## Run the local daemon

The current executable requires explicit private XDG runtime and state roots;
it does not fall back to a home directory. On a normal Linux user session these
variables are often already set. To launch it:

```sh
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:?set a private runtime directory}"
export XDG_STATE_HOME="${XDG_STATE_HOME:?set a private state directory}"
cargo run --manifest-path rust/Cargo.toml -p automonique -- daemon --foreground
```

From another terminal with the same environment:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- status
cargo run --manifest-path rust/Cargo.toml -p automonique -- status --json
printf '%s' 'local fixture' | cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  submit workspace:test fixture:1
cargo run --manifest-path rust/Cargo.toml -p automonique -- shutdown
```

If a prior daemon died after claiming synthetic work but before committing its
outcome, the successor stays online in `failed` state with intake closed. The
operator can inspect the durable record and submit an exact fail-only decision:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- reconcile inspect <run-id>
cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  reconcile fail <run-id> <generation-id> <epoch> <revision> <decision-key>
```

The decision never requeues ambiguous work. It atomically records a failed run,
failed inbox item, and fake reconciliation receipt; an exact retry replays the
same receipt.

Expired, outcome-ambiguous outbox effects can likewise be inspected without
revealing their payload or lease token. The CLI fetches and validates the exact
token over the authenticated local socket; only the receipt/reason is read as a
bounded line on stdin, keeping both values out of argv and process listings:

```sh
cargo run --manifest-path rust/Cargo.toml -p automonique -- outbox inspect <outbox-id>
printf '%s\n' '<receipt-or-reason>' | \
  cargo run --manifest-path rust/Cargo.toml -p automonique -- \
  outbox reconcile <delivered|dead-letter> <outbox-id> <generation-id> \
  <epoch> <attempt> <revision>
```

The daemon creates only `automonique/` children under those roots, refuses
permissive or foreign-owned paths, and exposes no network listener. The submit
command accepts only bounded local synthetic work, reads its task from stdin,
serializes it by scope, and atomically records one deterministic terminal plus
one pending `fake.receipt`. It cannot execute a process, call a provider, drain
the outbox, or send an external effect. `accepting_intake=true` refers only to
this local synthetic lane. The general runner remains fail-closed and sandbox
plans still grant no OS-enforcement or production-runner authority. A dedicated
descriptor-closure helper exercises a fixed inert Bubblewrap/BusyBox boundary,
but the product launch API still refuses with `missing_reviewed_helper_pin`;
there is no provider execution success type.

The runner now installs real, exercised kernel boundaries rather than only
observing that kernel interfaces exist. A run cgroup provides descendant-complete
containment on cgroup v2: placement is race-free because a self-migrating entry
helper confirms its own membership before it `execv`s the workload, ceilings are
applied before the cgroup can hold a process, `cgroup.kill` terminates the whole
subtree atomically, and disposal leaves no kernel residue. A test proves that a
`setsid` grandchild — which defeats process-group termination — is still reaped.
On top of that, the runner has verified descriptor closure (close everything
outside an explicit allowlist, then re-read `/proc/self/fd` to confirm), a
Landlock filesystem allowlist with distinct read / read-write / read-execute
grant intents that refuses partially enforced rulesets, and a Landlock ABI-4
TCP policy that denies `bind`/`connect` by default. The TCP policy is
deliberately not called network denial: UDP, raw sockets, `AF_UNIX`, and
already-connected inherited sockets remain outside Landlock's reach, the tests
record those gaps as executable fact, and closing them requires descriptor
closure (done) plus a future seccomp socket filter. A read-only capability
probe reports which of these mechanisms the host can actually enforce and a
mode selector refuses or degrades loudly, never silently.

A seccomp socket-family filter now closes the socket-creation side of that
gap: by default a sandboxed workload cannot create any socket at all, and a
plan may grant only a closed vocabulary of shapes (AF_UNIX stream/datagram,
AF_UNIX seqpacket, IPv4/IPv6 TCP streams). The filter masks the type flags so
`SOCK_CLOEXEC`/`SOCK_NONBLOCK` cannot slip past it, applies the same domain
discipline to `socketpair(2)`, denies the io_uring syscalls and the x32
syscall ABI, and refuses non-x86_64 builds rather than guessing. Its tests
record what remains honestly out of reach: descriptors inherited before
enforcement and `SCM_RIGHTS` passing over a granted unix socket.

A composed launch path ties the mechanisms together: a supervisor encodes a
bounded, typed `LaunchPlan` (program, argv, filesystem grants, TCP exceptions,
socket-shape grants — delivered over stdin, never argv), and a trusted entry
helper joins the run cgroup, confirms membership from the kernel, replaces
stdin with `/dev/null`, closes and verifies descriptors, installs both
Landlock domains and the socket filter, and only then `execve`s the workload
with an empty environment. A plan whose layers contradict each other — a TCP
port exception without the TCP socket grant — is refused rather than resolved
silently. An end-to-end test launches a real workload under all five
boundaries at once and reads the workload's own observations to prove each
held simultaneously, with the TCP probe denied by Landlock at `connect`
(EACCES) while the UDP probe dies earlier at `socket` (EPERM) — two distinct
errnos proving two distinct layers; a truncated plan refuses before anything
runs.

On top of the launch path sits the first execution backend: a supervised
direct-process run that records started/terminal lifecycle events in the
attempt's hash-chained spool, maps helper refusals distinctly from workload
failures, kills the whole tree on cancellation or deadline through the cgroup,
and never returns with the spool non-terminal or the cgroup left behind. A
runner control socket exposes each attempt over a private, versioned Unix
endpoint that authenticates kernel peer credentials before reading a single
request byte: bounded `inspect`, cursor-paged byte-exact `subscribe`,
read-only `heartbeat`, and durably idempotent `cancel` whose replay says
`already_delivered` and whose reuse across attempts conflicts. The store
crate gains a provider session journal persisting process, session, turn,
request, cursor, capability/schema, and approval bindings with revision-checked
transitions, transactional multi-row commits, and reads that surface
hand-written corruption as typed errors instead of trusting rows.

The launch frame now also carries an explicit environment allowlist and an
optional prompt: variables are validated by grammar and bounds and passed to
`execve` exactly as named (nothing inherited, nothing synthesized), and prompt
bytes are delivered as the workload's stdin through a sealed anonymous memfd —
no path ever names them, they cannot appear in argv, and without a prompt the
workload's stdin is still `/dev/null`. A supervised attempt now composes the
backend with the runner control socket: a peer can inspect and heartbeat a
live run over the authenticated endpoint and cancel it for real, with the
kill proven against a `setsid`-escaped descendant. The store crate adds a
durable host-wide cancellation ledger whose delivered/already-delivered/
conflict answers survive restart, ready to replace the control socket's
documented in-memory ledger when the daemon composition wires the two
together. Provider execution is planned but still cannot happen: the agents
crate builds exact sandboxed launch plans for a digest-pinned provider
executable and parses provider event streams incrementally, while refusing
the things it cannot yet deliver honestly rather than approximating them.
The daemon's status now reports a measured `execution_state`
(`sandbox_unavailable_no_lane` / `sandbox_enforceable_no_lane`): what the
host could enforce for a launcher, never a claim that any lane exists. The
admin status read surface and the doctor report schema are now generated
into the Apache-2.0 TypeScript SDK by a maintained generator with a drift
gate that fails when the checked-in files no longer match, a typecheck
against the package's strict tsconfig, and a test comparing the Rust
encoder's own field sets against the generated ones. A strict Slack Socket
Mode envelope parser with typed plan-then-ack acknowledgement discipline
joins the Telegram parser as the second network-free connector core.

Enforcement needs a delegated cgroup v2 subtree, which is what the daemon gets
as a systemd user service with `Delegate=yes`; where no delegated domain
exists every API refuses fail-closed and never reports partial enforcement.
These paths are exercised by tests only — the daemon does not yet call the
backend, no provider is wired to it, and provider launch authority still
requires the release-manifest trust chain that remains unbuilt.

The Codex adapter cannot spawn or probe a process. The Telegram poller now has a concrete synchronous HTTPS
client with WebPKI certificate verification, redirects and environment proxies
disabled, bounded response headers/body, and a request deadline inside the
lease margin. Telegram's required token-bearing URL exists only during that
request and is absent from public errors and Debug output; the dependency graph
statically disables Trace logging because the HTTP library exposes request
paths at that level. The concrete store adapter persists dispositions and the
offset atomically. The daemon now loads an explicit operator-written bot
configuration from a private `telegram/bot.conf` under its state directory —
header/terminator-framed, owner-only permissions required, the token validated
against its `bot_id` — and, when one is present, acquires, renews, and cleanly
releases the durable per-bot poller lease beneath its generation fence. An
absent configuration stays honestly `disabled_no_client`; a present-but-invalid
or insecure one refuses startup instead of degrading silently, and a live
predecessor's bot lease is fenced out by expiry, never seized. Whether that
lease is *used* is a second, explicit decision: without an `allow=` line naming
who may command the bot, the token is dropped, no client is constructed, and
the daemon reports `lease_owned_no_client` with the lease epoch. With one, the
token is retained in memory, one worker thread long-polls beneath the same
lease, and the status reports `polling_live` — a daemon holding a client never
reports a no-client state. That poller answers `/help`, `/status` and `/runs`
from the daemon's own read surfaces on its own store connections, refuses a
sender outside the allowlist without reading their message, and replies to
`/run`, `/cancel`, `/approve` and `/deny` that the surface behind them does not
exist yet rather than faking an effect. The observability crate derives bounded metrics from one timestamped
SQLite snapshot and serves them over the local authenticated status command,
but it has no metrics exporter. A release-manifest candidate can bind the
descriptor helper, boundary installer, fixture, workspace, and runner digests
for review, but cannot mint launch authority; an independently authenticated
release trust root is still missing. Those paths remain unavailable
until enforcement and production integration are implemented.

## Clean-room and licensing

The prior implementation source is forbidden input. The checked-in
specification, authorized structural references, public standards, and
provenanced black-box fixtures are permitted; see `AGENTS.md` and
[`PROVENANCE.md`](PROVENANCE.md).

Product code is under Elastic-2.0. Code under `sdk/`, `integrations/`, and
`connectors/` is under Apache-2.0. See
[`LICENSE-POLICY.md`](LICENSE-POLICY.md).
