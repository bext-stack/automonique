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
there is no provider execution success type. The Codex adapter cannot spawn or
probe a process. The Telegram poller now has a concrete synchronous HTTPS
client with WebPKI certificate verification, redirects and environment proxies
disabled, bounded response headers/body, and a request deadline inside the
lease margin. Telegram's required token-bearing URL exists only during that
request and is absent from public errors and Debug output; the dependency graph
statically disables Trace logging because the HTTP library exposes request
paths at that level. The concrete store adapter persists dispositions and the
offset atomically, but no token is loaded and the client is not wired into the
daemon. The observability crate derives bounded metrics from one timestamped
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
