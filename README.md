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
and explicit ambiguity reconciliation. A side-effect-free Telegram polling
orchestrator binds parsed batches to an atomic sink with a fenced deadline and
content digest, while a detached observability model provides closed,
content-free metric and event vocabularies. Large historical
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

The daemon creates only `automonique/` children under those roots, refuses
permissive or foreign-owned paths, and exposes no network listener. The submit
command accepts only bounded local synthetic work, reads its task from stdin,
serializes it by scope, and atomically records one deterministic terminal plus
one pending `fake.receipt`. It cannot execute a process, call a provider, drain
the outbox, or send an external effect. `accepting_intake=true` refers only to
this local synthetic lane. The general runner remains fail-closed and sandbox
plans still grant no OS-enforcement or production-runner authority. The Codex
adapter cannot spawn or probe a process, and the Telegram slice performs no
HTTP call. Its token reaches only an injected, trusted HTTP boundary through a
short-lived redacted view; no concrete network client or store adapter is wired
into the daemon. The observability crate is likewise a validated projection
model, not a live exporter or health authority. Those paths remain unavailable
until enforcement and production integration are implemented.

## Clean-room and licensing

The prior implementation source is forbidden input. The checked-in
specification, authorized structural references, public standards, and
provenanced black-box fixtures are permitted; see `AGENTS.md` and
[`PROVENANCE.md`](PROVENANCE.md).

Product code is under Elastic-2.0. Code under `sdk/`, `integrations/`, and
`connectors/` is under Apache-2.0. See
[`LICENSE-POLICY.md`](LICENSE-POLICY.md).
