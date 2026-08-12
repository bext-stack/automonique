# Automonique

Automonique is a durable, local-first agent control plane that accepts work,
executes it through multiple model and tool providers, preserves state across
failures and upgrades, and exposes the same authority through every client.

Linux-first and built primarily in Rust, it aims to make every state change and
external effect typed, revision-checked, journaled, and reconcilable.

## Repository status

Automonique is in early implementation. Product code currently lives mainly in
`rust/crates/automonique-protocol/` and `rust/crates/automonique-policy/`.
Large historical planning and development-harness surfaces remain in the tree,
but they are no longer prerequisites for product development.

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

## Clean-room and licensing

The prior implementation source is forbidden input. The checked-in
specification, authorized structural references, public standards, and
provenanced black-box fixtures are permitted; see `AGENTS.md` and
[`PROVENANCE.md`](PROVENANCE.md).

Product code is under Elastic-2.0. Code under `sdk/`, `integrations/`, and
`connectors/` is under Apache-2.0. See
[`LICENSE-POLICY.md`](LICENSE-POLICY.md).
