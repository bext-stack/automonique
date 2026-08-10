# Automonique

Automonique is a durable, local-first agent control plane that can accept work,
plan it, execute it through multiple model and tool providers, preserve state
across failures and upgrades, expose the same authority through every client,
and develop its own source within a sealed policy envelope.

Linux-first, built primarily in Rust. Every state change and external effect is
typed, revision-checked, journaled and reconcilable.

## Repository status

**Early implementation. 11 of 375 items are done, 2 of them product.**

Most of the source in this tree is the development harness, not the product.
`rust/crates/automonique-lab/` and `tools/` build the machine that develops
Automonique; `rust/crates/automonique-protocol/` and `-policy/` are the only
product domain code so far. That imbalance is a known regression, recorded and
frozen by [`GATE-HARNESS`](plan/gates.md#gate-harness) — see
[`plan/ready.md`](plan/ready.md) § Focus ledger for the live split. The
canonical repository is <https://github.com/bext-stack/automonique>.

```text
plan/                    executable layer — what may be started, and when
├─ ready.md              selectable work right now, and the focus ledger
├─ gates.md              blocking conditions and their closing evidence
├─ work-graph.toml       375 items: deps, gates, track, licence, allowed paths
└─ contracts/            per-item objective, verification and stop conditions

docs/product-plan/       specification — what to build and why
├─ architecture.md       target architecture
├─ requirements/         18 capability and non-functional requirements
└─ reference/            6 historical documents: parity, migration, review

rust/crates/             product code (protocol, policy) and the frozen lab
tools/                   Python development harness — frozen, being retired

AGENTS.md                what an implementing agent may and may not do
GOVERNANCE.md            separated roles and autonomous integration rules
LICENSE-POLICY.md        Elastic-2.0 / Apache-2.0 directory boundary
PROVENANCE.md            clean-room boundary and repository identity
```

## Start here

| If you are… | Read |
|---|---|
| implementing | [`plan/ready.md`](plan/ready.md) → the item's contract |
| reviewing | the contract → [`docs/product-plan/requirements/`](docs/product-plan/requirements/) |
| new to the project | [`docs/product-plan/architecture.md`](docs/product-plan/architecture.md) |
| an agent | [`AGENTS.md`](AGENTS.md) first, without exception |
| starting the buildout | [`plan/kickoff.md`](plan/kickoff.md) — a paste-ready session prompt |

The current selectable work is generated in [`plan/ready.md`](plan/ready.md).
`BOOT-001` is complete; implementation may begin from any listed work unit and
its contract.

The system being replaced is inventoried at
[`docs/product-plan/reference/legacy-inventory.md`](docs/product-plan/reference/legacy-inventory.md):
schema, config, effect surface, routes, and which of its behavior is pinned by
a test. Read it before estimating anything.

## Plan integrity

The work graph is generated from the checked work breakdown and verified in
both directions — a ticket cannot vanish from the graph, and a graph node
cannot be invented:

```sh
python3 plan/generate.py    # rebuild plan/work-graph.toml
python3 plan/check.py       # verify integrity, rewrite plan/ready.md
```

`check.py` also enforces the licence boundary, rejects dependency cycles,
refuses any ready item that has no contract, and refuses a graph in which
harness work has escaped `GATE-HARNESS` into the ready set. It exits non-zero
on failure so CI can gate on it.

## Open gates

Three conditions currently block classes of work. Identity separation and
release-grade licence review remain advisory and do not block implementation. See
[`plan/gates.md`](plan/gates.md) for closing evidence.

| Gate | Blocks |
|---|---|
| `GATE-SCRUB` | making the repository public |
| `GATE-ORACLE` | differential parity and fixture capture |
| `GATE-HARNESS` | further self-host harness work (`R0-19`…`R0-40`) |

The path-aware SPDX check runs with the plan workflow. Dependency notices,
SBOMs, and distribution-specific licence review are deferred until the first
release artifact exists.

## Licensing

- Product code is made available under the Elastic License 2.0.
- Official SDKs and integration libraries are licensed under Apache-2.0.
- Commercial, hosting, OEM, and partner rights are available only through a
  separate written agreement.
- Automonique names, logos, mascots, and brand assets are governed separately
  by the trademark policy.

See [LICENSE-POLICY.md](LICENSE-POLICY.md) for the exact directory boundary.
