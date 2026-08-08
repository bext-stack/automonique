# Automonique

Automonique is a durable, local-first agent control plane that can accept work,
plan it, execute it through multiple model and tool providers, preserve state
across failures and upgrades, expose the same authority through every client,
and develop its own source within a sealed policy envelope.

## Repository status

This repository is the public planning home for Automonique: it contains the
product specification, architecture, autonomous development contract and the
checked work DAG under `docs/product-plan/`. It deliberately contains no
implementation source. The canonical repository is:

<https://github.com/bext-stack/automonique>

## Product plan

The authoritative product specification lives under `docs/product-plan/`:

- `docs/product-plan/README.md` — index, decision precedence and plan transfer
  notes;
- `docs/product-plan/architecture.md` — target architecture;
- `docs/product-plan/requirements/` — capability and non-functional
  requirements;
- `docs/product-plan/decisions/` — accepted design decisions (ADRs);
- `docs/product-plan/work-dag.toml` — the checked work DAG that drives
  implementation.

Work starts only from a `ready` item in `docs/product-plan/work-dag.toml`.
See `docs/product-plan/README.md` for the full product intent and non-goals.

## Licensing

- Product code is made available under the Elastic License 2.0.
- Official SDKs and integration libraries are licensed under Apache-2.0.
- Commercial, hosting, OEM, and partner rights are available only through a
  separate written agreement.
- Automonique names, logos, mascots, and brand assets are governed separately
  by the trademark policy.

See [LICENSE-POLICY.md](LICENSE-POLICY.md) for the exact directory boundary.
