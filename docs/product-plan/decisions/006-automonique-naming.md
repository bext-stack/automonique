# ADR 006: Automonique naming and legacy compatibility

- **Status:** accepted
- **Decision date:** 2026-08-04

## Context

The pre-genesis assistant is being rebranded to Automonique while the Rust architecture, TypeScript SDK, TUI and new channel connectors are being designed. A rename-only migration would either break deployed clients and durable state or leave public artifacts permanently fragmented between two identities.

## Decision

- Automonique is the canonical product, repository, package, crate, binary and fresh-install identity. The assistant persona is Monique.
- The canonical upstream is `bext-stack/automonique`, code releases use the licence boundary established at genesis (product under `Elastic-2.0`; `sdk/` and `integrations/` under `Apache-2.0`, per the checked-in `LICENSE-POLICY.md`), the official product site is `https://automonique.fr`, and Inklura (`https://inklura.fr`) is acknowledged as founding sponsor.
- Sponsor metadata is non-authoritative and never grants repository, tenant, approval or runtime privileges.
- Existing pre-genesis assistant names, `legacy-*`, `LEGACY_*`, `legacy.*` protocol names, Slack commands, database tables and durable IDs are compatibility surfaces, not names to rewrite destructively.
- All new/internal Rust packages, crates, modules, features, binary targets, source directories, schemas, metrics/tracing targets, fixtures and release/container coordinates use Automonique names. Legacy names survive only in the enumerated compatibility manifest, never as a parallel public crate family.
- Canonical configuration wins; a simultaneous conflicting legacy value fails closed with a diagnostic.
- Legacy CLIs, SDK packages and commands forward to the same implementation and control socket. They may not launch a second daemon or maintain a divergent data store.
- Protocol and schema changes use ordinary version negotiation and expand/migrate/contract releases. Branding alone never changes a durable identifier.
- Public source moves through the audited new-upstream process in the [Automonique rebrand plan](../reference/rebrand/README.md); the private production repository remains a recovery source until cutover evidence is complete.
- A compatibility surface can be removed only after telemetry and a documented release prove zero supported consumers for the stated deprecation window.

## Consequences

New documentation and APIs use Automonique names, while implementation plans must explicitly label legacy names that remain. Every release tests canonical and legacy entry points against one authority. Repository publication, runtime cutover and connector rollout have coordinated compatibility gates but remain separately reversible decisions.
