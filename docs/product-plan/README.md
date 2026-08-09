# Automonique product plan

This directory is the authoritative product specification available to
Automonique's autonomous development control plane. The public repository does
not fetch or mount the private planning archive at runtime.

## Decision precedence

When documents disagree, use this order and stop on an unresolved conflict:

| Layer | Authority | Where |
|---|---|---|
| 1 | licensing, governance, security, provenance, agent policy | `LICENSE-POLICY.md`, `GOVERNANCE.md`, `SECURITY.md`, `PROVENANCE.md`, `AGENTS.md` |
| 2 | blocking gates | `plan/gates.md` |
| 3 | executable plan — order, authority, licence class | `plan/work-graph.toml`, `plan/contracts/` |
| 4 | product intent and target architecture | this file, `architecture.md` |
| 5 | product requirements and the capability ledger | `requirements/` |
| 6 | historical context | `reference/` |

No requirement can grant itself authority that a higher layer withholds. A
lower layer may refine a higher one; it may never widen it.

`reference/` material describes the prior product and migration. It is context,
never a source of new product requirements, and cannot override any higher
layer. Decisions in `reference/corpus-index.md` that later layers superseded are
listed in that file's own superseded-decisions table.

## Plan transfer

The private planning archive contained both reusable product planning and
obsolete migration material. Eight implementation-independent requirement
documents were transferred byte-for-byte from the source archive. Favre
Benjamin, as owner of the source material, authorized
their use as Automonique planning inputs under this repository's licence
policy.

A second owner-authorized transfer on 2026-08-05 brought the remainder of the
planning corpus: 33 documents transferred as a sanitized corpus.

Sanitization has been applied in two passes and its exact scope is recorded
rather than asserted in general terms:

| Pass | Date | What it replaced |
|---|---|---|
| 1 | 2026-08-05 | Former daemon/service/protocol names, replaced by neutral `legacy*` compatibility terms; the two primary GPL licence statements rewritten to `LICENSE-POLICY.md` |
| 2 | 2026-08-09 | Third-party and internal product names: client portal, site platform, deploy broker, fleet/provisioning service, and the deploy-channel environment variable |

What deliberately remains, and why:

- `Monique` — first-party mascot name, retained as product identity
  (`requirements/client-experience-and-surfaces.md`);
- `bext-stack` — the real repository organization, required by `SECURITY.md`
  for vulnerability reporting;
- legacy source filenames in `reference/migration-plan.md` — permitted
  structural references under the boundary in `PROVENANCE.md`;
- `legacy*` compatibility identifiers — dormant by design, not leaks.

Historical GPL reference documents are marked superseded.
`reference/corpus-index.md` is the former planning-tree index and carries the
canonical-surface and licence notes.

Any new private identifier entering this tree is a defect. `plan/gates.md`
records the pre-publication scrub gate that must pass before the repository
becomes public.

Documents tied to the former implementation were not copied as source. The
migration and parity documents now live under
`reference/` as sanitized historical context; their durable design
goals—recovery, exactly-once effects, generation handoff, isolated
workspaces, self-hosting and independent verification—are restated here
without importing implementation source. Legacy compatibility surfaces
(`legacy_*` tables, `legacy.*` protocols) are dormant: this clean-room
repository does not maintain the former daemon, and compatibility work
requires a separate owner decision.

This is a specification transfer, not a Git-history or implementation-source
import. Agents may use this directory; they must not access the private archive.

## Product intent

Automonique is a durable, local-first agent control plane that can accept work,
plan it, execute it through multiple model and tool providers, preserve state
across failures and upgrades, expose the same authority through every client,
and develop its own source within a sealed policy envelope.

The product is Linux-first and built primarily in Rust. Official SDKs and
out-of-process integrations live under their Apache-2.0 boundary. All state
changes and external effects are typed, revision-checked, journaled and
reconcilable.

## Non-goals

- importing or maintaining the former application;
- preserving obsolete names, database layouts or deployment behavior;
- allowing model output to become an unrestricted command line;
- giving candidates repository-administration, signing, secret-management or
  production-deployment authority;
- treating a green self-test as independent verification;
- adding product breadth before the durable autonomy and recovery spine works.

## How work starts

A ready work item receives an immutable base, leased paths, licence class,
budget, verification contract and stop conditions. Completing an item may
unlock its direct dependants after evidence is recorded; it never makes the
whole graph implicitly ready.

Selection happens in [`plan/`](../../plan/README.md), not here:

- [`plan/ready.md`](../../plan/ready.md) — what is selectable right now;
- [`plan/gates.md`](../../plan/gates.md) — what must be true first;
- [`plan/contracts/`](../../plan/contracts/) — what a specific item means.

The first executable item is
[`BOOT-001`](../../plan/contracts/BOOT-001.md) — make the executable plan
self-verifying. Everything else is blocked behind it, including every `R0`
discovery ticket, because until the graph is checked in CI a claimed
dependency set cannot be reviewed.

## Reading order

| If you are… | Start at |
|---|---|
| implementing | [`plan/ready.md`](../../plan/ready.md), then the contract |
| reviewing an implementation | the contract, then `requirements/` |
| deciding whether a thing is in scope | Non-goals above, then `requirements/external-capability-ledger.md` |
| new to the project | `architecture.md`, then `requirements/goals-and-invariants.md` |
| tracing why something is designed this way | `reference/plan-review.md` |
