# Automonique product plan

This directory describes the product Automonique is trying to build. It is a
design reference, not a development workflow or a source of repository
authority.

## Decision precedence

When documents disagree, use this order:

| Layer | Authority | Where |
|---|---|---|
| 1 | licensing, security, provenance, development safety | `LICENSE-POLICY.md`, `SECURITY.md`, `PROVENANCE.md`, `AGENTS.md` |
| 2 | product intent and target architecture | this file, `architecture.md` |
| 3 | product requirements and the capability ledger | `requirements/` |
| 4 | historical context | `reference/` |

No product requirement can grant authority withheld by the active policy.

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
The remaining `reference/` documents are sanitized technical context.

Any new private identifier entering this tree is a defect. The public scanner
helps detect regressions but cannot stand in for private-data review.

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

## Working with product documents

Start with the requested outcome, then read only the requirements relevant to
the code being changed. Roadmaps and reference material are optional context,
not a development checklist.

## Safety property specifications

**Amended 2026-08-15.** Four requirement documents join `requirements/`. They
are authored here rather than transferred: `reference/feature-parity.md`
reclassified nineteen rows `replace` on 2026-08-09 for want of any fixture, and
recorded that four of the nineteen are safety properties which must be
**deliberately re-specified, not inferred**. These are those four.

| Property | Document | Suite |
|---|---|---|
| Deployment notices fail closed to a dedicated route, never to ticket intake | [`requirements/deploy-notifications.md`](requirements/deploy-notifications.md) | `automonique_protocol::safety_conformance::deploy_route` |
| Every externally visible mutation is preceded by a durable announcement naming the exact target, with a stop-check window | [`requirements/mutation-announcement.md`](requirements/mutation-announcement.md) | `automonique_protocol::safety_conformance::mutation_announcement` |
| Deletion is a distinct approval class under a separately held credential | [`requirements/deletion-authority.md`](requirements/deletion-authority.md) | `automonique_protocol::safety_conformance::deletion_authority` |
| Bounded parallelism, per-scope serialization, pause and cancel | [`requirements/scheduler-core.md`](requirements/scheduler-core.md) | `automonique_core::scheduler_conformance` |

Each ships a conformance suite that is generic over a small trait and runs today
against an in-memory reference model, so the specification is executable before
the implementation exists. `scheduler-core.md` deliberately also serves as the
M8 scheduler specification, so those two are one document rather than two
answers.

Their exact semantics are **owner-confirmable** — `launch-roadmap.md` calls them
"four decisions that cannot be inferred". They are drafted rather than deferred
because an unspecified safety property is not a neutral gap: it is a behaviour
that gets decided by whoever writes the code first, with nobody reviewing the
decision. Each document marks the constants an owner is expected to weigh in on,
and changing one means changing a constant and re-running a suite.

Passing a suite proves that an implementation of its trait has the property. It
proves nothing about the daemon until something binds them, and
`automonique_protocol::safety_conformance::PENDING_BINDINGS` names the surface
each property is still waiting for.

## Reading order

| If you are… | Start at |
|---|---|
| implementing | the relevant file in `requirements/`, then current code and tests |
| reviewing an implementation | the requirement and the exact change |
| deciding whether a thing is in scope | Non-goals above, then `requirements/external-capability-ledger.md` |
| new to the project | `architecture.md`, then `requirements/goals-and-invariants.md` |
| implementing one of the four safety properties | Safety property specifications above, then its suite |
| tracing why something is designed this way | `reference/plan-review.md` |
