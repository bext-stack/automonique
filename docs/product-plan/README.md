# Automonique product plan

This directory is the authoritative product specification available to
Automonique's autonomous development control plane. The public repository does
not fetch or mount the private planning archive at runtime.

## Decision precedence

When documents disagree, use this order and stop on an unresolved conflict:

1. repository licensing, governance, security, provenance and agent policy;
2. `.automonique/bootstrap/` and `policy/bootstrap*.toml`;
3. this file, `architecture.md` and the checked work
   DAG;
4. product requirements and the capability ledger in `requirements/`;
5. historical context in `reference/` and `crosswalk.md`.

No requirement can grant itself authority that a higher layer withholds.
`reference/` material describes the prior product and migration; it is
context, never a source of new product requirements, and cannot override any
higher layer.

## Plan transfer

The private planning archive contained both reusable product planning and
obsolete migration material. Eight implementation-independent requirement
documents were transferred byte-for-byte and are identified by source hashes in
`provenance.toml`. Favre Benjamin, as owner of the source material, authorized
their use as Automonique planning inputs under this repository's licence
policy.

A second owner-authorized transfer on 2026-08-05 brought the remainder of the
planning corpus: 33 documents transferred as a sanitized corpus plus an
authored `crosswalk.md` mapping every work-DAG item to its spec documents.
Sanitization removed all former assistant/product names and private
identifiers (neutral `legacy*` compatibility terms replace them) and rewrote
the two primary GPL licence statements to the current licence boundary
(`LICENSE-POLICY.md`); historical GPL reference documents are marked
superseded. `reference/corpus-index.md` is the former planning-tree index and
carries the canonical-surface and licence notes.

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

Only a `ready` item in `work-dag.toml` may execute. The selected item receives
an immutable base, leased paths, licence class, budget, verification contract
and stop conditions. Completing an item may unlock its direct dependants after
evidence is recorded; it never makes the whole graph implicitly ready.

The first executable item is `BOOT-001`. Its contract is in
`../bootstrap/BOOT-001.md`.
