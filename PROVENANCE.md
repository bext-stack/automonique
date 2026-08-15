# Provenance

## Clean-room boundary

This repository begins with one root commit and no parent. It imports no source
code, test code, build scripts, deployment files, binary assets, generated
artifacts, Git objects, branches, tags, pull requests, issue data, or commit
metadata from a prior repository.

Prior repositories and run evidence are retained privately as read-only
archives. They are not submodules, dependencies, vendored inputs, or alternate
history for this repository.
## Permitted implementation inputs

Future implementation may use only:

- requirements whose ownership and licence are recorded;
- independently written architecture and protocol specifications;
- public standards under terms compatible with their use;
- sanitized black-box input/output fixtures with recorded provenance; and
- third-party dependencies approved by the dependency and licence policies.

`docs/product-plan/` contains the public, bot-authored implementation
specification. Eight implementation-independent planning documents were
transferred byte-for-byte from the private archive with the owner's
authorization; a second authorized transfer brought the remaining 33 as a
sanitized corpus. The transfer scope and sanitization passes are recorded in
`docs/product-plan/README.md` § Plan transfer.

## Structural references

Migration and parity documents were imported as sanitized historical context
under `docs/product-plan/reference/`, including the porting map that names
prior source files and their Rust destinations.

This is an intentional narrowing of the boundary, not an oversight. The owner
holds the rights to the prior implementation, so the clean-room rule here is
engineering hygiene rather than a licence necessity. It forbids reproducing
prior *source* — text, control flow, algorithms, comments — while permitting
*structural* references: file and module names, directory shape, table and
column names, and command and environment names. `AGENTS.md` states the rule
agents must follow.

Agents implementing the clean product must not receive legacy implementation
source. A parity oracle may execute privately against synthetic inputs, but it
must expose only bounded behavior results and must not emit source, private
data, credentials, proprietary identifiers, or implementation text. The
enforcement mechanism for that boundary is built and measured — `tools/oracle/`,
under `BOOT-004` — but is not yet accepted: it is tracked as `GATE-ORACLE` in
`plan/gates.md`, which stays open on its fourth closing condition and states
what it blocks. That statement is the authority for the scope; this paragraph
does not restate it.

## Repository identity

The identity register below records the repository's candidate automation
identity and its historical exceptions. From the direct-development decision
of 2026-08-12 onward it is an optional audit rather than a work-admission or CI
gate. Codex-authored commits continue to use `Automonique Candidate`; human
commits may use the human's truthful configured identity.

**Declared state.** Identity separation: not claimed. Commit signing: not
enabled. Identities of record: `.github/identity/register.toml`.

The archived `.github/identity/check_identity.py` derives that line from the
register and refuses this document when the two disagree. It can still audit
the candidate-identity era; it no longer determines whether ordinary work may
start or land.

**Recorded candidate-bot state.** One identity, `Automonique Candidate`,
performed every role in `GOVERNANCE.md` § Roles, so no role was separated and
no commit was signed. Three commits predate that rule and are recorded as pinned
exceptions in the register rather than rewritten: the root commit and the
commit after it carry an owner bootstrap identity, and one later commit
inherited an ambient personal Git configuration.
`plan/owner-decisions/2026-08-10-candidate-identity-rewrite.md` records the
rewrite that brought the rest of that history to the candidate identity.

**Direct-development state.** Codex uses the candidate identity; humans may use
their truthful configured identity. Ordinary non-force pushes are permitted.
Repository administration, release, publication, credential, and production
operations remain separately authorized.

**Optional hardened state.** Dedicated workload identities may separate
candidate, review/build and integration activity when the operational value
justifies their cost. Repository administration and legal approval remain
external actions. The root commit ID, tree digest, signer identity when used,
policy digest and legal approval receipt belong in an external immutable
receipt.

Identity hardening is tracked as `GATE-IDENTITY` in `plan/gates.md`. It is
advisory and blocks only a claim that identity separation has been achieved; it
does not block implementation, review, local commits, harness trials or
owner-configured protected integration.
