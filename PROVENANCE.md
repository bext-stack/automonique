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
enforcement mechanism for that boundary is unbuilt; it is tracked as
`GATE-ORACLE` in `plan/gates.md` and blocks differential parity work.

## Repository identity

**Current state.** Every commit, including the root commit, is authored and
committed by the owner's personal Git identity, and no commit is signed.

**Bootstrap state.** Owner-supervised development permits truthful human or
local-automation commit identities while every push, protected integration and
release action remains external. This lets the implementation and its harness
be built before unattended integration credentials exist.

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
