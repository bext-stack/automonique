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
enforcement mechanism for that boundary is built and measured in
`tools/oracle/`.

## Repository identity

Codex uses the `Automonique Candidate` identity; humans use their truthful
configured identity. Commit signing and role-separated identities are optional
operator choices, not repository gates. Ordinary non-force pushes are permitted.
Repository administration, release, publication, credential, and production
operations remain separately authorized.
