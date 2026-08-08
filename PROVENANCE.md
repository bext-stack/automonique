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
specification. Its provenance manifest identifies eight
implementation-independent planning documents transferred byte-for-byte from
the private archive with the owner's authorization. Mixed migration and
implementation-dependent documents were not imported; current architecture
and self-development requirements were restated without legacy source.

Agents implementing the clean product must not receive legacy implementation
source. A parity oracle may execute privately against synthetic
inputs, but it must expose only bounded behavior results and must not emit
source, private data, credentials, proprietary identifiers, or implementation
text.

## Repository identity

The root commit is authored and committed by the dedicated Automonique
workload identity. Repository administration and legal approval are
external actions and do not become commit authorship.

The root commit ID, tree digest, signer identity, policy digest, and legal
approval receipt are recorded in an external immutable receipt.
