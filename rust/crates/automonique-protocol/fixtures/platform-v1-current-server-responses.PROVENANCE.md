<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Platform v1 current-server response transcript provenance

`platform-v1-current-server-responses.json` was newly authored on 2026-08-28
inside this clean-room repository from only the Platform v1 contract and the
public current-server response constructors present at clean-room base
`c0089deedb6b90793b977578712165ccaa4fe7dc`. The five payload strings are
black-box observations of that current encoder for synthetic capabilities,
snapshot, sessions, receipt, and refusal values. The acceptance test makes the
observations immutable by requiring the current encoder to reproduce every
payload byte exactly.

No prior implementation source or tests, Git history, other worktree, pull
request branch, historical binary, production traffic, customer data, real
session, or real infrastructure identifier was used. All identifiers, times,
summaries, and explanations are visibly synthetic. These fixtures were not
extracted from a historical installed client and make no such claim.

The companion reference decoder is independently authored, v1-only, and does
not import Automonique protocol or wire types. This corpus is representative,
not exhaustive: it covers five response families and exact JSON bytes, but it
does not prove compatibility with an unavailable historical executable, every
valid v1 value, transport framing, authentication, deployment, or runtime
behavior outside response negotiation and decoding.
