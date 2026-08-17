# Provider execution status

This page replaces an obsolete owner-decision brief. It records current product
state; it is not a gate or a development permission document.

## What exists

Automonique can run a pinned provider binary through its sandbox and brokered
egress path, behind an authenticated daemon lane. Telegram, Slack, GitHub, and
support connectors can also perform live effects when an operator explicitly
configures them. The repository status table in `README.md` is the concise
inventory of those surfaces.

These capabilities are available for ordinary repository development. Their
production use remains separately authorized.

## What remains incomplete

Release-signature verification is still fail-closed: the release trust-root
type cannot mint a successful signature proof because no cryptographic backend
or trusted key set is configured. Provider admission relies on pinned binary
digests and the workspace registry, not release signatures.

Generation handoff is also incomplete. Code activation restarts the service,
which can interrupt in-flight work; the target behavior remains the handoff in
[`requirements/reload-protocol.md`](requirements/reload-protocol.md).

## Authority

Building and testing these code paths is ordinary repository development.
Actually deploying, enabling a live provider or connector, supplying
credentials or trusted keys, publishing a release, or mutating production
requires explicit owner authority under `AGENTS.md`.
