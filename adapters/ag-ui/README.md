<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Automonique AG-UI adapter

This directory contains the independently buildable AG-UI compatibility
adapter tracked by issue #103. The current slice is intentionally pure: it
pins the canonical `@ag-ui/core` contract and translates an authorized,
sanitized native event projection into schema-validated AG-UI events.

It is not yet a server and has no listener, database, credential, provider,
session-store, receipt, lease, or effect authority. The Automonique daemon and
Platform v1 remain authoritative. Supervision, health reporting, native SDK
transport, replay/backpressure, and Manage integration are later slices.

Run the bounded checks with:

```sh
bun install --frozen-lockfile
npm run typecheck
npm test
```
