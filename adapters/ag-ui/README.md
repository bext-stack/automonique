<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Automonique AG-UI adapter

This directory contains the independently buildable AG-UI compatibility
adapter tracked by issue #103. It pins the canonical `@ag-ui/core` contract,
translates authorized sanitized native events, and exposes an injectable,
loopback-only HTTP/SSE runtime with strict input, health, readiness,
capabilities, reconnect, cancellation, interrupt, and backpressure handling.
Reconnect IDs combine the retained native cursor with a per-projection offset,
so a disconnect within a multi-event AG-UI message cannot skip content.

The package has no database, credential store, provider, session store,
receipt ledger, lease, or independent effect authority. A release composition
must inject `PlatformRunAuthority`; that implementation owns authorization,
native cursors, receipts, interrupt validation, and cancellation. The
production daemon binding and Manage forwarding path are not in this slice, so
the package must not be deployed yet.

Run the bounded checks with:

```sh
bun install --frozen-lockfile
npm run typecheck
npm test
```
