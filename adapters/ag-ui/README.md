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
receipt ledger, lease, or independent effect authority. The production
`ProductionPlatformAuthority` submits and confirms mutations through canonical
Platform v1, rebuilds translation state from the peer-authenticated native
progress cursor, and resolves follow-ups from native Platform sessions. The
adapter is separately supervised on loopback; Manage authenticates the browser,
selects the tenant-bound fleet node, and replaces browser credentials with the
private node token before forwarding.

Run the bounded checks with:

```sh
bun install --frozen-lockfile
npm run typecheck
npm test
```

The executable entry point is `src/main.ts`. It requires a private token file,
the canonical peer-authenticated Platform socket, and the daemon progress socket through
`AUTOMONIQUE_AG_UI_TOKEN_FILE`, `AUTOMONIQUE_PLATFORM_SOCKET`, and
`AUTOMONIQUE_PROGRESS_SOCKET`. `AUTOMONIQUE_NODE_ID` binds submissions to the
active daemon generation reported by its status surface. The token is reread for each request and is
never accepted in a query string or emitted in an error.
