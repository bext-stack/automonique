# AG-UI adapter supervision

The AG-UI package exports `startSupervisedServer(authority, config)`. It is a
composition library, not a second daemon: a release host must inject the
Automonique `PlatformRunAuthority` implementation and the short-lived
Manage-to-node authorization verifier. The package has no fallback authority.

## Process boundary

Run the composed entry point as a dedicated non-login user on loopback and an
unprivileged port. The service manager should enforce at least:

- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`;
- `ProtectSystem=strict`, `ProtectHome=yes`, and an empty writable-path set;
- no supplementary groups and no access to daemon/provider credential stores;
- address-family restriction to the chosen loopback transport;
- a memory ceiling, process ceiling, startup deadline, and bounded restart
  policy;
- readiness through `/readyz`, not process existence or `/healthz` alone.

The authority implementation may receive a short-lived credential through a
supervisor-managed private file descriptor or credential file. Never place it
in argv, environment dumps, query strings, logs, SSE events, or readiness
output. The HTTP handler receives only a verifier callback and does not retain
the presented token.

## Release contents

An immutable release contains the adapter source bundle, `package.json`,
`bun.lock`, the exact Bun runtime pin, golden fixtures, and the composed
Platform authority entry point. Installation runs `bun install
--frozen-lockfile`; activation must not resolve packages from the network.

Before activation, require strict TypeScript checking, the complete adapter
test suite, lockfile reproduction, licence and scrub checks, and an isolated
readiness probe against the release's Platform binding. Rollback stops only the
adapter and restores the prior immutable link. It must not restart or mutate
the Automonique daemon, Manage jobs, Slack, or ShellDeck.

## Current delivery boundary

The repository now contains the supervised server, strict admission, SSE
ordering/backpressure behavior, and authority seam. It intentionally does not
contain the production daemon binding or Manage forwarding credential path.
Do not install or deploy this package until those two pieces are reviewed,
packaged, and tested together.
