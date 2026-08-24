# AG-UI adapter supervision

The AG-UI package exports `startSupervisedServer(authority, config)` and ships a
production composition at `src/main.ts`. It is a separately supervised
projection, not a second execution daemon: canonical Platform v1 over the
peer-authenticated admin socket remains the mutation/receipt authority and
`progress.sock` remains the cursor authority.
The package has no fallback authority.

## Process boundary

Run the composed entry point under the same unprivileged user as the daemon so
Unix peer authentication admits `progress.sock`, on loopback and an
unprivileged port. The service manager should enforce at least:

- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`;
- `ProtectSystem=strict`, `ProtectHome=yes`, and an empty writable-path set;
- no supplementary groups and no access to provider credential stores;
- address-family restriction to the chosen loopback transport;
- a memory ceiling, process ceiling, startup deadline, and bounded restart
  policy;
- readiness through `/readyz`, not process existence or `/healthz` alone.

The HTTP boundary receives its scoped fleet credential through a
supervisor-managed private credential file; Platform itself uses Unix peer
authentication. Never place the credential
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

## Activation and rollback

Install the verified adapter directory under `%S/automonique/ag-ui-adapter`,
write `%S/automonique/ag-ui-adapter.conf` with mode `0600`, install the checked
unit, then enable `automonique-ag-ui-adapter.service`. `/healthz` proves only
the listener; `/readyz` proves the configured Platform authority is reachable.
Rollback atomically restores the previous adapter directory and restarts only
this service. It must not restart the daemon, Manage worker, dashboard, Slack,
or any active provider run.
