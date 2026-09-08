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

- `NoNewPrivileges=yes` and `PrivateTmp=yes`;
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
test suite, lockfile reproduction, the licence check, and an isolated
readiness probe against the release's Platform binding. Rollback stops only the
adapter and restores the prior immutable link. It must not restart or mutate
the Automonique daemon, Manage jobs, Slack, or ShellDeck.

## Activation and rollback

Install the verified adapter directory under `%S/automonique/ag-ui-adapter`,
write `%S/automonique/ag-ui-adapter.conf` with mode `0600`, install the checked
unit, then enable `automonique-ag-ui-adapter.service`. `/healthz` proves only
the listener; `/readyz` proves the configured Platform authority is reachable
*and* that a fresh Automonique node is discoverable, which is the lookup every
`/agent` submission performs.

The adapter is not bound to one daemon generation. On every submission it
reads the Platform snapshot and targets the daemon's current `fresh` node, so
a daemon restart (new holder id) needs no adapter change; `AUTOMONIQUE_NODE_ID`
is optional and only states a preference among fresh nodes. A submission the
daemon refuses as `unknown_node` or `target_not_active_node` is re-resolved
and retried once.
Rollback atomically restores the previous adapter directory and restarts only
this service. It must not restart the daemon, Manage worker, dashboard, Slack,
or any active provider run.

## Diagnosing accepted runs that fail before output

A rejected terminal receipt with `run_failed` is an execution failure, not proof
of a policy denial. The adapter reports it as `automonique.internal_failure`;
only an explicit `policy_refused` receipt gets that classification. A provider
fault's retryability does not establish policy authority either.

Inspect the exact native run's progress and spool before changing permissions.
Two host prerequisites can leave `/readyz` green while real analysis fails:

- The separated workload identity must traverse the ancestors of the pinned
  provider binary and private provider home. A private account directory owned
  by a group outside the namespace's group mapping can deny traversal even
  with the intended namespace capabilities. Where necessary, grant only
  execute/traverse on that ancestor to the configured subordinate workload uid
  (the last uid of the account's first subordinate range), preserving its
  existing ACL. Do not make private credentials world-readable or disable
  identity separation/Landlock. Verify with the installed-provider test using
  production identity separation and namespaced temporary storage.
- The configured OAuth provider needs both inference and credential-refresh
  destinations. If native progress specifically reports a refused refresh
  destination, add that exact host and port to the owner-controlled egress
  policy. An OpenAI OAuth session may require `auth.openai.com 443 public`
  in addition to its inference hosts. The daemon loads this policy at startup;
  after a queues-empty restart, require a real authoritative assistant response
  and successful terminal event. Never infer execution from readiness alone.

The installed-provider integration test
`installed_jcode_negotiates_with_production_identity_and_tempfs_when_configured`
uses the same JCode test inputs as the existing handshake test and requires a
`Delegate=yes` scope plus the production launch helper. Its private runtime and
journal are disposable; it creates no model turn. Run both tests so the simpler
protocol check cannot conceal a failure in the production filesystem boundary.
