<!-- SPDX-License-Identifier: Elastic-2.0 -->

# systemd user service

Install the units in this directory under `~/.config/systemd/user/`, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now automonique.socket automonique.service
systemctl --user enable --now automonique-manage-worker.service
systemctl --user enable --now automonique-backup.timer
systemctl --user status automonique.service
```

The socket unit owns the private admin listener across daemon restarts. The
service adopts that one named descriptor, starts the directly installed daemon
binary from the product state directory, creates private XDG runtime/state
directories, delegates its cgroup subtree, and waits for the daemon's real
readiness notification. A supervised reload sends SIGHUP and waits while the
daemon atomically reloads `approvals/approvals.conf` without changing its PID;
a refused replacement leaves the active policy intact and is reported in the
unit status. Upgrade replaces that binary atomically and restarts the service
without unbinding the admin endpoint.
The timer writes an online recovery set every five minutes.
`automonique-recovery.service` is started manually after a restore; it disables
external transports and refuses provider starts.
`automonique-manage-worker.service` heartbeats the configured Manage instance,
claims confirmed jobs with bounded parallelism, and streams their progress back
to AI Operations. It also publishes an owner-only dashboard projection with a
bounded tail of parsed agent output and a link to the corresponding issue in
the configured Manage origin. Raw provider frames, stderr, prompts and fleet
credentials are not copied into that projection. The worker keeps its own
installed release path, independently of the directly installed daemon. The
worker maintains a private `manage-fleet-worker/auth-health.json` projection:
local credentials begin as `configured_unverified`, a successful provider turn
proves `authenticated`, and recognized sign-out or token-refresh failures become
`signed_out` or `expired`. Unhealthy authentication pauses new claims until the
private credential revision changes. The dashboard exposes only these closed
states, the sign-in method, safe evidence codes, and timestamps; it never returns
the credential, provider-reported account identity, provider home, or raw
provider output.

The hosted dashboard also owns a native subscription-account broker under
`%S/automonique/agent-auth`. Codex CLI accounts authenticate with ChatGPT in an
isolated `CODEX_HOME`; Claude Code accounts authenticate with Claude.ai in an
isolated `CLAUDE_CONFIG_DIR`. The browser receives only the provider's
short-lived authorization URL and, when required, one-time code. Reusable
credentials, provider-reported identity and raw CLI output remain in the private
server-side profile. Operator-defined aliases and opaque local account IDs are
safe dashboard metadata. Multiple accounts can coexist for each provider, but
the worker uses only the account selected explicitly by the operator and never
rotates across subscriptions automatically. The worker unsets API-key and raw
OAuth-token environment variables and accepts only native ChatGPT or Claude.ai
login status.

The optional hosted dashboard is deliberately separate from the daemon.
`automonique-web-entry.service` binds a small Rust operations console to
loopback; `automonique-web-tunnel.service` publishes it through an
operator-provisioned Cloudflare tunnel. The console reads a sanitized status
projection through the same peer-authenticated local protocol as the CLI. Its
Slack tool is strictly read-only. Configured MCP servers are discovered
independently, so Support and Manage can both ground the dashboard and chat
without one masking the other. A unique server sharing the validated
`manage/manage.conf` console origin is classified as Manage; read-only ticket
tools from other configured services remain separately sourced work queues.
Tools explicitly annotated as read-only can ground an answer immediately.
Every other tool becomes an in-chat action card showing
its proposed arguments and runs once only after the operator explicitly
approves it. When dashboard chat discovers that its attached context is
insufficient but the shared router can perform a deeper read or contained task,
it likewise returns a scoped approve/deny card to the requester. These cards
are included in the AI Operations pending-action projection. Safe configured
reads remain automatic; a genuinely missing integration or credential produces
a configuration instruction rather than an ineffective permission request.
Denial and expiry change nothing. The retired hostname redirects to the
canonical dashboard hostname.
Every dashboard resource and API response on the canonical hostname requires
HTTP Basic authentication over the Cloudflare TLS boundary. The strict private
credential file is `%S/automonique/dashboard-auth.conf`; it stores a username
and the SHA-256 digest of an operator-generated high-entropy secret, never the
secret itself. The loopback-only health check is the sole unauthenticated route.
`automonique-dashboard-auth` creates that verifier and a separate owner-only
recovery file without printing the credential. The recovery file is not read by
the service and should be moved into the operator's password manager, then
removed. `%S/automonique/dashboard-integration.conf` binds the dashboard to one
existing memory tenant and actor and names its canonical and retired public
hostnames. The hostnames are deployment configuration rather than repository
identifiers; the tenant and actor remain absent from every web configuration
response. Chat turns use the daemon's contained run lane and
the canonical memory database, rather than a dashboard-specific provider path.

Company Manager uses a separate server-to-server Manage chat API. It is not a
dashboard alias and cannot be authorized by dashboard Basic credentials or the
dashboard session cookie. Its four versioned JSON operations are
`POST /api/v1/manage-chat/history`, `POST /api/v1/manage-chat/turn`,
`POST /api/v1/manage-chat/new`, and `POST /api/v1/manage-chat/action`. The
browser never receives its bearer token: Company Manager authenticates its own
requester and calls these routes from its same-origin server. Automonique keeps
the configured Monique tenant and actor while deriving a distinct conversation
scope from the validated opaque Manage subject. Optional page context is a
bounded typed reference under `/manage/ai-operations`, explicitly untrusted and
never proof of resource state or authority. CORS and frame embedding remain
disabled.

Every request is `Content-Type: application/json` and carries
`Authorization: Bearer <token>`. Unknown JSON fields are refused. The request
and response contracts are:

```text
history request  {"subject":"<opaque>"}
new request      {"subject":"<opaque>"}
action request   {"subject":"<opaque>","action_id":"act-...","decision":"approve|deny"}
turn request     {"subject":"<opaque>","message":"...","profile":"conversation|operational","context":{"kind":"...","id":"...","path":"/manage/ai-operations..."}}

history/new response
  {"schema":"automonique.manage-chat.history/v1","messages":[{"role":"user|assistant","content":"...","created_at_ms":0}],"pending_actions":[{"id":"act-...","title":"...","detail":"...","impact":"..."}]}

turn/action response
  {"schema":"automonique.manage-chat.turn/v1|automonique.manage-chat.action/v1","answer":"...","profile":"conversation|operational","memory_evidence":0,"live_sources":[],"duration_ms":0,"conversation_retained":true,"action":null|{"id":"act-...","title":"...","detail":"...","impact":"..."}}

error response   {"error":"<bounded static category>"}
```

`profile`, `context`, and context `id` are optional. Context `kind` is one of
`dashboard`, `run`, `session`, `agent`, `decision`, `workflow`, `task`,
`event`, `tool`, `budget`, `analytics`, `activity`, `settings`,
`circuit_breaker`, `preset`, `timeline`, `vertical`. Company Manager maps the
snake-case wire names into its UI model; the service does not return a separate
camel-case browser contract.

The shared owner-only credential file is
`%S/automonique/manage-chat-auth.conf`. It deliberately contains the raw bearer
token so the web entry process and same-host Company Manager server can read
the same file; neither service may log, project, return, or expose it to client
JavaScript. Generate it without printing the token, then point Company Manager
`AUTOMONIQUE_MANAGE_CHAT_AUTH_FILE` at that exact file:

```sh
automonique-manage-chat-auth \
  "$XDG_STATE_HOME/automonique/manage-chat-auth.conf" company-manager
```

The file is created with mode `0600` and has this private schema:

```text
schema=automonique.manage-chat-auth/v1
id=company-manager
token=<URL-safe high-entropy bearer token>
end=automonique.manage-chat-auth/v1
```

The `id` line is optional metadata. The token is required. Provisioning or
rotating this production credential is a separate deployment operation; do not
commit the file.

The dashboard reuses the deployment's private Manage URL and MCP credentials;
it never embeds a production address, token, app identity or header in source.
When AI Operations is served from a different origin than the support/MCP
console, the rollback-safe `manage/platform.conf` frame names that authority
explicitly; platform bearer validation never guesses or rewrites a host.
The configuration API exposes capability booleans and the validated console
link, but keeps all authentication material concealed. If Manage or its exact
same-origin MCP server is absent, Manage actions are simply unavailable rather
than guessed.
Create both private files with the binding helper, supplying deployment-owned
hostnames explicitly:

```sh
automonique-dashboard-bind \
  /private/state/automonique \
  /private/state/automonique/dashboard-integration.conf \
  /private/state/automonique/dashboard-runtime.conf \
  dashboard.example.invalid retired.example.invalid
```

The private `%S/automonique/dashboard-runtime.conf` supplies the absolute live
daemon state directory as `AUTOMONIQUE_DAEMON_STATE`; no deployment path is
embedded in the committed unit.
Tunnel credentials and `config-monique-web.yml` are deployment state under
`~/.cloudflared/` and must never be committed. Install and start both units only
with owner authority for the public hostname and production change.

Before replacing an installed unit, verify the checked-in file with
`tools/verify_systemd_unit.sh`.

The AG-UI adapter is installed as its own immutable source bundle and supervised
by `automonique-ag-ui-adapter.service`. Its private configuration supplies only
deployment values: the peer-authenticated local Platform and progress sockets,
the active node coordinate, the existing fleet token file, and optional port. Activate a staged bundle by
switching `%S/automonique/ag-ui-adapter` atomically, then restart only the
adapter and require both probes:

```sh
systemctl --user restart automonique-ag-ui-adapter.service
curl --fail --silent http://127.0.0.1:18083/healthz
adapter_token=$(sed -n 's/^token=//p' "$AUTOMONIQUE_AG_UI_TOKEN_FILE")
curl --fail --silent --header "Authorization: Bearer $adapter_token" \
  http://127.0.0.1:18083/readyz
unset adapter_token
```

The dashboard deliberately uses a direct binary install. It does not use a
content-addressed release builder or a `current` symlink. Build it,
stage one replacement beside the installed binary, retain one previous binary,
rename the replacement atomically, and restart only the dashboard:

```sh
cargo build --release --locked -p automonique-web-entry
install -d -m 0700 "$XDG_STATE_HOME/automonique/web-entry/bin"
if test -x "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry"; then
  install -m 0700 "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry" \
    "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry.previous"
fi
install -m 0700 target/release/automonique-web-entry \
  "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry.next"
mv "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry.next" \
  "$XDG_STATE_HOME/automonique/web-entry/bin/automonique-web-entry"
systemctl --user restart automonique-web-entry.service
curl --fail --silent http://localhost:18082/healthz
```

Rollback installs `automonique-web-entry.previous` through the same `.next`
and rename sequence, then restarts and checks the service. Old dashboard
release directories are not part of the procedure and may be removed later as
a separately authorized cleanup.

The daemon uses the same direct, atomic replacement pattern. Build the daemon
and its sandbox entry helper, retain one previous copy of each, install through
`.next` files, and restart only the daemon after its zero-work deployment gates
pass:

```sh
cargo build --release --locked -p automonique --bin automonique
cargo build --release --locked -p automonique-runner --bin automonique-launch-enter
install -d -m 0700 "$XDG_STATE_HOME/automonique/bin"
if test -x "$XDG_STATE_HOME/automonique/bin/automonique"; then
  install -m 0700 "$XDG_STATE_HOME/automonique/bin/automonique" \
    "$XDG_STATE_HOME/automonique/bin/automonique.previous"
fi
if test -x "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter"; then
  install -m 0700 "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter" \
    "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter.previous"
fi
install -m 0700 target/release/automonique \
  "$XDG_STATE_HOME/automonique/bin/automonique.next"
install -m 0700 target/release/automonique-launch-enter \
  "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter.next"
mv "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter.next" \
  "$XDG_STATE_HOME/automonique/bin/automonique-launch-enter"
mv "$XDG_STATE_HOME/automonique/bin/automonique.next" \
  "$XDG_STATE_HOME/automonique/bin/automonique"
systemctl --user restart automonique.service
"$XDG_STATE_HOME/automonique/bin/automonique" status --json
```

Before the restart, recheck that the live daemon is ready with no running work,
pending inbox/outbox effects, ambiguous outbound effect or reconciliation.
Rollback installs both `.previous` binaries through the same `.next` and rename
sequence, then restarts and checks the service. The Manage fleet worker remains
a separate service and is not restarted by a daemon-only deployment.

## Shutdown drain budget

`systemctl --user stop` or `restart automonique.service` delivers `SIGTERM`,
and the daemon drains in one pass: it signals every worker group at the same
moment, then joins them all while it keeps renewing its generation and bot
leases, so the groups' independent transport deadlines overlap instead of
adding up. A handoff quiesce drains the same way.

Each worker carries a 20 s diagnostic budget. The daemon writes one structured
journal observation per worker when the drain starts (`started`), one when
that worker's thread ends (`completed`), and one more if the worker is still
running at 20 s (`over_budget`). The records carry
`AUTOMONIQUE_EVENT=shutdown_worker_drain` and name only the worker group, the
worker's ordinal within its group, the phase, the elapsed milliseconds and the
budget in milliseconds. No message content, credential, channel, user, ticket
or job identifier is ever written to them. Read a drain back with:

```sh
journalctl --user -u automonique.service -o verbose \
  AUTOMONIQUE_EVENT=shutdown_worker_drain
```

The budget is diagnostic, not a deadline: a worker that runs over it is named
in the journal and is still joined. In particular a live contained attempt
drains to its own document deadline rather than being abandoned, because an
orphaned process tree is the outcome the containment exists to prevent.
`TimeoutStopSec=90s` in `automonique.service` is the hard bound: a daemon still
draining at 90 s is killed by systemd.

The expected idle cadence — the longest a worker stays blocked before it
looks at its stop flag when nothing is happening — is, per group:

| Worker group | Idle cadence | What the worker is blocked in |
| --- | --- | --- |
| `attempt_adoption` | 20 ms | accept poll on the adoption socket; one request is bounded by a 2 s I/O timeout |
| `progress_endpoint` | 25 ms | accept poll on the progress socket; a subscriber write is bounded by a 2 s I/O timeout |
| `managed_tui` | 50 ms | idle poll of the managed terminal |
| `execution` | 100 ms | command poll between provider turns, one thread per live attempt; a running turn drains to the document deadline |
| `ticket_intake` | 100 ms | stop poll between support-API polls |
| `slack_tickets` | 2 s | one idle Socket Mode read; connect, the handshakes, writes and an in-flight `apps.connections.open` keep their 10 s ceilings, and the stop flag is checked after each |
| `telegram` | 3 s | one `getUpdates` long poll (the HTTP call is bounded at 8 s); retry back-off is sliced at 25 ms |

With every group at or under a few seconds, a routine stop completes well
inside the 20 s budget. `slack_tickets` used to be the last group by a wide
margin because its idle read shared the connector's 10 s I/O ceiling; its read
cadence is now separate from that ceiling, so a stop is observed within about
2 s of an idle read while the notification poll keeps its own 3 s throttle.
