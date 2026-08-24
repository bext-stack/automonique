<!-- SPDX-License-Identifier: Elastic-2.0 -->

# systemd user service

Install the units in this directory under `~/.config/systemd/user/`, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now automonique.service
systemctl --user enable --now automonique-manage-worker.service
systemctl --user enable --now automonique-backup.timer
systemctl --user status automonique.service
```

The unit starts the current verified release from the product state directory,
creates private XDG runtime/state directories, delegates its cgroup subtree,
and waits for the daemon's real readiness notification. Upgrade switches the
`improvement-code/current` release link; restarting the unit activates it.
The timer writes an online recovery set every five minutes.
`automonique-recovery.service` is started manually after a restore; it disables
external transports and refuses provider starts.
`automonique-manage-worker.service` heartbeats the configured Manage instance,
claims confirmed jobs with bounded parallelism, and streams their progress back
to AI Operations. It also publishes an owner-only dashboard projection with a
bounded tail of parsed agent output and a link to the corresponding issue in
the configured Manage origin. Raw provider frames, stderr, prompts and fleet
credentials are not copied into that projection. It runs from the same
immutable release as the daemon. The
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
Slack tool is strictly read-only. When both `manage/manage.conf` and a unique
same-origin server in `mcp/servers.json` are present, chat can also discover
Manage AI Operations tools. Tools explicitly annotated as read-only can ground
an answer immediately. Every other tool becomes an in-chat action card showing
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
The dashboard reuses the deployment's private Manage URL and MCP credentials;
it never embeds a production address, token, app identity or header in source.
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
`tools/verify_systemd_unit.sh`. To roll back,
restore the previous `current` link through the release activation procedure
and restart the unit.

For an owner-authorized local release, use the checked-in operator tool rather
than creating an ad-hoc helper:

```sh
cargo run --release -p automonique --bin automonique-release -- deploy \
  --state-dir /private/state/automonique \
  --worktree /path/to/clean/automonique \
  --unit automonique.service \
  --plan-digest sha256:<approved-plan-digest> \
  --changed-path rust/crates/example/src/lib.rs
```

Repeat `--changed-path` for every path in the release. `deploy` refuses a dirty
worktree, derives the source commit and tree itself, builds the immutable
release, then rechecks that the live daemon
is ready with no running work, pending inbox/outbox effects, ambiguous outbound
effect or reconciliation before activation. Activation uses the same atomic
link switch, supervised restart and automatic rollback as the approved
self-improvement path. `build` and `activate` subcommands are also available
when an operator deliberately needs the two phases separated.
