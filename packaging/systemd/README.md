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
to AI Operations. It runs from the same immutable release as the daemon.

The optional hosted dashboard is deliberately separate from the daemon.
`automonique-web-entry.service` binds a small Rust read-only dashboard server
to loopback; `automonique-web-tunnel.service` publishes it through an
operator-provisioned Cloudflare tunnel. The dashboard reads a sanitized status
projection through the same peer-authenticated local protocol as the CLI and
keeps mutations on the authenticated Manage console. The retired hostname
redirects to the canonical dashboard hostname.
Every dashboard resource and API response on the canonical hostname requires
HTTP Basic authentication over the Cloudflare TLS boundary. The strict private
credential file is `%S/automonique/dashboard-auth.conf`; it stores a username
and the SHA-256 digest of an operator-generated high-entropy secret, never the
secret itself. The loopback-only health check is the sole unauthenticated route.
`automonique-dashboard-auth` creates that verifier and a separate owner-only
recovery file without printing the credential. The recovery file is not read by
the service and should be moved into the operator's password manager, then
removed. `%S/automonique/dashboard-integration.conf` binds the dashboard to one
existing memory tenant and actor; those identifiers remain absent from every
web configuration response. Chat turns use the daemon's contained run lane and
the canonical memory database, rather than a dashboard-specific provider path.
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
