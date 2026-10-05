# Artifact integrations

The Share service owns application grants, manifests, jobs and event journals.
Monique presents these records in Configuration → Applications & API and the
deliverable revision panel. `/api/integrations` is an authenticated dashboard
proxy with an explicit control-action allowlist. It never accepts worker actions.

Public integration documentation, the OpenAPI contract and dependency-free
TypeScript/Python clients are served from Share's `/developers` page. Create one
scoped connection per application, store its token on that application's server,
and grant only the required projects and operations. Publishing is private by
default. Changing visibility requires a separate permission.

## Worker deployment

Deploy the web-entry binary using the documented immutable release procedure.
The integration worker is a separate user service: it does not restart the main
daemon, Slack transport or fleet workers.

1. Copy `tools/monique_integration_worker.py` and `tools/monique_artifact.py` into
   an immutable release directory named for the checked source commit. Keep the
   prior release for rollback.
2. Copy `tools/deploy/automonique-integration-worker.service.example` into the
   user's systemd directory, replacing each path placeholder. The state directory
   is the daemon's private `automonique` directory, containing `share/share.conf`.
   The accounts directory contains the connected-account registry and profiles.
   Use absolute paths to the native Claude and Codex executables.
3. Create a private runtime directory (mode 0700). Install the unit with mode
   0600. Run `systemctl --user daemon-reload`, then enable/start the integration
   worker. For an update, wait until its jobs are idle before restarting it.
4. Verify the worker heartbeat in Applications & API, then submit a private test
   deliverable, request a revision, and verify the new version and downloaded
   content. Verify the configured subscription account and actual token usage.
5. On failed readiness, restore the unit's previous release path and restart only
   this worker. Do not replay interrupted provider work automatically.

The worker uses the account selected in Monique. It sends bounded source text to
the native subscription client with tools disabled, validates structured UTF-8
file output, preserves unchanged assets and publishes using the job's lease and
current grant. It supports HTML, CSS, JavaScript, JSON, text, Markdown, CSV, SVG
and XML changes. Binary editing or missing context produces a failed job. A model
message alone is insufficient: a completed provider turn is required.

Leases are renewed every 20 seconds and expire after 120 seconds. Revocation,
cancellation or a stale lease prevents publication. A publication with a lost
acknowledgement is reconciled from its immutable version receipt. Interrupted
model calls remain visible for inspection rather than spending tokens again.

## MCP and signed notifications

Add Share's `/api/mcp` endpoint to the existing private `mcp/servers.json` registry
using a scoped app token. Preserve other entries and the existing schema. The
server uses the same MCP protocol as Monique's client and filters tools by grant.
New frontend releases load this registry; per-request clients load it themselves.

Create an event subscription for Monique's `/api/integration-events` endpoint.
Store the returned signing secret in the private `share/webhooks.json` file as a
JSON array of strings, mode 0600. It is read on receipt and supports overlapping
keys during rotation. Do not store app tokens or signing secrets in source.

The worker delivers signed HTTPS events with bounded retry, rejects redirects
and private IP targets, and records each delivery outcome. Monique verifies raw
body HMAC and timestamp, records the event ID and digest durably, and acknowledges
identical replays. Events never overwrite canonical job state. The dashboard
shows failed deliveries with a retry action. Subscriptions to additional origins
require Share's `SHARE_WEBHOOK_ALLOWED_ORIGINS` setting.

Usage counts API/MCP requests, errors, latency and upload volume. Provider token
counts are recorded only when returned by the provider; subscription quota is
not inferred from them. Event delivery is at least once, so consumers must dedupe
by event ID. The polling event feed retains 10,000 cursor entries; an expired
cursor requires resource resynchronization.
