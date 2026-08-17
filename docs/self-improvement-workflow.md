# Self-improvement workflow

This is the operator how-to for the daemon's direct self-improvement lane. The
authority boundaries are specified in
[`docs/product-plan/requirements/self-hosting-and-bootstrap.md`](product-plan/requirements/self-hosting-and-bootstrap.md).

Automonique accepts explicit self-change requests from a Telegram administrator,
for example: `Improve Automonique by adding a durable status view.` Ordinary
capability questions do not create work.

Automonique drafts a short internal work brief pinned to the current public
source SHA, then immediately runs a pinned Codex App Server in an isolated
worktree. The candidate receives model auth but no GitHub, SSH-agent,
deployment, or production credential. The host runs its standard local checks,
records their compact receipts, commits with the Automonique Candidate
identity, builds an immutable release, pushes the exact candidate, and opens a
source pull request.

The work brief is not published and does not require approval. It exists to
give the agent a bounded task and to make retries reproducible. Remote CI
status, check receipts, token usage, duration, and other metrics may be
inspected or reported, but they are diagnostics rather than workflow keys.

The only approval appears when the source pull request and built release are
ready. The Telegram challenge is single-use and bound to the requesting actor,
chat, durable revision, and release digest. Requesting changes returns the item
to draft; send guidance as `IMP-000001: keep this skill-only`. Approving merges
only the recorded PR head and activates only the matching built release.

Skill-only releases switch an atomic digest link and are read again on every
provider run. Code and
mixed releases switch an atomic release link, restart the configured systemd
user service, verify readiness, and restore the prior code and skill links if
readiness fails.

Code activation is automatic after owner approval and merge. The out-of-band
activation helper switches the release link and asks
the supervisor for an orderly restart. The daemon stops accepting new work and
joins already accepted Telegram questions, provider attempts, Slack work and
Support work before its process exits. Activation refuses before changing the
link unless the configured service reports `TimeoutStopUSec=infinity`, which
prevents systemd from turning a long drain into a kill.

This is a **drain-and-restart**, not the generation handoff specified in
[`reload-protocol.md`](product-plan/requirements/reload-protocol.md). Accepted
work is preserved, but intake is briefly unavailable between the old process
releasing its leases and the successor becoming ready. True overlap with zero
intake gap still requires generation handoff.

For code activation to switch the executable atomically, the configured unit's
`ExecStart` must invoke
`<state-directory>/improvement-code/current/bin/automonique daemon --foreground`.
The code release also carries the pinned `automonique-chat-provider` and
`automonique-launch-enter` companions. The conversation-provider configuration
should name
`<state-directory>/improvement-code/current/bin/automonique-chat-provider` so
the same atomic link switches all three executables together; the daemon finds
the launch helper beside its own executable.
The initially installed executable may schedule the one-shot activation helper,
but subsequent service starts must resolve the `current` release link. The unit
must also set `TimeoutStopSec=infinity`; a bounded timeout makes code activation
fail closed while leaving the current link and generation untouched.

## Owner prerequisites

Branch protection and required checks on the source repository are optional
owner-managed GitHub policy. Automonique does not create or alter them. If
configured, GitHub may still refuse a merge independently of the daemon.

The daemon state directory may contain a private `improvement-lab.json` file
(owner-only mode such as `0600`):

```json
{
  "schema": "automonique.improvement-lab-config/v1",
  "repository": "/path/to/a/clean/automonique/checkout",
  "worktree_root": "/path/to/private/improvement-worktrees",
  "codex_binary": "/path/to/pinned/codex",
  "codex_binary_sha256": "64-lowercase-hex-characters",
  "codex_home": "/path/to/a/private/codex-home-containing-auth-json",
  "cargo_home": "/path/to/read-only/cargo-home",
  "rustup_home": "/path/to/read-only/rustup-home",
  "model": "owner-selected-pinned-model",
  "systemd_unit": "automonique.service"
}
```

Only `auth.json` is copied from the configured Codex home into a fresh,
attempt-specific private home. Other Codex configuration, including MCP server
or app configuration, is not copied into the candidate sandbox.

If the lab file is absent, the internal brief remains available. After
provisioning the lab, send `IMP-000001: continue` to resume it. Failures
preserve the durable journal and never imply that GitHub merge or activation
succeeded.
