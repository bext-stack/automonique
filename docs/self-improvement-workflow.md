# Self-improvement workflow

Automonique accepts explicit self-change requests from a Telegram administrator,
for example: `Improve Automonique by adding a durable status view.` Ordinary
capability questions do not create work.

The workflow has two independent approvals:

1. Automonique drafts a bounded plan, pins the current public source SHA, and
   publishes the canonical Markdown to an issue and plan-only pull request in
   the private `bext-stack/automonique-plans` repository. The Telegram buttons
   approve or request changes for the exact actor, chat, state revision, and
   plan digest. Requesting changes returns the item to draft; send guidance as
   `IMP-000001: keep this skill-only`.
2. After plan approval, the plan PR is merged and a pinned Codex App Server runs
   in an outer sandbox over a detached worktree. It receives Codex model auth
   but no GitHub, SSH-agent, deployment, or production credential. The host runs
   fixed checks, commits with the Automonique Candidate identity, builds an
   immutable release, pushes the exact tested commit, and opens a source PR. A
   second Telegram gate binds the tested commit and release-manifest digest.

Requesting changes at either gate returns the item to a draft plan. The owner
can send `IMP-000001: revision guidance`; the replacement plan receives a new
revision, plan pull request, and first approval before another lab attempt.

The second approval merges only the recorded PR head. Skill-only releases
switch an atomic digest link and are read again on every provider run. Code and
mixed releases switch an atomic release link, restart the configured systemd
user service, verify readiness, and restore the prior code and skill links if
readiness fails.

For code activation to switch the executable atomically, the configured unit's
`ExecStart` must invoke
`<state-directory>/improvement-code/current/bin/automonique daemon --foreground`.
The initially installed executable may schedule the one-shot activation helper,
but subsequent service starts must resolve the `current` release link.

## Owner prerequisites

The owner must create `bext-stack/automonique-plans` as a private repository.
Automonique checks that it is private and that `bext-stack/automonique` is
public; it does not create repositories or alter repository settings.

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

If the lab file is absent, planning and review remain available, but an approved
plan stays at `plan_approved`. After provisioning the lab, send
`IMP-000001: continue` to resume it. Failures preserve the durable journal and
never imply that GitHub merge or activation succeeded.
