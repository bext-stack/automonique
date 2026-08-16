# Self-improvement workflow

This is an operator how-to. It carries no requirements authority: what this
pipeline is permitted to do is specified in
[`docs/product-plan/requirements/self-hosting-and-bootstrap.md`](product-plan/requirements/self-hosting-and-bootstrap.md)
§ Shipped self-improvement pipeline, and the authority decision behind it is
[`plan/owner-decisions/2026-08-15-self-improvement-authority.md`](../plan/owner-decisions/2026-08-15-self-improvement-authority.md).
Where this file and those disagree, they win.

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

## What the candidate is verified against

The host runs the same gate set the required CI jobs run, with the same flags,
against the staged candidate — the formatting, workspace check, test and
`clippy -D warnings` gates in `rust/`, plus the licence boundary, the
publication scrub and the identifier rule from the worktree root. A gate added
to CI and not to this list, or the reverse, fails the build.

## The required-check gate

The second approval does not merge on its own. Before anything is merged,
Automonique reads the check runs GitHub recorded for exactly the tested commit
and requires that every required check — `workspace`, `licence-boundary` and
`development-scrub` — has a completed, successful run on that commit. Only then
is the pull request merged and the release activated, and the evidence (the
commit, and each check's run id, URL and completion time) is written to the
improvement record.

Anything else refuses without merging, and the reply says which check and why:

| Reply says | Meaning | What to do |
|---|---|---|
| still running | the check has not finished on that commit | send `IMP-000001: continue` once it has |
| did not pass | the check completed with a failure | request changes and revise the plan |
| never ran | no run exists on that commit at all | the workflow was renamed, deleted or never triggered — fix CI, then `continue` |

In all three cases the item stays at `release_approved`. The approval button is
single-use and is not re-issued; `IMP-000001: continue` is how an approved
release resumes, and it re-runs the same gate.

The second approval merges only the recorded PR head. Skill-only releases
switch an atomic digest link and are read again on every provider run. Code and
mixed releases switch an atomic release link, restart the configured systemd
user service, verify readiness, and restore the prior code and skill links if
readiness fails.

Code activation is automatic after the second approval, exact-commit CI gate,
and merge. The out-of-band activation helper switches the release link and asks
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

The owner must create `bext-stack/automonique-plans` as a private repository.
Automonique checks that it is private and that `bext-stack/automonique` is
public; it does not create repositories or alter repository settings.

Branch protection on the source repository's `main` is an owner action and is
**not** enabled by anything here. Automonique cannot set it, and cannot verify
it from the inside. Until the owner enables it, the required-check gate above
is the only thing standing between an approved release and public `main`, and
it is enforced by this daemon rather than by the remote. Enable it, requiring
the same three checks, so that the remote refuses independently.

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
