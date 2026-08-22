# Monique Slack rollout

This is the activation contract for the Slack-native Monique surface. The v1
configuration remains readable for rollback and retains its text-confirmation
behavior. Interactive decisions are enabled only by a v2 frame.

## Slack configuration v2

The file is `<state>/automonique/slack/slack.conf`, owned by the daemon user,
mode `0600`, inside a private state directory. Never commit it.

```text
schema=automonique.slack/v2
token=xoxb-REDACTED
app_token=xapp-REDACTED
channel=<channel-label>:C0000000000
member=U0000000001
admin=U0000000002
feature=approvals
feature=conversation
feature=commands
feature=app_home
end=automonique.slack/v2
```

- `channel=` is the exact intake/output allowlist, written as
  `<channel-label>:<channel-id>`. The label is the operator's own name for the
  channel and is configuration, never code. Any human in an allowlisted intake
  channel may post one GitHub issue URL to create a pending gate.
- `member=` enables read-only conversation, `/monique help`, and App Home.
- `admin=` enables mutation. Every admin is implicitly a member.
- `feature=` is repeatable and closed to `approvals`, `conversation`,
  `commands`, `files`, and `app_home`.
- v1 implies the pre-v2 approvals/conversation/commands behavior but never
  enables interactive decisions.

`files` is reserved but must remain disabled until the tenant has an explicit
artifact size, retention, access and deletion policy and the external-upload
connector is activated. A Slack file is never treated as model-readable merely
because Slack delivered its metadata.

## Manage configuration

The Manage console's address and its key-value app identity are properties of
one deployment, so they live beside the credentials rather than in source. The
file is `<state>/manage/manage.conf`, owned by the daemon user, mode `0600`.
Never commit it.

```text
schema=automonique.manage/v1
url=https://support-console.example.test/
profile_app=<manage-app-id>
end=automonique.manage/v1
```

- `url=` must be an `https://` URL. It is the "Open Manage" button on the
  interactive approval card. With no file, or no `url=`, the card is posted
  without that button; both decisions remain on the card itself.
- `profile_app=` is the app identity the site-profile read model addresses.
  With no file, or no `profile_app=`, that source is never attached and
  site-profile questions answer `source=not_attached`.
- An absent file disables both. A present file that is world-readable, is
  malformed, sets an unknown or duplicate key, carries an invalid value, or
  sets neither key refuses daemon startup rather than being ignored.

When the AI Operations authority differs from the support/MCP console, put its
origin in the separate owner-only `<state>/manage/platform.conf` frame. Keeping
this additive configuration in a separate file preserves rollback parsing for
older releases:

```text
schema=automonique.manage-platform/v1
url=https://ai-operations.example.test/
end=automonique.manage-platform/v1
```

Without that file, platform bearer validation retains the `url=` origin.

## Slack app settings

Use Socket Mode with an app-level token carrying `connections:write`. Enable
interactivity, the Home tab and the `/monique` command. Keep the legacy
`/github_*` commands for one compatibility release.

Subscribe the bot to the events used by the enabled features:

- `message.channels` and, if configured private channels are used,
  `message.groups`;
- `app_mention` for channel conversation;
- `app_home_opened` for App Home;
- file events only after the artifact policy gate is implemented.

The bot token needs the narrow scopes for the enabled calls. The present
surface uses `chat:write`, channel history scopes appropriate to configured
channel types, and `users:read`. App Home publishing itself requires a valid
app installation; Slack currently documents no additional OAuth scope for
`views.publish`. Do not add `chat:write.public`: invite the app to each
configured channel instead.

## Decision contract and ordering

Slack approvals and rejections call Manage's
`automonique-ticket-decision` action with the exact `job_id`, original
`source_key`, stable `decision_key`, server-bound actor key, and typed decision.
A rejection requires a reason. Manage must provide these semantics before v2
`approvals` is activated:

1. the same key and same decision is an idempotent replay;
2. the same key with different coordinates or decision conflicts;
3. approval moves a pending gate out of `pending_approval`;
4. rejection atomically moves it to `cancelled` and releases no work;
5. an opposite decision after a terminal decision conflicts.

For every Slack interaction Monique authorizes and records the exact gate in
`slack-ticket-interactions.sqlite3` before acknowledging Socket Mode. Only
after that durable commit does it call Manage. Successful decisions update the
original Block Kit message without action buttons.

## Staged activation

1. Keep the live v1 configuration and validate build/tests.
2. Deploy code with v2 support but leave the live file on v1.
3. Prove Manage's decision endpoint against a non-production pending job,
   including rejection and replay/conflict behavior.
4. Configure `/monique`, interactivity and App Home in Slack; verify the
   installed scopes and event subscriptions.
5. Switch to v2 with `conversation`, then `commands`, then `app_home`.
6. Enable `approvals` only after the Manage preflight passes. Create a canary
   pending ticket, approve it in Slack, create another and reject it with a
   reason, and verify Slack, Telegram and Manage agree.
7. Cancel the two preserved legacy gates through the typed Manage decision
   endpoint with an explicit migration reason. Do not edit the legacy database
   or approve them as a cleanup shortcut.
8. Leave `files` disabled until artifact policy and bidirectional upload tests
   pass.

Rollback is a private atomic rewrite to the v1 frame followed by the repository
documented safe reload. Existing Manage decisions remain authoritative; a
rollback must never resurrect a cancelled gate.
