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
- `auto_confirm=U…` (optional, repeatable, accepted by v1 and v2) names a
  Slack user whose ticket posts in a configured channel are confirmed through
  the ordinary confirm path, so the worker starts without an approval card.
  Off unless listed. It never applies while a Claude Code session holds the
  ticket, and a confirmation Manage refuses falls back to the approval card.
  Unlisted users keep the approval card.
- `team_github_login=<login>` (optional, repeatable, v1 and v2) names a GitHub
  login of the delivery team. Logins are configuration, never code.
- `retire_stale_approvals=on|off` (optional, v1 and v2; may be repeated when
  every occurrence agrees) controls the retirement described under "Stale
  approvals" below. It has an effect only when a `team_github_login` is
  configured, and then defaults to `on`.

Every key must be known to the parser: an unrecognized key refuses the whole
file (`slack_config_malformed`) for the daemon and for the dashboard, which
read it through the same parser. Add a new key only after every running binary
has been upgraded to a release that knows it.

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
surface uses `chat:write`, `reactions:write`, channel history scopes
appropriate to configured channel types, and `users:read`. App Home publishing
itself requires a valid app installation; Slack currently documents no
additional OAuth scope for `views.publish`. Do not add `chat:write.public`:
invite the app to each configured channel instead.

## Ticket status reactions

The daemon is the single owner of the status reactions on a Slack message that
posted a GitHub ticket. Nothing else reacts with the bot token — in particular
no Claude Code hook: a session claims and releases through the daemon instead.

- 👀 `eyes` — somebody has started: a Monique job reached `claimed` or
  `running`, or a local Claude Code session claimed the ticket.
- ✅ `white_check_mark` — the ticket is verifiably finished: its Monique job
  reached `done`, or GitHub shows the pull request merged, the issue closed as
  `completed` (or with no recorded reason), or the issue's **latest** comment
  written by a `team_github_login` reports a delivery (`en ligne`,
  `en production`, `déploi…`/`deploy…`, `corrigé`, `maintenant`, `is live`,
  `deployed`, `fixed`, case-insensitive). A later comment from anyone else
  makes the ticket unfinished again. A turn or a run ending never counts.

The reactions are derived from `ticket-work.v1.json`, an owner-only ledger
beside the other ticket registries: per ticket, the Slack posts that cited it
(recorded at intake and seeded from `slack-ticket-jobs.v1.json` on start), its
claims, the reactions already applied, and a verification queue. A released
ticket that is not finished stays queued and is checked again every ten
minutes, three tickets per pass, for up to 21 days. A post of a ticket already
verified finished receives no 👀; it is checked once more and receives its ✅
only if the ticket is still finished. The bot only ever adds its own
reactions; a human's reactions are never touched. A Claude claim lapses after
twelve hours without renewal.

Local sessions use the admin socket:

```text
automonique ticket claim <github-url> --holder claude:<session>
automonique ticket release <github-url> --holder claude:<session>
```

Both print one JSON line, `{"conflicts":[{"holder":…,"status":…}],"posts_found":N,"reacted":N}`.
A claim reacts 👀 on every known post of the ticket — searching the configured
channels' recent history when the daemon has not recorded one — and reports
every competing Monique job (`pending_approval`, `pending`, `claimed`,
`running`) or other session. While a session holds a ticket, Slack intake for
it answers in thread instead of opening a Monique job. A release checks GitHub
at once and reacts ✅ when the ticket is finished; otherwise the ticket is
queued for verification.

### Stale approvals

A Monique job in `pending_approval` is a question nobody answered, not work in
progress: it never earns 👀 and it does not keep its ticket away from GitHub.
When a `team_github_login` is configured, a ticket whose jobs are all still
awaiting approval is verified on the same bounded cadence (three tickets per
pass, the longest-due first, so a backlog rotates), at most every thirty
minutes per ticket, until 21 days after its newest Slack post.

When such a ticket is found finished it receives its ✅, and, unless
`retire_stale_approvals=off`, the approval it no longer needs is retired: the
daemon reads the job's status again and, only if it is still
`pending_approval`, sends Manage the ordinary reject decision for that exact
job with the gate coordinates retained at intake, the actor
`automonique:stale-approval`, a decision key derived from the job id (so a
retry is the same decision) and the fixed reason "Superseded: the ticket was
finished outside Monique before this run was approved." A job that is
`pending`, `claimed`, `running` or terminal is never rejected. A failed
attempt is retried every ten minutes, five times at most, then abandoned and
reported once in the journal (`stale_approval_settled`); the job then stays
waiting in Manage.

Manage records the rejection as a `cancelled` job whose result is that reason.
The originating Slack thread is not told: its notification is settled without
a message, because the ✅ already says the ticket is done. If the client
reopens the ticket (a newer comment from outside the team) and posts it again,
intake runs as usual and opens a fresh approval; the finish is withdrawn at
the next verification.

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

## Mobile channel and ticket queue

The mobile `manage_work` grant is opt-in when pairing a phone. It allows reading
one operator-configured Slack channel and submitting, approving or rejecting
GitHub-linked tickets on this server's configured Manage instance. It does not
send Slack messages or change a user's Slack workspace membership. Existing
credentials retain their old grants. An operator must deliberately pair a new
phone with this permission; an email address alone never grants access.

Create an owner-only, mode `0600` `<state>/mobile-work.json` binding:

```json
{"channel":"configured-channel-label","display_name":"channel-name"}
```

`channel` must already appear in `slack/slack.conf`. The app shows a bounded
recent-message view, not a complete Slack archive. Manage remains authoritative
for job state. Queue reads return up to 50 recently updated GitHub-linked
Automonique jobs belonging to the configured instance and tenant; `has_more`
reports truncation. The support endpoint requires the existing staff token.

`POST /api/mobile/work` is mobile-bearer-only and requires `manage_work` for
all requests. It accepts `channel`, `snapshot`, `dispatch` and `decide` actions.
The phone never supplies an instance, tenant, actor, Slack ID or service token.
Dispatch creates a pending gate, and a separate confirmed approval releases it.
Rejection requires a reason. Mutation keys are bound durably to the credential
and exact payload before contacting Manage. A phone retains an uncertain request
and can explicitly retry that same key; it never queues actions offline or
retries automatically. Decisions are audited under the issuing mobile credential.
