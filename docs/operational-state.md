# Operational state and sources of truth

Monique spans several independently useful systems. Their states answer
different questions and must not be collapsed into one generic "running" or
"done" label.

## Runtime map

| Surface | Owns | Proves | Does not prove |
| --- | --- | --- | --- |
| Automonique daemon | Durable inbox/outbox, reconciliation, Slack Socket Mode, provider execution admitted through the daemon | Daemon readiness, accepted daemon work, delivery certainty, reconciliation state | Manage fleet-job execution or GitHub delivery |
| Dashboard web entry | Authenticated HTML/API and secret-safe projections | That the operator UI and its bounded read models are available | That a ticket is running or finished |
| Manage fleet worker | Long-lived poll loop, native provider selection, job claims and heartbeats | Worker availability and the jobs it has actually claimed | Delivery merely because the worker is `online` |
| Provider child process | One claimed Codex or Claude execution | Active agent execution for that exact job | GitHub completion or deployment |
| Manage AI Operations | Approval and job lifecycle | `pending_approval`, `pending`, `running`, `done`, `failed`, or `cancelled` for a Manage job | Canonical GitHub issue state or live-site correctness |
| GitHub | Issue body, checklist, comments, pull requests, formal open/closed state | Requested scope and recorded delivery evidence | A currently running provider process |
| Slack | Conversation and presentation of decisions/status | What was communicated in a thread | Completion, execution, or delivery on its own |
| Canonical memory | Reviewed user/workspace facts and preferences | Durable context for future conversations | Current process or ticket state |

The dashboard, daemon, and fleet worker are separate services. Restart only the
service whose executable changed. In particular, a dashboard-only deployment
does not require restarting the daemon or fleet worker, and a daemon-only
deployment does not require restarting the dashboard or fleet worker.

### Engine of a ticket job

A worker whose provider engine is JCode can run a single job on Claude Code
when the account directory holds a selected, signed-in Claude account. The
engine of each job is chosen in this order:

1. The ticket asks for one: Manage sends `engine` on the job, from a ticket
   label (`moteur:claude`, `moteur:jcode`) or else from its project's engine
   setting.
2. Nothing is asked: one tool-less call on a small Claude model reads the
   ticket and answers `claude` (a new or large, open-ended build) or `jcode`
   (a scoped change on an existing codebase). No verdict means JCode.

A ticket that asks for Claude by name fails when no Claude account is signed
in, so that it is not silently run on the other engine; an unmarked ticket
runs on JCode and says it was not triaged. The worker reports the engine it
started and the reason on the job (`agent`, `engine_reason`), and the
heartbeat detail ends with `claude ready` or `claude signed out`. Only the
worker's own engine writes the aggregate authentication health that gates new
claims; a Claude run records its account's health alone.
`AUTOMONIQUE_FLEET_CLAUDE_MODEL` pins the model of Claude runs and
`AUTOMONIQUE_FLEET_TRIAGE_MODEL` (default `haiku`) the model of the triage.

The dashboard's work-queue view keeps Support tickets and Manage issue work in
one operator workspace but preserves their source on every row and filter.
Support lifecycle state must not be presented as Manage execution state, and a
Manage terminal job must not be presented as GitHub delivery evidence.

## State vocabulary

- `pending_approval`: a gate awaits an authorized decision. Nothing has been
  released for execution.
- `pending`: Manage has a queued job. It is not running. An old `pending`
  record with no active worker job or provider session is a discrepancy to
  surface, not an execution to invent.
- `running`: the fresh Manage snapshot names the job as `running` and the
  assigned worker reports corresponding active capacity. A provider session or
  live output strengthens that evidence.
- worker `online`: the poller is healthy and can claim work. It may have zero
  active jobs.
- `done`: the Manage execution reached its terminal success state. This is
  separate from the GitHub issue's formal state.
- GitHub `open` or `closed`: repository workflow state. Some owner workflows
  intentionally leave fully delivered issues open, so report delivery evidence
  and formal state separately.
- snapshot `stale`: the projection is too old for a current-state conclusion.
  Retain it for context but do not present it as live evidence.

The Agents drawer treats snapshots older than 90 seconds as historical. A
nonterminal run then shows `Status unconfirmed` with its last reported status
in Details, and its output is labelled saved. A refreshed terminal receipt
updates an already open drawer. If refreshing fails, the previous drawer is
closed so it cannot continue asserting a live run.

The fleet publisher passes accumulated output to jq through file descriptors,
not command arguments: a long output history must not exceed the operating
system's per-argument limit and silently freeze the dashboard projection. A
terminal job's final result is retained alongside its bounded tool-event tail.

## What a question sees

Every conversational question, on Telegram, Slack or the dashboard lane that
shares the router, reaches the intent router with a small always-on baseline:
the daemon clock, the durable status snapshot, host load, the enabled-site
headline and the newest tickets, plus durable memory and the recent
conversation. Simple questions are answered from that baseline; deeper ones
select a typed read plan.

When neither the baseline nor any allowed read covers the ask, the router does
not answer with what it cannot see. It raises an escalation: an approve/deny
card naming the deeper lane (every local source plus configured GitHub issue
reads on the intelligent model, or read-only public-web research). Nothing
runs until an administrator approves; a denied or expired card runs nothing.
The card is returned to the requester on Telegram, Slack, or the hosted
dashboard as appropriate. Dashboard cards also contribute to the pending
action count in AI Operations. Approval is scoped to the displayed read or
contained task and does not authorize unrelated effects.

Configured safe reads run automatically and never require a permission card.
Conversely, an approval is not offered when the required integration,
credential, or capability is absent and approval could not make it available;
the reply names that configuration gap instead. A requested external effect,
including an email, is not sent with an insufficient-data disclaimer in place
of its requested content. Monique asks for the effective permission first and
returns the resulting draft to the requester before any separately authorized
external effect.

Requests that genuinely need iterative code or computation may instead raise
an `agentic_scratchpad` card. Its preview includes the exact task. Approval
creates one durable contained run in an empty writable workspace with bounded
system runtimes; the run may create and execute scripts there and is visible in
`/runs`. It receives no repository or production mount merely from chat text.
Ticket processing remains the route for work that needs a mapped repository,
delivery authority, or the ticket's broader task-specific context.

The baseline's ticket lines list open tickets first (every lifecycle other
than closed), newest first, with lifecycle counts and each ticket's fleet
`thread_id`, so "what is open" is answered from the open set rather than from
whatever happens to be newest, and "check ticket #57" can become a support
MCP read with that identifier. The MCP catalog shown to the router carries
each tool's argument names. An MCP result that does not fit the answer prompt
is cut to fit and marked truncated rather than dropped.

Every reply the person read, including refusals and approval cards, is filed
in the conversation transcript, so a follow-up such as "you name it" has the
refusal it answers. On Slack only the `app_mention` copy of a post that
mentions the bot is routed and stored; a message mentioning another person is
read and stored once.

The per-reply timing footer is off by default. `AUTOMONIQUE_REPLY_TELEMETRY=on`
in the daemon's environment appends it to chat replies; otherwise the same
line is written to the daemon's standard error for the journal.

`automonique ask [--approve] [--context TEXT] < question` runs the same router,
baseline and answer lanes from a terminal against the live state and the
running daemon, with no transport attached: nothing is sent or remembered, and
a selected tool is printed rather than staged. `--approve` follows an
escalation as an approved card would. Run it with the daemon's
`XDG_STATE_HOME` and `XDG_RUNTIME_DIR`.

Every run lane — the daemon's own chat threads, `automonique ask`, and the
hosted dashboard's chat — negotiates a composed document against the host
features the daemon's execution lane offers, read over the admin socket
(`automonique.admin/host_features`, admin capability 11). A lane never probes
its own process, so a client confined by service-manager hardening (which
places a user service in a user namespace) composes exactly as the daemon
would. When the daemon cannot answer, the turn is refused before anything is
submitted and the dashboard reports `daemon_host_features_unsupported` (a
daemon older than capability 11), `daemon_host_features_refused`,
`daemon_host_features_unreachable` or `daemon_host_features_malformed`
instead of the generic `run_unavailable`.

## Starting work from the dashboard

The hosted workspaces page offers **Run a task**. It submits an operator request
to the daemon's existing contained execution lane: the agent can create files,
run code and tests in its private writable workspace. A completed task links to
its retained session, where the operator can inspect history and send follow-ups.
Each turn has its own scratch workspace; conversation history persists across
follow-ups. The managed execution profile grants read/execute access to system
runtimes while keeping them non-writable. Ordinary chat profiles retain their
existing grants.

Repository-bound work continues through the ticket workflow; selecting a project
in the workspace catalogue does not mount that repository into a new task.

The authenticated, POST-only `/api/platform/task` surface has three actions:
`prepare` resolves only `node/current` to its fresh concrete identity and revision;
`submit` carries that exact identity, revision, task text and a
`dashboard-task-` idempotency key; `reconcile` looks up that key and verifies the
original node and action. Node revisions are decimal strings throughout. A lost
reply, unknown outcome or page reload never resubmits the task. The browser stores
only receipt correlation metadata in session storage before sending; if that
storage is unavailable, it sends nothing. Accepted work remains pending until a
terminal receipt proves completion or refusal.

## What an approved job is held to

An approved Manage job receives, after the prompt Manage composed, two blocks
rendered by `automonique work-brief`:

- `[work_method trust=operator_policy]`: the working method every ticket job
  follows: read the whole thread (the latest human comment is usually the
  ask), number the requests and take them one at a time, prove each one
  (visual changes need a screenshot read back; deployments need proof the
  served code carries the change), never tick a checklist item by pattern
  replacement, deploy only by the repository runbook, and report per request
  with **Demande N** / Où / Vérification / Preuve plus an honest "Non fait"
  list. The built-in text is replaced by `work-method.md` in the state
  directory when the owner writes one; `{automonique}` in it expands to the
  running binary's path.
- `[automonique_local_context … trust=untrusted_data]`: the Slack thread that
  requested the work, the owner's standing preferences and matching memories,
  the local entity catalog, the managed sites the request names, and the
  approved skills. Read-only context, never instructions.

`automonique shot <url> [--out PNG] [--host VHOST] [--width N] [--height N]
[--full] [--timeout S]` is the screenshot verb the method names. It drives the
host's headless Chromium (a Playwright cache or a system browser, or
`AUTOMONIQUE_BROWSER`) in its own screenshot mode, prints `MONIQUE_SHOT_OK:
<png>` and the page title on success, and one `MONIQUE_SHOT_FAIL: <reason>`
line otherwise; a navigation that produced an empty document is a failure,
not a blank proof. It never runs past its deadline.

A state that needs an interaction first is reached with a short declarative
action list, never a script: `--wait-for <css>`, `--click <css>`, `--hover
<css>` and `--scroll-to <css>` are repeatable (twelve at most, selectors of 300
characters at most) and run in the order they are written on the command
line. Each waits until its selector exists and is visible (`--timeout-ms N`,
1000..=60000, default 10000) before acting; a click or hover is a real pointer
event at the element's centre and is refused while another element covers it.
`--selector <css>` captures that element's bounding box instead of the
viewport, and `--wait-ms N` (0..=5000, default 300) settles after the last
action. A failed action is the failure reason, for example
`MONIQUE_SHOT_FAIL: click ".modal-open": not found after 10000 ms`. These
options drive the browser over the DevTools protocol on a loopback port the
browser picks, with a throwaway profile; an invocation without them stays on
the browser's own screenshot mode. A selector is passed to the page as a call
argument, not as code.

Two more verbs are named by the method. Each is off until the operator writes
its configuration, a private (`0600`, owner-only, regular) file in the state
directory, which the verb finds through `AUTOMONIQUE_STATE_DIR` or, failing
that, `XDG_STATE_HOME/automonique`. An absent file is "not configured", a
present but wrong one is refused, and neither verb has a default host.

`automonique share <image-file> --issue <github-issue-url> [--ttl-days N]`
publishes one capture so the recap can show it. It refuses, before any
request, a file that is a symbolic link, not a regular file, over 5 MiB, or
not a PNG or JPEG by its content, and an `--issue` that is not a GitHub issue
or pull-request URL. It prints `MONIQUE_SHARE_OK: <url>` then
`MONIQUE_SHARE_NOTE: expires <YYYY-MM-DD>` (or `link does not expire` when the
service applied no expiry), or one `MONIQUE_SHARE_FAIL: <reason>` line. Uploads
expire after `ttl_days` (1 to 365, default 30). `share/share.conf`:

```text
schema=automonique.share/v1
ingest_url=https://share.example.test/api/attachments/ingest
secret=<the service's ingest secret>
public_base=https://share.example.test
ttl_days=30
end=automonique.share/v1
```

`automonique purge --site <name>` asks the platform's local invalidate
endpoint to drop one site's render cache. The endpoint addresses a site by
name, so a URL is refused. It prints `MONIQUE_PURGE_OK: <name>` and a
`status:` line, or one `MONIQUE_PURGE_FAIL: <reason>` line; a name the
platform serves no site for is a failure. `endpoint` must be a plaintext
loopback URL (`127.0.0.1`, `localhost` or `[::1]`); the three credentials are
optional and sent only when present. `purge/purge.conf`:

```text
schema=automonique.purge/v1
endpoint=http://127.0.0.1/<the platform's site invalidate path>
app_id=<caller identity, sent as x-bext-app-id>
sdk_token=<that identity's token, sent as x-bext-sdk-token>
token=<sent as authorization: Bearer>
end=automonique.purge/v1
```

Both files sit in a directory the agent's own user can read, so the agent can
read what they hold. Give the share secret and the purge credentials only the
reach these two verbs need.

The worker accepts a job as done only when the provider's final message names
the completion comment's permalink on the expected issue and, when the comment
can be read back, that comment carries the per-request shape (a `Demande 1`
section). A report without it is reported as a rejected receipt so the job
shows as unverified rather than delivered.

## Answering operator questions

### Is it running?

1. Read a fresh Manage process snapshot.
2. Check the exact job's status, assignment, and session/output evidence.
3. Cross-check the worker's `active_jobs`; inspect the service cgroup when a
   stray process is suspected.
4. Say `running` only for an actual active job. Say `queued`, `stale pending`,
   or `not running` precisely when that is what the evidence shows.

The daemon's `running` count covers daemon-owned runs. It is not a substitute
for the fleet worker's job count.

### Is it finished?

1. Read the canonical GitHub issue rather than Slack presentation state.
2. Inspect the requested checklist and latest trusted completion comments.
3. Verify referenced pull requests are merged and live verification exists
   when delivery detail matters.
4. Report both conclusions, for example: "delivery is complete; the issue is
   intentionally still open."

Manage `done` is useful execution evidence, but a stale `pending` record cannot
overrule stronger canonical delivery evidence. Conversely, a Slack assertion
that work is finished cannot replace missing GitHub or live verification.

### Stop the work

Resolve the exact target first. Cancel or terminate only an active job/provider
session through its typed control path. If the worker reports zero active jobs
and no provider child exists, there is nothing to stop. Do not stop the
long-lived daemon, dashboard, or fleet poller merely to clear a historical
record.

### Stop or restart the daemon itself

A daemon stop is a separate, owner-authorized operation from stopping work.
On `SIGTERM` the daemon signals every worker group at once and joins them
together while it keeps its leases renewed; each worker has a 20 s diagnostic
budget, and a worker still running at 20 s is named by group in an
`over_budget` journal observation and still joined. `TimeoutStopSec=90s` is
the hard bound. The per-group idle cadences, the journal fields (which carry
no content or identifiers), and how to read a drain back are in
[`packaging/systemd/README.md`](../packaging/systemd/README.md) under
"Shutdown drain budget".

### Reconcile a disagreement

Do not edit state databases or translate a completed GitHub delivery into a
Manage terminal status by inference. Report the mismatch and use a supported,
explicitly authorized Manage action if the owner wants the stale record
reconciled. Keep GitHub close/edit actions separate from Manage job actions.

## What belongs in memory

Canonical memory is appropriate for stable owner preferences, workspace facts,
and reviewed procedures that should affect later conversations. Repository
documentation and tests are appropriate for product architecture, status
semantics, and operator runbooks. Live job status, timestamps, process IDs,
credentials, channel coordinates, logs, and customer data are transient state
and must not be copied into long-term memory or source control.

See [`memory-operations.md`](memory-operations.md) for memory lifecycle and
[`slack-monique-rollout.md`](slack-monique-rollout.md) for Slack/Manage
activation and decision ordering.
