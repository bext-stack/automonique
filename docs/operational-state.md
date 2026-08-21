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
service whose immutable release changed. In particular, a dashboard-only
release does not require restarting the daemon or fleet worker.

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

An approved Manage job receives, in addition to the prompt Manage composed,
the local context block rendered by `automonique work-brief`: the Slack thread
that requested the work, the owner's standing preferences and matching
memories, the local entity catalog, the managed sites the request names, and
the approved skills. The block is read-only context, never instructions, and a
job is never refused for lack of it.

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
