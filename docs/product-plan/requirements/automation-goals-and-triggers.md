# Automations, goals and triggers

**Status:** accepted product architecture

## Durable automations

The existing scheduler grows a user-facing automation service. `AutomationJob` stores owner/tenant, enabled revision, schedule, timezone/DST policy, prompt or workflow, optional skills/profile/provider/model, workspace/context references, sandbox/budget, delivery targets, concurrency/overlap policy and last/next execution.

Schedules accept one-shot ISO timestamps, fixed durations, five-field cron and parsed natural-language expressions. The parser returns the exact canonical schedule and future examples for review; it never schedules directly from ambiguous prose.

Operations include create/preview, list/read, edit with expected revision, pause/resume, run-now, cancel active occurrence, clone, history and remove/archive. Each occurrence is a normal work item/run with durable events, approvals, artifacts and receipts. A fenced scheduler lease and occurrence idempotency key prevent duplicate firing across reload.

Jobs can:

- start a fresh agent turn;
- run a reviewed no-agent script/workflow and deliver stdout/artifacts;
- chain typed output/artifacts from predecessor jobs;
- target a registered workdir/project and its context rules;
- deliver to origin, files/artifacts, Slack, Telegram, Teams, Discord or any graduated connector;
- run notification-only with zero model call.

Unattended mutations require pre-approved scope or produce an approval request; schedule creation is never blanket authority for future arbitrary effects.

## Persistent goals

A `Goal` is a durable user objective with owner, text, completion contract, criteria/subgoals, budget, deadline, policy, active session/work graph and status. It differs from a ticket: it may drive multiple turns and waits, while every concrete effect remains a normal action.

After each turn a deterministic checker and optional bounded judge select `continue`, `complete`, `wait`, `blocked` or `budget_exhausted` with evidence. Wait conditions reference durable timers, process/run IDs, connector events or monitored patterns. User input always preempts automatic continuation. Completion never rests only on persuasive prose when tests/artifacts/receipts were required.

Self-improvement goals are a restricted development origin defined by [Self-hosting and bootstrap](self-hosting-and-bootstrap.md). They may be proposed from deterministic failures, approved ledger gaps or metric regressions and execute only in candidate namespaces. They cannot change their own acceptance metric, security/authorization policy, legal/retention rules, privilege boundary, trusted builders/signers or production promotion authority. Repeated unchanged or oscillating evidence pauses the goal for root-cause review.

## Work boards and dispatch

Expose the existing work DAG as a Kanban/command-center projection: create, assign, link dependencies, comment, block/unblock, complete, archive, tail events, statistics, runs and dispatcher health. Workers receive board/task-scoped capabilities and heartbeat claims. Failure thresholds auto-block rather than retry forever. Boards are hard authorization boundaries; labels are not tenancy controls.

## Inbound webhook subscriptions

External services may create durable input through managed webhook routes. A route declares:

- stable ID/path, tenant/actor service account and allowed event types;
- HMAC/public-key/mTLS verification and replay window;
- payload/header/body limits, content type and rate policy;
- declarative filters (`equals`, `contains`, existence, membership and bounded regex with all/any/not);
- a sandboxed transformation workflow or typed template;
- destination goal/automation/intake route and delivery-only option;
- idempotency extraction and response/acknowledgement semantics.

Transform scripts live in immutable extension packages, receive JSON on stdin and have no ambient network/secrets. Direct delivery bypasses the model but not destination authorization, outbox receipts or content limits. Test/preview operations use synthetic payloads and cannot contact production destinations without a separate action.

## Hooks, watchers and wakeups

Registered GitHub, CI, monitoring, filesystem, RSS, calendar, email and platform events can wake an automation through the same durable input boundary. Polling watchers use leases, cursors, budgets and backoff. A wake never resumes an arbitrary session solely from a text label; it resolves exact goal/job/session context.

## Notifications and escalation

Delivery policy covers quiet hours, digesting, severity, acknowledgement, escalation, retry/dead letter and alternate destinations. Platform delivery is correlated but never mirrored into provider conversation history unless explicitly included as context.

## Exit gate

Natural-language schedules round-trip to deterministic canonical schedules; duplicate ticks/webhooks create one occurrence; no-agent and agent jobs obey identical identity/sandbox/outbox rules; goals stop, wait and resume safely across reload; board claims are fenced; and every connector delivery or inbound trigger is attributable, revocable and replay-safe.
