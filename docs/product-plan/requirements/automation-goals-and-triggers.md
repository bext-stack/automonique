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

### The occurrence key and the fence, as built

The slice that ships (`automonique-daemon::automation_scheduler`, tracked as
M8 #45) implements the durable half of the paragraph above and names what it
does not:

- **What a registered job is.** `RegisterAutomation` carries a canonical
  schedule, a scope and a bounded prompt. The schedule is the one-shot
  (`once@<unix-ms>`) or fixed-interval (`every@<ms>`) form of
  `CanonicalSchedule`; the five-field cron form is canonical and is refused
  with the typed `automation_unsupported_schedule`, because no
  dependency-free cron evaluator with a timezone database ships, and a
  schedule the daemon could not fire is not registered. Natural-language
  phrases are parsed to a rendering before the wire (`hourly`), never stored
  as typed. The scope and the prompt carry the durable submit lane's bounds:
  the prompt is that lane's task (non-empty, at most 8 KiB, free of NUL), and
  the scope is bounded by the scheduler core's 160-byte identifier ceiling
  because an occurrence is admitted by both.
- **The occurrence key.** Every occurrence is identified by
  `automation:<automation_id>:<occurrence_instant>`, where the instant is the
  scheduled Unix millisecond — never the instant the daemon happened to
  notice it. The same key is the work identity in the durable scheduler core
  and the transport key on the synthetic lane; both dedupe on it. A replayed
  tick, a restarted daemon or a re-elected generation derives the same bytes
  and is refused (`duplicate_work` by the core, `duplicate: true` by the
  lane) rather than firing again. Because the key has to fit the lane's
  128-byte idempotency-key bound at any instant, an identity registered with
  a schedule is bounded to 97 bytes; the registry's wider identity grammar
  still serves rows registered before schedules existed.
- **The fence.** Every tick is judged under the generation fence twice: the
  product store's generation row must name the worker's holder and epoch with
  a live lease, and the scheduler core checks the `SchedulerFence` installed
  at open on every operation. A stale tick starts nothing. The worker is
  rebuilt with the new epoch when a handoff returns authority.
- **Exactly one per instant.** The registry keeps at most one active
  occurrence per automation (`active_occurrence_ms`) and its `next_fire_at_ms`
  is advanced past an instant the moment that instant is handed to the lane.
  Every occurrence verb on the registry is a compare-and-set on the instant it
  names, so a worker replaying a crashed tick re-admits nothing and re-submits
  nothing; the lane and the core dedupe the rest.
- **Catch-up.** A fixed interval that fell behind — the daemon was down, or
  the automation was paused across several instants — fires its oldest due
  instant once and continues from the first grid instant after `now`. A burst
  of catch-up firings is never produced. A one-shot fires once and is then
  exhausted (`next_fire_at_ms` null).
- **Pause, resume, archive.** A withdrawn automation derives no new
  occurrence. One already queued in the core is cancelled (`never_started`)
  and its instant skipped, because the core remembers the identity as
  terminal. One the lane is already running is left to finish — pause is not
  cancel — except that an archived automation, which nothing can resume,
  requests a stop; custody stays with the core until the lane's terminal
  commit lands. On resume, the automation continues from its next due
  instant.
- **What fires.** The occurrence is a normal item on the daemon's durable
  synthetic lane — the same lane `automonique submit` uses — claimed and
  completed by the serve loop's controller with that lane's own outbox
  intent. There is no second outbox and no second executor, and therefore no
  provider runs the prompt yet: the effect of an occurrence in this slice is
  the synthetic lane's fixture receipt, which is what "unattended mutations
  need pre-approved scope" costs nothing to keep true.
- **Restart.** A due-but-unfired occurrence fires once after restart; a
  running occurrence is found active in the registry, running in the core and
  present on the lane, and is waited on rather than resubmitted; a paused
  automation is still paused, because the registry is what says so.

Not built: trigger evaluation, delivery targets, run-now, history, clone,
natural-language schedules beyond the two recognized phrases, and the cron
form.

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
