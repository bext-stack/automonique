# Legacy system inventory

What the system Automonique replaces actually does, measured rather than
recalled. This is the evidence behind [`feature-parity.md`](feature-parity.md):
that ledger says what must be preserved, this says what currently exists and
which behavior is already pinned by a test.

Captured 2026-08-09 against the running system. Identifiers follow the
sanitization rules in `docs/product-plan/README.md`; the legacy tree uses its
own names.

## Shape

| | |
|---|---|
| Stack | Bun + TypeScript, `@slack/bolt`, SQLite (WAL) |
| Source | 47 modules, 13,635 lines under `src/` |
| Tests | **220 passing across 32 files, 2,338 assertions, 2.3 s** |
| State | one SQLite database, WAL-active |
| Runtime | two live systemd user units: the ticket bot and a durable tmux server |

It is in production and serving traffic. Every observation below was taken
without writing to it.

### Largest modules and their destinations

| Module | Lines | Rust destination |
|---|---|---|
| `index.ts` | 2,806 | `automonique-transports`, `automonique-core` |
| `dashboard.ts` | 1,396 | `automonique-web`, SDK |
| `conversation-router.ts` | 1,063 | `automonique-core` |
| `claude.ts` | 981 | `automonique-agents` |
| `db.ts` | 730 | `automonique-store` |
| `fleet.ts` | 615 | `automonique-fleet` |
| `telegram.ts` | 413 | `automonique-transports` |
| `commands.ts` | 367 | `automonique-core` |
| `term.ts` / `tmux-exec.ts` / `runs.ts` | 829 | `automonique-runner` |

The concentration matters: `index.ts` alone is 21% of the system and owns Slack
lifecycle, routing and approvals together. The target architecture separates
those into three crates, so it is the highest-risk port and the least covered
by tests relative to its size.

## Behavioral coverage

220 tests exist. They are not evenly distributed, and the distribution is the
useful part.

| Area | Files | Tests | What is pinned |
|---|---|---|---|
| Conversation routing | `conversation`, `conversation-state`, `conversation-ai` | 47 | deterministic route selection, durable slots, follow-up scoping |
| Fleet lifecycle sync | `manage-sync` | 14 | split approval gates, idempotency keys, transaction rollback, envelope ack, backoff/retry, malformed-payload drop |
| Dashboard contract | `dashboard-ui`, `telegram-dashboard` | 21 | UI contract surface |
| Execution spools | `spool-reader`, `spool-store`, `ndjson-lines` | 33 | framing, retention, monotonic reads |
| Support workflows | `support-*` (6 files) | 16 | inbox query, compose, exact-draft review, mailer result |
| Operational queries | `operational-query` | 11 | bounded query execution |
| Provider backends | `codex-backend`, `jcode-backend`, `jcode-integration`, `codex-guard` | 16 | two of four backends, guard denials |
| Telegram transport | `telegram` | 8 | transport semantics |
| Prompt-injection hardening | `security-hardening` | 8 | untrusted-context labels |
| Command registry | `commands` | 7 | registry, aliases, help |
| Sites and access | `site-conversation`, `site-inventory`, `access-conversation` | 10 | inventory, read-only catalog behavior |
| Runs plumbing | `runs-wiring` | 5 | reaper timing, live-run protection, no double fork |
| Privileged proposals | `privileged-actions` | 3 | proposal-only boundary |
| Slack durability | `slack-event-dedup`, `slack-reconcile` | 3 | claim-once, orphan gate adoption |
| tmux transport | `tmux-exec` | 1 | argv beyond tmux's command limit |

## Parity coverage map

Of 39 rows in the parity ledger, **15 are fully pinned, 5 are partially pinned,
and 19 have no behavioral evidence at all**. A partial row has a test covering
one aspect, not the row.

The 19 unpinned rows were reclassified `replace` by owner decision on
2026-08-09; see [`feature-parity.md`](feature-parity.md).

### Pinned

| Parity row | Pinned by | Tests |
|---|---|---|
| Deterministic query/chat/ticket/memory/chatter/clarify routing | `conversation` | 41 |
| Short contextual follow-ups and pending Support composition intent | `conversation-state` | 3 |
| Canonical direct command registry, aliases, help, presets | `commands` | 7 |
| Telegram polling, chats, commands, reply correlation, inline approval | `telegram` | 8 |
| Client request portal | `support-inbox-query` | 3 |
| Internal raw output versus staff-published client reply | `support-review-wiring` | 3 |
| Support inbox query and formatting | `support-query`, `operational-query` | 13 |
| Support email compose, exact review and send | `support-email-compose`, `support-email`, `support-mailer` | 8 |
| Known managed sites and functional site summaries | `site-inventory`, `site-conversation` | 6 |
| Account/access explanations | `access-conversation` | 4 |
| Persona, job envelope and untrusted-context labels | `security-hardening` | 8 |
| Live action, heartbeat, transcript, stderr and telemetry | `spool-*`, `ndjson-lines` | 33 |
| Guard hooks and sandbox launcher | `codex-guard` | 3 |
| Dashboard live tickets, approvals, history, settings | `dashboard-ui`, `telegram-dashboard` | 21 |
| Ops-command proposal classification | `privileged-actions` | 3 |

### Partial

| Parity row | Covered | Not covered |
|---|---|---|
| Slack Socket Mode messages, mentions, threads, commands, actions | claim-once dedup | mention/thread routing, command dispatch, action handling |
| Human work approval | orphan gate adoption, no-reopen-after-button-removal | creation, expiry, supersession, eligible-actor policy |
| GitHub issue as durable ticket truth | split gates, idempotency, rollback, ack, retry (`manage-sync`) | issue body/state inspection, conflict handling |
| Four selectable agent backends and session-prefixed resume | Codex and Jcode backends | Claude and opencode backends, cross-provider resume safety |
| Provider execution approval | guard denials | approval as a distinct class with exact turn/item coordinates |

### Unpinned — no behavioral evidence exists

Reclassified `replace` on 2026-08-09. Automonique provides the outcome through
a new contract of its own design; there is no baseline for these to regress
against. The four marked **safety** must be re-specified deliberately in their
target requirement documents rather than left to emerge from implementation.

| Parity row | Why it matters |
|---|---|
| Multi-ticket split | parent/fan-in status has no test; `manage-sync` tests split *approval gates*, not the split itself |
| Delivery-team completion heuristics and reopen semantics | language-dependent behavior, explicitly needs language-neutral fixtures |
| Detailed GitHub report plus brief completion/link/mentions | idempotent publication separation is unproven |
| Dedicated deployment notifications channel | fail-closed behavior is a safety property with no test **safety** |
| Notes, notify rules and GitHub-to-Slack mapping | role-scoped CRUD and matching |
| Bounded per-user conversation history | limits, pruning, explicit clearing |
| Learned domain-to-server targets | currently a JSON file; becomes revisioned records |
| Announce target before action and show site/server/IP | a stop-check before workspace mutation — safety-critical **safety** |
| Site-platform knowledge-base files | release hash and workspace applicability |
| Bounded parallelism, per-thread serialization, pause and cancel | the scheduler core, entirely unpinned **safety** |
| Progress announcements (`legacy-say`) | scope/audience binding |
| Screenshot proof | artifact outcome |
| Scoped application KV operations | fixed typed operations boundary |
| Fleet/provisioning helper | supported API boundary |
| Live channel feed and post-as-assistant | read/post capability separation |
| Browser desktop notifications | permission UX and server-side state |
| Force ignored message into a ticket | original source identity, fresh approval gate |
| Delete user-authored message | separately authorized action; must never bundle with cleanup **safety** |
| Site digest and bounded one-shot assistance | bounded no-tools profile, timeouts |

The pattern is legible: **intake, conversation and support are well covered;
scheduling, notification, artifact and moderation behavior is not.** That is
the inverse of the risk ordering — the unpinned set contains the safety
properties (fail-closed deploy channel, announce-before-mutate, authorized
deletion) and the concurrency core.

## Durable state

16 tables, read read-only from the live database. This is what `R4` must
expand-migrate and what "import and preserve current legacy tables and IDs"
refers to.

Twelve carry a uniform legacy prefix; four do not, and that split is itself
information — the unprefixed four are the original schema.

| Table | Rows | Cols | Role |
|---|---:|---:|---|
| `tickets` | 29 | 23 | the central work record: status, timing, session, cost, target, site/server, actions log, **`partIndex`/`partCount`** (multi-ticket split), gate ts, fleet-sync flag |
| `sessions` | 27 | 3 | key → provider session id (this is the "session-prefixed resume" surface) |
| `memory` | 0 | 7 | notes and notify rules: kind, match, notifyIds, text, creator |
| `ignored` | 0 | 7 | ignored messages retained with reason, for force-into-ticket |
| `*_action_gates` | 23 | 13 | approval gates: prompt, parts, action, **`deliveryStatus`** separate from **`status`** |
| `*_pending_slack_gates` | 28 | 9 | gate keyed by thread, with permalink |
| `*_slack_events` | 39 | 10 | durable intake: event id, type, route, reason, status, completedAt |
| `*_telegram_updates` | 1 | 9 | durable intake with attempts/error |
| `*_telegram_messages` | 264 | 4 | chat/message → thread correlation |
| `*_telegram_state` | 1 | 2 | poller offset |
| `*_chat_messages` | 92 | 5 | bounded per-user conversation history |
| `*_pending_intents` | 0 | 8 | structured slots with **`expiresAt`** — the follow-up mechanism |
| `*_report_outbox` | 0 | 16 | terminal report with full token/cost telemetry |
| `*_manage_event_outbox` | 2 | 5 | fleet lifecycle outbox with attempts/backoff |
| `*_control_events` | 0 | 7 | pause/cancel/steer audit |
| `*_executor_runs` | 0 | 7 | privileged action execution record |

Observations that matter for the port:

- **Two outboxes already exist** (`report`, `manage_event`), both with
  `attempts`/`nextAt` backoff. The target's single typed outbox must subsume
  both without losing their distinct retry semantics.
- **`deliveryStatus` is separate from `status`** on action gates — transport
  delivery state is already distinguished from approval state. The target
  architecture makes the same split; this confirms it is load-bearing rather
  than new.
- **`pending_intents.expiresAt`** means follow-up scope already expires. Any
  reimplementation that treats follow-ups as "most recent message" loses a
  property the current system has.
- **No tenant column anywhere.** Identity is Slack/Telegram-native throughout.
  Tenancy is genuinely new in Automonique, not a port — every `R4` identity
  table is greenfield with no legacy rows to migrate.
- `tickets` carries `siteUrl`/`serverIp` inline, which is the
  announce-target-before-action data. It is a column, not an event.

## Configuration surface

~85 environment variables. All product variables share one uniform legacy
prefix, so the suffixes are listed here and the prefix noted once; `R0-13`
classifies each as durable, compatibility-only or presentation-only.

| Group | Variables (suffixes) |
|---|---|
| Storage / runtime | `DB`, `REPO_DIR`, `SPOOL_ROOT`, `WORKER_TMP_ROOT` |
| Concurrency | `MAX_CONCURRENCY`, `GLOBAL_MAX_CONCURRENCY`, `SPLIT` |
| Dashboard | `DASH_HOST`, `DASH_PORT`, `DASH_USER`, `DASH_PASS`, `DASH_TOKEN` |
| Fleet | `FLEET_ENABLED`, `FLEET_URL`, `FLEET_TOKEN`, `FLEET_POLL_MS`, `FLEET_HEARTBEAT_MS`, `FLEET_CONCURRENCY`, `FLEET_INSTANCE_ID`, `FLEET_LOCK_HARNESS` |
| Routing | `AGENT`, `MODEL`, `MODELS`, `CLASSIFY`, `CLASSIFY_MODEL`, `CONVERSATION_ROUTER_V2`, `CONVERSATION_ROUTER_SHADOW` |
| Sandbox / guard | `GUARD`, `GUARD_SETTINGS`, `WORKER_SANDBOX`, `WORKER_SANDBOX_BIN`, `CODEX_DANGER_FULL_ACCESS` |
| Terminal | `TMUX_EXEC`, `TMUX_SOCKET`, `TERM_COLS`, `TERM_ROWS`, `TERM_IDLE_TTL_MS` |
| Provider (per-backend) | `JCODE_*` (10 vars: home, model, provider, profile, tools, disabled tools, policy version, daemon socket canary ×3) |
| Intake | `SLACK_EVENT_DEDUP_TTL_MS`, `MANAGE_SLACK_SYNC` |
| Mailer | `SUPPORT_MAILER_PATH`, `SUPPORT_MAILER_NODE`, `SUPPORT_MAILER_ENV` |

Unprefixed, and therefore credentials or third-party contracts:
`SLACK_BOT_TOKEN`, `SLACK_DELETE_TOKEN`, `SLACK_CHANNELS`,
`SLACK_DEPLOY_CHANNEL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_POLL_TIMEOUT_SEC`,
`POSTMARK_TOKEN`, `CLAUDE_*` (6), `CODEX_*` (2), `OPENCODE_*` (2), `TMUX_BIN`.

`SLACK_DELETE_TOKEN` being a **separate token** from `SLACK_BOT_TOKEN` is the
existing implementation of "delete is a separately authorized action." The
parity ledger states that as policy; the credential split is how it is enforced
today.

A JSON settings file carries the runtime-mutable subset: `agent`,
`allowedChannels`, `allowedUsers`, `classifyEnabled`, `classifyModel`,
`confirmers`, `maxConcurrency`, `model`, `models`, `splitEnabled`. These are
the settings the dashboard writes, so they are the ones needing revisioned
settings records in the target.

## External effect surface

Every outward-facing call the system can make. This is the set that must move
behind the typed outbox.

**Chat platform:** `chat.postMessage`, `chat.update`, `chat.delete`,
`chat.postEphemeral`, `chat.getPermalink`, `reactions.add`,
`conversations.history`, `conversations.replies`, `conversations.info`,
`conversations.members`, `users.info`, `users.list`, `auth.test`.

Thirteen methods, of which **three mutate** (`postMessage`, `update`,
`delete`) and one is quasi-mutating (`reactions.add`). The parity ledger's
"read/post capabilities separated and fully audited" applies to exactly those
four.

**Outbound hosts:** the messaging platform APIs, a transactional email
provider's inbound endpoint, the source host, a loopback address, and three
first-party domains (client portal, fleet console, support portal). Font and
CDN origins appear in dashboard markup — a target that embeds assets must
account for them or the dashboard degrades offline.

## Dashboard API

38 routes. This is the surface `R8A`/`R8C` must reproduce through the generated
SDK with no private endpoints.

| Group | Routes |
|---|---|
| State | `/api/state`, `/api/history`, `/api/runs`, `/api/ticket` |
| Work | `/api/submit-ticket`, `/api/followup-ticket`, `/api/rerun-ticket`, `/api/force-ticket`, `/api/cancel`, `/api/pause`, `/api/concurrency` |
| Approvals | `/api/confirm`, `/api/reject` |
| Memory | `/api/memory`, `/api/memory/add`, `/api/memory/remove` |
| Targets | `/api/target`, `/api/targets`, `/api/targets/add`, `/api/targets/remove` |
| Ignored | `/api/ignored/remove` |
| Chat bridge | `/api/slack/history`, `/api/slack/members`, `/api/slack/channel-members`, `/api/say`, `/api/announce` |
| One-shot | `/api/oneshot`, `/api/oneshot/start`, `/api/oneshot/result`, `/api/site-digest` |
| Ops | `/api/ops-command`, `/api/deploy-webhook`, `/api/settings`, `/api/telegram` |
| Terminal | `/api/term`, `/api/term/`, `/api/term/upload`, `/api/term/download`, `/api/term/kill` |

The five terminal routes are the isolated-shell subsystem the parity ledger
marks *isolate*, including the base64 upload/download path it says must be
replaced by artifact APIs.

## Command and route vocabulary

**Commands (21):** `approvals`, `attention`, `cancel`, `failures`, `help`,
`id`, `ignored`, `new`, `queue`, `requests`, `retry`, `runs`, `sites`,
`status`, `steer`, `support`, `ticket`, `tickets`, `usage`.

**Conversation routes (13):** `query`, `chat`, `chatter`, `clarify`, `ticket`,
`tickets`, `memory`, `site`, `sites`, `access`, `support`, `support_email`,
`support_email_compose`.

The router has a **v2 behind a flag with a shadow mode**
(`CONVERSATION_ROUTER_V2`, `CONVERSATION_ROUTER_SHADOW`). A shadow-comparison
mechanism already exists in the legacy tree — the migration plan's shadow
classification step has a working precedent to match, not invent.

## Companions and operational scripts

**Companions (8):** a Codex guard, a guard binary, a sandbox (with C source), a
factory/provisioning helper, a KV helper, a progress-announcement helper, a
screenshot helper (Python), and a knowledge-base directory.

Two are compiled or non-TypeScript (the sandbox is C, the screenshot helper is
Python), which is why the parity ledger says companions need not be rewritten
for language purity but must ship as checksummed release assets.

**Operational scripts (10):** an audit, a benchmark, two build scripts, a
deploy-broker installer, a bootstrap bundler, and **four reconcilers** —
feedback-thread statuses, orphan gates, stale gates, and request reactions.

Those four reconcilers are the concrete content of the parity ledger's
"reconciliation and audits" section and of `R7-18`.

## Scheduled work

| Interval | Job |
|---|---|
| 2 s | flush fleet log |
| 15 s | drain chat lifecycle outbox |
| 30 s | drain report outbox |
| 60 s | reconcile orphan approval gates |
| configurable | fleet poll, fleet heartbeat |
| periodic | dashboard prune, spool reaper |

Six recurring jobs plus two configurable fleet timers. Every one becomes fenced
scheduled work in the target; none may run in two generations at once, which is
what the reload protocol's lease fencing is for.

## Deployment and runtime shape

Two user units, read from the live system:

| | Ticket bot | tmux server |
|---|---|---|
| `Type` | `simple` | `forking` |
| `Restart` | `on-failure` | `on-failure` |
| `KillMode` | default | **`process`** |
| `ExecStart` | a bundled `index.js` under a **current-release symlink** | a detached keepalive session |
| Resource limits | none | none |

Three findings that change how the port should be scoped:

1. **There is no graceful reload today.** No `Type=notify-reload`, no
   `ExecReload`, no `NotifyAccess`, no `MAINPID` transfer. Upgrading is a hard
   restart. Automonique's entire generation-handoff design is therefore **new
   work, not a port** — there is no existing behavior to preserve or regress
   against, and `R0-03` is a genuine spike rather than a re-implementation.
2. **Runner survival is achieved by `KillMode=process` on a separate unit.**
   That is the whole of the current isolation between daemon lifetime and
   execution lifetime. The target's transient-unit-per-attempt design is a
   large step up from a single shared tmux server.
3. **No resource limits exist anywhere.** No `MemoryMax`, no `CPUQuota`, no
   cgroup budgets. Every sandbox, quota and budget contract in
   `sandbox-management.md` is greenfield.

The current-release symlink pattern already exists and matches the target's
`.automonique-current` selector, so release selection is one of the few
mechanisms that ports directly.

## State vocabulary

Status literals in use across subsystems:

`queued`, `pending`, `running`, `processing`, `done`, `completed`, `error`,
`failed`, `cancelled`, `posting`, `posted`, `disabled`, `missing`, `ok`,
`unknown`, `unsupported`.

These overlap: `done`/`completed`, `error`/`failed`, `queued`/`pending`,
`running`/`processing` are four pairs of synonyms used by different subsystems
for the same concept. Live data shows only a subset in use
(`tickets.status` currently holds `done` and `error` only).

The target must define **one canonical enum** and map legacy values onto it in
the expand migration. Carrying both members of a synonym pair forward would
reproduce an accident.

## What is a port and what is new

The single most useful output of this inventory, for scoping:

| Genuinely a port | Genuinely new |
|---|---|
| intake, routing and approval flows (well tested) | generation handoff and reload |
| the two outboxes and their backoff | tenancy and identity (no tenant column exists) |
| spool framing and retention | sandbox, cgroup and resource budgets |
| dashboard surface (38 routes) | typed artifact service |
| command and route vocabulary | domain event journal and action receipts |
| release-selector symlink | workspace registry and worktree isolation |
| provider adapters for two of four backends | provider capability negotiation and session proxying |

The right-hand column is where the risk is, and none of it can be validated
against the legacy system because none of it exists there.

## Retired fixture safety

The retired fixture suite is not part of supported operations and must not be
run against production state. Its historical database defaults were unsafe by
construction; retain captured evidence as read-only input instead of executing
that suite on a live host.

## What this changes for the plan

- `R0-01` (current contract inventory) is substantially delivered by this file;
  what remains is the per-row owner assignment.
- `R0-08` (machine-readable parity ledger) now has a populated `fixture` and
  `evidence` column on all 39 rows; 20 name a real test, 19 record `none` with
  a disposition rather than an assumption.
- The 19 unpinned rows are **not** characterization work. The owner decided on
  2026-08-09 to replace rather than preserve them, so the legacy tree needs no
  new tests. Four are safety properties that must be re-specified deliberately
  in their target requirement documents.
