# M6 — Streaming UX & connector modernization (implementation plan)

Modernizes the chat surfaces to native streaming behind one normalized
progress-event stream (SOTA §1/§5/§6), and hardens the provider adapter into a
persistent-session model with cooldowns and fallbacks. Grounded at `c2f8b16`;
introduces **no** new dependencies (composes from `std::thread` + the 11 pinned
crates). Covers issues #36, #37, #38, #39, #40, #56.

## Verified ground truth the plan builds on
- **Telegram client** (`automonique-transport-runtime/src/https_client.rs`):
  closed private `WireMethod` enum with exactly 4 methods (getUpdates,
  sendMessage, setMessageReaction, setMyCommands); `canonical_body()` renders
  exact token-free JSON; 429 already surfaces as `HttpFailure::RateLimited {
  retry_after_ms }` (clamped 1s–300s).
- **The poller lease is a store operation, not a Telegram call:**
  `TELEGRAM_LEASE_TTL_MS = 20_000` (`daemon/src/lib.rs:284`),
  `TELEGRAM_HTTP_LEASE_MARGIN_MS = 5_000` (transport-runtime `lib.rs:54`).
  Renewal can continue during an API pause.
- **The outbox drain** (`daemon/src/telegram_bridge.rs:5602
  drain_telegram_outbox`) already supports per-intent retry via
  `fail_telegram_outbound(&lease, Some(retry_after_ms), "rate_limited", …)` and
  stops the drain on a 429 — but the pause is per-drain-loop only, not bot-wide
  and not durable.
- **The runner spool** (`automonique-runner/src/spool.rs`) is hash-chained
  NDJSON with `EventKind::AdapterEvent` already in the vocabulary (mirrored in
  `automonique-protocol/src/runs_api.rs` as `SpoolEventKind::AdapterEvent`) —
  **but nothing appends it**: the backend appends only `Started` + one terminal,
  and the workload's stdout is `Stdio::inherit()` (`launch.rs:754`). The
  provider's JSONL stream is unread in production; the answer comes back as a
  file (`compose.rs` answer_path).
- **`automonique-protocol/src/event.rs` already defines** a 23-variant
  normalized `EventKind` (session/turn lifecycle, ToolCallStarted/Updated/
  Completed, ApprovalRequested/Resolved, Subagent*, UsageUpdated, ProviderWarning/
  Fault, RunTerminal), an `Authority` split enforced by types (PreviewEvent
  cannot enter RunTimeline — compile-fail doctest), `ConsumerCursor`, and
  `SubscriptionStart::ResyncRequired { snapshot_from, snapshot_to }`. **#36 is
  mostly wiring + codegen, not invention.**
- **The runner control socket** (`automonique-runner/src/control.rs`) is the
  cursor prior art: `subscribe <attempt-id> <cursor>` returns ≤8 events + `end
  <next-cursor> <more>`, with `Refusal::CursorAhead`; same-uid `SO_PEERCRED`
  admission before any byte is parsed. The daemon deliberately does **not** use
  `AttemptSupervisor`/control sockets (`execute.rs` doc, ~line 83) — no peer can
  subscribe to a live attempt today.
- **Provider substrate:** `automonique-agents` has the incremental
  `ProviderEventStream` (refusal-first: unknown event/invalid line/truncated
  tail all poison the stream) over the codex `thread.*/turn.*/item.*` grammar;
  `automonique-store/src/provider_journal.rs` models processes/sessions/turns/
  requests/cursors/bindings/approvals with one-live-per-attempt and
  one-open-per-process STRICT constraints plus `recover_attempt`.
- **Session substrate (#39):** `automonique-store/src/agent_memory.rs` has
  `identity_bindings`, `conversations` (with `archived_at_ms`),
  `conversation_heads` PK (tenant, actor, transport, external_scope), and `/new`
  already exists in the closed `CommandKind` registry (`telegram_control.rs`).
- **Slack connector:** closed `SlackMethod` enum, 9 methods incl.
  ChatPostMessage/ChatUpdate; 429 already decoded with `retry_after_seconds`;
  hermetic plaintext-loopback test base exists.
- **SDK codegen:** `automonique-protocol/src/codegen.rs` `maintained_modules()`
  + drift gate in `tests/codegen.rs`; new vocabularies are added as a
  `GeneratedModule` (+ optional `CommandSurface`).

## Recommended order
1. **#36 first, alone** — the keystone (vocabulary + emission + spool
   persistence + minimal hub). Land the protocol/codegen half early so the TS
   SDK drift gate bakes.
2. Then three parallel tracks: **(a) #37 → #38** (generic budgeter core +
   transport-pause substrate land in #37; #38 reuses them); **(b) #39**
   independently; **(c) #56** after #36 (grows the hub in place).
3. **#40 last** — depends on #36's stream, largest sandbox-semantics change,
   benefits from #39's thread↔session binding, and its deployment-router touches
   `run_lane.rs` which #37 also edits.

### Issue #36 — One normalized progress-event stream (AG-UI-shaped vocabulary)
**Current state.** The 23-variant `EventKind` and authority split already exist
in `event.rs`; the spool has an unused `AdapterEvent` kind; workload stdout is
`Stdio::inherit()` so the provider's JSONL is unread in production.

**Approach.** Reuse and extend the existing vocabulary rather than minting a
second. Extend with (a) a `RetryContext` body on ProviderWarning/ProviderFault
(category, retryable, retry_after_ms, attempt ordinal) and (b) a `StepStatus ∈
{pending, in_progress, completed, error}` field on ToolCall*/Subagent* bodies so
Slack task cards and the desktop client render without re-deriving state; then a
wire shape in a new `progress_api.rs` (`ProgressFrame { run_id, sequence, at_ms,
authority, kind, body }`, canonical JSON, new `GeneratedModule` with drift gate).
Emission: the backend gains progress capture — workload stdout switches to
`Stdio::piped()` for provider-profile runs, a per-attempt reader thread feeds
`ProviderEventStream`, mapped events go over an mpsc that the backend's existing
SUPERVISION_POLL loop drains (the backend is the spool's single flock-holding
writer) and appends as spool `AdapterEvent` — payload = canonical ProgressFrame
body ≤ 64 KiB (`MAX_EVENT_PAYLOAD_BYTES`), Authority::Authoritative for Recorded
events, Authority::Synthetic for coalesced preview deltas (flush at ≥1 KiB or
≥750 ms, so previews cannot exhaust the spool budget). Persistence/replay: the
hash-chained per-attempt spool is the durable record (its sequence is the
cursor); live replay goes through a new minimal `daemon/src/progress_hub.rs`
(per-attempt bounded in-memory ring keyed by spool sequence, fed by the attempt
worker in `execute.rs` alongside the spool append — because the spool's
exclusive flock makes it unreadable mid-run); after terminal the re-opened spool
serves full-fidelity replay. Renderers: CLI (`automonique runs tail <run>`),
Telegram and Slack renderer seams consuming the same frames (native transports
land in #37/#38).

**Files.** `automonique-protocol/src/{event.rs, progress_api.rs (new),
codegen.rs, lib.rs}` + `tests/codegen.rs` + generated/ + TS SDK regen;
`automonique-runner/src/{backend.rs, launch.rs}`; `automonique-agents/src/
{normalize.rs, types.rs}`; `automonique-daemon/src/{execute.rs, progress_hub.rs
(new), telegram_bridge.rs, slack.rs}`; `automonique-cli/src/` (tail verb).

**Testing.** codegen drift gate + TS typecheck; exhaustive RecordedKind×item-kind
→ EventKind mapping test (closed-set style); spool round-trip (append
AdapterEvents → reopen → chain verifies → `events_after(cursor)` pages
byte-identically); backend hermetic test with a scripted fake provider emitting
fixture JSONL; coalescing-bound test (preview flood stays under budget); renderer
snapshot tests for CLI/Telegram/Slack.

**Effort.** L. **Dependencies.** none (keystone).

**Risks/decisions.** (1) Spool budget: progress events spend the run's admitted
`spool_budget_bytes` — decide coalescing constants and whether provider-profile
runs get a larger admitted budget; a run must never fail because it streamed too
much (on exhaustion, stop persisting previews, keep Recorded events, emit one
ProviderWarning). (2) `execute.rs`'s error arm hardcodes `(RunSpoolState::Failed,
2)` — the "2" assumes Started+Terminal only; must become the observed last
sequence. (3) Do not regress the answer-file contract (stdout capture is
additive). (4) The refusal-first normalizer poisons a stream on one bad line —
acceptable here (a poisoned stream ends progress rendering; the run is
unaffected); lenient policy is #40's scope. (5) Keep ProgressFrame bodies free of
raw provider lines (existing `UnknownEventKind` sanitization).

### Issue #37 — Telegram streaming via sendMessageDraft plus an API-call budgeter
**Approach.** Client: add `WireMethod::SendMessageDraft` and
`WireMethod::EditMessageText` (documented fallback) to the closed enum with
validated request types and exact `canonical_body()` renderings + tests.
Budgeter: new `automonique-transport-runtime/src/budget.rs` —
`TelegramCallBudget`, a deterministic token-bucket set (global ~30/s; per-chat
1/s; per-group 20/min) accounting **every** WireMethod claim including
getUpdates, with an injected clock (no async, no timer thread; claims checked at
call sites the loop already visits). Two priorities: durable (outbox intents,
reactions, menus) and ephemeral (draft updates) — ephemeral succeeds only with
configured global headroom, so streaming never starves final replies. Whole-bot
429: any `RateLimited` sets a bot-wide pause deadline persisted in a new STRICT
`transport_pauses` table (store ladder v+1) so a restart honors it; during the
pause the poller keeps renewing the durable lease (a store write, no Telegram
call) and skips getUpdates until the deadline — lease epoch and committed offset
untouched, and Telegram's 24 h update retention means nothing is lost; the outbox
absorbs the send backlog. Rendering: `RunLane` gains a progress seam inside
`run_lane.rs`'s `await_terminal` 50 ms poll loop — drain hub frames, coalesce
into a ≤4096-UTF-16-unit draft snapshot, claim an ephemeral token, send
sendMessageDraft; the final answer still travels the durable outbox. Drafts are
never staged in the outbox (ephemeral, superseded by the next snapshot).

**Files.** `automonique-transport-runtime/src/{budget.rs (new), https_client.rs,
lib.rs}`; `automonique-store/src/lib.rs` (transport_pauses ladder);
`automonique-daemon/src/{telegram_bridge.rs, telegram.rs, run_lane.rs, lib.rs}`.

**Testing.** canonical-body fixtures for both new methods (exact byte
assertions); budget unit tests with a fixed clock (interaction, headroom rule,
draft-starvation impossibility); synthetic-429 end-to-end (pause row written,
drain stops, poller issues zero getUpdates but N lease renewals during the pause,
drain resumes FIFO after the deadline, offset receipt unchanged); restart-under-
pause; ladder migration test.

**Effort.** L. **Dependencies.** #36 (renders its stream; the budgeter is
standalone and can land first).

**Risks/decisions.** (1) sendMessageDraft needs api.telegram.org ≥ 9.5 — a
rejected method must be *detected*, not retried: add a bounded typed decode of
Telegram's `{ok:false,…}` for the draft path and latch a per-boot "drafts
unsupported" flag falling back to editMessageText throttled ≥3 s (why
EditMessageText ships in the same change). (2) Pin the exact sendMessageDraft
field set from the SOTA capture before writing fixtures (canonical body is
fixture-locked). (3) The 20 s lease vs long-poll interplay is asserted in tests
(`transport_timeout_stays_inside_lease_margin`) — extend that family, don't
weaken it. (4) Draft snapshots quote provider output: existing `is_sendable_text`
control-char refusals apply; truncate on UTF-16 boundary, never mid-escape.
(5) A 429 blocks the whole bot — the pause gates getUpdates too, accepting up to
retry_after of added inbound latency.

### Issue #38 — Slack native streaming with thinking-steps task cards
**Approach.** Connector: extend `SlackMethod` with `ChatStartStream`,
`ChatAppendStream`, `ChatStopStream` plus validated request types (start:
channel + thread timestamp; append: channel + stream timestamp + bounded
markdown/chunks; stop: channel + stream timestamp +
optional `MessageBlocks`, reusing the existing 32 KiB/50-block Block Kit
validation so rich formatting exists only at stop) and response decoders for the
stream handle. Budgeter: extract the generic token-bucket core from #37's
`budget.rs` (it lives in transport-runtime, which hosts `slack_sink.rs`, so no
new crate) and instantiate a `SlackCallBudget` with tiered per-method limits and
central `Retry-After` honoring (the connector already surfaces
`retry_after_seconds`; today merely reported). Renderer: in `daemon/src/slack.rs`
consume #36 frames — ToolCall*/Subagent* frames with StepStatus become native
`task_update` chunks (one transition at a time, timeline order),
coalesced preview text becomes appendStream chunks, and the final answer lands as
Block Kit in stopStream only. Fallback: when the triple is rejected
(`unknown_method`/feature-gated), latch per-boot and fall back to
chat.postMessage + chat.update throttled ≥3 s.

**Files.** `automonique-slack-connector/src/{request.rs, response.rs, client.rs,
lib.rs}`; `automonique-transport-runtime/src/budget.rs` (generic core split);
`automonique-daemon/src/slack.rs` (renderer + budget + fallback latch).

**Testing.** hermetic loopback-fake tests asserting exact wire bodies/paths of
the three methods; decoder tests incl. error codes and 429-with-Retry-After
pausing the Slack budget; renderer fixture test (fixed frame sequence → exact
ordered start/append/stop with Block Kit only in stop); fallback test (rejection
→ post+update with the 3 s throttle under a fake clock); shared budget tier tests.

**Effort.** M. **Dependencies.** #36 (frames), #37 (generic budgeter core).

**Risks/decisions.** (1) Slack streaming is tied to the Agents/AI-Apps surface —
the token's app class may lack it; the fallback latch is a first-class path with
its own tests. (2) Socket Mode remains ingest for now (HTTP Events API migration
is out of M6 scope; note in the connector doc). (3) A daemon restart mid-stream
orphans the handle — stopStream on a best-effort startup sweep, and the final
answer must never depend on a live handle. (4) ~1 msg/s/channel governs the
fallback path; the budgeter owns that arithmetic.

### Issue #39 — Thread-session lifecycle verbs and a modifier grammar
**Approach.** Session binding: `conversations`/`conversation_heads` are already
keyed by (tenant, actor, transport, external_scope) — extend the scope grammar
the daemon derives (today `external_scope(chat_id)` in `StoreMemorySurface`) to
thread granularity: Telegram `chat/<id>/topic/<message_thread_id>` in forum
groups, Slack `channel/<id>/thread/<thread_ts>`; DMs keep the bare chat scope
(shared primary session), groups get per-thread isolation (SOTA defaults).
Binding rows are durable, so "stable session across restarts" falls out of the
existing tables; add `muted_until_ms` to `conversations` via the agent-memory
ladder (archive already exists). Lifecycle verbs: add `CommandKind::Mute` and
`CommandKind::Archive` to the closed registry in `telegram_control.rs` (`/new`
already exists) — update `ALL`, `COMMAND_COUNT`, the spec/tier table (both
`allowed` tier), help text, and the mirrored exhaustiveness tests; wire Slack
equivalents. Modifier grammar: new `automonique-transport-runtime/src/
modifier.rs` — closed `MessageModifier` enum (`!new`, `!fast`, `!ask`, `!think`,
`!model <alias>` over a closed alias set) with `const ALL_MODIFIERS`, scanned as
whole `!word` tokens before command parsing; parsing returns (modifiers, residual
text); an unknown `!token` is a typed `CommandRefusal` naming the closed set
(refusal-first, composes with — never replaces — the slash registry). Modifiers
map onto existing routing seams: `!fast`/`!ask`/`!think` select
`QuestionProfile`/`ProviderRunProfile`; `!new` rotates the conversation head.

**Files.** `automonique-store/src/agent_memory.rs` (scope producers,
muted_until_ms ladder, verb transitions); `automonique-transport-runtime/src/
{telegram_control.rs, modifier.rs (new), lib.rs}`; `automonique-daemon/src/
{telegram_bridge.rs, slack.rs}`.

**Testing.** registry closed-set tests extended (the existing exhaustiveness
family); modifier parser exhaustive tests (every member parses; unknown/case-
variant/mid-word tokens refuse with the exact typed refusal; residual byte-exact);
store tests (head stability across reopen, per-thread isolation vs DM sharing,
mute window + archive transitions revision-checked); bridge dispatch tests with
fixtures carrying `message_thread_id` / Slack `thread_ts`.

**Effort.** M. **Dependencies.** none (composes with #36's renderers but doesn't
require them).

**Risks/decisions.** (1) Scope-string migration: existing bare-scope heads must
be treated as the DM/legacy session, not orphaned — the derivation is versioned,
not a data rewrite. (2) Modifier collision with quoted content: whole-token scan
+ "modifiers only in operator-authored messages" rule; pin the code-fence choice
in tests. (3) `!model` aliases are a closed vocabulary resolved against configured
providers only, never a free string. (4) Mute semantics: recommend suppress
outbound *and* skip provider spend until unmuted/expired.

### Issue #40 — Provider adapter hardening: persistent subprocess, cooldowns, fallbacks
**Approach.** Session-scoped process: add a second closed argv shape to
`automonique-agents/src/spawn_plan.rs` for long-lived NDJSON mode (today the
single Codex shape is one-shot `exec [resume <session>] --json -`), and a new
`daemon/src/provider_session_host.rs` owning at most one live provider process
per session under the existing sandbox composition, with launch changes to keep
fd 0 as a supervisor-held pipe (turn prompts are NDJSON writes, replacing memfd
delivery for this profile) and a new admission profile in
`automonique-runner/src/admission.rs`: no run deadline; an idle TTL and
kill-on-session-close instead; same cgroup kill-tree, Landlock, seccomp,
descriptor-closure verification. Every lifecycle edge is journalled in
`provider_journal`; daemon startup runs `recover_attempt` so a crash-orphaned
session is marked lost, never reused. Failure rules verbatim as explicit policy:
`ProviderEventStream` gains `StreamPolicy::{Strict, Session}` — Session skips an
invalid JSONL line, increments a per-turn warn counter, emits a `ProviderWarning`
frame (never silent; Strict + rationale stay for fixtures); a stream ending
without terminal `result` or a non-zero exit maps to `TurnCompleted(ok=false)`/
Failed. Routing: a new STRICT `provider_deployments` table (deployment id,
failure counter, cooldown_until_ms, ordered fallback rank, context-window rank)
consulted by the selection seam `run_lane.rs` already owns; 3–5 failures/min
trips a 30–60 s per-deployment cooldown while siblings serve; a typed
context-window fault routes to the separate context-window chain; health probes
run as a dedicated daemon worker thread (the `improvement_worker.rs` pattern),
probing cheaply (version handshake, never a token-spending turn) and evicting
before a user request fails.

**Files.** `automonique-agents/src/{spawn_plan.rs, stream.rs, normalize.rs,
types.rs}`; `automonique-runner/src/{admission.rs, launch.rs, backend.rs}`;
`automonique-daemon/src/{provider_session_host.rs (new), run_lane.rs, execute.rs,
compose.rs, lib.rs}`; `automonique-store/src/{provider_journal.rs (touch only if
a column is genuinely missing), provider_deployments module + ladder}`.

**Testing.** parse-level chaos suite (truncated stream, garbage line mid-stream,
missing terminal result, non-zero exit — each asserting the specified outcome and
the warn-counter/ProviderWarning under Session while Strict still refuses);
turn-2 reuse test with a scripted fake provider counting spawns (exactly one
across two turns); journal recovery test (SIGKILL mid-turn, reopen,
`recover_attempt` marks process lost and open turn aborted, next turn spawns
fresh); cooldown tests under a fake clock; fallback-order tests incl. the
context-window chain; idle-TTL and kill-on-close containment tests reusing the
backend's kill-tree assertions.

**Effort.** L. **Dependencies.** #36 (session turns emit into the normalized
stream); #39 partially (thread↔session identity makes chat-surface turn-2 reuse
real; #40 can land keyed on run-lane sessions first).

**Risks/decisions.** (1) Largest sandbox-semantics change in the milestone: a
long-lived process breaks the run-to-terminal assumptions in admission/backend —
the new profile is a separate admitted shape, refusal-first, never a relaxation
of the one-shot path. (2) The lenient line policy deliberately contradicts the
agents crate's refusal-first rationale; make it a named policy with the warn
counter surfaced in frames and Strict kept default for fixtures; record the
deviation in the crate doc. (3) The spawn-plan TOCTOU gap (hash-then-exec-path)
gets a longer exposure window with a persistent process; note it and defer to M8
#48 (execveat) rather than half-fixing. (4) Idle sessions hold memory, a cgroup,
and possibly provider-side state: idle TTL + a hard cap on live sessions, both
admitted numbers. (5) Verify the NDJSON session mode against the pinned codex
version before freezing the argv shape. (6) No async: one thread per live session
(bounded by the cap) drains the stdout reader — state the thread budget in the
module doc.

### Issue #56 — Resumable event streams: bounded fan-out, cursors, capability versioning
**Approach.** Generalize #36's `progress_hub.rs` into the daemon's fan-out
authority, modeled on the runner control socket's proven shape but push-capable:
per-attempt ring retains frames keyed by spool sequence (bounded in bytes and
messages, time-shaped retention after terminal, then the durable spool is the
record); each subscriber gets a bounded queue (bytes and messages) drained by a
dedicated writer thread — on overflow the producer never blocks: drop the
subscriber's whole stale queue, enqueue exactly one terminal `lagged` frame,
disconnect; the client reconnects with its cursor and either resumes exactly or
receives a distinguishable cursor-too-old refusal carrying the oldest available
cursor (the protocol shape already exists as `SubscriptionStart::ResyncRequired`
in `event.rs`). Transport: a new dedicated Unix socket (`progress.sock` beside
the admin socket — `control.rs` is the precedent for a second purpose-bound
socket) with the same `SO_PEERCRED` same-uid admission-before-parse, speaking
framed canonical JSON from `progress_api.rs` (`Subscribe { run_id, cursor }` →
frames / CursorTooOld / Lagged); Telegram/Slack renderers stay in-process cursor-
pollers (the long-poll-over-cursor model SOTA recommends — a bridge restart
resumes from its cursor for free). Capability versioning: a monotonic
`ADMIN_CAPABILITY: u32` const with an append-only changelog in its doc comment
(bumped for additions, removals, and behavior-fixing bug fixes) plus a `const
ENDPOINT_MATURITY: &[(&str, Maturity)]` table (`Experimental/Stable/Deprecated`)
covering every admin/runs/execute/progress endpoint; surfaced in the greeting and
`DaemonStatus`, codegen'd to the TS SDK. Document normatively: a transport
disconnect is never a cancellation (cancellation remains the explicit dispatcher
path in `attempt_host.rs`). Export hub metrics through automonique-observability
(queue high-water, drops, lag disconnects, oldest retained cursor age).

**Files.** `automonique-daemon/src/{progress_hub.rs, lib.rs (socket bind +
serve)}`; `automonique-protocol/src/{progress_api.rs, admin.rs (capability in
status), codegen.rs, lib.rs}`; `automonique-observability` (new metric names);
`automonique-cli` (subscribe/resume verb); protocol tests + generated/ + TS regen.

**Testing.** slow-subscriber test (tiny queue, flooding producer → producer never
blocks, subscriber gets exactly one terminal lagged frame then disconnect, run
reaches its own terminal untouched); resume test (disconnect mid-stream, reconnect
with cursor, byte-exact continuation checked against the spool's hash chain);
cursor-too-old test (oldest-cursor payload); disconnect-is-not-cancel test;
capability tests (integer present in greeting/status; a snapshot test making the
changelog/maturity table append-only); metric assertions via the observability
snapshot.

**Effort.** M. **Dependencies.** #36 (frames and hub seed).

**Risks/decisions.** (1) Thread budget under no-async: one writer thread per
connected subscriber — bound subscriber count explicitly (CLI + two connectors +
one desktop client ≈ 8 max, refuse beyond) and join every writer on disconnect.
(2) Ring sizing is a policy number: retention must cover a bridge restart
(seconds) without pretending to be the durable record — the spool is; document
the two-tier replay story. (3) The lagged terminal frame must be distinguishable
from the run's own RunTerminal frame (two closed-vocabulary kinds).
(4) The append-only capability snapshot test is part of the definition, not
optional. (5) Do not fold this into the admin request/response socket — its
one-request-one-response framing is load-bearing for the serve thread; the
separate socket keeps the serve loop single-threaded.

## Cross-cutting notes
Every new table is a STRICT ladder step with a migration-replay test; every new
vocabulary ships with its `const ALL_*` exhaustiveness test and, where
wire-visible, a codegen module behind the drift gate. New threads (stdout reader
per attempt in #36, writer per subscriber in #56, probe worker in #40, one per
live session in #40) are all bounded and joined — state each budget in the owning
module doc. M6 introduces **no** new dependencies: everything composes from
`std::thread` + the 11 pinned crates. The protocol + generated SDK are touched by
M6 as well as M1-scrub and M7 — sequence those merges and keep PRs single-purpose.
