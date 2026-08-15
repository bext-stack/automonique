# State-of-the-art survey (2026-08) and applicability to Automonique

Status: external survey conducted 2026-08-15 from live primary sources, to
calibrate the improvement program in [`roadmap.md`](roadmap.md) against what
the strongest comparable systems do today. Each section ends with an
applicability verdict for a single-node, local-first, Rust + SQLite control
plane driving Slack and Telegram. Findings register:
[`audit-findings.md`](audit-findings.md).

---

## 1. ChatOps control surfaces for agents

Reference systems: Slack Agents & AI Apps platform, Claude in Slack, Devin's
Slack integration, GitHub Copilot cloud agent, and OpenClaw (the closest
structural analogue: a self-hosted single-daemon gateway bridging
Telegram/Slack/WhatsApp to agent sessions).

**Native streaming has replaced message-editing on both platforms.**
- Slack: `chat.startStream` → `chat.appendStream` → `chat.stopStream`;
  Block Kit only in the stop call; the legacy post-then-`chat.update`
  fallback is throttled to ~1 update / 3 s.
- Telegram: `sendMessageDraft` (Bot API 9.3, universal since 9.5,
  2026-03-01) renders a natively animating draft and replaces the
  send-then-`editMessageText` pattern every bridge used through 2025.

**Structured progress, not text walls.** Slack's thinking-steps pattern
streams typed chunks — markdown, task cards (one tool call with status),
plans (grouped task cards), sources — in plan or timeline display modes with
`pending/in_progress/completed/error` states.

**Thread-as-session with an explicit lifecycle vocabulary.** Devin binds a
Slack thread bidirectionally to a session with verbs like mute/sleep/archive;
OpenClaw isolates a session per group channel and shares the primary session
in DMs; Claude in Slack keeps one shared agent per channel with channel-scoped
memory. A bang-modifier grammar (`!fast`, `!ask`, `!new`, …) recognized
anywhere in a message is the current best answer to mode/model selection
without a settings UI.

**Approval affordances have sharp, documented edges.**
- Slack interaction handlers must ack in 3 s or Slack retries → button
  handlers **must be idempotent**; the message must be edited after a
  decision so stale buttons cannot be clicked (a real-world fail-open of
  exactly this class is on record in a public agent project).
- Telegram `callback_data` caps at 64 bytes → carry an opaque approval ID
  only; edit the keyboard away after the decision.

**Rate limits to design against.** Slack: tiered per-method limits,
~1 msg/s/channel, 30k events/workspace/hour, honor `Retry-After`. Telegram:
~30 msg/s global, ~1/s per chat, and a 429 blocks **the whole bot**;
*every* method call counts (an approval interaction is easily 3 calls).
Production consensus prefers HTTP Events API over Socket Mode for Slack
(Socket Mode = one process per app, reconnect overhead); Telegram rejects
concurrent `getUpdates` with 409 — which validates the existing poller-lease
discipline.

**Governance rules are explicit now.** Slack's agent-governance guidance:
never masquerade as a human; an agent must not read anything the invoking
user couldn't; least-privilege scopes; pause/resume/stop controls; audit
fields (user, agent identity, tool invocations, model version, tokens,
errors, latency). Frame: "bounded autonomy" that expands as trust is earned.

**Applicability: high.** Adopt one internal progress-event stream rendered
via `sendMessageDraft` on Telegram and start/append/stop on Slack; model
progress as plan/task-card events; make approval handlers
idempotent-by-construction (approval ID in `callback_data`, decision recorded
once in SQLite, keyboard stripped on decision); budget Telegram API *calls*,
not messages.

## 2. Human-in-the-loop approvals and permission systems

Reference systems: Claude Code permission modes + hooks, MCP 2026-07-28,
Vercel AI SDK tool approvals, LangGraph interrupts, Cloudflare Agents HITL,
Amazon Bedrock AgentCore Policy (Cedar, default-deny), OpenClaw exec
approvals, IETF Agent Audit Trail draft.

The six techniques that define the state of the art:

1. **Tighten-only layered policy.** Effective policy = strictest of config,
   host, and per-call policy; approvals can tighten, never loosen. (Claude
   Code's equivalent: hook denials apply even in bypass mode.)
2. **Approvals bound to canonical execution context.** Bind to cwd + exact
   argv + pinned executable + file hash, and **deny if the target changed
   between approval and execution** — the TOCTOU defense that separates an
   approval system from approval theater.
3. **Fail-closed headless default.** When a prompt is required and no
   approval surface is reachable, deny (`askFallback: deny`).
4. **Durable suspend/resume.** An approval wait is a durable state
   transition, not an in-memory block (LangGraph checkpointer, Cloudflare
   `waitForApproval()` "can wait months").
5. **Expiry with escalation.** Remind → escalate → auto-deny on TTL; an
   expired-then-re-wanted action produces a **new proposal with a new
   idempotency key** after re-validating business state. (Notably, the
   leading local-first implementation has no documented TTL — adopting one
   is differentiation, not catch-up.)
6. **Tamper-evident audit as a schema.** The IETF Agent Audit Trail draft:
   UUIDv4 record IDs, RFC 3339 timestamps, outcome ∈ {success, failure,
   timeout, denied, escalated}, `prev_hash` = SHA-256 over the RFC 8785
   (JCS) canonicalization of the prior record, optional ECDSA P-256
   signatures, write-once storage. EU AI Act Annex III high-risk
   obligations reached full enforcement 2026-08-02.

Also relevant: MCP's 2026-07-28 restructuring went stateless (no session
handshake) and replaced server-initiated elicitation with multi-round-trip
requests (`input_required` → retry with `inputResponses`); long-running work
moved to a polled `tasks` extension.

**Applicability: very high.** The existing `/run` `/approve` `/deny`
`/cancel` vocabulary is the right axis; the upgrades are context-binding,
fail-closed headless behavior, TTL + re-proposal, tighten-only composition,
and an AAT-shaped hash-chained log — nearly free given the store's existing
canonical-JSON + SHA-256 machinery.

## 3. Strangler-fig migration and parity gates

- **Shadow with published tolerances**: current guidance gates on diff rate
  < 0.1 %, P95 latency delta within 20 % of legacy, error-budget burn no
  worse than baseline.
- **Side-effect containment is the hard part for a ticket bot.** Under
  naive mirroring "emails, payments, and webhooks fire twice." The
  adaptation: the shadow path emits **intended-action envelopes** that are
  compared, never executed — no replies, no ticket transitions, no
  notifications from the shadow.
- **Characterization tests that deliberately encode legacy bugs**, golden
  behavioral snapshots, field-level diffing, and a three-bucket
  classification: parity / **known deviations** (documented, with reason:
  bug-fix or improvement) / regressions. The known-deviation registry is
  what lets the replacement be *better* than the legacy bot without failing
  its own gate.
- **A weighted confidence score as the promotion criterion**: happy-path ×1,
  error-path ×2, edge cases ×2, data variety ×1.5,
  **production-traffic representativeness ×3**; bands 0–30 block, 31–60
  caution, 61–85 shadow-ready, 86–100 cutover-ready.
- **Golden traces for agents**: record full prompt/action/tool sequences,
  replay against both engines with a deterministic mock runner, normalize
  before diffing; every investigated failure becomes a permanent regression
  gate.
- **Automated promotion**: metrics decide promotion/rollback continuously
  (the Argo Rollouts model), not humans watching dashboards.
- **The honest limit**: parity cannot be fully tested — hidden coupling
  surfaces only under production traffic; a gate licenses *progressive*
  cutover, never a flip.
- **Contract testing at the backend boundary**: bi-directional contract
  testing (provider-published spec statically compared against per-consumer
  contracts) fits a third-party Support backend that will not run
  verification.

**Applicability: direct.** This is the missing mechanism behind audit
finding F-03. The intended-action-envelope comparison plus the weighted
score plus a known-deviation registry is the concrete shape of the parity
gate the launch roadmap already mandates.

## 4. Support-ticket automation

Reference systems: Intercom Fin 3, Decagon, Sierra, Zendesk AI, Ada.

- **Declarative goals + deterministic guardrails**: guardrails are
  structured business logic ("returns only within 30 days"), not prompt
  text; **sensitive validation steps execute in code**, never at model
  discretion (refunds, identity checks).
- **A supervisor layer** reviews outputs against scope and policy before
  anything customer-visible ships, applying corrective steering rather than
  conversation-killing.
- **Risk-weighted escalation replaced confidence thresholds.** The field
  moved off tuned confidence numbers ("half guesswork") to "how bad is it
  if the agent is wrong", and treats self-escalation frequency as the
  honest signal. Deliberately high escalation rates (one cited deployment:
  ~74 % to humans) are a feature.
- **Resolution accounting with integrity guards**: confirmed vs assumed
  resolutions; one outcome per conversation; no resolution if the customer
  asked for a human; **a reopen revokes the resolution** — the guard that
  stops deflection metrics from lying.
- **Calibrate against measured, not marketed**: vendor benchmarks claim
  ~82 %; measured deployments cluster at 38–50 %, with B2B running 17–25
  points below vendor numbers. Set the parity target against the *legacy
  bot's observed* behavior.
- **Eval suites**: separate rubric dimensions (accuracy, empathy, policy
  adherence, resolution) plus verifiable rewards; LLM judges agree with
  humans ~85 % after 2–3 rubric iterations.

**Applicability: high for Increment 5+.** The staff-publishes-the-reply flow
already matches the supervisor pattern; adopt guardrails-as-code,
risk-weighted escalation, and reopen-revokes-resolution accounting.

## 5. Multi-provider LLM abstraction

Reference systems: LiteLLM (whose 2026 Rust proxy cut per-request overhead
~150×), OpenRouter, Vercel AI Gateway, Portkey, and the emerging class of
subprocess CLI providers.

- **Routing vocabulary is settled**: shuffle / least-busy / usage-based /
  latency-based / cost-based, with ordered fallbacks and a *separate*
  context-window fallback chain.
- **Cooldowns are per-deployment**, not per-model-group: a failure counter
  trips a deployment out of the pool (~3–5 fails/min, 30–60 s cooldown)
  while siblings keep serving.
- **Proactive background health probes** evict a deployment before a user
  request fails.
- **The subprocess-CLI provider contract is now well specified**: NDJSON
  stream in/out (`stream_event`/`assistant`/`user`/`result`), one
  long-lived CLI process per session via stdin (zero startup latency from
  turn 2), and two failure rules worth adopting verbatim — an invalid JSONL
  line warns and continues; a non-zero exit or a stream ending without a
  `result` event yields `completed(ok=false)`.
- **AG-UI is becoming the normalization vocabulary** for agent event
  streams (text chunks, structured thinking steps, tool-call events, state
  sync, typed errors with retry context); adopted by Bedrock AgentCore and
  Microsoft Agent Framework in 2026.
- **Cost/telemetry via OTel GenAI semantic conventions**: `gen_ai.system`,
  `gen_ai.request.model`, `gen_ai.usage.input_tokens` /
  `output_tokens`, `gen_ai.response.finish_reasons`; each tool call and LLM
  invocation a child span.

**Applicability: port the semantics, not the dependency.** In-process
routing over SQLite state with ordered fallbacks, per-deployment cooldowns,
and background probes; the subprocess contract for provider adapters; AG-UI
names for the internal normalized event schema (which also hands the planned
desktop client a standard vocabulary); OTel `gen_ai.*` attributes for
per-run cost records.

## 6. Durable execution and workflow state

Reference systems: Temporal, Restate, DBOS (which ships a production SQLite
backend, MIT — the most valuable read in the area), Resonate (a complete
durable-execution store in ~10 SQLite tables), Inngest, LittleHorse. Several
claims below were verified empirically on this host (kernel 6.8, systemd
255, unprivileged uid) during the survey.

**Journaling model.** Step-ID-keyed checkpoint rows (DBOS/Restate/Resonate)
beat an opaque ordered event log: addressable rows make fork, patch,
rerun-from-step, and SQL introspection fall out for free. LangGraph-style
snapshot-plus-re-execution is rejected outright (it re-runs LLM calls on
resume). Techniques worth copying: split the journal into **commands and
notifications** with a correlation id (a tool *dispatched* and a tool
*returned* are two records); step id = (step name, occurrence index) with a
loud error naming recorded-vs-expected on mismatch; human-readable step
names; a hard per-entry size cap with blobs stored content-addressed;
history-size thresholds with compaction as a *journaled* step.

**Exactly-once, honestly.** Every replay engine surveyed is at-least-once
*because* it cannot commit journal + effect in one transaction — a
single-node SQLite plane can, and should state the guarantee in two tiers:
internal effects are true exactly-once (co-committed); external effects are
at-least-once + idempotency key, with the key committed *before* the side
effect. Neither major model provider supports idempotency keys and both
SDKs silently retry by default — so the control plane must own the retry
loop (`max_retries=0` at the SDK), persist the provider request-id per
attempt, and treat a crash-mid-call as *indeterminate, not failed*
(commit an in-flight attempt row before the socket opens; resolve by
retrying the byte-identical request — which also exploits prompt caching:
cache reads cost ~0.1×, so byte-identical replays are cheap). Per-tool
`on_unknown_outcome: retry | fail` policy — a message-send and a payment
answer differently. Retry exhaustion should **pause** (journal intact,
resumable), not kill; paused *is* the dead-letter state, and DLQ rows
carry first-failed *and* last-failed timestamps, never auto-expire, and
replay by forking a new row.

**Leases and fencing.** The requirement is on the *resource*: a fencing
token nobody checks is decoration. The upgrade that matters is from fenced
*work* to fenced *writes* — every mutation on behalf of a lease carries
`AND epoch = ?` (Resonate re-checks the fence before every state change).
On one node, `flock` on a control-lock file (with a dev/inode equality
check after acquire) is the real fence and releases instantly on SIGKILL —
stale-lock "recovery" code is a split-brain bug, verified live. Wall-clock
and monotonic clocks are both wrong for lease TTLs across laptop suspend:
use absolute `CLOCK_BOOTTIME` deadlines paired with `boot_id`, treat a
lease spanning a suspend as *lost* (holder self-fences on resume), and
sweep leases from other boots exactly (boot-id mismatch), never
heuristically. Structure the epoch as (boot_id, invocation_id, seq) rather
than a bare counter. Recovery re-enqueues; it never executes directly.

**Suspend/resume and human-in-the-loop.** Keep three primitives distinct:
signals (resolve many times — steering), awakeables (once — approval
tokens), durable promises (once, read many). Store suspension descriptors
as a combinator *tree* (a flat waiting-set cannot express
`race(llm, timeout)`). Suspension must release the lease and the
concurrency slot. Buffer events durably so a human reply arriving before
the agent asks is not lost. Always race a timer against every human wait;
implement escalation as a loop of bounded waits so each escalation is a
journal entry. The session/task split (fast single-writer session object;
slow cancellable task; new input cancels and supersedes the running task)
is what prevents a long turn from blocking the conversation — the first
two-messages-in-a-row user hits this. One `invoke_time` column on the
outbox is a durable scheduler and cron substitute.

**SQLite engineering.** WAL + `synchronous=NORMAL` is ~3× WAL+FULL and
loses nothing under the process-crash failure model (SQLite documents
transactions as durable across *application* crashes regardless of the
setting) — NORMAL default with FULL as operator opt-in; batching beats the
durability dial where bulk-appending. `BEGIN IMMEDIATE` everywhere
(already the repo's discipline). The claim protocol: unlocked candidate
SELECT + conditional UPDATE … RETURNING — the CAS is admission control.
Plan every index as droppable/recreatable (SQLite cannot drop columns
under partial indexes); migrate before any worker starts; `VACUUM INTO` a
sidecar before destructive migrations; expire all outstanding leases in
any migration that changes lease semantics. Skip WAL2, BEGIN CONCURRENT,
libsql, and every Rust durable-execution crate (~zero adoption); the
architecture to copy is Restate's sans-io single-threaded VM split (the
engine decides *what* is durable; the host decides *how*).

**Sandboxing verdicts.** Landlock + seccomp + cgroup v2 delegation is the
complete unprivileged primitive set, all verified working here; everything
namespace-shaped is blocked on this host and eBPF is hard-off — the
architecture the repo chose is *forced*, not merely reasonable, and
systemd's own TODO endorses it for user sessions. Live traps: Landlock
TSYNC is ABI 8, so best-effort compat silently leaves sibling threads
unrestricted on older kernels — apply before threads exist or hard-require
and assert enforcement from inside the child; io_uring voids any seccomp
policy that permits it (the repo already denies it); every systemd
cgroup-BPF directive on a user manager is accepted and silently does
nothing — ship doctor checks that read back what was actually applied.
Egress: domain allowlisting is only possible in a local proxy (kernel's
job is solely to make direct egress impossible); parse-then-match; empty
allowlist must be the most restrictive state (a real CVE got that wrong);
resolve once and connect to the IP; reject private ranges even for
allowlisted names; and — the finding that should shape the design —
**bind the provider-API allowlist entry to the session's own credential,
not the hostname**: an attacker-supplied key exfiltrating through the
provider's legitimate domain is the documented 2026 failure mode
(identity-bound egress, not destination-bound). Every shipping vendor
confines only their shell tool and leaves MCP/provider processes
unconfined; closing that gap would be ahead of the field.

**Local daemon patterns.** Socket activation + `Type=notify-reload` + the
fd store measured zero dropped connections across restart with ~74 ms
worst-case connect — it retires self-exec, the bind/unlink dance, and most
of the upgrade problem in one decision. Peer auth: uid from `SO_PEERCRED`
is the trust boundary (snapshotted at connect, race-free); pid is a
diagnostic, never authorization; distinct principals get distinct sockets
rather than peer introspection; never abstract sockets for auth-bearing
daemons (server impersonation). Version the local API with a monotonic
capability integer plus per-endpoint maturity annotations (the exact fit
for a parity-gated strangler), and evolve append-only. Event fan-out: per
client bounded queue + dedicated writer; on overflow drop the *stale*
queue, send a terminal frame, disconnect (never block, never silently
drop); one monotonic sequence per stream accepted back as a resume
cursor with time-shaped retention; a disconnected client is *not* a
cancellation. Crash-safe file writes need the directory fsync everyone
skips; fsync errors are panic-and-recover, never retry.

**Applicability: this is the repo's home turf, and the survey mostly
confirms its instincts** (leases-as-ambiguity, refusal-first, BEGIN
IMMEDIATE, honest containment claims). The deltas that matter are fenced
*writes*, boot/suspend-aware lease time, the journal restructure that
unlocks offline replay-as-regression-test (the highest-leverage test an
agent control plane can have), the TSYNC fix, identity-bound egress, and
socket activation.
