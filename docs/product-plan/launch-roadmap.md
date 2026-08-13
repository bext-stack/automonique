# Launch roadmap — Automonique as the primary ticket agent

Status: **owner-steering document.** This is the staged program to make Automonique
the production ticket/support agent — live on Slack, controlled from Telegram,
integrated with the Support backend — in place of the legacy ticket bot. It
changes no behaviour; it exists so the owner can see and approve the whole path
before any increment is built.

Naming: this file uses the corpus's neutral terms, matching the sanitization the
plan already applies — **"the legacy ticket bot"** for the system being replaced
and **"the Support backend / client portal"** for the support product it
integrates with. Real product names, hosts, and credentials never appear in the
repository.

## The one rule that governs everything: strangler, never big-bang

The plan mandates a parity-gated strangler migration
([`reference/feature-parity.md` §Parity gate](reference/feature-parity.md)). We do
**not** replace the legacy ticket bot in one cutover. Automonique runs
**alongside** it; we take over one scope at a time; a scope becomes primary in
Automonique only when its behaviour is implemented and shadow-verified against
the legacy bot, which stays the fallback until then. This protects a live,
customer-facing support operation from a reimplementation risk.

## What "replacement" actually spans

The legacy bot is ~13.6k lines across three operator surfaces (Telegram, Slack, a
web dashboard), a central ticket model, four agent backends, a scheduler,
GitHub-issue-as-truth coupling, and the Support intake→review→publish→email flow
([`reference/legacy-inventory.md`](reference/legacy-inventory.md)). Of 39 parity
rows, **15 are behaviourally pinned by fixtures, 5 partial, and 19 have no
evidence and must be rebuilt as new contracts** (reclassified `replace`,
2026-08-09). Four safety properties must be **deliberately re-specified**, not
inferred:

1. the **fail-closed deploy-notifications channel** (never falls back to ticket intake);
2. **announce-target-before-mutation** (a stop-check before any external mutation);
3. **separately-authorized deletion** (enforced today by a distinct delete token);
4. the scheduler's **bounded-parallelism / per-thread-serialization / pause-cancel** core (the single largest unpinned gap).

## Where we are today (verified against the code)

**Built — the hard part is done:**

- The **enforced execution core**, proven end-to-end with a **live provider run**
  under cgroup + Landlock + seccomp containment
  (`rust/crates/automonique-runner/examples/live_codex.rs`, commit `34dc56d`).
- A **generation-fenced control plane**: eight durable SQLite stores, a
  peer-authenticated local admin socket, five lanes (admin/runs/automation/
  approval/batch), the one-poller Telegram **lease discipline** already enforced
  (`automonique-daemon/src/lib.rs`, `telegram.rs`).
- A **working Telegram `getUpdates` client** with real TLS
  (`automonique-transport-runtime/src/https_client.rs`) — built, tested, **unused**.

**Not yet live — the gaps this roadmap closes:**

- **Telegram** — the daemon holds the lease but constructs no client (it validates
  then drops the token) and has no outbound (`sendMessage`) or command routing.
- **Execution** — the daemon accepts run *custody* but has **no execute lane**;
  `SubmitRun` stops at custody by design (`lib.rs` "THIS LANE STOPS AT CUSTODY").
  The live run above is a manual example, not daemon-driven.
- **Slack** — unbuilt for live use: an inbound Socket Mode *parser* exists, but no
  websocket, no Web API client, no outbound, no token/signature handling.
- **Support backend** — entirely unbuilt; its live API contract is owner-supplied.
- **Deployment** — no service definition; foreground-only, needs a supervisor.

## Cross-cutting constraints (every increment obeys these)

- **Clean-room.** Built from requirements, the public Slack/Telegram/Support/GitHub
  APIs, and the authorized legacy inventory — never from legacy source.
- **Credentials.** The owner supplies every secret; none is committed or passed
  through a process environment (admission already refuses secrets-in-env).
- **Shadow before act.** Any customer-facing surface ingests and verifies in shadow
  before it is allowed to reply or mutate.
- **Reversible.** Every cutover has the legacy bot as a live fallback until the
  scope's parity gate is met.

---

## The increment ladder

Each increment ships something real. Ordered by rising risk and dependency.

### Increment 1 — Telegram control + a daemon execution lane (operator-only spine)

**Outcome:** from Telegram, you trigger a sandboxed agent run and get the result
back. This lights up the entire spine — operator → control plane → contained
provider → result — as a usable product that touches **nothing customer-facing**.

**Builds:** retain the validated Telegram token under the lease; construct the
existing `TelegramHttpsClient` + `TelegramPoller` and add a poll step to the serve
loop; add outbound `sendMessage` + `setMyCommands`; route inbound commands to the
admin lanes; an **allowed-user-ID** gate. Wire `admission → launch → spool` behind
an authenticated execute lane, reusing the proven `live_codex` launch path.

**Prerequisites / gates:** the execution owner-gates from
[`execution-unlock.md`](execution-unlock.md) — live-provider authority (granted for
Codex) and the wiring (Gate C). Uses the **already-proven relaxed-network
posture**, which is acceptable here because every run is owner-triggered and
operator-only; the egress broker (Increment 2) is required before any
less-trusted or customer-driven execution.

**Owner inputs:** Telegram bot token; the allowed Telegram user IDs (and the
subset eligible to approve).

**Exit criteria:** a Telegram command starts a contained run, streams status, and
returns the result; the poller honours the one-generation lease across restart;
non-allowlisted users are refused.

**Risk:** low — operator-only, no customers, no Slack, no Support backend.

### Increment 2 — Egress broker (remove the network deviation)

**Outcome:** contained runs reach their provider through a broker, so the network
axis is denied again — no relaxation. This is the prerequisite for any execution
that is not fully owner-trusted.

**Builds:** the `BrokeredNamed` egress broker the sandbox spec already names — the
workload gets only an `AF_UNIX` socket to a broker that makes outbound calls with
a destination allowlist; `live_codex` is rewritten to that shape and the network
stays denied.

**Owner inputs:** the destination allowlist (provider + Support endpoints).

**Exit criteria:** a contained run completes with network fully denied except
through the broker; the broker enforces its allowlist.

**Risk:** medium — security-critical component; no customer surface yet.

### Increment 3 — Slack ingest in shadow

**Outcome:** Automonique sees everything the legacy bot sees on Slack and records
it, **without replying** — the legacy bot remains the only actor.

**Builds:** a live **Socket Mode** websocket client (`apps.connections.open` +
envelope ack + reconnect), event-ID dedup, durable-insert-before-route into the
`slack_ingress`/inbox stores. No outbound.

**Owner inputs:** a Slack app you control — a **bot token** and an **app-level
token** for Socket Mode; the allowed channel IDs; the dedicated deploy channel ID.

**Exit criteria:** every inbound event is durably recorded once, matches what the
legacy bot processed (shadow comparison), and survives reconnect — with zero
messages sent.

**Risk:** low-to-medium — reads a live channel but sends nothing.

### Increment 4 — Slack outbound + first scope takeover

**Outcome:** Automonique becomes primary for **one** well-covered scope (e.g. a
single command or a single channel), with the legacy bot as fallback.

**Builds:** the Slack **Web API** client (`chat.postMessage/update/delete/
postEphemeral/getPermalink`, `reactions.add`, `conversations.*`, `users.*`,
`auth.test`); command + mention/thread routing; interactive approval/cancel
buttons; the **separately-authorized delete** (distinct delete token); the
**fail-closed deploy channel**; the **announce-target-before-mutation** stop-check.

**Owner inputs:** the normal bot token and the separate delete token; which scope
goes first.

**Exit criteria:** the chosen scope passes its parity gate in shadow, then serves
live with the legacy bot able to resume instantly; the four safety properties for
that scope are specified and tested.

**Risk:** medium-high — first customer-facing action. Scoped narrowly on purpose.

### Increment 5 — Support backend / client-portal integration

**Outcome:** the Support intake→review→publish→email flow runs in Automonique.

**Builds:** tenant-fenced intake from the client portal; routing to the support
flows; **internal raw output is never client-visible by default** — a staff member
publishes the client-facing reply; support-email compose→exact-review→durable-send
via the transactional mailer with reconciliation; GitHub-issue-as-durable-truth
coupling.

**Owner inputs (the big one):** the Support backend's **live API contract**
(portal + support-portal endpoints, request/response schemas, auth), the mailer
credentials and inbound endpoint, and the GitHub repo coordinates. None of this is
in the corpus — it is sanitized out and must come from you.

**Exit criteria:** a client request flows intake→review→published reply and/or
sent email, tenant-fenced, with durable send reconciliation, matching the legacy
flow in shadow before going primary.

**Risk:** high — customer-facing content and email; the largest new contract.

### Increment 6 — Scheduler, notifications, remaining backends, dashboard

**Outcome:** parity for the scopes with no behavioural evidence today.

**Builds:** the scheduler's bounded-parallelism / per-thread-serialization /
pause-cancel core (the largest unpinned gap); notification/artifact/moderation
flows; the remaining agent backends (beyond Codex/Jcode); the web dashboard
surface. Each behind its own parity gate.

**Risk:** high and broad — sequenced last among build work because it is the least
specified.

### Increment 7 — Graceful reload, full cutover, decommission

**Outcome:** the legacy bot is retired.

**Builds:** generation handoff / graceful reload (no reload exists in the legacy
bot today — genuinely new); always-on service definition (systemd units setting
`XDG_RUNTIME_DIR`/`XDG_STATE_HOME`, restart, monitoring); scope-by-scope cutover
until nothing routes to the legacy bot; then decommission.

**Risk:** the cutover itself — mitigated by every prior scope already running
primary with fallback.

---

## What the owner supplies, and when

| Increment | Owner must provide |
| --- | --- |
| 1 | Telegram bot token; allowed user IDs (+ approvers) |
| 2 | Egress destination allowlist |
| 3 | Slack bot token + app-level token; channel IDs (incl. deploy channel) |
| 4 | Slack delete token; first scope to take over |
| 5 | Support backend API contract; mailer credentials + inbound endpoint; GitHub repo coords |
| 6 | Remaining provider credentials; dashboard access policy |
| 7 | Cutover go/no-go per scope |

Plus four **decisions** that cannot be inferred: the exact behaviour of each of the
four flagged safety properties, and the egress posture for each execution class.

## The parity gate (go/no-go for making any scope primary)

A scope may become primary in Automonique only when: its preserve/replace rows are
implemented; it has run in shadow long enough to match the legacy bot on real
traffic; its safety properties are specified and tested; and the legacy bot can
resume the scope instantly on rollback. Until all four hold, the legacy bot stays
primary for that scope.

## Recommended first move

**Increment 1.** It is the lowest-risk path that produces a real, usable product
(Telegram-controlled sandboxed runs), touches no customers and no Support backend,
and builds directly on the one thing already proven live. Everything customer-facing
comes after the transports are exercised operator-only first.
