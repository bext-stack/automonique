# M3 — Approvals, authority & audit (implementation plan)

Status: grounded implementation plan for milestone **M3** of the improvement
program ([`../roadmap.md`](../roadmap.md) items 14–21 = GitHub issues
[#17–#24](https://github.com/bext-stack/automonique/issues)). Derived from
finding **F-06** in [`../audit-findings.md`](../audit-findings.md) and §2 of
[`../state-of-the-art.md`](../state-of-the-art.md).

Every claim below is anchored to a file and line in the tree at `c2f8b16`.
Naming follows the corpus's neutral-term rule: **the legacy ticket bot** and
**the Support backend**. Several user-facing strings in the transport surfaces
still carry the private names; they are referenced by file and line and never
quoted here. M1 item 1 rewrites them, which is a real dependency for #19 and
#24 (see [Cross-cutting notes](#cross-cutting-notes)).

---

## The finding this milestone answers, restated precisely

F-06 says "~16k lines of control surface that nothing reads". The measured
figure is **18,004 lines** across the triad's protocol, store and CLI modules,
before daemon handlers and tests:

| Lane | Protocol | Store | CLI | Total |
|---|---|---|---|---|
| Approval | `approval_api.rs` 2,037 | `approval_ledger.rs` 1,098 | `approval.rs` 914 | 4,049 |
| Automation | `automation_api.rs` 2,057 + `automation.rs` 4,415 | `automation_store.rs` 1,248 | `automation.rs` 1,032 | 8,752 |
| Batch | `batch_api.rs` 2,371 | `batch_registry.rs` 1,774 | `batch.rs` 1,058 | 5,203 |

Plus daemon handlers `handle_automation`
(`rust/crates/automonique-daemon/src/lib.rs:2432`), `handle_approval`
(`lib.rs:2652`), `handle_batch` (`lib.rs:2873`), and six dedicated test files
(`automonique-daemon/tests/{approval,automation,batch}_live.rs`,
`automonique-cli/tests/{approval,automation,batch}_cli.rs`).

The "nothing reads it" claim is exhaustively verifiable. Every access to the
three stores anywhere in the daemon:

| `lib.rs` line | Call | Purpose |
|---|---|---|
| 1373 | `self.approvals.decision_count()` | status counter |
| 1374 | `self.automations.automation_count()` | status counter |
| 2483, 2517, 2569, 2571, 2598 | automation register / transition / page / page / entry | inside `handle_automation` |
| 2714, 2774, 2790, 2812 | approvals record / page / by_subject / entry | inside `handle_approval` |
| 2943, 2983, 3061 | batches register / advance / batch | inside `handle_batch` |

There are no other call sites. `handle_execute` (`lib.rs:2306`) — the one lane
that starts real work — reads only the generation snapshot (`:2312`),
`degraded` (`:2321`) and `paused` (`:2323`), then calls `start_run`
(`:2326`). It consults none of the three. The store crate says the same about
itself at `automonique-store/src/approval_ledger.rs:44-50`:

> **It does not enforce the decision.** Nothing here gates anything. […] The
> row is written beside the action, never in front of it.

**The important correction to F-06's framing:** this is not dead code. It is
*unconsumed precursor state* for machinery the roadmap schedules later, and
two of the three lanes store exactly the vocabulary M8 item 42 (scheduler
core: "bounded parallelism, per-scope serialization, pause/cancel") will need:

- `automations.enablement IN ('enabled','paused','archived')`
  (`automation_store.rs` `SCHEMA_V1`) is item 42's pause/cancel axis;
- `batches.concurrency IN ('sequential','bounded_parallel')` with
  `concurrency_max` bounded 1–256 (`batch_registry.rs` `SCHEMA_V1`) is item
  42's bounded-parallelism axis.

So #17 is not really "is this code worth keeping" — it is **"which of these
three lanes gets a consumer in M3, and which wait for M8?"** That reframing
changes the recommended answer, and §17 below states it.

---

## #17 — Decide: wire or delete the automation/approval/batch triad `[owner]`

### Current state

- Each lane is a first-class protocol with its own name, ceiling and refusal
  vocabulary: `approval_api.rs:123`, `automation_api.rs:108`,
  `batch_api.rs:129`, dispatched by envelope through
  `LocalRequest::from_canonical_bytes` (`automonique-protocol/src/admin.rs:1685`)
  into `LocalRequest::{Automation,Approval,Batch}` (`admin.rs:1657,1662,1668`).
- All three are **deliberately outside** the closed admin command registry
  (`automonique-cli/src/approval.rs:6-9`, `automation.rs:6-9`, `batch.rs:6-9`),
  so deleting one does not disturb `admin_command_registry()`
  (`automonique-protocol/src/command_registry.rs:1341`).
- Each daemon handler's own doc comment states its inertness:
  `lib.rs:2406-2413` (automation: "registering an automation starts nothing"),
  `lib.rs:2622-2633` (approval: "A recorded approval allows nothing… A recorded
  denial blocks nothing"), `lib.rs:2836-2850` (batch: "Registering a batch
  submits nothing… Nothing is scheduled and nothing is throttled").
- A second, entirely separate in-memory approval gate exists and is also
  unwired: `automation::decide_unattended`
  (`automonique-protocol/src/automation.rs:1073`) returning
  `UnattendedDecision::{PreApproved,RequiresApproval}` (`:1331`), with test-only
  callers (`automonique-protocol/tests/automation.rs:506,527,556,579,597,639,669`).

### Owner-decision options

**Option A — Wire all three now.** M3 delivers approval consumers *and* an
automation trigger evaluator *and* a batch executor.
*Cost:* the automation and batch consumers are the M8 scheduler (item 42) built
early and without item 10's safety-property spec, which M2 has not written yet.
*Verdict:* not recommended. It builds the scheduler out of order and without
its spec.

**Option B — Wire approvals; hold automation and batch for M8 (recommended).**
M3 gives the approval lane a consumer (#19–#24) and leaves automation and batch
as recorded-only, but **re-labelled**: their handler doc comments change from
"nothing reads this, and there is no scheduler" to "this is the scheduler's
durable input; the scheduler lands in M8 item 42", and each gets a tracking
issue reference. Nothing is deleted, nothing new is built on them.
*Cost:* 8,752 + 5,203 lines stay unconsumed for the length of M8.
*Benefit:* the two Telegram verbs stop refusing, the highest-value half ships,
and the M8 scheduler inherits a durable, tested, fenced state machine instead
of designing one under deadline.

**Option C — Wire approvals; delete batch; hold automation.** As B, but the
batch lane (5,203 lines + `batch_api.rs`'s 13-variant `BatchRefusal` at
`batch_api.rs:1679` + `batch_live.rs`/`batch_cli.rs`) is deleted on the argument
that its concurrency policy is a *scheduler* concern that the scheduler should
own rather than inherit.
*Cost:* M8 item 42 re-derives `ConcurrencyPolicy`, the ordinal/member state
machine, and the `SequenceCoupling`/`SequenceRegression` refusals from scratch.
*Verdict:* defensible only if the owner intends the scheduler to be built
around leases/outbox rather than around a batch registry.

**Option D — Delete all three; rebuild an approval lane purpose-built.**
*Cost:* ~18k lines and six test files deleted, then a new approval lane written
that will look substantially like `approval_api.rs` + `approval_ledger.rs`,
minus their fencing, ceiling and conflict semantics.
*Verdict:* not recommended. The approval half's design is the strongest
existing asset in this area (write-once, replay-safe, conflict-naming), and the
gap is a consumer, not the code.

**Recommendation: Option B.** It is the only option that makes #18–#24 net-new
capability rather than partly re-implementation, and it is the option the
roadmap already assumes.

### If "delete" is chosen instead

Items #18–#24 change as follows, and this is the explicit branch the parent
task asked for:

| Issue | Under "wire" (Option B) | Under "delete" (Option D) |
|---|---|---|
| #18 cancel verb | Unaffected — cancellation never touched the triad; it rides `CancelLedger` + `CancelDispatcher` | Unaffected, identical work |
| #19 approval lane | Adds `approval_requests` beside the existing `approval_decisions` ledger; reuses `ApprovalRequest`/`ApprovalResponse` wire types | Must also re-create the decision ledger, the wire types, the CLI verbs and the daemon handler: **+~3,000 lines, +6–8 days** |
| #20 context binding | New column set on `approval_requests` | Same, but on a table that does not exist yet |
| #21 TTL | Same | Same |
| #22 fail-closed / tighten-only | Same (it is a policy-crate change, triad-independent) | Same |
| #23 audit chain | Same (new store module, triad-independent) | Same |
| #24 buttons | Same | Same |

Net: choosing "delete" costs roughly **6–8 additional engineer-days** and buys
back ~18k lines of unconsumed surface, of which ~4k is the approval half that
would be rewritten anyway. The delete case is strongest for *batch alone*
(Option C), not for the triad.

### Deliverable

An owner-decision record under `docs/product-plan/` (or wherever M1 item 4
lands the repaired authority stack) naming the chosen option, plus the doc-
comment re-labelling that Option B requires at `lib.rs:2402-2431`,
`lib.rs:2828-2872`, `automation_store.rs` and `batch_registry.rs` module docs.

**Effort:** 1 day to draft the decision record and the re-labelling PR, once
the decision exists. **Dependencies:** none — this gates #19–#21 and #24.

---

## #18 — Admin cancel verb + Telegram `/cancel`

### Current state

The dispatcher is complete, durable, host-wide, and reachable from nothing an
operator can type.

- `/cancel` parses cleanly into `ControlCommand::Cancel { run_ref: ControlRef }`
  (`automonique-transport-runtime/src/telegram_control.rs:1278-1281`), is
  admin-tier (`:445-450`), and is then refused at dispatch by
  `Unavailable::CancelVerb` (`automonique-daemon/src/telegram_bridge.rs:821`,
  selected at `:893`, rendered at `:847-849`). The refusal's own doc comment
  names the missing surface exactly: *"the admin protocol has no cancel verb to
  route to the host-wide dispatcher this daemon already owns."*
- That is accurate: `AdminCommand` has ten variants and none is a cancel
  (`automonique-protocol/src/admin.rs:382-409`).
- The dispatcher: `DaemonAttemptHost` (`automonique-daemon/src/attempt_host.rs:186`),
  `open()` at `:207` composing `CancelLedger` → `StoreCancelCustody`
  (`automonique-daemon/src/cancel_custody.rs:70`, `impl` at `:119`) →
  `CancelDispatcher::new` (`automonique-runner/src/dispatch.rs:414`) in one
  line at `attempt_host.rs:215`. Public API: `register()` `:261`,
  `cancel(attempt_id, request_ref, observed_sequence)` `:290`, `seat()` `:280`,
  `dispose()` `:315`.
- The daemon constructs it at `lib.rs:945-948` and hands an `Arc` clone to the
  execution lane at `lib.rs:956-957`. The lane registers every attempt at
  `automonique-daemon/src/execute.rs:672-682`, *before* `Spool::open` (`:684`)
  and before cgroup creation (`:690`) — comment at `:667-668`: "no cgroup can
  exist for an attempt cancellation cannot reach".
- Delivery path: `CancelDispatcher::cancel` → `DispatchCore::dispatch`
  (`dispatch.rs:323`, sink delivery *inside* the lock at `:363`) →
  `TokenCancelSink::deliver` (`execute.rs:1132`) → `CancellationToken::cancel`
  (`automonique-runner/src/runner.rs:10`, an `Arc<AtomicBool>`) → polled by the
  supervision loop at `automonique-runner/src/backend.rs:489` and `:526` →
  `RunContainment::kill()` (`automonique-runner/src/containment.rs:406`, writes
  `1` to `cgroup.kill`).
- The stale note: `attempt_host.rs:71-74` still says "Nothing registers an
  attempt in a running daemon". `execute.rs:672` does.

### Approach

**Placement decision — put the verb on the execute lane, not `AdminCommand`.**

Two options exist and the choice is load-bearing:

- *Admin command set:* add `AdminCommand::CancelRun`. This forces an eleventh
  entry in `admin_command_registry()` (`command_registry.rs:1341`) with an
  `ApprovalPolicy` annotation, and inherits the registry's one-variant
  `AuthorizationRequirement::LocalPeer` (`:740`). It matches the wording in
  `Unavailable::CancelVerb`'s doc comment.
- *Execute lane (recommended):* extend `ExecuteRequest`
  (`automonique-protocol/src/execute_api.rs:320`) with
  `CancelRun { request_id, run_id, request_ref, observed_sequence }` and
  `ExecuteResponse` (`:394`) with `Cancelled { request_id, run_id, disposition }`.
  Rationale: cancellation is the inverse of `ExecuteRun`, its refusals are
  already spelled in `ExecuteRefusal` (`execute_api.rs:205`: `UnknownRun`,
  `RunNotReady`, `AlreadyExecuting`, `ExecutionUnavailable`), and the envelope
  dispatch at `admin.rs:1707` plus the compile-time ceiling assert at
  `admin.rs:1554` already accommodate the lane. Either way, the doc comment at
  `telegram_bridge.rs:821` must be rewritten.

**Resolution seam — run_id → attempt_id → observed_sequence.** The dispatcher
keys on `attempt_id`, but an operator types a run reference. `start_run`
(`lib.rs:2363`) already walks exactly the path a cancel needs:

1. `self.run_index.by_run_id(run_id)` → the read-model record, which carries
   `spool_state`, `last_sequence` and `revision`
   (`automonique-store/src/run_index.rs` DDL at `:186-202`);
2. `self.run_submissions.run_submissions(&record.run_id)` → the custodied
   `document` blob;
3. `RunSpec::from_canonical_bytes(document)` → `spec.attempt_id()`, which is
   the same derivation `execute.rs:671` performs.

`record.last_sequence` is precisely the `observed_sequence` the cancel ledger
wants, and it is the daemon's own read model rather than a caller claim —
better evidence than the runner control socket gets today
(`cancel_ledger.rs:44-46`: "`observed_sequence` is the requester's claim […]
it never checks it against a spool"). Recommend the daemon supply it and reject
a caller-supplied sequence *ahead* of the read model.

New daemon method `Daemon::cancel_run(&mut self, run_id, request_ref) ->
Result<CancelDisposition, ExecuteRefusal>`, fenced identically to
`handle_execute` (`lib.rs:2312-2320`) but **not** gated on `paused`/`degraded`:
an operator who closed intake still needs to stop what is running, which is the
same argument `lib.rs:2291-2298` makes for leaving the read and control lanes
open.

**Answer vocabulary.** `DispatchOutcome` (`dispatch.rs:166`) already
distinguishes delivery from replay; map it onto `CancelDisposition::{Delivered,
AlreadyDelivered}` (`cancel_ledger.rs:244`) so a retry is idempotent end to end.
An unregistered attempt (finished, or never started) is `RunNotReady`, not a
failure.

**Telegram.** Delete the `Unavailable::CancelVerb` arm
(`telegram_bridge.rs:893`) and the variant (`:821`), add a
`ControlCommand::Cancel` dispatch arm near the `/approve` arm (`:3939-3943`)
producing a new `Answer` variant that submits through `SocketRunLane`
(`automonique-daemon/src/run_lane.rs:144`, `submit` at `:260`) — the same
socket the bridge already uses to start runs. `request_ref` should be minted by
the bridge as a deterministic function of `(chat_id, message_id, run_ref)` so a
duplicate Telegram delivery is an exact replay, not a second cancellation.

**CLI.** Add `automonique execute cancel <run-id> [--request-ref R]` alongside
the existing lanes in `automonique-cli/src/lib.rs` (parse arms at `:225`,
`:281`, `:320`; dispatch at `:469-477`), reusing
`admin_client::exchange` (`admin_client.rs:256`).

**Also fold in roadmap item 46** (M8: "wire the durable cancellation ledger
into the runner control socket"). The runner's default is still
`InMemoryCancelCustody` (`automonique-runner/src/control.rs:483`, installed by
`bind` at `:763`, disclaimed at `:99-104`), and `bind_with_custody` (`:783`)
already accepts the durable one. This is a two-line change in whatever
constructs the runner's control server and it should not wait for M8, because
until it lands there are two custody stores with different answers.

### Testing

- `automonique-daemon/tests/cancel_custody.rs` extension: a full loop —
  register an attempt, cancel by `run_id`, assert `Delivered`; replay the same
  `request_ref`, assert `AlreadyDelivered` and that
  `CancelLedger::entry` (`cancel_ledger.rs:433`) is unchanged; present the same
  `request_ref` against a *different* attempt, assert
  `CancelLedgerError::Conflict` surfaces as a typed refusal.
- Restart test: cancel, restart the daemon, replay the `request_ref`, assert
  `AlreadyDelivered` — the property `InMemoryCancelCustody` cannot provide.
- Fence test: cancel under a stale lease epoch refuses with `StaleEpoch`.
- Live test in `automonique-daemon/tests/execute_live.rs`: cancel a running
  attempt, assert the containment is killed and the read model reaches a
  terminal state, and that `RegistrationHandle` is released (`execute.rs:1013`).
- `automonique-daemon/tests/telegram_control.rs:2606` currently asserts
  `Unavailable::CancelVerb.operator_reply()`; it must be replaced by an
  assertion on the new answer, and the "every unavailable message contains
  `Not available yet.`" assertion at `:2609-2613` must still pass over the
  remaining variants.

### Effort

**M — 4–6 engineer-days.** The dispatcher, ledger, custody adapter and
registration are all done; this is protocol surface, one resolution walk, two
call sites and tests.

### Dependencies

Independent of #17 (cancellation never touched the triad). Should land first in
M3 — it is the cheapest removal of a typed refusal in the register.

---

## #19 — Wire the approval lane end-to-end (`/approve`, `/deny`)

### Current state

Three separate half-systems exist and none of them meet.

**(a) The durable decision ledger, unreachable from chat.**
`ApprovalLedger` (`approval_ledger.rs:587`) with
`record` `:694`, `entry` `:744`, `page` `:761`, `by_subject` `:791`, over

```sql
CREATE TABLE approval_decisions (
    entry_id INTEGER PRIMARY KEY,
    approval_key TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('granted', 'denied')),
    decider TEXT NOT NULL,
    decided_at_ms INTEGER NOT NULL CHECK (decided_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision = 1)
) STRICT;
```
(`approval_ledger.rs:241-252`.) Reachable only over `ApprovalRequest`
(`approval_api.rs:1513`) from `automonique-cli/src/approval.rs`. **The Telegram
bridge never touches it.**

**(b) The chat `/approve` path, which writes no decision.**
`/approve` produces `Answer::TicketApprovalReady` (`telegram_bridge.rs:3939-3943`,
variant at `:5849-5856`), submitted as `TicketActionJob::Confirm` (`:2222`) and
executed on a worker at `:2347-2405` by calling `confirm_ticket`
(`:1065-1079`). That call carries **no `decision_key` and no `actor_key`**, so
the Telegram approve path has no idempotency binding at all — unlike Slack's,
which does. The gate it resolves comes from `TicketGateRegistry`
(`:2068-2072`), an in-process `Vec` capped at 256 with FIFO eviction (`:2103-2117`)
projected to a JSON file (`:2136`), matched by **prefix**
(`matching()` at `:2119-2125`).

**(c) `/deny`, refused.** `Unavailable::ApprovalWiring` (`telegram_bridge.rs:823`,
selected at `:895`, rendered at `:850-852`). **Its doc comment is stale:**
`TicketActionSurface::decide_ticket` exists on the trait (`:1035-1044`) and is
implemented for the live client at `:1092-1109`, carrying both Approve and
Reject with `decision_key`/`actor_key` idempotency. Slack already calls it
(`slack.rs:1903-1911`). The missing piece is bridge dispatch only.

**(d) Slack, which is already correct and is the model to copy.**
`prepare_interaction` (`slack.rs:1809-1854`) runs a four-way authorization gate
(`:1814-1821`: interactive-decisions flag, `SlackFeature::Approvals`, admin
membership, configured channel), builds `actor_key` (`:1833`), and **records to
the durable store before acting** (`:1839-1850`). `handle_interaction`
(`:1857`) bails unless the record state is `Recorded` (`:1867-1869`), then calls
`decide_ticket` (`:1903-1911`). The store
(`automonique-store/src/slack_interactions.rs:23-40`) compares all six bound
fields on replay (`:212-218`) and resolves under an optimistic revision fence
(`:234-252`).

### The architectural gap this issue must close

`ApprovalLedger` has **no pending state** — by design:
`approval_ledger.rs:403-406` says "there is no 'pending' and no 'expired'. A
decision that was never made has no row." An approval *lane* needs a durable
record of the thing awaiting a decision. So #19's core deliverable is a **new
store module beside the existing ledger**, not a change to it:

- `approval_requests` — the proposal: what is awaiting a decision, who may
  decide, what context it is bound to (#20), when it expires (#21);
- `approval_decisions` — unchanged, write-once, the answer.

The template already exists and works: `improvement_approval_challenges`
(`automonique-store/src/improvements.rs:99-115`) with `bound_revision`,
`artifact_digest`, `actor_id`, `chat_id`, `expires_at_ms`, `consumed_at_ms`,
and a consume path (`::approve` at `:892-970`) that checks, in order: consumed →
expired → actor match → chat match → revision match → required state → digest
match → single-`UPDATE … WHERE consumed_at_ms IS NULL`. That is the strongest
single-use approval primitive in the tree; #19 generalizes it out of the
self-improvement feature.

### Approach

**New store module `automonique-store/src/approval_requests.rs`.** Own database,
own `user_version`, WAL, `synchronous = FULL`, per the discipline every sibling
module states (`approval_ledger.rs:188-196`).

```sql
CREATE TABLE approval_requests (
    request_entry_id INTEGER PRIMARY KEY,
    approval_key       TEXT NOT NULL UNIQUE,   -- the ledger's idempotency key
    subject            TEXT NOT NULL,          -- the ledger's subject
    proposer           TEXT NOT NULL,
    context_digest     TEXT NOT NULL CHECK (length(context_digest) = 64),  -- #20
    surface            TEXT NOT NULL CHECK (surface IN ('telegram','slack','cli')),
    audience           TEXT NOT NULL,          -- opaque: chat id, channel, or uid
    state              TEXT NOT NULL CHECK (
                           state IN ('pending','granted','denied','expired','superseded')),
    proposed_at_ms     INTEGER NOT NULL CHECK (proposed_at_ms >= 0),
    expires_at_ms      INTEGER NOT NULL CHECK (expires_at_ms >= proposed_at_ms), -- #21
    reminded_at_ms     INTEGER,                                                  -- #21
    decided_at_ms      INTEGER,
    supersedes_key     TEXT,                                                     -- #21
    revision           INTEGER NOT NULL CHECK (revision >= 1),
    CHECK ((state = 'pending') = (decided_at_ms IS NULL))
) STRICT;

CREATE INDEX approval_requests_by_state ON approval_requests(state, expires_at_ms);
CREATE INDEX approval_requests_by_subject ON approval_requests(subject, request_entry_id);
```

Public API mirroring the sibling modules' shape:
`ApprovalRequests::{open, propose, pending, expiring_before, decide, expire,
supersede, entry, page}`; `decide` is the fenced single-`UPDATE … WHERE
approval_key = ? AND revision = ? AND state = 'pending'` returning
`StaleRevision` on `changed != 1`, exactly as
`slack_interactions.rs:245-250` does.

**Two-write ordering, stated rather than hidden.** A decision touches two
databases (requests, decisions) and no transaction spans them — the same seam
`approval_ledger.rs:96-104` already names against `provider_journal`, and
`run_index` against `run_submissions`. Order: **fence the request row first,
then record the decision**. A crash between them leaves a request row in
`granted`/`denied` with no ledger row; a reconcile-on-open sweep (the pattern
`reconciliation_run_id` at `lib.rs:625` already establishes) re-records it,
which is safe precisely because `ApprovalLedger::record` is replay-safe
(`approval_ledger.rs:703-705`). Choosing the other order would risk a recorded
decision that no request row can be matched to.

**Protocol.** Extend `ApprovalRequest` (`approval_api.rs:1513`) with
`ProposeApproval` and `DecideApproval`, and `ApprovalResponse` (`:1640`) with
`Proposed` and `Decided`. Add refusals to `ApprovalRefusal` (`:1448`, currently
`ALL: [Self; 4]` at `:1469`): `UnknownRequest`, `AlreadyDecided`,
`RequestExpired`, `ContextChanged` (#20), `NoOperatorSurface` (#22). Each
addition needs its `ALL` array and `SecuritySensitiveEnum` spelling updated
(`:1505`) so unknown wire spellings still fail closed, and the compile-time
ceiling assert at `admin.rs:1526` re-checked.

**Telegram.** Replace both arms:

- `/approve <ref>` and `/deny <ref>` resolve the reference against
  `approval_requests` (prefix match on `approval_key`, ambiguity refused — the
  same three-way answer `telegram_bridge.rs:2354/:2389` already gives for
  gates), then call the daemon's decide path.
- The ticket-confirmation route is preserved but re-plumbed: both verbs now go
  through `decide_ticket` (`:1092-1109`) with `decision_key = approval_key` and
  `actor_key = "telegram:{user_id}"`, giving Telegram the idempotency binding it
  lacks today and matching Slack's `actor_key` shape (`slack.rs:1833`).
- Delete `Unavailable::ApprovalWiring` (`:823`) and its selection arm (`:895`).

**Slack.** No behavioural change to `prepare_interaction`/`handle_interaction`;
add a write to `approval_requests` + `approval_decisions` alongside the existing
`slack_ticket_interactions` row, so both platforms produce the same durable
decision record. Do not merge the two tables — `slack_ticket_interactions` binds
Slack message coordinates and is the replay guard for Socket Mode redelivery; it
is the Slack analogue of `provider_journal`'s per-session binding.

**Authority.** Telegram admin tier is already enforced before argument parsing
(`telegram_control.rs:1820-1833`, tier table `:445-462`), and admins can only
come from configuration, never from the durable roster
(`telegram_bridge.rs:477-479`). Record `decider` as the tier-checked actor id;
`approval_ledger.rs:51-57` is explicit that the ledger records but does not
verify it, so the verification must visibly happen at the bridge and be
asserted by test.

### Testing

- `automonique-store/tests/approval_requests.rs` (new): propose → decide →
  replay-decide is `AlreadyDecided`; decide under a stale revision is
  `StaleRevision`; conflicting propose under the same key is `Conflict`.
- `automonique-daemon/tests/approval_live.rs` extension: propose over the wire,
  decide over the wire, assert **both** databases agree; kill the daemon between
  the two writes (inject via a test-only seam) and assert the open-time sweep
  re-records the decision exactly once.
- `automonique-daemon/tests/telegram_control.rs`: `/deny` produces a decision
  rather than the refusal at `:2608`; `/approve` twice produces one decision and
  one `AlreadyRecorded`; a non-admin `/approve` is `NotPermitted` before any
  reference is parsed.
- Cross-surface test: a gate proposed by Slack decided from Telegram, and the
  reverse — the `TicketGateRegistry` doc (`:2065-2067`) already claims this
  property for confirmation; the test makes it true for denial too.

### Effort

**L — 10–14 engineer-days.** New store module with the crate's full discipline
(~1,000 lines including module doc, which is the house standard), protocol
extension across three enums with fail-closed decoding, two transport
rewrites, and the two-database reconcile.

### Dependencies

**#17 (blocking).** Also depends on #18 landing first only if the two share the
`ControlRef` resolution helper — recommended, since both need prefix-match
resolution with an ambiguity refusal.

---

## #20 — Bind approvals to canonical execution context (TOCTOU defense)

### Current state

Three digests already exist on the execution path, none of them composed into
an approval binding:

1. **Spec digest**, verified twice at submit: `Sha256::digest(document)`
   compared to the caller-declared value (`lib.rs:1543-1550`, refusal
   `run_spec_digest_mismatch`), then re-encoded and re-compared to prove
   canonicality (`lib.rs:1578-1594`, refusals `run_spec_not_canonical` /
   `run_spec_not_encodable`). Stored as
   `run_submissions.spec_digest TEXT NOT NULL CHECK (length(spec_digest) = 64)`
   (`run_submissions.rs:134-147`).
2. **Prompt digest**, computed daemon-side (`execute.rs:809`) and re-checked at
   admission (`admission.rs:1252`).
3. **Provider binary digest**, hashed at admission (`execute.rs:837-839`) and
   compared via `BinaryProvenance::matches` (`admission.rs:997-1002`).

What does **not** exist: any digest over the composed launch context.
`LaunchPlan` (`automonique-runner/src/launch.rs:231`) holds
`program`, `arguments`, `filesystem`, `connect_ports`, `bind_ports`,
`socket_grants`, `environment`, `prompt` — all private, no digest field, and
**no `cwd`**: `admission.rs:51-55` states "The launch frame has no `cwd` line, so
the workload starts in whatever directory the supervisor is in", with the
working directory published separately on `AdmittedLaunch::working_directory`
(`admission.rs:1020`). `build_plan` (`admission.rs:1259-1335`) composes the plan
deterministically in a fixed order (`admission.rs:67-72`), which is what makes a
digest over it well-defined.

Also relevant: nine domain-separated digest types exist on `RunSpec`
(`automonique-runner/src/spec_fields.rs:224-251` — profile, model routing,
toolset, skillset, extension set, persona, execution plan, scheduler decision,
artifact grant) and **every one is on `admission.rs`'s `INFORMATIONAL_FIELDS`
closed list** (`admission.rs:205-224`): declared, stored, verified against
nothing.

### Approach

**Define `ExecutionContextDigest` in `automonique-runner`, beside `LaunchPlan`.**
It is domain-separated SHA-256 over the canonical encoding of a fixed tuple,
computed from data the admission path already holds:

| Component | Source |
|---|---|
| `spec_digest` | `RunSpec::canonical_digest()` (`automonique-runner/src/spec.rs:597` → `spec_encode.rs:260`) |
| `program` | `LaunchPlan::program()` (`launch.rs:476`) |
| `argv` | `LaunchPlan` arguments, in encode order (`launch.rs:570-609`) |
| `working_directory` | `AdmittedLaunch::working_directory` (`admission.rs:1020`) |
| `filesystem grants` | `(PathIntent, PathBuf)` pairs in plan order |
| `environment names` | names only — values are secrets; the redacting `Debug` at `launch.rs:245` sets the precedent |
| `prompt_digest` | `execute.rs:809` |
| `provider_binary_digest` | `execute.rs:837-839` |

Implementation shortcut worth taking: `LaunchPlan::encode()` (`launch.rs:570`)
already produces a deterministic, fully-ordered byte frame
(`schema=automonique.launch/v1` … `end=`). Digesting **that frame plus the three
values it omits** (spec digest, working directory, provider binary digest) is a
five-line function whose determinism is already covered by `encode`'s own
tests — far safer than a second serializer. The environment-value problem is
handled by the frame carrying `env=<name-hex>:<value-hex>`: either digest the
frame as-is (values included, which is correct for TOCTOU and safe because the
digest is one-way) or emit a `digest_frame()` variant with values elided.
**Recommend digesting the frame as-is**: an env value change *is* a context
change, and a one-way digest leaks nothing.

**Bind and re-check.** `approval_requests.context_digest` is written at propose
time. At execution, `handle_execute` (`lib.rs:2306`) — after `start_run`
resolves the document but before `ExecutionLane::start` — recomputes the digest
from the admitted plan and compares. Mismatch → new
`ExecuteRefusal::ApprovalContextChanged` (added to `execute_api.rs:205` and its
`ALL` array), nothing started, nothing written except an audit record (#23) with
outcome `denied`.

**Where the check must live.** It must be inside the daemon's serve thread,
between admission and spawn, in the same section that already performs the
binary provenance check (`execute.rs:822-842`). Putting it in the CLI or the
bridge would make it advisory.

**What this does not close, stated plainly.** The residual exec TOCTOU remains:
`spawn_plan.rs:29-44` ("`ProviderSpawnRequest::plan` opens the executable,
hashes it, and compares it to the pin. The runner then `execve`s **the path**,
not the bytes that were hashed"), restated at
`automonique-agents/src/lib.rs:26-31`. Context binding narrows the window from
"anything may change between approval and execution" to "the bytes behind a
verified path may change between hash and `execve`". **Roadmap item 45**
(`execveat` on a sealed memfd) closes the remainder, and this plan must not
claim otherwise — that claim is exactly the "approval theater" SOTA §2.2 warns
about.

### Testing

- Determinism: the same `RunSpec` admitted twice yields the same digest;
  changing any one component (argv element, one grant, one env value, the
  prompt, the binary) changes it. One test per component — eight assertions,
  each naming its component, so a future field addition that is *not* digested
  fails a test rather than silently weakening the binding.
- A field-coverage test that asserts the digested component count equals the
  `LaunchPlan` field count + 3, so adding a `LaunchPlan` field forces a decision.
- End-to-end: approve a run, mutate the referenced spec document in custody
  (test-only seam), execute → `ApprovalContextChanged`, assert nothing spawned
  and the audit record's outcome is `denied`.
- Negative: an unapproved run is unaffected — context binding must not become a
  second admission gate for runs that never required approval.

### Effort

**M — 5–7 engineer-days**, of which roughly half is the eight-component test
matrix. Small if `encode()` is reused; large if a second serializer is written
(do not).

### Dependencies

**#19** (needs `approval_requests.context_digest`). Informs, and is informed
by, M8 item 45; independent of M2.

---

## #21 — Approval TTL with auto-deny, reminders, re-proposal

### Current state

- No TTL anywhere in the general approval path. The only expiring approval in
  the tree is the self-improvement challenge:
  `improvement_approval_challenges.expires_at_ms`
  (`automonique-store/src/improvements.rs:99-115`), checked at
  `:905` before actor/chat/revision/digest, with `CHALLENGE_LIFETIME_MS` set at
  `automonique-daemon/src/improvements.rs:328-330`.
- `ApprovalDecision` is closed at two values and explicitly has no `expired`
  (`approval_ledger.rs:403-406`).
- `TicketGateRegistry` "expires" by FIFO eviction at 256 entries
  (`telegram_bridge.rs:2112-2114`) — an eviction, not an expiry, and silent.

### Approach

**Auto-deny records a timeout, not a forged decision** *(amended 2026-08-15 to
match the shipped implementation, `c36fbf5`)*. On expiry the sweeper transitions
the request row to `expired` and appends a **#23 audit record with outcome
`timeout`** — it deliberately writes **no** ledger decision. The write-once
`ApprovalLedger` records decisions people made; putting a `decider: "system:ttl"`
denial there would stamp a decider's name on a silence, and the
`approval_requests` schema `CHECK ((state IN ('granted','denied')) = (approval_key
IS NOT NULL))` makes an `expired` row structurally incapable of carrying a ledger
key. The earlier draft of this section (which asked for a real `Denied` ledger
row) was superseded on that reasoning; the audit chain, not the ledger, is where
the timeout is durably and tamper-evidently recorded.

**Capacity consequence — no longer a concern.** Because expiry writes an audit
record rather than a ledger decision, expired proposals do **not** consume
permanent `ApprovalLedger` slots. `MAX_APPROVAL_DECISIONS = 65_536`
(`approval_ledger.rs:217`) is a hard lifetime ceiling with no prune, but only
real human decisions count against it, so an expiring-proposal storm cannot
exhaust it. It remains a hard ceiling worth surfacing as an operational metric
beside the existing `decision_count()` status counter (`lib.rs:1373`), so a full
ledger is seen approaching rather than discovered as a `LedgerFull` refusal.

**Sweeper placement.** A `Daemon`-owned periodic sweep, fenced on the
generation lease like every other write, calling
`ApprovalRequests::expiring_before(now_ms)` and processing a bounded batch. Not
a thread per request: durable suspend/resume (SOTA §2.4) means the wait is a
row, and the sweeper is a reader of that row.

**Reminder ladder.** `reminded_at_ms` on the request row; one reminder at a
configured fraction of the TTL, delivered on the originating `surface` to the
recorded `audience`. Cap at one reminder per request in the first version —
an escalation ladder needs a second approver identity, which
`command_registry.rs:772-779` says does not exist in this product ("a
named-approver policy — a second, identified party recorded durably — is not
represented, because there is no approver identity in this product to name").
Escalation is therefore scoped as **out of M3**, and the roadmap's
"escalation ladder" wording should be amended to "reminder, then auto-deny"
unless the owner wants approver identity built here.

**Re-proposal is a new row with a new key.** `supersedes_key` links the new
request to the expired one; the new request re-computes `context_digest` from
current state (#20) rather than copying it, which is the "re-validating business
state" half of SOTA §2.5. The old row moves to `superseded` only if it was
still `pending`; an already-`expired` row keeps its terminal state and its
denial.

**Configuration.** TTL as a daemon config value with a compiled default, not a
per-request field, so a caller cannot propose an approval that never expires.

### Testing

- Expiry at the boundary: `now_ms == expires_at_ms` is expired (match
  `improvements.rs:905`'s comparison direction exactly, and assert the two
  agree, so the two expiry semantics in the tree cannot drift).
- Sweep is idempotent: running it twice over the same expired row produces one
  ledger denial (`AlreadyRecorded` on the second).
- Sweep is fenced: under a stale lease it writes nothing.
- Re-proposal: expired → re-propose → the new key is distinct, the old denial
  survives, `by_subject` (`approval_ledger.rs:791`) returns both in order.
- A decision arriving in the same millisecond as the sweep resolves exactly one
  way — the single-`UPDATE` fence makes the loser a `StaleRevision`, asserted.
- Capacity: a full ledger refuses `LedgerFull` on auto-deny without corrupting
  the request row's state (the request must not report `expired` if the denial
  could not be recorded — recommend leaving it `pending` and retrying, and
  assert that).

### Effort

**M — 5–7 engineer-days.**

### Dependencies

**#19.** Interacts with #23 (each auto-deny is an audit record with outcome
`timeout`, not `denied` — the AAT vocabulary distinguishes them, and #23 should
land first or the outcome mapping gets retrofitted).

---

## #22 — Fail-closed headless approvals; tighten-only policy composition

### Current state

This is the weakest area in the milestone, and the audit understates it.

- **Authorization is one bit.** `authenticate_peer`
  (`automonique-daemon/src/lib.rs:3787`) is a hand-rolled
  `getsockopt(PeerCredentials)` + `uid != geteuid() || pid <= 0` check, called
  once at `lib.rs:1313` before any decode. The **identical predicate is
  duplicated** in the CLI at `automonique-cli/src/admin_client.rs:277-281`.
- `AuthorizationRequirement` has exactly one variant, `LocalPeer`
  (`command_registry.rs:740`), and `named()` refuses anything else with
  `UnenforceableAuthorization` (`:762`) — an honest design that admits its own
  limit.
- **`ApprovalPolicy` is declarative and unread.** Four admin commands carry
  `OperatorConfirmation` — `fail_reconciliation` (`command_registry.rs:1537`),
  `reconcile_outbox` (`:1616`), `pause_intake` (`:1640`), `shutdown` (`:1674`) —
  and **nothing outside the protocol crate ever calls `.approval()`**
  (`:1138`). Its doc comment says why (`:772-779`): "This is a *client*
  obligation. The daemon […] cannot observe whether a human confirmed anything,
  so **nothing here is enforced server-side**".
- **`automonique-policy` is an orphan crate.** Its `Cargo.toml` `[dependencies]`
  is empty (`:10`); no crate in the workspace depends on it; only its own tests
  reference it. It contains a well-designed capability model that nothing uses:
  `PeerCredential` (`peer.rs:158`, constructible only from explicit components,
  with a `compile_fail` doctest at `:145-156`), `Admission` (`:198`, obtainable
  only from `PeerPolicy::evaluate` so it cannot be fabricated),
  `PeerPolicy::evaluate` (`:293`), and no-wildcard admitted sets (`:230-233`).
  The crate's other half (`lib.rs:14-140`) is a *health* rule evaluator —
  `Importance`, `Observation`, `Disposition`, `summarize` — not an authorization
  one.
- **No composition exists.** No policy stack, no ordering, no evaluator taking
  an `Admission` and an action. The only fold is `summarize()`
  (`policy/src/lib.rs:140`), called from tests only.

### Approach

**Make `automonique-policy` the composition home, and give it its first
production consumer.** Two additions:

1. **`ApprovalRequirement` as a lattice with a tighten-only join.**
   ```rust
   pub enum ApprovalRequirement { None, OperatorConfirmation, Denied }
   impl ApprovalRequirement {
       pub const fn tighten(self, other: Self) -> Self { /* max, ordered */ }
   }
   ```
   Ordered `None < OperatorConfirmation < Denied`; `tighten` is `max`.
   Effective requirement = `config.tighten(host).tighten(per_call)`. The
   property that makes it tighten-only is that `tighten` is a join on a total
   order — **assert it by exhaustive test over all 27 triples**, which is
   tractable because the lattice is three-valued, and which is the kind of
   proof the codebase already favours (`telegram_control.rs:108`'s
   compile-time `assert!` is the precedent). SOTA §2.1's parallel: "hook denials
   apply even in bypass mode" — a loosening input must be unable to reach a
   looser output.

2. **`OperatorSurface` reachability, and the fail-closed default.**
   ```rust
   pub struct OperatorSurfaces { telegram: bool, slack_approvals: bool, cli_peer: bool }
   impl OperatorSurfaces { pub const fn any_reachable(&self) -> bool { … } }
   ```
   Evidence, not configuration: `telegram` is true only when the bridge holds a
   live poller (`telegram.rs:542` `PollerControl`); `slack_approvals` only when
   both the `interactive_decisions` flag (`slack.rs:418`, set at `:597`) and
   `SlackFeature::Approvals` (`:145`) are present — the module already refuses a
   half-configured approval surface (`slack.rs:31`); `cli_peer` only for the
   duration of an admitted admin connection.
   When the effective requirement is `OperatorConfirmation` and
   `any_reachable()` is false, the answer is **deny**, surfaced as
   `ApprovalRefusal::NoOperatorSurface` (#19). This is SOTA §2.3's
   `askFallback: deny`.

**Retire the duplicated peer check.** Route both `lib.rs:3787` and
`admin_client.rs:277-281` through `PeerPolicy::evaluate` (`peer.rs:293`),
producing an `Admission` (`peer.rs:198`) that the handler must hold to proceed.
This adds `automonique-policy` to two `Cargo.toml`s and turns a crate that is
currently a liability (an orphan with a `compile_fail` doctest defending an API
nobody calls) into the authority seam. Behaviour is unchanged in the first
step — same-euid only — which is what makes it a safe refactor to land inside
M3 rather than a new authorization model.

**Give `ApprovalPolicy` a server-side consumer.** The four
`OperatorConfirmation` commands become: daemon reads
`spec.approval()` (`command_registry.rs:1138`), composes with host and per-call
policy, and — when the result is `OperatorConfirmation` — requires a
**matching granted decision in the ledger, bound to this call's context digest
(#20)**, rather than trusting the client. This is the single change that turns
`ApprovalPolicy`'s doc comment (`:772-779`) from an accurate confession into a
historical note, and the doc comment must be rewritten in the same PR.

**Scope guard.** Do *not* introduce approver identity here (see #21). The
composition is over *requirement levels*, not over *who* may decide; who may
decide stays the existing admin tier.

### Testing

- Exhaustive `tighten` table: 27 triples, asserting the result is the maximum
  and that no input ordering produces a looser result than any single input.
- `OperatorSurfaces`: every combination of the three booleans; only
  all-false denies. A test asserting that a *configured but not running*
  Telegram host reports `false` — the difference between configuration and
  evidence is the whole point.
- Headless daemon (no bridge, no Slack, no connected CLI peer) refuses a
  `pause_intake` carrying `OperatorConfirmation` with `NoOperatorSurface`, and
  the audit record's outcome is `denied` (#23).
- Peer refactor: existing daemon and CLI tests must pass byte-identically; add
  one test asserting `Admission` cannot be constructed outside
  `PeerPolicy::evaluate` (extend the existing `compile_fail` doctest style at
  `peer.rs:145-156`).
- Property test (feeds M5 item 26): for random requirement triples, `tighten` is
  associative, commutative and idempotent.

### Effort

**M/L — 7–9 engineer-days.** The lattice is a day; the surface-reachability
evidence plumbing and the four-command server-side enforcement are the bulk,
and the peer refactor touches two crates' dependency graphs.

### Dependencies

**#19** (needs the ledger lookup) and **#20** (needs the context digest to make
"a matching granted decision" mean anything). Independent of #17 only in the
peer-refactor half, which can land early and alone.

---

## #23 — Hash-chained audit records

### Current state

- The pieces exist and are not connected. `Sha256` (`automonique-protocol/src/digest.rs:227`,
  `digest()` `:248`, `Sha256Digest::to_hex` `:171`) is a from-scratch FIPS 180-4
  implementation with the RFC 6234 `"abc"` vector as a doctest (`:16-20`).
  Canonical JSON is `automonique-protocol/src/wire.rs`: `to_canonical_bytes`
  (`:85`), `parse_canonical` (`:160`), key sort by raw bytes (`:107`).
- **`digest` and `wire` are not connected** — nothing hashes a canonical message
  anywhere on the local socket path.
- `generation_audit.rs` (1,382 lines) records tenure history but is not a
  hash chain.

### Correction the roadmap needs — this canonicalization is not RFC 8785

Issue #23 and roadmap item 20 both say "RFC 8785 canonical JSON". A repo-wide
grep for `8785|JCS|jcs` returns **zero hits**. `wire.rs:3-17` claims something
narrower and states it precisely: "Strict canonical JSON for the local protocol,
without a dependency. […] object keys are sorted, there is no insignificant
whitespace, and escaping is minimal and fixed. […] **Numbers are integers
only**". JCS additionally mandates ECMAScript number serialization and **UTF-16
code-unit** key ordering; `wire.rs:107` sorts by **raw UTF-8 bytes**. The two
orderings differ for keys containing characters above U+FFFF (surrogate-pair
range), so this is a real, if narrow, divergence.

Two options:

- **(a) Use the existing canonicalizer, name the profile, drop the JCS claim
  (recommended).** Document the chain as canonicalized under
  `automonique.wire/v1` and state the two divergences from RFC 8785 (integers
  only; byte-order key sort) in the module header. Zero risk, zero new code,
  and the audit record schema controls its own key set — restrict audit record
  keys to ASCII and the ordering divergence becomes unreachable, which an
  assertion can enforce.
- **(b) Implement JCS.** Requires float serialization the protocol deliberately
  refuses (`wire.rs:15-17`: "admitting floating point would add a class of
  precision and round-trip disagreement for no expressive gain") and a UTF-16
  collation. Justified only if the chain must be verified by an external tool
  that is JCS-only.

**Recommend (a), and amend the roadmap text.** Interoperability with the IETF
Agent Audit Trail draft is preserved at the *schema* level (record ids,
timestamps, outcome vocabulary, `prev_hash` semantics), which is the part that
matters for the EU AI Act Annex III obligations SOTA §2.6 cites.

### Approach

**New store module `automonique-store/src/audit_chain.rs`.**

```sql
CREATE TABLE audit_records (
    entry_id      INTEGER PRIMARY KEY,
    record_id     TEXT NOT NULL UNIQUE,       -- UUIDv4
    recorded_at   TEXT NOT NULL,              -- RFC 3339
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    outcome       TEXT NOT NULL CHECK (
                      outcome IN ('success','failure','timeout','denied','escalated')),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
    record_hash   TEXT NOT NULL UNIQUE CHECK (length(record_hash) = 64),
    revision      INTEGER NOT NULL CHECK (revision = 1)
) STRICT;
```

`revision = 1` makes write-once a property of the table, exactly as
`approval_decisions` does (`approval_ledger.rs:248`, rationale `:122-127`).

**Crate-boundary constraint that shapes the design.** `automonique-store`
depends on `nix` and `rusqlite` only — it does **not** depend on
`automonique-protocol` (`approval_ledger.rs:135-137` says so explicitly and
explains why the decision vocabulary is pinned by literal). So the store crate
cannot compute SHA-256 or canonical JSON. Therefore:

- **the daemon computes** `record_hash = SHA256(canonical_json(record ‖ prev_hash))`
  using `automonique_protocol::{wire, digest}`;
- **the store persists and verifies linkage structurally**: on append, it reads
  the current head's `record_hash` inside the same immediate transaction and
  refuses unless the caller's `prev_hash` equals it (`AuditChainError::ChainBroken`
  naming both values, the shape `CancelLedgerError::Conflict` uses at
  `cancel_ledger.rs:129-131`);
- **a verifier lives daemon-side**: `verify_chain(from, to)` recomputes every
  hash and reports the first break.

This keeps the dependency boundary intact and puts the cryptography where the
cryptography already is. It is the same split `cancel_custody.rs` uses — trait
in the runner, durable implementation in the daemon (`control.rs:88-98`).

**Genesis.** The first record's `prev_hash` is 64 zeros, asserted by test, and
the chain head is cached on `Daemon` so an append is one read plus one insert.

**Single-writer.** The daemon holds the generation lease, so the head is
uncontended by construction — the same argument `attempt_host.rs:38-61` makes
for one dispatcher per host. State it in the module doc and assert it with a
fenced-append test.

**What gets a record.** Every approval proposal, decision, expiry, override, and
every context-binding denial. Outcome mapping:
`granted → success`, `denied → denied`, `TTL auto-deny → timeout`,
`context mismatch → denied`, `no operator surface → denied`,
`escalated` reserved and unused until approver identity exists (#21) — declare
it in the CHECK so the vocabulary is complete, and assert by test that nothing
currently emits it.

**The two-database seam, again.** An audit record and the decision it describes
are separate databases. Order: **decision first, audit second**, because a
missing audit record is a detectable gap (the chain is contiguous by
`entry_id`; a decision with no record is found by reconciliation) while an audit
record for a decision that was never committed is a false claim. Document the
choice in the module header rather than leaving it implicit, per the house
practice at `approval_ledger.rs:96-104`.

### Testing

- Chain integrity: append N records, `verify_chain` passes; tamper with one
  row's `actor` via raw SQL, `verify_chain` names that exact `entry_id`.
- Append with a wrong `prev_hash` is `ChainBroken` and writes nothing.
- Genesis `prev_hash` is 64 zeros.
- Determinism: the same logical record hashed twice yields the same
  `record_hash` (guards against a map iteration order sneaking in).
- Outcome vocabulary is exhaustive: a test enumerating all five spellings
  against the CHECK, and one asserting `escalated` has no emitter.
- Cross-language: extend `automonique-protocol/tests/cross_language.rs` with a
  fixture chain, so the TS SDK can verify a chain independently. (Note M5 item
  28 — that suite currently returns early with an invisible `GAP:` note when the
  JS toolchain is absent; a chain fixture that silently does not run is worse
  than none, so this sub-item should wait for or accompany #28.)
- Fuzz seed for M5 item 26: the canonical-JSON encoder over audit record shapes.

### Effort

**M — 6–8 engineer-days.** ~700 lines of store module in house style, ~250
lines of daemon-side hashing and verification, and the test matrix.

### Dependencies

Independent of #17 — the chain is a new module recording events from wherever
they come. Should land **before** #21 so the TTL path emits `timeout` natively.
Consumes #19's decision events and #20's denial events, so it is most useful
after them but can be built in parallel.

---

## #24 — Idempotent approval buttons; strip keyboards after decision

### Current state

Slack is nearly there. Telegram is missing two Bot API methods.

**Telegram outbound is a closed four-method vocabulary**
(`automonique-transport-runtime/src/https_client.rs:214-229`):
`getUpdates`, `sendMessage`, `setMessageReaction`, `setMyCommands`. There is
**no `answerCallbackQuery`**, **no `editMessageText`**, **no
`editMessageReplyMarkup`**. Consequences:

- A pressed button leaves the client-side spinner undismissed — the bridge
  answers with a *new* `sendMessage` (`telegram_bridge.rs:4202-4204`,
  delivered `:5198-5202`).
- A keyboard cannot be stripped after a decision, so a stale message keeps
  firing buttons. The single-use *challenge* prevents a second effect
  (`store/improvements.rs:892-970` consumes on `WHERE consumed_at_ms IS NULL`),
  but the operator sees a live-looking button that silently does nothing.

**The keyboard type is hard-coded to one shape.** `ApprovalKeyboard`
(`https_client.rs:376-379`) holds exactly `approve_callback` and
`revise_callback`; rendering at `:748-755` emits exactly two buttons labelled
"Approve" and "Request changes" in one row, with the golden fixture at `:1171`.
`ApprovalKeyboard::new` (`:382-408`) validates non-empty, ≤ **64 bytes** (the
Bot API `callback_data` cap), no control characters, and
`approve != revise`.

**Inbound callbacks already work, admin-gated.** `callback_query` parsing at
`automonique-transports/src/lib.rs:553-576` requires `data` XOR
`game_short_name` and `message` XOR `inline_message_id`, extracts `from.id` and
`message.chat.id`; the bridge branch at `telegram_bridge.rs:3623-3646` refuses
non-admins (`:3630-3634`) and routes to
`improvement_callback_answer` (`:4209-4333`). The stale comment at
`:3648-3650` still claims "A callback carries no operator command in this
build".

**The callback format is a good template.** `improvements.rs:683-689` /
`:691-708`: `v:<a|r>:<48 hex chars>`, ~54 bytes, where the 24-byte challenge is
HMAC-SHA256 over `improvement_id ‖ revision ‖ kind ‖ actor_id ‖ chat_id ‖
expires_at_ms` (`:619-636`) under a 32-byte key read from `/dev/urandom`, mode
`0600`, never leaving the state directory (`:646-681`). That is already an
opaque, unforgeable, actor-bound, expiring approval ID.

**Slack has everything but the strip.** Buttons and confirm dialog at
`slack.rs:1454-1481`; reject modal at `:1500-1520`; durable idempotency with a
six-field replay comparison and a revision fence at
`slack_interactions.rs:204-252`. The connector **already supports
`chat.update`**: `SlackMethod::ChatUpdate` (`automonique-slack-connector/src/request.rs:56`,
route `:794`), `SlackClient::update_message`
(`automonique-slack-connector/src/client.rs:255`). Nothing calls it after a
decision.

### Approach

**Telegram — add two `WireMethod` variants.** `AnswerCallbackQuery` and
`EditMessageReplyMarkup`, with request types and `canonical_body()` arms beside
the existing ones (`https_client.rs:740-780`), plus `TelegramOutbound` variants
(`:711-719`) and golden-body fixtures in the style of `:1171`. Both are
low-risk: one takes a callback id and optional text, the other takes
`(chat_id, message_id, reply_markup)` and is sent with an **empty**
`inline_keyboard` to strip.

On every decided callback: `answerCallbackQuery` first (dismiss the spinner),
then `editMessageReplyMarkup` with an empty keyboard (strip), then the outcome
message. Order matters — the acknowledgement has a ~10 s deadline on Telegram's
side and must not queue behind the decision's durable writes.

**Generalize `ApprovalKeyboard`.** Replace the two fixed fields with a bounded
list of `(label, callback_data)` pairs — cap at 3 buttons in one row, which
covers approve / deny / request-changes — keeping `new()`'s existing validation
per entry (non-empty, ≤ 64 bytes, no control characters, pairwise distinct
callbacks). Labels stay product vocabulary chosen from a closed set, per the
existing doc comment at `:371-374` ("Labels are product vocabulary rather than
model output"); do not let a caller supply free text.

**Reuse the challenge minting for the general lane.** `approval_key` from #19
is the opaque ID; mint the callback payload the same way
`improvements.rs:619-636` does — HMAC over
`(approval_key ‖ actor_id ‖ chat_id ‖ expires_at_ms)` truncated to 24 bytes.
The `v:<verb>:<48 hex>` shape stays under the 64-byte cap with room for a
three-way verb.

**Idempotency is already structurally guaranteed** by #19's single-`UPDATE`
fence on `approval_requests`; the button work makes it *visible*. A press on an
already-decided request must answer "already decided by X at T" via
`answerCallbackQuery`, never a second effect — and the test must assert both
halves.

**Slack — call `chat.update` after a decision.** In `handle_interaction`
(`slack.rs:1857`), after the decision resolves `Applied`, re-post the card with
the buttons removed and a decided-by line, via
`SlackClient::update_message` (`client.rs:255`). Resolve the interaction row to
`Applied`/`Failed` as it does today (`:1872-1887`). A `chat.update` failure must
**not** roll back the decision — the decision is durable, the card is a view.
Assert that.

**Delete the stale comment** at `telegram_bridge.rs:3648-3650`.

### Testing

- Golden-body tests for both new methods, matching the fixture style at
  `https_client.rs:1171`; a byte-exact fixture for the empty-keyboard strip.
- `ApprovalKeyboard` bounds: 4 buttons refused, a 65-byte callback refused
  (`OutboundRefusal::CallbackData`, `https_client.rs:327`), duplicate callbacks
  refused, an empty label refused.
- Double-press: two `callback_query` updates with the same data produce exactly
  one decision row and two acknowledgements, the second saying "already
  decided".
- Strip ordering: acknowledge precedes strip precedes outcome message; assert
  on the recorded outbound sequence.
- Stale press after strip: an admin who kept an old client copy presses again →
  acknowledged, no effect, no second ledger row.
- Slack: decision applied, `chat.update` called once with no action blocks; a
  simulated `chat.update` failure leaves the decision intact and the interaction
  row `Applied`.
- Non-admin press remains refused (`telegram_bridge.rs:3630-3634`) — regression
  guard, since the callback lane is being widened beyond the improvements
  feature.

### Effort

**M — 5–7 engineer-days**, dominated by the two new Bot API methods and their
golden fixtures rather than by the approval logic.

### Dependencies

**#19** (needs `approval_key` and the request row). Touches the same
`telegram_bridge.rs` regions as #19, so the two should be sequenced rather than
parallelized. Also depends on **M1 item 1**: the outcome strings this issue
re-renders currently carry the legacy bot's real name
(`telegram_bridge.rs:2374`, `:2389`), and #24 must not copy them forward.

---

## Cross-cutting notes

**1. #17's answer changes less than the roadmap implies.** Only #19, #20, #21
and #24 are gated on it, and only #19 changes *size* under "delete"
(+6–8 days). #18, #22 and #23 are triad-independent: cancellation rides
`CancelLedger`/`CancelDispatcher`, policy composition rides
`automonique-policy`, and the audit chain is a new module. **Recommendation:
start #18, #22's peer-refactor half, and #23 immediately, without waiting for
the owner decision.** That is roughly 12–15 days of work that is correct under
every option, and it materially de-risks the milestone.

**2. The load-bearing architectural finding: approvals need a second table.**
`ApprovalLedger` is a *decision* ledger with no pending state, by explicit
design (`approval_ledger.rs:403-406`). Every M3 issue from #19 onward hangs off
a new `approval_requests` table. The working template is
`improvement_approval_challenges` (`automonique-store/src/improvements.rs:99-115`
and its consume path at `:892-970`) — actor-bound, chat-bound, revision-bound,
digest-bound, expiring, single-use. **M3 is largely the exercise of lifting that
one table out of the self-improvement feature and making it the product's
general approval primitive.** Framing the work that way is worth more than any
individual issue in this milestone.

**3. Three roadmap-assumption changes.**
   - *RFC 8785 is not what this repo implements* (#23). `wire.rs:3-17` is a
     self-defined canonicalization: integers only, byte-order key sort. Adopt it
     under a named profile and drop the JCS claim, or accept ~4 extra days to
     implement JCS. Roadmap item 20's wording needs amending either way.
   - *"Escalation ladder" is not buildable in M3* (#21). It needs a second
     approver identity, which `command_registry.rs:772-779` says does not exist
     in this product. Amend item 18 to "reminder, then auto-deny", or add
     approver identity as a separate owner-decision item.
   - *Roadmap item 46 should move from M8 into M3* (#18). The runner still
     defaults to `InMemoryCancelCustody` (`control.rs:483`, `:763`) while the
     daemon has a durable one; leaving them split for the length of M8 means two
     custody stores giving different answers to the same retry.
     `bind_with_custody` (`control.rs:783`) already exists, so this is small.

**4. Four stale doc comments this milestone must fix.** The codebase's prose is
its strongest asset (the audit says most findings were discovered *from* it), so
letting it drift is expensive:
   - `telegram_bridge.rs:822` — `ApprovalWiring` claims the typed connector does
     not expose rejection; `decide_ticket` at `:1092-1109` does.
   - `telegram_bridge.rs:3648-3650` — "A callback carries no operator command in
     this build"; the improvements callback lane at `:3623-3646` is live.
   - `attempt_host.rs:71-74` — "Nothing registers an attempt in a running
     daemon"; `execute.rs:672` does.
   - `command_registry.rs:772-779` — accurate today, false the moment #22 lands.

**5. Two dead or near-dead assets this milestone should resolve rather than
leave.** `automonique-policy` (orphan crate, empty `[dependencies]`, a
capability model nobody calls) is adopted by #22 — the alternative is archiving
it, and leaving it as-is is the worst of the three.
`automation::decide_unattended` (`automonique-protocol/src/automation.rs:1073`,
`UnattendedDecision` at `:1331`, test-only callers) is a *third* approval
concept alongside `ApprovalPolicy` and `ApprovalLedger`; #17's decision record
should name which of the three survives. Note the name collision that will bite
during #19: `automation::ApprovalRequest` (in-memory value) versus
`approval_api::ApprovalRequest` (wire request enum) versus
`connector::ApprovalRequired` (`connector.rs:467`).

**6. The two-database seam appears three times in this milestone** — requests vs
decisions (#19), decisions vs audit chain (#23), and the existing decisions vs
`provider_journal` (`approval_ledger.rs:96-104`). The house practice is to state
the write order and the bounded failure it buys, in the module header, rather
than to hide it. Each new module must do so, and #19's reconcile-on-open sweep
is the first place the product actually repairs one of these seams rather than
only documenting it.

**7. What M3 does not close, and must not claim to.** The exec TOCTOU
(`spawn_plan.rs:29-44`) survives #20; roadmap item 45 closes it. The same-uid
sandbox gap (F-10) survives everything here; item 44 closes it. An approval
system that binds context but executes a path whose bytes can still change is
*better* than approval theater, but the distance to "verified" should be stated
in the approval module's own header, in the voice the rest of this codebase
uses.

**8. Suggested landing order.**
`#18` → `#23` → `#22`(peer half) → **[#17 decision]** → `#19` → `#20` → `#21` →
`#22`(enforcement half) → `#24`.
Total: **45–60 engineer-days**, of which ~12–15 are unblocked today.

**9. Milestone dependencies outward.** M3 depends on **M1 item 1** (the
identifier scrub) for every user-facing string #19 and #24 re-render. It is
independent of M2. It feeds **M4** (the self-improvement gate at
`improvements.rs:892-970` becomes a consumer of the general approval lane rather
than a parallel implementation), **M6** (approval events belong in item 33's
normalized progress-event stream), **M7** (the audit chain and the approval
capacity ceiling both need item 38's exporter), and **M8** (items 42 and 46
inherit automation/batch and the cancellation ledger from #17 and #18).
