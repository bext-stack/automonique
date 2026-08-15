# M2 — Parity harness & shadow gate (implementation plan)

Builds the enforcement mechanism the launch roadmap's parity gate depends on
(finding F-03): a shadow path that produces typed **intended-action
envelopes** instead of executing effects, a golden-trace replay corpus, a
weighted confidence score with a known-deviation registry, and the four
re-specified safety properties. Covers issues #10–#16.

Grounded in the tree at `c2f8b16`; every file:line below was read, and every
tool invocation quoted was run. Neutral terms throughout — where a finding is
about a private identifier in the tree, it is cited by file and line and never
repeated.

## The effect-suppression seam (load-bearing for every issue below)

The central design question — where does "decide to post" become "actually
post"? — has a clean answer: **every externally visible effect in this daemon
already passes through a narrow injected trait.** No new architecture is
required to suppress effects; the work is to add a recording decorator per
trait and a per-scope mode flag that selects it. Full inventory, verified
against the tree:

| Effect | Suppression seam | Definition | Production impl |
|---|---|---|---|
| Slack ticket routing, approval cards, modals, home | `SlackTicketPoster` | `daemon/src/slack.rs:1374` | `slack.rs:1430` (`for SlackClient`) |
| Slack `/say` and `/slack` read | `SlackApi` | `slack.rs:195` | `slack.rs:241` (`for SlackClient`) |
| Slack surface behind the Telegram bridge | `SlackSurface` | `telegram_bridge.rs:981` | `slack.rs:846` (`for SlackWorkspace<A>`) |
| Support-backend ticket mutations | `TicketActionSurface` | `telegram_bridge.rs:1013` | `telegram_bridge.rs:1050` (`for FleetClient`) |
| Support outbound email | `EmailActionSurface` | `telegram_bridge.rs:1113` | `telegram_bridge.rs:1124` (`for FleetClient`) |
| GitHub issue create/reply/checklist/manage | `GitHubActionSurface` | `daemon/src/github.rs:304` | `github.rs:1045` (`for GitHubWorkspace`) |
| GitHub read + inventory completion | `GitHubSurface` | `github.rs:71` | `github.rs:870` (`for GitHubWorkspace`) |
| Telegram `sendMessage` / reaction / menu | `TelegramOutboundClient` | `transport-runtime/src/https_client.rs:877` | daemon holds it as `O: TelegramOutboundClient` (`telegram_bridge.rs:3091`) |

Notes that change the shape of the work:

- **`SlackTicketPoster` is private** (`trait`, not `pub trait`, `slack.rs:1374`)
  and `SlackTicketRouter<P>` (`slack.rs:1566`) is generic over it while holding
  `manage: Box<dyn TicketActionSurface + Send>` (`slack.rs:1568`). Decorating it
  from a sibling module needs it raised to `pub(crate)`; the router needs no
  other change because it is already generic.
- **Telegram is the strongest precedent in the tree, and it is already built.**
  `TelegramOutbound` (`https_client.rs:702`) is a closed enum of the three
  methods this product may call, and `TelegramOutbound::canonical_body()`
  (`https_client.rs:731`) renders the exact wire body with the doc comment
  "Token-free by construction, so a host may log or fixture it." Every Telegram
  effect funnels through one function, `send_outbound`
  (`telegram_bridge.rs:5532`), which for a `SendMessage` already builds a
  serde-serializable `PersistedTelegramMessage` (`telegram_bridge.rs:5763`),
  takes `Sha256::digest(&payload).to_hex()`, mints an `intent_key`, and stages
  it in the canonical durable outbox before delivery (`:5563`), draining via
  `drain_telegram_outbox` (`:5605`). That is an intended-action envelope with a
  content digest and an idempotency key, in production, today. **The envelope
  design below should generalize this, not invent beside it.**
- The daemon already splits decide from execute on the Telegram path:
  `answer_for` (`telegram_bridge.rs:3619`) returns the typed `Answer` enum
  (`telegram_bridge.rs:5810`) before anything is delivered.
- The one path with no trait between decision and effect is
  `github_actions: Option<GitHubActionEngine<SocketRunLane>>` (`slack.rs:1575`)
  — but the engine itself holds `surface: Box<dyn GitHubActionSurface + Send>`
  (`github_actions.rs:83`), so the seam exists one level in.
- **There is no dry-run or effect-suppression flag anywhere in Rust today.**
  The only `DryRun` type is schema metadata in
  `protocol/src/command_registry.rs:827`, and its own doc (`:1332-1335`) says
  "No shipped command supports a dry run"; every registered command is
  `DryRun::Unsupported`. `slack.rs:65` states the opposite of shadow mode
  outright: "Nothing here is a dry run."

**Two more reusable facts:**

- Store pattern: one module = one SQLite file, STRICT tables, `user_version`
  ladder, record-once with three-way answers (Recorded / AlreadyRecorded /
  Conflict); `cancel_ledger.rs` and `slack_ingress.rs` are the templates, and
  `run_submissions.rs:135` is the exact precedent for *document bytes + content
  digest* (`document BLOB NOT NULL`, `spec_digest TEXT NOT NULL CHECK
  (length(spec_digest) = 64)`, validated on write *and* re-validated on read).
- The oracle already fixes a closed diff vocabulary
  (`tools/oracle/vocabulary.py`, generated list in `vocabulary.md`): outcomes
  exact / equivalent / intentionally_changed / unexplained; relations
  value_differs / absent_in_candidate / absent_in_reference / type_differs /
  order_differs / masked_nondeterministic; magnitudes none / minor / moderate /
  major. Better still, `tools/oracle/fields.json` already registers the
  comparison fields this harness needs — `state_transition`, `action_effect`,
  `receipt`, `rendered_message` ("rendered message structure, not its text"),
  `provider_event` — with `receipt_timestamp` and `provider_event_id` flagged
  `masked: true` as approved-nondeterministic. Reuse both (also matters for
  #16): a live-traffic comparison and a future archive-differential comparison
  should produce verdicts in one shape.

## Recommended order

1. **#15** — S, no dependencies. Fixes the one red tools test and turns on the
   CI guardrails every doc-derived artifact in this milestone depends on. Do it
   in week one so nothing later lands on an unguarded tree.
2. **#16** — S, owner-decision memo. The gate's own text claims it blocks "all
   differential parity work" (`gates.md:202`), so an unresolved #16 reads as
   blocking the rest of M2. Resolve the *reading* before building against it.
3. **#13 spec half** — docs plus conformance scaffolding. Independent of the
   harness, and the semantics need owner sign-off, so start the clock early.
4. **#10** — the keystone. Split it in two and ship the halves separately:
   **(4a)** the protocol envelope + store table + the **Telegram** decorator,
   which is the smallest complete vertical slice and reuses a mechanism already
   in production; **(4b)** the Slack/Support/GitHub decorators and the
   legacy-observer, which is where the real unknowns are (the `bot_id` filter,
   correlation by thread ts).
5. **#11** — depends on 4a, not on all of #10. A replay corpus over Telegram
   envelopes is useful before Slack shadowing exists.
6. **#12** — depends on #10 + #11.
7. **#14** — last in logic, but start traffic capture the moment 4b lands;
   its cost is calendar time, not code.

Dependency spine: #15, #16, #13 → none; #10 → none; #11 → #10 (4a);
#12 → #10 + #11; #14 → #10 (4b) + #12.

### Issue #10 — Build the shadow-comparison harness (intended-action envelopes)
**Current state.** See the seam table above: every effect is already behind a
trait. What does not exist is any envelope type, any shadow store, any
suppression mode, and any comparator — confirmed by a repo-wide search
(`rg -i 'shadow|dry.?run|parity'` over `rust/crates`): the only `DryRun` is
inert schema metadata, and `slack.rs:65` documents the current posture as
"Nothing here is a dry run."

**Approach — the protocol type.** New module
`automonique-protocol/src/parity.rs` (+ `pub mod` line in `lib.rs`, alphabetical).
Follow the crate's actual conventions, which are *not* serde and not RFC 8785:

- The crate has **zero dependencies**; canonical JSON is hand-rolled in
  `wire.rs` (`JsonValue::to_canonical_bytes`, `wire.rs:85`; `parse_canonical`,
  `wire.rs:160`), sorts object keys in **UTF-8 byte order**, admits **integers
  only**, and *refuses* non-canonical input rather than normalizing it
  (round-trip proof at `wire.rs:173-177`).
- There is no `Serialize` trait to derive. The idiom is the three-method set
  `to_document(&self) -> JsonValue` / `to_canonical_bytes()` /
  `from_canonical_bytes()`, with `BatchPlan` (`batch_runner.rs:885-928`) as the
  closest working template, and a private `exact_fields` gate on decode
  (`batch_runner.rs:1222-1258`) so unknown *and* missing keys are refused.
- Carry a `schema` member, `"automonique.intended-action/v1"`, as **domain
  separation** — the reason is written out at `release_trust_root.rs:122-125`
  ("Without it, a signature over some other document that happened to share
  this shape would also verify here"). Check it with `expect_schema` →
  `UnknownSchema`.
- Digest via `digest::Sha256Digest` (`digest.rs:160`, `Sha256::digest`,
  `digest.rs:248`), following `ReleaseManifest::canonical_digest`
  (`release.rs:1137-1143`). Prefer `Sha256Digest` over the crate's three weaker
  digest newtypes: it is the only one where a wrong-width or unnamed-algorithm
  digest is unrepresentable.
- The action-kind enum selects behaviour, so implement `SecuritySensitiveEnum`
  (`codec.rs:734`) — an unknown spelling must be refused, not retained.
- Absent optionals are written as `JsonValue::Null` and still named in
  `exact_fields` (the crate distinguishes Optional from Nullable deliberately —
  `codegen.rs:822-832`).

Shape: `IntendedActionEnvelope { schema, scope, source_key (≤ the 640-byte
transport-key bound, `store/src/lib.rs:61`), sequence (u32), engine ∈
{shadow-candidate, legacy-observed}, action: IntendedAction, observed_at_ms
(caller-supplied — the store crate takes `now_ms` from callers everywhere so
tests carry no ambient clock, `store/src/lib.rs:5-7`) }`, with
`content_digest()` derived rather than stored. `IntendedAction` is a closed
enum mirroring the seam table one-for-one: `SlackThreadReply`,
`SlackChannelPost`, `SlackApprovalCard`, `SlackDecisionUpdate`, `SlackModalOpen`,
`TicketDispatch`, `TicketConfirm`, `TicketDecision`, `TelegramSend`,
`GitHubIssueAction`, `SupportEmailSend`, and `NoAction { reason }` — deliberate
silence must be diffable, or a shadow that stays quiet scores as agreement.
Normalization is typed rules in the same module (`normalized()`: whitespace
collapse, timestamp and opaque-id elision using the `masked: true` fields
already registered in `tools/oracle/fields.json`); field-level diffs emit the
oracle's closed relation vocabulary.

**No codegen or SDK regeneration is required.** The TypeScript emitter covers
only the modules listed in `codegen.rs:5384` (`maintained_modules()`), and
`codegen.rs:96-113` explicitly excludes `models`, `sandbox`, `release`,
`journal`, `context`, `interaction`, `event`, `workspace`. A new
`automonique_protocol::parity` module inherits the namespace prefix and passes
`tests/namespace.rs` with no list to update. Only if the envelope later has to
cross the admin/runs/approval wire does it enter `maintained_modules()` and
force `AUTOMONIQUE_PROTOCOL_REGENERATE=1 cargo test -p automonique-protocol
--test codegen` plus committed `.ts` and `fixtures/*-v1.json`.

**Approach — the store table.** New sibling module
`automonique-store/src/shadow_parity.rs` with its own SQLite file at
`SCHEMA_VERSION = 1`, following `run_submissions.rs` as the template
(`open` → `open_with_capacity`, `secure_path`, `create_new` at `0o600`,
`NOFOLLOW|NO_MUTEX|PRIVATE_CACHE`, WAL verified, `synchronous=FULL`, own error
enum with `category()`, own `tests/shadow_parity.rs`). A **sibling, not the main
DB**, is the right call and the crate's own doctrine says why: the per-file doc
comments at `daemon/src/lib.rs:133-251` reserve the main DB for scheduler state
and for anything that must commit *in the same transaction* as the thing it
gates (that is the stated argument for `intake_pauses` in `MIGRATE_V5_TO_V6`,
`store/src/lib.rs:384-397`). A parity record is derived observation and needs no
such atomicity, and a sibling avoids bumping `SCHEMA_VERSION` 6→7, editing all
nine ladder-replay tests in `mod migration_tests` (`store/src/lib.rs:4774`), and
re-pinning `tests/compat_manifest.rs:27-32` against
`protocol/src/compat.rs:1136`.

Two tables. `intended_actions`: `UNIQUE (scope, source_key, engine, sequence)`,
`envelope BLOB NOT NULL` + `envelope_digest TEXT NOT NULL CHECK
(length(envelope_digest) = 64 AND envelope_digest NOT GLOB '*[^0-9a-f]*')` —
the DDL-level hex-alphabet check from `context_memory.rs:341`, which is stricter
than `run_submissions`' Rust-side `validate_digest` — `observed_at_ms INTEGER
NOT NULL CHECK (observed_at_ms >= 0)`, record-once with the three-way
answer (Recorded / AlreadyRecorded / Conflict naming the first differing field)
copied from `run_submissions.rs:483-561`. `comparisons`: verdict ∈
{match, mismatch, shadow_only, legacy_only}, the diff as canonical JSON bytes,
classification ∈ {parity, known_deviation, regression}, `compared_at_ms`. Both
STRICT; capacity ceiling refused as `LogFull { capacity }` rather than evicting,
per the crate-wide convention (`run_submissions.rs:103`). The store never
computes or parses JSON — it stores opaque bytes and validates the digest's
spelling; canonicalization and hashing belong to the caller. That is not a
simplification, it is the existing rule (`grep -i json` over
`automonique-store/src` returns nothing).

**Approach — interposition.** New `automonique-daemon/src/shadow.rs` supplying a
recording decorator per seam: `ShadowPoster: SlackTicketPoster`,
`ShadowTicketSurface: TicketActionSurface`, `ShadowEmailSurface:
EmailActionSurface`, `ShadowGitHubSurface: GitHubActionSurface`, and
`ShadowTelegramClient: TelegramOutboundClient`. Each records an envelope and
performs no IO, returning a synthetic non-committal receipt
(`dispatch_ticket` → an unapproved receipt; `post_thread` → `Ok(())` with no
call). Raise `SlackTicketPoster` to `pub(crate)`. A per-scope mode flag
{primary, shadow, dual} in daemon config selects which implementations the
router and bridge are built with — deliberately mirroring the legacy bot's own
router flag + shadow-mode precedent, which `reference/legacy-inventory.md:275-278`
records as "a working precedent to match, not invent."

The Telegram lane needs the least new code and should be built **first** as the
reference implementation: `send_outbound` (`telegram_bridge.rs:5532`) already
digests and stages a canonical payload before delivery, so shadow mode there is
staging the envelope and skipping the drain, and the existing outbox is the
proof the pattern survives restart.

**Approach — the legacy-observed side.** A `LegacyObserver` on the same Slack
ingest recognizes messages authored by the configured legacy bot user id
(config-driven, never a literal, per F-01) and records them as
`engine=legacy-observed`, correlated by channel + thread ts to the provoking
event's `source_key`. Comparison runs offline as CLI verb `parity compare` over
the DB — deterministic, no network.

**Files.** create `automonique-protocol/src/parity.rs` (+ `pub mod` line, tests
at `automonique-protocol/tests/parity.rs`);
`automonique-store/src/shadow_parity.rs` (+ `pub mod` line,
`automonique-store/tests/shadow_parity.rs`); `automonique-daemon/src/shadow.rs`;
modify `slack.rs` (raise `SlackTicketPoster` visibility, per-scope router
construction, observer hook), `telegram_bridge.rs` (mode selection at
`:3091`/`:5532`), the `DaemonConfig` path accessors and `Daemon::open` opening
order in `daemon/src/lib.rs:333-405` / `:745-982`; CLI verb in
`automonique-cli`.

**Testing.** protocol round-trip / bounds / refusal / unknown-schema in-crate;
store ladder + record-once/conflict mirroring `run_submissions`; daemon test
`automonique-daemon/tests/shadow_parity.rs` driving
`SlackTicketRouter<ShadowPoster>` and asserting **zero** calls landed on a
spying fake poster/surface *and* the exact envelope stream — the zero-call
assertion is the real deliverable, because "the shadow performed no effect" is
the property the whole milestone rests on. Plus a comparator test producing
match/mismatch from two recorded streams. No new runtime dependencies in any
crate.

Add parity counters to the observability crate at the same time:
`MetricName` is a closed enum with `pub const ALL: [Self; 19]`
(`observability/src/lib.rs:45`), so new names are a compile-checked edit there,
not an ad-hoc counter.

**Effort.** L overall — but split as recommended above it is M (4a: protocol
type, store module, Telegram decorator) + M (4b: remaining decorators plus the
legacy observer, where the unknowns live). **Dependencies.** None in code; see
#16 for the governance reading.

**Risks/decisions.** (1) `GitHubActionEngine<SocketRunLane>` is concrete
(`slack.rs:1575`), but it holds `Box<dyn GitHubActionSurface + Send>`
(`github_actions.rs:83`), so the GitHub lane is decorated one level in and needs
no new trait. Nor does the provider side: `RunLane`
(`telegram_bridge.rs:1708`, `run` / `run_question`) is already a public trait
that tests inject fakes for, which is exactly the deterministic mock runner #11
needs — **no new seam is required anywhere in this milestone.** (2) `slack_ticket_event`
(`slack.rs:889`) drops any event carrying a `bot_id` (`slack.rs:901`, and again
at `slack.rs:2628`), so the legacy bot's own messages are filtered out *before*
the observer could see them — the observer
must tap upstream of that filter or carve an allowance for the configured legacy
bot id alone. This is a real code change, not a configuration one. (3) Legacy bot
id and tenant coordinates live in daemon config only, never as literals (F-01;
note `slack.rs:1471` currently hard-codes a real client console URL in a Block
Kit button, which M1 item 1 is removing). (4) DB retention needs a stated bound
from day one — the crate's convention is a capacity ceiling that refuses, not an
evicting ring buffer.

### Issue #11 — Golden-trace fixture corpus with deterministic replay
**Current state.** Golden-fixture precedent exists
(`automonique-runner/tests/fixtures/run_spec_v1_full.cjson` + adversarial/
decode/invariants triple); `scrub.yml` scans every push. No parity trace
format or replay harness today.

**Approach.** A trace is an ordered canonical-JSON-lines file (`.cjson`): a
header (schema `automonique.parity-trace/v1`, scope, parity-row ref, category
tag for #12, provenance), then inbound-event records, provider-interaction
records (prompt digest + canned response), and both engines' envelopes from
#10. Capture is `tools/parity/traces.py`, exporting from
`shadow-parity.sqlite3`, anonymizing **at capture** (stable synthetic
tokens for user/channel/tenant/thread ids via a deterministic mapping), and
refusing any output that trips `tools.scrub.scan`. Replay is a hermetic
`cargo test` in the daemon crate: construct `SlackTicketRouter` with the #10
shadow surfaces and a deterministic mock provider lane fed from the trace's
canned responses, feed recorded inbound events, collect+normalize envelopes,
diff against recorded legacy envelopes; assert every diff classifies parity or
known-deviation. Corpus organized per parity row, seeded from the pinned and
partial rows of `feature-parity.md` — seed from the **derived ledger**, not the
prose: the prose claims 15 pinned / 5 partial (`feature-parity.md:20-21`) while
`plan/ledgers/parity.json` measures 14 / 6 and records the gap as two
`declared-count-divergence` findings. Wiring the ledger into CI (#15) makes that
divergence visible on every push, so reconcile it once here rather than seeding a
corpus from a count that is about to change. The mismatch→fixture ritual is one
documented command.

**Files.** create `tools/parity/traces.py` + `test_traces.py`;
`automonique-daemon/tests/fixtures/parity/<scope>/*.cjson`;
`automonique-daemon/tests/parity_replay.rs`; `docs/parity-harness.md`.

**Testing.** the replay test is the deliverable (hermetic, part of
`cargo test --workspace`); `traces.py` unittest coverage including a deliberate
leak-attempt vector proving capture refuses unscrubbed content; a determinism
test replaying one fixture twice for byte-identical streams.

**Effort.** M. **Dependencies.** #10.

**Risks/decisions.** Anonymization at capture, never at commit review — a raw
trace must never exist in the tree even transiently. The deterministic mock
provider needs no new seam: `RunLane` (`telegram_bridge.rs:1708`) is already the
injection point and daemon tests already substitute fakes for it. Trace schema
frozen at v1 and refused on unknown schema rather than best-effort parsed, which
is the crate-wide decode posture (`expect_schema` → `UnknownSchema`). Note the
trace format is canonical-JSON *lines* while the protocol crate's canonical form
admits integers only and no floats (`wire.rs:305-336`) — any latency or score
recorded in a trace must be an integer (milliseconds, basis points), or it
cannot round-trip.

### Issue #12 — Weighted parity confidence score and known-deviation registry
**Current state.** The doc→derived-ledger pattern exists
(`tools/parity/ledger.py` → `plan/ledgers/parity.json`). No score, bands, or
deviation registry today.

**Approach.** The score is a pure function in `parity.rs`: weights (happy ×1,
error ×2, edge ×2, variety ×1.5, production-representative ×3) and bands
(0–30 block, 31–60 caution, 61–85 shadow-ready, 86–100 cutover-ready) as
constants with unit tests, over typed category-tagged inputs (category from
the trace header for fixtures, production-representative for live rows).
Computation runs in CLI `parity score --scope`, reading
`shadow-parity.sqlite3` + fixture-replay results + the registry; the
go/no-go is recorded durably as a `gate_decisions` row (scope, score, band,
per-category counts, registry digest, evidence digest, decided_at_ms, decider).
The known-deviation registry follows the doc→derived-ledger pattern: a human
doc `docs/product-plan/reference/known-deviations.md` (scope, action kind,
field, relation, reason ∈ {bug-fix, deliberate-improvement}, owner/date)
derived + drift-checked by `tools/parity/deviations.py` into
`plan/ledgers/deviations.json` with a closed vocabulary and refusal semantics.
The Rust comparator loads the digest-pinned registry and classifies each diff
parity / known-deviation (with entry id) / regression; an unmatched mismatch
is always regression.

**Files.** modify `parity.rs` (weights/bands/score/classification) and
`shadow_parity.rs` (`gate_decisions` via ladder migration); create
`known-deviations.md`, `tools/parity/deviations.py` + `test_deviations.py`,
`plan/ledgers/deviations.json`; CLI verbs `parity score` / `parity gate`.

**Testing.** protocol unit tests pinning exact weights/bands and boundaries
(30/31, 85/86); a scorer test over a synthetic corpus; registry drift tests in
the `ledger.py` style; a classification test (registered deviation →
known-deviation; identical unregistered diff → regression); a store test that a
gate decision row is immutable (conflict on re-decide without a new id).

**Effort.** M. **Dependencies.** #10, #11.

**Risks/decisions.** Category tagging is human judgement (in the trace header,
PR-reviewed); the score record pins the registry digest so a later edit cannot
rewrite a past decision.

If #12 is certain to follow #10 closely, put `gate_decisions` in the sibling
DB's **v1 schema** rather than migrating it in. Sibling stores in this crate
almost never migrate: `support_tickets` is the only one that ever has, and it
needed a full rename-and-copy table rebuild (`support_tickets.rs:261-274`)
because `ALTER TABLE ADD COLUMN` cannot add the cross-column `CHECK` the new
invariant required — which is exactly the shape a `gate_decisions` row needs.

The weights are non-integer (variety ×1.5), so keep the score in fixed-point
integers end to end — the protocol crate's canonical JSON refuses floats
outright (`wire.rs:305-336`), and a score that cannot be canonically encoded
cannot be digested into an immutable decision row.

**Owner decision:** whether cutover-ready (86+) licenses progressive cutover
automatically or still requires an owner ack per scope — recommend the latter
(SOTA §3: a gate licenses progressive cutover, never a flip).

### Issue #13 — Specify and test the four legacy safety properties
**Current state.** The four properties have no spec and no implementation, but
they are not undocumented — each already has a parity row that states the
requirement and records that no fixture pins it, which is the exact reason
`launch-roadmap.md:32-39` says they must be "deliberately re-specified, not
inferred":

- fail-closed deploy channel — `feature-parity.md:70`, marked **Replace**, with
  evidence "no fixture; fail-closed is a safety property and must be
  re-specified, not inferred";
- scheduler bounded-parallelism / per-scope serialization / pause-cancel —
  `feature-parity.md:90`, "the scheduler core is entirely unpinned — largest
  single gap";
- separately-authorized deletion — already *enforced* in the legacy system by a
  distinct delete credential held apart from the ordinary bot credential
  (`legacy-inventory.md:211-214`), so this one has an observable reference
  behaviour to specify against rather than invent;
- announce-target-before-mutation — named in launch Increment 4
  (`launch-roadmap.md:148-167`) with no row-level fixture.

The conformance pattern to reuse exists at
`automonique_protocol::connector_conformance` (`protocol/src/connector_conformance.rs`).

**Approach.** Four new requirement docs, one per property, each with explicit
failure-mode semantics: `requirements/deploy-notifications.md` (unconfigured/
unreachable channel ⇒ typed refusal + operator alert, never fallback to intake),
`requirements/mutation-announcement.md` (durable announcement naming the exact
target precedes every externally visible mutation, with a stop-check window),
`requirements/deletion-authority.md` (deletion is a distinct approval class
under a separately held credential; the ordinary credential's delete verb
refuses), `requirements/scheduler-core.md` (bounded parallelism, per-scope
serialization, pause/cancel — deliberately also the M8 scheduler spec).
Conformance tests ship with each spec using the existing conformance pattern:
a generic suite over a small trait per property, exercised now against an
in-memory reference implementation so the suite is green and *defines* the gate,
with daemon bindings as later work. Each `feature-parity.md` row for these four
gains a spec citation via the corpus amendment scheme.

**Files.** create the four requirement docs; register in
`docs/product-plan/README.md` index; conformance modules + reference models
(e.g. `automonique-protocol/src/safety_conformance.rs` or one module per
property beside its future owner); amend `feature-parity.md` rows.

**Testing.** the four conformance suites (green against reference models in
`cargo test --workspace`, including the negative fail-closed cases). Cases that
can only bind to unbuilt daemon surface are `#[ignore = "gate: awaiting
implementation"]` (CI runs the full workspace, so red-by-design is not an
option).

**Effort.** L. **Dependencies.** none.

**Risks/decisions.** the corpus is provenance-tracked and mostly frozen at the
2026-08-09 baseline — new docs and row amendments must follow the amendment
scheme (transferred_sha256/amended_per) and be registered, or the
derived-artifact checkers (#15) flag drift. The exact semantics are owner
decisions per the launch roadmap ("four decisions that cannot be inferred") —
draft, then owner-sign before treating the suites as gates.

### Issue #14 — Retroactive shadow verification for scopes already live  [owner-decision]
**Current state.** Live scopes shipped past the gate: Slack ticket routing +
approval cards, Slack conversational/GitHub Q&A, Support ticket intake +
drafting, GitHub issue actions, Support email compose/send. Slack outbound
landed in `d49e8da` and `550265b` with no shadow-comparison run, and launch
Increment 3 (Slack ingest **in shadow**, zero outbound) was skipped entirely.

Enumerating the live scopes cannot be done from `launch-roadmap.md`, and that is
its own problem: the roadmap's "Where we are today (verified against the code)"
section (`:41-65`) still says Telegram has no client, there is no execute lane,
Slack is "unbuilt for live use", and the Support backend is "entirely unbuilt".
None of that is true. The scope enumeration must come from the code and the
daemon's configuration surface, and the reconciliation of the roadmap text is
M1 item 3 (F-04) — do not let #14 silently become that work.

**Approach.** Enumerate live scopes, map each to its parity-ledger rows. For
each, use the #10 per-scope mode: where the legacy bot still serves the scope,
run dual-mode (primary keeps executing, every decision also recorded as an
envelope) or full shadow, accumulate production-representative comparisons for
a stated window, compute the #12 score, record the gate decision. Where the
legacy bot no longer serves a scope there is no comparison target — the
owner-decision named by the issue: scope back (legacy resumes primary,
Automonique drops to shadow) or record explicit risk acceptance. Every outcome
lands in two places: a `gate_decisions` row and a dated
`plan/owner-decisions/*.md`; deviations get registered (#12); each investigated
mismatch becomes a #11 fixture.

**Owner-decision options.** Per scope: (A) scope back to shadow-only until it
passes — safest, reversible; (B) record explicit risk acceptance and keep it
primary — faster, but names the residual risk. Recommend A for any scope
without a live legacy comparison target.

**Files.** daemon config per-scope modes (from #10); one
`plan/owner-decisions/*.md` per scope; registry entries + regenerated ledger;
fixtures; a scope-status table in the harness doc.

**Testing.** the verification is operational; repo-side tests are the minted
fixtures plus a `tools/parity` check that every enumerated live scope has a
recorded gate status.

**Effort.** M in code; L in calendar time — days-to-weeks of traffic per scope,
so start capture on the first scope the moment #10 lands.

**Risks/decisions.** dual-mode on a live scope must be provably read-only on
its shadow half (reuse #10 zero-effect tests); if both the legacy bot and
Automonique currently act on the same scope, that fact is itself a finding to
record before comparing.

### Issue #15 — Wire parity ledger and identifier inventory into CI
**Current state.** `tools/parity/ledger.py` and `tools/identifiers/inventory.py`
are green and orphaned; one red test (`tools/identifiers/test_inventory.py:326`
— its injected fixture cites AGENTS.md with evidence literal "automonique-lab",
removed in the 2026-08-12 rewrite, so it dies on the evidence-literal check
before reaching the corpus-boundary refusal it exists to prove; verified live:
42 tests, exactly this failure). `plan.yml` job is `licence-boundary` only.

**Approach.** Fix the red test first. The mechanism, confirmed by running it:
the fixture at `test_inventory.py:313-327` injects a `Cited` entry naming
`AGENTS.md` to prove the *corpus-boundary* refusal, but `build()` checks the
citation's evidence literal first (`inventory.py:1196-1206`) and raises
"cited entry 'automonique-lab' no longer occurs in AGENTS.md", so the assertion
at `:326` never sees the message it is testing for. Commit `8acf150`
(2026-08-12) removed that literal from `AGENTS.md`. The fix is to point the
fixture at a string `AGENTS.md` still contains, so the corpus check is the
first one to fire — the tool is correct, only the fixture rotted.

Then extend `.github/workflows/plan.yml` (workflow `name: source-policy`, which
already sets up Python 3.12 at `:20-22` and already runs a
`python3 -m unittest tools.*` step at `:28`) with the derived-artifact
verifications. Exact invocations, all verified green today except the one noted:

```
python3 tools/parity/ledger.py                        # exit 1 on drift
python3 -m unittest tools.parity.test_ledger          # 35 tests
python3 tools/identifiers/inventory.py verify         # exit 1 drift, 2 error
python3 -m unittest tools.identifiers.test_inventory  # 42 tests, 1 red until fixed
python3 tools/oracle/check_boundary.py                # exit 1 on drift
python3 -m unittest discover -s tools/oracle -p 'test_*.py'   # 74 tests
```

This makes editing `feature-parity.md` without regenerating
`plan/ledgers/parity.json` a CI failure, and gives #12's `deviations.py` a slot
in the same step. Note what CI runs today: only `tools/scrub/` and
`tools/test_check_licenses.py` — 13 of 14 top-level `tools/test_*.py` files and
all of `tools/parity`, `tools/identifiers`, `tools/oracle`,
`tools/contract_inventory`, `tools/surface_inventory` run nowhere.

While in this file, record two stale gate claims for M1/M5 rather than fixing
them here: `plan/gates.md:75-76` says `.github/identity/check_identity.py` is
"run by `.github/workflows/identity.yml`", a workflow `8acf150` deleted; and
GATE-BASELINE is marked **closed** on evidence (`gates.md:37`,
"`python3 plan/check.py --verify` exits zero in CI on every push") that the same
commit removed from `plan.yml`.

**Files.** modify `tools/identifiers/test_inventory.py` (fixture literal);
modify `.github/workflows/plan.yml` (add steps to the existing
`licence-boundary` job, or a sibling `derived-artifacts` job in the same file —
either keeps one checkout and one Python setup).

**Testing.** the wired suites are the tests; prove the negative path once via a
scratch-branch one-character `feature-parity.md` edit confirming CI goes red.

**Effort.** S. **Dependencies.** none — do this first.

**Risks/decisions.** confirm each checker has a true write-nothing verify mode
and exact invocation before wiring (ledger.py and inventory.py verified here;
the other four need the same one-minute check). `plan/check.py` and
`plan/selftest.py` stay out of scope (red for deeper reasons — M5 #34).

### Issue #16 — Close or re-scope GATE-ORACLE  [owner-decision]
**Current state.** GATE-ORACLE (`plan/gates.md:190-237`) declares "Blocks:
`R0-02` and `R0-07` fixture capture, and **all differential parity work**"
(`:202`). Three of its four closing conditions are met and measured; the fourth
is not — "the candidate records 0 reviewers, there is no owner acceptance under
`plan/owner-decisions/`" (`:221`).

Closure is mechanical and cannot be done in prose: `plan/check.py:364-365`
derives the closed set as `{closes_gate where status == "done"}`, and
`BOOT-004` — the only item carrying `closes_gate = "GATE-ORACLE"`
(`plan/work-graph.toml:83`) — is `status = "blocked"` (`:84`). Two items declare
`blocked_by_gates = ["GATE-ORACLE"]` (`work-graph.toml:116`, `:172`). The gate
text says so itself (`gates.md:225-226`): "no edit to this file can close it
alone."

`tools/oracle/` is a protected policy boundary: 74 adversarial tests green,
`check_boundary.py` green, and `GOVERNANCE.md` § Protected policy changes
reserves changes to `release.py`/`scan.py`/`vocabulary.py`/`fields.json` to an
external exact-revision decision. Nothing in CI or `plan/check.py` runs it today
(#15 fixes that).

**Owner-decision options.** **Path A (staff it):** name reviewers, run the
configured review against the exact boundary candidate revision, complete
BOOT-004 (the only unmet closing condition). **Path B (re-scope):** record that
GATE-ORACLE's blocking claim distinguishes archive-differential work (against
the private legacy archive on the custody host — stays blocked) from
live-traffic shadow comparison (#10/#11/#14 observe only what the legacy bot
publicly emits in shared channels, never crossing the custody boundary) — under
that reading, all of M2 proceeds while the gate stays open for the fixture-
capture items. **Recommendation:** B now + A when archive fixtures are actually
wanted; the M2 harness reuses the oracle's closed relation vocabulary so later
archive-differential verdicts land in the same shape.

**Files.** create `plan/owner-decisions/2026-XX-XX-gate-oracle-scope.md`; under
B, a measured update to the GATE-ORACLE scope statement in `gates.md` (+ any
`plan/baseline.py` derivation touch); under A, the review record bound to the
exact revision.

**Testing.** `tools/oracle/test_boundary.py` (74 adversarial tests) stays green
untouched — re-scoping changes what the gate blocks, never what the boundary
releases; plan-side records must survive the #15 checkers.

**Effort.** S. **Dependencies.** none (resolve in week one — the roadmap text
currently reads as blocking all of M2's differential work).

**Risks/decisions.** changing the oracle boundary's scope is a protected policy
change under GOVERNANCE.md — path B must narrow the gate's *blocking claim*,
not weaken the boundary. If the owner wants archive-differential comparison
inside M2, that converts #16 into path A and adds custody-host review time
ahead of #14.

## Cross-cutting notes

**No new seams, and no new dependencies.** The single most important finding of
this survey is that the effect-suppression seam this milestone was assumed to
need already exists eight times over (see the seam table). `automonique-protocol`
has *zero* dependencies and `automonique-store` has three; nothing in M2 should
change that. Every envelope, digest, and canonical encoding uses machinery
already in the tree.

**Build the Telegram lane first.** It is the only surface where the full
pattern — typed action enum, token-free canonical body, content digest,
idempotency key, durable staging before delivery — is already running in
production (`telegram_bridge.rs:5532-5605`). Generalizing a working mechanism is
a much smaller risk than designing one, and it gives #11 and #12 a real envelope
stream weeks before the Slack observer work lands.

**The zero-effect property is the deliverable.** A shadow harness whose shadow
half can still post is worse than no harness, because it converts a missing gate
into a false one. Every decorator ships with a test that asserts zero calls
reached the underlying seam, and those tests are the gate on merging #10 — not
the envelope schema, not the diff format.

**Identifier hygiene composes with M1.** No legacy or client identifiers in
code, config defaults, fixtures, or commit messages, with anonymization applied
at trace capture rather than at review. Two live examples this milestone touches
directly: `slack.rs:1471` (a real client console URL in a Block Kit button) and
`slack.rs:1968,2022` (a real tenant string). Wiring the identifier inventory into
CI (#15) is what keeps new parity fixtures from re-introducing them.

**The oracle vocabulary is the single diff vocabulary.** `tools/oracle/fields.json`
and the `Outcome`/`Relation`/`Magnitude` enums in `tools/oracle/vocabulary.py`
already cover this milestone's comparison surface, including which fields are
approved-nondeterministic. Using them means a live-traffic verdict and a future
archive-differential verdict are the same shape, and it means #16's Path B
re-scope costs nothing in rework if the owner later chooses Path A.

**What this milestone cannot do, and must say so.** SOTA §3's honest limit
applies: parity cannot be fully tested, hidden coupling surfaces only under
production traffic, and a passing gate licenses *progressive* cutover, never a
flip. The harness's output is evidence for a decision, not the decision. That is
also why #12 records each go/no-go as an immutable durable row pinning the
registry digest — so a later registry edit cannot retroactively rewrite what was
known when a scope was promoted.
