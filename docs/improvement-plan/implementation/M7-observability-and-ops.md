# M7 — Observability and operations

Implementation plan for milestone **M7** of the improvement program
([`../roadmap.md`](../roadmap.md) §M7), covering GitHub issues **#41–#44,
#54, #55** (roadmap work items 38–41, 51–52). Findings: **F-11**
(observability is a requirement with no exporter) and **F-13** (stale pins,
stale fixtures, dead state).

Every "current state" claim below is a file:line reference verified against
the tree at `agent/deep-audit-improvement-plan`, or the recorded output of a
command run on this host. Where the roadmap's own text does not match the
tree, the correction is stated in [Cross-cutting notes](#cross-cutting-notes)
rather than silently absorbed.

| Issue | Item | Shape | Effort |
| --- | --- | --- | --- |
| [#41](#41--metrics-exporter-with-otel-gen_ai-attributes) | Metrics exporter, OTel `gen_ai.*` attributes | Wire two functions that have never had a caller; build the token substrate that does not exist | L (~8 d) |
| [#42](#42--trace-correlation-and-causation-id-propagation) | `trace_id` / `correlation_id` / `causation_id` | Schema v7 + explicit provenance parameter threaded through the lanes | M–L (~5 d) |
| [#43](#43--productize-backuprestore-clean-host-drill-runbooks) | Backup/restore, clean-host drill, runbooks | Port a Python spike into product code; provision a genuinely clean host | XL (~15 d) |
| [#44](#44--service-definition-and-provider-inventory-pins) | systemd unit; refresh provider pins | Two unrelated jobs sharing an issue number | M + S (~4 d) |
| [#54](#54--socket-activation-notify-reload-and-the-fd-store) | Socket activation, `Type=notify-reload`, fd store | Tier A costs nothing; Tier B costs one `unsafe` | M ×2 (~7 d) |
| [#55](#55--doctor-checks-for-silent-no-ops-store-pragma-review) | Doctor read-back checks; store pragma review | Narrower than the roadmap thinks; 18 pragma sites and one hard assertion | M ×2 (~7 d) |

---

## #41 — Metrics exporter with OTel `gen_ai` attributes

### Current state

The observability crate is a projection library with **no exporter and no
emitter**, and the half of its API that an exporter would use has never had a
caller.

- `rust/crates/automonique-observability/src/lib.rs:22-42` declares a closed
  19-name `MetricName` vocabulary; `:68-90` gives each one its
  Prometheus-style spelling (`automonique_outbox_pending`,
  `automonique_sandbox_launch_refusals_total`, …).
- **`MetricName::as_str` (`:67-90`) has zero call sites in the entire
  workspace, including the crate's own tests.** So do
  **`MetricsSnapshot::samples()` (`:309-313`)** — the canonical-order
  iterator — and `EventCategory::as_str` (`:351-361`, tests only). These are
  precisely the three functions a text exporter needs, written in advance and
  never wired.
- `OperationalEvent` / `OperationalEventKind` / `Severity` / `EventCategory`
  (`:316-455`) have no emitter and no sink anywhere; `tests/projection.rs`
  is their only exercise. `StoreAssessment` + `StoreProjection::assessment()`
  (`:103-110`, `:197-200`) likewise.
- The only consumer in the workspace is the daemon, which imports exactly
  `MetricName, MetricValue, StoreProjection`
  (`rust/crates/automonique-daemon/src/lib.rs:25`), builds a projection at
  `:1408-1410`, and folds 13 of the 19 values into the JSON `Status` response
  at `:3670-3700`. Nothing renders a metric name.
- Five of the 19 samples are hard-coded `Unavailable(NotIntegrated)` in
  `StoreProjection::from_status` — `DaemonReady`, `IntakeEnabled`
  (`:133-134`), `TelegramOffsetLag`, `ProviderAvailable`,
  `SandboxLaunchRefusals` (`:147-149`). Two of those five are *computed by
  the daemon ten lines later*: readiness at `daemon/src/lib.rs:1418-1422`
  and intake enablement at `:1428`, both of which reach `DaemonStatus`
  instead. The projection declares "not integrated" about facts its only
  caller holds.
- Token/cost accounting has no substrate.
  `rust/crates/automonique-agents/src/normalize.rs:166-188` parses the
  provider's `turn.completed` event, asserts that
  `usage.{cached_input_tokens, input_tokens, output_tokens}` are all present
  and all `u64` — and then calls `self.record(RecordedKind::UsageUpdated,
  None)`. **The counts are validated and discarded.** No table holds them:
  `rust/crates/automonique-store/src/provider_journal.rs:108-151`
  (`provider_turns`, `provider_requests`) has no token, model, or cost
  column. `automonique_protocol::models::UsageRecord` (`models.rs:2564-2632`)
  and `AccountUsage` (`:1519-1563`) exist as types with no call site outside
  `tests/models.rs`.
- The transport that a scrape would ride already exists and is already
  authenticated: one Unix socket serving six protocols separated by declared
  protocol name (`automonique-protocol/src/admin.rs:20-45`), with peer
  authorization by `SO_PEERCRED` uid at `daemon/src/lib.rs:3787-3794`.
- `requirements/verification-and-rollout.md:276-306` lists ~45 metric
  families required "before rollout". 19 names exist; 14 carry measured
  values.

### Approach

**1. Close the five phantom gaps before exporting anything.** Give
`StoreProjection` a companion constructor that accepts the runtime facts the
daemon already holds — readiness, intake enablement, Telegram offset lag,
provider availability, sandbox launch refusals — as explicit
`Result<u64, UnavailableReason>` arguments. A caller that genuinely cannot
measure passes a *reason other than* `NotIntegrated`
(`CapabilityMissing` / `DependencyUnavailable` / `MeasurementFailed` already
exist at `:204-210`). This keeps the crate's refusal-first contract and
removes five metrics that today lie about *why* they are absent.

**2. Add the text renderer, built on the two dead functions.**
`render_exposition(&MetricsSnapshot) -> Result<Vec<u8>, ObservabilityError>`
inside the observability crate:

- `# HELP` / `# TYPE` from a closed table alongside `MetricName::ALL`, so a
  new metric cannot be added without its type.
- Counters keep their `_total` suffix (already correct in `as_str`); gauges
  do not.
- **An `Unavailable` sample emits no series.** It emits
  `# automonique_x unavailable: not_integrated` as a comment. Exporting an
  unmeasured value as `0` is exactly the "invented default" this crate
  refuses (`:212-217`, and the daemon's own argument at
  `daemon/src/lib.rs:3654-3662`: "Zero is a fact an operator acts on … a read
  that failed supports none of those conclusions"). Prometheus practice
  agrees — an absent series is honest, a wrong zero is not.
- One `automonique_build_info{generation_id="…"} 1` line. `generation_id` is
  the only label, it is already length-bounded and alphabet-validated by
  `valid_coordinate` (`:476-482`), and that validation is what makes it
  label-safe.

**3. Serve it as a seventh protocol on the existing socket — no listener.**
`automonique.metrics` with one request (`Scrape`) and one response carrying
the exposition body as bounded bytes plus a content-type. The admin module
documents the cost of a new lane precisely: "one enum arm, one match arm and
one frame-fit assertion" (`admin.rs:38-45`); follow it, including a
`MAX_METRICS_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES` static assertion
in the style of `admin.rs:1507-1555`. No HTTP server, no network bind, no new
authorization surface — `authenticate_peer` already gates every frame.

**4. `automonique metrics` CLI verb** writing the exposition to stdout. That
makes the daemon scrapeable through a node_exporter *textfile collector* or a
systemd timer without the daemon ever owning a network socket, which is the
right trade for a single-node local-first control plane. An OTLP push would
put an HTTP client on the daemon's path and need an egress-broker allowlist
entry; reject it.

**5. Build the `gen_ai` substrate, which is the real work.**

- Carry the three token counts on the normalized record in
  `automonique-agents/src/normalize.rs:166-188` instead of dropping them.
- Provider journal schema v2: a `provider_turn_usage` table keyed by
  `turn_id`, with columns named to map 1:1 onto the OTel GenAI conventions —
  `gen_ai_system`, `gen_ai_request_model`, `gen_ai_response_model`,
  `input_tokens`, `output_tokens`, `cached_input_tokens`, `finish_reason`.
  STRICT, with the same `CHECK`-constraint discipline as its siblings
  (`provider_journal.rs:69-183`).
- Three new names in the closed vocabulary:
  `automonique_gen_ai_usage_input_tokens_total`,
  `automonique_gen_ai_usage_output_tokens_total`,
  `automonique_gen_ai_requests_total`.
- **Labels come only from closed, pinned vocabularies.** `gen_ai_system` from
  `ProviderKind`; `gen_ai_request_model` from the pinned provider catalog
  (`automonique-protocol/src/provider_catalog.rs`). A model string parsed out
  of a provider response never becomes a label — that is both the cardinality
  bound and the redaction bound, and it is what keeps the crate's opening
  promise that "user content, credentials, paths, prompts, and provider
  output are not representable" (`observability/src/lib.rs:5-8`).

### Testing

- Golden exposition test: a full snapshot renders byte-exactly; a snapshot
  with an unavailable sample emits the comment and **no numeric line** for
  that name (the invented-default guard, asserted directly).
- Exhaustive over `MetricName::ALL`: every rendered name matches the
  Prometheus name grammar `[a-zA-Z_:][a-zA-Z0-9_:]*` and every name has a
  `# TYPE`.
- Worst-case frame fit: longest legal `generation_id` (128 bytes,
  `MAX_GENERATION_ID_BYTES` at `:18`), all 19 measured, every counter at
  `u64::MAX` — must fit `MAX_METRICS_CANONICAL_BYTES`.
- Cardinality bound: the label set is asserted to be a subset of
  |`ProviderKind`| × |catalog models| against the pinned catalog.
- Integration over the socket in a tempdir: the daemon answers a scrape, all
  19 names appear or are explicitly unavailable, and a foreign uid is refused
  (reuse the existing peer-auth test pattern).
- Normalizer: the three token counts survive into the record. Today's test
  only asserts the event's *shape*.

### Effort

**L, ~8 engineer-days.** Exporter + protocol lane + CLI verb ≈ 3 d. The five
phantom-gap fixes ≈ 1 d. The `gen_ai` substrate (journal migration,
normalizer plumbing, catalog-bounded labels, projection) ≈ 4 d.

### Dependencies

None hard. Two sequencing notes: M6 item 37 (provider adapter hardening)
edits the same normalizer, so land the usage plumbing with or before it; and
if #42 is scheduled in the same window, put both schema changes in **one**
provider-journal migration rather than two.

---

## #42 — Trace, correlation, and causation ID propagation

### Current state

- `rust/crates/automonique-store/src/lib.rs:182-192` — `domain_events`
  (`event_id`, `aggregate_kind`, `aggregate_id`, `revision`,
  `schema_version`, `occurred_ms`, `kind`, `payload`). No correlation column.
- `:303-342` — the v4 `outbox`. Its only link to a cause is the `event_id`
  foreign key; `runs.outbox_intent_key` (`:159-172`) is the other half. There
  is no id that survives across the inbox → run → event → outbox chain.
- Ingress tables where a trace would be minted: `telegram_ingress`
  (`lib.rs:265-284`, `source_key` UNIQUE) and
  `slack_ingress_dispositions` (`slack_ingress.rs:158`).
- `provider_journal.rs:69-183` — eight tables keyed only by internal row ids.
  `provider_sessions.provider_session_key` is the *provider's* identifier,
  not ours.
- Migration ladder: `SCHEMA_VERSION = 6` (`lib.rs:40`), replayed through
  `MIGRATE_V1_TO_V2` … `MIGRATE_V5_TO_V6` (`:205-415`), STRICT tables
  throughout.
- The requirement already names the exact triple:
  `requirements/operations-and-governance.md:145` — "Propagate `trace_id`,
  `correlation_id`, `causation_id`, input/work/attempt/run/host/session/turn
  IDs and outbox/action IDs through logs, events and external request
  metadata where safe."
- **The constraint that shapes the whole item: there is no logger, and its
  absence is deliberate.** `log` appears in five crates' manifests for one
  purpose — a compile-time ceiling assertion,
  `const _: () = assert!(log::STATIC_MAX_LEVEL <= LevelFilter::Debug)` at
  `slack-connector/src/client.rs:76`, `github-connector/src/client.rs:68`,
  `support-connector/src/client.rs:47`,
  `transport-runtime/src/https_client.rs:44`, `chat-provider/src/lib.rs:55`
  — so that `ureq` and `tungstenite` cannot emit trace-level records
  containing credentials. **No crate in the workspace calls a log macro.**
  The daemon writes nothing to stderr while serving. "Propagate through
  logs" cannot be satisfied by adding a logger without reopening that
  decision.

### Approach

**1. Three bounded newtypes in the protocol crate** — `TraceId`,
`CorrelationId`, `CausationId` — over the same restricted alphabet
`valid_coordinate` already enforces (`observability/src/lib.rs:476-482`:
ASCII alphanumeric plus `. _ : -`). That alphabet is what lets an id become a
metric label or an HTTP header value without a second redaction argument.

**2. Mint deterministically, at ingress admission, once.**
`trace_id = hex(SHA-256(transport ‖ 0x00 ‖ transport_key)[..16])`, computed
with the protocol crate's existing `digest::Sha256`. Deterministic rather
than random for three reasons: the repo has no PRNG anywhere (F-07), a
replayed update recomputes the same trace so a duplicate cannot fork the
trace tree, and offline replay (M8 item 49) needs ids to be a function of
inputs.

**3. `correlation_id` is the current unit of work** (the run or attempt);
**`causation_id` is the id of the record that directly caused this one** —
the parent's id, not a new namespace. This is the command/notification split
SOTA §6 describes, reduced to the two columns that make it expressible later.

**4. Store migration v6 → v7.** `ALTER TABLE … ADD COLUMN` for `trace_id`,
`correlation_id`, `causation_id` on `domain_events` and `outbox`; `trace_id`
on `inbox` and `telegram_ingress`. All nullable — history has no ids, and
backfilling invented ones is the failure mode this codebase refuses
everywhere else. Add `CREATE INDEX domain_events_by_trace ON
domain_events(trace_id, event_id)` as a **plain, droppable** index; SOTA §6's
warning applies (SQLite cannot drop columns under partial indexes, so every
index should be planned as droppable). Same three columns on
`provider_turns` in the provider journal.

**5. Thread the ids as an explicit parameter, never as ambient context.** A
`Provenance { trace, correlation, causation }` argument on the store write
APIs that create durable records (`submit_inbox`, outbox enqueue, run claim).
Thread-locals are how these systems rot; an explicit parameter makes an
unattributed write a compile error at the call site, which is the same
technique `protocols.rs:36-54` already uses to make an unauthenticated
binding uncompilable.

**6. Egress metadata "where safe", off by default.** A correlation header on
outbound requests publishes an internal id to a third party. Recommend: on
for GitHub and the Support backend, off for Slack and Telegram, all four
config-gated. Never a user-content-derived value — the alphabet bound in (1)
guarantees that mechanically.

**7. Surface on the detail reads that already exist**, not on the aggregate
status: `runs_api::RunDetailView`, `AdminOutboxEvidence`,
`AdminReconciliationEvidence`. An operator reconciling an ambiguous effect
(`daemon/src/lib.rs:1344-1381`) is the highest-value reader of a trace id,
and that path is already built.

### Testing

- Migration ladder test in the existing style: a v6 fixture upgrades to v7;
  pre-existing rows keep NULL ids; new writes carry them; the ladder still
  replays from v1.
- Determinism: the same `(transport, transport_key)` yields the same trace id
  across processes; a duplicate submission does not mint a second trace.
- Chain integrity: an integration test driving synthetic intake → run →
  outbox asserts the causation chain is connected and acyclic, and that the
  outbox row's `causation_id` names the domain event that produced it.
- A `compile_fail` doctest (the crate already uses this technique,
  `protocols.rs:36-54`) proving a durable-record write without `Provenance`
  does not compile.
- Alphabet property: no id can ever contain a byte outside the coordinate
  set, so an id can never smuggle user content into a label or a header.

### Effort

**M–L, ~5 engineer-days.** The newtypes and the migration are each under a
day; threading the parameter through the daemon's lanes is the bulk.

### Dependencies

Independent of #41, but shares a provider-journal schema bump with it — one
migration if co-scheduled. Feeds M8 item 49; **do not** build the
command/notification journal split here, only the ids it will key on.

---

## #43 — Productize backup/restore; clean-host drill; runbooks

### Current state

- **Product code has no backup path at all.** The daemon owns 16 isolated
  SQLite databases through the accessors at
  `daemon/src/lib.rs:339-407`; there is no `VACUUM INTO`, no
  `sqlite3_backup`, and no snapshot verb anywhere in `rust/`.
- Everything that exists is a Python spike under `spikes/recovery/`, run by
  nothing in CI. `drill.py` exits `2` by design.
- **The two backup-ordering rules exist only in prose in that spike's
  README** (`spikes/recovery/README.md:95-107`): (1) blob bytes durable
  before the row referencing them commits; (2) a config revision durable in
  the file before the database records it current. The backup then
  "snapshots the database *first* and derives everything else from that
  snapshot".
- `--fault naive-backup` (`README.md:115-119`) proves the payoff: copying in
  the wrong order tears the recovery *set* while each database still passes
  its own `integrity_check` — i.e. "the database restored fine" is not
  evidence of a consistent backup. That is the single most valuable test in
  the spike and it has no Rust equivalent.
- `README.md:41-43`: `drill.compare_to_objective` returns `MET`/`MISSED`
  only for `Scope.CLEAN_HOST`, "which nothing in this repository can
  currently produce. A test holds that door shut." Five of nine restore
  dependencies are `not_drilled`, and `README.md:49-58` names them —
  including **"a service definition that starts the restored installation in
  disconnected recovery mode"**.
- Authority: `plan/inventory/surface/restore-dependencies.json` is the R0-09
  canonical publication (21 ordered positions, two objectives, one excluded
  credential class). `spikes/recovery/restore-dependencies.json` is a
  *generated description of the old local drill's own needs* and is
  explicitly **not** accepted as authority (`README.md:150-158`).
- Objectives and contract:
  `requirements/operations-and-governance.md:23` (short snapshot lease,
  SQLite's supported online backup, integrity check, hash every component,
  do not stop execution hosts), `:25` (RPO ≤ 5 min, RTO ≤ 30 min), `:29`
  (credential descriptors alone are not a recoverable backup), `:123-125`
  and `:165` (the runbook inventory), `:174` (`disconnected-recovery` mode),
  `:186` (preview → immutable plan → revalidation → apply → verify).
- `spikes/recovery/anonymous_*` (~133 KB across four modules and four test
  files) is absent from that README. `anonymous_backup.py:25-40` holds the
  strongest mechanism in the set: an online snapshot with a *concurrent
  committer firing from inside the copy's own progress callback*, which is
  what makes the drill's watermark deterministic.

### Approach

Split into **43a** (backup/restore in product code) and **43b** (clean-host
drill + runbooks). 43b depends on #44a.

**43a — port the ordering rules into product code.**

- New `automonique-backup` crate rather than a store module: it must open all
  16 databases, and the store crate's design is one type per database.
- Contract, matching `operations-and-governance.md:23`: acquire a short
  snapshot lease under the generation fence; `VACUUM INTO` each database to a
  staging path (SOTA §6 names `VACUUM INTO` for exactly this); record
  `PRAGMA integrity_check` and the SHA-256 of every component; **then** derive
  the blob and config set *from the snapshot*, never from the live tree.
- Emit one `automonique.recovery-set/v1` manifest carrying the watermark,
  per-component digests, and both ordering rules as asserted invariants —
  so a set that violates them is refused at creation, not discovered at
  restore.
- The snapshot runs **inside the daemon** under its own fence, driven by a
  CLI verb over the admin socket. A second process opening the 16 databases
  would break the single-writer discipline the audit lists as a core
  strength.
- Verbs: `automonique backup create <dir>`, `backup verify <dir>`,
  `restore --from <dir> --into <dir>` (refusing a non-empty target — port the
  drill's `workspace_not_empty` refusal), `restore drill --scope
  clean-host|local-fixture`.
- Adopt the `anonymous_backup.py` concurrent-committer mechanism as the Rust
  crate's own online-backup test.

**43b — a genuinely clean host, and the runbooks.**

- **Recommendation for `Scope.CLEAN_HOST`:** a GitHub Actions job on a fresh
  `ubuntu-latest` runner. A per-run runner *is* a clean host by construction
  — no prior installation, provisioned fresh — which is precisely what the
  spike says it cannot produce locally. The job installs the release from its
  manifest, restores a fixture recovery set, starts the daemon in
  disconnected recovery mode, and measures RTO. That makes
  `compare_to_objective` return `MET`/`MISSED` honestly for the first time.
- Keep the test that holds the door shut; **narrow** it rather than delete
  it, so a local-fixture measurement still cannot claim a host objective.
  Credential resolution stays explicitly out of scope and stays
  `not_drilled` — `operations-and-governance.md:29` is clear that descriptors
  alone are not a recoverable backup, and a CI runner has no escrowed key.
- **`disconnected-recovery` mode** (`operations-and-governance.md:174`)
  becomes an explicit start flag. Mechanically it is the existing intake
  pause (`intake_pauses`, `MIGRATE_V5_TO_V6`) plus the already-no-op paths
  (`TicketIntakeHost::Disabled`, an empty Telegram allowlist) promoted from
  an accident of configuration to a declared state — no transport lease, no
  provider start, no outbox delivery.
- **Runbooks** under `docs/runbooks/`, one file per named failure from
  `operations-and-governance.md:165`, each opening with a preview-only step
  per the `:186` rule. Ship these four first, because they are the ones an
  operator will need before the others exist: stuck lease, poisoned outbox,
  corrupt database/spool, failed handoff.
- **`anonymous_*` disposition — [owner].** Adopt-vs-archive for the
  *sealed-execution boundary* work (`anonymous_boundary.py`,
  `anonymous_worker.py`, `anonymous_composition.py`) is a separate question
  from backup. Either way, add it to the spike README: 133 KB of undocumented
  design is a liability under both outcomes.

### Testing

- `--fault naive-backup` ported to Rust: a set built in the wrong order fails
  the blob-before-row invariant **while every database passes
  `integrity_check`**. This is the test that proves the distinction.
- `--fault leak-source` ported: a file present in the target that the
  manifest does not carry fails `target_matches_manifest`.
- Residue: every run cleans up unconditionally and re-reads the filesystem to
  confirm it.
- Reproducibility: two runs produce identical manifests modulo wall-clock,
  workspace name, and run token — the spike's existing `reproducible` block
  rule.
- The clean-host CI job fails if measured RTO exceeds 30 min; RPO is measured
  from the watermark.
- Keep the Python suite green and running in CI until the port completes
  (M5 item 29 covers `tools/`; add `spikes/recovery/` alongside it).

### Effort

**XL, ~15 engineer-days** — the largest item in M7. 43a: backup crate +
verbs ≈ 6 d, fault-injection port ≈ 2 d. 43b: clean-host CI drill ≈ 4 d,
runbooks ≈ 3 d. Ship as two issues.

### Dependencies

**#44a is a hard prerequisite of 43b** — the spike's own dependency list
names a service definition that starts the restored installation as one of
the five undrilled positions, and the roadmap does not record this edge.
M1 item 1 (identifier scrub) must land before any recovery set is published
as a CI artifact.

---

## #44 — Service definition and provider inventory pins

Two unrelated jobs share this issue. Treat them as separate work.

### 44a — systemd user unit

#### Current state

- The product **calls** systemd and **ships no unit**.
  `daemon/src/release_activation.rs:25` pins `/usr/bin/systemctl`; `:99-127`
  runs `systemctl --user restart <unit>` and
  `systemctl --user is-active --quiet <unit>`;
  `daemon/src/improvement_worker.rs:243` runs `/usr/bin/systemd-run`;
  `improvement_worker.rs:40,49,125` carry a `systemd_unit` field.
  **No `.service` or `.socket` file exists anywhere in the tree.**
- `docs/self-improvement-workflow.md:58` names the unit `automonique.service`
  and `:32-36` requires its `ExecStart` to invoke
  `<state-directory>/improvement-code/current/bin/automonique daemon
  --foreground`.
- **The readiness proof is wrong today.** For a `Type=simple` unit,
  `is-active` becomes true as soon as the fork succeeds — before
  `Daemon::open` validates paths (`daemon/src/lib.rs:752-771`), binds the
  socket, or acquires the generation lease (`:786-794`). So
  `release_activation.rs:194` can accept a release whose daemon then refuses
  to start. `Type=notify` closes this exactly.
- **The most likely first-boot failure is an environment variable.**
  `DaemonConfig::from_environment` (`daemon/src/lib.rs:312-323`) requires
  **both** `XDG_RUNTIME_DIR` and `XDG_STATE_HOME` and deliberately refuses to
  fall back to a home path. A systemd user manager sets the first and not the
  second.
- `validate_root` (`:3826-3839`) requires mode `0700` on both roots, so the
  directory-mode directives are load-bearing rather than cosmetic.
- Host: systemd 255, `default-hierarchy=unified`.

#### Approach

Ship `packaging/systemd/automonique.service` (user unit):

- `Type=notify` (or `notify-reload` once #54 Tier A lands), `NotifyAccess=main`.
- `Delegate=yes` — the cgroup delegation `ContainmentDomain::discover`
  requires (`cli/src/kernel.rs:139-141`).
- `RuntimeDirectory=automonique`, `RuntimeDirectoryMode=0700`,
  `StateDirectory=automonique`, `StateDirectoryMode=0700`,
  and `Environment=XDG_STATE_HOME=%S` — without that last line the daemon
  refuses to start.
- `Restart=on-failure` with `RestartSec=` and a burst limit; `WatchdogSec=`;
  `TimeoutStopSec=` comfortably longer than the execution lane's worker join
  (`daemon/src/lib.rs:1133-1143`).
- `ExecStart=` the release-link path `self-improvement-workflow.md:32-36`
  requires; `%S`/`%t` specifiers so the unit needs no path substitution at
  install time.
- **Deliberately omit every cgroup-BPF-shaped directive** (`IPAddressDeny`,
  `RestrictNetworkInterfaces`, …). SOTA §6 records that on a *user* manager
  these are accepted and silently do nothing. Declaring them would be a
  containment claim the host does not honor, which is exactly #55's subject.
  The unit carries only directives whose effect the doctor can read back.

#### Testing

- `systemd-analyze verify --user` on the shipped unit in CI.
- A host test starting the daemon under `systemd-run --user` with the shipped
  directives (the repo already uses delegated-scope `systemd-run` for
  enforcement proofs), asserting: readiness is not reported before an admin
  `Status` succeeds; the delegated cgroup's `cgroup.controllers` contains
  `cpu io memory pids`; `XDG_STATE_HOME` is present in the daemon's
  environment.

#### Effort

**M, ~3 d** — the unit itself is small; the notify plumbing is #54's.

#### Dependencies

`Type=notify` needs #54 Tier A. If #54 slips, ship the unit `Type=simple` and
record the weak readiness proof as an explicit temporary deviation rather
than shipping silently.

### 44b — refresh the provider inventory pins

#### Current state

Verified by running it on this host:

```
$ python3 tools/provider_inventory.py verify --capture-date 2026-08-09
error: artifact differs: claude/version.txt
error: artifact differs: jcode/acp-help.txt
error: artifact differs: jcode/api-bridge-help.txt
error: artifact differs: jcode/root-help.txt
error: artifact differs: jcode/run-help.txt
error: artifact differs: jcode/server-help.txt
error: artifact differs: jcode/version.txt
error: artifact differs: manifest.json          → exit 1
```

Pinned in `spikes/provider-surfaces/inventory.json` vs installed today:
claude `2.1.226` → **2.1.233**; jcode `0.68.0` → **v0.76.0**; codex
`0.147.0` → matches; opencode `1.17.18` → matches.

The inventory is a **trust root**: its digest is pinned in Rust at
`rust/crates/automonique-lab/src/provider.rs:24-25`
(`R0_06_INVENTORY_SHA256 = "3eebad2e…"`) and compared against the admitted
bytes at `:104`. So a re-capture is a three-part atomic change — re-run
`capture`, update the constant, update `inventory.json`'s `capture_date` and
per-provider `surface_sha256`.

`provider_inventory.py` is **not in any workflow** (`.github/workflows/`
contains only `rust.yml`, `plan.yml`, `scrub.yml`).

#### Approach

- Re-capture with a fresh `--capture-date`, update the pin and the inventory
  in **one commit that changes no code**. The digest is a trust root; an
  unreviewed re-capture is an unreviewed change to a trust root.
- **CI wiring needs a two-part answer**, because `verify` re-runs the live
  probes (`verify_capture` → `capture_document` → `run_probe`,
  `tools/provider_inventory.py:154-172, 326-355`) and therefore needs all
  four CLIs on `PATH`. A stock GitHub runner has none of them and would
  report `127 unavailable: executable not found` for every probe:
  1. **In `rust.yml` / `plan.yml` (static, always runs):** assert
     `R0_06_INVENTORY_SHA256` equals the SHA-256 of the checked-in
     `inventory.json`. Nothing asserts this today — the constant is only
     checked when the lab admits an inventory at runtime, so the pin and the
     file can drift apart silently.
  2. **On a host that has the CLIs (scheduled or self-hosted):** the live
     `verify`, so provider drift turns up the day it happens rather than six
     months later.
- **[owner]:** whether the four provider CLIs are version-pinned in the
  development environment. Today they drift freely and this inventory is the
  only thing that notices.

#### Testing

Static digest test (Rust) plus the live `verify` job. Both are assertions
about files already in the tree; neither needs new fixtures.

#### Effort

**S, ~1 d** — half a day for the re-capture, half for the CI wiring and the
digest test.

#### Dependencies

None. Do not let this wait behind 44a; it is a half-day chore with a trust
root attached.

---

## #54 — Socket activation, `Type=notify-reload`, and the fd store

### Current state

- `Daemon::open` performs the full bind/unlink dance:
  `prepare_socket_path` (`daemon/src/lib.rs:3796-3824`) connects to a stale
  socket to decide whether it is dead, re-verifies `(dev, ino)` after the
  probe, then unlinks; `UnixListener::bind` at `:763`;
  `set_permissions(0o600)` at `:764`; a re-stat verifying type, uid and mode
  at `:765-771`. `SocketCleanup` (`:725-743`) unlinks on drop and
  `Drop for Daemon` (`:3702-3706`) does it again, both guarded by
  `remove_socket_if_identity` (`:3708-3716`) which re-checks `(dev, ino)`.
  This is careful code, and it is exactly what socket activation retires.
- **There is no self-exec anywhere.** `automonique/src/main.rs:39-55` runs
  the daemon in the calling process, and `requirements/target-architecture.md:29-31`
  states it "never self-daemonizes". The roadmap's "retires self-exec" is
  imported from the external survey's generic description of the pattern and
  does not describe this tree.
- The accept loop is a 25 ms non-blocking poll (`ACCEPT_POLL`, `:286`;
  `:1117-1119`) — the natural place for a watchdog ping.
- Signals: `run_foreground` (`:3724-3763`) blocks SIGINT/SIGTERM and drains a
  `signalfd` on a helper thread into an `AtomicBool`. There is no SIGHUP or
  reload path.
- Already correct per SOTA §6: authorization is `SO_PEERCRED` uid
  (`:3787-3794`), pid is not used for authorization, and the socket is a
  filesystem path under a `0700` runtime directory — never abstract.
- **Blocker for the fd store:** `rust/Cargo.toml:46-47` sets
  `unsafe_code = "forbid"` workspace-wide and
  `automonique-daemon/Cargo.toml` inherits it via `[lints] workspace = true`.
  Adopting an inherited descriptor requires `OwnedFd::from_raw_fd`, which is
  `unsafe`; there is no safe path in std or nix from an integer fd to an
  owned socket. "Zero `unsafe`" is one of the properties the audit lists as
  genuinely strong.
- Requirements already authorize both halves as *optional adapters*:
  `reload-protocol.md:34` ("when supplied by an optional adapter, accepted
  admin descriptors") and `:129-130` ("An optional supervisor adapter may
  translate that event into its native readiness notification").

### Approach

Two tiers, because they have very different costs.

**Tier A — `Type=notify` / `notify-reload` + watchdog. No `unsafe`, no new
dependency.**

`sd_notify` is a `sendto` on an `AF_UNIX SOCK_DGRAM` socket the daemon
creates itself, addressed by `$NOTIFY_SOCKET` (a leading `@` meaning the
abstract namespace, which nix's `UnixAddr::new_abstract` handles). nix 0.29
is already a workspace dependency with the `socket` feature enabled. ~60
lines, zero new crates, zero `unsafe`.

- `READY=1` sent from `serve` **after** the generation lease is acquired, the
  tenure row is recorded, every sibling database is open, and the workers
  have started (`daemon/src/lib.rs:1058-1071`). This is the direct fix for
  `release_activation.rs:116-126`'s `is-active` readiness proof.
- `STATUS=` a bounded line derived from the same closed vocabulary the
  observability crate uses — never free-form — so `systemctl --user status`
  shows generation, epoch, and degraded state.
- `WATCHDOG=1` from the accept loop, which already ticks every ≤25 ms; ping
  at `WatchdogSec/3`. **Gate the ping on the loop making progress**, not on
  it merely spinning: a watchdog fed by a loop that has stopped doing
  anything useful proves nothing. A wedged lease renewal or a hung store read
  should stop the pings.
- `RELOADING=1` + `MONOTONIC_USEC=` on SIGHUP for `Type=notify-reload`
  (systemd ≥ 253; this host runs 255).

**What "reload" means is M8's decision, not M7's.** M7 wires the
notification protocol and defines reload as a no-op that re-reads nothing and
immediately re-sends `READY=1`. M8 item 43 fills in the generation handoff
behind the same signal. Wiring the transport now means M8 does not also have
to negotiate systemd.

**Tier B — socket activation + `FDSTORE`. Requires an owner decision on
`unsafe`.**

- Read `LISTEN_FDS`/`LISTEN_PID`; verify `LISTEN_PID == getpid()`,
  `LISTEN_FDS == 1`, and `fstat(3)` reports a socket of the expected family;
  clear the variables; then adopt. The adoption is one
  `unsafe { OwnedFd::from_raw_fd(3) }`.
- `FDSTORE=1` with `FDNAME=admin`, `FileDescriptorStoreMax=1`,
  `FileDescriptorStorePreserve=restart` to hand the listener back across a
  restart.
- Payoff: the socket exists before the daemon does, so a client connecting
  mid-restart **blocks in the kernel backlog** instead of getting `ENOENT`
  or `ECONNREFUSED`. It also retires `prepare_socket_path`, `SocketCleanup`,
  and both unlink paths, because systemd owns the socket's lifetime.
- **Recommendation: take it, but contain it.** A new ~80-line
  `automonique-activation` crate owning the entire systemd interface (notify
  and activation), which does *not* opt into the workspace lint table, sets
  `#![deny(unsafe_code)]`, and carries exactly one `#[allow(unsafe_code)]`
  function with a safety comment naming the `LISTEN_PID`/`LISTEN_FDS`
  contract and the `fstat` check that establishes the descriptor is a
  listening socket. Its only dependency is `nix`. The audit's claim then
  becomes "one reviewed, contained, ~15-line `unsafe` function", which is a
  statement the repository can defend.
- **[owner] either way.** This is a deliberate weakening of a forbid-level
  invariant and should not arrive inside a PR. If refused, ship Tier A only:
  the daemon keeps binding its own socket, restarts keep a small connect
  gap, the bind/unlink dance stays. That is a legitimate outcome; it costs
  only the zero-drop property.

**Boundary with M8.** M8 item 43 owns *what* a reload does — N+1 readiness
proof, transactional lease transfer under fencing epochs, drain, automatic
return on failure, and the `reload`/`rollback`/`generations`/`reload-status`
verbs. M7 #54 owns only *how the supervisor is told*: the notify protocol,
the watchdog, and (Tier B) who owns the listening descriptor. Neither tier
implements handoff.

### Testing

- Tier A: a fake `$NOTIFY_SOCKET` datagram receiver asserting the exact byte
  sequences **and their ordering** — `READY=1` must not appear before an
  admin `Status` over the socket succeeds. A watchdog test that stalls the
  loop and asserts the pings stop.
- `systemd-run --user --property=Type=notify` on this host (systemd 255):
  the unit reaches `active` only after readiness, and
  `systemctl --user reload` round-trips.
- Tier B: a harness that pre-binds a listener, sets `LISTEN_FDS=1` and
  `LISTEN_PID`, execs the daemon, and asserts it serves on the inherited
  socket and never unlinks it. Negative tests: a `LISTEN_PID` mismatch must
  refuse rather than adopt a descriptor meant for another process; a
  non-socket fd 3 must refuse.
- **Reproduce the zero-drop claim locally**: a connecting-client loop across
  `systemctl --user restart`, counting failures and recording worst-case
  connect latency. Do not quote the survey's ~74 ms; measure this daemon.

### Effort

**M ×2, ~7 engineer-days.** Tier A ≈ 3 d including the unit integration.
Tier B ≈ 4 d plus the owner decision.

### Dependencies

44a is the same work item in practice — sequence 44a and Tier A together.
Tier B before 43b would be convenient but is not required.

---

## #55 — Doctor checks for silent no-ops; store pragma review

Two items again.

### 55a — doctor checks that read back what was applied

#### Current state — better than the roadmap implies

The doctor **already** implements the SOTA §6 discipline the issue asks for:

- `cli/src/kernel.rs:48-89` reads back `/sys/fs/cgroup/cgroup.controllers`.
- `:139-141` asks the *delegation* question separately, through the runner's
  own `ContainmentDomain::discover` — the same call the runner makes before
  creating a run cgroup, "so the doctor cannot report a domain the runner
  would then refuse". The module doc at `:9-15` argues the exact
  visible-is-not-usable distinction.
- `:182-197` probes Landlock **by syscall** and explicitly refuses to consult
  securityfs, with `:16-20` recording that on the development host the
  securityfs entry is absent while the kernel reports ABI 4.

The report is 11 checks (`cli/src/lib.rs:993-1008`) against
`MAX_DOCTOR_CHECKS = 256` (`protocol/src/lib.rs:58`) — ample headroom.

The **real** gaps are three stale placeholders and three missing checks:

- `cli/src/supervisor.rs:17-27` — `supervisor.adapter` is a hard-coded
  `Unavailable` that by design "does not read process, D-Bus, environment, or
  filesystem state". Nothing checks the unit at all.
- `cli/src/diagnostics.rs:84-98` and `:101-115` —
  `control-plane.database-health` and `runtime.foreground-generation` are
  hard-coded `Unavailable` with the reason "RPC is not available in this
  release". **That RPC exists now**: `AdminCommand::Status` returns
  `OperationalStatus` and `DurableStateCounts`
  (`daemon/src/lib.rs:1410-1434`). These two lines actively misinform.
- Nothing checks `cgroup.subtree_control`, seccomp, the egress broker, or
  whether a declared systemd directive took effect.

#### Approach

1. **Retire the three placeholders.** Wire
   `control-plane.database-health` and `runtime.foreground-generation` to
   `AdminCommand::Status`. Cheapest doctor improvement in the register, and
   it removes two checks that lie.
2. **Make `supervisor.adapter` real.** Read the unit with
   `systemctl --user show --property=…` (read-only, no D-Bus writes): is a
   unit installed, does `ExecStart` resolve to the release link
   `self-improvement-workflow.md:32-36` requires, is `Type` `notify` or
   `notify-reload`, is `Delegate=yes` present. Then — the whole point —
   **cross-check every answer against the host**: `Delegate=yes` is believed
   only if `ContainmentDomain::discover` also succeeds; a declared
   `WatchdogSec` is believed only if `WATCHDOG_USEC` is in the daemon's
   environment. A declaration that the host does not honor must read
   `Finding`, never `Healthy`.
3. **New `sandbox.enforcement-readback`.** `kernel.landlock-support` proves
   the *kernel* accepts Landlock rights; nothing proves a *launched workload*
   is confined. Launch the existing descriptor-probe helper
   (`automonique-runner/src/bin/automonique-descriptor-probe.rs`) under the
   real composition and have the **child** report, from inside itself, that
   the ruleset and the seccomp filter are installed. SOTA §6's TSYNC trap is
   exactly this: best-effort compat can silently leave sibling threads
   unrestricted, so the assertion must come from inside the child, not from
   the parent's return code.
4. **New `cgroup.controllers-enabled`.** Today the doctor reads the *root*
   controller list. Also read `cgroup.subtree_control` on the delegated
   cgroup: a controller present in `cgroup.controllers` but absent from the
   parent's `subtree_control` is not available to children — the silent
   no-op that makes later `cpu.max`/`memory.max` writes fail (directly
   relevant to M8 item 44's rlimit work).
5. **`host.journald-fields`, honestly.** Emitting one bounded structured
   record and reading it back with `journalctl --user -o json -n 1` is the
   right check — but see #42: the daemon emits **no logs at all** and five
   crates depend on `log` precisely to *cap* what third-party crates may
   emit. Until a bounded structured sink exists, this check must report
   `Unavailable` with the honest reason "no structured sink is installed",
   not `Finding`. Shipping it as a finding would report the absence of a
   deliberate design decision as a defect.

### 55b — store pragma review

#### Current state

`synchronous = FULL` is set at **18 sites** — 16 in `automonique-store` and
2 in `automonique-lab`:

`store/src/lib.rs:1294`, `agent_memory.rs:526`, `approval_ledger.rs:649`,
`automation_store.rs:680`, `batch_registry.rs:1068`, `cancel_ledger.rs:357`,
`context_memory.rs:831`, `generation_audit.rs:637`, `improvements.rs:457`,
`operator_members.rs:287`, `provider_journal.rs:893`, `run_index.rs:633`,
`run_submissions.rs:442`, `slack_ingress.rs:531`,
`slack_interactions.rs:185`, `support_tickets.rs:798`;
`lab/src/state.rs:589`, `lab/src/build.rs:271`.

Six module docs state the rule in prose ("under the same privacy, WAL and
`synchronous = FULL` rules as `crate::Store`", e.g. `cancel_ledger.rs:61`,
`run_index.rs:122`, `approval_ledger.rs:191`).

And **one site asserts it**: `lab/src/state.rs:1341-1350`, where
`verify_connection` returns `StateError::Corrupt("required SQLite pragmas are
inactive")` unless `synchronous == 2`. It runs on every open (`:597`). This
is the single line most likely to be missed by a naive flip — the lab
database would refuse to open the moment the constant moves.

#### Approach

**Do not flip the default globally.** SOTA §6's claim is precise: NORMAL
"loses nothing under the *process-crash* failure model". It trades durability
against **power loss and OS crash**, not against a daemon crash. Two
databases here cannot make that trade:

- the **approval ledger** is write-once and is the audit of who authorized
  what;
- the **generation audit** is what a successor reads to decide tenure
  adjacency, and `daemon/src/lib.rs:796-815` argues at length that a tenure
  the process really held and never wrote down "*corrupts* the next daemon's
  reading of it. The log would be wrong rather than short."

For the main `Store` (leases, outbox, intake pauses), a lost tail turns a
`delivered` outbox row back into `in_flight` — which the reconciliation path
already handles, but that path is the product's most load-bearing invariant
and is not worth spending for throughput.

So:

1. A typed `Durability { Full, Normal }` parameter at open time, with
   **per-database defaults**, not one global switch. Recommend `Full` for
   `automonique.sqlite3`, `approvals`, `generation-audit`, and
   `run-cancel-ledger`; `Normal` for the high-write derived and read-model
   databases where a lost tail is recoverable by replay — `run-index` (a
   projection of `run-submissions`), `slack-ingress`, `slack-interactions`,
   `provider-journal`, `context-memory`, `agent-memory`.
2. Each choice gets a one-line justification in the module doc that already
   states the rule in prose. Six docs change; do not leave them asserting
   FULL while the code sets NORMAL.
3. Operator opt-in **tightens only**: one config key can raise every database
   to `Full`; loosening below a module's declared floor is refused. This is
   the same tighten-only composition rule M3 item 19 establishes for policy.
4. Change `lab/src/state.rs:1348` to assert the *declared* durability rather
   than the constant `2`.
5. **Measure first.** SOTA cites ~3× for WAL+NORMAL vs WAL+FULL, but on this
   workload — small transactions, `BEGIN IMMEDIATE` everywhere, 16 separate
   databases — the win may be much smaller, and SOTA's own caveat applies
   ("batching beats the durability dial where bulk-appending"). A change to a
   durability invariant that buys nothing measurable should not be made.

### Testing

- 55a: golden doctor reports per check under fixture hosts, extending the
  tempdir pattern `cli/src/kernel.rs:443-489` already uses. A test that a
  `Delegate=yes` declaration paired with a failing `discover()` produces a
  `Finding` and not `Healthy` — that inversion is the entire point of the
  item. The in-child enforcement assertion as an integration test, gated on
  the delegated-scope environment the repo already uses for enforcement
  proofs.
- 55b: a per-database test reading `PRAGMA synchronous` back and asserting it
  equals the declared durability (a read-back check, in keeping with the
  theme). A refusal test proving a config that tries to loosen a `Full`
  database is denied. A benchmark harness — **not** a CI gate — recording the
  measured delta so the decision is evidence-based.
- **Explicitly not proposed:** a crash-injection test. A process kill cannot
  distinguish FULL from NORMAL (both survive it by SQLite's own
  documentation); only a power-loss simulator could. Say so in the test
  module rather than shipping a test that proves nothing.

### Effort

**M ×2, ~7 engineer-days.** 55a ≈ 4 d (the three placeholder rewires are
~1 d; the in-child enforcement readback is the rest). 55b ≈ 3 d including
measurement, plus owner sign-off on any database moved off FULL.

### Dependencies

55a's supervisor check needs 44a (a unit to inspect) and #54 Tier A (a
`Type=notify` declaration to cross-check). 55b is independent of everything.

---

## Cross-cutting notes

### 1. The observability crate is a designed interface awaiting its exporter

`MetricName::as_str` and `MetricsSnapshot::samples()` have **zero call sites
in the entire workspace, including the crate's own tests** — and they are
precisely the two functions a text exporter needs. `OperationalEvent`,
`OperationalEventKind`, `Severity`, `EventCategory` and `StoreAssessment` are
exercised only by `tests/projection.rs`. F-11 describes this as "about half
the crate's public API has no call site outside its own tests", which is
accurate, but the right reading is not *dead code to delete*: it is an
interface written in advance for work that never happened. **Delete nothing
here before #41 lands.**

### 2. There is no logger, and its absence is deliberate

Five crates depend on `log` for one purpose — a compile-time ceiling
assertion on `STATIC_MAX_LEVEL` (`slack-connector/src/client.rs:76`,
`github-connector/src/client.rs:68`, `support-connector/src/client.rs:47`,
`transport-runtime/src/https_client.rs:44`, `chat-provider/src/lib.rs:55`)
so `ureq` and `tungstenite` cannot emit trace-level records containing
credentials. No crate calls a log macro. The daemon writes nothing to stderr
while serving.

Every plan item that says "structured logs" — including
`verification-and-rollout.md:307` ("Structured logs include `generation_id`,
`reload_id`, `input_id`, `work_id`, `run_id`, and `outbox_id`") and
`operations-and-governance.md:145` — must be satisfied through the durable
event tables and the observability crate's closed vocabulary, **or must first
reopen the logging decision with the owner**. #42's propagation and #55a's
journald check both hinge on this, and neither should quietly introduce a
logger.

### 3. Labels are the cardinality risk and the redaction risk at once

The observability crate opens by promising that "user content, credentials,
paths, prompts, and provider output are not representable"
(`observability/src/lib.rs:5-8`). OTel `gen_ai.*` attributes are labels, and
a model name arriving from a provider response is exactly the shape that
promise excludes. The rule to hold across #41 and #42: **a label value may
come only from a closed, pinned vocabulary** (`ProviderKind`, the pinned
provider catalog) **or from a coordinate already validated by
`valid_coordinate`** (`:476-482`) — never from a parsed provider response.

### 4. `unsafe` is the one forbid-level invariant M7 can break

#54 Tier B is the only item in this milestone that needs it, it needs exactly
one function, and `rust/Cargo.toml:46-47` says `unsafe_code = "forbid"`.
Decide it explicitly and in advance.

### 5. Roadmap assumptions this plan corrects

- **Item 51, "retires self-exec"** — there is no self-exec in this tree.
  `main.rs:39-55` runs the daemon in-process and
  `target-architecture.md:29-31` states it never self-daemonizes. Only the
  bind/unlink dance is retired.
- **Item 51, "~74 ms worst-case connect"** — a figure the external survey
  measured elsewhere. It is not a measurement of this daemon and must be
  reproduced locally rather than quoted.
- **Item 52, "read back `cgroup.controllers` and sandbox enforcement instead
  of trusting accepted directives"** — the doctor **already** reads back
  `cgroup.controllers`, asks delegation separately through the runner's own
  discovery, and probes Landlock by syscall while refusing securityfs
  (`cli/src/kernel.rs`). Scope item 52 to what is actually missing: the three
  hard-coded `Unavailable` placeholders (`diagnostics.rs:84-115`,
  `supervisor.rs:17-27`), `cgroup.subtree_control`, and an in-child
  enforcement assertion.
- **Item 52, `synchronous=NORMAL` as the WAL default** — stated as a flat
  default change; it is 18 call sites, six prose statements, and one hard
  assertion (`lab/src/state.rs:1348`) that will refuse to open the lab
  database the moment the constant moves. Per-database defaults, not a global
  flip, and the approval ledger and generation audit stay `FULL`.
- **Item 41 pairs the systemd unit with the provider-inventory refresh** —
  they share nothing. The second is a half-day chore with a trust-root digest
  attached and must not wait behind the first.
- **Item 38, "Prometheus text endpoint or OTLP push — local, authenticated"**
  — SOTA §6 and this daemon's design point the same way: **no listener at
  all**. Ride the existing peer-authenticated admin socket as a seventh
  protocol name, with a CLI verb for textfile-collector scraping. OTLP push
  would put an HTTP client on the daemon's path and need an egress-broker
  allowlist entry.
- **Item 40's clean-host drill has an unrecorded prerequisite** —
  `spikes/recovery/README.md:49-58` lists "a service definition that starts
  the restored installation in disconnected recovery mode" among the five
  undrilled dependencies. Item 41 (the unit) is therefore a hard prerequisite
  of item 40's clean-host half.
- **`provider_inventory.py verify` cannot run on a stock CI runner** — it
  re-runs the live probes (`tools/provider_inventory.py:154-172, 326-355`),
  so it needs all four provider CLIs on `PATH`. The CI gate must be split
  into a static digest check and a live check on a host that has them.

### 6. Revised ordering within M7

1. **44b** — provider inventory re-pin. Standalone, half a day, unblocks
   nothing but stops a trust root rotting.
2. **#54 Tier A + 44a** — sd_notify and the unit. One work item in practice;
   fixes the `is-active` readiness gap that `release_activation.rs` depends
   on today.
3. **#55a's three placeholder rewires** — cheap, and the supervisor check
   needs the unit from step 2.
4. **#41** — exporter, then the `gen_ai` substrate.
5. **#42** — id propagation (shares a journal migration with #41 if
   co-scheduled).
6. **#55b** — pragma review, gated on measurement.
7. **#43a** — backup/restore in product code.
8. **#43b** — clean-host drill and runbooks (needs step 2).

**#54 Tier B** slots in wherever its owner decision lands.

### 7. Decisions this milestone cannot make for itself

- **[owner]** One contained `unsafe` function for descriptor adoption
  (#54 Tier B), against a workspace-wide `forbid`.
- **[owner]** Moving any database off `synchronous=FULL` (#55b). The approval
  ledger and generation audit are recommended to stay `FULL` regardless.
- **[owner]** Version-pinning the four provider CLIs in the development
  environment (#44b). They drift freely today and the inventory is the only
  thing that notices.
- **[owner]** Adopt-vs-archive for `spikes/recovery/anonymous_*` (#43),
  separately from the backup port. Either way it gets a README entry.
- **Measurement gate:** do not land 55b without a measured delta on this
  workload.

### 8. What M7 must not build

- The generation handoff itself — M8 item 43. #54 wires the notification
  channel and defines reload as a no-op; M8 fills in the semantics behind it.
- The command/notification journal split and `replay(turn_id)` — M8 item 49.
  #42 supplies only the ids that work will key on.
- The resumable event stream and bounded per-client fan-out — M6 item 53.
  Note that item also wants a monotonic capability integer on the admin
  protocol; #41's seventh protocol name should be **designed to fit** that
  scheme rather than pre-empt it.
- The normalized progress-event stream — M6 item 33, which shares the
  `automonique-agents` normalizer with #41's usage plumbing. Coordinate the
  two edits; do not duplicate them.
