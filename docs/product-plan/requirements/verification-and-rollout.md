# Verification and rollout

## Test layers

### 1. Unit and property tests

- Protocol framing, size bounds, enum rejection, and peer authorization.
- State-machine transitions for inbox, approval, work graph, attempt, execution host, workspace, artifact, outbox, action receipt, lease and generation.
- Lease epoch fencing under paused/resumed generations.
- Agent event parsers with unknown and malformed provider events.
- UTF-8 and arbitrary chunk boundaries.
- Retry/backoff calculations and terminal idempotency.
- Migration compatibility ranges.
- Tenant/role policy decisions, controller leases, budget reservations and stable pagination under concurrent writes.
- Domain projection plus event atomicity, deterministic replay and proof that replay cannot execute effects.

Use property tests to generate event orderings, generation crashes, lease expiry, duplicates, and retries. An invariant checker must reject two active owners or two terminal effects for one idempotency key.

### 2. Golden parity tests

Reuse current tests and add language-neutral fixtures for:

- exact commands and aliases;
- ticket vs query/chat/clarify routing;
- contextual follow-ups such as the t25/t26 failures;
- approval rendering and recovery;
- Slack/Telegram formatting;
- operational queries;
- Support composition/review/send;
- site/access behavior;
- agent backend results and telemetry;
- dashboard JSON contracts.
- every machine-readable parity-ledger entry, including client-portal tenant fencing, client publication, companions, learned targets, reconciliation/audit, notifications, operational commands and ignored-message behavior.

Golden fixtures should compare semantic records rather than unstable timestamps or wording where wording is intentionally model-generated.

### 3. Runner integration tests

Every backend must cover:

- normal completion and nonzero exit;
- 64-KiB or larger prompt without argv transport;
- stderr isolation;
- incomplete final line;
- multibyte UTF-8 split at every byte boundary;
- session ID captured before timeout;
- timeout and explicit cancellation;
- descendants that create new process groups/sessions;
- daemon disconnect/reconnect at every event boundary;
- runner crash before/after atomic terminal status;
- disk full, permission failure, missing executable, and unsafe cwd;
- Landlock filesystem denial and seccomp syscall/address-family denial;
- mount/user/PID namespace views with minimal `/proc`, `/dev`, tmp/runtime and no unrelated host sockets;
- provider-control connectivity separated from no-network or brokered tool/MCP/browser egress;
- egress broker rejection of private/link-local/metadata/loopback destinations, DNS rebinding, redirect escape and policy confusion;
- cgroup/rlimit/tmp/workspace/spool/artifact limits and complete descendant/namespace cleanup;
- sealed credential delivery with no provider/control-plane credential inherited by nested tools;
- attempt-scoped host termination versus session-scoped host reuse/idle TTL;
- isolated workspaces, dirty-source snapshots, concurrent worktree locks and revision-checked promotion;
- artifact ingestion/materialization, digest mismatch, malicious archive/link rejection and visibility enforcement;
- launch-time executable replacement and credential rotation/revocation races.

Each provider must run the same adapter conformance suite in both its preferred native mode and every declared fallback that remains supported. The suite verifies:

- capability discovery and rejection of unsupported requested features;
- provider instance/session/turn identity capture and resume;
- streaming preview events followed by one authoritative terminal record;
- steering or follow-up input while a turn is active, when advertised;
- interrupt, timeout, abort, and descendant cleanup;
- provider permission requests mapped to Automonique policy without auto-approving;
- reconnect and cursor reconciliation after Automonique daemon, adapter, or provider-process loss;
- malformed, duplicated, reordered, unknown, and oversized provider events;
- native-surface failure followed by an observable, policy-approved fallback;
- raw transcript retention limits, redaction, and normalized-event parity.
- cross-tenant/account/workspace session-resume denial and immutable security-context binding.

Provider-specific fixtures must cover Jcode ACP and daemon reload—including proof that daemon-spawned tools remain in the declared cgroup/sandbox or an equivalent per-context daemon boundary—Claude bidirectional stream-JSON and resume, Codex App Server threads/turns/approvals, and opencode HTTP/SSE session reconciliation plus ACP fallback.

### 4. Reload matrix

Inject reload at each boundary:

- before and after durable Slack acknowledgement;
- during model classification;
- while waiting for approval;
- between approval CAS and queue insertion;
- between lock acquisition and runner start;
- during agent tool use;
- while persisting an event cursor;
- between terminal state and outbox insert;
- while sending Slack/GitHub/Fleet/Support effects;
- during Telegram long polling;
- during dashboard mutation;
- during database migration;
- during old-generation drain.
- while a global domain event/action receipt commits, a controller lease expires, a session host becomes idle, or an artifact/workspace is promoted.

For every injection, assert durable state, active lease epochs, process/unit inventory, external effect count, and eventual user-visible state.

### 5. Chaos suite

Automate randomized sequences of:

- `SIGSTOP`, `SIGCONT`, `SIGTERM`, and `SIGKILL` to old/new daemon generations;
- runner kill and cgroup cancellation;
- Slack/Telegram/Fleet timeouts and duplicate deliveries;
- SQLite busy/locked responses;
- socket disappearance and reconnect;
- corrupt/partial spool tail;
- filesystem permissions and low disk space;
- clock jumps where monotonic deadlines must remain correct;
- failed release checksum or incompatible schema range;
- provider binary replacement, incompatible generated schema, and capability removal;
- native provider connection loss during streaming, tool use, approval wait, steering, and terminal reconciliation;
- repeated reload/rollback loops.
- scheduler starvation/rate-limit/cost exhaustion, provider quarantine and work-graph cancellation races;
- database/artifact backup interruption, clean-host restore and disconnected-recovery enablement.
- sandbox launcher/egress broker crash, lost namespace/routing state, resource pressure, policy-attestation drift and cleanup interruption.

The suite must produce a reproducible seed and a final invariant report.

### 6. Security verification

- Fuzz all local and external protocol decoders.
- Verify Unix peer credentials and runtime-directory permissions.
- Confirm no credential appears in process argv, logs, spool, manifest, crash report, or dashboard.
- Test symlink, hard-link, path traversal and file replacement races.
- Validate Landlock and seccomp on the production kernel.
- Validate mount/user/PID/network namespace and selected-backend hardening behavior on the production kernel; required features fail closed rather than degrading silently.
- Prove provider API/auth connectivity cannot be used as model-directed general egress and Unix sockets cannot bypass the reviewed network/path policy.
- Prove resource/storage exhaustion produces bounded terminal evidence without host-wide denial of service.
- Test identical/narrower session reuse, reject sandbox widening, and verify N -> N+1 -> N adoption preserves the exact attestation digest.
- Validate exact sudo invocation and root-owned broker immutability.
- Fuzz and independently review the optional sandbox launcher and egress host capability separately from the deployment broker.
- Run dependency audit and supply-chain policy checks on every release.
- Prove cross-tenant denial for every snapshot, search, artifact, workspace, session, approval and export API.
- Test SDK credential issuance/expiry/rotation/revocation and provider-extension digest/provenance enforcement.
- Test deletion/export/retention/legal-hold workflows without erasing action evidence or leaking tombstoned content.
- Verify signed outbound webhooks reject replay and rotate keys without ambiguous delivery.

### 7. Operator TUI verification

- Reducer/property tests cover duplicate events, gaps, stale revisions, retention expiry, reordered delivery and snapshot replacement.
- Golden terminal tests cover wide, narrow, monochrome and high-contrast layouts without relying on color for state.
- Command palette fixtures prove the TUI consumes the canonical server registry and does not duplicate preset/regex routing.
- Action tests cover dry-run preview, exact target/revision display, idempotency reconciliation, conflicts and stale-confirmation invalidation.
- Approval tests keep Automonique work approvals separate from provider execution approvals and reject mismatched revisions/items.
- Live-run tests cover preview versus authoritative output, follow-up session binding, capability-gated steering, permission response and cgroup cancellation.
- Attachment tests prove multiple clients can observe any authorized cross-provider session, detach independently, and close/crash without changing runner or provider lifetime.
- N-pane tests cover dynamic pane counts, mixed providers/states, independent cursors/resync, focus/reorder/maximize/tabs, preview coalescing, noisy-pane backpressure and global alerts.
- Controller tests prove a single renewable owner, contention/conflict reporting, expiry, explicit release, reload revalidation and no implicit control from focus/layout restore.
- Reload tests keep the TUI open through N -> N+1 -> N, force disconnect at every mutation boundary, and compare the final reducer state with a fresh snapshot.
- Terminal lifecycle tests cover resize, suspend/resume, panic, `SIGINT`, `SIGTERM` and forced server loss, always restoring the terminal.
- Security tests verify peer identity/role enforcement, read-only downgrade, redaction, bounded export and absence of direct database/provider access.
- Explainability/work-graph/artifact/budget views are complete and shell controls remain a separate capability-gated subsystem.

### 8. TypeScript SDK verification

- Schema generation is reproducible: regenerate Rust-derived types, validators, OpenAPI/event clients and require zero diff.
- A coverage manifest proves every stable operator capability is represented in the SDK and no dashboard/TUI/CLI mutation depends on a private route.
- Run the same semantic contract suite through local Node/Bun, remote Node/Bun and browser transports.
- Validate every service group listed in `typescript-sdk.md`, including work graphs, execution hosts, workspaces, artifacts, identity, reconciliation, recovery, webhooks and optional local shells.
- Event tests cover `AsyncIterable` cancellation, multiplexed attachments, independent backpressure, unknown variants, cursor expiry/resync and authoritative reconstruction.
- Mutation tests cover generated/reused idempotency keys, revision conflicts, abort-versus-run-cancel distinction, ambiguous disconnect and durable receipt reconciliation.
- Compatibility tests run current and previous SDK versions against current and candidate generations during overlap, including canonical `@automonique/sdk*` imports and supported `@legacy/sdk*` forwarding imports.
- Bundle tests reject Node built-ins/credentials in browser output, browser dependencies in protocol-only output, duplicate wire types and undeclared side effects.
- Provider SDK tests run an out-of-process TypeScript fake adapter through the complete provider conformance, crash, approval, sandbox and reconnect matrix.
- Documentation examples compile and execute against the deterministic fake server; published declaration/source maps contain no build-host paths or secrets.
- Pagination/search tests prove stable order and no silent duplicate/skip behavior during concurrent writes; credential tests prove tenant scope and revocation.

### 9. Recovery, governance and reconciliation verification

- Take an online consistent recovery set, destroy the disposable installation, restore to a clean host, verify database/artifact/workspace/config checksums, resolve required secret descriptors through the escrowed key or external-provider recovery path, and meet the documented RPO/RTO without exposing plaintext credentials.
- Start restored Automonique in disconnected-recovery mode; reconcile transport offsets, provider sessions and remote action receipts before enabling intake/outbox effects.
- Exercise pause, drain, maintenance-read-only, provider-quarantine and rollback paths with explicit entry/exit audit events.
- Run `automonique audit --preview` (and the supported `legacyctl` alias), reject a stale plan, apply an exact plan revision and prove a second preview proposes zero changes.
- Run time-travel replay at selected event IDs and compare rebuilt projections without emitting an outbox row.
- Exercise tenant export, expiry, deletion, tombstones and legal holds against artifacts and raw provider records.
- Verify scheduler fairness, reservations, quotas, circuit breakers, cost anomaly alerts and work-graph dependency/cancellation behavior.
- Verify the optional shell subsystem is disabled by default, separately authorized and uses artifact-mediated file transfer.

### 10. Automonique identity and repository verification

- Prove canonical and supported legacy CLI, SDK, command, environment and path entry points reach one daemon, one admin socket and one durable store.
- Reject conflicting canonical/legacy configuration and prove no secret value appears in the diagnostic.
- Upgrade and roll back a copied legacy installation into Automonique without rewriting durable IDs, duplicating a service or losing an approval/session binding.
- Rebuild the candidate public repository from its documented import procedure and require secret/history, license, provenance, binary-asset and private-coupling gates before visibility changes.

### 11. Teams and Discord connector verification

Run one shared connector conformance suite plus platform-specific fixtures:

- authenticate/verify the platform envelope before bounded decoding;
- map application plus Microsoft tenant or Discord installation/guild to exactly one Automonique tenant and actor;
- deduplicate repeated Teams Activities, Discord Interactions and Gateway messages into one durable input;
- distinguish platform defer/acknowledgement from durable acceptance and terminal completion;
- preserve personal/DM, group, channel, thread/reply, mention/command and edited/deleted-message semantics;
- re-authenticate Adaptive Card/button/select/modal actions and reject wrong actor, tenant, revision, expiry or replay;
- ingest/download and publish attachments only through artifact grants, including malicious archive/link/size failures;
- reconnect connector event subscriptions and optional Discord Gateway sequences through connector plus daemon restart;
- reconcile ambiguous reply/edit/follow-up/proactive delivery using platform message IDs and action receipts;
- rotate/revoke Teams app credentials, Graph consent, Discord bot tokens/interaction secrets/webhooks and fail closed;
- enforce mention-only and minimal permissions/intents by default; prove RSC, Graph and `MESSAGE_CONTENT` remain unavailable until individually enabled;
- parse Discord rate-limit buckets/`Retry-After` and exercise Teams throttling without hard-coded retry timing;
- validate reproducible Teams app and Discord command/permission manifests contain no secret;
- verify notification-only webhooks cannot submit work or approve actions;
- compare captured egress with the published Microsoft/Discord data-boundary statement.

Teams fixtures cover personal/group/channel activities, Adaptive Cards, proactive targets, app uninstall/reinstall and scoped Graph/RSC denial. Discord fixtures cover HTTP signature/PING, commands, deferred/edit/follow-up responses, ephemeral approvals, components/modals, allowed mentions, optional Gateway resume/invalid session and webhook rotation.

### 12. Context, memory, skills, automation and tools verification

- Golden context manifests prove identical ordering/trust/provenance across providers, bounded rule/reference resolution and explicit cache invalidation.
- Queue/retry/undo/stop/compress/checkpoint tests inject reload/disconnect at every provider acceptance and workspace mutation boundary.
- Compression retains original history, citations and protected facts; token/component estimates reconcile with provider usage within declared tolerances.
- Memory/FTS/profile tests prove tenant isolation, exact source citation, supersession/correction/deletion, capacity review and no promotion of untrusted content to policy.
- Skill tests cover agentskills parsing, progressive disclosure, catalogs/signatures/licenses, bundles/fallbacks, learning proposal approval/trial and curator archive/restore/backup.
- Tool/toolset/search tests prove per-channel intersections, no inaccessible-name disclosure, deferred schema compatibility and prompt-cache consequences.
- MCP/client/server, workflow RPC, extension and hook suites cover discovery/reconnect, filtering, sampling, capability-call budgets, ordering/timeouts, filter/transform bounds, quarantine and daemon survival.
- Automation/goal/board tests cover DST/timezone schedules, duplicate ticks, script-only/chained jobs, wait/resume, completion evidence, user preemption, stale claim reclaim and webhook signature/filter/transform/idempotency.

### 13. Public protocol, desktop and connector-catalog verification

- ACP/OpenAI/Run/MCP/A2A/relay conformance maps every input/session/tool/approval/event/effect to one canonical record and survives current/previous release overlap.
- OpenAI clients cover streaming, stored response continuation, function items, model discovery, idempotency, retention/deletion and honest unsupported-field errors.
- Desktop/PWA/TUI semantic suites cover multi-session queues, attachments, project/Git/checkpoints, terminals/agent panes, OIDC reconnect, plugins/themes/keybinds/localization/accessibility and signed update rollback.
- Each connector catalog package runs the common identity/dedup/thread/edit/delete/attachment/component/rate-limit/revocation/reconnect/data-boundary suite plus its authoritative platform fixtures.
- Voice/meeting connectors prove consent indicators, participant/tenant mapping, artifact retention and that spoken content cannot approve privileged action implicitly.

### 14. Model, media and execution-provider verification

- Routing/pool/fallback/MoA tests prove no cross-tenant/billing/residency rotation, explainable selection, auxiliary disclosure, budget accounting and tool-free reference advisors.
- Vision/STT/TTS/image/video/web/browser/computer/LSP adapters verify modality/format limits, costs, artifact provenance, credential/egress confinement, stale references and cancellation.
- Rootless OCI, SSH, HPC, microVM, Kubernetes and cloud executors pass the same workspace/artifact/spec/attestation/event/approval/cancel/cleanup/cost contract.
- Hibernation/scale-to-zero tests distinguish snapshot, asleep, waking, running, lost and terminal states across daemon/remote control-plane outages.

### 15. Batch, trajectory and ecosystem verification

- Batch runs resume by stable record identity, never double-complete, enforce per-record capabilities and merge deterministic structured outputs.
- Trajectory exports exclude secrets, credentials and hidden reasoning by default, retain source/schema/model/tool/artifact provenance and honor tenant consent/retention/license.
- Compression/evaluation outputs cite immutable source hashes and reproduce statistics/filters from the same release.
- Profile/skill/extension/theme distributions pass signature, provenance, license, compatibility, revocation and clean-profile import/update tests.
- The machine-readable external capability ledger has no row without owner, ticket, fixture, SDK/no-client classification and graduation state.

### 16. AI implementation harness and commit-metrics verification

- Generate the executable work DAG and prove bidirectional completeness against phases, work IDs, dependencies, acceptance gates and the capability/parity ledgers.
- Run representative mechanical, durable-state and provider/transport trials
  under the owner-configured role/review policy; reject false independence
  claims and unresolved configured blockers.
- Race workers against path/crate leases, merge-train rebases and conflict invalidation; no overlapping write or stale review evidence may integrate.
- Kill/reload the harness, provider workers and build broker at every boundary and recover durable todos, attempts, build tasks, budgets, findings and evidence without duplicate commits.
- Enforce command/Git/resource policies and prove workers cannot reset/stash/force-push/merge, escape worktrees, exhaust the host, access production credentials or bypass the typed brokers.
- Seed agents with tempting shortcuts and prove deleted/skipped/ignored tests, weakened assertions, silent golden refresh, stubs, broad lint allowances and unjustified unsafe increases fail the gate.
- Reproduce every `automonique.dev-metrics/v1` manifest from its revision/environment class and verify its commit trailers, digest, sample counts, uncertainty and null-with-reason fields.
- Compare parity/correctness, reload/input/session latency, idle/per-session resources, binary/bundle size, prompt/cache/token/cost, review and safety deltas against pinned budgets without treating lines/commits/agents as quality.
- Verify a work unit cannot modify its judging metric/baseline in the same review scope and that secret/tenant/hidden-reasoning data cannot enter commit, CI or public metric artifacts.

### 17. Self-hosting and bootstrap verification

- Bootstrap from a clean disposable host using both a verified seed artifact and the documented source/toolchain path; interrupt/resume every step and reproduce the recovery bundle.
- Reject wrong repository/revision, manifest/schema/signature, mutable/unallowlisted dependency, toolchain/environment drift, source change during build and dirty release promotion.
- Prove stable/candidate UID, socket, database, artifact, workspace, network, credential, lease and outbox separation with negative cross-boundary tests.
- Exercise the complete candidate lifecycle, reject candidate attempts to write independent/promotion states and reconcile ambiguous prepare/approve receipts.
- Run fixture, sanitized replay and shadow modes with zero external effect; restrict canary/integration to exact reviewed tenants/destinations/branches and visible canary identity.
- Build A1 from stable, rebuild A2 from the candidate and build A3 on an independently authenticated clean worker; compare exact/normalized artifacts, generated source, dependencies and provenance with no unexplained mismatch.
- Make the candidate read the DAG, complete the fixture work unit, observe a background task, rebuild itself, reload C0→C1 and recover sessions/providers/builds/todos/findings/cursors/receipts.
- Kill/corrupt C0, C1, candidate database, build broker, provider and configured
  clean builder at every boundary; stable remains healthy and restores/abandons
  the candidate without production impact.
- Attempt candidate access to production transports, Support/fleet, stable database/socket, protected branch, signing, deployment and promotion credentials; every path fails closed and emits stable evidence.
- Corrupt stable development state and restore the last known-good seed/recovery bundle in disconnected mode before repository/evidence reconciliation.
- Verify recursive improvement depth/concurrency/time/token/cost limits, unchanged/oscillating-evidence stop rules and mandatory external review for product/security/legal/metrics/privilege/release decisions.
- Run current/previous bootstrap verifier and stable lab against the candidate schema/protocol; no self-host feature makes the only recovery controller unreadable.

## Observability required before rollout

The authenticated local exporter currently exposes the 26 closed
`automonique_*` metrics defined by `automonique-observability`, including
daemon/intake readiness, inbox/run/reconciliation/outbox state, Telegram and
live-progress health, provider availability, sandbox refusals, and durable
GenAI request/input/output token totals. The inventory below is the broader
rollout target; an item is not live merely because it appears here. Additions
must enter the closed metric vocabulary and the exporter together.

Expose these metrics/events:

- active and draining generation IDs, revisions and ages;
- reload phase, duration and last failure;
- exclusive lease owner/epoch/expiry;
- inbox rows by state and oldest age;
- work items and locks by state;
- execution hosts by lifetime, heartbeat age, event lag and spool bytes;
- outbox rows, retries and oldest pending age;
- transport connection/poller owner and offsets;
- duplicate inputs suppressed;
- adoption and reconciliation outcomes;
- schema/protocol compatibility ranges.
- domain-event/action-journal lag, receipt ambiguity and consumer cursor age;
- execution hosts by lifetime/state/idle age, workspace locks and artifact integrity/bytes;
- actor/tenant authorization denials, credential expiry and controller-lease contention;
- admission delay, fairness, rate/token/cost budgets and provider circuit breakers;
- backup age, last restore drill, retention/deletion backlog and safe-mode state;
- trace IDs spanning intake -> route -> approval -> attempt -> provider -> outbox/action receipt.
- connector installation/manifest/credential state, Teams permission/consent health, Discord intents/Gateway sequence/rate buckets and platform delivery reconciliation lag.
- context/cache/compression/input-queue/checkpoint state, memory/skill/goal/automation health and learning/curator proposal backlog;
- tool/MCP/extension/hook health, deferred-schema load, workflow-call budgets and quarantine;
- public-protocol sessions/errors, desktop/remote-client versions and complete connector-catalog health;
- routing/pool/auxiliary/MoA decisions, media/browser/computer jobs and remote-executor/hibernation state;
- batch/evaluation/trajectory progress and export-consent/redaction failures.
- bootstrap stage/manifest/toolchain health, source/build fingerprints,
  candidate state/gate age, self-host reload/rebuild status, build provenance
  and reproducibility mismatches.

Structured logs include `generation_id`, `reload_id`, `input_id`, `work_id`, `run_id`, and `outbox_id` as applicable. User content remains bounded/redacted.

## CI gates

A merge cannot ship when any of these fail:

- `cargo fmt --check`;
- clippy with warnings denied for project crates;
- Rust unit/integration/property tests;
- current Bun parity suite during migration;
- protocol schema compatibility checks;
- pinned provider binary/capability matrix checks and generated upstream schema diffs;
- native/fallback adapter conformance tests for Jcode, Claude, Codex, and opencode;
- migration upgrade and rollback-range tests;
- release reproducibility/checksum test;
- dependency vulnerability/license policy;
- runner sandbox smoke test on a compatible Linux CI worker.
- per-profile sandbox conformance, egress-confused-deputy, resource/quota and cleanup tests on the production-kernel class.
- headless TUI reducer, golden-screen, terminal-restoration and daemon-reconnect tests.
- TypeScript formatting/typecheck/unit/contract tests across supported Node, Bun and browser targets.
- generated SDK zero-diff, API coverage, bundle-boundary and current/previous compatibility checks.
- deterministic package archive, metadata, provenance and dependency-policy checks.
- domain journal/replay, RBAC/tenant isolation, workspace/artifact and scheduler/work-graph property suites.
- clean-host restore, reconciliation preview/apply, retention/deletion/export and safe-mode drills.
- machine-readable parity ledger with no unexplained entries.
- signed webhook replay/key-rotation and provider-extension provenance gates.
- Teams/Discord connector conformance, manifest permission diff, fake-platform restart and package reproducibility gates.
- core context/memory/skills/tools/MCP/automation/goal/trigger conformance and external capability-ledger completeness gates.
- public protocol, extension/UI, desktop and connector-catalog package conformance for every enabled artifact.
- model/media/browser/executor adapter lifecycle/data-boundary suites and research-export consent/redaction gates when those features are enabled.
- canonical/legacy identity compatibility and clean public-source audit gates.
- executable implementation-DAG completeness, harness policy/trial/reload tests and per-commit metrics-attestation verification.
- clean-host bootstrap, stable/candidate isolation, self-build/reload/recovery,
  configured build provenance/rebuild and promotion-authority conformance.

## Rollout stages

### Stage A — developer and fixture mode

No production tokens. Replayed sanitized inputs and fake external APIs only.

The baseline backup/clean-host restore drill and parity ledger are established before production schema migration begins.

The SH0 seed and `automonique-bootstrap` graduate here. Self-host candidates
remain in fixture/replay mode until namespace and credential isolation passes;
owner verification and configured SH4 reproducibility evidence are required
before the candidate may alter bootstrap, sandbox, authorization or promotion
code.

### Stage B — runner and provider canaries

TypeScript remains the daemon. Rust handles explicitly selected low-risk jobs one provider and one native mode at a time: Jcode ACP, Claude stream-JSON, Codex App Server, then opencode HTTP/SSE. Each provider advances only after session resume, approvals, cancellation, reconciliation, and fallback telemetry are demonstrated; the old transport remains available as an explicit fallback.

### Stage C — Rust shadow daemon

Rust consumes copied/replayed durable inputs and produces decisions into shadow tables. It cannot post, approve, claim, send mail, deploy, or mutate GitHub.

The TUI first ships read-only against this stage. Mutating controls remain hidden until the corresponding Rust action contract has passed idempotency and revision-conflict tests.

The SDK ships first against fake/shadow endpoints. Read-only services graduate before mutations; the dashboard moves service-by-service until its handwritten protocol layer reaches zero.

Teams and Discord use fake platform servers only at this stage. No production tenant/guild app is installed.

### Stage D — scoped primary ownership

Rust owns one test Slack channel/user and test Telegram chat through explicit leases. TypeScript owns all other scopes.

### Stage E — production intake with TypeScript fallback

Rust owns transports and scheduling. TypeScript remains installable as a rollback release but cannot concurrently mutate the same scopes.

### Stage F — active-work reload canary

Reload Rust during manually approved low-risk work. Increase from one to three concurrent jobs after event/report parity is demonstrated.

### Stage G — default and soak

The Rust foreground runtime becomes the default control plane. Optional
supervisor packaging graduates independently. Keep the previous compatible
release, database backup procedure, and tested rollback for a defined soak
window.

The restore drill, governance workflows, reconciliation zero-diff check and safe-mode runbooks must pass during the soak.

Teams and Discord then graduate independently through notification-only, personal/DM, mention-only channel and exact-revision approval canaries. Graph/RSC, Discord Gateway privileged intents, attachments and proactive messages remain separate later flags. Connector graduation is not a prerequisite for the core Stage G decision.

### Stage H — compatibility removal

Remove obsolete Bun backend paths only after rollback support no longer requires them. Legacy names/tables remain until the telemetry and deprecation gates independently authorize contraction; branding is not deletion authority.

### Stage I — independent ecosystem graduation

ACP/OpenAI/MCP/A2A/relay, native desktop/PWA, each additional connector, each media/browser/computer backend, each remote executor and research/catalog features graduate behind separate capability flags and canaries. Their failure or deferral cannot weaken the core service or another graduated family.

### Stage J — self-host development integration

After SH4, Automonique may integrate fully reviewed units into a bot-owned development branch under explicit repository policy. Canary artifacts remain development-signed/non-production and visually distinct. Production `main`, stable tags, public packages, signing and deployment remain external promotion actions; SH6 produces their immutable proposal and evidence only.

## Go/no-go checklist for production reload

- Target manifest and checksums verified.
- Current/target schema and protocol ranges overlap.
- Database integrity and free-space checks pass.
- Backup freshness is inside RPO and the latest clean-host restore drill is inside policy.
- No prior reload is incomplete.
- Active execution hosts report compatible protocols, lifetime modes and immutable binary/schema identities.
- Active provider bindings report compatible binary/schema ranges and required capabilities.
- Every active host reports the expected sandbox profile/policy/attestation digests, resource boundary and provider/tool egress separation; no sandbox implementation is quarantined.
- No unresolved provider permission request would be orphaned by the handoff.
- Durable inbox/outbox ages are within operational bounds.
- Domain journal/action receipts, workspace locks and artifact integrity checks are healthy.
- Identity/tenant policy, credential revocation, budgets and controller leases compile and fence correctly.
- The parity ledger has no unexplained or evidence-free production item.
- Every attached Teams/Discord connector has an exact tenant binding and a protocol range compatible with the candidate. Installation/credential/permission failures are visible degradation and keep that connector disabled; they do not veto an otherwise safe daemon handoff.
- Healthy connectors have reviewed manifests/permissions/intents, current data-boundary disclosure and reconciled receipt/rate-limit state; notification-only webhooks cannot invoke work.
- Candidate warm readiness passes.
- Old generation remains recoverable until lease transfer.
- Automatic failure rollback has been exercised on the exact release mechanism.
- Operator can see the reload and abort before ownership transfer.
- An attached TUI has either reconnected to the target generation or is visibly stale/read-only; no mutation is left in an unreconciled client state.
- The current and previous supported TypeScript SDK schema/protocol ranges overlap the target generation, and their contract suites pass against the candidate.
- Canonical and legacy runtime locators resolve to one service/state owner and no conflicting configuration is present.
- Required production sandbox profiles pass the exact-host doctor/self-test; work requiring an unavailable stronger boundary remains ineligible.
- Context/queue/compression, memory/skills, tools/MCP, automations/goals/triggers and profile state schemas required by active work are compatible and their background workers can resume safely.
- Every enabled public protocol, extension, connector, media adapter and remote executor reports a compatible manifest/cursor/attestation or remains explicitly disabled.

## Success report

Every reload produces a bounded audit record:

- source and target generation/revision;
- release checksum;
- phase timings;
- leases transferred;
- active execution hosts, attempts, workspaces and runs adopted with their event cursors;
- provider instances, sessions, turns, approvals, capabilities, and fallback modes adopted;
- compatible TypeScript SDK range and schema digest exposed by the target;
- inbox/outbox counts before and after;
- global domain cursor, unresolved action receipts, artifact/workspace verification and controller-lease results;
- transport reconnect results;
- Teams/Discord connector installation, cursor, consent/intent, credential and message-reconciliation results when enabled;
- old generation drain result;
- rollback compatibility status;
- final success/failure reason.
