# Work breakdown

Each item should be a small reviewable issue/PR. IDs express dependency order, not calendar estimates.

## Epic R0 — discovery and handoff proof

- **R0-01 Current contract inventory:** map every input, state transition, timer, side effect, command, backend event and operational script. Done when each has an owner and parity fixture plan.
- **R0-02 Sanitized fixture corpus:** capture Slack, Telegram, Fleet, Support and four backend streams. Depends on R0-01. Done when CI can replay without secrets/network.
- **R0-03 Foreground lifecycle spike:** prove readiness, bounded drain, replacement failure fallback and clean shutdown with directly launched generations and no service manager.
- **R0-04 Execution-host ownership spike:** prove a runner remains discoverable across control-plane reconnect, is cancellable with all descendants, and reports unsupported isolation features without requiring a service unit.
- **R0-05 Runtime topology decision:** pin the foreground lifecycle and execution-backend contracts; compare direct process ownership with optional supervisor adapters and record what would justify adding one.
- **R0-06 Provider surface inventory:** record tested versions, native protocols, schemas, capabilities, authentication, lifecycle commands, unsafe/experimental methods and fallback modes for Jcode, Claude, Codex and opencode.
- **R0-07 Provider transcript corpus:** capture sanitized native and fallback sessions covering stream, tool, approval, steer/follow-up, cancel, resume, reconnect and failure behavior.
- **R0-08 Machine-readable parity ledger:** classify every current feature/script/companion as preserve, replace, isolate or retire with owner, fixture and evidence; include client-portal, client publication, audits, live feed, notifications, targets and operational commands.
- **R0-09 Identity/data/operations inventory:** document tenants, actor mappings, roles, credentials, artifact classes, workspaces/dirty trees, retention, budgets, backup dependencies and runbooks.
- **R0-10 Baseline recovery drill:** take a consistent backup and restore it to a clean disposable host within initial RPO/RTO.
- **R0-11 Shell decision fixture:** measure current interactive shell/file-transfer use and accept the isolated compatibility boundary or an explicit retirement decision.
- **R0-12 Channel connector corpus:** fake/sanitized Teams Activities/Cards and Discord Interactions/Gateway/components plus manifest/permission fixtures with no live tenant/guild credentials.
- **R0-13 Automonique identifier inventory:** classify every service, path, environment, protocol, package, command and external-platform legacy name as durable, compatibility-only or presentation-only.
- **R0-14 Sandbox host-capability spike:** record Landlock ABI, namespaces, cgroup controllers, systemd hardening, rootless routing and required privileged setup on the production kernel; choose rootless or minimal-launcher implementation per feature.
- **R0-15 Provider/tool egress spike:** prove provider-control connectivity can be separated from tool, MCP, browser and extension egress for every native/fallback provider mode; reject incompatible profile/mode combinations.
- **R0-16 External capability baseline:** turn `external-capability-ledger.md` into a machine-readable ledger keyed to capability, specification, track, owner, ticket and fixture; schedule periodic ecosystem capability review without product-comparison names in public plans.
- **R0-17 Executable implementation DAG:** generate `.automonique/dev/program.yaml` from every phase/ticket/dependency/exit gate and reject drift in either direction.
- **R0-18 Development guides and objectives:** freeze reviewed porting, state-machine, security, naming, test-preservation and metrics guides; assign each unit a measurable objective and hill-climbability score.
- **R0-19 Minimal `automonique-lab`:** durable Rust orchestrator, separate dev state/credentials, execution-host provider adapters, isolated worktree/file leases, build broker, Git broker, budgets and TypeScript scenario client.
- **R0-20 Role-policy trials:** run three representative units under the owner-configured review policy, including zero-reviewer and fresh-context-review cases; rerun after harness-policy correction and compare deterministic evidence.
- **R0-21 Commit metrics and baselines:** emit compact Git trailers plus content-addressed `automonique.dev-metrics/v1` manifests covering correctness/parity, product performance, prompt/cache/economics, safety/maintainability and environment/sample provenance.
- **R0-22 Harness reload and merge train:** preserve workers, builds, queues, leases and evidence across harness reload; serialize reviewed commits, invalidate stale review after conflicts and prove clean abandon/rollback.
- **R0-23 Self-hosting levels/policy:** encode SH0–SH6, repository ceiling (`proposal_only` through `production_proposal`), role separation and forbidden candidate authority.
- **R0-24 Bootstrap manifest/schema:** source/toolchain/dependency/environment/build/test/output/trusted-builder contract with fixed digests and no secrets.
- **R0-25 `automonique-bootstrap` inspector:** non-mutating host/repository/toolchain/sandbox/recovery plan and schema/signature verification.
- **R0-26 Fresh-host bootstrap:** resumable apply/verify/export-recovery flow creating the isolated development identity, state and SH0 lab from reviewed inputs.
- **R0-27 Source/build identity:** repository/tree/dirty-patch/dependency/generated-source fingerprints, pre/post build validation, deduplication and superseded results.
- **R0-28 Stable/candidate isolation:** digest-named units, UIDs/runtime paths, sockets, database/artifacts/workspaces, credentials, network and lease/outbox separation.
- **R0-29 Candidate lifecycle journal:** proposed-through-promoted state machine, role-owned evidence, quarantine/reject/rollback and action receipts.
- **R0-30 Self-development session/actions:** repository-scoped profile, stable/candidate identity, build/test/background/evidence/reload/rollback and promotion-proposal commands without generic exec.
- **R0-31 Candidate modes:** fixture, sanitized replay, shadow, explicit canary and bot-owned development-integration boundaries with unmistakable identity.
- **R0-32 Candidate build/publication:** centralized resource-bounded queue, immutable digest-addressed candidates, binary identity smoke tests and no dirty promotion.
- **R0-33 Candidate self-host fixture:** bounded work-DAG read, fixture unit, background build observation, same-source rebuild and exact identity reporting.
- **R0-34 Candidate generation reload:** stable-observed C0→C1 handoff preserving sessions/providers/builds/todos/findings/cursors/receipts plus forced-failure fallback.
- **R0-35 Reproducible builder/provenance:** clean source acquisition, isolated build, authenticated provenance, SBOM and vulnerability/license results; separate builder identity is optional.
- **R0-36 Reproducibility comparison:** A1 stable build versus A2 candidate self-build and optional A3 clean rebuild, bit-identical target and declared deterministic normalization during transition.
- **R0-37 Self-host SDK/operator views:** generated TypeScript services and TUI/dashboard stable/candidate topology, queues, gates, comparisons, metrics and rollback readiness.
- **R0-38 Promotion protocol:** exact-revision prepare/approve receipts, required external authorities, protected-branch/signing/deployment exclusion and ambiguous-outcome reconciliation.
- **R0-39 Recursive improvement policy:** bounded evidence sources, hill-climb objectives, auto-queue ceiling, oscillation/repetition stop rules and owner-configured review classes.
- **R0-40 Self-host recovery drill:** corrupt/crash candidate and stable development state, restore last seed/recovery bundle, reconcile repository/evidence and prove production isolation.

## Epic R1 — workspace and shared protocol

- **R1-01 Cargo workspace and CI.**
- **R1-02 Bounded domain primitives:** IDs, bounded text, timestamps, revisions, URLs and secret wrappers.
- **R1-03 Length-delimited local protocol codec:** version negotiation, message limits and error mapping.
- **R1-04 Unix peer authorization:** UID/PID checks and mode-0700 runtime layout.
- **R1-05 Release manifest:** hashes, revision, schema/protocol ranges and platform requirements.
- **R1-06 Cross-language fixtures:** Bun encoder/Rust decoder and Rust encoder/Bun decoder.
- **R1-07 `automonique doctor`:** non-mutating host and release checks plus the `legacyctl` forwarding contract.
- **R1-08 Provider capability contract:** typed capabilities plus provider instance/session/turn/item/request identities and negotiation rules.
- **R1-09 Provider event contract:** bounded raw envelopes, preview versus authoritative normalized events, approval records and cursor semantics.
- **R1-10 Upstream schema pipeline:** generate/capture schemas, hash fixtures, map them to binary ranges and classify compatible versus breaking diffs.
- **R1-11 TypeScript codegen spike:** prove Rust-derived domain/API/event schemas can generate reproducible runtime validators and clients without losing bounds, unions, branded IDs or unknown-event compatibility.
- **R1-12 Domain event/action contracts:** schema-versioned global journal, aggregate revisions, action receipts, consumer cursors and side-effect-free replay.
- **R1-13 Identity and policy contracts:** actors, tenants, external identities, roles, credentials, authorization evidence and break-glass audit.
- **R1-14 Workspace/artifact contracts:** registry, immutable bases, locks, provenance, visibility, retention and storage abstraction.
- **R1-15 Execution-host lifecycle contract:** separate work, attempt, host, provider session and turn plus idle-TTL/hibernation semantics.
- **R1-16 External connector contract:** installation/tenant/actor resolution, source keys, durable input, render intents, action tokens/receipts, artifact grants and conformance protocol.
- **R1-17 Canonical/legacy compatibility contract:** generate Automonique names plus legacy forwarding aliases from one registry, reject configuration conflicts and prove one runtime/state owner.
- **R1-18 Sandbox contracts:** versioned profiles, `SandboxSpec`, enforcement attestation, violations/quarantine, resource/storage budgets, provider/tool egress split and implementation capability negotiation.
- **R1-19 Canonical Rust namespace gate:** name every Cargo package/crate/module/feature/binary, schema, metric, tracing target, fixture and release artifact `automonique-*`/`automonique_*`; generate only explicitly inventoried legacy compatibility codecs and forwarding executables, and fail CI on undocumented legacy identifiers.
- **R1-20 Context and learning contracts:** context manifests/references, queues, compression lineage, memory/FTS, skills, profiles and learning proposals.
- **R1-21 Tool and extension contracts:** tool registry/toolsets/search, capability RPC, MCP client/server, extension manifests, hook classes and secret-source descriptors.
- **R1-22 Automation and goal contracts:** canonical schedules, occurrences, goals/subgoals/waits, board claims, inbound triggers and notification delivery.
- **R1-23 Public protocol contracts:** ACP host, OpenAI compatibility, native Runs, MCP export, A2A and relay identity/session/action mappings.
- **R1-24 Model/media/executor contracts:** routing/pools/auxiliaries/MoA, media/browser/computer adapters and execution-provider lifecycle/attestation.
- **R1-25 Cross-surface interaction contracts:** queued composer input, retry/undo/stop/compress/checkpoint semantics, context usage and UI/plugin projections.

## Epic R2 — execution hosts, workspaces and artifacts

- **R2-01 RunSpec schema and validator.**
- **R2-02 Exclusive protected spec delivery:** no prompt/secret argv.
- **R2-03 Spool writer:** monotonic events, raw channels and atomic terminal status.
- **R2-04 Runner control socket:** inspect, subscribe, heartbeat and cancel.
- **R2-05 Execution-backend launcher:** typed direct-process baseline plus optional supervisor adapters.
- **R2-06 cgroup cancellation and timeout semantics.**
- **R2-07 Landlock filesystem policy.**
- **R2-08 seccomp/network policy.**
- **R2-09 Capability probe and mode selector:** choose only compatible native/fallback modes and make every degradation observable.
- **R2-10 Provider session journal:** persist provider process, session, turn, request, cursor, capability, schema and approval bindings.
- **R2-11 Raw/normalized event pipeline:** preserve bounded provider records while emitting stable preview and authoritative Automonique events.
- **R2-12 Provider approval bridge:** keep Automonique's outer work approval distinct from provider tool/file/network/command permission decisions.
- **R2-13 Jcode ACP client:** explicit daemon socket, session continuity, model/auth/usage telemetry and protocol reconciliation.
- **R2-14 Jcode daemon lifecycle:** health, graceful reload, reconnect/adoption and NDJSON fallback.
- **R2-15 Claude stream-JSON adapter:** long-lived bidirectional stream, replay, partials, hooks/subagents, session capture, resume/fork and telemetry.
- **R2-16 Claude permission and fallback adapter:** permission request mapping, interrupt/reconnect, bounded one-shot fallback and parity fixtures.
- **R2-17 Codex schema bindings:** generate and pin App Server request/response/event schemas to tested binary ranges.
- **R2-18 Codex App Server adapter:** session-host stdio, initialize, threads/turns/items, steer/interrupt, MCP/skills/model/account/rate-limit telemetry and terminal reconciliation.
- **R2-19 Codex approval and fallback adapter:** command/file approval mapping, stable-method allowlist and `codex exec --json` fallback.
- **R2-20 opencode OpenAPI client:** session-host authenticated server, health/config/provider/MCP/agent inventory and session APIs.
- **R2-21 opencode SSE reconciler:** async prompt, events, status/messages/diff/permissions, abort and cursorless reconnect reconciliation.
- **R2-22 opencode fallback adapters:** ACP first, JSON-run last, with capability loss made explicit.
- **R2-23 Operator event renderer/attach:** show provider mode, capabilities, session/turn, approvals, reconnects and fallbacks without exposing secrets.
- **R2-24 Retention and orphan reconciliation:** adopt or terminate abandoned provider processes and bound raw transcripts.
- **R2-25 TypeScript runner client behind feature flags:** provider- and mode-specific rollout controls plus immediate legacy fallback.
- **R2-26 Cross-provider conformance and chaos suite:** run the shared contract against every supported native/fallback mode.
- **R2-27 Provider upgrade gate:** probe a candidate binary/schema in isolation and refuse incompatible upgrades before production selection.
- **R2-28 Dual host lifetimes:** implement attempt-scoped and session-scoped execution hosts with serialized turns, idle TTL and explicit close; discovery recognizes compatible legacy units during upgrade.
- **R2-29 Workspace registry/provisioner:** isolated worktrees or captured snapshots, immutable base revisions, lock fencing and dirty-source policy.
- **R2-30 Workspace promotion:** reviewed diff/merge/integration with expected base/head revisions and conflict receipts.
- **R2-31 Artifact service core:** content-addressed ingest, metadata, provenance, visibility, quotas, retention and malicious-file defenses.
- **R2-32 Artifact materialization/publication:** capability grants, safe workspace paths, reviewed downloads/publication and exact digest evidence.
- **R2-33 Immutable launch identity:** opened/verified executable identity plus versioned credential descriptors revalidated at use time.
- **R2-34 Reboot/hibernation reconciler:** classify remote-resumable, hibernated, interrupted and reconciliation-required sessions without false running state.
- **R2-35 Jcode security-context enforcement:** attest tenant/account/workspace/cgroup/tool execution for shared-daemon sessions, otherwise provision per-context daemons; add cross-tenant resume and descendant-boundary tests.
- **R2-36 Mount/user/PID boundary:** minimal filesystem, `/proc`, `/dev`, tmp/runtime and descriptor view using the rootless implementation selected by R0-14.
- **R2-37 Landlock/seccomp engine:** versioned rulesets for filesystem defense in depth, syscall/address-family denial and fail-closed kernel feature probing.
- **R2-38 Resource and storage controller:** cgroup v2 CPU/memory/PID/I/O/runtime limits, rlimits, scratch/workspace/spool/artifact quotas, reservation and terminal reconciliation.
- **R2-39 Egress namespace and broker:** loopback/no-network defaults, reviewed destination objects, DNS/private/metadata/rebinding/redirect defenses, byte/time bounds and durable receipts.
- **R2-40 Provider/tool network split:** provider API/auth egress isolated from nested command/MCP/browser egress; provider modes that cannot prove separation are ineligible.
- **R2-41 Process-class credentials:** sealed descriptors plus optional supervisor credential adapters, empty nested-tool environments, audience/version revalidation and revocation quarantine.
- **R2-42 Nested tool/MCP/extension host:** separately constrained child process boundaries with explicit executable, path, credential, egress and resource grants plus descendant cleanup.
- **R2-43 Sandbox attestation and observability:** persist effective digests/namespace/cgroup/kernel evidence, emit prepared/violation/limit/quarantine/released events and project safe evidence to operators.
- **R2-44 Sandbox conformance/escape suite:** links/mounts/`proc`/descriptors, sockets/private network/DNS/redirects, provider-egress confused deputy, resource exhaustion, credential inheritance, cleanup and reload adoption.

## Epic R3 — generations and reload skeleton

- **R3-01 Generation and reload audit schema.**
- **R3-02 Admin socket and authenticated CLI commands.**
- **R3-03 Candidate spawn and warm-readiness handshake.**
- **R3-04 Lease implementation with fencing epochs.**
- **R3-05 Quiesce and transactional ownership transfer.**
- **R3-06 Foreground readiness and lifecycle handoff with optional supervisor notification adapters.**
- **R3-07 Old-generation drain and forced retirement.**
- **R3-08 Failed-candidate automatic recovery.**
- **R3-09 Rollback through the same protocol.**
- **R3-10 Active-run adoption across repeated reloads.**
- **R3-11 Provider-binding adoption:** transfer provider instance/session/turn cursors and pending permission requests without duplicating prompts or terminal effects.
- **R3-12 Admin endpoint ownership:** atomic foreground ownership is required; optional activation adapters may queue/pass connections without unlink/rebind races.
- **R3-13 Controller-lease fencing:** persist, expire and revalidate one interactive owner independently of observation and generation lifetime.
- **R3-14 Host/workspace/artifact adoption:** prove both host lifetimes, locks and artifact references survive repeated N -> N+1 -> N.

## Epic R4 — durable application state

- **R4-01 Migration framework and compatibility ranges.**
- **R4-02 Durable inbox repositories and claims.**
- **R4-03 Work-item state machine and serialization locks.**
- **R4-04 Run repository and event cursor transactions.**
- **R4-05 Typed outbox and delivery leases.**
- **R4-06 Import current tickets, ignored rows, sessions, chat, gates and outboxes.**
- **R4-07 Pending approval restoration.**
- **R4-08 Running-ticket reconciliation instead of boot-time failure.**
- **R4-09 Adjacent-generation migration tests.**
- **R4-10 Provider session/turn repositories:** durable bindings, capabilities, schema hashes, cursors and reconciliation state.
- **R4-11 Provider approval repository:** exact revision/request binding, expiry, decision audit and recovery across reload.
- **R4-12 Attempt/execution-host repositories:** retry lineage, attempt numbers, host lifetimes and no one-run-per-work uniqueness shortcut.
- **R4-13 Global domain journal:** transactional aggregate events, schema versions, consumer cursors and bounded snapshot/resync.
- **R4-14 Durable action receipts:** idempotency key, actor/tenant, target revision, result/effect evidence and unknown-outcome reconciliation.
- **R4-15 Identity/authorization repositories:** actors, external mappings, tenants, roles, policy revisions, credentials and decision audit.
- **R4-16 Workspace/artifact repositories:** registry revisions/locks, object metadata/links, visibility, encryption refs and tombstones.
- **R4-17 Operational state repositories:** reload epochs, transport offsets, raw provider records, settings revisions, notifications and audit events.
- **R4-18 Typed outbox v2:** schema version, lease epoch, sent time, remote ID and reconciliation evidence with expand/contract migration.
- **R4-19 Event replay/time travel:** rebuild and compare projections at a cursor with effects forcibly disabled.
- **R4-20 Connector state repositories:** installations, external identities, transport conversations/messages/interactions, proactive targets, consent/intents, rate limits and connector cursors.
- **R4-21 Inbox/work/host separation:** keep transport routing out of approval/queue states, support non-input work origins, and model a run's optional pre-launch execution-host binding consistently with the lifetime design.
- **R4-22 Context/session state:** component manifests, reference resolutions, compression lineage, prompt-cache invalidations and durable input queues.
- **R4-23 Memory and retrieval state:** typed/provenanced memory, supersession/deletion, FTS5 session/messages and external adapter cursors.
- **R4-24 Skills/extensions state:** source/digest/license/capabilities, installs, scoped activation, bundles, learning proposals, curator state and revocations.
- **R4-25 Profiles and model accounts:** persona/defaults/toolsets/skills/adapters/channel bindings plus isolated provider-account/credential-pool metadata.
- **R4-26 Automations/goals/boards:** schedules, occurrences, waits, criteria, board claims/comments/dependencies and delivery state.
- **R4-27 Trigger and hook state:** inbound routes/signature versions/filters/idempotency, hook registrations/order/health and causation receipts.
- **R4-28 Protocol/client mappings:** ACP/OpenAI response/A2A/relay coordinates, public API idempotency and stored-response retention.

## Epic R5 — scheduling and fleet

- **R5-01 Bounded scheduler and pause/resume.**
- **R5-02 Thread/issue/session serialization.**
- **R5-03 Fleet heartbeat and configuration projection.**
- **R5-04 Fleet claim/unclaim with lease fencing.**
- **R5-05 Fleet cancellation watch and runner cancellation.**
- **R5-06 Job-log batching with durable cursor.**
- **R5-07 Terminal report outbox and backoff.**
- **R5-08 No-double-claim and reload fault tests.**
- **R5-09 Admission and fairness:** tenant/actor/workspace/provider limits, deterministic fair queueing and observable rejection/throttling reasons.
- **R5-10 Budget reservations:** token, cost, time and rate reservations/settlement with hard/soft limits and anomaly events.
- **R5-11 Provider circuit breakers/quarantine:** health-scored admission, explicit degradation and no silent unsafe fallback.
- **R5-12 Durable work graphs:** dependencies, parent/child/subagent links, retries, partial completion, critical path and cancellation propagation.
- **R5-13 Automation scheduler:** timezone/DST-safe one-shot/interval/cron occurrences, edit/pause/resume/run-now, overlap policy and fenced duplicate suppression.
- **R5-14 Script-only and chained jobs:** zero-model workflow execution, typed predecessor outputs/artifacts and multi-connector delivery.
- **R5-15 Persistent goal controller:** completion contracts, criteria/subgoals, deterministic/auxiliary judge, waits, continuation budget and user preemption.
- **R5-16 Work-board dispatcher:** Kanban projection, scoped worker claims/heartbeat, stale reclaim, failure auto-block and command-center statistics.
- **R5-17 Trigger admission:** signed inbound webhook/watch/event intake, declarative filters, sandbox transforms, rate limits and delivery-only path.

## Epic R6 — transports and approvals

- **R6-01 Slack Socket Mode connect, ack and durable insert.**
- **R6-02 Slack Web API client with bounded retry.**
- **R6-03 Slack mentions/messages/actions/commands dispatch.**
- **R6-04 Slack approval gate creation, recovery and exact revision binding.**
- **R6-05 Slack reaction/status reconciliation.**
- **R6-06 Telegram Bot API and access policy.**
- **R6-07 Telegram durable polling and offset.**
- **R6-08 Telegram per-scope scheduler and reply correlation.**
- **R6-09 Telegram approval and command UI.**
- **R6-10 Poller lease handoff during reload.**
- **R6-11 Duplicate/overlap and reconnect tests.**
- **R6-12 External identity resolution:** map Slack/Telegram/browser/SDK identities to actors and tenants before routing or approval.
- **R6-13 Transport RBAC and tenant tests:** deny cross-tenant thread, approval, artifact and operator access with durable policy evidence.
- **R6-14 Cross-channel conversation contract:** normalize mention/command, personal/group/channel/thread/reply, edit/delete tombstones and platform acknowledgement versus durable acceptance.

## Epic R7 — Automonique behavior and integrations

- **R7-01 Declarative command registry and generated help.**
- **R7-02 Conversation state and exact follow-up recovery.**
- **R7-03 Deterministic route parsers and validators.**
- **R7-04 Bounded model classifier/chat adapter.**
- **R7-05 Operational queries and GitHub truth resolution.**
- **R7-06 Memory and notification rules.**
- **R7-07 Job envelope, persona and risk classification.**
- **R7-08 Site and access conversations.**
- **R7-09 Support inbox/query/compose/review/mail flow.**
- **R7-10 GitHub context and report publication outbox.**
- **R7-11 Privileged action proposal/review boundary.**
- **R7-12 Full conversation/security fixture parity.**
- **R7-13 Restricted provider profiles:** route classification and chat through the shared adapters with explicit no-tools/no-network capability requirements.
- **R7-14 Deterministic execution plan:** persist resolved route, command, provider/fallback, workspace, tools, limits plus persona/policy/registry hashes.
- **R7-15 Client-portal publication parity:** tenant-fenced Support flows and explicit internal-draft versus client-published records.
- **R7-16 Companion/knowledge packaging:** versioned companion prompts/assets/knowledge bases with provenance and release compatibility.
- **R7-17 Learned target registry:** revisioned suggestions, human confirmation, tenant scoping, expiry and explainability.
- **R7-18 Reconciliation product:** typed reconcilers and `automonique audit --preview [--full]` / `--apply <plan-id>` (plus legacy alias) for Slack/GitHub/database drift.
- **R7-19 Remaining operational parity:** Slack live feed/post-as-assistant, browser notifications, site digest/oneshot/ops commands, deploy webhook, worker capabilities and ignored-message policy.
- **R7-20 Signed outbound webhooks:** revisioned endpoints, signing-key rotation, replay defense, receipts and reconciliation.
- **R7-21 Cross-provider context compiler:** rules, references, trust labels, provenance, component budgets and deterministic provider projection.
- **R7-22 Conversation control:** durable input queue, provider acceptance boundary, retry/undo/stop/steer/compress/new/fork semantics and command-registry UX.
- **R7-23 Agent-scoped checkpoints:** one-per-turn snapshot, diff/list/restore, caps/pruning and worktree/promotion integration.
- **R7-24 Typed memory and session search:** user/workspace/team/task records, FTS5 exact retrieval, correction/deletion and optional external-memory SPI.
- **R7-25 Skills runtime:** agentskills.io parsing, progressive loading, scoped catalogs, install/update/publish, bundles and fallback activation.
- **R7-26 Governed learning and curator:** evidence-backed memory/skill proposals, test/trial/approval, usage tracking, pin/archive/restore/backup and consolidation proposals.
- **R7-27 Canonical tools and tool search:** registry, per-channel/profile toolsets, deferred authorized schema retrieval and cache invalidation.
- **R7-28 Native MCP:** managed stdio/HTTP client, discovery/filtering/health, sampling policy and scoped Automonique MCP server.
- **R7-29 Programmatic workflow RPC:** WASI/JS/Python sandbox adapters, capability socket, call/resource limits and nested causation.
- **R7-30 Extension and hook hosts:** signed manifests, out-of-process lifecycle, observer/filter/transform/context/trigger hooks and quarantine.
- **R7-31 Profiles and personality:** persona/SOUL import, clone/export/distribution, isolation and explicit distinction from tenant/workspace/sandbox.
- **R7-32 Model routing and credentials:** aliases, capability/locality/cost routes, same-boundary pools, fallback graphs, auxiliary models and MoA presets.
- **R7-33 Secret-source adapters:** systemd/local encryption, 1Password, Bitwarden and pinned command helper with sealed delivery.
- **R7-34 LSP and developer intelligence:** sandboxed language servers, normalized diagnostics/code actions and native-provider coexistence.

## Epic R8A — operator, identity and event foundation

- **R8A-01 Operator protocol:** versioned snapshot, topic subscription, cursor expiry/resync, action receipt and capability negotiation shared by SDK/TUI/web/CLI.
- **R8A-02 Server-described command registry:** stable command IDs, aliases, typed fields, authorization, approval policy and action-preview schemas.
- **R8A-03 Rust schema/service export:** reproducible JSON Schema, OpenAPI, event-channel, local-protocol, command and provider-adapter manifests with digests.
- **R8A-04 Server adapters:** authenticated local Unix-socket API plus Axum HTTP/WebSocket projections of the same domain contracts.
- **R8A-05 Durable multiplexed event stream:** topic/attachment filtering, independent reconnect cursors, per-stream resync, snapshot replacement and idempotency-receipt lookup.
- **R8A-06 Identity/admin API:** actor/tenant/role/session projection, scoped credential issue/rotate/revoke and policy-decision evidence.
- **R8A-07 Stable query API:** bounded deterministic search/pagination and consistent revision/cursor semantics.
- **R8A-08 Extended operator services:** work graphs, execution hosts, workspaces, artifacts, budgets, reconciliation, recovery, webhooks and why/explainability.
- **R8A-09 Safe modes:** pause, drain, maintenance-read-only, disconnected-recovery and provider quarantine with audited transitions.

## Epic R8B — complete TypeScript SDK

- **R8B-01 TypeScript protocol generation:** branded domain IDs, discriminated wire unions, runtime validators, codecs and low-level clients generated without handwritten duplicate types.
- **R8B-02 Runtime-neutral `@automonique/sdk` client:** transport abstraction, negotiation, typed services, errors, `AbortSignal`, action receipts and redacted logging.
- **R8B-03 Node/Bun SDK transport:** local Unix socket, remote HTTPS/event transport, peer/server auth projection and strict no-fallback behavior.
- **R8B-04 Browser SDK transport:** HTTP/WebSocket/event transport, injected auth and bundle isolation from Node/server dependencies.
- **R8B-05 SDK service coverage:** complete machine-readable manifest for every service in `typescript-sdk.md`.
- **R8B-06 SDK attachment and control APIs:** `AsyncIterable` streams, multiplexed observers, resync, detach, controller leases, follow-up/steer/answer/cancel and authoritative reducers.
- **R8B-07 `@automonique/sdk/provider`:** out-of-process host protocol, bounded adapter helpers, capability/approval/reconciliation contract and sandbox integration.
- **R8B-08 `@automonique/sdk/testing`:** fake server/transports, deterministic clock/IDs, builders, redacted record/replay and fault injection.
- **R8B-09 SDK conformance/compatibility:** semantic cross-transport suite, complete API coverage manifest, current/previous release matrix, supported `@legacy` forwarding imports and provider adapter harness.
- **R8B-10 SDK documentation/release:** generated reference, compiling examples, changelog/migrations, deterministic packages, provenance and schema/protocol metadata.

## Epic R8C — SDK-only dashboard

- **R8C-01 Dashboard SDK migration:** replace handwritten fetch/WebSocket calls and wire types; prohibit private dashboard-only endpoints.
- **R8C-02 Operations and why views:** generations, hosts, work graphs, workspaces, artifacts, budgets, policies, recovery and reconciliation.
- **R8C-03 Static browser release:** embed or checksum the SDK-backed build against its operator-protocol/schema digest.

## Epic R8D — Automonique TUI

- **R8D-01 TUI foundation:** `automonique tui` subcommand plus `legacy-tui` forwarding entry point, Unix-socket client, reducer, terminal lifecycle guard, responsive layout, keymap and help.
- **R8D-02 TUI overview and navigation:** service health, requests, approvals, runs, providers, reloads, failures and settings views.
- **R8D-03 TUI command palette and composer:** schema-driven forms, free-form durable intake and explicit follow-up/session binding.
- **R8D-04 TUI approval flows:** separate work/provider approval views, exact revision/item preview, approve/reject and conflict recovery.
- **R8D-05 Session attachment protocol:** authorized attachable-session discovery, fan-out observer handles, attach/detach lifecycle and retained-session replay.
- **R8D-06 N-pane agent cockpit:** dynamic tiling/tabs/focus, searchable attach picker, independent reducers/cursors, preview coalescing, unread/alert aggregation and local layout restore.
- **R8D-07 Interactive control arbitration:** durable renewable controller leases plus capability-gated follow-up/steer/answer/cancel with revision conflicts.
- **R8D-08 TUI generation operations:** doctor, reload, rollback, phase timeline, compatibility failures, pane reattachment and pending-action reconciliation.
- **R8D-09 TUI work/artifact/why/budget views:** graph navigation, reviewed artifact actions, route/policy evidence and scheduler pressure.
- **R8D-10 the `automonique` CLI operations:** status, pause, resume, runs, cancel, reload, rollback, audit and TUI launcher over shared contracts, with a tested `legacyctl` forwarding entry point.
- **R8D-11 TUI accessibility and export:** narrow/monochrome/high-contrast modes, copyable content and bounded redacted JSON export.
- **R8D-12 Shell separation:** status and capability-gated launcher only; no general shell bytes or file-transfer paths in the TUI protocol.
- **R8D-13 Operator-client verification:** multi-attachment reducers, N-pane golden screens, controller contention, terminal restoration and reload/disconnect faults.

## Epic R8E — operator-client canaries

- **R8E-01 Read-only client canary:** ship SDK/dashboard/TUI observation first, then enable each mutation family behind server capabilities.
- **R8E-02 Mixed-version canary:** current/previous clients through reload, cursor expiry, policy changes and ambiguous actions.
- **R8E-03 Cross-tenant and load canary:** noisy N-pane sessions, large artifacts, pagination churn and tenant-isolation probes.
- **R8E-04 Optional shell canary:** status/attach discovery only after separate authorization and isolation verification.

## Epic R8F — optional Teams and Discord connectors

- **R8F-01 Connector SDK package:** target `@automonique/sdk/connector`, temporary `@legacy` export, scoped credentials, source keys, subscriptions, receipts, artifacts and fake server.
- **R8F-02 Connector registration/admin:** installation, manifest digest, tenant binding, actor mapping, credential rotation, permission/intents and health APIs.
- **R8F-03 Teams app skeleton:** current Microsoft Teams SDK TypeScript service, verified activity endpoint, reproducible development/staging/production manifests and package checks.
- **R8F-04 Teams conversation mapping:** personal, group, channel mention, reply/edit/delete and durable Activity ID deduplication.
- **R8F-05 Teams Adaptive Cards:** clarification, exact-revision work/provider approval, progress and terminal renderers with opaque action tokens.
- **R8F-06 Teams Graph/RSC profiles:** typed least-privilege user/app Graph tools, RSC consent evidence, mention-only default and revoked-consent behavior.
- **R8F-07 Teams artifacts/proactive targets:** scoped download/upload, artifact grants, conversation references, notification policy and publication receipts.
- **R8F-08 Discord HTTP Interactions:** signature/PING verification, canonical commands, defer/edit/follow-up behavior and durable interaction deduplication.
- **R8F-09 Discord components/modals:** exact-revision action tokens, ephemeral sensitive responses, explicit allowed mentions and actor/tenant reauthorization.
- **R8F-10 Discord Gateway worker:** optional fenced session/resume cursor for DMs/mentions, minimal intents and `MESSAGE_CONTENT` disabled by default.
- **R8F-11 Discord artifacts/rate limits:** attachment grants, channel permission checks, observed bucket scheduling and `Retry-After` handling.
- **R8F-12 Notification-only destinations:** Teams Workflow and Discord incoming webhooks as typed scoped outbox targets with rotation/reconciliation.
- **R8F-13 Connector sovereignty disclosure:** measured egress, install-time data boundary, retention/export/delete behavior and air-gap incompatibility.
- **R8F-14 Connector conformance:** shared fake-platform suite plus Teams/Discord manifest, restart, revocation, ambiguity and cross-tenant tests.

## Epic R8G — channel connector canaries

- **R8G-01 Notification-only canary:** one reviewed Teams Workflow and Discord webhook target with no intake authority.
- **R8G-02 Personal/DM command canary:** no tools, attachments or proactive sends; prove installation/actor mapping and deduplication.
- **R8G-03 Mention-only channel canary:** threaded replies, edit/delete handling and no all-message permission/intent.
- **R8G-04 Approval canary:** Cards/components resolve exact revisions once across connector and daemon reconnect.
- **R8G-05 Attachment/proactive canary:** artifact and destination grants, publication evidence and revocation.
- **R8G-06 Permission-family canaries:** Teams Graph/RSC and Discord Gateway/privileged intents graduate independently after admin review.
- **R8G-07 Failure rehearsal:** connector/daemon reload, uninstall/reinstall, credential rotation, invalid Gateway session, expired interactions and platform throttling.

## Epic R9 — privileged boundary

- **R9-01 Typed Rust deploy-broker request parser.**
- **R9-02 fd-relative revision/artifact/snapshot validation.**
- **R9-03 root lock, receipt and atomic deployment semantics.**
- **R9-04 installer, ownership checks and exact sudo policy.**
- **R9-05 adversarial filesystem and request tests.**
- **R9-06 independent security review and remediation.**
- **R9-07 Optional isolated shell service:** local-only, disabled by default, separate `shell_operator` role, dedicated unit/cgroup and no TUI byte proxy.
- **R9-08 Artifact-mediated file transfer:** upload/download grants, malware/archive checks, quotas, provenance and audit receipts instead of arbitrary host paths.
- **R9-09 Optional sandbox launcher:** if R0-14 requires privilege, implement a separate closed-schema namespace/routing launcher with prepared descriptors, no arbitrary argv and no deployment authority.
- **R9-10 Sandbox/egress privileged review:** fuzz parsers and independently review namespace setup, routing rules, cleanup, confused-deputy behavior and separation from the deploy broker.
- **R9-11 Strong-isolation provider contract:** define the same events/artifacts/credentials/cancellation/attestation boundary for a future microVM or remote executor; high-risk work remains rejected until a conformant implementation graduates.

## Epic R10 — production transition

- **R10-01 Automated immutable Rust release and rollback packaging.**
- **R10-02 Runner canary with the TypeScript control plane.**
- **R10-03 Rust shadow control-plane comparison reports.**
- **R10-04 Allowlisted Slack/Telegram ownership.**
- **R10-05 Production low-risk active-work reload.**
- **R10-06 Three-concurrent-job reload and rollback exercise.**
- **R10-07 Rust foreground runtime becomes the default; supervisor packaging remains optional.**
- **R10-08 Soak review and compatibility-retention decision.**
- **R10-09 Remove legacy backend paths only after the rollback window; remove legacy names/state only through the separate telemetry and deprecation gate.**
- **R10-10 Per-provider native canaries:** graduate Jcode, Claude, Codex and opencode independently through resume, approval, cancel, reconnect and reload gates.
- **R10-11 Provider upgrade rehearsal:** prove binary/schema upgrade and rollback without losing active sessions or silently changing capabilities.
- **R10-12 Backup/restore automation:** consistent recovery sets, encryption/key checks, off-host retention, clean-host restore and RPO/RTO evidence.
- **R10-13 Governance drill:** tenant export, retention expiry, deletion/tombstone/legal hold and raw-record minimization.
- **R10-14 Safe-mode/runbook drill:** pause, drain, maintenance-read-only, disconnected recovery, provider quarantine and alerts with named ownership.
- **R10-15 Reconciliation closure:** preview/apply/full audit plus zero-diff post-check against Slack, GitHub, local state and action receipts.
- **R10-16 Parity closure:** machine-readable ledger has evidence for every preserve/replace/isolate/retire decision and no unexplained item.
- **R10-17 Cost/observability acceptance:** end-to-end traces, SLO alerts, budget/anomaly telemetry and why/explainability records under production-like load.
- **R10-18 Channel connector acceptance:** enabled Teams/Discord installations pass `channel-integrations.md`, expose current data boundaries and have independent rollback/disable controls.
- **R10-19 Automonique runtime cutover:** canonical and legacy entry points reach one service/state owner, and copied-install upgrade/rollback passes.
- **R10-20 Sandbox acceptance:** required profiles pass production-kernel escape/resource/egress/cleanup tests, provider modes publish exact profile support, runbooks/alerts are exercised and unsupported stronger-isolation work fails closed.
- **R10-21 Core platform acceptance:** context/queue/compression/checkpoints, memory/FTS, skills/learning, tools/MCP, profiles, goals/automations/triggers and their complete SDK services pass reload, policy, redaction and rollback gates.

## Epic R11 — public protocols and extension ecosystem

- **R11-01 Automonique Runs API:** native HTTP runs/events/stop/approval/session/job resources over canonical receipts and cursors.
- **R11-02 OpenAI Chat Completions adapter:** streaming, model selection, tools and namespaced progress events with honest compatibility errors.
- **R11-03 OpenAI Responses adapter:** stored response IDs, `previous_response_id`, function items, retention and idempotency.
- **R11-04 ACP agent server:** IDE sessions, diffs, terminal/tool events, model selection, approvals and reload reconciliation.
- **R11-05 Scoped MCP server:** local stdio/Streamable HTTP tools/resources/prompts, OAuth/service identity and sampling/elicitation policy.
- **R11-06 A2A and relay adapters:** agent card/task mapping, authenticated WebSocket/HTTPS relay, command manifests, media and reconnect cursors.
- **R11-07 Local provider proxy:** loopback short-lived tokens, provider-terms guard, quota/billing identity and audited OpenAI compatibility.
- **R11-08 `@automonique/sdk/extension`:** manifests, host lifecycle, typed settings, tools/hooks/memory/context/media/secret-source adapters and test harness.
- **R11-09 `@automonique/sdk/ui`:** pure read models, design tokens, namespaced storage/actions and plugin conformance.
- **R11-10 Extension catalog/security:** signing, provenance/license/SBOM, review, staged enablement, revocation, quarantine and rollback.

## Epic R12 — complete client experience

- **R12-01 Shared composer semantics:** multiline/history, command/reference completion, queue editing, retry/undo/stop/compress and context meter across clients.
- **R12-02 TUI management expansion:** sessions/search, skills, memory, goals, automations, tools/MCP, profiles, connectors and checkpoint controls.
- **R12-03 TUI widgets and skins:** declarative/WASI dock API, accessible tokens, reload and zero-authority safety.
- **R12-04 Dashboard command center:** embedded chat/Kanban, learning graph, automation/webhook/MCP/tool/profile/model/extension management.
- **R12-05 ShellDeck desktop integration:** shared Rust protocol client crate, Linux/macOS packaging and signed updates in the owner-controlled ShellDeck repository; Windows is served by the dashboard/PWA until a build passes conformance. Tauri was evaluated and rejected.
- **R12-06 Desktop session UX:** multi-tab/window, drag/drop/paste, artifact preview, timeline/search, queues and native notifications.
- **R12-07 Desktop project/Git UX:** multi-folder projects, file browser, worktrees, diff/review/checkpoint, stage/commit/push/PR proposal.
- **R12-08 Desktop terminals and agent panes:** separately authorized persistent shells, N-pane agents and add-selection-to-context.
- **R12-09 Desktop UI plugins/themes:** namespaced signed plugins, command palette, keybinds, localization and sanitized VS Code theme import.
- **R12-10 PWA/Termux/mobile clients:** responsive offline-aware client, Android Termux matrix and later native client contracts.
- **R12-11 Setup/lifecycle CLI:** section wizards, doctor/fix separation, status/logs, completions, signed update/rollback and data-preserving uninstall.
- **R12-12 Agent importers:** dry-run legacy/OpenClaw/other-agent persona, memory, skills, rules, settings, channel and allowlisted-secret import.
- **R12-13 Mascot/pet packs:** signed presentation-only Monique assets/animations with accessibility and no security-state impersonation.

## Epic R13 — complete connector catalog

- **R13-01 Generic connector generator/conformance:** manifest, fake platform, directory/pairing, media, commands/components and independent rollout flags.
- **R13-02 Email and SMS:** thread/message/delivery identity, sender-domain/opt-out/compliance, attachments and approved outbound actions.
- **R13-03 WhatsApp:** Business Cloud adapter first; isolated device/QR compatibility adapter with account-risk disclosure.
- **R13-04 Signal/SimpleX/Matrix:** identity/key custody, group/reply/edit/media semantics and local bridge lifecycle.
- **R13-05 iMessage bridge:** BlueBubbles/Photon-style trusted macOS host, stable identity, media and availability diagnostics.
- **R13-06 Mattermost/Google Chat/IRC:** independently packaged team-chat connectors with exact thread/user/channel mapping.
- **R13-07 LINE/DingTalk/Feishu/WeCom:** official enterprise APIs, consent scopes, commands/cards/files and revocation.
- **R13-08 Weixin/QQ/Yuanbao:** official APIs where available; experimental paths remain quarantined and visibly unsupported for privilege.
- **R13-09 Home Assistant/ntfy/devices:** event subscriptions, entity/target allowlists and notification-only modes.
- **R13-10 Open WebUI/API/A2A relays:** connector-side client packages over public protocols.
- **R13-11 Voice/meeting media:** Discord voice and Teams meeting/transcript workers with participant consent and retention.
- **R13-12 Cross-platform continuity:** actor pairing, home target, channel directory, session binding, reactions/stickers and rich-media rules.
- **R13-13 Per-connector canaries:** notification, DM, mention, attachments, approvals, proactive, broad subscription/media and uninstall/revocation drills.

## Epic R14 — models, media and execution providers

- **R14-01 Provider/model plugin catalog:** custom endpoints, aliases, modalities, region/data/pricing/capability metadata and conformance.
- **R14-02 Routing and fallback engine:** capability/locality/cost/latency/health policy, explicit decisions and auxiliary fallback graphs.
- **R14-03 Credential pools:** account/billing/tenant-bound rotation, quota health, thread safety, revocation and no cross-boundary failover.
- **R14-04 Mixture of Agents:** reference slots, aggregator, fanout/cadence, privacy redaction, budgets and non-recursive presets.
- **R14-05 Vision and document media:** clipboard/file images, OCR/extraction, artifact derivatives and provider capability tests.
- **R14-06 STT/TTS and voice mode:** adapter registries, streaming/platform delivery, local/cloud disclosure and spoken-approval prohibition.
- **R14-07 Wake word:** local hotword worker, explicit capture indication and no authority escalation.
- **R14-08 Image/video generation:** provider plugins, long-running progress, cost/content policy, provenance and artifact publication.
- **R14-09 Web/search registry:** grounded citations, provider routing, egress receipts and local/sovereign options.
- **R14-10 Browser automation:** local CDP/Playwright and remote providers, isolated profiles, downloads/artifacts and credential injection.
- **R14-11 Computer use:** accessibility/screenshot driver, explicit display/session, stale references, event audit and disposable environments.
- **R14-12 LSP manager:** language-server installation/health, workspace sandbox, diagnostics/code actions and provider-native coexistence.
- **R14-13 Rootless OCI executor:** image provenance, immutable mounts, attestation and no root daemon socket.
- **R14-14 SSH/HPC executors:** host attestation, transfer/cursors plus Apptainer/Singularity and optional Slurm lifecycle.
- **R14-15 MicroVM/Kubernetes executors:** strong-isolation and policy-existing cluster Jobs with complete cleanup/cost evidence.
- **R14-16 Modal/Daytona/Vercel adapters:** provider-specific identity, persistence, artifact/event/approval and data/billing contracts.
- **R14-17 Hibernation/scale-to-zero:** environment snapshots, wake fencing, cost state and distinction from running processes.
- **R14-18 Sovereign tool gateway:** approved search/browser/media services behind Automonique quotas, identity and receipts.

## Epic R15 — research, evaluation and ecosystem polish

- **R15-01 Batch runner:** bounded parallel datasets, per-record profile/tools/workspace/media, checkpoint/resume and structured output.
- **R15-02 Trajectory schema/export:** normalized public messages/tools/events/artifacts/costs with hidden-reasoning/secret exclusion.
- **R15-03 Trajectory compression:** source hashes, compressor provenance, deterministic merge and reversible lineage.
- **R15-04 Evaluation harness:** assertions, quality filters, tool success, reasoning-availability metadata, statistics and regression dashboards.
- **R15-05 Training-data governance:** consent, tenant exclusion, redaction, license, retention and synthetic/public defaults.
- **R15-06 Profile distributions/marketplace:** signed agent/skill/extension/theme packages, update channels, review and revocation.
- **R15-07 Localization/accessibility:** locale catalogs, screen-reader/keyboard/contrast/reduced-motion and terminal compatibility suites.
- **R15-08 Ecosystem capability review:** periodically survey agent-platform capabilities, add Automonique requirements to the neutral ledger and perform explicit no-copy/license review outside product documentation.

## Dependency spine

```text
R0 handoff proof + implementation harness + SH0–SH4 self-host foundation
  -> R1 protocol/identity/events
    -> R2 execution hosts/workspaces/artifacts
      -> R3 reload skeleton
        -> R4 durable core
          -> R5 scheduler/fleet/work graphs
          -> R6 transports/identity
            -> R7 behavior
              -> R8A operator/auth/events
                -> R8B TypeScript SDK
                  -> R8C dashboard
                  -> R8D TUI
                    -> R8E canaries
                -> R10 cutover

R7 core context/learning/tools/automation -> R10-21 core platform acceptance
R8B SDK + R10 core -> R11 public protocols/extensions -> R12 desktop/client ecosystem
R8B connector SDK -> R13 connector families and independent canaries
R2 sandbox/executor contract + R7 routing -> R14 media/execution providers
R4 event/artifact schemas + R8B SDK -> R15 batch/evaluation/ecosystem tracks

R0-17..R0-22 harness foundation -> every implementation epic; each epic feeds failure and metric evidence back into the harness
R0-23..R0-40 self-host foundation -> candidate-driven implementation; SH4 independently verified before self-modification of bootstrap/security/promotion boundaries

R8B connector SDK -> R8F optional Teams/Discord connectors -> R8G independent channel canaries

R0 sandbox/provider-egress spikes -> R1 sandbox contract -> R2 sandbox/artifacts -> R9 brokers/security/optional shell/strong isolation -> R10 cutover
R0 recovery baseline -> R4 recovery schemas -> R10 restore/governance gates
```

R5 and R6 can proceed in parallel only after R4's identity, journal, receipt, lease and durable-inbox contracts are stable. R8C, R8D and R8F may proceed in parallel only after R8A and the corresponding R8B SDK services are stable. R8F/R8G are optional expansion paths and do not block core R10 cutover when no connector is enabled; Teams and Discord also graduate independently. The former rebrand epic (B0–B4) was dissolved; its naming/repository prerequisites for R8B/R8D are now R1-17 (compatibility registry) and R1-19 (canonical namespace gate), and its runtime cutover is R10-19. Required sandbox profiles and provider-control/tool separation block enabled provider cutover; brokered egress, extensions, shell and strong isolation graduate independently. R9 can proceed after the R0 sandbox decision plus shared bounded types, workspace/artifact policy and release tooling exist.

## Definition of done for every ticket

- Contract and failure behavior documented.
- Tests cover success, malformed input, timeout/cancellation and restart where applicable.
- Structured logs and operational state are observable.
- No secret-bearing fixture or output is introduced.
- Adjacent-version compatibility impact is declared.
- Canonical/legacy naming impact is declared and forwarding aliases are tested when the ticket changes a public identity.
- Tenant/role, event/action receipt, workspace/artifact, retention and observability impacts are declared.
- A parity-ledger entry and recovery/runbook update are included when the ticket changes current behavior or operational state.
- Current TypeScript behavior remains available until the phase exit gate is met.
- The PR updates this plan when it changes an architectural decision.
- The commit/CI links a reproducible metrics manifest with work/run identity,
  required checks, configured review result and before/after baselines; missing
  or incomparable metrics state why.
- No test/assertion/fixture is deleted, skipped, ignored or broadly regenerated and no stub/lint allowance/unsafe widening is used merely to make a queue green without explicit ticket authority.
- Implementer, reviewer and fixer roles are recorded truthfully under the
  owner-configured policy; unresolved configured blocking findings prevent
  integration.
- A self-hosting ticket states stable/candidate/builder/promoter evidence
  ownership, candidate credential/data mode, source/build fingerprints and
  last-known-good rollback path.
