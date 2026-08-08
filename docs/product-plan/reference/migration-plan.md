# Migration plan
> **Superseded decision note:** the `GPL-3.0-or-later` licence recorded in this
> document was superseded. The binding licence boundary is product
> `Elastic-2.0` with `sdk/` and `integrations/` under `Apache-2.0` (checked-in
> `LICENSE-POLICY.md`). GPL statements below remain historical.

The rewrite uses a strangler approach. Production behavior remains owned by the existing daemon until each Rust boundary passes parity and failure tests. Avoid a branch that diverges for months; merge small compatibility increments continuously.

The [Automonique rebrand and repository migration](rebrand/README.md) is a coordinated program, not an implicit phase of the rewrite. Its identity decisions and additive aliases land before public SDK/TUI releases; its service/path cutover waits for runtime compatibility evidence; and public-repository launch has its own legal/security gate. None requires deleting the private recovery repository.

Implementation is driven through [Automonique's AI development harness](../requirements/ai-implementation-harness.md). Before broad code generation, the team freezes mechanical/security/state guidance, builds the minimal durable loop, trials three representative units and proves isolated authorship, two fresh-context adversarial reviews, bounded verification, commit attestations and restart/reload recovery. The harness accelerates the phases below; it does not change their exit gates or gain merge/deploy authority.

## Phase 0 — freeze contracts and prove reload primitives

### Work

- Inventory every current inbound event, durable table, external mutation, timer, agent event dialect, and operator command.
- Inventory every legacy identifier across services, paths, environment, protocols, packages and external platforms; classify each as durable, compatibility-only or presentation-only under ADR 006.
- Complete the machine-readable [feature-parity ledger](feature-parity.md), including Inklura tenant fencing, internal/client publication, companions, learned targets, audits, notifications, operational commands, deploy webhook and ignored-message behavior.
- Complete the neutral [external capability coverage ledger](../requirements/external-capability-ledger.md) with track, specification, owner, ticket, fixture and security/data-boundary classification for every row.
- Generate the executable development DAG from this plan, define porting/state/security/naming guides and baseline the commit metrics contract.
- Build the minimal `automonique-lab` orchestrator, Git/build brokers and TypeScript scenario client outside the unfinished production daemon.
- Trial one mechanical port, one durable-state unit and one provider/transport unit with an implementer, two independent reviewers and a fixer; correct the loop and rerun from identical bases.
- Inventory actual role/identity/tenant mappings, credential owners/rotation, artifact classes, workspace/dirty-tree behavior, scheduling limits, retention obligations and recovery dependencies.
- Capture a consistent baseline backup and prove restore on a clean disposable host before schema work begins.
- Record the installed binary version, native integration surface, protocol/schema version, capability probe, authentication mode, and fallback hierarchy for Jcode, Claude, Codex, and opencode.
- Maintain a checked-in provider compatibility matrix and sanitized transcripts for each supported native and fallback mode.
- Export sanitized fixtures for Slack, Telegram, Manage, Support, and all four agent backends.
- Capture fake/sanitized Teams Activity/Card and Discord Interaction/Gateway/component fixtures plus app-manifest/permission inventories; no tenant/guild credential enters the corpus.
- Convert current behavioral tests into language-neutral input/output fixtures where possible.
- Record the current 219-test baseline and tmux prototype contracts.
- Prototype systemd 255 generation handoff:
  - `Type=notify-reload` behavior;
  - `NotifyAccess=all` and `MAINPID` transfer;
  - old/new process overlap;
  - failed candidate recovery;
  - transient attempt- and session-host unit survival.
- Decide whether self-handoff or a credential-free stable launcher owns generations.
- Decide and record the compatibility-only `legacy-shell` boundary; the agent TUI is never a general shell.
- Spike the production kernel/systemd sandbox matrix: Landlock ABI, cgroup v2 controllers, user/mount/PID/network namespaces, systemd hardening properties, rootless routing and whether a separate typed sandbox launcher is required.
- Prove provider-control traffic can be separated from model-directed tool/MCP traffic for each native provider; mark incompatible versions/profiles ineligible.

### Exit gate

A toy old generation can start a persistent child unit, hand service readiness to a new binary, drain, roll back, and survive a deliberately failed candidate without losing the child. The development harness also passes its three trial units, reloads without losing agent/build/evidence state and emits reproducible secret-free commit attestations.

## Phase 0S — trusted seed and self-hosting foundation

### Work

- Create the private `bext-stack/automonique` staging repository through the rebrand B0/B1 gates; add GPL/provenance/governance files before importing product source.
- Define SH0–SH6 policy, `bootstrap.toml`/schema, trusted builder/signer public identities, source/environment/build fingerprints and corresponding-source rules.
- Implement the minimal `automonique-bootstrap` inspect/plan/apply/verify/resume/recovery path with no provider or production credentials.
- Add `scripts/automonique-dev` plus the finite Bun `tools/bootstrap-seed` coordinator so one reviewed `start` command can create SH0 before the Rust bootstrap/lab exists.
- Check in the finite `seed-program.yaml`, seed policy/guides/scenarios and explicit Claude/Codex/opencode/Jcode probes; default to one worker and no automatic Git commit/push.
- Split stable development and digest-named candidate state, sockets, service identities, credential audiences, workspaces, artifacts, leases and outboxes.
- Add source-state snapshot/revalidation, build deduplication, superseded-result handling, immutable candidate publication and smoke verification.
- Implement the candidate lifecycle/evidence journal, self-development sessions and typed selfdev/background/evidence/promotion-proposal actions.
- Run candidate fixture/replay/shadow modes; reserve canary/development-integration modes until identity/connector/Git broker gates exist.
- Make the candidate perform a bounded work unit, self-build and development-generation reload while stable observes and can restore the previous candidate.
- Add an independently authenticated clean builder and reproducibility/normalized-comparison policy with provenance, SBOM and dependency/license evidence.
- Generate SDK plus TUI/dashboard read models for bootstrap, candidates, builds, comparisons and promotion plans.

### Exit gate

A clean host verifies the bootstrap manifest and creates a recoverable SH0 lab. SH0 builds an isolated candidate from an immutable source fingerprint; the candidate completes the self-host fixture, rebuilds and reloads without losing work; injected candidate failure returns to SH0; an independent builder produces authenticated comparison evidence; and the candidate has no route to stable/production credentials or promotion state.

The first-run launcher must also prove plan-before-apply, exact confirmation, detach/resume/reboot recovery and one-way handoff. Repeating `start` after handoff attaches to the existing Rust lab rather than launching another seed coordinator.

Broad autonomous implementation may begin after SH0 plus isolated build/review loops work. SH4 independent verification must pass before `automonique-lab` is trusted to develop its own security, promotion or bootstrap boundary.

## Phase 1 — Rust workspace and contracts

### Work

- Create the Cargo workspace and CI jobs for format, clippy, unit tests, dependency audit, license checks, and release builds.
- Implement shared IDs, bounded strings, enums, timestamps, protocol framing, manifest parsing, checksum validation, and structured errors.
- Implement the accepted identity/authorization, domain-event/action, workspace, artifact and execution-host contracts as shared schemas before feature code.
- Implement the accepted sandbox profile, policy-compilation, attestation, violation and resource-budget contracts before provider feature code.
- Implement shared contracts for context manifests/references/queues/compression, typed memory/FTS, skills/learning, profiles, tools/MCP/extensions/hooks, automations/goals/triggers, public protocol mappings and model/media/executor adapters before freezing SDK schemas.
- Implement the shared provider capability model, session/turn/item identities, approval requests, raw-event envelope, and authoritative normalized events defined in `agent-integrations.md`.
- Check generated JSON schemas into the release.
- Emit complete operator HTTP, event-channel, local protocol, command-registry and provider-adapter service descriptions from the Rust source of truth.
- Emit the external connector protocol: installation/actor resolution, durable input/source keys, action tokens/receipts, render intents and artifact grants.
- Scaffold TypeScript protocol generation and require reproducible types, validators and low-level clients before handwritten consumers appear.
- Generate or capture upstream protocol schemas where available, pin them to tested binary ranges, and fail CI on an unexplained incompatible diff.
- Build `automoniquectl doctor` for local manifest, systemd, runtime-directory, SQLite, and kernel capability checks, plus a `legacyctl` forwarding entry point.
- Add golden compatibility tests callable from Bun and Rust.

### Exit gate

TypeScript and Rust exchange protocol fixtures byte-for-byte, reject the same invalid bounds, and validate the same release manifest.

## Phase 2 — independent Rust execution hosts

### Work

- Implement host/attempt specs, protected handoff and launch-time binary/credential revalidation.
- Start attempt-scoped and session-scoped hosts as distinct transient user service/cgroups.
- Implement the workspace registry, isolated worktree/snapshot provisioning, locks, dirty-source capture, artifact materialization and explicit promotion handoff.
- Implement stdout/stderr separation, UTF-8-safe framing, monotonic events, atomic status, heartbeat, timeout, cancellation, and spool retention.
- Port worker environment allowlisting and implement the layered sandbox plan: minimal mount/`/proc`/`/dev` view, Landlock defense in depth, seccomp syscall/address-family denial, cgroup/rlimit/storage budgets and complete descendant cleanup.
- Implement separate provider-control and nested tool/MCP execution boundaries. Add a network namespace plus DNS/private-range/redirect-safe egress broker for destination-aware grants; never represent seccomp as a destination allowlist.
- Implement sealed descriptor/systemd credential delivery by process class so nested tools inherit no provider/control-plane secrets.
- Implement sandbox attestation, violation/limit events, quarantine, cleanup reconciliation and SDK/operator projections.
- Build the optional minimal root-owned sandbox launcher only if the rootless spike proves it necessary; keep it separate from deployment privilege and prohibit arbitrary argv or root container-engine sockets.
- Promote the host from a process wrapper to the durable provider-session proxy described in `agent-integrations.md`, including idle TTL and hibernation/reboot classification.
- Implement native adapters in this order so each one hardens the common contract:
  1. Jcode ACP through an explicit daemon socket, including daemon health/reload, session capture, auth/model/usage telemetry, security-context attestation or per-context daemon isolation, and NDJSON fallback;
  2. Claude bidirectional stream-JSON, including replayed user messages, partial assistant events, hooks/subagent events, permission requests, resume/fork, and one-shot fallback;
  3. Codex App Server over session-host stdio, including generated schemas, thread/turn/item state, steer/interrupt, approvals, models/account/rate-limit telemetry, and attempt-scoped `codex exec --json` fallback;
  4. opencode through an authenticated session-host HTTP server and SSE stream, including session reconciliation, status/diff/permissions, async prompt/abort, provider/MCP/agent inventory, attempt-scoped ACP fallback, and JSON-run fallback.
- Persist provider instance/session/turn bindings and the last authoritative cursor so a daemon generation can reconnect without inventing completion.
- Preserve bounded raw provider records alongside normalized events for diagnostics and forward compatibility.
- Implement `automoniquectl runs/attach/cancel` with legacy forwarding commands.
- Keep a compatibility renderer so operators retain a readable live view.

### Integration

The existing TypeScript daemon launches and consumes the Rust runner behind canonical `AUTOMONIQUE_RUNNER=rust`; `LEGACY_RUNNER` is accepted only as a recorded migration alias. The old tmux path remains an immediate fallback. No Slack/Telegram behavior changes yet.

### Exit gate

All existing spool/tmux protocol tests pass against the Rust runner, every native adapter passes the conformance suite in `agent-integrations.md`, and the required `observe`/`workspace-offline` sandbox profiles pass filesystem, egress, credential, resource, cleanup and production-kernel tests. Chaos tests cover daemon death, runner/provider death, approval waits, cancellation descendants, 64-KiB prompts, split UTF-8, partial terminal events, disk pressure, schema drift, binary upgrades, native-to-fallback transitions, and reconnect from a durable offset.

## Phase 3 — Rust daemon skeleton with real generation reload

### Work

- Implement generation registration, heartbeats, the systemd/launcher-owned stable admin socket, reload epochs, readiness, lease primitives, controller fencing and systemd notification.
- Serve only health/admin endpoints initially.
- Adopt Rust execution-host units, provider process bindings, provider sessions/turns, pending provider approvals, workspaces and event cursors without performing business effects.
- Implement immutable release build/select/rollback tooling.
- Run repeated N -> N+1 -> N rollbacks while execution hosts remain active.

### Exit gate

The Rust skeleton reloads and rolls back under active execution hosts for an extended soak with zero event gaps. This ensures reload is structural, not added after the application port.

## Phase 4 — durable store and lifecycle core

### Work

- Implement expand-only migrations for generations, reload epochs, leases, identities/tenants/roles, inbox, work items, attempts, execution hosts, locks, approvals, provider sessions/turns/raw records, workspaces, artifacts, context manifests/references/compression/input queues, typed memory/FTS, skills/bundles/learning/curator, profiles/model accounts, tools/MCP/extensions/hooks, automations/goals/boards/triggers, public-protocol mappings, settings revisions, transport offsets, connector installations/conversations/interactions/cursors, notifications, domain events, action receipts, audit events and outbox.
- Import and preserve current legacy tables and IDs.
- Implement repositories and transaction-level state transitions.
- Implement ticket registry, approval records, session mapping, cancellation, action receipts, global event subscriptions, retention classes and crash adoption.
- Replace the current “running becomes error on boot” rule with runner reconciliation.
- Add migration/rollback compatibility declarations to manifests.

### Integration

Run Rust in shadow-read mode against a database copy and sanitized production snapshots. Do not allow two implementations to mutate the same business rows until lease semantics are active.

### Exit gate

Property tests prove valid state transitions, migrations preserve every current row, and N/N+1 can read/write the expanded schema concurrently.

## Phase 5 — scheduler, fleet, and external outboxes

### Work

- Port bounded concurrency and serialization by Slack thread, GitHub issue, and backend session.
- Add tenant/actor/provider admission, fair queueing, rate/token/cost budgets, reservations, anomaly alerts and provider circuit breakers.
- Add durable work graphs for dependencies, split tickets, subagents, retry lineage, cancellation propagation and partial completion.
- Add user-facing schedules, script-only/chained jobs, persistent goals/waits and Kanban board/dispatcher projections on the same scheduler and graph primitives.
- Add signed inbound trigger admission, declarative filters, sandbox transforms and direct no-model delivery with exact idempotency.
- Port Manage claims, heartbeat, cancellation watch, job logs, terminal reporting, and retry backoff.
- Move every terminal external effect behind the typed outbox.
- Add lease epochs to scheduler/reconciler writes.
- Reconcile old outbox rows into the new schema.

### Exit gate

Replay and fault-injection tests show no double-claim, stranded claimed job, lost terminal report, or concurrent use of one agent session across reload.

## Phase 6 — transports and approval gates

### Slack work

- Implement Socket Mode envelope acknowledgement and reconnect.
- Persist the event before routing.
- Port Web API calls, member/channel resolution, thread handling, reactions, approval actions, commands, and gate recovery.
- Preserve current status-reaction policy and GitHub durable-truth behavior.

### Telegram work

- Implement durable update ingestion, per-scope ordering, reply correlation, commands, approval buttons, and access control.
- Implement exclusive poller lease transfer.

### Rollout

- Start with shadow classification from sanitized/replayed inputs.
- Then route one allowlisted test channel/user through Rust.
- Keep TypeScript as fallback owner; never let both produce business effects for the same scope.

### Exit gate

Behavioral fixtures match, duplicate Slack connections do not duplicate work, and Telegram reload tests show no skipped/replayed user-visible action.

## Phase 7 — conversation, commands, and integrations

### Work

- Port the exact command registry before model-assisted routing.
- Port conversation state, deterministic routes, operational queries, site/access/support flows, memory, and prompt envelopes.
- Add the provider-independent context compiler, typed references, usage/compression lineage, durable queued input, capability-aware retry/undo/stop and per-turn checkpoints.
- Replace generic memory with typed user/workspace/team/task records, FTS session retrieval and governed external-memory adapters.
- Add agentskills-compatible progressive skills, scoped catalogs/bundles, evidence-backed learning proposals and non-destructive curator.
- Add the canonical tool registry/toolsets/search, native MCP client/server, sandboxed workflow RPC, extension manifests/hook hosts, agent profiles, routing/pools/auxiliaries and secret-source adapters.
- Persist deterministic execution plans plus persona, command-registry and policy hashes so every route and fallback has an explainable “why.”
- Route provider classification/chat calls through the same capability-aware adapters, selecting an explicitly restricted no-tools profile rather than a separate untracked execution path.
- Preserve all untrusted-context labels, field limits, approval boundaries, and safe fallbacks.
- Port GitHub context/reporting and Support mail workflows through outboxes.
- Port every unresolved parity-ledger item: Inklura tenant fencing, internal-vs-client publication, companions/knowledge bases, learned targets, Slack live-feed/posting, browser notifications, site digest/oneshot/ops commands, deploy webhook, worker capabilities and audit/reconciliation commands.

### Exit gate

Every current conversation and security-hardening fixture passes. Shadow decisions on real sanitized traffic remain within an agreed mismatch threshold, with every mismatch reviewed before cutover.

## Phase 8A — operator, identity and event foundation

- Port authenticated REST/WebSocket endpoints to Axum.
- Implement one versioned operator domain API for snapshots, cursor-based subscriptions, command discovery, action previews and revision-bound idempotent mutations.
- Implement identity/session/role administration, stable cursor pagination/search, artifact grants, work-graph views, reconciliation previews/applies and “why” projections.
- Add generation, reload, execution-host adoption, workspace, artifact, budget, lease, outbox and domain-journal observability.
- Add reconnect from `last_event_id`, action receipts and signed outbound webhook delivery.

### Exit gate

The local and HTTP transports expose the same authorized contracts; snapshot-plus-cursor resync, policy denial, receipt reconciliation, pagination and redaction pass conformance tests.

## Phase 8B — TypeScript SDK

### Work

- Generate `@automonique/sdk` wire types, runtime validators and low-level clients from the release schemas, then implement the complete high-level service map in `typescript-sdk.md`.
- Add explicit Node/Bun Unix-socket, remote server and browser HTTP/WebSocket transports with capability negotiation and no cross-runtime dependency leakage.
- Add TypeScript session attachment, multiplexed events, controller leases, action receipts, resync and ambiguous-mutation reconciliation.
- Build `@automonique/sdk/provider` as an out-of-process adapter SPI with the same bounded capabilities, approvals, reconciliation and conformance contract as Rust providers.
- Build extension, UI, OpenAI and MCP SDK entry points plus complete services for context/queues/checkpoints, memory/skills/profiles, tools/MCP/extensions, automations/goals/triggers, models/media/executors and public-protocol diagnostics.
- Ship `@automonique/sdk/testing` with fake transports/server, deterministic clocks, fixture builders, record/replay and fault injection.
- Ship `@automonique/sdk/connector` with scoped installation/identity, intake, render, action-token, artifact and connector-conformance helpers.
- Generate tested `@legacy/sdk*` forwarding packages for the deprecation window; do not maintain a second implementation.

### Exit gate

Node/Bun and browser suites exercise every authorized service; generated output is reproducible, current/previous compatibility passes and no stable capability requires private types/routes.

## Phase 8C — dashboard parity

### Work

- Migrate the existing TypeScript dashboard and remaining TypeScript compatibility integrations to the SDK; delete their private HTTP/event types and handwritten route calls.
- Add work graph, artifacts, budgets, policy/why, reconciliation, recovery freshness and provider quarantine views.
- Add embedded chat/command center, context/compression, queue/checkpoint, skills/learning, memory graph, goals/automations, webhook/MCP/tool/profile/model/extension/connector and evaluation views.
- Keep the current browser layout initially, then improve it only after semantic parity.

### Exit gate

The dashboard uses the public SDK exclusively and every dashboard action has the same authorization, receipt and conflict behavior as local clients.

## Phase 8D — Automonique TUI

### Work

- Build `automonique-tui` as a first-class local Unix-socket client with overview, requests, approvals, runs, providers, reloads, failures, settings/health and command-palette views; ship `legacy-tui` as a forwarding compatibility entry point.
- Add authorized attach/detach to any active or reconcilable session, including sessions created outside the TUI, without coupling attachment to runner lifetime.
- Build the dynamic N-pane agent cockpit with multiplexed subscriptions, independent cursors, per-pane backpressure, tiling/tabs/focus and local layout restoration.
- Add controller leases for interactive steering/provider input plus request composition, explicit follow-up/session selection, provider permission responses, cancel and reload/rollback flows without bypassing existing approval policy.
- Add work graph, artifact review, budgets and “why” views; keep `automonique-shell` a separate optional local subsystem with only a declared `legacy-shell` forwarding alias.
- Add shared composer/history/reference completion, queue/retry/undo/compress/checkpoint controls plus sessions/search, skills, memory, goals, automations, tools/MCP, profiles, connectors, skins and sandboxed widget views.
- Make the TUI reconcile unknown mutation outcomes and invalidate stale confirmations after a revision change.
- Embed versioned static assets into the release or ship checksummed assets beside it.

### Exit gate

A TUI attached to N simultaneous cross-provider sessions can detach and reattach individual panes without affecting work, survives repeated reloads, converges every pane on a fresh snapshot, preserves at most one controller per session, never repeats an unknown mutation, and cannot execute an action from a stale confirmation.

## Phase 8E — operator-client canaries

### Work

- Ship SDK, dashboard and TUI read-only first; enable mutation families independently by server capability and role.
- Run mixed current/previous client versions through reload, cursor expiry, authorization changes, action ambiguity, large artifact and noisy N-pane scenarios.
- Canary the isolated shell/status bridge separately; it is not a prerequisite for ordinary TUI operation.

### Exit gate

All operator clients pass the same semantic conformance matrix and production canaries show no private route, duplicate mutation, cross-tenant disclosure or stale-control action.

## Phase 8F — Teams and Discord connector applications

This phase may proceed after the required R8A/R8B connector services stabilize, but it is an optional product expansion rather than a prerequisite for the core Rust cutover. Only installations actually enabled in a deployment enter that deployment's reload and acceptance gates.

### Work

- Build the Teams SDK TypeScript connector, reproducible app manifests, Entra/bot registration projection, mention/personal/group routing and Adaptive Card action renderer.
- Add optional Graph/RSC capability families behind explicit installation consent and typed tools; mention-only mode remains the default.
- Build the Discord HTTP Interactions connector with request-signature verification, commands, components/modals, deferred/edit/follow-up responses and explicit allowed mentions.
- Add an optional fenced Discord Gateway worker for DM/mention intake with minimal intents, durable resume state and `MESSAGE_CONTENT` disabled by default.
- Implement Teams Workflow and Discord incoming-webhook notification destinations through the typed outbox.
- Add connector installation/credential rotation, artifact transfer, proactive-target and reconciliation operations.
- Publish the platform data-boundary statement in install/admin views.

### Exit gate

Fake-platform suites prove exact tenant/actor mapping, one durable input per source event, revision-bound cards/components, artifact isolation, receipt reconciliation and connector restart. Reproducible app packages request only reviewed permissions/intents and contain no secrets.

## Phase 8G — channel connector canaries

Teams and Discord graduate independently after the core control plane is ready. A failed or deferred channel canary disables that connector; it does not roll back an otherwise accepted core daemon.

### Work

- Canary Teams and Discord independently in notification-only, personal/DM command, mention-only channel and approval modes.
- Enable attachments, proactive sends and optional Graph/RSC/Gateway permission families one at a time after administrator review.
- Run connector plus `automoniqued` reload, token/certificate rotation, uninstall/reinstall, revoked consent, rate-limit and expired-interaction drills.
- Compare measured platform traffic/retention with the published sovereignty boundary.

### Exit gate

Each enabled channel passes its connector exit gate in `channel-integrations.md`; no canary exposes another tenant, silently broadens permissions, loses an accepted input or repeats an external action.

## Phase 8H — public protocols and extension ecosystem

### Work

- Graduate the native Runs API, OpenAI Chat Completions/Responses, ACP host, scoped MCP server, optional A2A/relay and loopback provider proxy over canonical domain services.
- Ship extension/UI/OpenAI/MCP SDK packages, manifest/catalog tooling, signing/provenance, typed hooks and conformance/quarantine flows.
- Verify every compatibility protocol maps identity, session, input, tool, approval, event and effect to one durable Automonique coordinate.

### Exit gate

Current/previous protocol clients survive reload, unsupported semantics fail honestly, no adapter creates alternate state/authority, and extension quarantine cannot stop the core daemon.

## Phase 8I — desktop and cross-platform clients

### Work

- Build the Tauri desktop application, remote OIDC transport, multi-session chat, project/Git/artifact/terminal/agent panes and complete settings/management surfaces.
- Add signed UI plugins, themes, keybindings, localization, accessibility, native notifications, quick entry and presentation-only mascot packs.
- Add PWA, Termux and future mobile-client capability matrices plus setup/doctor/update/uninstall/import flows.

### Exit gate

Linux/macOS/Windows desktop packages and enabled portable clients pass shared SDK semantics, signing/update, accessibility, reconnect and no-direct-authority tests.

## Phase 8J — connector catalog

### Work

- Use the connector generator for email/SMS, WhatsApp, Signal/SimpleX/Matrix, iMessage bridge, Mattermost/Google Chat/IRC, LINE/DingTalk/Feishu/WeCom, Weixin/QQ/Yuanbao, Home Assistant/ntfy and API/A2A relays.
- Add directory/pairing/home-target, cross-platform continuity, reactions/stickers/rich media and separately consented voice/meeting workers.
- Graduate every connector from notification-only through broader modes independently.

### Exit gate

Only connectors that pass the catalog exit gate are listed as supported; optional failures never weaken or roll back another connector/core release.

## Phase 8K — model, media and execution providers

### Work

- Add model/provider plugins, aliases, routing/fallback, same-boundary credential pools, auxiliaries and optional MoA.
- Add vision/document, STT/TTS/voice/wake, image/video, web/search, browser, computer-use and LSP adapters with artifact/sandbox/data-boundary evidence.
- Graduate rootless OCI, SSH, HPC, microVM, Kubernetes, Modal, Daytona and Vercel execution providers plus hibernation/scale-to-zero and optional sovereign tool gateway.

### Exit gate

Every adapter publishes exact capability, cost, credential, data, artifact and isolation evidence; rotation/fallback never crosses policy; remote environments pass lifecycle/cleanup/reload conformance.

## Phase 8L — batch, evaluation and ecosystem tracks

### Work

- Add resumable batch runs, redacted trajectory export/compression, evaluation assertions/statistics and training-data consent/licensing controls.
- Add profile distributions and reviewed catalogs for skills/extensions/themes while keeping source/revocation evidence.
- Periodically update the neutral capability ledger through external ecosystem review without product-comparison names in public planning documents.

### Exit gate

Research exports are reproducible, consented and secret/hidden-reasoning safe; marketplace artifacts are signed/revocable; optional tracks remain independently disableable.

## Phase 9 — privileged broker and sandbox consolidation

### Work

- Rewrite the root Bext broker with strict typed input and fd-relative filesystem operations.
- Install a new exact sudo rule and validate ownership/mode.
- Consolidate Landlock/seccomp implementation into the runner.
- Implement the optional `automonique-shell` service, artifact-mediated file transfer and separate `shell_operator` authorization only if the parity ledger keeps it; retain `legacy-shell` only as a declared forwarding alias.
- Perform adversarial review of symlink, ownership, argv, environment, socket-peer, revision, and race handling.
- Independently review any privileged sandbox launcher, egress host capability and stronger-isolation executor; deployment and sandbox privilege remain distinct schemas/binaries.

### Exit gate

Existing privileged-action and sandbox tests pass, plus negative tests and an independent security review.

## Phase 10 — production cutover and removal

### Work

- Run Rust as primary for progressively wider scopes.
- Keep TypeScript fallback releases until rollback confidence is established.
- Exercise real reload and rollback during active but low-risk jobs.
- Complete a clean-host restore drill, reconciliation dry-run/apply, retention/deletion/export exercise and safe-mode recovery rehearsal.
- Make Rust the systemd default after soak.
- Complete the additive Automonique service/path cutover with exactly one active daemon and prove canonical plus supported legacy aliases against the same state.
- Require the current stable lab to produce the final candidate through the SH4 cycle and attach independent rebuild/provenance, compatibility and recovery evidence to the production proposal.
- Archive the compatibility protocol and migration tooling.
- Publish/checksum the matching `@automonique/sdk*` packages and forwarding legacy packages, and retain the previous compatible SDK through the rollback window.
- Remove TypeScript backend paths only after the rollback window closes; retain browser assets as appropriate.
- Close the parity ledger with machine-verifiable evidence and no unexplained preserve/replacement gap.
- Close every core row of `external-capability-ledger.md`; optional/expansion/research rows retain named tickets, owners and independent graduation gates.

### Exit gate

All completion criteria in `README.md` pass in production-like and controlled production runs. No critical mismatch or reload failure remains open.

## Porting map

| Current area | Rust destination | Phase |
|---|---|---:|
| `tmux-exec.ts`, `legacy-run.sh`, spool modules | `automonique-runner` execution hosts | 2 |
| agent portions of `claude.ts` and backend-specific launch/parsing | `automonique-agents`, `automonique-runner` | 2/7 |
| `registry.ts`, `db.ts`, sessions/settings | `automonique-store`, `automonique-core`, `automonique-policy` | 4 |
| `queue.ts`, `fleet.ts`, `manage-sync.ts` | `automonique-core`, `automonique-fleet` | 5 |
| Slack lifecycle in `index.ts` | `automonique-transports`, `automonique-core` | 6 |
| `telegram.ts` | `automonique-transports` | 6 |
| commands/conversation/support/site/companion modules | `automonique-core`, packaged companion assets | 7 |
| reconciliation scripts and `legacy:audit` | typed `automonique-core` reconcilers plus `automoniquectl audit`; legacy commands forward during migration | 7/8A |
| `dashboard.ts`, `term.ts`, `runs.ts` | `automonique-web`, SDK, `automonique-tui`, `automoniquectl` | 8A–8E |
| new Microsoft Teams app | Teams SDK connector + generated SDK connector package | 8F–8G |
| new Discord app | HTTP Interactions connector, optional Gateway and webhook outbox | 8F–8G |
| context, memory, skills, tools and schedules beyond current parity | canonical Rust services plus generated SDK surfaces | 4–8D |
| ACP/OpenAI/MCP/A2A/relay and extension ecosystem | compatibility protocol crates and sandboxed extension hosts | 8H |
| native desktop/PWA/portable clients | Tauri/TypeScript SDK clients | 8I |
| broader messaging/device catalog | independently deployed TypeScript connector packages | 8J |
| model/media/browser/remote execution adapters | Rust or out-of-process capability SPIs | 8K |
| batch/evaluation/trajectory and package distributions | isolated research/catalog services | 8L |
| implementation harness, bootstrap and self-hosting | `automonique-bootstrap`, `automonique-dev-protocol`, `automonique-lab`, independent builder and development SDK | 0/0S |
| interactive shells/file transfer | optional isolated `automonique-shell`, artifact APIs; `legacy-shell` is a migration alias only | 9 |
| sandbox C and privileged broker Python | runner/broker crates | 9 |
