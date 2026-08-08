# Automonique core rewrite (legacy compatibility runtime)

> **Reference material, not the authoritative index.** The authoritative
> product-plan index and decision-precedence order live in the checked-in
> `docs/product-plan/README.md`. This document is the historical corpus index
> from the original planning tree; where it disagrees with the checked-in
> plan, the checked-in plan wins.
>
> **Canonical surface note (2026-08-05):** the implemented repository ships a
> single `automonique` binary with subcommands (for example
> `automonique bootstrap`, `automonique status`, `automonique doctor`) from
> the single crate `crates/automonique`, supervised as `automonique.service`,
> `automonique-lab.service`, `automonique-agent@.service` and
> `automonique-run@.service`. The `automoniquectl` / `automoniqued` naming in
> this corpus describes a planned surface and is not implemented; do not build
> a parallel CLI or daemon binary without an accepted decision.
>
> **Licence note:** the corpus originally recorded `GPL-3.0-or-later`; the
> binding licence boundary is product `Elastic-2.0` with `sdk/` and
> `integrations/` under `Apache-2.0` (checked-in `LICENSE-POLICY.md`).

**Status:** proposed design and implementation plan

**Primary requirement:** reload Automonique onto a new binary without interrupting active jobs, losing accepted messages, duplicating side effects, or waiting for the system to become idle.

**Target host:** Linux with systemd 255, cgroup v2, SQLite WAL, Slack Socket Mode, Telegram long polling, optional public-HTTPS Teams/Discord connectors, and local agent CLIs.

This directory is the planning source of truth for replacing the legacy Bun/TypeScript backend with the Automonique Rust daemon. Automonique is the canonical product and repository identity; legacy names remain compatibility identifiers until the additive migration in the [Automonique rebrand and repository plan](rebrand/README.md) is complete. The browser UI may remain TypeScript and be served as immutable assets by the Rust service.

The rewrite is justified here by the desired runtime model, not by throughput or development cost. Automonique should behave like Jcode's graceful server reload: a new generation becomes ready, adopts durable work, and takes ownership before the old generation exits.

## Documents

1. [Automonique rebrand and repository plan](rebrand/README.md) defines the canonical identity, new-upstream strategy and additive compatibility migration. (Largely superseded by the clean-room repository; retained for legacy-daemon migration context.)
2. [Goals and invariants](../requirements/goals-and-invariants.md) defines what “reload in place” means and which guarantees are non-negotiable.
3. [Plan review findings](plan-review.md) records the gaps found after checking the installed agent integration surfaces.
4. [Target architecture](../requirements/target-architecture.md) defines the Rust processes, systemd ownership, component boundaries, and release layout.
5. [State and protocols](../requirements/state-and-protocols.md) defines the durable state model, generation leases, execution-host protocol, and compatibility rules.
6. [Sandbox management](../requirements/sandbox-management.md) defines profiles, policy compilation, filesystem/network/process/credential enforcement, attestations and stronger-isolation gates.
7. [Agent integrations](../requirements/agent-integrations.md) defines native Jcode, Claude Code, Codex and opencode session adapters and fallbacks.
8. [Context, memory and learning](../requirements/context-memory-and-learning.md) defines deterministic context, compression, queue controls, typed memory, skills, profiles and the governed learning loop.
9. [Tools, MCP, extensions and hooks](../requirements/tools-extensions-and-hooks.md) defines the canonical tool runtime, workflow RPC, MCP client/server, plugins, hooks and secret sources.
10. [Automations, goals and triggers](../requirements/automation-goals-and-triggers.md) defines user schedules, script-only jobs, persistent goals, Kanban projection and signed inbound triggers.
11. [Public agent protocols](../requirements/public-agent-protocols.md) defines ACP host, OpenAI-compatible, native Runs, MCP server, A2A, relay and local proxy surfaces.
12. [Client experience and surfaces](../requirements/client-experience-and-surfaces.md) defines shared interaction semantics, CLI/TUI/web/desktop clients, themes/widgets and cross-platform lifecycle.
13. [Models, media and execution backends](../requirements/models-media-and-execution.md) defines routing, credential pools, MoA, media/browser/computer use, LSP, remote execution and trajectory/evaluation systems.
14. [Teams and Discord integrations](../requirements/channel-integrations.md) defines the first separately deployable TypeScript channel connectors, identity/tenancy, cards/components, permissions and rollout.
15. [Connector catalog](../requirements/connector-catalog.md) extends that contract to the complete planned messaging, notification, meeting and relay catalog.
16. [Current feature-parity ledger](feature-parity.md) accounts for every current product and operational surface, including companions, reconciliation and the isolated shell subsystem.
17. [External capability coverage ledger](../requirements/external-capability-ledger.md) records exhaustive agent-platform capability coverage and the Automonique-specific adaptation or graduation track.
18. [AI implementation harness and commit metrics](../requirements/ai-implementation-harness.md) defines the durable author-review-fix loops, worktree/build coordination, hill-climbing objectives and per-commit evidence used to implement the program.
19. [Self-hosting and bootstrap](../requirements/self-hosting-and-bootstrap.md) defines the trusted seed, stable/candidate topology, self-build/reload cycle, independent rebuild and externally authorized promotion.
20. [Operations and governance](../requirements/operations-and-governance.md) defines recovery, configuration, credentials, retention, scheduling, observability and safe-mode contracts.
21. [TypeScript SDK](../requirements/typescript-sdk.md) defines complete typed client coverage, generated contracts, extension packages and testing utilities.
22. [Automonique operator TUI](../requirements/operator-tui.md) defines the local terminal experience, control boundary and reload-safe interaction model.
23. [Reload protocol](../requirements/reload-protocol.md) specifies the normal handoff and its failure paths.
24. [Migration plan](migration-plan.md) gives the phased strangler migration from the current daemon and independently gated product expansions.
25. [Verification and rollout](../requirements/verification-and-rollout.md) defines parity, chaos, security, provider-conformance and production gates.
26. [Work breakdown](work-breakdown.md) turns the design into ordered implementation tickets.

Blocking decisions are recorded as accepted ADRs:

- [ADR 001: execution-host and session lifetime](../decisions/001-execution-host-lifecycle.md)
- [ADR 002: domain-event and action journal](../decisions/002-domain-event-and-action-journal.md)
- [ADR 003: workspace registry and isolation](../decisions/003-workspace-isolation.md)
- [ADR 004: identity, tenancy and authorization](../decisions/004-identity-and-authorization.md)
- [ADR 005: artifacts and attachments](../decisions/005-artifact-storage.md)
- [ADR 006: Automonique naming and legacy compatibility](../decisions/006-automonique-naming.md)
- [ADR 007: layered sandbox enforcement and profiles](../decisions/007-sandbox-enforcement.md)

## Directional decisions

- Rewrite the backend, not necessarily the browser UI.
- Separate work items, attempts, execution hosts, provider sessions and turns. Retries create attempts; a session-scoped host may serve many turns, while an attempt-scoped host ends with its attempt.
- Use independent Rust execution-host units. An Automonique generation never owns their lifetime, and an idle-TTL policy—not a daemon reload—retires session-scoped hosts.
- Prefer native programmatic surfaces: Jcode ACP, Claude bidirectional stream JSON, Codex App Server stdio, and opencode HTTP/OpenAPI/SSE.
- Negotiate and persist capabilities for the exact provider binary/protocol; fall back only when safety and requested behavior remain representable.
- Keep SQLite as the durable authority, using WAL and an explicit single-writer abstraction inside each generation.
- Commit domain events and action receipts transactionally with authoritative state; snapshots plus the global event cursor are the only supported resume model.
- Give every attempt an isolated registered workspace and make promotion/merge/deploy explicit, revision-checked actions.
- Compile every run into an immutable sandbox profile with attested filesystem, process, resource, credential and provider/tool network boundaries; missing enforcement fails closed.
- Compile provider-independent context manifests, retain original history through compression, and make queue/retry/undo/checkpoint behavior capability-correct and durable.
- Treat memory, skills and agent profiles as revisioned governed state; learned executable behavior is proposed, tested and reviewed rather than silently activated.
- Own one canonical tool registry with per-channel/profile toolsets, native MCP client/server, deferred schema search and sandboxed extension/hook/workflow boundaries.
- Make user automations, inbound triggers and persistent goals ordinary durable work with fenced scheduling, exact authority and idempotent delivery.
- Make actors, external identities, tenants, roles and authorization decisions durable; no transport identity or SDK credential implies global authority.
- Treat attachments, patches, logs, reports and exports as content-addressed artifacts with provenance, visibility and retention policy.
- Allow old and new daemon generations to overlap briefly during reload.
- Make all external inputs durable before business processing.
- Make all externally visible mutations idempotent or outbox-backed.
- Use versioned protocols and expand/contract database migrations.
- Pin active execution hosts to provider binary and schema digests so a CLI update cannot change an in-flight protocol.
- Ship generated, capability-complete `@automonique/sdk*` packages for Node, Bun and browsers; `@legacy/sdk*` exists only as a tested forwarding compatibility layer during migration.
- Expose the same domain through independently tested ACP-host, MCP-server, OpenAI-compatible, Runs, A2A and relay adapters without creating alternate authority or state.
- Ship Teams and Discord as independently supervised TypeScript connector apps over the generated SDK; connectors terminate platform protocols but never call models/tools or decide policy.
- Use the connector SDK for the full catalog in `connector-catalog.md`; every platform, media or subscription family graduates independently.
- Ship `automonique-tui` as a first-class operator client over the versioned admin/event protocol; `legacy-tui` is a temporary compatibility shim and neither reads the database nor provider sockets directly.
- Build a Tauri desktop client and optional cross-platform clients over the public SDK; UI plugins/widgets remain namespaced and cannot acquire backend authority.
- Support explainable model routing, policy-bounded credential pools/fallbacks, auxiliary/MoA calls, media/browser/computer capabilities and multiple execution providers only through explicit capability/data-boundary gates.
- Build `automonique-lab` first: a durable, reloadable AI implementation harness with isolated work ownership, independent adversarial reviews, centrally scheduled builds/tests, measurable objectives and compact commit-linked attestations.
- Make the development system functionally self-hosting through explicit SH0–SH6 levels: a signed stable seed builds an isolated candidate, the candidate rebuilds/reloads itself, an independent builder verifies it and only external authority may promote it to production.
- Judge implementation progress by parity, correctness, failure, latency, memory, cache/prompt, safety and cost evidence—not lines, commits or agent count—and forbid a work unit from redefining the metric that judges it.
- Retain tmux only as an optional operator view during migration; it is not the lifetime owner in the target architecture.
- Publish immutable, checksummed releases and make rollback use the same generation handoff as upgrade.
- Require a tested backup/restore path, retention/deletion controls, admission budgets, reconciliation plans and actionable observability before cutover.

## Completion definition

The rewrite is complete only when this scenario passes repeatedly:

1. Three agent attempts are running concurrently and using tools, including two turns sharing one resumable provider session.
2. Slack and Telegram messages arrive while a reload begins.
3. One job completes during the generation overlap and another receives cancellation.
4. The new binary becomes active without waiting for idle.
5. Every accepted input is processed exactly once at the Automonique business boundary.
6. Every job event and terminal report is delivered without gaps or duplicates.
7. Automonique approvals and provider permission requests remain actionable and bound to their exact revisions/items.
8. Execution hosts, provider sessions, turns, capabilities, workspace bindings and authoritative event cursors are adopted without restarting a session-scoped provider process.
9. The dashboard remains reachable apart from a bounded connection reconnect.
10. An open Automonique TUI (or supported legacy compatibility entry point) keeps its N-pane cross-provider cockpit, reattaches each session independently, reconciles pending actions and renders the same durable state after handoff.
11. Current and previous TypeScript SDK clients retain complete negotiated coverage through the reload without private endpoints or handwritten wire types.
12. The old generation exits after draining.
13. The same procedure can roll back to the previous binary.
14. A clean-host restore recovers the database, artifact manifests, workspaces, cursors and encrypted configuration inside the stated RPO/RTO.
15. Every entry in the machine-readable parity ledger is proved, explicitly replaced, isolated by an accepted decision, or intentionally retired.
16. Tenant/role denials, artifact access, scheduler budgets and action receipts remain correct across reload, retry and reconnect.
17. For every enabled Teams or Discord connector, its representative personal/channel or command/DM flow survives connector plus daemon restart, preserves tenant/actor identity and reconciles cards/components without duplicate work. Optional connector general availability is governed by its own exit gate and does not block the core Rust cutover when that connector is not enabled.
18. Context, queue, compression, memory, skill, profile, goal and automation state survives reload with complete revision/provenance evidence and no prompt-cache or authority ambiguity.
19. Tool, MCP, workflow and hook extensions are capability-filtered, sandboxed, reload-safe and quarantinable; every stable operation is represented in the TypeScript SDK.
20. ACP/OpenAI/MCP/A2A/relay clients and every enabled connector map one external request to the same canonical session/work/action records and cannot bypass exact approvals.
21. Every row in the external capability ledger has an implementation owner/ticket, fixture, security/data-boundary classification and graduation or explicit safety-adapted replacement evidence.
22. Every implementation ticket is traceable through a reproducible harness run, independent review evidence, required tests and a commit/CI metrics attestation; no skipped/deleted test, unexplained parity difference or threshold regression is hidden by aggregate progress.
23. A clean SH0 bootstrap creates the stable lab; stable builds an immutable candidate; the candidate runs a bounded self-host fixture, rebuilds/reloads itself and falls back under failure; an independent builder verifies provenance/output; and production promotion remains an external typed action.

## Explicit non-goals

- Preserving arbitrary in-memory futures across `exec`.
- Hot-patching machine code inside a running process.
- Cross-host high availability in the first core rewrite release; remote/scale-to-zero execution is an independently gated expansion.
- Changing Automonique's inherited approval policy, GitHub-as-ticket-truth policy, or worker persona as part of the language migration.
- Replacing SQLite merely because the daemon is being rewritten.
- Completing the public-repository or legal rebrand as a hidden prerequisite of the language rewrite; the two programs share compatibility gates but have separate release decisions.
- Shipping every optional connector, media backend, desktop plugin, cloud executor or research export before core cutover; all remain planned and independently gated rather than silently omitted.
- Claiming to eliminate trust in the operating system, compiler/toolchain, source host, dependency sources, model providers, independent builder or release authority; self-hosting makes these roots explicit rather than pretending they do not exist.
