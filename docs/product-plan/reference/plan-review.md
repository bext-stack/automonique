# Plan review findings

This review compares the original Rust rewrite plan with the agent surfaces installed on the production host on 2026-08-04:

- Jcode 0.65.0 CLI, with a separately running reloadable daemon;
- Claude Code 2.1.221;
- Codex CLI 0.146.0;
- opencode 1.17.18.

The plan remains directionally correct: independently supervised runners plus a reloadable Automonique daemon are the right foundation. The original provider layer was too generic, however. Treating every backend as “argv in, NDJSON out” would discard supported session, steering, approval, health, model, usage, and reconnect capabilities.

## Findings and corrections

| Gap in the original plan | Risk | Correction |
|---|---|---|
| One generic adapter shape | Lowest-common-denominator behavior and provider-specific hacks | Add capability negotiation and protocol-specific adapters |
| Session, turn, process and Automonique work item conflated | Unsafe resume/cancel and unclear ownership | Persist distinct provider server/session/turn/process identities |
| Only final result/session ID modeled | Lost steering, approval and live state | Define a normalized session/turn/event/approval model |
| Streaming deltas treated like durable events | Duplicate or incomplete final text after reconnect | Mark preview/delta events ephemeral; reconcile with authoritative completed records |
| No provider approval bridge | Either bypass everything or deadlock on hidden prompts | Route provider approval requests through a typed Automonique policy/approval bridge |
| No schema/version pinning | Silent breakage after CLI auto-update | Probe version/capabilities, snapshot schemas, and gate upgrades with conformance tests |
| No provider lifecycle policy | Updating a CLI could kill or corrupt active work | Pin each active execution host to its provider binary/protocol; upgrade only new hosts except supported graceful daemon reload |
| No reconnect/adoption contract per provider | legacy reload could preserve the runner but lose its provider stream | Give each adapter explicit reconnect and reconciliation behavior |
| Fallbacks underspecified | Native integration failure could strand work or silently downgrade security | Define native, supported fallback, and refusal levels per provider |
| Health/usage/model surfaces omitted | Dashboard cannot explain availability or select safely | Normalize auth, model catalog, quota/usage and provider health projections |
| MCP/skills/subagents omitted | Deep provider features disappear after rewrite | Model these as negotiated capabilities without assuming identical semantics |
| Raw event retention omitted | Parser upgrades cannot replay or diagnose protocol drift | Store bounded raw provider events alongside normalized events and schema hash |
| Local operation limited to CLI commands, web UI and tmux views | Slow command discovery, fragmented approvals and weak SSH ergonomics | Add a first-class reload-safe TUI over the canonical operator protocol |
| TypeScript consumers would otherwise duplicate routes and wire types | Dashboard drift, incomplete automation surface and unsafe retry differences | Generate a capability-complete TypeScript SDK from Rust schemas and require all TypeScript clients to use it |

## Revised integration principle

`automonique-runner` is not just a process wrapper. It is a durable **provider-session proxy**:

1. It starts or connects to the provider's supported programmatic surface.
2. It negotiates an observed capability set for that exact provider version.
3. It owns provider connection/session/turn state independently of the `automonique` daemon.
4. It journals raw and normalized events before forwarding them.
5. It handles reconnect, replay/reconciliation, steering, cancellation and provider approval requests.
6. It continues operating while Automonique daemon generations hand off.
7. It refuses unsafe silent downgrades.

## Selected native surfaces

| Provider | Preferred integration | Supported fallback | Reason |
|---|---|---|---|
| Jcode | ACP adapter backed by the selected Jcode daemon socket | `jcode run --ndjson` | ACP plus daemon reload/session ownership aligns directly with Automonique reload goals |
| Claude Code | Long-lived bidirectional `stream-json` print/SDK process | one-shot `-p --output-format stream-json` plus `--resume` | Installed CLI exposes realtime input, replay acknowledgements, partial messages, hook and subagent events |
| Codex | Session-scoped App Server over stdio with generated schema pinned to the installed binary | attempt-scoped `codex exec --json -` plus `exec resume` | App Server exposes threads, turns, steering, interrupt, approvals, models, auth, rate limits, skills and MCP state |
| opencode | Session-scoped authenticated headless HTTP server with OpenAPI client and SSE events | attempt-scoped ACP stdio, then `opencode run --format json` | Server API exposes sessions, async prompts, status, abort, permissions, diffs, providers, MCP and event stream |

The preferred surfaces are not assumed universally stable. Runtime probes select them only after versioned conformance succeeds. A fallback is allowed only when the requested Automonique behavior and security policy remain representable.

## Architecture consequences

- One active execution host is pinned to one provider integration mode and binary version.
- New provider binaries affect new hosts first; active hosts drain on their pinned version.
- Jcode's own supported daemon reload may upgrade in place after an explicit compatibility check.
- Codex App Server and opencode servers live inside session-scoped execution-host boundaries so an Automonique generation reload does not disconnect them.
- Claude's long-lived stream process also lives inside a session-scoped host; its session ID is assigned/persisted before the first prompt where supported.
- Provider-side sessions outlive a single Automonique work item and are linked through explicit session bindings.
- A follow-up creates a new turn against the bound provider session; it does not invent a new session from an opaque string.
- Provider approval requests are different from Automonique's outer ticket approval and must never be conflated.
- The dashboard and Automonique TUI show both normalized cross-provider state and provider-specific detail.

## New go/no-go questions

Before enabling a native adapter version:

1. Can Automonique create, resume, observe, steer and cancel a session/turn without a TTY?
2. Which events are authoritative and which are live previews?
3. Can missed events be replayed, listed, or reconstructed after reconnect?
4. How are permission/tool/MCP requests represented and answered?
5. Can the adapter prove the exact cwd, sandbox, tools, model and session identity in effect?
6. Can an old execution host continue after the provider binary on disk changes?
7. Does the provider persist sessions, and what exactly survives process or machine restart?
8. Is the selected protocol documented/stable, experimental-but-schema-generated, or internal?
9. What security guarantees are lost when falling back?
10. Can conformance tests run without consuming a real model call?

The detailed answers and adapter contracts live in [Agent integrations](../requirements/agent-integrations.md).

## Whole-system review additions

A second review stepped back from provider integration and found five architecture blockers plus several product/operations omissions. The accepted design positions are:

1. **Execution-host and session lifetime:** work items, attempts, execution hosts, provider sessions and turns are separate lifecycles.
2. **Domain-event and action journal:** authoritative state, resumable events and mutation receipts are transactionally linked.
3. **Workspace registry and isolation:** every mutating attempt gets an isolated immutable-base worktree/snapshot and explicit promotion.
4. **Identity, tenancy and authorization:** transport IDs resolve to durable tenant-scoped actors/roles and revisioned policy decisions.
5. **Artifacts and attachments:** files, patches, logs and publications are content-addressed objects with provenance and retention.

The review also added:

- a [feature-parity ledger](feature-parity.md) for support/client-portal, GitHub/client publication, companions, learned targets, live feeds, notifications, operational commands, reconciliation and the isolated shell subsystem;
- an [operations and governance contract](../requirements/operations-and-governance.md) for backup/restore, credential rotation, retention/deletion/export, scheduler budgets/fairness, work DAGs, deterministic plans, observability/runbooks, safe modes, signed webhooks and extension supply chain;
- explicit 8A–8E operator-platform sequencing so identity/events stabilize before the SDK, dashboard, TUI and production canaries;
- stable pagination/search, “why” explainability, cost anomaly alerts, provider quarantine, reboot/hibernation classification and time-travel replay as supported product behavior.

These are cutover requirements, not aspirational post-rewrite cleanup. An implementation may defer an optional parity item only by recording a replacement, isolated compatibility boundary or intentional retirement with owner and evidence.

## Channel expansion review

Microsoft Teams and Discord are planned as out-of-process TypeScript connector applications over the generated SDK, not as model/provider adapters or direct chat endpoints. [Teams and Discord integrations](../requirements/channel-integrations.md) defines installation/tenant identity, acknowledgement and deduplication, Adaptive Card/component approvals, artifacts, Graph/RSC and Gateway permission gates, webhook-only notification modes, sovereignty disclosures and independent canaries.

## Integrated plan audit corrections

A final cross-document review corrected the remaining contradictions and missing decisions:

| Gap | Correction now owned by the plans |
|---|---|
| Rebrand mentioned without a repository/runtime migration | Added the dedicated Automonique identity plan: new audited upstream, additive aliases, one runtime/state owner and no branding-driven ID rewrite |
| Inbox transport state mixed with approval/queue state | Inbox now ends at routing; work items own approval, capacity, queue and execution lifecycle |
| Run schema required a host although the lifetime design permits zero before launch | `host_id` is optional until the atomic start transition and host identity carries tenant/account/workspace/boot context |
| Shared Jcode daemon could execute outside the host sandbox | Require security-context attestation and descendant-boundary tests, otherwise use a per-context daemon |
| SDK package namespace was split between legacy and Automonique | Canonicalize every public package under `@automonique/sdk*`; supported `@legacy` names are forwarding-only |
| Optional Teams/Discord rollout accidentally blocked core completion | Core cutover excludes disabled connectors; attached protocol incompatibility blocks reload, platform/credential outage is explicit degradation |
| Connector processes were absent from the service topology | Add independently supervised Teams and Discord services with separate lifecycle and credentials |
| Backup listed credential metadata but not a usable recovery path | Require encrypted ciphertext plus escrowed key or recoverable external-provider authentication, and prove descriptor resolution in restore drills |
| Public-source, brand licensing and old-repository retirement were implicit | Give each an evidence gate; keep the private repository recoverable until cutover, never delete it as part of repository migration |

## Ecosystem capability audit

The final breadth review is maintained as a neutral, product-owned [external capability ledger](../requirements/external-capability-ledger.md), not as a dependency on or comparison to another named project. It closes the remaining product families with technology-specific contracts:

- [context, memory and learning](../requirements/context-memory-and-learning.md), including deterministic manifests, typed references, compression lineage, FTS search, durable input steering, skill catalogs and reviewed learning;
- [tools, extensions and hooks](../requirements/tools-extensions-and-hooks.md), including a canonical registry, deferred discovery, sandboxed workflow runtimes, MCP client/server roles, signed packages and secret-provider adapters;
- [automations, goals and triggers](../requirements/automation-goals-and-triggers.md), including timezone-safe schedules, script/workflow jobs, persistent judged goals, Kanban projection and verified inbound webhooks;
- [public agent protocols](../requirements/public-agent-protocols.md), including the native Runs API, compatible chat/run projections, agent control, MCP server, A2A and relay boundaries;
- [client experiences](../requirements/client-experience-and-surfaces.md), including the Rust TUI, SDK-backed web app, ShellDeck desktop, mobile/PWA access, setup/update/import and constrained UI customization;
- the [connector catalog](../requirements/connector-catalog.md), covering conversational, notification, regional, sovereign, device and directory/meeting integrations under one installation and identity contract;
- [models, media and execution](../requirements/models-media-and-execution.md), including catalog/routing/pools, aggregation, voice/vision/generation, browser/computer use, LSP, portable local-to-cluster executors, batch trajectories and evaluation.

These additions preserve the architecture's central rule: optional breadth composes through canonical durable state, policy, sandbox, artifacts, receipts and generated SDK contracts. No connector, extension, compatibility API, media worker or executor may create a privileged side channel or a second source of truth. Core cutover remains independently achievable; every optional family has its own conformance and graduation gate.

## Implementation-system review

The breadth of the program makes manual prompt-by-prompt execution an avoidable risk. The plan now begins with [Automonique's AI implementation harness](../requirements/ai-implementation-harness.md): a separate durable work DAG, isolated path/worktree leases, central build scheduling, bounded workers, owner-configurable review passes and serialized integration. Compiler/test/parity/security/performance failures become explicit queues, while incomplete work is resumed across agent or harness reload instead of being declared done from prose.

Every integrated unit carries a compact commit trailer set pointing to a reproducible metrics manifest. The manifest measures correctness/parity, agent-product latency and resources, prompt/cache/model economics, review evidence and safety/maintainability deltas. It records lines, commits and agent count only as context, never as a reward. Humans retain merge, release and production-deploy authority, and the harness cannot alter the metric/baseline that judges its own change in the same review unit.

## Self-hosting review

The implementation harness originally allowed migration onto its own interfaces but did not define who could trust the resulting candidate. [Self-hosting and bootstrap](../requirements/self-hosting-and-bootstrap.md) closes that gap with SH0–SH6 maturity levels, a signed bootstrap manifest, immutable source/build identity, completely separate stable/candidate namespaces, a candidate evidence state machine, bounded self-development sessions, candidate self-build/reload, owner-configured reproducibility checks and typed external promotion.

The design distinguishes productive self-development from circular trust. A candidate can generate source, tests, metrics and a production proposal, but those remain untrusted claims until the stable or independent control plane observes them. Candidate credentials cannot write protected branches, sign releases, deploy production or mark their own independent/promotion gates. The last known-good seed and recovery bundle remain runnable even if candidate or stable development state is corrupted.
