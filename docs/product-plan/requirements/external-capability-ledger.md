# External capability coverage ledger

**Status:** exhaustive planning baseline

## Purpose

This ledger prevents useful agent-platform capabilities from disappearing into vague “future integration” language. It records how each product family fits Automonique's Rust daemon, generated TypeScript SDK, durable approvals/events, connector boundary and attested sandbox. It defines Automonique behavior and does not assert compatibility with another product.

Every row must acquire implementation ticket IDs, owner, fixtures and one of: `core`, `expansion`, `optional`, `research`, or an explicit safety-adapted replacement. No row is silently dropped.

## Core conversation and context

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Classic CLI, full TUI and one-shot/quiet modes | Rust CLI plus Ratatui N-pane client over canonical SDK protocol | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Multiline editor, history and slash autocomplete | Shared command registry, composer history and generated completion | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Interrupt and redirect | Provider-capability-aware stop/steer plus durable queued input | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Retry, undo, new/reset and session continuation | Revisioned attempts/forks/projections without audit erasure | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Queue editing and turn-boundary stop | Durable per-session input queue with provider acceptance boundary | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Context usage/insights/compression | Component token budget, compression lineage, UI breakdown and cache telemetry | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Project context files | Bounded `AGENTS.md`-first context compiler with labelled provider compatibility files | core | automonique-core | R1-25 | none — GATE-ORACLE |
| `@file`, folder, diff, staged, Git, URL and session references | Typed authorized context references with artifact/provenance limits | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Personalities and SOUL files | Versioned persona profiles, import/export and no authority semantics | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Prompt caching | Stable-prefix policy, invalidation events and provider telemetry | core | automonique-core | R1-25 | none — GATE-ORACLE |
| Checkpoints and rollback | Per-turn workspace checkpoint/diff/restore layered on isolated worktrees | core | automonique-core | R1-25 | none — GATE-ORACLE |

## Memory, skills and self-improvement

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Persistent memory and user profile | Typed user/workspace/team/task memory with review, correction and deletion | core | automonique-memory | R1-20 | none — GATE-ORACLE |
| Session FTS5 search and surrounding history | Tenant-filtered SQLite FTS with exact message citations | core | automonique-memory | R1-20 | none — GATE-ORACLE |
| Background memory review | Budgeted review proposals; never silent policy mutation | expansion | automonique-memory | R1-20 | none — GATE-ORACLE |
| External memory providers/Honcho-style user modeling | Sandboxed memory-provider SPI with provenance and consent | optional | automonique-memory | R1-20 | none — GATE-ORACLE |
| Learning journey/memory graph | SDK read model linking evidence, memories, skills and outcomes | expansion | automonique-memory | R1-20 | none — GATE-ORACLE |
| agentskills.io skills and progressive disclosure | Native signed skill runtime and scoped discovery | core | automonique-memory | R1-20 | none — GATE-ORACLE |
| `/learn` and agent-created skills | Evidence/test-backed learning proposals with approval policy | core | automonique-memory | R1-20 | none — GATE-ORACLE |
| Skill Hub, direct URLs, GitHub taps and well-known registries | Allowlisted catalogs, signature/license/digest verification | expansion | automonique-memory | R1-20 | none — GATE-ORACLE |
| Skill bundles and conditional fallback skills | Revisioned profile/workspace bundles and capability predicates | core | automonique-memory | R1-20 | none — GATE-ORACLE |
| Curator stale/archive/pin/backup/consolidate | Non-destructive lifecycle service with optional reviewed consolidation | expansion | automonique-memory | R1-20 | none — GATE-ORACLE |
| Skill secure setup/config | Typed secret/config requirements resolved outside skill prose | core | automonique-memory | R1-20 | none — GATE-ORACLE |

## Tools, extensions and development intelligence

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Built-in tools and per-platform toolsets | Canonical tool registry; effective grants intersect tenant/profile/workspace/channel policy | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Tool search/deferred schemas | Authorization-filtered catalog search and on-demand schema loading | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Programmatic tool calls from Python | Bounded sandboxed workflow runtime over capability RPC; add WASI/JS/Python adapters | expansion | automonique-tools | R1-21 | none — GATE-ORACLE |
| MCP stdio/HTTP client and sampling | Native managed MCP client; sampling is separately budgeted/policy checked | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Agent platform as MCP server | Scoped Automonique MCP server over local/HTTP identity | expansion | automonique-tools | R1-21 | none — GATE-ORACLE |
| Plugin tools, memory and context engines | Signed out-of-process extension SPI | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Gateway/plugin/shell hooks | Typed observer/filter/transformer/context/trigger hooks with deterministic ordering | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Desktop plugins and backend namespaces | Signed UI extensions plus separately sandboxed backend extension | expansion | automonique-tools | R1-21 | none — GATE-ORACLE |
| TUI widget apps | Declarative/WASI widgets over read-only SDK projections | optional | automonique-tools | R1-21 | none — GATE-ORACLE |
| LSP manager | Workspace-scoped sandboxed language servers and normalized diagnostics | expansion | automonique-tools | R1-21 | none — GATE-ORACLE |
| Git/worktree review tooling | Workspace diff/review/checkpoint/stage/commit/push/PR proposal services | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Autonomous implementation loop | Separate `automonique-lab` work DAG with bounded workers, owner-configurable review passes and human merge/deploy authority | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Measurable objectives and commit evidence | Hill-climbability objective plus content-addressed correctness/performance/prompt/safety metrics attestation referenced by each commit | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Self-hosting bootstrap | Signed SH0 seed and manifest; stable builds an isolated candidate that self-builds/reloads under stable observation | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Candidate verification | Stable verification, provenance/SBOM and reproducible A1/A2 plus optional clean A3 comparison before promotion eligibility | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Recursive self-improvement | Evidence-driven bounded proposals/loops with external review for scope, policy, metrics, privilege, release and production | core | automonique-tools | R1-21 | none — GATE-ORACLE |
| Computer-use driver | High-risk accessibility/screenshot adapter in disposable/eligible environment | optional | automonique-tools | R1-21 | none — GATE-ORACLE |

## Agents, goals and orchestration

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Foreground/background delegation | Durable work-DAG nodes or provider-native children with explicit lifecycle | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Orchestrator depth/concurrency | Scheduler budgets, spawn depth and child capability limits | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Persistent goals and subgoals | Goal aggregate, completion contract/judge, waits and continuation budget | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Kanban multi-profile work queue | Work-graph command-center/Kanban projection with fenced claims | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Mixture of Agents | Tool-free reference advisors plus acting model, privacy/cost policy | optional | automonique-agents | R1-22 | none — GATE-ORACLE |
| Independent spawned agents | Session-scoped execution hosts with isolated workspaces and attachable TUI panes | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Agent profiles | Persona/model/tools/skills/memory/channel package distinct from tenant/workspace/sandbox | core | automonique-agents | R1-22 | none — GATE-ORACLE |
| Profile distributions | Signed import/export packages excluding secrets and private memory by default | expansion | automonique-agents | R1-22 | none — GATE-ORACLE |

## Automation and integration

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Natural-language/cron/interval/one-shot jobs | Reviewed canonical schedule with timezone/DST examples | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Job edit/pause/resume/run/remove/history | Revisioned automation service and SDK/TUI/dashboard/CLI clients | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Per-job skills/model/provider/workdir/delivery | Immutable occurrence plan with ordinary policy/sandbox | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Script-only zero-model jobs | Reviewed sandbox workflow with exact output delivery | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Job output chaining | Typed artifact/output dependencies in work graph | expansion | automonique-automation | R1-22 | none — GATE-ORACLE |
| Inbound webhook subscriptions | Signed routes, idempotency, filters, templates and sandbox transforms | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Direct no-agent webhook delivery | Typed notification outbox with no model call | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Outbound lifecycle webhooks | Durable signed subscriptions and receipts already planned | core | automonique-automation | R1-22 | none — GATE-ORACLE |
| Watchers and boot/startup checklists | Leased trigger adapters creating durable input; no inline privilege | expansion | automonique-automation | R1-22 | none — GATE-ORACLE |
| Automation blueprints | Signed templates with previewed schedules/capabilities | expansion | automonique-automation | R1-22 | none — GATE-ORACLE |

## Models, credentials and provider behavior

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Broad model-provider plugins/custom endpoints | Provider catalog/SPI alongside primary Jcode/Claude/Codex/opencode adapters | expansion | automonique-models | R1-24 | none — GATE-ORACLE |
| Model aliases and per-session selection | Versioned profile aliases and explicit turn revisions | core | automonique-models | R1-24 | none — GATE-ORACLE |
| Provider sort/only/ignore/order/routing | Explainable tenant routing by capability, locality, cost and health | expansion | automonique-models | R1-24 | none — GATE-ORACLE |
| Fallback chains including auxiliary tasks | Policy-preserving independent fallback graphs | core | automonique-models | R1-24 | none — GATE-ORACLE |
| Credential pools and automatic rotation | Named same-boundary pools with billing/tenant/quota evidence | expansion | automonique-models | R1-24 | none — GATE-ORACLE |
| OAuth sign-in and subscription proxy | Scoped auth brokers/local proxy respecting provider terms | optional | automonique-models | R1-24 | none — GATE-ORACLE |
| Auxiliary models | Separate usage/policy for titles, compression, memory, media and evaluation | core | automonique-models | R1-24 | none — GATE-ORACLE |
| Prompt-cache-aware provider switching | Cache invalidation and context-cost warning | core | automonique-models | R1-24 | none — GATE-ORACLE |
| Local models/custom OpenAI endpoints | Provider plugin plus data-boundary/capability conformance | expansion | automonique-models | R1-24 | none — GATE-ORACLE |

## Public protocols and surfaces

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| ACP server for IDEs | Automonique ACP host; separate from consuming provider ACP | expansion | automonique-daemon | R1-23 | none — GATE-ORACLE |
| OpenAI Chat Completions/Responses API | Authenticated compatibility adapter over canonical runs/sessions | expansion | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Runs/jobs/sessions HTTP APIs | Native SDK remains complete; compatibility APIs map to same receipts | core | automonique-daemon | R1-23 | none — GATE-ORACLE |
| OpenAI-compatible local proxy | Short-lived loopback credential and audited provider use | optional | automonique-daemon | R1-23 | none — GATE-ORACLE |
| A2A/relay/Buzz-style clients | Authenticated task/relay adapters with cursors and media artifacts | optional | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Web dashboard with embedded chat | SDK-only dashboard plus complete management surfaces | core | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Native desktop | ShellDeck (Rust/GPUI) over the shared Rust protocol client; Linux/macOS first, Windows via dashboard/PWA until conformant | expansion | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Remote desktop/gateway selection | OIDC/VPN remote profiles and multi-backend client | expansion | automonique-daemon | R1-23 | none — GATE-ORACLE |
| PWA/Termux/Windows native support | PWA and Termux clients; platform-specific execution capability matrix | optional | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Shell completions/setup/doctor/update/uninstall | Signed lifecycle CLI with non-destructive modes | core | automonique-daemon | R1-23 | none — GATE-ORACLE |
| Import from OpenClaw/other agents | Dry-run import of persona, memory, skills, rules, settings and allowlisted secrets | expansion | automonique-daemon | R1-23 | none — GATE-ORACLE |

## Messaging and channels

| Capability family | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Telegram, Slack and Discord | Existing/mapped connector contract | core | automonique-transports | R1-16 | none — GATE-ORACLE |
| Microsoft Teams | Teams SDK connector, Cards and Graph/RSC as already planned | expansion | automonique-transports | R1-16 | none — GATE-ORACLE |
| WhatsApp Cloud/device | Official Cloud first; isolated device compatibility adapter | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| Signal, SimpleX and Matrix | Dedicated identity/key-custody connectors | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| iMessage/BlueBubbles/Photon | Trusted macOS bridge connector | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| Email and SMS | Threaded mail and compliant typed SMS provider | expansion | automonique-transports | R1-16 | none — GATE-ORACLE |
| Mattermost, Google Chat, IRC | Standard connector packages | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| LINE, DingTalk, Feishu, WeCom/Weixin, QQ, Yuanbao | Official API packages; unofficial paths experimental/quarantined | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| Home Assistant, ntfy and notification webhooks | Device/notification connector packages | optional | automonique-transports | R1-16 | none — GATE-ORACLE |
| Open WebUI/API server | OpenAI-compatible API client surface | expansion | automonique-transports | R1-16 | none — GATE-ORACLE |
| Pairing, home target and channel directory | Durable actor pairing and authorization-filtered target directory | core | automonique-transports | R1-16 | none — GATE-ORACLE |
| Cross-platform continuity | Explicit session/profile bindings, never display-name matching | core | automonique-transports | R1-16 | none — GATE-ORACLE |
| Reactions, stickers and rich components | Bounded presentation/media capability per connector | expansion | automonique-transports | R1-16 | none — GATE-ORACLE |
| Voice notes, Discord voice and Teams meetings | Consent-aware media workers and artifact retention | optional | automonique-transports | R1-16 | none — GATE-ORACLE |

## Media, browser and external tools

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Voice transcription and TTS | STT/TTS adapter registries plus platform derivatives | expansion | automonique-media | R1-24 | none — GATE-ORACLE |
| Live voice and wake word | Local capture/hotword with no approval authority | optional | automonique-media | R1-24 | none — GATE-ORACLE |
| Vision and clipboard images | Artifact-backed multimodal context | expansion | automonique-media | R1-24 | none — GATE-ORACLE |
| Image generation | Provider adapter with provenance/cost/content policy | optional | automonique-media | R1-24 | none — GATE-ORACLE |
| Video generation | Provider adapter with long-running artifact workflow | optional | automonique-media | R1-24 | none — GATE-ORACLE |
| Web search and grounded extraction | Provider registry with citations and egress evidence | core | automonique-media | R1-24 | none — GATE-ORACLE |
| Browser automation | Local/remote isolated browser session adapter | expansion | automonique-media | R1-24 | none — GATE-ORACLE |
| Native computer use | High-risk capability requiring disposable desktop/session | optional | automonique-media | R1-24 | none — GATE-ORACLE |
| Tool gateway | Sovereign capability/usage gateway for approved media/web services | optional | automonique-media | R1-24 | none — GATE-ORACLE |
| Secret sources (1Password/Bitwarden/command) | Sealed secret-source SPI with pinned command helper | expansion | automonique-media | R1-24 | none — GATE-ORACLE |

## Execution, scale and research

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Local terminal backend | direct-process execution hosts, optional supervisor adapters and sandbox attestation | core | automonique-runner | R1-15 | none — GATE-ORACLE |
| Docker | rootless OCI execution provider; no root daemon socket | expansion | automonique-runner | R1-15 | none — GATE-ORACLE |
| SSH | attested remote execution provider | expansion | automonique-runner | R1-15 | none — GATE-ORACLE |
| Singularity | Apptainer/Singularity HPC provider, optional Slurm | optional | automonique-runner | R1-15 | none — GATE-ORACLE |
| Modal, Daytona, Vercel Sandbox | Independent cloud executor adapters with billing/data policy | optional | automonique-runner | R1-15 | none — GATE-ORACLE |
| Persistent serverless hibernation/scale-to-zero | Explicit environment snapshot/hibernation/wake lifecycle | expansion | automonique-runner | R1-15 | none — GATE-ORACLE |
| MicroVM/strong isolation | Strong-isolation provider already required for hostile-kernel work | expansion | automonique-runner | R1-15 | none — GATE-ORACLE |
| Batch processing | Resumable dataset runner with bounded concurrency | research | automonique-runner | R1-15 | none — GATE-ORACLE |
| Trajectory capture/compression | Redacted normalized export with provenance and consent | research | automonique-runner | R1-15 | none — GATE-ORACLE |
| Evaluation/quality filtering/statistics | Assertion and tool/outcome metrics over synthetic/approved datasets | research | automonique-runner | R1-15 | none — GATE-ORACLE |

## Customization and product polish

| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |
|---|---|---|---|---|---|
| Skins/themes | Shared accessible design-token format and sanitized imports | expansion | automonique-tui | R1-25 | none — GATE-ORACLE |
| Desktop theme/plugin marketplace | Signed allowlisted UI catalog with review/revocation | optional | automonique-tui | R1-25 | none — GATE-ORACLE |
| Rebindable shortcuts/localization | Shared command IDs, conflict detection and locale catalogs | expansion | automonique-tui | R1-25 | none — GATE-ORACLE |
| Pet mascots | Signed presentation-only Monique/pet packs with zero authority | optional | automonique-tui | R1-25 | none — GATE-ORACLE |
| Native notifications/quick entry | Desktop/PWA notification and global quick-entry controls | expansion | automonique-tui | R1-25 | none — GATE-ORACLE |
| Learning graph/star map | Evidence-backed visualization described in context plan | expansion | automonique-tui | R1-25 | none — GATE-ORACLE |

## Safety adaptations

Potentially unsafe agent-platform behaviors are represented through safer Automonique outcomes:

- no global YOLO mode; development sandboxes may use a named policy that still cannot bypass tenant/privileged-action boundaries;
- no automatic executable skill/plugin activation after agent-authored changes;
- no silent credential/provider rotation across billing, tenant, residency or provider-account boundaries;
- no broad tools enabled on every connector by default;
- no untrusted in-process plugin code in the Rust daemon/TUI;
- no production-session training export without explicit consent and redaction evidence;
- no desktop/mobile client direct access to database, provider sockets or privileged brokers.

## Closure gate

The ledger closes only when every row has ticket IDs, an owner, specification link, security/data-boundary classification, SDK capability, fixtures and graduation evidence. Optional/research means independently gated—not forgotten. External agent-platform capability surveys are reviewed periodically without naming comparison sources in the product plans; additions are recorded as Automonique requirements so scope drift remains visible.
