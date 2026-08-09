# External capability coverage ledger

**Status:** exhaustive planning baseline

## Purpose

This ledger prevents useful agent-platform capabilities from disappearing into vague “future integration” language. It records how each product family fits Automonique's Rust daemon, generated TypeScript SDK, durable approvals/events, connector boundary and attested sandbox. It defines Automonique behavior and does not assert compatibility with another product.

Every row must acquire implementation ticket IDs, owner, fixtures and one of: `core`, `expansion`, `optional`, `research`, or an explicit safety-adapted replacement. No row is silently dropped.

## Core conversation and context

| Capability | Automonique adaptation | Track |
|---|---|---|
| Classic CLI, full TUI and one-shot/quiet modes | Rust CLI plus Ratatui N-pane client over canonical SDK protocol | core |
| Multiline editor, history and slash autocomplete | Shared command registry, composer history and generated completion | core |
| Interrupt and redirect | Provider-capability-aware stop/steer plus durable queued input | core |
| Retry, undo, new/reset and session continuation | Revisioned attempts/forks/projections without audit erasure | core |
| Queue editing and turn-boundary stop | Durable per-session input queue with provider acceptance boundary | core |
| Context usage/insights/compression | Component token budget, compression lineage, UI breakdown and cache telemetry | core |
| Project context files | Bounded `AGENTS.md`-first context compiler with labelled provider compatibility files | core |
| `@file`, folder, diff, staged, Git, URL and session references | Typed authorized context references with artifact/provenance limits | core |
| Personalities and SOUL files | Versioned persona profiles, import/export and no authority semantics | core |
| Prompt caching | Stable-prefix policy, invalidation events and provider telemetry | core |
| Checkpoints and rollback | Per-turn workspace checkpoint/diff/restore layered on isolated worktrees | core |

## Memory, skills and self-improvement

| Capability | Automonique adaptation | Track |
|---|---|---|
| Persistent memory and user profile | Typed user/workspace/team/task memory with review, correction and deletion | core |
| Session FTS5 search and surrounding history | Tenant-filtered SQLite FTS with exact message citations | core |
| Background memory review | Budgeted review proposals; never silent policy mutation | expansion |
| External memory providers/Honcho-style user modeling | Sandboxed memory-provider SPI with provenance and consent | optional |
| Learning journey/memory graph | SDK read model linking evidence, memories, skills and outcomes | expansion |
| agentskills.io skills and progressive disclosure | Native signed skill runtime and scoped discovery | core |
| `/learn` and agent-created skills | Evidence/test-backed learning proposals with approval policy | core |
| Skill Hub, direct URLs, GitHub taps and well-known registries | Allowlisted catalogs, signature/license/digest verification | expansion |
| Skill bundles and conditional fallback skills | Revisioned profile/workspace bundles and capability predicates | core |
| Curator stale/archive/pin/backup/consolidate | Non-destructive lifecycle service with optional reviewed consolidation | expansion |
| Skill secure setup/config | Typed secret/config requirements resolved outside skill prose | core |

## Tools, extensions and development intelligence

| Capability | Automonique adaptation | Track |
|---|---|---|
| Built-in tools and per-platform toolsets | Canonical tool registry; effective grants intersect tenant/profile/workspace/channel policy | core |
| Tool search/deferred schemas | Authorization-filtered catalog search and on-demand schema loading | core |
| Programmatic tool calls from Python | Bounded sandboxed workflow runtime over capability RPC; add WASI/JS/Python adapters | expansion |
| MCP stdio/HTTP client and sampling | Native managed MCP client; sampling is separately budgeted/policy checked | core |
| Agent platform as MCP server | Scoped Automonique MCP server over local/HTTP identity | expansion |
| Plugin tools, memory and context engines | Signed out-of-process extension SPI | core |
| Gateway/plugin/shell hooks | Typed observer/filter/transformer/context/trigger hooks with deterministic ordering | core |
| Desktop plugins and backend namespaces | Signed UI extensions plus separately sandboxed backend extension | expansion |
| TUI widget apps | Declarative/WASI widgets over read-only SDK projections | optional |
| LSP manager | Workspace-scoped sandboxed language servers and normalized diagnostics | expansion |
| Git/worktree review tooling | Workspace diff/review/checkpoint/stage/commit/push/PR proposal services | core |
| Autonomous implementation loop | Separate `automonique-lab` work DAG with bounded workers, owner-configurable review passes and human merge/deploy authority | core |
| Measurable objectives and commit evidence | Hill-climbability objective plus content-addressed correctness/performance/prompt/safety metrics attestation referenced by each commit | core |
| Self-hosting bootstrap | Signed SH0 seed and manifest; stable builds an isolated candidate that self-builds/reloads under stable observation | core |
| Candidate verification | Stable verification, provenance/SBOM and reproducible A1/A2 plus optional clean A3 comparison before promotion eligibility | core |
| Recursive self-improvement | Evidence-driven bounded proposals/loops with external review for scope, policy, metrics, privilege, release and production | core |
| Computer-use driver | High-risk accessibility/screenshot adapter in disposable/eligible environment | optional |

## Agents, goals and orchestration

| Capability | Automonique adaptation | Track |
|---|---|---|
| Foreground/background delegation | Durable work-DAG nodes or provider-native children with explicit lifecycle | core |
| Orchestrator depth/concurrency | Scheduler budgets, spawn depth and child capability limits | core |
| Persistent goals and subgoals | Goal aggregate, completion contract/judge, waits and continuation budget | core |
| Kanban multi-profile work queue | Work-graph command-center/Kanban projection with fenced claims | core |
| Mixture of Agents | Tool-free reference advisors plus acting model, privacy/cost policy | optional |
| Independent spawned agents | Session-scoped execution hosts with isolated workspaces and attachable TUI panes | core |
| Agent profiles | Persona/model/tools/skills/memory/channel package distinct from tenant/workspace/sandbox | core |
| Profile distributions | Signed import/export packages excluding secrets and private memory by default | expansion |

## Automation and integration

| Capability | Automonique adaptation | Track |
|---|---|---|
| Natural-language/cron/interval/one-shot jobs | Reviewed canonical schedule with timezone/DST examples | core |
| Job edit/pause/resume/run/remove/history | Revisioned automation service and SDK/TUI/dashboard/CLI clients | core |
| Per-job skills/model/provider/workdir/delivery | Immutable occurrence plan with ordinary policy/sandbox | core |
| Script-only zero-model jobs | Reviewed sandbox workflow with exact output delivery | core |
| Job output chaining | Typed artifact/output dependencies in work graph | expansion |
| Inbound webhook subscriptions | Signed routes, idempotency, filters, templates and sandbox transforms | core |
| Direct no-agent webhook delivery | Typed notification outbox with no model call | core |
| Outbound lifecycle webhooks | Durable signed subscriptions and receipts already planned | core |
| Watchers and boot/startup checklists | Leased trigger adapters creating durable input; no inline privilege | expansion |
| Automation blueprints | Signed templates with previewed schedules/capabilities | expansion |

## Models, credentials and provider behavior

| Capability | Automonique adaptation | Track |
|---|---|---|
| Broad model-provider plugins/custom endpoints | Provider catalog/SPI alongside primary Jcode/Claude/Codex/opencode adapters | expansion |
| Model aliases and per-session selection | Versioned profile aliases and explicit turn revisions | core |
| Provider sort/only/ignore/order/routing | Explainable tenant routing by capability, locality, cost and health | expansion |
| Fallback chains including auxiliary tasks | Policy-preserving independent fallback graphs | core |
| Credential pools and automatic rotation | Named same-boundary pools with billing/tenant/quota evidence | expansion |
| OAuth sign-in and subscription proxy | Scoped auth brokers/local proxy respecting provider terms | optional |
| Auxiliary models | Separate usage/policy for titles, compression, memory, media and evaluation | core |
| Prompt-cache-aware provider switching | Cache invalidation and context-cost warning | core |
| Local models/custom OpenAI endpoints | Provider plugin plus data-boundary/capability conformance | expansion |

## Public protocols and surfaces

| Capability | Automonique adaptation | Track |
|---|---|---|
| ACP server for IDEs | Automonique ACP host; separate from consuming provider ACP | expansion |
| OpenAI Chat Completions/Responses API | Authenticated compatibility adapter over canonical runs/sessions | expansion |
| Runs/jobs/sessions HTTP APIs | Native SDK remains complete; compatibility APIs map to same receipts | core |
| OpenAI-compatible local proxy | Short-lived loopback credential and audited provider use | optional |
| A2A/relay/Buzz-style clients | Authenticated task/relay adapters with cursors and media artifacts | optional |
| Web dashboard with embedded chat | SDK-only dashboard plus complete management surfaces | core |
| Native desktop | ShellDeck (Rust/GPUI) over the shared Rust protocol client; Linux/macOS first, Windows via dashboard/PWA until conformant | expansion |
| Remote desktop/gateway selection | OIDC/VPN remote profiles and multi-backend client | expansion |
| PWA/Termux/Windows native support | PWA and Termux clients; platform-specific execution capability matrix | optional |
| Shell completions/setup/doctor/update/uninstall | Signed lifecycle CLI with non-destructive modes | core |
| Import from OpenClaw/other agents | Dry-run import of persona, memory, skills, rules, settings and allowlisted secrets | expansion |

## Messaging and channels

| Capability family | Automonique adaptation | Track |
|---|---|---|
| Telegram, Slack and Discord | Existing/mapped connector contract | core |
| Microsoft Teams | Teams SDK connector, Cards and Graph/RSC as already planned | expansion |
| WhatsApp Cloud/device | Official Cloud first; isolated device compatibility adapter | optional |
| Signal, SimpleX and Matrix | Dedicated identity/key-custody connectors | optional |
| iMessage/BlueBubbles/Photon | Trusted macOS bridge connector | optional |
| Email and SMS | Threaded mail and compliant typed SMS provider | expansion |
| Mattermost, Google Chat, IRC | Standard connector packages | optional |
| LINE, DingTalk, Feishu, WeCom/Weixin, QQ, Yuanbao | Official API packages; unofficial paths experimental/quarantined | optional |
| Home Assistant, ntfy and notification webhooks | Device/notification connector packages | optional |
| Open WebUI/API server | OpenAI-compatible API client surface | expansion |
| Pairing, home target and channel directory | Durable actor pairing and authorization-filtered target directory | core |
| Cross-platform continuity | Explicit session/profile bindings, never display-name matching | core |
| Reactions, stickers and rich components | Bounded presentation/media capability per connector | expansion |
| Voice notes, Discord voice and Teams meetings | Consent-aware media workers and artifact retention | optional |

## Media, browser and external tools

| Capability | Automonique adaptation | Track |
|---|---|---|
| Voice transcription and TTS | STT/TTS adapter registries plus platform derivatives | expansion |
| Live voice and wake word | Local capture/hotword with no approval authority | optional |
| Vision and clipboard images | Artifact-backed multimodal context | expansion |
| Image generation | Provider adapter with provenance/cost/content policy | optional |
| Video generation | Provider adapter with long-running artifact workflow | optional |
| Web search and grounded extraction | Provider registry with citations and egress evidence | core |
| Browser automation | Local/remote isolated browser session adapter | expansion |
| Native computer use | High-risk capability requiring disposable desktop/session | optional |
| Tool gateway | Sovereign capability/usage gateway for approved media/web services | optional |
| Secret sources (1Password/Bitwarden/command) | Sealed secret-source SPI with pinned command helper | expansion |

## Execution, scale and research

| Capability | Automonique adaptation | Track |
|---|---|---|
| Local terminal backend | direct-process execution hosts, optional supervisor adapters and sandbox attestation | core |
| Docker | rootless OCI execution provider; no root daemon socket | expansion |
| SSH | attested remote execution provider | expansion |
| Singularity | Apptainer/Singularity HPC provider, optional Slurm | optional |
| Modal, Daytona, Vercel Sandbox | Independent cloud executor adapters with billing/data policy | optional |
| Persistent serverless hibernation/scale-to-zero | Explicit environment snapshot/hibernation/wake lifecycle | expansion |
| MicroVM/strong isolation | Strong-isolation provider already required for hostile-kernel work | expansion |
| Batch processing | Resumable dataset runner with bounded concurrency | research |
| Trajectory capture/compression | Redacted normalized export with provenance and consent | research |
| Evaluation/quality filtering/statistics | Assertion and tool/outcome metrics over synthetic/approved datasets | research |

## Customization and product polish

| Capability | Automonique adaptation | Track |
|---|---|---|
| Skins/themes | Shared accessible design-token format and sanitized imports | expansion |
| Desktop theme/plugin marketplace | Signed allowlisted UI catalog with review/revocation | optional |
| Rebindable shortcuts/localization | Shared command IDs, conflict detection and locale catalogs | expansion |
| Pet mascots | Signed presentation-only Monique/pet packs with zero authority | optional |
| Native notifications/quick entry | Desktop/PWA notification and global quick-entry controls | expansion |
| Learning graph/star map | Evidence-backed visualization described in context plan | expansion |

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
