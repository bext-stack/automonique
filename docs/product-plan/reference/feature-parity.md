# Feature-parity ledger

## Purpose

The rewrite preserves current behavior unless this ledger records an explicit retirement decision. Phase 0 converts every row into fixtures and an owner; phase exit gates cannot rely only on broad statements such as “dashboard parity.”

Status values:

- **preserve** — required before Rust becomes primary for the relevant scope;
- **replace** — preserve the user outcome through a new contract;
- **isolate** — retain behind a narrower optional security boundary;
- **retire only by decision** — measure use, document replacement and obtain explicit approval before removal.

## Intake, conversation and approvals

| Current capability | Target owner | Decision and acceptance |
|---|---|---|
| Slack Socket Mode messages, mentions, threads, commands and actions | `automonique-transports`, durable inbox | Preserve event claims, thread correlation, system-message exclusion and status reactions |
| Telegram polling, groups/private chats, commands, reply correlation and inline approval/cancel | `automonique-transports`, durable inbox | Preserve access policy, ordered per-scope processing and offset handoff |
| Canonical direct command registry, aliases, help, Slack presets and Telegram `setMyCommands` | `automonique-core`, operator protocol | Replace with one schema registry consumed by transports, SDK, TUI and dashboard |
| Deterministic query/chat/ticket/memory/chatter/clarify routing | `automonique-core` | Preserve exact fixtures and bounded model fallback |
| Short contextual follow-ups and pending Support composition intent | conversation/session repositories | Preserve explicit scope/revision; never infer from the newest unrelated message |
| Multi-ticket split | work graph and scheduler | Preserve independent child work plus parent/fan-in status |
| Human work approval | approval repository/policy | Preserve exact revision, eligible actor, expiry/supersession and transport recovery |
| Provider execution approval | provider approval repository | Preserve as a distinct approval class with exact turn/item coordinates |

## Support, GitHub and client delivery

| Current capability | Target owner | Decision and acceptance |
|---|---|---|
| Inklura client request portal | Support/Manage integration | Preserve tenant fencing, safe lifecycle, context additions and relaunch after review |
| Internal raw agent output versus staff-published client reply | artifact/publication workflow | Preserve: raw output is never client-visible by default |
| Support inbox query and formatting | Support service | Preserve bounded period/filter behavior and provider error normalization |
| Support email compose, exact sender/recipient/content review and send | Support workflow + outbox | Preserve exact-recipient/content revision and durable send reconciliation |
| GitHub issue as durable ticket truth | GitHub projection/reconciler | Preserve issue body/state/latest-comment inspection and conflict handling |
| Delivery-team completion heuristics and newest-occurrence reopen semantics | reconciliation policy | Preserve with language-neutral fixtures |
| Detailed GitHub report plus brief Slack completion/link/mentions | report artifact + outboxes | Preserve separation and idempotent publication |
| Dedicated deployment notifications channel | typed deploy webhook/outbox | Preserve fail-closed `SLACK_DEPLOY_CHANNEL`; never fall back to ticket intake |

## Memory, sites and operational context

| Current capability | Target owner | Decision and acceptance |
|---|---|---|
| Notes, notify rules and GitHub-to-Slack mapping | memory/notification repositories | Preserve role-scoped CRUD, matching and audit |
| Bounded per-user conversation history | conversation repository | Preserve limits, pruning and explicit clearing |
| Known PRISM sites and functional site summaries | workspace registry + site service | Preserve deterministic inventory and no-tools/read-only fallbacks |
| Account/access explanations | site/access service | Preserve read-only catalog behavior and reviewed change requests |
| Learned domain-to-server targets | workspace registry | Replace JSON file with revisioned actor/provenance records |
| Announce target before action and show site/server/IP | work events + Slack outbox | Preserve as a stop-check before workspace mutation |
| Persona, job envelope and untrusted-context labels | versioned policy bundle | Preserve and store persona/policy/template hashes on each attempt |
| PRISM knowledge-base files | versioned companion/tool bundle | Preserve exact release hash and workspace applicability metadata |

## Execution, companions and operator surfaces

| Current capability | Target owner | Decision and acceptance |
|---|---|---|
| Four selectable agent backends and session-prefixed resume | native adapters/session bindings | Replace prefixes with typed provider coordinates while preserving safe non-cross-provider resume |
| Bounded parallelism, per-thread serialization, pause and cancel | scheduler | Preserve and add admission/fairness policy |
| Live action, heartbeat, transcript, stderr and telemetry | event journal, runner spools, artifacts | Preserve bounded/redacted views and authoritative completion |
| `legacy-say` progress announcements | canonical `automonique-say` worker capability + outbox; forwarding alias during migration | Preserve scope/audience binding; no general Slack credential in workers |
| Screenshot proof | artifact pipeline | Preserve the current `legacy-shot` outcome under canonical `automonique-shot`; implementation may remain Python initially |
| Scoped application KV operations | companion contract | Preserve fixed typed operations; no arbitrary database access |
| Manage/Factory helper | fleet/integration service | Preserve supported API boundary and remove worker possession of factory credentials |
| Codex/worker guard hooks and sandbox launcher | versioned sandbox profiles/attestation plus runner policy bundle | Strengthen before native adapter cutover; Landlock, namespaces, cgroups, resource limits and provider/tool egress separation fail closed |
| Dashboard live tickets, approvals, history, ignored messages, settings, memory and targets | SDK-backed dashboard | Preserve service-by-service with a zero-private-route gate |
| Live Slack channel feed and legacy “post as the assistant” behavior | transport service rendered as Automonique/Monique after rebrand | Preserve with read/post capabilities separated and fully audited |
| Browser desktop notifications | SDK/dashboard notification service | Preserve permission UX and server-side notification state |
| Force ignored message into a ticket | intake/workflow service | Preserve exact original source identity and a fresh approval gate |
| Delete ignored/user-authored Slack message | critical Slack moderation workflow | Preserve only as explicit separately authorized action; never bundle with ordinary cleanup |
| Site digest and bounded one-shot assistance | site/restricted-provider services | Preserve bounded no-tools profiles, timeouts and authorization |
| Ops-command proposal classification | command proposal service | Preserve pure proposal behavior; execution remains reviewed elsewhere |

## Interactive shells and file transfer

The current dashboard exposes tmux-backed interactive shells plus upload/download. This is not ordinary agent-session attachment and does not become an implicit TUI feature.

Decision: **isolate and preserve during migration; retire only by explicit later decision.**

- Add an optional `automonique-shell` subsystem using dedicated transient units and a separate typed protocol; `legacy-shell` is only a forwarding migration alias.
- Default availability is local-only and disabled unless configured.
- Shell creation requires a `shell_operator` capability, explicit workspace, model/agent choice, TTL and resource policy.
- Shell attachment is observer/controller audited independently from provider sessions.
- Upload/download crosses the artifact service; no arbitrary base64 path bridge remains.
- Shells receive no Automonique control-plane credentials and cannot bypass workspace isolation.
- Idle reaping, cgroup cancellation, terminal restoration and multi-attach behavior remain tested.
- `automonique-tui` remains an agent cockpit, not a general shell; `automoniquectl shell attach` or the secured dashboard terminal is the retained operator surface. Legacy commands forward during their compatibility window.

## Expansion channels

Teams and Discord are new product surfaces rather than current-parity rows, so they do not block replacement of an existing Slack/Telegram scope. Once enabled for a tenant they acquire the same non-regression obligation: installation identity, mention/command routing, follow-ups, approvals, artifacts, notifications, deletion/tombstone behavior and reconciliation must remain covered by fixtures.

The common contract and full transport inventory are in the [connector catalog](../requirements/connector-catalog.md); the first two detailed implementations are in [Teams and Discord integrations](../requirements/channel-integrations.md). Notification-only Teams Workflow or Discord webhook targets may ship before conversational connectors, but they never satisfy conversational parity.

## Expansion platform ledger

New platform capabilities do not block replacement of existing legacy behavior, but each enabled capability becomes a supported, fixture-backed surface. The neutral [external capability ledger](../requirements/external-capability-ledger.md) tracks complete coverage and disposition across:

- deterministic context, typed references, memory, skill catalogs, learned-skill review and isolated agent profiles;
- the canonical tool registry, deferred discovery, workflows, hooks, signed extensions, MCP client/server operation and secret adapters;
- automations, natural-language schedules, persistent goals, inbound triggers and durable prompt steering;
- native and compatible agent APIs, relay/A2A operation, desktop/mobile clients and UI extensions;
- the complete connector catalog, identity/directory functions, attachments, meetings and proactive delivery;
- model routing and pools, multi-model aggregation, media/voice/vision, browser/computer use, LSP, portable executors, batch trajectories and evaluation.
- the SH0–SH6 bootstrap/self-hosting cycle, including stable/candidate isolation, candidate self-build/reload, independent provenance and external promotion.
- the one-command initial development launcher, finite seed program and verified handoff/retirement path into the permanent Rust lab.

Every row has one terminal disposition: core, independently gated optional capability, adapted replacement, or explicit rejection with owner and rationale. A label such as “plugin support” or “API compatibility” cannot close a row without protocol, safety and acceptance evidence.

## Product identity and legacy compatibility

The Automonique rebrand is additive product migration, not permission to break current behavior. Current legacy service, command, environment, path, SDK and protocol surfaces are classified under [ADR 006](../decisions/006-automonique-naming.md):

- canonical Automonique and supported legacy entry points reach one implementation, state store and authorization policy;
- Slack/Telegram commands and aliases retain deterministic command IDs, approval revisions and reply/follow-up context;
- durable input, work, approval, session, event and external-message IDs are never rewritten for presentation;
- an old deployment can upgrade and roll back without two active services or an implicit fresh database;
- removing a legacy surface is a measured, documented retirement decision with fixtures and consumer evidence.

## Reconciliation and audits

Current audit/reconciliation scripts become supported operations:

- `automoniquectl audit --preview [--full]` (or `legacyctl` alias) produces a signed/bounded mutation plan;
- `automoniquectl audit --apply <plan-id>` revalidates GitHub, durable state and Slack revisions before changing presentation state;
- targeted reconcilers cover stale/provisional/orphan approval messages, request reactions and feedback-thread completion;
- audits never delete user-authored Slack messages, close GitHub issues, approve work or start production work without the distinct required authority;
- SDK/TUI/dashboard may display plans and results but cannot weaken preview/apply separation.

## Companion and operational packaging

Every retained companion/script receives an owner, protocol, sandbox grants, version/hash, fixtures and replacement phase. TypeScript or Python companions need not be rewritten merely for language purity; they must ship as checksummed release assets with stable typed boundaries.

## Parity gate

The ledger becomes machine-readable. Each row links fixtures, target implementation, rollout flag and terminal disposition. Rust cannot become primary for a scope while a preserve/replace row for that scope is unimplemented, untested or silently routed to the old daemon.
