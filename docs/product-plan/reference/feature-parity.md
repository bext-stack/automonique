# Feature-parity ledger

## Purpose

The rewrite preserves current behavior unless this ledger records an explicit retirement decision. Phase 0 converts every row into fixtures and an owner; phase exit gates cannot rely only on broad statements such as “dashboard parity.”

Status values:

- **preserve** — required before Rust becomes primary for the relevant scope;
- **replace** — preserve the user outcome through a new contract;
- **isolate** — retain behind a narrower optional security boundary;
- **retire only by decision** — measure use, document replacement and obtain explicit approval before removal.

## Owner decision, 2026-08-09 — unpinned rows become `replace`

Every row now carries a `Fixture` and an `Evidence` column, measured against
the legacy system's actual test suite rather than assumed. See
[`legacy-inventory.md`](legacy-inventory.md) for how the measurement was taken.

Of 39 rows: **15 are fully pinned, 5 are partially pinned, and 19 have no
behavioral evidence at all.**

For those 19 the owner has decided: **do not attempt behavioral preservation.**
There is no fixture, no specification, and the behavior exists only in legacy
source that the clean-room boundary keeps out of implementation. Reconstructing
it would mean guessing, and a guess recorded as `preserve` is a false claim of
fidelity.

Each of the 19 is therefore reclassified `replace`: Automonique provides the
*outcome* through a new contract of its own design, and the new contract is
authoritative. They cannot regress against a baseline that was never captured.

What this decision costs, stated plainly:

- behavior that users depend on but nobody wrote down may be lost, and will be
  discovered by its absence rather than by a failing test;
- four of the 19 are safety properties — fail-closed deploy routing,
  announce-before-mutation, separately-authorized deletion, and the scheduler's
  serialization guarantees. These must be **re-specified deliberately** in their
  target requirement documents, not left to emerge from implementation.

`R0-08` closes on these rows by writing that new contract, not by finding a
fixture. The remaining 20 rows keep their `preserve`/`partial` obligation and
their fixtures are named.

## Intake, conversation and approvals

| Current capability | Target owner | Decision and acceptance | Fixture | Evidence |
|---|---|---|---|---|
| Slack Socket Mode messages, mentions, threads, commands and actions | `automonique-transports`, durable inbox | Preserve event claims, thread correlation, system-message exclusion and status reactions | `slack-event-dedup` (1) | partial: claim-once only; mention/thread routing, command dispatch and action handling unpinned |
| Telegram polling, groups/private chats, commands, reply correlation and inline approval/cancel | `automonique-transports`, durable inbox | Preserve access policy, ordered per-scope processing and offset handoff | `telegram` (8) | pinned |
| Canonical direct command registry, aliases, help, Slack presets and Telegram `setMyCommands` | `automonique-core`, operator protocol | Replace with one schema registry consumed by transports, SDK, TUI and dashboard | `commands` (7) | pinned; 21 command IDs inventoried |
| Deterministic query/chat/ticket/memory/chatter/clarify routing | `automonique-core` | Preserve exact fixtures and bounded model fallback | `conversation` (41) | pinned; 13 route kinds inventoried |
| Short contextual follow-ups and pending Support composition intent | conversation/session repositories | Preserve explicit scope/revision; never infer from the newest unrelated message | `conversation-state` (3) | pinned; durable slots with expiry |
| Multi-ticket split | work graph and scheduler | **Replace** — rebuild to provide independent child work plus parent/fan-in status | **none** — replace by decision 2026-08-09 | no fixture; `tickets.partIndex`/`partCount` is the only surviving contract |
| Human work approval | approval repository/policy | Preserve exact revision, eligible actor, expiry/supersession and transport recovery | `slack-reconcile` (2) | partial: orphan adoption and no-reopen; creation, expiry, supersession and eligible-actor policy unpinned |
| Provider execution approval | provider approval repository | Preserve as a distinct approval class with exact turn/item coordinates | `codex-guard` (3) | partial: guard denials only; distinct approval class with exact turn/item coordinates unpinned |

## Support, GitHub and client delivery

| Current capability | Target owner | Decision and acceptance | Fixture | Evidence |
|---|---|---|---|---|
| Client request portal | support/fleet integration | Preserve tenant fencing, safe lifecycle, context additions and relaunch after review | `support-inbox-query` (3) | pinned |
| Internal raw agent output versus staff-published client reply | artifact/publication workflow | Preserve: raw output is never client-visible by default | `support-review-wiring` (3) | pinned |
| Support inbox query and formatting | Support service | Preserve bounded period/filter behavior and provider error normalization | `support-query`, `operational-query` (13) | pinned |
| Support email compose, exact sender/recipient/content review and send | Support workflow + outbox | Preserve exact-recipient/content revision and durable send reconciliation | `support-email-compose`, `support-email`, `support-mailer` (8) | pinned |
| GitHub issue as durable ticket truth | GitHub projection/reconciler | Preserve issue body/state/latest-comment inspection and conflict handling | `manage-sync` (14) | partial: split gates, idempotency, rollback, ack, retry; issue body/state inspection and conflict handling unpinned |
| Delivery-team completion heuristics and newest-occurrence reopen semantics | reconciliation policy | **Replace** — rebuild to provide with language-neutral fixtures | **none** — replace by decision 2026-08-09 | no fixture; language-dependent behavior, needs language-neutral fixtures if ever restored |
| Detailed GitHub report plus brief Slack completion/link/mentions | report artifact + outboxes | **Replace** — rebuild to provide separation and idempotent publication | **none** — replace by decision 2026-08-09 | no fixture; idempotent publication separation unproven |
| Dedicated deployment notifications channel | typed deploy webhook/outbox | **Replace** — rebuild to provide the fail-closed dedicated deploy-channel setting; never fall back to ticket intake | **none** — replace by decision 2026-08-09 | no fixture; fail-closed is a safety property and must be re-specified, not inferred |

## Memory, sites and operational context

| Current capability | Target owner | Decision and acceptance | Fixture | Evidence |
|---|---|---|---|---|
| Notes, notify rules and GitHub-to-Slack mapping | memory/notification repositories | **Replace** — rebuild to provide role-scoped CRUD, matching and audit | **none** — replace by decision 2026-08-09 | no fixture; `memory` table shape known (kind, match, notifyIds, text, creator) |
| Bounded per-user conversation history | conversation repository | **Replace** — rebuild to provide limits, pruning and explicit clearing | **none** — replace by decision 2026-08-09 | no fixture; `chat_messages` shape known (scope, role, content) |
| Known managed sites and functional site summaries | workspace registry + site service | Preserve deterministic inventory and no-tools/read-only fallbacks | `site-inventory`, `site-conversation` (6) | pinned |
| Account/access explanations | site/access service | Preserve read-only catalog behavior and reviewed change requests | `access-conversation` (4) | pinned |
| Learned domain-to-server targets | workspace registry | **Replace** — JSON file with revisioned actor/provenance records | **none** — replace by decision 2026-08-09 | no fixture; currently a JSON file, already slated for revisioned records |
| Announce target before action and show site/server/IP | work events + Slack outbox | **Replace** — rebuild to provide as a stop-check before workspace mutation | **none** — replace by decision 2026-08-09 | no fixture; safety-critical stop-check. `tickets.siteUrl`/`serverIp` are columns, not events |
| Persona, job envelope and untrusted-context labels | versioned policy bundle | Preserve and store persona/policy/template hashes on each attempt | `security-hardening` (8) | pinned; prompt-injection hardening |
| Site-platform knowledge-base files | versioned companion/tool bundle | **Replace** — rebuild to provide exact release hash and workspace applicability metadata | **none** — replace by decision 2026-08-09 | no fixture; ships as a companion bundle |

## Execution, companions and operator surfaces

| Current capability | Target owner | Decision and acceptance | Fixture | Evidence |
|---|---|---|---|---|
| Four selectable agent backends and session-prefixed resume | native adapters/session bindings | Replace prefixes with typed provider coordinates while preserving safe non-cross-provider resume | `codex-backend`, `jcode-backend`, `jcode-integration` (13) | partial: 2 of 4 backends; cross-provider resume safety unpinned |
| Bounded parallelism, per-thread serialization, pause and cancel | scheduler | **Replace** — rebuild to provide and add admission/fairness policy | **none** — replace by decision 2026-08-09 | no fixture; the scheduler core is entirely unpinned — largest single gap |
| Live action, heartbeat, transcript, stderr and telemetry | event journal, runner spools, artifacts | Preserve bounded/redacted views and authoritative completion | `spool-reader`, `spool-store`, `ndjson-lines` (33) | pinned; framing, retention, monotonic reads |
| `legacy-say` progress announcements | canonical `automonique-say` worker capability + outbox; forwarding alias during migration | **Replace** — rebuild to provide scope/audience binding; no general Slack credential in workers | **none** — replace by decision 2026-08-09 | no fixture; companion helper |
| Screenshot proof | artifact pipeline | **Replace** — rebuild to provide the current `legacy-shot` outcome under canonical `automonique-shot`; implementation may remain Python initially | **none** — replace by decision 2026-08-09 | no fixture; Python companion |
| Scoped application KV operations | companion contract | **Replace** — rebuild to provide fixed typed operations; no arbitrary database access | **none** — replace by decision 2026-08-09 | no fixture; companion helper |
| Fleet/provisioning helper | fleet/integration service | **Replace** — rebuild to provide supported API boundary and remove worker possession of provisioning credentials | **none** — replace by decision 2026-08-09 | no fixture; companion helper |
| Codex/worker guard hooks and sandbox launcher | versioned sandbox profiles/attestation plus runner policy bundle | Strengthen before native adapter cutover; Landlock, namespaces, cgroups, resource limits and provider/tool egress separation fail closed | `codex-guard` (3) | partial: allow/deny classes; sandbox launcher unpinned |
| Dashboard live tickets, approvals, history, ignored messages, settings, memory and targets | SDK-backed dashboard | Preserve service-by-service with a zero-private-route gate | `dashboard-ui`, `telegram-dashboard` (21) | pinned; 38 routes inventoried |
| Live Slack channel feed and legacy “post as the assistant” behavior | transport service rendered as Automonique/Monique | **Replace** — rebuild to provide with read/post capabilities separated and fully audited | **none** — replace by decision 2026-08-09 | no fixture; read/post capability split must be re-specified |
| Browser desktop notifications | SDK/dashboard notification service | **Replace** — rebuild to provide permission UX and server-side notification state | **none** — replace by decision 2026-08-09 | no fixture |
| Force ignored message into a ticket | intake/workflow service | **Replace** — rebuild to provide exact original source identity and a fresh approval gate | **none** — replace by decision 2026-08-09 | no fixture; `ignored` table shape known |
| Delete ignored/user-authored Slack message | critical Slack moderation workflow | **Replace** — rebuild to provide only as explicit separately authorized action; never bundle with ordinary cleanup | **none** — replace by decision 2026-08-09 | no fixture; enforced today by a separate delete credential — preserve that split |
| Site digest and bounded one-shot assistance | site/restricted-provider services | **Replace** — rebuild to provide bounded no-tools profiles, timeouts and authorization | **none** — replace by decision 2026-08-09 | no fixture |
| Ops-command proposal classification | command proposal service | Preserve pure proposal behavior; execution remains reviewed elsewhere | `privileged-actions` (3) | pinned; proposal-only boundary |

## Interactive shells and file transfer

The current dashboard exposes tmux-backed interactive shells plus upload/download. This is not ordinary agent-session attachment and does not become an implicit TUI feature.

Decision: **isolate and preserve during migration; retire only by explicit later decision.**

- Add an optional `automonique-shell` subsystem using a dedicated execution-backend boundary and separate typed protocol; `legacy-shell` is only a forwarding migration alias.
- Default availability is local-only and disabled unless configured.
- Shell creation requires a `shell_operator` capability, explicit workspace, model/agent choice, TTL and resource policy.
- Shell attachment is observer/controller audited independently from provider sessions.
- Upload/download crosses the artifact service; no arbitrary base64 path bridge remains.
- Shells receive no Automonique control-plane credentials and cannot bypass workspace isolation.
- Idle reaping, cgroup cancellation, terminal restoration and multi-attach behavior remain tested.
- `automonique tui` remains an agent cockpit, not a general shell; `automonique shell attach` or the secured dashboard terminal is the retained operator surface. Legacy commands forward during their compatibility window.

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
- the SH0–SH6 bootstrap/self-hosting cycle, including stable/candidate
  isolation, candidate self-build/reload, configured build provenance and
  external promotion.

Every row has one terminal disposition: core, independently gated optional capability, adapted replacement, or explicit rejection with owner and rationale. A label such as “plugin support” or “API compatibility” cannot close a row without protocol, safety and acceptance evidence.

## Product identity and legacy compatibility

Automonique identity is additive product naming, not permission to break current behavior. Current legacy service, command, environment, path, SDK and protocol surfaces are classified as compatibility surfaces:

- canonical Automonique and supported legacy entry points reach one implementation, state store and authorization policy;
- Slack/Telegram commands and aliases retain deterministic command IDs, approval revisions and reply/follow-up context;
- durable input, work, approval, session, event and external-message IDs are never rewritten for presentation;
- an old deployment can upgrade and roll back without two active services or an implicit fresh database;
- removing a legacy surface is a measured, documented retirement decision with fixtures and consumer evidence.

## Reconciliation and audits

Current audit/reconciliation scripts become supported operations:

- `automonique audit --preview [--full]` (or `legacyctl` alias) produces a signed/bounded mutation plan;
- `automonique audit --apply <plan-id>` revalidates GitHub, durable state and Slack revisions before changing presentation state;
- targeted reconcilers cover stale/provisional/orphan approval messages, request reactions and feedback-thread completion;
- audits never delete user-authored Slack messages, close GitHub issues, approve work or start production work without the distinct required authority;
- SDK/TUI/dashboard may display plans and results but cannot weaken preview/apply separation.

## Companion and operational packaging

Every retained companion/script receives an owner, protocol, sandbox grants, version/hash, fixtures and replacement phase. TypeScript or Python companions need not be rewritten merely for language purity; they must ship as checksummed release assets with stable typed boundaries.

## Parity gate

The ledger becomes machine-readable. Each row links fixtures, target implementation, rollout flag and terminal disposition. Rust cannot become primary for a scope while a preserve/replace row for that scope is unimplemented, untested or silently routed to the old daemon.
