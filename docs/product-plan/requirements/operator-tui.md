# Automonique operator TUI (managed client)

## Implemented production slice

The maintained JCode fork provides the terminal runtime while Automonique owns
the protocol and action semantics. The shipped slice includes the
`automonique tui` launcher, authority-qualified overview/run/session/approval/
model/failure/receipt views, exact server-advertised action-registry resources,
durable new request and session-follow-up composition, receipt reconciliation,
observation attachments, controller leases, dynamic bounded panes, local
owner-only workspace restoration, stale/read-only reconnect behavior and
fixed-size/reducer/PTY conformance coverage. Unsupported future operations are
absent from the daemon's advertised action list and therefore cannot appear as
client-side guesses.

## Purpose

Automonique needs a first-class terminal interface for daily operation, not merely CLI subcommands or a tmux pane. The TUI is a local operator client over the durable control and event protocols. It presents the same state and performs the same typed actions as the web dashboard without owning business logic, reading SQLite directly, or connecting to agent providers.

The target surface is `automonique tui`. `legacy-tui` and `legacyctl tui` forward to the same client during the declared compatibility window. It is shipped in every Rust release and works comfortably through SSH in an ordinary terminal.

## Boundary and trust model

```text
terminal
  └─ automonique tui (or legacy-tui alias)
       └─ $XDG_RUNTIME_DIR/automonique/admin.sock
            └─ active automonique daemon generation
                 ├─ durable store
                 ├─ runner control sockets
                 └─ external transports/outboxes
```

- The TUI talks only to the versioned local admin socket. Migrated installs may resolve the legacy socket through the compatibility locator, but never both. It never opens `legacy.db`, `.env`, provider sockets, or execution-host spools directly.
- The server authenticates the Unix peer credentials and projects an operator role/capability set. TUI visibility does not imply mutation authority.
- Remote use is SSH to the host; the admin socket is not exposed as a TCP service for the TUI.
- All mutations use typed requests, idempotency keys, expected revisions and server-side authorization.
- A disconnect after submission has an `unknown` client state until the TUI reconciles the idempotency key. It must never invite a blind retry.
- Secrets, hidden reasoning and unbounded provider payloads are not rendered. Raw diagnostic events require an explicit view and remain bounded/redacted.

## Interaction model

The default screen is usable without memorizing commands:

```text
┌ Automonique 2a353cc │ ACTIVE N+1 │ queue 2/3 │ approvals 1 │ providers 4/4 ┐
│ Overview  Requests  Approvals  Runs  Providers  Reloads  Failures     │
├──────────────────────────────┬─────────────────────────────────────────┤
│ filtered list/table          │ selected record, timeline or preview    │
│                              │                                         │
├──────────────────────────────┴─────────────────────────────────────────┤
│ : command palette / request composer                         ? help    │
└────────────────────────────────────────────────────────────────────────┘
```

Core views:

- **Overview:** service health, active/draining generation, intake state, concurrency, queue, pending approvals, active runs, provider health, outbox lag and recent failures.
- **Requests:** durable inbox/work items, origin, route, selected command, approval revision, GitHub ticket and lifecycle timeline.
- **Approvals:** Automonique work approvals and provider execution approvals in separate sections, with exact reviewed action/diff, scope, requester, expiry and current revision.
- **Runs:** active/recent runs, backend/mode/model, provider session/turn, elapsed time, heartbeat, token/cost telemetry, current tool and terminal outcome.
- **Run detail:** normalized event timeline with preview text visually distinct from authoritative messages; follow-up/steer, cancel and attach actions appear only when capabilities allow them.
- **Agent cockpit:** a configurable N-pane workspace attached to several active runs/provider sessions at once.
- **Providers:** Jcode/Claude/Codex/opencode binary and schema versions, auth/model availability, negotiated capabilities, active sessions, degraded modes, reconnects and fallback reasons.
- **Reloads:** installed/current/previous releases, compatibility checks, handoff phases, generations, leases, adopted runs and rollback readiness.
- **Failures:** failed work, dead-letter/outbox rows, reconciliation state and bounded diagnostic context.
- **Settings/health:** live settings allowed by policy plus read-only host, database, process/supervisor, sandbox and provider diagnostics.
- **Sandbox detail:** requested/effective profile, attestation/kernel health, bounded filesystem/egress/tool/credential summaries, resource pressure, violations/quarantine and refusal reason without exposing secrets or host paths.
- **Work graph:** parent/child work, dependencies, subagents, retries, critical path and blocked nodes without flattening orchestration into log text.
- **Artifacts:** attachment/diff/report provenance, visibility, retention and reviewed download/publish actions.
- **Why:** the matched route, identity and role, policy revision, approval evidence, execution-plan/persona hashes, capability selection and fallback reason behind a decision.
- **Budgets:** tenant/provider concurrency, token/cost/rate reservations, circuit breakers and throttling reasons.
- **Context/session:** component/token breakdown, references and provenance, compression lineage, prompt-cache state, queued input, retry/undo/stop and checkpoints.
- **Memory/learning:** typed memories, FTS session search, learning evidence graph, skill catalog/bundles/proposals and curator state.
- **Goals/automations:** completion criteria/waits, schedules/occurrences, board/Kanban claims and signed trigger history.
- **Tools/MCP/extensions:** effective toolsets, deferred tool search, MCP health/filters, manifests/hooks and quarantine without arbitrary code/config editing.
- **Profiles/models:** persona/profile defaults, routing/fallback/pools/auxiliaries/MoA and explicit data/billing boundaries.
- **Connectors/protocols:** complete connector catalog plus ACP/OpenAI/MCP/A2A/relay health and durable coordinate mapping.
- **Media/executors/evaluation:** artifact-backed media/browser work, remote environment/hibernation state and consented batch/evaluation progress.

## Commands without regex ambiguity

The TUI consumes a server-described command registry. Each command includes its stable ID, label, aliases, required fields, field types, authorization, approval policy and whether it supports dry-run preview. The client renders a searchable command palette and structured forms from that schema.

This avoids duplicating the current preset/regex logic in another UI:

1. The operator selects a canonical command or starts a free-form request.
2. Structured commands collect and validate fields locally, then the server validates them again.
3. The server returns a canonical action preview and immutable revision.
4. The TUI clearly shows whether submission answers a question, creates a request, creates an approval gate, or performs an already authorized local operation.
5. Approval always targets the exact returned revision.

Free-form requests enter the same durable inbox/router as Slack and Telegram with origin `tui` and the authenticated local operator identity. Selecting an existing Automonique/provider session binds a follow-up explicitly; nearby text or the currently highlighted row must never imply conversational context on its own.

## Action safety

- Read-only navigation and filtering need no confirmation.
- Reversible operational actions such as pause/resume use a concise confirmation showing current and requested state.
- Approve/reject, cancel, reload, rollback, retry delivery, change concurrency and provider permission responses show the exact target, revision and consequence.
- Destructive or privileged actions are never represented as arbitrary shell input. They follow Automonique's inherited proposal/review boundary.
- Bulk actions require an explicit selected set and count; selection is cleared after data revision changes.
- Dangerous actions cannot be bound to a single unmodified key. Their default flow is palette/action selection, preview, then confirmation.
- The client never auto-approves a provider request merely because the outer Automonique work item was approved.

## Live run interaction

The run view subscribes to Automonique's normalized durable event stream from a `last_event_id`. It can display preview deltas for responsiveness, but rebuilds final content from authoritative completed records after reconnect.

Available controls are capability-driven:

- `follow up` starts a new turn on the explicitly selected provider session;
- `steer` modifies an active turn only when the adapter advertises safe steering;
- `answer` resolves provider user-input/permission requests through the typed approval bridge;
- `cancel` targets the Automonique run/cgroup and reconciles provider terminal state;
- `attach` opens a focused event/terminal view, not a tmux session and not an uncontrolled shell.
- `queue/edit/withdraw` changes only provider-unaccepted input by expected revision;
- `retry/undo/compress/checkpoint restore` creates explicit durable actions and never erases audit history.

The TUI does not emulate provider-native interfaces. Provider-specific details may be inspected, but all control flows through normalized Automonique operations.

## Attach and detach semantics

An authorized operator can attach to any active or reconcilable Automonique run/provider session regardless of whether it originated in Slack, Telegram, Fleet, Support, the dashboard, another TUI, or a scheduled job. When an adapter exposes a stable subagent identity and independent event stream, that subagent may also be attached as its own pane; otherwise it remains nested in the parent session timeline. Attachment is an observation subscription, not process ownership:

- multiple TUIs and dashboard clients may observe the same session concurrently;
- attaching never pauses, resumes, restarts or changes the provider session;
- detaching removes only that client's subscription and pane; the runner and provider session continue untouched;
- closing or crashing the TUI implicitly detaches all of its observer handles;
- reattaching begins from the pane's last durable event cursor or a bounded authoritative snapshot;
- completed sessions may be attached read-only for timeline replay while retained;
- visibility is filtered by the authenticated operator's scope before the session appears in the attach picker.

Each attachment has a client-local `pane_id` and a server-issued `attachment_id` bound to `run_id`, `provider_session_id`, optional active `provider_turn_id`, event cursor and observed capabilities. Provider identifiers are never inferred from pane position or display title.

Observation is fan-out; interactive control is arbitrated separately. `take control` acquires a short renewable, durable lease for low-latency steering or provider input on one session. Other clients remain observers and can see who holds control. Lease loss immediately makes the pane read-only. Normal durable follow-up requests, approvals and authorized emergency cancellation still use their own revision/idempotency contracts rather than being hidden inside the controller stream.

## N-pane agent cockpit

The cockpit displays any negotiated number of attached sessions up to a configurable client/server safety cap. “N” is dynamic, not hard-coded to two or four.

Each pane contains:

- agent/provider, model, integration mode and health;
- Automonique run plus provider session/turn identity;
- running/waiting-approval/reconnecting/terminal state, elapsed time and heartbeat age;
- current tool/subagent and bounded token/cost telemetry;
- scrollable normalized event timeline with preview and authoritative records visually distinct;
- controller/observer status and capability-driven actions.

Layouts include automatic tiling, rows, columns, a grid, tabbed panes, and focused/maximized mode. Operators can add from a searchable live-session picker, detach a pane, reorder/pin panes, save a local layout, and restore attachments by durable session identity. A restored layout never starts missing sessions or assumes control automatically.

One admin-socket connection multiplexes all pane subscriptions. The client maintains an independent cursor and reducer per attachment. Under high output:

- authoritative events and state transitions are never dropped;
- preview deltas may be coalesced per pane;
- unfocused panes render at a lower refresh rate while their reducers remain current;
- off-screen/tabbed panes show unread, approval and failure indicators;
- a global alert strip surfaces approvals, disconnects and terminal failures from every attached pane;
- per-pane bounded buffers spill into cursor-based history rather than growing terminal memory without limit.

Keyboard actions always apply to the visibly focused pane. Multi-pane/bulk actions require an explicit selection set and confirmation listing every durable target; focus alone can never authorize a bulk cancellation or follow-up.

The focused pane has a session input bar. Sending text chooses an explicit operation—new follow-up, queued input, active-turn steering, or provider-request answer—based on advertised capabilities and current state. The TUI shows that choice before submission; it never guesses from timing or silently starts a replacement session.

Interactive POSIX shells and file transfer are intentionally outside this cockpit. If the isolated legacy shell subsystem is enabled, the TUI may show its status and launch an authorized `automonique shell attach` (or legacy alias), but it never proxies shell bytes or broadens an agent controller lease into shell authority.

## Protocol behavior

The admin protocol needs these primitives shared by the TUI, web dashboard and the `automonique` CLI:

1. `GetSnapshot(view, filters)` returns a bounded revisioned snapshot and current event cursor.
2. `Subscribe(after_event_id, topics)` streams ordered changes or declares that the cursor is too old and a new snapshot is required.
3. `Execute(action, target_revision, idempotency_key)` validates and durably records a typed mutation before replying.
4. `ListAttachableSessions(filters)` returns only authorized active/reconcilable or retained sessions and their observable capabilities.
5. `Attach(target, after_event_id)` creates a fan-out observer handle; `Detach(attachment_id)` destroys only that handle.
6. `ClaimControl(target, expected_revision, ttl)` and `ReleaseControl(lease_id)` arbitrate interactive input independently of observation.
7. `ResolveContextReference`, `EditInputQueue`, `CompressContext` and `RestoreCheckpoint` expose exact preview/revision/receipt semantics.
8. Management snapshots/actions for memory, skills, profiles, goals, automations, tools/MCP/extensions, connectors/protocols and executors use the same generated SDK services as web/desktop.

Server capability negotiation tells the client which views, fields and actions exist. Adjacent Automonique releases remain compatible through additive fields and unknown-event tolerance. The TUI shows a clear upgrade-required state instead of attempting a mutation against an incompatible daemon.

## Reload and failure behavior

- `automonique tui` and its compatibility alias remain running while daemon generations hand off.
- During disconnect it switches to an obvious stale/read-only state, retains the last snapshot in memory, and retries the admin socket with bounded backoff.
- On reconnect it verifies the active generation and protocol, resumes from the last committed event cursor, or requests a fresh snapshot when retention was exceeded.
- Every pane independently reattaches by durable run/session identity and reconciles its cursor; panes do not all fail because one provider session disappeared.
- A controller lease is revalidated after reconnect and is never assumed to remain held merely because the pane was restored.
- Pending mutations are reconciled by idempotency key before controls are re-enabled.
- Selected records are retained by durable ID, not table position. If a record disappears or changes revision, the detail pane explains the transition and invalidates stale confirmation state.
- Terminal resize, suspend/resume, panic and signals restore the terminal cleanly. A TUI crash cannot affect Automonique or active execution hosts.

## Self-hosting cockpit

Development-authorized operators receive a separate self-hosting workspace over the development socket:

- stable/candidate generation and source/build fingerprint topology;
- bootstrap/toolchain/environment health and clean-host stage progress;
- build/test queues, deduplication, superseded results and background-task survival;
- candidate lifecycle from proposal through independent verification, with authoritative gate owner shown;
- fixture/replay/shadow/canary mode, namespace/credential boundary and external-effect status;
- self-build/reload/reconnect evidence, reproducibility comparisons, metrics deltas and rollback readiness;
- promotion proposal preview with exact source, artifact, provenance, compatibility and recovery revisions.

Candidate panes display an unavoidable canary banner. Candidate-generated text cannot render itself as independently verified, approved or promoted; those badges come only from stable development records. The production operator workspace never automatically switches to a candidate socket.

## Implementation shape

Ship `automonique tui` from the maintained MIT-licensed JCode fork rather than
building a second terminal interaction stack. JCode retains standalone mode;
managed mode uses an `AutomoniqueBackend` over the shared Rust client and must
not fall through to direct provider control. The compatibility binary is a thin
launcher or symlink, not another TUI codebase.

Reuse JCode's Ratatui/Crossterm terminal lifecycle, composer, viewport,
rendering, side-panel, picker and golden-test infrastructure. Automonique owns
the protocol reducers, authority-qualified view models and action semantics.
Keep these layers separate:

- protocol client and reconnect state machine;
- multiplexed attachment registry with one reducer/cursor per pane;
- pure snapshot/event reducer;
- view models and redaction/formatting;
- input/keymap and command-palette state;
- widgets/layout;
- context composer/completion, input queue and management view models;
- declarative/WASI dock-widget host and shared accessible skin tokens;
- dynamic tiling, focus and local workspace persistence;
- typed action preview/confirmation flow;
- terminal lifecycle guard.

The fork pins its upstream base, retains MIT notices on directly adapted files
and passes both standalone JCode tests and Automonique semantic conformance.

The deployed managed execution path consumes `SubmitRequest` and `FollowUp`
through Automonique's fenced scheduler and authenticated local execution lane.
It captures the normalized provider session identifier from the event stream,
persists the exact session-to-run binding, resumes only that binding, and
terminalizes the platform receipt through a restart-reconcilable outbox. The
cockpit therefore never guesses a provider session from a filename or recent
process, and an interrupted generation cannot blindly replay an uncertain
provider or platform effect.

Most behavior should be testable without a real terminal. Golden screen tests use a fixed terminal size and sanitized data; reducer/property tests cover duplicates, gaps, reorder rejection, reconnects and stale revisions.

## Accessibility and operability

- Support keyboard-only operation, discoverable help and configurable non-conflicting keymaps.
- Do not rely on color alone for status; include symbols/text and offer monochrome/high-contrast themes.
- Handle narrow terminals with a single-pane layout and horizontal truncation that never hides target identity in confirmations.
- Preserve copyable text and a JSON export command for already-redacted records.
- Show timestamps in operator-selected local time while retaining precise UTC in detail/export.
- Keep animation optional and low-frequency; active output must not starve input handling.

## Explicit non-goals

- Replacing Slack or Telegram as user-facing intake channels.
- Becoming a general shell, SSH client, terminal multiplexer or provider-native client.
- Direct database repair or secret editing.
- Keeping a terminal attached for work to continue.
- Giving local operators broader authority than Automonique's configured policy.
- Loading untrusted JavaScript/native plugins in the TUI process or letting a theme/widget represent approval state deceptively.

## TUI exit gate

The TUI is production-ready when it can attach concurrently to multiple sessions from all supported providers, rearrange/detach/reattach panes without affecting their runners, and remain open through repeated N -> N+1 -> N reloads while active runs stream, an approval is resolved, a command is submitted, and a cancellation occurs. Afterward every pane must match a fresh authoritative snapshot, control leases must have one owner or none, every mutation must appear once in the audit trail, no stale confirmation may execute, and the terminal must restore correctly after forced disconnect and process termination. Sandbox policy/attestation drift, resource pressure, denied egress and quarantine must be visible without exposing secrets/host paths or offering arbitrary policy weakening. The development cockpit separately passes SH0 bootstrap, candidate self-build/reload/fallback and independent-evidence rendering while proving that candidate text cannot forge stable verification or promotion state.
