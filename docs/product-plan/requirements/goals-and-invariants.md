# Goals and invariants

## Reload vocabulary

“Reload in place” means **generation handoff**, not process memory continuation:

- generation N continues serving while generation N+1 starts;
- N+1 proves readiness before acquiring intake and scheduler leases;
- independently supervised jobs keep running throughout;
- durable cursors let N+1 resume event consumption;
- N drains already-started callbacks and outbox writes, then exits;
- failure to start N+1 leaves N active;
- rollback is a handoff to an older compatible release.

## Product goals

1. Deploy Automonique without waiting for a 30-minute ticket to finish.
2. Preserve Slack, Telegram, dashboard, TUI, Manage, and agent-run continuity.
3. Make a daemon crash and a deliberate reload use the same recovery machinery.
4. Preserve current legacy behavior as an explicit legacy parity baseline before introducing new Automonique product behavior.
5. Produce a single auditable backend release with explicit protocol and schema versions.
6. Keep operator commands simple: `automoniquectl reload`, `automoniquectl rollback`, `automoniquectl status`, and `automoniquectl doctor`, with tested `legacyctl` aliases during migration.
7. Provide a first-class local TUI for inspection, command discovery, approvals and live-run control without bypassing Automonique's durable APIs.
8. Provide a supported TypeScript SDK covering every stable Automonique control-plane capability and provider extension contract.
9. Provide first-class Teams and Discord connector applications without moving routing, approvals, models, tools or durable authority into platform-specific services.
10. Introduce the Automonique/Monique identity additively: one service owner, one durable authority and no branding-driven ID rewrite.
11. Make context, memory, skills, tools, profiles and learned behavior inspectable, versioned and portable rather than hidden in prompts or one client.
12. Support durable automations, goals, triggers and queued steering through the same work and approval model as conversational requests.
13. Expose Automonique safely through native and compatible public agent protocols, a cross-platform desktop client and a broad connector catalog.
14. Treat model routing, media, browser/computer use and execution backends as governed capabilities with explicit provenance, budgets and isolation.
15. Maintain a neutral external-capability ledger so useful ecosystem behavior is either implemented, deliberately adapted, independently gated or explicitly rejected with rationale.
16. Implement the program through a durable, measurable AI development loop whose independent reviews, resource bounds and commit evidence raise confidence without granting autonomous merge or production authority.
17. Reach functional self-hosting: a trusted stable Automonique can develop, build, launch, evaluate and reload a candidate without surrendering the independent evidence, rollback and promotion boundary.

## Non-negotiable invariants

### Intake

- An input acknowledged to Slack or Telegram is durably recorded first.
- The durable input key is stable across generations.
- A generation may claim an input only through an atomic compare-and-swap.
- Replayed deliveries must resolve to the existing durable input, never a second ticket.
- Every Teams/Discord input is bound to one installation, external tenant/guild, conversation and stable actor identity before routing.
- Platform acknowledgement/defer is distinct from durable Automonique business acceptance and terminal completion.

### Approval

- Approval authority remains human and transport-bound.
- An approval references the exact immutable action/request revision that was reviewed.
- A reload cannot auto-approve, replace, or widen a pending action.
- Old approval buttons remain actionable when their durable gate remains pending.

### Scheduling

- Per-thread, per-issue, and per-agent-session serialization survives reload.
- Concurrency reservations are durable leases, not only in-memory counters.
- A generation that loses its scheduler lease cannot claim new work.
- An expired lease permits adoption only after execution-host liveness is checked.
- Admission is tenant-, actor-, workspace- and provider-aware; concurrency, rate and cost budgets are enforced before a claim.
- Fairness is deterministic and observable, and a provider circuit breaker cannot silently reroute work to a less capable backend.

### Execution hosts and workspaces

- A work item may have multiple attempts; an attempt references zero or one execution host (none before launch or after a pre-launch cancellation), but a session-scoped host may serve many attempts/turns.
- Attempt-scoped hosts terminate with their attempt. Session-scoped hosts survive daemon reload and retire only by explicit close, policy, failure or idle TTL.
- Every mutating attempt receives an isolated registered workspace at an immutable base revision.
- Concurrent attempts never share a writable checkout. Merge, promotion and deployment are explicit revision-checked actions with receipts.
- Dirty or non-Git sources require a captured snapshot and declared restore strategy before execution.

### Agent execution

- A job is a separate supervised unit whose lifetime is independent of `automoniqued`.
- The supervised runner owns the provider connection, session and active turn; Automonique daemon generations are replaceable subscribers.
- The prompt and environment are never serialized into a shell command line.
- Stdout events, stderr, status, and metadata remain separate.
- Events have a monotonically increasing sequence number.
- A consumer checkpoint advances only after a complete event is durably handled.
- Cancellation targets the whole job cgroup and produces a terminal status.
- Sandboxing and minimal worker environment remain mandatory.
- Provider capabilities are probed and pinned for the exact binary/protocol version.
- Preview deltas never become authoritative reports without a completed provider record or reconciliation.
- Provider-side approvals remain distinct from Automonique's outer ticket approval and are answered only through typed durable policy.
- An external/shared provider daemon may execute tools only when it proves the same tenant, account, workspace, credential and sandbox context as the execution host; otherwise it is isolated per security context.

### External mutations

- Slack posts/reactions, GitHub comments, Support mail, Manage reports, and privileged actions use stable idempotency keys where the remote API permits them.
- Otherwise, the local outbox records intent and reconciliation evidence before retry.
- A new generation may resend an outbox item safely.
- Terminal job state and its report intent are committed atomically.
- Every accepted mutation has a durable action receipt whose outcome can be queried after disconnect.
- Cards, buttons, selects and modals carry only opaque short-lived action tokens; authorization always rechecks actor, tenant, target revision and expiry server-side.

### Channel connectors

- Teams and Discord connectors are replaceable SDK clients. They do not own conversation truth, model sessions, approvals, workspaces or business effects.
- Mention/command intake is the channel/group default; all-message/RSC or privileged Gateway intents require a separately recorded capability and consent decision.
- Connector installations, manifests, permissions/intents and credential versions are durable tenant-scoped state.
- Platform roles, handles, emails and display names never imply an Automonique role.
- Inbound and outbound files cross the artifact service; platform download URLs/tokens never reach execution hosts.
- The product explicitly reports that Teams/Discord content crosses Microsoft/Discord infrastructure even when Automonique itself is self-hosted.
- Optional connector availability does not block a core daemon reload; protocol incompatibility for a currently attached connector does.

### Event history and replay

- Every authoritative domain transition appends a schema-versioned event in the same transaction as its state change.
- The global event ID is monotonically increasing and supports bounded snapshot-plus-cursor recovery for every operator client.
- Transport offsets, provider cursors and consumer checkpoints never substitute for the domain journal; each has its own namespace and authority.
- Replay and time-travel diagnostics never execute side effects.

### Reload

- At most one generation owns each exclusive lease: Telegram polling, scheduler claiming, reconciliation, and mutable settings.
- Slack generations may overlap because Slack can redeliver; durable event claims suppress duplicate business handling.
- Database changes remain readable and writable by both adjacent generations during overlap.
- The old generation is never told to exit before the new generation passes readiness.
- A timeout or failed readiness returns ownership to the old generation automatically.

### Operator clients

- The web dashboard, `automoniquectl`, and `automonique-tui` (plus supported legacy aliases) use the same typed server-side action contracts and durable authority.
- The TUI never reads SQLite, credentials, provider sockets, or runner spools directly.
- Client disconnects and daemon reloads cannot turn an unknown mutation result into an automatic retry.
- Every mutating request carries an idempotency key and the exact target revision.
- The canonical command registry, not duplicated client regexes, drives preset discovery and structured input.
- Any authorized active session can have multiple observers; attach/detach never owns or changes runner/provider lifetime.
- One TUI connection may multiplex N independently resumable session panes without letting a noisy pane starve the others.
- Interactive provider input has at most one valid controller lease per session/turn; merely focusing or restoring a pane never grants control.
- The dashboard and TypeScript compatibility integrations consume the published SDK; they have no private route or handwritten wire-type advantage.
- Rust protocol/schema artifacts generate TypeScript wire types and runtime validation from one source of truth.
- SDK retry, revision, idempotency, cursor and approval semantics are identical to TUI/CLI semantics.

### Context, memory, skills and profiles

- Every provider turn references an immutable context manifest that explains source order, inclusion, omission, compression and token accounting.
- A typed reference resolves through tenant/workspace policy; user text cannot smuggle an arbitrary host path or unreviewed remote resource into context.
- Memory and learned-skill proposals never grant tools, credentials, filesystem access, network access, roles or approval authority.
- Published memories and skills retain origin, revision, visibility, retention and revocation; deletion removes future use while preserving the required audit tombstone.
- Agent profiles compose existing policy-bound resources. Switching profile cannot widen authority without the same review required to change those resources directly.
- Search, embeddings and external memory indexes are rebuildable projections, never the sole copy of durable truth.

### Tools, extensions and interoperability

- The canonical tool registry and schemas are shared by daemon, SDK, TUI, dashboard, workflows, extensions and model-facing deferred discovery.
- Discovering a tool, MCP capability or hook does not authorize its use; every invocation is admitted against current actor, tenant, workspace, sandbox, credential and budget state.
- Extension and hook execution is deterministic, version-pinned and isolated. A failed or incompatible optional extension cannot prevent the core daemon from entering a safe mode.
- Public API, MCP, agent-control, relay and compatibility adapters project the canonical work state machine; they do not invent parallel approval, session or retry semantics.
- Local subscription or OAuth-backed provider adapters are opt-in, credential-isolated and disabled where provider terms or deployment policy do not permit them.

### Automation, goals and triggers

- Natural-language schedules round-trip to an explicit timezone, recurrence, next-fire preview and immutable automation revision before activation.
- Each firing has a stable occurrence key; reload, daylight-saving transitions, delayed clocks and retries cannot create duplicate business work.
- Webhook verification, replay protection, size limits, filters and transforms complete before an inbound payload becomes accepted input.
- Script-only jobs, chained workflows and persistent goals use normal identity, policy, approval, sandbox, budget, artifact and receipt contracts.
- Waiting goals consume no execution lease, and goal judges cannot silently raise budgets, widen authority or redefine completion.
- Steering, retry, reorder, cancel and undo are durable typed actions; undo is available only where a tool declares and proves a compensating operation.

### Models, media and execution backends

- Model selection is policy- and capability-aware, records exact model/provider/credential-pool revisions and never downgrades silently across a required capability or data boundary.
- Multi-model aggregation preserves each contribution and the deterministic or declared judging policy needed to explain the final answer.
- Voice, vision, image, video, browser and computer-use inputs and outputs enter through the artifact and consent model with bounded capture and retention.
- A browser session or computer-use worker receives no broader network, display, clipboard, credential or filesystem access than its reviewed task requires.
- Local, container, SSH, cluster, microVM and hosted executors consume the same portable execution specification and return equivalent fenced lifecycle evidence.
- Batch, trajectory and evaluation systems use scrubbed, policy-approved data and cannot replay historical side effects.

### Client and connector breadth

- Desktop, terminal, web and mobile/PWA surfaces share generated contracts and reconnect semantics; no surface receives a privileged private API.
- Every connector implements the common installation, identity, conversation, attachment, interaction, rate-limit and outbox contracts before product-specific features.
- Platform-specific convenience, including all-message access, proactive delivery, contacts, meetings or device bridges, is opt-in and cannot weaken Automonique's durable authorization.
- Optional connectors, desktop plugins, UI themes, media engines and remote executors graduate independently and cannot delay or destabilize the core release.

### AI implementation harness

- Development orchestration uses separate state, credentials, workspaces and authority from production Automonique.
- An implementer cannot approve its own candidate; blocking review requires new evidence, a corrected candidate or an explicit human disposition.
- File/crate leases and typed Git/build brokers prevent overlapping writes, destructive history operations, unbounded builds and direct merge/deploy actions.
- A green queue cannot be obtained by silently deleting/skipping tests, weakening assertions, refreshing unrelated goldens, stubbing behavior or widening unsafe/lint exceptions.
- Harness, worker or provider restart/reload preserves work DAG, attempts, todos, builds, review findings, budgets and evidence without duplicate commits.
- Commit metrics are reproducible, environment-labelled and content-addressed. Missing/incomparable values remain explicit, and the judged unit cannot silently redefine its baseline.
- Lines, commits, tokens, cost and agent count are descriptive; only contract/parity/correctness, safety and declared product objectives determine completion.
- Human authority remains required for protected-branch merge, release signing, production migration and deployment.

### Self-hosting and bootstrap

- Stable and candidate generations use distinct state, sockets, service identities, credentials, workspaces, artifacts, leases and outboxes; a candidate cannot bind a stable/production endpoint.
- Every candidate is pinned to immutable source, toolchain, environment and artifact digests. Source drift makes a build superseded, never silently current.
- Candidate-authored tests, metrics, logs and provenance are claims until observed or signed by the stable/independent control plane that owns the evidence.
- A candidate cannot write its own `independently_verified`, `promotable` or `promoted` transition, weaken its required checks or access protected-branch/release/deployment authority.
- Dirty builds are eligible for isolated development only and can never become release candidates.
- Self-host reload preserves or reconciles development sessions, workers, builds, todos, findings, cursors and receipts; failure returns to the last known-good seed.
- Bootstrap uses verified fixed artifacts and argument-vector recipes. It never treats an unsigned installer, mutable latest URL, password file or arbitrary shell string as authority.
- An independently authenticated rebuild has no unexplained output, dependency, generated-source or behavior mismatch before promotion eligibility.
- Recursive improvement is bounded by approved objectives, depth/concurrency/time/token/cost limits and external review for product, security, legal, metrics, privilege and production decisions.

### Security

- The reload coordinator does not receive Slack, Telegram, fleet, or provider credentials.
- Release selection accepts only root/user-owned immutable files with verified checksums.
- Admin and runner Unix sockets live below a mode-0700 runtime directory.
- Peer credentials are checked on every privileged local protocol.
- Secrets are not placed in argv, logs, manifests, or spool metadata.
- External identities resolve to durable actors and tenants before authorization; every privileged decision records policy revision and evidence.
- Provider and SDK credentials are scoped, rotatable and revocable. A descriptor grants access to a secret at launch; it never embeds the secret.
- Executables, schemas and credential descriptors are revalidated at the use boundary to prevent selection/use races.
- Canonical Automonique and legacy configuration never create two runtimes; conflicting values fail closed, and durable IDs are not renamed for presentation.

### Sandbox enforcement

- Every provider/tool execution has an immutable versioned sandbox policy digest and an effective enforcement attestation tied to tenant, account, workspace and host.
- Workspace, mount view, Landlock, process/cgroup, credential and network controls are layered; no single mechanism is called sufficient for the complete boundary.
- Tool/workload egress is distinct from trusted provider-control egress. Destination-aware policy uses a namespace plus reviewed egress broker; seccomp alone is not an allowlist.
- Nested tools, MCP servers and third-party extensions receive separate path, credential, egress and resource grants or are ineligible for the requested profile.
- CPU, memory, PID, I/O, runtime, scratch, workspace, spool and artifact budgets are bounded and observable.
- A follow-up can reuse a session host only with an identical or narrower sandbox; widening authority creates a new reviewed revision and normally a new host.
- Missing kernel/systemd enforcement, attestation drift or an orphan boundary fails closed and quarantines affected provider work.
- Same-kernel isolation is not marketed as a VM boundary. Work requiring hostile-kernel isolation waits for the conformant `strong-isolation` profile.

### Artifacts and data governance

- Attachments and generated files enter a content-addressed artifact store with digest, size, media type, provenance, tenant, visibility and retention policy.
- Workspaces receive artifacts by explicit materialization; providers never receive arbitrary host paths from a client payload.
- Raw provider records, reasoning-sensitive data and client-published reports have distinct visibility and retention classes.
- Tenant export, legal retention, deletion and tombstone workflows are auditable and cannot erase evidence needed to prove a still-pending action.

### Recovery and operability

- A backup is a consistent recovery set: database, artifact manifests/objects, encrypted configuration, independently recoverable credential path, release manifest and workspace metadata.
- Restore is regularly rehearsed on a clean host and proves cursors and idempotency before transports or outboxes are enabled.
- Pause, drain, maintenance-read-only, disconnected-recovery and provider-quarantine modes are explicit durable states.
- Reconciliation produces a reviewable plan before applying typed repairs; it never hides drift through ad hoc SQL.

## Service objectives

These are initial acceptance targets, not performance promises:

| Measure | Target |
|---|---:|
| Reload readiness | under 10 seconds normally |
| Intake pause during lease transfer | under 2 seconds |
| Dashboard reconnect | under 5 seconds |
| TUI reconnect/resync | under 5 seconds normally |
| Lost accepted inputs | 0 |
| Duplicate business actions | 0 |
| Interrupted active jobs during reload | 0 |
| Automatic rollback after failed readiness | under 15 seconds |
| Supported generation overlap | N and N+1 |
| Backup recovery point objective | 5 minutes or less |
| Clean-host recovery time objective | 30 minutes or less |

## Current gaps this rewrite must close

- The current registry changes persisted `running` and `queued` tickets to `error` at boot.
- Slack scheduling and child handles are partly in memory.
- Job ownership is split between Bun, tmux, Bash, and agent processes.
- Process-tree cancellation logic exists in more than one place.
- Some external actions are durable, while others depend on a live callback finishing.
- The dashboard server and transport loops are tied to the Bun process lifetime.
- Existing safe release waits for idle rather than handing ownership to a new generation.
