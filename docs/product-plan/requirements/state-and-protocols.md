# State and protocols

The physical `legacy_*` tables and `legacy.*` protocol names below are the version-1 compatibility surface. Fresh public names move to Automonique only through the additive naming rules; durable IDs are never rewritten merely for branding.

## Versioning rules

Every local protocol message contains:

```json
{
  "protocol": "legacy.runner",
  "version": 1,
  "request_id": "uuid",
  "kind": "subscribe"
}
```

- Unknown protocol names and unsupported major versions fail closed.
- Additive fields are allowed within a major version.
- Security-sensitive enums reject unknown values. Read-only enums use an explicit `unknown` representation so additive values do not break adjacent-generation overlap.
- Message size and nesting are bounded before deserialization.
- Unix peer UID/PID credentials are verified before request parsing.
- Protocol compatibility ranges are declared in the release manifest.

JSON is preferred initially because it is inspectable during migration. Length-prefix each frame; never use newline framing for messages containing arbitrary model text. Large event bodies live in the spool and are referenced by sequence/offset rather than copied through the control socket.

## Durable tables

Names are provisional. All timestamps are UTC epoch milliseconds and IDs are opaque text.

### Generations and leases

```sql
CREATE TABLE legacy_generations (
  generation_id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  revision TEXT NOT NULL,
  pid INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('starting','ready','active','quiescing','draining','retired','failed')),
  protocol_min INTEGER NOT NULL,
  protocol_max INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  ready_at INTEGER,
  heartbeat_at INTEGER NOT NULL,
  failure TEXT
);

CREATE TABLE legacy_leases (
  name TEXT PRIMARY KEY,
  owner_generation TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

Required exclusive leases initially:

- `scheduler` — claims approved work;
- `telegram-poller` — owns `getUpdates`;
- `settings-writer` — applies runtime settings;
- `slack-reconciler` — performs scheduled reconciliation;
- `spool-reaper` — removes old run state.

Lease acquisition increments `epoch`. Every consequential write from a lease holder includes the observed epoch, preventing a paused old generation from acting after expiration.

### Durable inbox

```sql
CREATE TABLE legacy_inbox (
  input_id TEXT PRIMARY KEY,
  transport TEXT NOT NULL,
  transport_key TEXT NOT NULL UNIQUE,
  scope_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('received','claimed','routed','ignored','rejected','completed','failed')),
  route_kind TEXT,
  route_revision INTEGER,
  owner_generation TEXT,
  lease_epoch INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  error TEXT
);
```

Examples of `transport_key`:

- Slack: team ID plus event ID;
- Telegram: bot ID plus update ID;
- Teams: Microsoft tenant ID plus app/bot ID plus Activity ID;
- Discord: application ID plus interaction ID, or guild/channel plus message ID for Gateway intake;
- dashboard: authenticated idempotency key;
- Fleet: remote job ID plus transition version.

Payloads are bounded and contain only the input necessary for deterministic replay. Secrets and full provider credentials are not stored.

Inbox state describes transport ingestion and deterministic routing only. Approval, scheduling and execution states belong to work items; an input may route to zero, one or many work items without overloading the transport record with work lifecycle.

### Durable work and serialization

```sql
CREATE TABLE legacy_work_items (
  work_id TEXT PRIMARY KEY,
  input_id TEXT,
  origin_event_id INTEGER NOT NULL,
  scope_key TEXT NOT NULL,
  thread_key TEXT,
  issue_key TEXT,
  session_key TEXT,
  action_revision TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('pending_approval','approved','blocked','waiting_input','waiting_capacity',
     'queued','starting','running',
     'reporting','done','failed','cancelled')),
  owner_generation TEXT,
  owner_epoch INTEGER,
  active_attempt_id TEXT,
  queued_at INTEGER,
  started_at INTEGER,
  ended_at INTEGER,
  FOREIGN KEY(input_id) REFERENCES legacy_inbox(input_id),
  FOREIGN KEY(origin_event_id) REFERENCES legacy_domain_events(event_id)
);
```

`input_id` is optional because schedules, recovery actions and graph children can create work without a new transport input. `origin_event_id` is always present, providing a durable causal root. `scope_key` is the authorization and serialization scope; a transport thread is optional presentation context, not the universal work identity.

Serialization keys are claimed transactionally before `queued -> starting`. A unique active-lock table is clearer than reconstructing locks from in-memory sets:

```sql
CREATE TABLE legacy_work_locks (
  lock_key TEXT PRIMARY KEY,
  work_id TEXT NOT NULL,
  owner_epoch INTEGER NOT NULL,
  acquired_at INTEGER NOT NULL
);
```

Locks are released only with terminal work state or verified execution-host loss/reconciliation. Reload transfers ownership; it does not delete locks.

The `legacy_work_edges` table stores parent/child/dependency relations, required/optional semantics, fan-in policy and cancellation propagation; fresh schemas use the canonical mapping recorded by the name-migration manifest. The scheduler derives readiness from durable node/edge state; provider-native subagents receive graph nodes only when Automonique must independently approve, schedule, retry or report them.

### Attempts, execution hosts and event cursors

`work`, `attempt`, `execution host`, `provider session` and `turn` are distinct. A retry appends an attempt; it never overwrites prior evidence. A session-scoped host can execute multiple turns, while an attempt-scoped host is one attempt's process boundary.

```sql
CREATE TABLE legacy_execution_hosts (
  host_id TEXT PRIMARY KEY,
  unit_name TEXT NOT NULL UNIQUE,
  lifetime TEXT NOT NULL CHECK (lifetime IN ('attempt','session')),
  backend TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  workspace_context_hash TEXT NOT NULL,
  boot_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('starting','ready','busy','idle','hibernated','stopping','stopped','failed','lost')),
  binary_digest TEXT NOT NULL,
  schema_digest TEXT,
  idle_expires_at INTEGER,
  heartbeat_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE legacy_runs (
  run_id TEXT PRIMARY KEY,
  work_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  retry_of_run_id TEXT,
  host_id TEXT,
  execution_mode TEXT NOT NULL CHECK (execution_mode IN ('attempt','session_turn')),
  protocol_version INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('pending','starting','running','cancelling','done','failed','cancelled','lost')),
  last_event_seq INTEGER NOT NULL DEFAULT 0,
  last_event_offset INTEGER NOT NULL DEFAULT 0,
  host_heartbeat_snapshot_at INTEGER,
  started_at INTEGER,
  ended_at INTEGER,
  exit_code INTEGER,
  result TEXT,
  error TEXT,
  UNIQUE(work_id, attempt_no),
  FOREIGN KEY(host_id) REFERENCES legacy_execution_hosts(host_id)
);
```

A run has zero or one execution host. `host_id` remains null while pending or admission-blocked and may remain null for a pre-launch cancellation; the scheduler assigns it atomically with `pending -> starting`. Host identity includes tenant, provider account, workspace security context and boot identity so a resumable provider session cannot be attached through a weaker or different boundary.

The cursor advances in the same transaction as the durable effect derived from the event. Ephemeral dashboard rendering may read ahead, but terminal reporting may not.

### Provider instances, sessions and turns

Provider identities must not be compressed into the run row or one opaque session string:

```sql
CREATE TABLE legacy_provider_sessions (
  binding_id TEXT PRIMARY KEY,
  backend TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  provider_namespace TEXT NOT NULL,
  integration_mode TEXT NOT NULL,
  binary_version TEXT NOT NULL,
  binary_digest TEXT NOT NULL,
  schema_digest TEXT,
  provider_instance_id TEXT,
  provider_session_id TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(tenant_id, backend, provider_account_id, provider_namespace, provider_session_id)
);

CREATE TABLE legacy_provider_turns (
  turn_binding_id TEXT PRIMARY KEY,
  binding_id TEXT NOT NULL,
  work_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  provider_turn_id TEXT,
  state TEXT NOT NULL,
  last_source_cursor TEXT,
  started_at INTEGER,
  ended_at INTEGER,
  FOREIGN KEY(binding_id) REFERENCES legacy_provider_sessions(binding_id),
  FOREIGN KEY(run_id) REFERENCES legacy_runs(run_id)
);
```

Store bounded raw provider records in `legacy_provider_records`, keyed by host, run, turn, source sequence/cursor, event type, provider/schema digest and authority. Records reference an artifact when the bounded inline envelope is insufficient. Raw records enable replay after parser upgrades without letting unbounded output fill SQLite.

### Identity, approvals and controller leases

The durable authorization model follows the identity design: actors are tenant-scoped principals; external Slack, Telegram, GitHub, Support and SDK identities are mapped explicitly; role grants and policy revisions are queryable historical records.

`legacy_approvals` stores the immutable proposal/action revision, tenant, requesting actor, eligible approver policy, decision actor, transport evidence, expiry and terminal decision. Outer work approvals and provider permission approvals use distinct kinds.

`legacy_controller_leases` keys ownership by provider session/turn and records actor, client instance, lease epoch and expiry. Attach/focus never creates a lease. Expiry or disconnect revokes interactive input, not the provider session.

### Domain events and action receipts

The global `legacy_domain_events` and `legacy_action_receipts` tables define the journal contract. Every authoritative state transition and accepted mutation commits its journal row in the same transaction. Event IDs, aggregate revisions and action idempotency keys are globally resumable; transport offsets and provider cursors remain separate source checkpoints.

Consumer cursors are durable by consumer identity and topic. A client outside the retained range receives `resync_required` and a bounded snapshot operation. Replay may rebuild projections or explain history but never drains outboxes or repeats effects.

### Workspaces, artifacts and configuration

`legacy_workspaces` registers tenant, canonical source, immutable base revision/snapshot, isolation kind, writable path token, lock state and lifecycle. A run references one workspace revision; host paths are never accepted directly from API clients.

`legacy_artifacts` records content digest, size, media type, tenant, creator, provenance, visibility, retention class, encryption/key reference and storage locator. `legacy_artifact_links` binds artifacts to inputs, work, runs, turns, approvals and publications.

`legacy_settings_revisions` stores validated non-secret configuration snapshots. Secret fields contain only credential descriptors and versions. `legacy_transport_offsets`, `legacy_reload_epochs`, `legacy_audit_events`, `legacy_notifications` and `legacy_raw_provider_records` have explicit schemas and retention policies rather than being hidden JSON in unrelated rows.

### External connector installations and conversations

Teams and Discord require durable platform state rather than environment-only bot tokens:

- `legacy_connector_installations` binds platform application identity plus Microsoft tenant or Discord guild/user installation owner to exactly one Automonique tenant, manifest digest, allowed modes/scopes/intents, credential descriptor/version and lifecycle state;
- `legacy_transport_conversations` records personal/group/team/guild/channel/thread scope, external coordinates, proactive-send capability and retention class;
- `legacy_transport_messages` links source/outbound platform message revisions and deletion tombstones to input/work/outbox IDs;
- `legacy_transport_interactions` stores the hash of an opaque card/component/modal action token, target/action revision, eligible actor policy, acknowledgement and result receipt;
- `legacy_proactive_targets` stores a reviewed destination/audience capability with expiry and last permission validation;
- `legacy_connector_cursors` stores Discord Gateway session/resume sequence or another platform cursor under a fenced connector owner;
- `legacy_transport_rate_limits` stores observed provider buckets/defer-until state without hard-coded limits.

External identity uniqueness includes platform, application, external tenant/installation and immutable user ID. Teams UPN/email/display name and Discord username/roles remain attributes, not keys or authority. Interaction continuation tokens, webhook URLs and secret-bearing Teams service coordinates live in the credential store or short-retention encrypted records.

See [Teams and Discord integrations](channel-integrations.md) for the connector protocol and data boundary.

### Context, memory, skills and profiles

Prompt assembly is durable and explainable rather than an opaque string concatenation:

- `legacy_context_manifests` records the ordered, content-addressed inputs, token budget, omission decisions, compression lineage and policy revision for every turn;
- `legacy_context_references` resolves typed file, revision, URL, session, ticket, artifact and workspace references without accepting arbitrary host paths;
- `legacy_memories` stores tenant-scoped user, workspace, team, task and episodic memories with provenance, confidence, visibility, retention and revocation state;
- `legacy_memory_proposals` keeps model-suggested learning separate from reviewed publication, and `legacy_memory_provider_bindings` records optional external memory indexes without transferring authority;
- `legacy_skill_revisions`, `legacy_skill_catalogs` and `legacy_skill_installations` pin signed skill content, declared capabilities and tenant/workspace availability;
- `legacy_agent_profiles` and `legacy_profile_revisions` bind persona, model policy, toolset, memory visibility, sandbox and budget without creating a second source of authorization.

Search indexes are disposable projections over these authoritative records. Removing or superseding a memory, skill or profile revision invalidates affected projections and future context assembly while preserving the audit trail.

### Tools, extensions and MCP

`legacy_tool_revisions` and `legacy_toolsets` form the canonical registry used by every client and model. Each revision declares input/output schemas, required grants, execution class, timeout, idempotency semantics and implementation digest. Deferred tool search returns eligible descriptors only; invocation still passes policy and sandbox admission.

`legacy_extension_packages`, `legacy_extension_installations` and `legacy_hook_bindings` record signed package provenance, compatibility, grants, lifecycle and deterministic hook order. `legacy_mcp_servers` and `legacy_mcp_capability_snapshots` pin transport, trust boundary and discovered tool/resource/prompt schemas. Extension, workflow and MCP processes remain replaceable workers whose state changes return through typed actions and receipts.

### Automations, goals and inbound triggers

- `legacy_automations` and immutable `legacy_automation_revisions` define schedules, event triggers, script/workflow steps, actor, workspace/profile and budget;
- `legacy_automation_firings` uses a unique trigger occurrence key so failover or clock recovery cannot enqueue duplicate work;
- `legacy_goals`, `legacy_goal_iterations` and `legacy_goal_judgements` preserve objective, stop conditions, budget, wait state and evidence across reloads;
- `legacy_trigger_endpoints` stores only public identifiers and policy; signing secrets remain credential descriptors;
- `legacy_trigger_deliveries` records request digest, replay window, filter/transform revision, resulting input ID and terminal receipt;
- `legacy_input_queue_items` gives steer, retry, reorder, cancel and undo requests durable identities rather than mutating an in-memory prompt queue.

Scheduler ownership is fenced separately from automation definition. A scheduled, webhook or goal-generated input enters the same authorization, approval, workspace and sandbox path as an interactive input.

### Public protocols, media and execution backends

`legacy_protocol_clients` binds API, MCP, ACP-compatible, relay and OpenAI-compatible callers to tenant actors, scopes, quotas and credential revisions. `legacy_protocol_runs` maps external protocol identifiers onto canonical work/run/turn IDs; compatibility projections never become a competing state machine.

`legacy_media_assets`, `legacy_transcriptions`, `legacy_speech_generations` and `legacy_media_derivations` reference artifact digests, model revision, consent/visibility and provenance. Browser and computer-use state records reviewed origin, capture policy and sandbox attestation; raw screenshots and recordings follow artifact retention rules.

`legacy_executor_registrations`, `legacy_executor_capability_snapshots` and `legacy_executor_allocations` describe local, container, SSH, batch, cluster, microVM and remote workers. An allocation is admitted from a portable execution specification and must return signed or mutually authenticated lifecycle evidence. Remote vendor IDs are coordinates, never authority.

### Development bootstrap and self-hosting state

Self-hosting uses a separate development database/schema namespace; these records never share production leases or outboxes:

- `automonique_dev_bootstrap_runs` records inspected/applied manifest revision, seed/toolchain/environment inputs, steps, recovery checkpoint and terminal evidence;
- `automonique_dev_source_states` records repository/base/tree/dirty patch/dependency/generated-source fingerprints;
- `automonique_dev_build_requests` records dedupe key, exact requested source/environment/target, queue lease, output artifacts and `superseded` detection;
- `automonique_dev_candidates` records immutable source/build digests and the monotonic proposed-through-promoted lifecycle;
- `automonique_dev_candidate_evidence` binds smoke, fixture, replay, shadow, self-host, reload, crash, rollback, comparison and independent-build evidence to its owning observer/builder;
- `automonique_dev_selfhost_sessions` binds actor, repository, stable/candidate generations, worktree, profile, budgets, pending tasks and recovery directive;
- `automonique_dev_promotion_plans` records expected stable/candidate/source
  revisions, required gates, configured build provenance, recovery proof,
  eligible external approvers and action receipt;
- `automonique_dev_trust_roots` records public builder/signer identities and revisions, never private signing or promotion credentials.

The candidate may append candidate-scoped observations through a bounded protocol but cannot update independently verified or promotion-owned fields. Stable imports only digest-verified evidence/artifacts. See [Self-hosting and bootstrap](self-hosting-and-bootstrap.md).

### Outbox

Use a single typed outbox or typed tables with the same contract:

```sql
CREATE TABLE legacy_outbox (
  outbox_id TEXT PRIMARY KEY,
  destination TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','sending','sent','dead')),
  owner_generation TEXT,
  owner_epoch INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  sent_at INTEGER,
  remote_id TEXT,
  reconciliation_evidence TEXT,
  last_error TEXT,
  UNIQUE(destination, idempotency_key)
);
```

Destinations include Slack message/reaction, GitHub report, Fleet lifecycle/report, Support mail, and privileged-action request. Remote APIs without idempotency support require reconciliation metadata sufficient to detect an already-applied action.

Outbox payloads are bounded, versioned envelopes containing immutable action data or artifact and credential references. They never embed reusable secrets, arbitrary filesystem paths or unbounded message bodies.

## Execution-host filesystem

```text
$XDG_RUNTIME_DIR/legacy/hosts/<host-id>/
├─ control.sock       0600 socket, peer credentials checked
├─ host-spec.json     0400 immutable sanitized host/lifetime spec
├─ attempts/          0700 immutable attempt specs and cursors
├─ events.ndjson      0600 append-only normalized runner events
├─ stdout.ndjson      0600 raw agent stdout when applicable
├─ stderr             0600 bounded/rotated
├─ status.json        0600 atomic replace
└─ manifest.json      0600 protocol, unit, pid and hashes
```

Long-term diagnostic spools may be under a private state directory rather than volatile runtime storage. After reboot Automonique classifies each session as resumable, hibernated, terminally interrupted or reconciliation-required from authoritative provider capability/evidence; it never calls a missing local process “running.”

## `RunSpec`

Required host/attempt fields:

- protocol version, work ID, run/attempt ID, host ID, host lifetime and backend;
- executable identity and exact argv vector;
- prompt delivery mode (`stdin`, protected file, or backend daemon session);
- workspace registry ID, immutable base revision/snapshot, isolated cwd token and read-only/write policy;
- environment allowlist values;
- timeout and resource limits;
- sandbox profile/version/policy digest, required enforcement features and filesystem/mount/network grants;
- separate trusted provider-control and model-directed tool/MCP egress policies;
- CPU, memory, PID, I/O, runtime, tmp/workspace/spool/artifact quota reservations;
- nested tool/extension isolation requirements and accepted implementation digests;
- optional resumable backend session ID;
- expected native integration mode and eligible fallbacks;
- required and prohibited capability sets;
- context manifest, agent-profile, model-routing, toolset, skill-set and extension-set revision digests;
- automation/goal/trigger origin and causal event IDs when execution is not directly interactive;
- executor class, portability requirements and remote attestation policy;
- pinned provider executable digest and optional protocol/schema digest;
- policy revision, persona digest, deterministic execution-plan digest and scheduler budget reservation;
- tenant/actor identity, artifact grants and versioned credential descriptors (never secret values);
- expected output/event dialect and approval policy.

The host receives specs through inherited descriptors or mode-0600 files created with exclusive semantics. It rejects symlinks, unexpected ownership, unknown fields, path escapes, embedded NUL, oversized values and unsupported policies. Executable/file descriptors and credential versions are verified again immediately before launch/use to close time-of-check/time-of-use races.

Before provider input, the host persists the effective sandbox attestation: real workspace paths, namespaces, process-group/cgroup/backend identity, kernel/boot identity, optional-supervisor hardening properties, Landlock/seccomp/egress digests, resource limits, credential delivery classes and external-daemon enforcement evidence. Reload adoption compares this attestation rather than reconstructing a boundary around the live process. See [Sandbox management](sandbox-management.md).

## Runner event envelope

```json
{
  "protocol": "automonique.runner.event",
  "version": 1,
  "run_id": "r-...",
  "seq": 42,
  "at": 1785840000000,
  "kind": "agent_event",
  "payload": {"backend":"jcode","event":{}}
}
```

Runner-owned kinds include `started`, `provider_connected`, `session_bound`, `turn_started`, `preview_delta`, `message_completed`, `tool_event`, `approval_requested`, `usage_updated`, `heartbeat`, `cancel_requested`, and `terminal`. There is exactly one terminal event. Provider-specific records remain available by bounded reference and are normalized by `automonique-agents` into Automonique activity/result records. Every event states whether it is preview, authoritative, or synthetic. Compatibility releases may decode `legacy.runner.event` v1, but never emit it for a fresh installation.

## Operator client protocol

The TypeScript SDK, web dashboard, the `automonique` CLI and `automonique tui` share versioned snapshot, subscription, command-discovery and mutation contracts. Supported `legacyctl`/`legacy-tui` aliases reach the same protocol. The local TUI/Node SDK use the admin Unix socket; browser transport exposes the same domain records through HTTP/WebSocket.

- Snapshots are bounded, revisioned and include the durable event cursor from which live subscription may begin.
- Subscriptions accept `after_event_id` and selected topics. A cursor outside retention receives `resync_required`, never a silent partial stream.
- The command registry exposes stable command IDs, aliases, typed fields, authorization requirements, approval policy and dry-run support. Clients never copy command-routing regexes.
- Mutations include action ID, typed target, expected revision and idempotency key. The durable action receipt is queryable after a client disconnect.
- Responses distinguish `accepted`, `completed`, `rejected`, `conflict`, `unknown` and `resync_required` so a UI cannot mistake transport failure for operation failure.
- Additive fields and unknown read-only events are tolerated across adjacent releases; incompatible clients are read-only and receive an explicit upgrade requirement.
- Attachable-session discovery is authorization-filtered and returns durable run/session/turn identities plus observable capabilities.
- `Attach` creates a fan-out observer subscription with its own cursor; `Detach` destroys only that subscription and never changes runner/provider lifecycle.
- One connection may multiplex many attachment streams, each with independent backpressure, cursor and resync state.
- Interactive steering/provider input uses a short durable controller lease keyed by provider session/turn. Observation never acquires control implicitly, and control is revalidated after daemon/client reconnect.
- Server-side sequencing and expected revisions arbitrate follow-ups, approvals and cancellation independently of pane focus or controller ownership.
- Rust schemas/service descriptions are the wire source of truth; generated TypeScript types, validators and clients carry the same protocol version and schema digest.
- No supported SDK operation maps to a dashboard-only route. Node/Bun, browser, TUI and CLI see the same authorized domain capabilities through transport-specific projections.

See [TypeScript SDK](typescript-sdk.md) and [Automonique operator TUI](operator-tui.md) for clients built on this protocol.

## Database migration compatibility

- Each binary declares `[min_schema, max_schema]`.
- N+1 may start only if the current schema lies in its readable range.
- Migrations needed for reload are expand-only: new table, nullable column, index, or trigger.
- N and N+1 must both tolerate the expanded schema.
- Destructive/semantic cleanup occurs only after no supported rollback release requires the old shape.
- One migration lease exists, and backups/integrity checks precede schema changes.
- A release that cannot coexist with the selected rollback release is rejected before handoff.
- Adding a stored enum value is a compatibility change: first deploy readers that accept/represent it, then writers that emit it, and only later make it required.
- Event/action schemas are versioned independently of table schema. Adjacent generations must share a decode range for every event they may emit during overlap.
