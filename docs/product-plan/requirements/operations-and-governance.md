# Operations and governance

## Purpose

Reload safety is only one part of production safety. This document owns backup/restore, configuration and credentials, retention/privacy, scheduling/admission, observability/runbooks, reconciliation, extension supply chain and maintenance behavior.

The separate development control plane is defined in [AI implementation harness and commit metrics](ai-implementation-harness.md). It uses the same safety vocabulary but never shares production state, transport credentials, merge authority or deployment authority.

## Backup and disaster recovery

Back up one consistent recovery set:

- SQLite database plus WAL-consistent snapshot metadata;
- artifact metadata/blobs and deletion tombstones;
- non-secret configuration/workspace registry revisions;
- current/previous release manifests, schemas and SDK compatibility metadata;
- policy/persona/command/companion bundle hashes;
- context/compression manifests, memory/FTS state, skills/bundles/learning/curator state, profiles, goals, automations, boards and trigger definitions;
- tool/MCP/extension/hook manifests and enabled/quarantine revisions;
- recoverable secret material: either encrypted credential ciphertext plus a separately escrowed/rotatable recovery key, or external secret-provider references plus independently recoverable authentication and version metadata; never plaintext exports;
- audit/event journal through the snapshot watermark.

The backup coordinator acquires a short snapshot lease, uses SQLite's supported online backup mechanism, records an integrity check and hashes every component. It does not stop active execution hosts; events after the watermark belong to the next backup.

Initial acceptance objectives are RPO <= 5 minutes for durable control state and RTO <= 30 minutes on the same class of host. Artifact RPO may vary by class but must be declared. Production values remain configurable and visible.

Restore is rehearsed automatically into an isolated path with no production credentials or transports. The drill verifies database integrity, manifests, artifact hashes, policy versions and startup in disconnected recovery mode before any transport lease can be acquired.

Credential descriptors or metadata alone do not constitute a recoverable backup. The restore drill must resolve each required descriptor to the expected secret version through the selected recovery path, without exposing its value. Until required credentials resolve and their audiences/tenants are revalidated, transport intake, outbox delivery, provider starts and connector sends remain disabled.

## Configuration and credential lifecycle

Separate:

- immutable release configuration;
- revisioned non-secret runtime settings;
- workspace/target registry data;
- secret credentials;
- temporary worker/provider capabilities.
- agent profiles, model routing/pools and auxiliary/media/executor settings;
- extension, connector and public-protocol credentials/capabilities.

Non-secret mutations use expected revisions, durable events and audit. Adjacent generations read the same schema and only the settings lease owner writes.

Prefer systemd credentials, protected descriptors or a host secret provider over copying long-lived secrets into child environments. Each credential records owner, purpose, audience, creation, expiry/rotation deadline and health state without exposing its value. Rotation supports an overlap window and canary; revocation immediately disables new work and invalidates derived capabilities where possible.

Provider executables and companions are selected from immutable content-addressed release paths. Verification and execution use the same inode/descriptor or an immutable directory so a path replacement cannot defeat the recorded digest.

Canonical `AUTOMONIQUE_*` configuration is resolved before legacy `LEGACY_*` fallback. Conflicting simultaneous values fail closed and are recorded without logging either secret.

Teams app secrets/certificates, Entra/Graph credentials, Discord bot tokens, interaction secrets and webhook URLs follow the same descriptor/rotation model. Each credential is bound to a connector installation and tenant; connector processes cannot read provider, workspace, Slack/Telegram or root-broker credentials. Rotation rehearsals cover overlapping app credentials and revocation while outstanding card/component actions remain pending.

Secret-source adapters for systemd/local encryption, 1Password, Bitwarden and pinned command helpers return sealed descriptors and run with audience-specific identity. Credential pools group only accounts explicitly approved to share tenant, billing and data-boundary policy; automatic rotation cannot cross those boundaries.

## Retention, privacy and deletion

Define policy classes for:

- durable business/audit records;
- Slack/Telegram/Support/client content;
- conversation history and memory;
- provider raw records and normalized events;
- previews, logs and stderr;
- artifacts/screenshots/builds;
- credentials/authentication sessions;
- backups and deletion tombstones.
- Teams/Discord activities, interaction tokens, platform identity attributes, consent records and connector diagnostics.
- context manifests/references/compression, typed memory, skills/learning proposals and profile packages;
- goals/automations/board history and webhook payloads;
- extension/MCP/hook records, public-protocol stored responses and desktop/client sessions;
- media/browser/computer-use artifacts, remote-environment snapshots and trajectory/evaluation exports.

Every class specifies owner, default TTL, maximum size, redaction, export eligibility, legal hold and deletion method. Preview deltas and raw provider records have shorter defaults than authoritative business/audit records. Memory is user/tenant addressable and supports inspect, correct and delete subject to audit/legal requirements.

Deletion first removes access, records a tombstone, cancels future publication and then garbage-collects unreferenced bytes/backups according to policy. Cross-tenant deduplication never prevents logical deletion or leaks existence.

## Scheduler, admission and budgets

The scheduler applies policy before queue insertion and again before host start:

- global and per-provider concurrency;
- per-tenant/origin/user/workspace quotas;
- priority classes with aging to prevent starvation;
- maximum queue length and oldest-age limits;
- provider token/cost/turn/time budgets;
- disk/artifact/spool capacity watermarks;
- provider health, rate-limit and circuit-breaker state;
- workspace/integration locks;
- maintenance/drain state.

Admission rejection is explicit and durable: rejected, deferred-until, or waiting-capacity. Automonique never accepts unbounded work it cannot retain. Cross-provider fallback requires an explicit policy and cannot silently migrate a provider session or widen capabilities.

Automation occurrences, goal continuations, inbound triggers, background curation, media jobs, remote-environment wakeups and batch/evaluation work use the same reservations and fairness. Unattended origin is never a priority or approval bypass.

## Work graphs and multi-agent orchestration

Represent split tickets and subagent work as a durable DAG:

- parent/child/dependency edges;
- required/optional children and fan-in rule;
- per-node reviewed scope, workspace and budget;
- cancellation propagation policy;
- partial failure and retry policy;
- artifact/result aggregation;
- parent terminal/reporting state derived from durable child state.

Provider-native subagents remain observable items, but an Automonique work-graph node is created when Automonique must schedule, approve, retry or report it independently.

## Plans, policy and reproducibility

Before approval, Automonique may produce a deterministic execution plan containing workspace/base revision, provider/model, tools, filesystem/network grants, budget, expected external effects and required approvals. The reviewed plan hash becomes the action revision.

Development runs additionally retain the executable work-unit revision, agent-role/prompt/provider revisions, frozen candidate diff, reviewer findings, command/test evidence and metrics-manifest digest. CI artifact retention keeps commit attestations for the supported release/audit window; public summaries are derived only from consented, secret-scanned data. A baseline or metric-definition change is reviewed separately from the implementation unit it will judge.

## Self-hosting operations and trust roots

Self-hosting development state is backed up separately from production and includes bootstrap runs/manifests, public trust-root revisions, source/build fingerprints, work DAG, candidate lifecycle/evidence, self-host sessions, build/test queues, metrics, promotion plans and repository/action receipts. Recovery keeps the last known-good seed/bootstrap verifier, exact corresponding source and dependency locks, plus an independently checksummed disconnected-start bundle.

Private release-signing, protected-branch and deployment credentials are never part of candidate or ordinary lab recovery. Their external systems expose public identities and typed approval results only. Development provider credentials are audience-bound to stable or candidate identities and rotation cannot turn a canary credential into production access.

Candidate retention is state-based: active/promotable and last-known-good artifacts are protected; superseded/rejected candidates age out after evidence and referenced metrics/provenance are retained. Garbage collection verifies that no recovery, comparison, PR, release or audit record references the artifact.

Runbooks cover clean-host SH0 bootstrap, source/toolchain acquisition failure, non-reproducible rebuild, superseded source, stuck build queue, candidate crash loop, failed self-host reload, candidate boundary violation, independent-builder outage, stale promotion plan, compromised development credential/trust root and stable development-state recovery. No runbook repairs self-host state with ad hoc database edits.

The `automonique-bootstrap` runbook covers inspect/plan without mutation, exact start confirmation, status/attach, restart/resume, disk-pressure stop, failed handoff, cleanup preview and state export. Its runtime directories and repository worktrees are registered explicitly; cleanup never follows unresolved variables or removes unrelated source/user state.

Promotion preparation and approval are separate typed actions. The approver revalidates protected branch, source/artifact/provenance digests, required checks, current stable, compatibility, backup and rollback immediately before mutation. Candidate output cannot satisfy external-builder, signer or deployer evidence.

Each attempt stores hashes/versions for:

- persona and prompt templates;
- policy/risk rules;
- command registry;
- workspace registry and base revision;
- provider binary/schema/capabilities;
- tools, companions and sandbox profile;
- model and relevant provider settings.
- context manifest/compression lineage, profile/memory/skill/toolset/extension revisions;
- automation/goal/trigger revision and public-protocol/connector/executor manifest;

Any material change produces a new revision or a documented compatible retry decision.

## Observability and runbooks

Propagate `trace_id`, `correlation_id`, `causation_id`, input/work/attempt/run/host/session/turn IDs and outbox/action IDs through logs, events and external request metadata where safe.

Provide metrics plus alerts for:

- generation/reload failure and drain age;
- lease expiry/contention/fencing rejection;
- intake, queue and approval age;
- provider health/rate limits/cost anomalies;
- runner/host heartbeat and event lag;
- sandbox preparation/attestation failure, policy drift, denial/violation rate, egress-broker failure and orphan namespace/cgroup cleanup;
- per-profile CPU, memory, PID, I/O, runtime, tmp/workspace/spool/artifact pressure and quota exhaustion;
- disk, database WAL, spool and artifact watermarks;
- outbox retry/dead-letter age;
- backup age/restore-drill failure;
- authentication failure/revocation/break-glass use;
- reconciliation drift and invariant violations.
- context/cache/compression/queue/checkpoint failures, memory/skill proposal backlogs and automation/goal lateness;
- MCP/extension/hook health, public-protocol errors, connector catalog status and desktop/client version skew;
- routing/pool/auxiliary/MoA decisions, media/browser/computer runs, remote executor/hibernation state and batch/export failures.

Ship redacted diagnostic bundles and runbooks for stuck leases, corrupt database/spool, disk exhaustion, provider outage, invalid schema, orphan host, poisoned outbox, failed handoff, failed rollback, credential expiry, artifact quarantine, kernel enforcement loss, stuck sandbox namespace/cgroup, egress-broker outage, denied dependency fetch, external-daemon attestation mismatch and sandbox-launcher failure. Diagnostic creation is read-only and audited.

## Maintenance and safe modes

Distinct modes:

- `pause` — keep intake but do not start new approved work;
- `drain` — stop accepting/claiming new work and finish/adopt existing work;
- `maintenance-read-only` — serve health/history while disabling mutations and external delivery;
- `disconnected-recovery` — no external transports or provider starts; inspect/restore/reconcile only;
- `provider-quarantine` — disable a provider binary/digest for new hosts while preserving evidence and safe cancellation.
- `sandbox-quarantine` — disable affected profiles/implementation digests after enforcement drift while retaining observation, reconciliation and cancellation.
- `extension-quarantine` — disable selected tool/MCP/hook/memory/media/secret packages without stopping core services.
- `connector-quarantine` — stop one platform installation/family while preserving unrelated transport intake.
- `executor-quarantine` — refuse new work on one local/remote backend while retaining observation/cancellation/recovery.
- `learning-read-only` — permit memory/skill reads while rejecting new learning proposals or curator mutations.

Transitions are revisioned actions with visible reason, actor and expiry. Restarting Automonique does not silently clear a safety mode.

## Reconciliation and repair

Invariant checkers compare database state, systemd units, runner manifests, provider sessions, artifacts, GitHub truth, Slack/Telegram presentation, Manage state and outboxes. Repair always follows preview → immutable plan → revalidation → apply → verify.

Supported repairs are typed and narrow: requeue an expired claim, adopt/finalize a host, rebuild a projection, resend/reconcile an outbox row, restore a missing presentation marker, or quarantine inconsistent state. No general SQL/command repair endpoint is exposed.

## Extension and SDK supply chain

Provider, tool, MCP, hook, memory/context, media/browser, secret-source, executor, connector and UI extension packages require:

- signed/verified package and lockfile;
- exact runtime/dependency manifest;
- declared capabilities, secrets, filesystem/network needs and event schemas;
- isolated conformance result keyed by digest;
- staged enablement and immediate quarantine/rollback;
- no install-time scripts in production unless explicitly reviewed;
- no network-fetched code at provider-host startup.

Catalog/marketplace metadata is not trust. Installation is separate from enablement, and activation is scoped by tenant/profile/workspace/channel. UI extensions cannot import backend host APIs. A revoked digest remains readable in audit/history but cannot start a new process.

## Context, learning and automation governance

Memory and skill writes carry source evidence, sensitivity, visibility and review policy. Executable learned behavior is never silently enabled. Users can inspect/correct/delete profile memory, and organization knowledge requires a distinct promotion action. Curator and background review have token/time budgets and a zero-model deterministic mode.

Natural-language schedules are reviewed as canonical schedules with timezone examples. Persistent goals expose completion criteria and budgets. Webhook transforms and script-only jobs are immutable sandboxed packages. Repeated failure auto-pauses/blocks rather than creating an unbounded loop.

## Public protocol, media and research governance

ACP/OpenAI/MCP/A2A/relay adapters publish honest capability limits and share canonical identity/state. Desktop/mobile clients and UI plugins cannot hold provider or root credentials. Voice/meeting recording, biometric-like voice data, browser profiles and computer-use captures receive explicit consent/retention classes.

Batch/trajectory/evaluation export defaults to synthetic or explicitly approved data. Hidden reasoning, secrets and production customer content are excluded; consent, license, source hashes and redaction evidence accompany every export.

## Search, pagination and exports

All list APIs define stable filtering, sort, page size and opaque pagination cursors. Search indexing is a rebuildable projection from durable state/events and never becomes ticket truth. Exports are bounded, redacted, artifact-backed and audited.

## Signed outbound integrations

External consumers that cannot hold an event stream may register an approved scoped webhook subscription. Deliveries use the outbox, event IDs, signatures, replay protection, secret rotation and bounded retry/dead-letter policy. Subscriptions cannot observe more than the creating service account is authorized to read.

Teams Workflow and Discord incoming-webhook destinations are typed notification targets, not generic arbitrary URLs. Their secret URLs are credential descriptors; destination tenant/team/guild/channel, audience and permitted template families are reviewed and reconciled before retry.

## Operational exit gate

Before production cutover, a restore drill, credential rotation, disk-pressure exercise, provider quarantine, maintenance-mode transition, reconciliation preview/apply, work-graph partial failure, context/compression/queue recovery, memory/skill governance, automation/goal/trigger duplicate suppression, retention deletion and alert/runbook exercise must all succeed against the exact release mechanism. Every enabled public protocol, extension, connector, media/browser backend or executor also proves its independent revocation/quarantine/reconnect/data-boundary contract before graduation.
