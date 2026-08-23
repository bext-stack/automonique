# Target architecture

Target diagrams use Automonique names. Version-1 legacy identifiers appear only in explicitly labelled compatibility notes and the machine-readable inventory; aliases must resolve to one runtime owner, never two processes.

## Process model

```text
operator, test harness, or optional supervisor adapter
├─ automonique daemon --foreground       active product control plane
├─ automonique lab --foreground          development control plane
├─ automonique runner                     session- or attempt-scoped execution host
├─ automonique tool-host                  nested tool/MCP sandbox
├─ automonique extension-host             plugin/hook/media/secret adapter sandbox
├─ connector processes                    independently credentialed SDK applications
└─ local sockets/listeners                 admin, API, dashboard, MCP, relay, webhooks

optional deployment adapters
├─ systemd user units and socket activation
├─ launchd or desktop/session launchers
├─ container/process supervisors
└─ direct foreground execution for development and small installations

root-owned
├─ automonique-deploy-broker        narrow privileged deployment broker
└─ automonique-sandbox-launcher   optional narrow namespace/network setup broker
```

The required first design runs directly as `automonique daemon --foreground`.
It never self-daemonizes and exposes readiness, drain, shutdown, restart and
reconnect through portable process and protocol contracts. Tests invoke this
mode directly. Installing an operating-system service is optional.

Execution hosts are separate child process trees with explicit ownership and a
typed control channel. Session-scoped hosts may execute multiple serialized
turns and retire after a configured idle TTL; attempt-scoped hosts terminate
with one attempt. The selected execution backend must provide complete
descendant cleanup and resource accounting. A systemd adapter may use transient
units and cgroups, but the lifecycle contract also supports direct process
groups, containers, remote executors, and stronger future isolation.

In the foreground baseline, the active generation owns the admin endpoint and
publishes its generation identity atomically. Reload uses a handoff channel and
durable fencing rather than assuming socket activation. An optional adapter or
stable launcher may pre-open and pass the endpoint to remove reconnect gaps.
Compatibility aliases always resolve to the same owner.

## Target workspace layout

```text
rust/
├─ Cargo.toml
├─ crates/
│  ├─ automonique-protocol/ versioned wire/domain types (`legacy.*` v1 codecs retained)
│  ├─ automonique-store/   SQLite schema, migrations and repositories
│  ├─ automonique-runner/  execution hosts, sandbox, spool and control socket
│  ├─ automonique-sandbox/ policy compiler, profiles, attestation and enforcement
│  ├─ automonique-agents/  native Claude, Codex, opencode and Jcode session adapters
│  ├─ automonique-workspaces/ registry, worktree/snapshot isolation and promotion
│  ├─ automonique-artifacts/ content-addressed objects, metadata and access policy
│  ├─ automonique-context/ context manifests, references, compression and queues
│  ├─ automonique-memory/   typed memory, FTS session retrieval and adapters
│  ├─ automonique-skills/   agentskills runtime, catalogs, learning and curator
│  ├─ automonique-tools/    canonical tool/MCP registry and capability RPC
│  ├─ automonique-extensions/ manifests, hosts, hooks and secret providers
│  ├─ automonique-automation/ schedules, goals, triggers and board projection
│  ├─ automonique-models/   provider catalog, routing, pools, auxiliaries and MoA
│  ├─ automonique-media/    vision, STT/TTS, image/video and browser adapters
│  ├─ automonique-executors/ local, container, remote, HPC and cloud host backends
│  ├─ automonique-policy/  identities, tenants, authorization and budgets
│  ├─ automonique-transports/ Slack and Telegram clients
│  ├─ automonique-core/    routing, approvals, scheduling and lifecycle
│  ├─ automonique-fleet/   Fleet claim, heartbeat and report outboxes
│  ├─ automonique-web/     dashboard API, WebSocket and static assets
│  ├─ automonique-compat-api/ ACP, OpenAI, MCP-server, A2A and relay adapters
│  ├─ automonique-dev-protocol/ bootstrap, candidate, evidence and promotion contracts
│  ├─ automonique-bootstrap/ fresh-host manifest verifier and recovery
│  ├─ automonique-daemon/  foreground control plane and generation lifecycle
│  ├─ automonique-cli/     operator command surface and rendering
│  ├─ automonique-tui/     interactive operator cockpit
│  ├─ automonique-shell/   optional isolated interactive shell/file-transfer service
│  ├─ automonique-lab/     AI implementation orchestrator, build/Git brokers
│  └─ automonique/         THE SINGLE BINARY — argv dispatch only, no domain logic
└─ xtask/                   builds, fixtures, release manifests and checks

sdk/typescript/             published as `@automonique/sdk*`
├─ packages/protocol/       generated types, validators and codecs
├─ packages/client/         runtime-neutral high-level Automonique client
├─ packages/node/           Node/Bun Unix-socket and server transports
├─ packages/browser/        browser HTTP/WebSocket transport
├─ packages/provider/       out-of-process provider adapter SPI
├─ packages/connector/      channel connector runtime and conformance
├─ packages/extension/      tools, hooks, memory/context, media and secret-source SPI
├─ packages/ui/             dashboard/desktop/TUI read models and namespaced UI plugins
├─ packages/openai/         OpenAI-compatible client/server extension types
├─ packages/mcp/            MCP client/server helpers and conformance
├─ packages/dev-harness/    implementation scenario/metrics client and fixtures
└─ packages/testing/        fake server, fixtures and conformance tools

connectors/typescript/
├─ core/                    shared installation, receipt and artifact helpers
├─ teams/                   Teams SDK app, manifests and Adaptive Cards
├─ discord/                 HTTP Interactions app and optional Gateway/voice worker
├─ email-sms/               email threading and typed SMS providers
├─ meta/                    WhatsApp Cloud and isolated compatibility bridge
├─ secure/                  Signal, SimpleX and Matrix packages
├─ enterprise/              Mattermost, Google Chat, LINE, DingTalk, Feishu, WeCom
├─ social/                  iMessage bridge, QQ, Weixin and Yuanbao packages
├─ devices/                 Home Assistant, ntfy and notification packages
└─ relay/                   A2A, API/Open WebUI and authenticated relay packages

apps/
└─ dashboard/               SDK-only web/PWA application
                            (the native desktop client is ShellDeck, in its own repository)

scripts/
└─ bootstrap.sh             first-run shell entry; hands off to `automonique bootstrap`
```

### One binary rule

The product ships **exactly one unprivileged executable**, `automonique`, which
dispatches by subcommand:

```text
automonique bootstrap | doctor | status | generations
automonique daemon | reload | rollback | reload-status
automonique tui | attach | runs | cancel | audit
automonique runner | agent | run          internal, execution-backend invoked
automonique lab | self-host               development control plane
automonique shell                         optional, separately enabled
```

`crates/automonique` contains argv dispatch and nothing else. Every subcommand
delegates to a library crate, so the binary boundary carries no behavior and a
subcommand cannot acquire authority its library does not already have.

`daemon` names the long-running control-plane role for compatibility and
operator clarity. The command stays in the foreground, does not fork or detach,
and has no dependency on installation as a system service.

Two executables are deliberately **excluded** from this rule because privilege
separation outranks surface simplicity:

- `automonique-deploy-broker` — root-owned deployment broker;
- `automonique-sandbox-launcher` — optional root-owned namespace/routing setup.

Each is a separate binary with a closed request schema, its own installer and
its own sudo rule. Deployment privilege and sandbox privilege never share a
binary with each other or with the product. See Epic R9.

### Crate boundaries

Library crates may be merged initially, but `automonique-protocol`,
`automonique-store`, `automonique-runner` and `automonique-daemon` must remain
dependency boundaries. In particular, `automonique-runner` must not depend on
Slack or business-routing code, and `crates/automonique` must not be a
dependency of anything.

Compatibility entry points (`legacyd`, `legacyctl`, `legacy-tui`) are installed
as thin forwarding shims that exec `automonique <subcommand>`. They contain no
logic, are generated from the compatibility registry in R1-17, and are removed
by the deprecation gate in R10-09.

`automonique-lab` is deliberately outside the production process graph. It uses a separate development database and credential domain, consumes the same generated contracts/provider adapters and may restart/reload its own generation without affecting the `automonique` daemon. Its workers never possess direct merge, release or production-deploy authority; typed Git/build brokers enforce path ownership, bases, commands and budgets. See [AI implementation harness and commit metrics](ai-implementation-harness.md).

### `automonique bootstrap` and self-hosting generations

`automonique bootstrap` is a non-network-by-default verifier/installer. It reads the reviewed bootstrap manifest, verifies fixed source/toolchain/build inputs, creates the isolated development identity/state and produces or verifies the first `automonique-lab` seed. It has no provider, transport, GitHub merge, release-signing or production-deployment credential.

The stable lab launches candidate lab/control-plane/client components into a digest-named namespace with separate sockets, database, artifacts, workspaces, credentials and process ownership. Candidate code never loads into the stable verifier. Stable owns lifecycle and evidence observation; a clean builder may add rebuild provenance when configured; protected external authority owns promotion. See [Self-hosting and bootstrap](self-hosting-and-bootstrap.md).

## Application ownership

Each heading below is a responsibility owned by a library crate and reached
through an `automonique` subcommand, not a separate executable. See the one
binary rule above.

### `automonique daemon` (`legacyd` compatibility shim)

- owns the active generation identity and lease heartbeat;
- ingests Slack and Telegram events into the durable inbox;
- accepts authenticated, tenant-bound Teams/Discord connector inputs through the same durable intake contract;
- executes deterministic commands and conversation routing;
- creates and resolves approval gates;
- authorizes typed actions against durable actor, tenant, role and policy revisions;
- schedules approved jobs;
- commits domain events/action receipts with state and coordinates workspace/artifact policy;
- consumes execution-host events and performs terminal reporting;
- drains local outboxes;
- serves the shared operator API used by the TypeScript SDK, dashboard, TUI and CLI;
- owns canonical context manifests, queued input, memory/skills/profiles, tool registry, automations/goals and their domain events;
- exposes capability-filtered native services consumed by compatibility-protocol and extension processes;
- participates in reload handoff.

### `automonique runner` execution host

- accepts an immutable host spec plus one or more serialized attempt/turn specs through protected descriptors/sockets according to its declared lifetime mode;
- starts or connects to the provider's supported programmatic surface and records negotiated capabilities;
- validates executable, cwd, environment allowlist, limits, and sandbox policy;
- creates or adopts the attested mount/network/process boundary, separating provider-control egress from nested tool/MCP egress;
- creates agent/adapter processes inside the selected execution backend's owned process boundary;
- enforces and reports CPU, memory, PID, I/O, runtime and storage budgets plus sandbox violations;
- owns provider instance, session, active turn, approval and reconnect state without owning the business work-item lifecycle;
- writes raw provider events plus ordered normalized events, stderr, checkpoints, and atomic terminal status;
- accepts authenticated status/subscribe/cancel control messages;
- remains operational with no daemon connected; a session-scoped host hibernates or expires only under its recorded policy;
- never calls Slack, Telegram, GitHub, Fleet, or Support.

See [Agent integrations](agent-integrations.md) for the provider-specific contracts. The target native modes are supervised JCode `api-stdio` protocol v1 inside the execution host, Claude Code bidirectional stream JSON, Codex App Server over pinned stdio schemas, and an authenticated session-host-scoped opencode HTTP/OpenAPI/SSE server.

An active execution host is pinned to its provider executable digest, integration mode, schema hash and credential descriptors. The executable is opened/verified at launch to close selection/use races. Provider upgrades affect new hosts only; a live JCode process is never replaced behind an attached Automonique session.

The sandbox boundary is pinned in the same way. A host records profile/policy/attestation digests and cannot gain filesystem, network, credential, tool or resource authority through a follow-up or daemon reload. Destination-aware networking uses the reviewed egress broker; seccomp is used for syscall/address-family denial, not domain allowlisting. See [Sandbox management](sandbox-management.md).

### `automonique shell` (optional legacy-shell compatibility subsystem)

The optional shell service preserves compatibility for authorized interactive shells and file transfer without turning the Automonique TUI or agent protocol into a general terminal multiplexer. It is disabled by default, separately authorized, sandboxed and audited; transferred files enter/leave through artifact APIs. See the [feature-parity ledger](../reference/feature-parity.md).

### `automonique` operator commands (`legacyctl` compatibility alias)

- talks only to the local admin socket;
- performs status, doctor, reload, rollback, pause, resume, attach, and cancel;
- verifies human-readable release and generation state;
- does not open or parse `.env` itself.

### `automonique tui` (`legacy-tui` compatibility alias)

- talks only to the versioned local admin socket and authenticates through Unix peer credentials;
- renders durable requests, approvals, runs, providers, reloads, failures and settings from snapshots plus cursor-based events;
- attaches/detaches as an observer to any authorized active session and multiplexes independently resumable streams into a dynamic N-pane agent cockpit;
- uses an explicit short controller lease for interactive steering/input; observation and pane focus never imply control;
- builds its command palette and forms from the canonical server-described command registry;
- submits typed, revision-bound, idempotent actions and reconciles unknown results after reconnect;
- remains open in a stale/read-only state during daemon generation handoff, then resumes from its last cursor;
- never reads the database, credentials, provider sockets or runner spools directly.

See [Automonique operator TUI](operator-tui.md) for its complete interaction, safety and reload contract.

### Context, learning and automation services

Context manifests, compression, typed memory, skills, profiles, goals, automation schedules and input queues are authoritative domain services inside the `automonique` daemon; expensive retrieval/review/curation or scheduled occurrences run as ordinary supervised workers. Learned or scheduled state never lives only in a client/plugin process. See [Context, memory and learning](context-memory-and-learning.md) and [Automations, goals and triggers](automation-goals-and-triggers.md).

### Tool, MCP and extension hosts

The daemon owns descriptors and authorization; `automonique-tool-*` and `automonique-extension-*` units execute code. Native MCP client/server, workflow RPC, hook classes and UI/backend plugin separation follow [Tools, MCP, extensions and hooks](tools-extensions-and-hooks.md). No extension is dynamically linked into the daemon in production.

### Public protocol adapters

ACP, OpenAI-compatible, MCP-server, A2A and relay listeners are protocol adapters over the same sessions, runs, events, actions and identity policy. They may be in the Rust binary or separately supervised depending on dependency/risk, but cannot own alternate state. See [Public agent protocols](public-agent-protocols.md).

### Desktop and other clients

The dashboard/PWA, IDE and future mobile clients use the generated SDK. The native desktop client is ShellDeck, an owner-controlled Rust/GPUI application in its own repository; it consumes the typed admin protocols through the same shared Rust client crate as the TUI and passes the same conformance suite. Persistent terminals remain the separate `automonique-shell` capability. Signed UI plugins receive namespaced projections/actions only. See [Client experience and surfaces](client-experience-and-surfaces.md).

### Model, media and execution adapters

Routing, credential pools, auxiliary/MoA calls, media/browser/computer tools and local/remote execution backends are capability-negotiated adapters. Each keeps exact data-boundary, artifact, sandbox, cost and lifecycle evidence defined in [Models, media and execution backends](models-media-and-execution.md).

### TypeScript SDK

- is generated from the canonical Automonique schemas/service descriptions while retaining version-1 legacy codecs and adds ergonomic runtime-neutral clients;
- covers every stable operator service, event stream, session attachment and typed mutation without private dashboard endpoints;
- provides explicit Node/Bun local-socket and browser HTTP/WebSocket transports;
- includes an out-of-process provider adapter SPI plus deterministic testing/conformance packages;
- negotiates protocol/capabilities and refuses unsupported mutations rather than guessing from server version;
- remains a client/extension boundary and never reads SQLite, secrets, root broker input or runner spools directly.

See [TypeScript SDK](typescript-sdk.md) for package, compatibility, safety and release contracts.

### Teams and Discord connectors

- are independently supervised TypeScript services using `@automonique/sdk/connector` (with a temporary `@legacy` compatibility export if needed);
- verify Microsoft/Discord protocol authentication, resolve installations/actors and translate platform activities/interactions into durable inputs;
- render Automonique events as Teams messages/Adaptive Cards or Discord responses/components without implementing business policy;
- keep platform app credentials, Graph/RSC scopes, Discord intents and webhook targets outside `automonique` daemon worker/provider environments;
- reconnect from durable domain/action cursors and reconcile remote message IDs before retrying ambiguous delivery.

See [Teams and Discord integrations](channel-integrations.md) for the first platform contracts and the [Connector catalog](connector-catalog.md) for the complete independently graduated set.

### Privileged broker

- accepts only a strictly typed, bounded request on stdin;
- verifies exact workspace, revision, action ID, ownership, and release snapshot;
- remains a separately installed root-owned executable;
- never accepts an arbitrary command or argument vector.

If rootless user services cannot create the required namespace or routing boundary, `automonique-sandbox-launcher` is a separate minimal broker. It accepts only a validated policy digest, UID, prepared descriptors and bounded resource/network values, returns attestation evidence, and never performs deployment or executes provider-supplied argv. A root container-engine socket is never part of the design.

## Transport model during overlap

### Slack

The new generation opens its Socket Mode connection before the old one exits. A short overlap is allowed. Every event is inserted by Slack event ID before routing, so duplicate deliveries are harmless. The old generation stops taking new durable inbox claims after lease transfer but may finish claims already owned.

### Telegram

Only one generation may call `getUpdates`. Ownership is controlled by a renewable database lease. The old poller completes or cancels its current long poll, commits received updates, releases the lease, and the new poller begins from the durable offset.

### Teams and Discord

Connector processes outlive an `automonique` daemon generation and reconnect through the public connector API. They do not participate in generation lease transfer. Teams HTTPS requests and Discord HTTP interactions may reach any healthy connector instance; stable platform IDs and the durable inbox suppress duplicates. An optional Discord Gateway uses its own fenced connector lease/session cursor so only one logical shard owner processes a sequence.

Connector availability is an independently supervised deployment concern. An unavailable optional connector is reported as degraded but does not block a daemon handoff; an attached connector with a protocol range that cannot overlap the candidate generation does block that handoff until it is upgraded, disabled or explicitly removed from service.

### Dashboard

An optional activation adapter or inherited listener can preserve the TCP bind
across handoff. The foreground baseline may instead expose a bounded reconnect
gap: WebSocket clients reconnect using a durable `last_event_id`, and mutating
requests carry idempotency keys.

### Fleet

Only the scheduler lease holder claims jobs. Heartbeat may briefly show both generation IDs, but there is one logical Automonique instance. Terminal reports remain in a durable outbox and can be resent by the new generation.

## Data access model

SQLite stores authoritative projections plus the append-only domain-event/action journal. The artifact store contains immutable content addressed by digest; SQLite stores its metadata, references, visibility and retention state. Workspace paths are resolved only through the workspace registry. No client, adapter or broker may manufacture a host path from untrusted input.

Only the `automonique` daemon writes business projections, events and action receipts. Execution hosts write their private spools/status and submit versioned observations; the active generation validates and commits them. Read clients consume bounded snapshots and journal cursors rather than database files.

SQLite remains authoritative. Use WAL, foreign keys, a bounded busy timeout, and explicit transactions. A dedicated store actor per generation serializes local writes, while SQLite arbitrates the brief two-generation overlap.

Avoid sharing Rust references to mutable domain objects across subsystems. Store durable identifiers and reload state from repositories. In-memory maps are caches only and must be disposable.

## Release layout

```text
.automonique-releases/<timestamp>-<revision>/
├─ bin/automonique         the single unprivileged binary, all subcommands
├─ bin/automonique-deploy-broker     root-owned, installed by separate rule
├─ bin/automonique-sandbox-launcher  optional, root-owned, separate rule
├─ compat/                 legacyd, legacyctl, legacy-tui forwarding shims
├─ web/
├─ sdk/                    TypeScript package archives/manifests or exact published versions
├─ connectors/             checksummed connector packages and app manifests
├─ extensions/             signed built-in extension manifests and WASI/sidecar components
├─ schemas/
├─ policies/               persona, policy, command and companion bundles
├─ migrations/
├─ bootstrap.toml          seed/toolchain/build and trusted-builder contract
├─ provenance/             build attestations, SBOM and reproducibility evidence
├─ manifest.json
└─ SHA256SUMS

.automonique-current -> .automonique-releases/<selected>
```

Existing installations continue to recognize `.legacy-releases` and `.legacy-current` during the compatibility window. Migration adopts or links one verified release tree; it must not create two independently active release selectors.

The manifest includes application version, git revision, build target, protocol/event ranges, database schema range, compatible TypeScript SDK range/artifacts, binary/schema/policy/persona/companion/asset hashes, migration compatibility, minimum kernel/process requirements and any optional supervisor-adapter requirements. Release selection is atomic. Reload verifies compatibility before spawning the new generation.

## Suggested libraries

These are defaults to validate in spikes, not irrevocable choices:

- Tokio for async runtime and process/network coordination;
- Axum for dashboard/admin HTTP;
- reqwest plus tokio-tungstenite for external APIs and Slack Socket Mode;
- serde/serde_json for versioned inspectable protocols;
- rusqlite behind a store actor for SQLite;
- rustix or nix for Unix credentials, file descriptors and process operations;
- tracing for structured logs;
- Ratatui plus Crossterm for the operator TUI, subject to a terminal-compatibility spike;
- secrecy/zeroize for in-memory credential wrappers where useful;
- proptest and cargo-fuzz for protocol/state-machine validation.
