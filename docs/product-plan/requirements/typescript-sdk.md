# TypeScript SDK

## Goal

Automonique ships a supported TypeScript SDK covering every stable system capability. The dashboard, automation, external integrations and TypeScript compatibility code use this SDK instead of handwritten HTTP calls, duplicated event types or private routes.

“Entire system” means complete typed access to Automonique's supported control plane and extension points. It does not mean bypassing authorization, exposing credentials, reading SQLite directly, or turning internal root/runner sockets into public APIs.

## Package layout

Maintain the SDK in the repository as a TypeScript workspace:

```text
sdk/typescript/
├─ package.json
├─ packages/
│  ├─ protocol/       generated wire/domain types, validators and codecs
│  ├─ client/         runtime-neutral high-level Automonique client
│  ├─ node/           Node/Bun local Unix-socket and server transports
│  ├─ browser/        browser HTTP/WebSocket transport and auth hooks
│  ├─ provider/       out-of-process provider-adapter authoring API
│  ├─ connector/      external channel connector authoring API
│  ├─ extension/      tool/hook/memory/context/media/secret-source authoring API
│  ├─ ui/             framework-neutral UI projections and namespaced plugin API
│  ├─ openai/         OpenAI compatibility types/adapters
│  ├─ mcp/            MCP client/server helpers
│  └─ testing/        fake server, fixtures, record/replay and conformance tools
├─ examples/
└─ scripts/           generation, compatibility and package validation
```

Publish stable packages under one namespace:

- `@automonique/sdk` — primary runtime-neutral client and domain types;
- `@automonique/sdk/node` — local Unix-socket helpers and Node/Bun integrations;
- `@automonique/sdk/browser` — browser transport without Node built-ins;
- `@automonique/sdk/provider` — provider adapter SPI and conformance harness;
- `@automonique/sdk/connector` — Teams, Discord and future channel connector surface;
- `@automonique/sdk/extension` — out-of-process tool, hook, memory/context, media and secret-source extensions;
- `@automonique/sdk/ui` — framework-neutral read models and strictly namespaced dashboard/desktop/TUI plugin capabilities;
- `@automonique/sdk/openai` — OpenAI-compatible API types and bridging helpers;
- `@automonique/sdk/mcp` — MCP server/client registration and conformance helpers;
- `@automonique/sdk/testing` — deterministic test server and fixtures.

These may be implemented as export paths from fewer physical packages initially. Consumers must not need to know the internal workspace layout. Temporary `@legacy/sdk*` packages and exports are generated forwarding layers over the same implementation; they are never forked clients.

## One source of truth

Rust Automonique protocol types and service descriptions are authoritative. Version-1 `legacy.*` codecs remain generated compatibility artifacts. The release build emits:

- JSON Schemas for domain values, requests, responses and events;
- an OpenAPI document for HTTP endpoints;
- an AsyncAPI-like event/channel manifest or equivalent checked-in subscription schema;
- a local admin/runner protocol manifest;
- command-registry schemas and provider-adapter protocol schemas;
- protocol versions, capability IDs and schema digests.

TypeScript wire types, runtime validators, discriminated unions and low-level clients are generated from those artifacts. Handwritten SDK code adds ergonomic APIs, lifecycle management and documentation; it does not redefine wire structures.

CI regenerates into a temporary tree and requires a zero diff. Every released SDK records the exact schema digest and Automonique protocol range it supports, including any explicitly supported `legacy.*` v1 codec range.

## Supported runtimes and transports

| Runtime | Transport | Intended use |
|---|---|---|
| Node.js / Bun on the Automonique host | authenticated Unix socket | full local operator and automation surface |
| Node.js / Bun off-host | HTTPS plus WebSocket/event stream | authorized remote automation |
| Browser | HTTPS plus WebSocket/event stream | dashboard and approved browser applications |
| Provider adapter process | framed stdin/stdout or inherited Unix socket | sandboxed third-party/custom backend integration |
| Teams/Discord connector | authenticated HTTPS plus event stream | separately deployed platform protocol bridge |
| Other connector catalog package | authenticated HTTPS/relay plus event stream | independently deployed platform bridge |
| Extension process | framed inherited socket/stdio | sandboxed tools, hooks, memory/context, media and secret sources |
| Native desktop (ShellDeck) | not a TypeScript SDK consumer; shared Rust client crate over HTTPS/Unix socket | local or remote typed-protocol client with no database access |
| ACP/OpenAI/MCP/A2A adapter | canonical internal service transport | compatibility protocol termination |
| Development harness/bootstrap client | separate authenticated development socket | source/build/candidate/evidence and promotion-proposal orchestration |
| Tests | in-memory/fake transport | deterministic unit and contract testing |

The runtime-neutral client depends on injected `Transport`, clock, ID factory and optional logger interfaces. Browser bundles never include Unix-socket, filesystem, child-process or server credential code. Node/Bun entry points never silently fall back from a local socket to a remote endpoint.

## Complete client surface

The high-level `AutomoniqueClient` exposes capability-grouped services. `LegacyClient` may remain a deprecated type alias during migration. Every dashboard/TUI/CLI operation must map to one of these services; there are no UI-only endpoints.

| Service | Representative capabilities |
|---|---|
| `system` | version, capabilities, health, active generation, metrics projection |
| `commands` | list canonical commands, schemas, aliases, dry-run/preview |
| `context` | manifest/provenance, typed references, usage breakdown, compression lineage and policy-correct projection |
| `intake` | submit durable SDK-origin request, inspect route, correlate source identity |
| `requests` | list/read/watch durable inbox and work lifecycle |
| `tickets` | list/read history, GitHub linkage and durable status projection |
| `approvals` | list/read/approve/reject exact Automonique revisions and provider permission items |
| `scheduler` | queue, concurrency, pause/resume, serialization locks and cancellation projection |
| `automations` | preview/create/edit/pause/resume/run/archive schedules, occurrences, delivery and history |
| `goals` | persistent objectives, criteria/subgoals, waits, continuation budgets and evidence-backed completion |
| `workGraphs` | parent/child work, dependencies, subagents, retries, critical path and blocked-node projection |
| `runs` | list/read/watch/attach/detach/cancel, status, events, usage and diagnostics |
| `executionHosts` | attempt/session host health, lifetime, idle TTL, adoption and authorized stop projection |
| `sandboxes` | profiles/capabilities, effective attestation, resource/egress summaries, violations, quarantine and explainable refusal; no raw policy bypass |
| `sessions` | list attachable, create/follow-up/fork where supported, controller leases and history |
| `conversations` | Automonique conversation state, explicit follow-up binding and bounded history |
| `inputQueue` | enqueue/edit/reorder/withdraw, provider acceptance boundary, retry/undo/stop/compress receipts |
| `memory` | typed user/workspace/team/task records, proposals, FTS session retrieval, external adapters and learning graph |
| `skills` | catalog/search/install/update/bundles, activation, learning proposals, curator/archive and provenance |
| `profiles` | agent profile create/clone/import/export/defaults without implicit tenant/sandbox semantics |
| `tools` | registry/toolsets, deferred search/describe, capability manifests and execution evidence |
| `mcp` | server registrations, tool filters, connection health, scoped exports and sampling policy |
| `extensions` | install/preview/configure/enable/quarantine, manifests, hooks and conformance evidence |
| `providers` | catalog/routing, aliases, health, binary/schema, capabilities, models, auth projection, pools, quotas, auxiliaries, MoA and fallbacks |
| `media` | vision/STT/TTS/image/video/browser/computer adapters and artifact-backed operations |
| `executors` | local/container/SSH/HPC/microVM/cloud capabilities, environment state, hibernate/wake and cost |
| `workspaces` | registry, immutable bases, isolated attempts, locks, diffs and reviewed promotion |
| `artifacts` | metadata, provenance, upload/download grants, retention and publication workflows |
| `identity` | current actor/tenant/roles, external identity links and admin-scoped credential lifecycle |
| `transports` | complete connector catalog installation health, offsets, consent/intents and authorization-safe diagnostics |
| `connectors` | installation registration, capability negotiation, actor/conversation resolution and manifest health |
| `fleet` | Manage claim/heartbeat/report projections and job lifecycle |
| `outbox` | delivery status, failures, reconciliation and authorized retry |
| `reconciliation` | preview typed repair plans, inspect evidence and apply an exact plan revision |
| `github` | durable issue truth/context, linkage and report-publication workflow |
| `support` | inbox query, draft, review, exact-recipient approval and send workflow |
| `sites` | site inventory, read-only summaries and reviewed access/change requests |
| `notifications` | list, acknowledge and manage role-scoped notification state |
| `privilegedActions` | propose, inspect review evidence and observe broker receipt; never arbitrary execution |
| `settings` | schema, readable values, revisioned updates and validation |
| `releases` | list, doctor, reload, rollback, generations and handoff progress |
| `bootstrap` | inspect/plan/verify/resume seed/toolchain/environment state; mutation stays local and explicitly authorized |
| `selfHosting` | source states, build queue, candidate lifecycle, self-host sessions, shadow/comparison/reload/rollback and promotion proposals |
| `developmentEvidence` | metrics, reviews, tests, independent provenance, reproducibility comparisons and gate status |
| `recovery` | backup freshness, restore-drill evidence and safe-mode status; destructive restore remains local/offline |
| `webhooks` | endpoint registration, signing-key rotation projection and delivery receipts |
| `triggers` | inbound route preview/test, signatures, filters/transforms, idempotency and delivery-only behavior |
| `protocols` | ACP/OpenAI/MCP/A2A/relay capability and client/session mapping diagnostics |
| `checkpoints` | list/diff/restore agent-scoped workspace checkpoints with exact target revision |
| `batches` | research/evaluation job submission, resume, trajectory manifests and redacted exports |
| `shells` | local-only capability-gated shell status/attach tokens when the isolated subsystem is enabled |
| `audit` | bounded filtered action/event history and redacted export |

Support mail, GitHub reporting, site/access work and privileged actions remain typed Automonique workflows. Their service methods create/query the same durable proposals, reviews and outbox actions as other clients; they cannot invoke an unreviewed hidden shortcut.

## Client example

```ts
import { Automonique } from "@automonique/sdk/node";

const automonique = await Automonique.connectLocal();
const server = await automonique.system.negotiate();
const abort = new AbortController();

if (!server.capabilities.has("sessions.attach")) {
  throw new Error("This Automonique release cannot attach to sessions");
}

const sessions = await automonique.sessions.listAttachable({ state: "active" });
const session = sessions.items[0];
if (!session) throw new Error("No active session");

const attachment = await automonique.sessions.attach({
  sessionId: session.id,
  afterEventId: session.lastEventId,
});

for await (const event of attachment.events({ signal: abort.signal })) {
  if (event.type === "approval.requested") {
    console.log(event.approval.id, event.approval.summary);
  }
}
```

The actual generated names may evolve, but the semantics—negotiation, explicit identity, cursor, cancellation and discriminated events—are fixed.

## Events, subscriptions and attachment

- Subscriptions use `AsyncIterable` and accept `AbortSignal`, topic filters, buffer policy and `afterEventId`.
- Each event is a closed known variant or an `unknown` forward-compatible variant containing bounded metadata.
- The SDK separates preview, authoritative and synthetic events in its types.
- Cursor expiry produces a typed `ResyncRequiredError` carrying the safe snapshot operation; it never restarts at “now” silently.
- Session attachment returns an `Attachment` handle with identity, observed capabilities, current snapshot, event iterator, detach and control-lease helpers.
- One client connection multiplexes many attachments. Each iterator has independent cursor/backpressure state.
- Detach and iterator cancellation affect only the observer handle, never the runner/provider session.
- Convenience reducers for multi-pane UIs are included in the client package but remain pure and framework-independent.
- All list/search APIs use stable opaque cursors, deterministic tie-breakers, explicit filters and bounded page sizes. A revision/cursor lets clients detect a changing result set instead of silently duplicating or skipping rows.

## Mutations and unknown outcomes

All mutations accept or generate an idempotency key and carry an expected target revision when applicable. The SDK returns an `ActionHandle`/receipt rather than reducing every write to a transport response:

```ts
const action = await automonique.runs.cancel({
  runId,
  expectedRevision,
  reason: "operator request",
  idempotencyKey,
});

const result = await action.wait({ signal });
```

Automatic retry rules are strict:

- safe reads may retry within caller policy;
- subscription reconnect resumes from the last acknowledged cursor;
- mutations are never blindly repeated after an ambiguous disconnect;
- the SDK queries the durable action receipt by idempotency key and returns `unknown` until reconciled;
- conflicts return the current revision and a typed preview invalidation result.

Timeout and cancellation are caller-controlled. `AbortSignal` stops client waiting or subscription work; it does not cancel an Automonique run unless the caller explicitly invokes `runs.cancel`.

## Approvals and interactive control

Automonique work approvals and provider execution approvals are distinct discriminated types. Approval methods require the exact approval ID, target revision/item and decision. The SDK cannot construct a wildcard approval.

Interactive session input uses an explicit controller lease:

- `claimControl` returns lease ID, owner projection, expiry and renewal handle;
- lease renewal is bounded and stops on abort/disconnect;
- steering/provider input includes lease ID and expected turn revision;
- focus, attachment and reconnection never claim or restore control implicitly;
- follow-up, approval and emergency cancellation retain their independent durable semantics.

## Provider adapter SDK

`@automonique/sdk/provider` allows a new agent backend to implement Automonique's normalized provider contract without linking JavaScript into the daemon or execution host. The temporary `@legacy/sdk/provider` export forwards to it. Adapters run as separately supervised, sandboxed processes using the versioned provider protocol.

The SPI covers:

- initialize/version/capability negotiation;
- health, auth projection, models and usage;
- create/load/resume/fork session;
- start/queue/steer/interrupt turn;
- normalized messages, tool calls, subagents and terminal events;
- provider approval requests and responses;
- authoritative history/reconciliation after reconnect;
- shutdown and crash semantics.

The package supplies bounded codecs, redaction helpers, heartbeats and a conformance harness. Declared capabilities are accepted only after behavior tests pass. An adapter cannot request secrets or sandbox grants outside its immutable `RunSpec`, call Automonique transports directly, or bypass the outer approval gate.

The built-in Jcode, Claude, Codex and opencode Rust adapters remain the primary production integrations. The TypeScript provider SPI is an extension and migration surface, not a reason to replace native adapters with JavaScript wrappers.

## General extension and UI SDKs

`@automonique/sdk/extension` implements the manifest and out-of-process contracts in [Tools, MCP, extensions and hooks](tools-extensions-and-hooks.md). Separate entry points prevent a UI plugin from importing backend/tool host helpers. `@automonique/sdk/ui` provides pure read models, subscriptions, actions, design tokens and namespaced storage for dashboard/desktop plugins; TUI widgets use an equivalent generated WASI/declarative schema rather than in-process JavaScript.

Memory/context/model/media/browser/secret-source adapters receive only their declared capability socket and typed settings. Hook filters/transformers use bounded result unions and cannot manufacture approvals or sandbox grants.

## Channel connector SDK

`@automonique/sdk/connector` lets a separately deployed channel service submit authenticated durable input and render authorized events without exposing general operator administration. It supplies installation/tenant/actor resolution, stable source-key builders, action-token/receipt reconciliation, artifact grants, subscription recovery, redacted logging and a connector conformance harness.

The Teams and Discord packages use this SDK but retain their official platform types locally. A connector credential is scoped to named installations and capabilities; it cannot enumerate other tenants, call providers, read workspaces, approve as the external user or create arbitrary outbox destinations.

See [Teams and Discord integrations](channel-integrations.md) and the complete [Connector catalog](connector-catalog.md) for platform-specific behavior.

## Compatibility and capability negotiation

Every connection starts with client/server protocol negotiation containing:

- SDK version and schema digest;
- supported protocol range;
- runtime and transport features;
- server release/generation and protocol range;
- authorized capability set and resource limits;
- deprecations and minimum compatible SDK when applicable.

The SDK must tolerate additive response/event fields and unknown read-only event variants. It refuses a mutation when its exact request schema/capability is not negotiated. Deprecated APIs remain through a documented window and emit development-time warnings without leaking data in production logs. Canonical and legacy packages negotiate identically and pass the same conformance suite.

SDK semantic version and Automonique application version are independent. A compatibility table and machine-readable manifest identify supported combinations. Adjacent Automonique releases must accept the SDK shipped with either release during generation overlap.

## Authentication and security

- Local Node/Bun clients use Unix peer credentials; possessing the package grants no authority.
- Remote clients use server-issued scoped credentials/session mechanisms and TLS; the SDK never accepts secrets in URLs.
- Browser auth is injected by the host application and never bundled into generated source.
- Every method is authorized server-side against negotiated roles/scopes.
- SDK credentials are tenant-bound, named, expiring, rotatable and individually revocable. Creation returns secret material once; ordinary reads expose only descriptors and last-used/expiry state.
- Secret-bearing values use redacted wrappers and are excluded from default serialization/logging.
- The SDK logger receives structured redacted metadata, not arbitrary request bodies.
- Raw provider records, hidden reasoning, credentials and unrestricted filesystem paths are absent from ordinary client types.
- Sandbox APIs expose redacted evidence and typed profile selection only; clients cannot submit arbitrary paths, destinations, seccomp rules, namespace options or privileged launcher input.
- The provider SPI runs out of process and crosses the same bounded validation/sandbox boundary as native adapters.
- Provider extension packages require pinned digests, provenance, an allowlisted capability manifest and conformance results before production enablement.

## Developer experience

Each service ships:

- generated API reference linked to protocol/schema source;
- runnable Node/Bun and browser examples;
- examples for request submission, approvals, event watching, N attachments, control leases and reload progress;
- typed error documentation and retry guidance;
- changelog and migration guide;
- source maps and declaration maps without embedding secrets/build-host paths.

The testing package supplies:

- an in-memory `AutomoniqueTransport` (`LegacyTransport` compatibility alias) and deterministic fake clock;
- builders for valid bounded domain records;
- golden provider/operator event streams;
- fault injection for gaps, duplicates, disconnects, stale revisions and ambiguous mutations;
- a fake provider host and adapter conformance runner;
- fake Teams/Discord connector servers and installation/action/artifact/restart fixtures;
- fake generic connector, MCP, extension, hook, automation, ACP/OpenAI and remote-executor hosts;
- context/memory/skill/goal/input-queue/checkpoint fixtures plus time/DST and learning-proposal fault injection;
- record/replay with mandatory redaction and fixture size limits.

## Release and supply chain

- Build SDK packages from the same commit and schema artifacts as the Rust release.
- Produce deterministic package archives and verify their contents in CI.
- Publish provenance/signatures using the repository's release policy.
- Include license, repository, commit, schema digest and protocol range metadata.
- Reject generated output drift, undeclared runtime dependencies, Node-only imports in browser bundles and accidental secret fixtures.
- Keep at least the current and previous compatible SDK available throughout the rollback window.
- Build connector packages/manifests from pinned Microsoft/Discord dependencies, record platform schema/permission diffs and prohibit secrets or live installation IDs in archives.
- Build every extension/connector/UI package from pinned sources with its manifest, license, capabilities, schema digest, platform matrix and revocation metadata.

## Explicit non-goals

- A direct SQLite client or migration API.
- Arbitrary root broker, shell, provider socket or runner spool access.
- Client-side reimplementation of routing, approval or authorization policy.
- A second set of handwritten types for the dashboard.
- Framework lock-in; React/Vue/Svelte bindings may be thin optional packages later.
- Claiming every internal Rust function is a supported remote operation.

## SDK exit gate

The SDK is production-ready when the dashboard uses it exclusively, a Node/Bun program can exercise every authorized operator service, N concurrent session attachments survive daemon reload, ambiguous mutations reconcile exactly once, the provider/connector/extension/UI/MCP/public-protocol/executor conformance fixtures pass against Rust, browser/Node/connector bundles contain only their allowed dependencies, generated artifacts reproduce from the release schemas, every row of the external capability ledger has an SDK representation or documented no-client reason, and the current/previous SDK-release compatibility matrix—including canonical `@automonique` and supported forwarding `@legacy` packages—passes without private endpoints or handwritten wire types. The development package must additionally drive bootstrap inspection, stable/candidate build and self-host fixtures, independent evidence comparison and promotion proposals without exposing signing material, protected-ref mutation or a candidate-only shortcut.
