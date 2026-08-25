# Agent integrations

## Purpose

Automonique must integrate deeply with Jcode, Claude Code, Codex and opencode without forcing them into one artificial protocol. The common layer normalizes lifecycle and safety; provider adapters retain native capabilities.

Primary references used for this plan:

- the installed CLI help/version output on the current legacy host;
- Jcode's installed ACP, daemon socket, server reload, auth, model and usage surfaces;
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage);
- [Codex App Server manual](https://learn.chatgpt.com/docs/app-server.md) and the installed schema generator;
- [opencode server API](https://dev.opencode.ai/docs/server/) and [ACP support](https://dev.opencode.ai/docs/acp/).

## Layering

```text
automonique daemon
  └─ Automonique work/session API
       └─ execution-host control protocol
            └─ automonique-runner (attempt- or session-scoped provider proxy)
                 ├─ JCode protocol-v1 adapter -> contained `jcode api-stdio`
                 ├─ Claude stream-json adapter -> Claude Code process
                 ├─ Codex app-server adapter -> Codex App Server process
                 └─ opencode HTTP/SSE adapter -> opencode server process
```

The execution host, provider process and raw event journal survive an Automonique generation reload. the `automonique` daemon can disconnect and later subscribe from the last committed normalized event sequence. The host's lifetime is explicit: attempt-scoped for one-shot work or session-scoped for resumable multi-turn agents.

## Common capability model

Capabilities are observed at runtime and persisted with the run/session binding. They are not inferred forever from the provider name.

```rust
struct AgentCapabilities {
    protocol: ProtocolIdentity,
    sessions: SessionCapabilities,
    turns: TurnCapabilities,
    events: EventCapabilities,
    approvals: ApprovalCapabilities,
    tools: ToolCapabilities,
    telemetry: TelemetryCapabilities,
    lifecycle: LifecycleCapabilities,
}
```

Important capability flags include:

- create, load/resume, fork, list/read, rename, archive and compact session;
- start turn, queue input, steer active turn, interrupt and retry;
- replayable event history, authoritative completed messages, text/tool deltas, hook/subagent events;
- command, file, network, MCP, elicitation and generic permission approvals;
- MCP status/calls, skills, plugins, attachments, structured output and custom tools;
- model catalog, auth state, quota/rate limit, usage/cost and token/cache telemetry;
- provider daemon reconnect/reload and session survival guarantees.

Each adapter declares three sets:

- `required`: Automonique cannot safely run without these capabilities;
- `native`: available and tested for this binary/protocol;
- `degraded`: missing in the selected fallback.

Selection fails closed when a required capability is missing. It never silently replaces an approval-aware protocol with auto-approval, or a resumable session with a fresh run.

## Distinct identities

Persist these separately:

- `work_id`: Automonique's approved unit of business work;
- `run_id`: one attempt at a work item (retries receive new IDs and attempt numbers);
- `host_id`: one supervised execution-host unit, which may serve one attempt or a serialized session;
- `provider_instance_id`: daemon/server process or socket identity;
- `provider_session_id`: durable conversation/thread identity;
- `provider_turn_id`: one active user turn/request;
- `provider_item_id`: tool/message/approval item when supplied;
- `provider_request_id`: protocol request correlation;
- `provider_event_id` or source cursor when supplied.

Use structured session bindings including tenant, backend, provider account/instance and session ID, never an unvalidated opaque value that can accidentally resume through another tenant, account or backend.

## Normalized event model

Raw provider events are recorded with provider, binary version, protocol mode and schema hash. A bounded normalized event stream drives Automonique:

- `ProviderConnected` / `ProviderDisconnected`;
- `SessionCreated` / `SessionLoaded` / `SessionUpdated`;
- `TurnQueued` / `TurnStarted` / `TurnSteered` / `TurnInterrupted` / `TurnCompleted`;
- `AssistantPreviewDelta` — ephemeral presentation only;
- `AssistantMessageCompleted` — authoritative text;
- `ToolCallStarted` / `ToolCallUpdated` / `ToolCallCompleted`;
- `ApprovalRequested` / `ApprovalResolved`;
- `InputRequested` — a provider input request pausing the turn until the
  controller lease holder answers it; distinct from an approval because the two
  are answered through different authorities;
- `SubagentStarted` / `SubagentEvent` / `SubagentCompleted`;
- `UsageUpdated`;
- `ProviderWarning` / `ProviderFault`;
- `RunTerminal`.

Preview/delta events may be dropped after bounded retention and never determine final reports. Completed provider messages/items or reconciled history are authoritative.

Every normalized record contains an Automonique sequence, provider coordinates, source event type, source schema/version, timestamp, authority (`preview`, `authoritative`, `synthetic`), and bounded payload.

## Approval bridge

Automonique has two separate approval layers:

1. **Outer Automonique approval:** authorizes the reviewed ticket/action to start.
2. **Provider execution approval:** a command, file, network, MCP or permission request raised while the approved job runs.

Provider requests are mapped into a typed `ProviderApprovalRequest`. A deterministic local policy may allow or deny requests already covered by Automonique's sandbox and approved scope. Anything requiring new authority becomes a durable Automonique approval and pauses the provider turn. The response carries the original provider request/item/turn coordinates and is idempotent.

An adapter without an approval response channel can run only in an externally sandboxed mode whose policy covers the complete approved scope. Otherwise it is ineligible for that job.

## Jcode

### Production target and rollout state

The maintained JCode fork is the production provider-execution engine target.
Its version-one supervised stdio adapter passes local protocol and containment
conformance. Production selection and the federated live canary remain the
rollout gates; the direct Codex JSONL path is rollback-only during that canary.

### Preferred surface

Run the exact configured binary as `jcode api-stdio` inside the same
attempt-scoped sandbox and cgroup as the provider turn. Automonique owns the
process, protocol stream, session journal, approval bridge, controller queues
and termination. JCode may supervise its internal server child only inside
that same execution boundary; no shared external daemon or debug socket is a
production dependency.

The adapter negotiates protocol version one and a closed capability set before
opening or attaching a session. It uses newline-delimited typed requests and
events over inherited stdio, with bounded frames and no terminal scraping.
Every process, session, turn, provider request and terminal settlement is
committed to the provider journal before it is projected.

### Capability contract

A `hello_ok` negotiates only when it advertises every base capability
(`sessions`, `streaming`, `cancellation`, `soft_interrupt`, `history`,
`model_catalog`, `reasoning_effort`, `usage`, `runtime_info`) plus one
input-request capability:

- `stdin_requests` is the maintained harness API. The engine forwards
  `stdin_request` events (session, request, prompt, password mask, tool-call
  identity) and accepts the correlated `stdin_response` request.
- `permission_requests` is the advertisement of pinned builds that predate the
  maintained harness exposing stdin requests. It is accepted only when
  `stdin_requests` is absent, so the daemon carrying this contract is deployed
  first and the engine pin moves afterwards with no flag day.
- A build advertising neither is refused as `missing_capability`.

Additive capabilities are ignored. Both `permission_request` and
`stdin_request` events are bridged whichever mode negotiated: Automonique
answers the request it observes, not the one advertised.

The negotiated capability list is recorded exactly as the write-once
`jcode-harness-api` binding of the journal session each process opens, next to
the `jcode-server` identity and `jcode-execution-config` bindings. Those
bindings are evidence, not version pins. The journal's resume and replay drift
tuple is what Automonique presents to the engine — prompt version, tool schema
version and model — and it deliberately excludes the executable digest, so an
engine build may change beneath one attempt. An exact-session resume whose new
`hello_ok` still negotiates is therefore compatible even when its capability
list, including the input-request mode, differs from the recorded one; the
change stays auditable through the differing session bindings. Only a hello
that fails the contract above refuses the resume.

The composed sandbox environment sets `JCODE_NO_TELEMETRY=1` for a JCode
workload. The sandbox has no telemetry egress, so the opt-out changes nothing
the engine can reach; it only keeps the engine's opt-out notice out of every
contained run's journal.

### Integration work

- Pin the executable digest, reported build revision and protocol version.
- Prove create/attach, prompt, streaming, exact resume, permission response,
  lease-authorized steering, cancellation and terminal settlement.
- Bind each Automonique session key to the exact JCode session ID and contained
  process identity; a mismatched resume fails closed.
- Project fixed read-only `model list --json`, `provider current --json` and
  `usage --json` results without account identity or credentials.
- Reject duplicate, reordered, cross-session or post-terminal records unless
  the journal can reconcile them deterministically.
- Prove every JCode descendant remains inside the declared execution boundary
  and that close/cancel leaves no process, control queue or ambiguous request.

### Fallback

No JCode terminal, `run --ndjson`, shared-daemon or debug-socket fallback may
claim production equivalence. During the canary only, the separately pinned
direct Codex JSONL compatibility path may handle explicitly eligible work and
must report its reduced capability set. It is removed from production
selection once the JCode live vertical slice passes.

## Claude Code

### Preferred surface

Run one long-lived Claude Code SDK/print process inside a session-scoped execution host:

```text
claude -p
  --input-format stream-json
  --output-format stream-json
  --verbose
  --replay-user-messages
  --include-partial-messages
  --include-hook-events
  --forward-subagent-text
```

The exact flags are capability-probed because some require specific Claude Code versions. Realtime stream input lets one process accept later messages; replay acknowledgements correlate accepted input; partial, hook and forwarded subagent events improve observability.

### Integration work

- Preallocate and persist `--session-id` before the first user message when supported.
- Correlate replayed user messages with Automonique input IDs.
- Treat partial messages as previews and final assistant/result messages as authoritative.
- Persist the first session ID before any timeout path can lose it.
- Support `--resume`, `--fork-session`, named sessions and per-turn queued input.
- Map permission policy, allowed/disallowed tools, MCP config, settings sources, effort, model, fallback model, budget and maximum turns into validated adapter configuration.
- Include hook lifecycle and subagent coordinates without exposing unbounded reasoning content.
- Use an explicit MCP permission-prompt bridge when tool-level approval is required and supported.
- Probe `claude auth status`, version and background-agent inventory for health only; do not make undocumented background-agent control Automonique's primary lifecycle.

Claude Code has no required shared daemon in this design. The long-lived CLI process survives Automonique reload because its host unit owns it. Provider binary upgrades affect new hosts; an active Claude process remains pinned until its session proxy closes or reaches idle TTL.

### Fallback

Use one-shot `claude -p --output-format stream-json --verbose` and resume by captured session ID. This retains session continuation but loses bidirectional in-process steering and may have narrower event visibility. Jobs requiring live steering or provider approval pause cannot silently use this fallback.

## Codex

### Current production status

Production temporarily uses the pinned Codex CLI `exec --json` fallback at
version 0.149.0. The fallback preserves durable new/resumed thread identity,
the answer-file contract and normalized JSONL progress. It does not advertise
App Server-only steering, provider approval/input RPCs, model/account RPCs or
authoritative item-history reconciliation. This fallback remains available for
truthfully degraded operation after the JCode cutover; the preferred App Server
surface below is Codex-specific future capability, not a replacement for the
JCode production target or a claim about the deployed adapter.

### Preferred surface

Start one `codex app-server --listen stdio:// --strict-config` inside an execution-host process boundary. Use stdio JSONL, not remote WebSocket. The installed CLI can generate a JSON Schema bundle for its exact version; check that bundle into adapter fixtures and include its hash in the host manifest.

The adapter performs `initialize`/`initialized`, identifies itself as Automonique, and uses stable methods without opting into `experimentalApi` by default.

### Integration work

- Start/resume/fork/read Codex threads and persist thread IDs.
- Start turns with explicit cwd, model, effort/personality, sandbox and approval policy.
- Implement `turn/steer` and `turn/interrupt`.
- Subscribe to thread/turn/item notifications and reconcile stored thread history after reconnect.
- Map command, file, network, MCP elicitation, user-input and permission approval requests into Automonique's bridge.
- Normalize agent messages, command execution, file changes, MCP calls, reviews, token usage and turn status.
- Use `model/list`, provider capabilities, `account/read`, rate-limit/usage reads, MCP status, skills and hooks for health/capability reporting.
- Generate and diff App Server schemas on every Codex upgrade before enabling that version.
- Maintain an allowlist of methods; notably do not expose APIs that execute outside the selected Automonique sandbox merely because App Server offers them.

Codex's App Server command and some transports/methods carry experimental maturity. Therefore this adapter is version-pinned and canary-gated. Remote WebSocket is not required; host-local stdio avoids unsupported remote transport and keeps the provider process inside the execution host's cgroup and Landlock boundary.

### Fallback

Use `codex exec --json -` and `codex exec resume <thread> --json -`. Prompt delivery stays on stdin. The fallback preserves basic streaming and resume but loses rich thread inspection, steering, approval server requests, model/account RPC and authoritative item reconciliation. Automonique records the downgrade and applies job eligibility rules.

## opencode

### Preferred surface

Start a dedicated `opencode serve` instance inside an execution-host process boundary, bound to loopback on an allocated port. Set a random high-entropy Basic Auth password through a protected credential descriptor/environment mechanism, never argv or a durable spec. Generate or vendor a Rust client from the server's OpenAPI 3.1 document for the pinned opencode version.

Use:

- `/global/health` for version/readiness;
- session create/read/status/fork/abort/diff/summarize APIs;
- asynchronous prompt submission;
- `/event` or `/global/event` SSE for live events;
- session message history for reconnect reconciliation;
- permission response endpoint for provider approvals;
- provider/model, MCP, agent and command inventories for capabilities.

### Integration work

- Pin each server to one tenant/workspace security context; do not share a mutable server across unrelated tenants or cwd policies.
- Allocate the port without a bind race, or add a Unix-socket front/proxy owned by the runner.
- Keep Basic Auth material only in runner memory/environment and redact HTTP traces.
- Persist session/message IDs and distinguish SSE preview/live events from stored message history.
- On SSE reconnect, reconcile session status and message history before resuming live delivery.
- Map async prompt, abort, permission response, forks, diffs, todos, costs and provider state.
- Snapshot/diff the OpenAPI schema on upgrade.
- Disable or explicitly configure external plugins using `--pure` according to Automonique policy.

### ACP and CLI fallbacks

`opencode acp` is the first fallback and communicates over JSON-RPC stdio. It retains tools, MCP, project rules, agents and permissions, although its documented surface does not support every built-in slash command. If both HTTP and ACP fail conformance, use `opencode run --format json` with explicit session/model/agent/dir settings.

Fallback selection is capability-driven: HTTP is preferred for session history, status, abort, permission and SSE reconciliation; ACP is useful as a standardized interactive bridge; run mode is last-resort one-shot compatibility.

## Provider process and upgrade policy

| Situation | Policy |
|---|---|
| Automonique daemon reload | Provider process and execution host remain untouched; new Automonique generation re-subscribes |
| Host protocol upgrade | Active host stays on old compatible binary; new hosts use the new binary |
| Jcode daemon upgrade | Use Jcode graceful server reload only after ACP compatibility canary |
| Claude/Codex/opencode binary upgrade | Do not replace an active provider process; drain its host and use the new binary for new hosts |
| Provider protocol mismatch | Refuse native mode; use an explicitly eligible fallback or reject the job |
| Provider process crash | Restart/reconnect only if session and authoritative history can be reconciled; otherwise report resumable failure |
| Machine reboot | Reconcile persisted provider sessions; distinguish resumable conversation from lost local tool process |

Auto-update is disabled for Automonique-owned invocations. Binary upgrades occur through explicit Automonique release/canary procedures so schema and behavior cannot change midway through an active run.

Executable selection returns an immutable opened file/verified image identity, not only a path string. Credential selection returns a versioned descriptor resolved by the host at launch. Both digest and descriptor version are recorded with the run so rotation affects new attempts without mutating in-flight evidence.

## Adapter conformance suite

Every integration mode must prove:

1. version and capability probe without a model call;
2. new session and exact persisted provider identity;
3. follow-up/resume after runner client reconnect;
4. authoritative final message after dropped preview deltas;
5. tool start/update/result normalization;
6. approval request, durable pause, idempotent response and completion;
7. steer/queued input semantics where advertised;
8. cancellation and provider terminal state;
9. auth/model/usage/health projection with redaction;
10. Automonique generation reload during an active turn;
11. provider process/daemon reload or crash at each event boundary;
12. schema drift detection and fallback eligibility;
13. sandbox/cwd/tool policy attestation;
14. session serialization across concurrent Automonique work;
15. no secret or prompt leakage through argv, logs or diagnostics.

Conformance results are keyed by provider binary digest, version, integration mode, schema hash and Automonique adapter version. A binary digest without a passing record cannot become the production native adapter automatically.
