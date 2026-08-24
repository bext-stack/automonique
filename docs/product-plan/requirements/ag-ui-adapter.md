# AG-UI compatibility adapter

**Status:** accepted architecture; bounded translator implementation started

## Pinned compatibility contract

The first implementation line targets `@ag-ui/core` **0.0.58**, installed as
an exact dependency with its complete transitive resolution in
`adapters/ag-ui/bun.lock`. The canonical TypeScript runtime schemas validate
every translated output in both product code and golden tests. Changing that
version, lockfile, or the emitted capability set is a reviewed compatibility
change, not an ambient package update.

The first bounded code slice lives in `adapters/ag-ui/`. It defines a sanitized
adapter-internal native event projection and a deterministic, side-effect-free
translator. It deliberately contains no listener, credentials, durable state,
or mutation path. Separately supervised service scaffolding and health
reporting remain the next delivery slice.

## Decision

Automonique should support the [Agent User Interaction Protocol
(AG-UI)](https://docs.ag-ui.com/introduction) as a user-interface compatibility
adapter. AG-UI does not replace Automonique Platform v1, the native Runs API,
Slack, or any durable domain service.

The first implementation is a separately supervised, unprivileged adapter. It
translates native session, turn, event, approval, and action services into a
pinned AG-UI event stream. The Automonique daemon remains the sole owner of
state and effects. Manage exposes the browser-facing endpoint and retains
identity, tenant and node selection, rate limiting, CORS, and CSRF policy.

```text
browser or other generic AG-UI client
                  |
          Manage /api/ag-ui
    identity, tenant/node scope, limits
                  |
      automonique-agui-adapter
       loopback or protected Unix transport
                  |
       Automonique native SDK
                  |
        Automonique daemon
       sole state/effect authority

ShellDeck -------- Platform v1 --------+
    `-- optional AG-UI conversation client later
```

ShellDeck keeps its native Platform v1 cockpit. A future AG-UI client in
ShellDeck is only a conversational surface and gains no fleet-control
authority.

## Why this boundary

AG-UI is an event protocol for bidirectional agent/user interaction. Its
streaming messages, tools, shared-state projections, activities, and interrupts
fit Automonique's user-facing surfaces. Its state is not a durable business
domain, however. Treating an AG-UI thread, state patch, or tool declaration as
canonical would create a second session store, action system, or policy engine.

The adapter therefore follows the same rule as ACP, OpenAI, MCP-server, and A2A:
external identifiers resolve to native resources under the authenticated actor;
all effects pass through native revision, policy, idempotency, and receipt
checks.

## Ownership and identity

| Concept | Owner and mapping |
| --- | --- |
| AG-UI `threadId` | Resolves to one durable, authorized Automonique session. |
| AG-UI `runId` | Maps to one native turn execution, not an AI Operations job. |
| AI Operations job | Remains a namespaced custom resource with its own lifecycle. |
| AG-UI messages/state | Derived projections; never authoritative records. |
| Resume payload | An untrusted proposal mapped to a revision-bound native action. |
| Tool declaration | A capability proposal intersected with the native registry and policy. |

Manage resolves every thread, run, approval, and node under the authenticated
actor and tenant. It must not accept client ownership claims or require private
node identifiers in standard AG-UI payloads. Manage sends the selected adapter
a short-lived, audience-bound node credential. Credentials never appear in
query strings, events, logs, or client-visible errors.

## Event mapping

The translator is deterministic and fixture-tested:

| Native event | AG-UI projection |
| --- | --- |
| Turn start | `RUN_STARTED` |
| Successful terminal turn | `RUN_FINISHED` |
| Failed terminal turn | Sanitized `RUN_ERROR` |
| Append-only authoritative assistant text | `TEXT_MESSAGE_START`, one or more `TEXT_MESSAGE_CONTENT`, `TEXT_MESSAGE_END` |
| Tool invocation | `TOOL_CALL_START`, streamed `TOOL_CALL_ARGS`, `TOOL_CALL_END`, then `TOOL_CALL_RESULT` |
| Bounded UI read model | `STATE_SNAPSHOT` and RFC 6902 `STATE_DELTA` |
| Work progress | Step or activity events |
| Native approval gate | Interrupt outcome after messages and state are checkpointed |
| Native coordinates, cursors, receipts, artifacts, or control loss | Namespaced `CUSTOM` events |

Provider preview text is streamed as standard message content only when the
provider guarantees that it is append-only and equivalent to the authoritative
final record. Otherwise the adapter waits for the final record or uses a clearly
namespaced, replaceable preview event. Raw provider records, hidden reasoning,
chain of thought, credential material, and unrestricted tool arguments/results
are never emitted.

Every run begins with `RUN_STARTED` and ends exactly once with `RUN_FINISHED` or
`RUN_ERROR`. An interrupted run finishes with the protocol's interrupt outcome;
resumption creates a new run and invokes native approval policy. Stream
disconnect does not imply cancellation or success.

## State, reconnect, and backpressure

Native event sequence and resource revisions are included in namespaced event
metadata. The adapter checkpoints the last emitted native cursor. Reconnect
either resumes from a retained cursor or returns a typed resynchronization
requirement followed by an authorized snapshot; it never invents missing
deltas.

State patches are bounded derived projections. Inbound state and `forwardedProps`
are ignored unless a field is explicitly allowlisted and mapped to a native
command. Streams have bounded messages, event rates, buffering, run duration,
and subscriber counts. A slow client is disconnected with a resumable cursor
before it can block daemon event consumption.

## Mutation safety

New-turn submission, cancellation, and approval resume require stable
idempotency keys. The adapter persists or can recover the native action receipt
before acknowledging acceptance. If the HTTP result is lost, the client
reconciles the same key through the native receipt service instead of submitting
a new effect.

Client tool schemas do not install or authorize tools. The adapter intersects
requested tools with the actor's native registry and current policy revision.
Approval resumes identify the exact native approval, expected resource
revision, choice, and idempotency key. Stale, already-resolved, cross-tenant, or
unknown approvals fail closed with typed public errors.

Artifact links are scoped, short-lived, and re-authorized on retrieval. The
adapter has no database, provider socket, credential-store, arbitrary action,
deployment, or workspace filesystem access.

## Implementation choice

The first server adapter should use the mature, pinned TypeScript AG-UI server
packages in a separate process. It consumes only the generated Automonique SDK
and a least-authority node credential. Its package lock, schema fixture digest,
and supported capability table are release inputs.

The official repository now includes the community Rust `ag-ui-client` 0.1.0,
but its README describes state/message integration as work in progress. It is a
client rather than the required server adapter. Do not add it to the daemon or
Platform v1 dependency graph. It may be evaluated behind an optional ShellDeck
feature after golden-fixture, reconnect, dependency, and security review. Pin
the exact version; do not track its main branch.

Reconsider a Rust-native server adapter only when its ecosystem has complete
state and interrupt semantics, local conformance coverage, and an acceptable
maintenance history.

## Delivery phases

1. Freeze the AG-UI version, package lock, capability table, event matrix,
   public error model, and threat model.
2. Implement a pure native-event-to-AG-UI translator with golden fixtures and
   no network or effect authority.
3. Expose authenticated, read-only session replay and cursor reconnect through
   Manage.
4. Add new-turn submission and live streaming with durable idempotency receipts.
5. Add cancellation, then native approval interrupts and resume.
6. Trial supported generic browser clients behind tenant and node feature
   flags.
7. Evaluate optional ShellDeck conversation support behind a compile-time and
   runtime feature gate.
8. Graduate only after isolation, reload, reconnect, compatibility,
   backpressure, and rollback gates pass in staging and production canaries.

Each phase is independently disableable. Read-only replay ships before any
mutation. Approval resume ships after ordinary mutation recovery, not before.

## Conformance and release gates

Required automated evidence includes:

- golden mapping and terminal ordering for every supported event;
- duplicate, missing, out-of-order, unknown, oversized, and expired-cursor
  cases;
- preview/final equivalence and non-equivalent-preview fallback;
- cross-tenant identifiers, forged tools/state/resume, redaction, and hidden
  reasoning tests;
- disconnect after every event boundary, adapter restart, and daemon generation
  handoff;
- browser to Manage to adapter to daemon workflows for submit, tools,
  cancellation, approval, parallel interrupts, and provider failure;
- pinned-client compatibility fixtures and explicit unsupported-capability
  behavior;
- rate, buffer, memory, latency, and slow-consumer limits;
- rollback to Platform/native-only operation without session or receipt loss.

Production readiness requires evidence that the adapter can be stopped without
affecting the daemon, Slack, Manage AI Operations jobs, or ShellDeck Platform
v1. No compatibility test may rely on raw chain of thought.

## Explicit non-goals

- Replacing Platform v1, the native Runs API, Slack, ACP, MCP, A2A, or native
  ShellDeck AI.
- Giving AG-UI messages or state canonical ownership.
- Flattening an AI Operations job into an AG-UI run.
- Exposing chain of thought or raw provider events.
- Turning ShellDeck or the adapter into an executor.
- Letting client tool declarations, state patches, or interrupt responses bypass
  native authorization.

## Exit gate

The adapter may be called supported only when an authenticated client can replay,
start, disconnect, resume, cancel, and complete a session across adapter and
daemon restarts; approvals remain exact and idempotent; tenant isolation and
redaction tests pass; and disabling AG-UI leaves all canonical Automonique,
Manage, Slack, and ShellDeck behavior unchanged.
