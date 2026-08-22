# Monique agent harness

Monique's conversational runtime is moving to a bounded agent harness.
Transport code authenticates the actor, binds the room and delivers replies;
it does not infer
tool authority from prose. The model chooses only among a granted catalog, and
the broker validates every call before an executor can run.

## Boundaries

- `agent_profile` defines shared-room conversation identity, actor-authored
  turns, presentation-only persona, security-policy revision and context
  manifests. Persona has no authority or tool fields.
- `agent_harness` owns model rounds and the append-only turn transcript. A
  model step returns either a final answer or one typed tool call. Tool results
  return to the model until the turn completes or a bound is reached.
- `agent_tool_broker` owns the local registry, granted catalog, schema
  validation, effect classification, replay fencing and approval custody.
- `agent_runtime` adapts the broker to the harness. Its replay identity derives
  from the trusted transport namespace plus canonical tool arguments, not a
  provider-generated call id.

The provider, model, persona and tool result cannot grant authority. Tools are
registered locally, catalog grants are exact and revision-bound, and only a
locally declared read-only tool with no approval requirement can execute
automatically. Every effect-shaped call is frozen before execution.

## Conversation model

A conversation belongs to a transport room, not to the participant who spoke
last. Slack keys a lane by installation, channel and thread. Telegram keys it
by bot installation, chat and optional topic. The actor remains attached to
each turn for authorization and private-memory filtering.

The canonical Automonique transcript remains the source of recovery. A native
provider session may later cache that transcript, but it must never become the
only copy or cross a room, persona, policy, toolset or model revision.

## Turn bounds

The conversational defaults are deliberately small:

- four model rounds;
- six total tool calls;
- two calls per tool;
- one identical canonical call;
- bounded catalog, arguments, results, transcript and final answer.

Malformed model control output is a typed failure and is never displayed as a
fallback answer. Repeated calls and exhausted bounds stop the turn rather than
creating implicit background work.

## Agentic scratchpads from chat

Slack and Telegram conversation may escalate a task that needs non-trivial
computation or iterative code execution into one `agentic_scratchpad` approval
card. The card shows the exact frozen task. It creates and runs nothing until a
configured administrator approves it; denial performs no work.

Approval submits the frozen task through the same durable contained run lane as
`/run`, under a distinct trusted profile. That profile provides an empty
writable per-run workspace and read/execute access to bounded system runtimes,
so the provider may create, execute, test, and revise scripts. Resource limits,
the brokered network allowlist, run custody, progress, cancellation, and `/runs`
visibility remain unchanged. No repository, production path, customer data, or
ambient credential is mounted because chat text names it.

This is not a substitute for ticket execution. A canonical GitHub or Manage
ticket continues through its mapped workspace and existing authorization flow,
which may grant task-specific repository and deployment capabilities that an
empty conversational scratchpad does not have.

## Approval and replay

An effect proposal freezes the exact tool, canonical arguments, local
descriptor revision, digest and broker-owned idempotency key. Approval pauses
the harness. Denial executes nothing. Approval resumes only the exact frozen
request, and repeated decisions return the recorded outcome.

Provider call ids are correlation data, not replay authority. Transport
redelivery uses a stable trusted namespace and canonical call digest. An
executor that started without a confirmed receipt must report an ambiguous
outcome and must not be retried blindly.

## Transport migration

Deterministic commands, authentication, delivery, deduplication, source-of-
truth rules and approval custody stay in code. Semantic phrase lists and
canned personality replies move behind the harness. During migration the old
closed intent schema is accepted as a provider adapter, but malformed JSON-like
output fails closed and tool calls still pass through the broker.

The safe rollout order is:

1. shared profile, harness and broker conformance tests;
2. synchronous Slack/CLI read-tool loop;
3. Telegram background continuation with the same transcript contract;
4. durable approval pause/resume on both transports;
5. provider-session caching after adapter conformance;
6. removal of remaining semantic routing branches.

No rollout step may infer production delivery from a pending Manage job, an
online worker, a Slack reply or a provider process. The canonical GitHub issue,
trusted completion evidence and live verification remain distinct facts.
