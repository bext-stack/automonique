<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Unified client platform

**Status:** shared clients and production TUI deployed; JCode provider implementation complete and cutover verification in progress

## Delivery status

As of 2026-08-23, the contract/fork baseline, shared substrate, client
convergence, ShellDeck execution cleanup and the production TUI are deployed.
The current vertical slice has completed AI Operations release approval and
job delivery through a registered Automonique node, the temporary pinned Codex
CLI fallback and an ordered terminal receipt. Exact idempotent replay returns
the original completed receipt, and the JCode-derived TUI, the ShellDeck
client-only build and the hosted web surface agree on the authority-qualified
provider model catalog. The JCode adapter now passes local protocol,
containment, session-resume, approval, steering and cancellation conformance.
The target vertical slice remains incomplete until the immutable release is
selected in production and the federated live run is verified.

The maintained JCode cockpit is installed as the `automonique tui` managed
client. Production verification submitted a new durable request, reconciled
its completed receipt and exact provider session, resumed that same session
for a follow-up, and exercised observer attach, exclusive control acquisition,
control release and detach. Both provider answers matched their requested
canaries, the session revision advanced, terminal teardown restored the shell,
and the daemon returned to zero running, pending, outbox and reconciliation
work. The JSON cockpit projection also returned the fresh configured-account
model catalog, replacing the former status-only answer path.

ShellDeck's client-only implementation is published and merged after Linux,
macOS, Windows, dependency-policy and RustSec checks. The production worker now
uses the owned AI Operations platform and support routes, and the superseded
fleet endpoint is absent in source and returns 404 in production. The central
epic and repository issues retain the delivery evidence.

## Outcome

AI Operations, Automonique, the maintained JCode fork, ShellDeck and
`monique.1clic.pro` form one federated product without pretending that their
state is one database. They share resource identities, commands, events,
receipts and client reducers while retaining explicit authority boundaries.

The shipped clients are:

- the JCode-derived `automonique tui`, using the shared Rust client;
- ShellDeck, using the same Rust client from GPUI;
- `monique.1clic.pro`, remaining in `automonique-web-entry` and using the
  generated browser SDK;
- the CLI and supported automation clients, using the same domain services.

No client owns business policy, invents an approval path or executes a provider
behind the control plane in managed mode.

The maintained JCode fork is also the target production provider-execution
engine. Automonique remains the execution authority and hosts JCode through a
pinned adapter; JCode does not become a second control plane. The current
direct Codex JSONL route is a temporary, capability-reduced fallback.

## Authority map

| Authority | Owns | Does not own |
|---|---|---|
| AI Operations | global jobs, release approvals, fleet/node registration, assignment and organization-wide coordination | local process truth, sandbox enforcement, provider credentials or session control |
| Automonique node | local intake and execution, sandbox/credential admission, provider hosts and sessions, local/provider approvals, ordered events, action receipts and controller leases | GitHub issue truth or an AI Operations job state it has not received |
| GitHub | issue scope, checklist, discussion, pull requests and recorded delivery evidence | live execution or node health |
| JCode engine/provider | target provider-native session execution and raw/provider events | work authority, external-effect approval or canonical job state |
| Direct Codex compatibility path | rollback-only degraded execution during the JCode production canary | changing the JCode production target or advertising unavailable native controls |
| Clients | authorized projections, composition and explicit typed actions | durable authority, direct provider bypasses or private retry semantics |

Every cross-authority record carries its authority, opaque resource ID,
revision and freshness. A projection may correlate records, but never collapses
AI Operations `pending`, node `running`, provider activity and GitHub delivery
into one status.

AI Operations owns approval to release a global job. Automonique separately
owns approvals required by the selected local action, sandbox or provider.
Granting either approval never grants the other implicitly.

## Platform contract v1

The Rust domain schema in Automonique remains the source for generated Rust and
TypeScript clients. Local clients use the peer-authenticated Unix socket;
remote clients use HTTPS plus WebSocket with identical domain semantics.

The additive, separately negotiated v2 project/workspace model is specified in
[Platform v2 work-context contract](platform-v2-work-context.md). It does not
change any v1 wire shape or reinterpret v1 resource summaries.

The minimum shared service surface is:

| Service | Contract |
|---|---|
| `Capabilities` | Reports supported services, schema digests, maturity and authorized operations. Unsupported mutations fail closed. |
| `Snapshot` | Returns one bounded, revisioned projection and the durable event cursor from which subscription begins. |
| `Subscribe` | Streams ordered authority-qualified events after a cursor, or returns `resync_required` without a silent partial stream. |
| `Execute` | Accepts a typed action, target authority/ID, expected revision and idempotency key; authorization and durable recording happen before acknowledgement. |
| `GetReceipt` | Reconciles a submitted idempotency key after disconnect and distinguishes accepted, completed, rejected, conflict and unknown outcomes. |
| `ListSessions` | Returns only authorized, attachable sessions with durable run/session/turn identities and negotiated capabilities. |
| `Attach` / `Detach` | Creates or removes an observation subscription without affecting provider lifecycle. |
| `ClaimControl` / `ReleaseControl` | Manages a short durable steering/input lease independently from observation and pane focus. |
| `Execute(Steer)` | Injects bounded input into one active turn only when targeted at a current exclusive control lease; provider acknowledgement completes the durable receipt. |

One connection may multiplex subscriptions, but each subscription owns its own
cursor, backpressure state and resync lifecycle. Authoritative events are never
dropped; previews may be coalesced. Model catalog entries include discovery
source, observed freshness, account/route boundary, configured fallback and
live availability rather than treating configured names as proof of access.

### Authentication

- Local CLI/TUI clients authenticate with Unix peer credentials and receive a
  server-projected role/capability set.
- ShellDeck authenticates to AI Operations through its existing account/OIDC
  flow and receives scoped platform credentials; it stores them in the OS
  keychain and never receives provider credentials.
- Browser users authenticate through an AI Operations-backed server session.
  The browser receives an HTTP-only session and CSRF protection, never node or
  provider credentials.
- AI Operations and Automonique use mutually authenticated, node-scoped service
  credentials. A node credential cannot administer another node or widen a
  local sandbox.

## Repository responsibilities

### `bext-stack/automonique`

- consolidate the experimental local lanes behind the platform-v1 services;
- implement authority-qualified snapshots/events/actions, durable receipts,
  session attachment and controller leases;
- publish `automonique-client`, presentation-neutral UI reducers,
  `@automonique/protocol` and `@automonique/sdk` from one schema source;
- host `monique.1clic.pro` and migrate it off handwritten/private endpoints;
- consume AI Operations assignments without turning its projection into local
  execution evidence;
- host JCode through a pinned, conformance-tested provider adapter;
- retain the pinned direct Codex CLI path only as a degraded fallback and
  advertise only the capabilities that fallback actually has.

### `benfavre/bext` / AI Operations

- own global jobs, approvals, node registration, assignment and federation
  policy;
- expose versioned commands, receipts, sessions, capabilities and model
  catalogs through the shared contracts;
- expose dedicated Automonique platform and support routes, with no ShellDeck
  transport ownership of worker lifecycle;
- provide browser authentication/session exchange for `monique.1clic.pro`.

### `benfavre/jcode`

- remain a traceable MIT fork of `1jehuang/jcode` with an explicit upstream
  synchronization and divergence policy;
- retain standalone mode while introducing a backend boundary for managed mode;
- in Automonique mode, route start, follow-up, steering, approval, cancellation
  and model selection through the shared client with no direct-provider bypass;
- expose its headless engine through the supervised `api-stdio` protocol-v1
  adapter and supply the terminal interaction implementation for
  `automonique tui`.

Directly adapted upstream files retain MIT copyright and licence notices and
are recorded in the third-party inventory before distribution.

### `benfavre/shelldeck`

- use the shared Rust client for Automonique and AI Operations state/actions;
- render native multi-session observation, control, approvals and receipts;
- remove the independent fleet `JobExecutor` provider path after migration;
- retain terminal/SSH capabilities as separately authorized ShellDeck
  functionality, never as implicit agent authority.

## End-to-end flow

1. An authenticated user creates or approves a global job in AI Operations.
2. AI Operations assigns a revisioned command and idempotency key to one
   registered Automonique node.
3. The node validates current assignment, local authorization, sandbox,
   credentials and provider capabilities before recording a local action.
4. The node launches or reconnects the pinned JCode engine through a contained,
   attempt-scoped `api-stdio` host and durably records normalized events. The
   direct Codex JSONL path is rollback-only during the production canary and is
   removed from production selection after live verification.
5. AI Operations receives bounded authority-qualified projections and receipts;
   transport loss leaves the command unknown until receipt reconciliation.
6. The TUI may connect directly to the node. ShellDeck and the web client may
   consume remote projections through AI Operations. All reduce the same event
   vocabulary and display the owning authority.
7. Observation is fan-out. Steering or provider input requires a current local
   controller lease; AI Operations forwards the request but does not fabricate
   lease ownership.
8. Terminal execution, AI Operations completion and GitHub delivery remain
   separately reported outcomes.

## Delivery phases and automatic retirement

1. **Contract and fork baseline:** synchronize the JCode fork, record
   provenance and freeze platform-v1 authority/resource semantics.
2. **Shared substrate:** implement generated clients, reducers and conformance
   fixtures alongside the Automonique kernel, AI Operations federation and
   JCode backend boundary.
3. **Vertical slice:** prove AI Operations job -> approval -> Automonique node
   -> JCode execution -> ordered events and receipt. A temporary fallback slice
   is evidence for the surrounding platform, not completion of this phase.
4. **Client convergence:** expose the same job, session and model inventory in
   `automonique tui`, ShellDeck and `monique.1clic.pro`.
5. **Execution convergence:** disable and remove ShellDeck's independent
   provider executor after its client-only path passes the migration gates.
6. **Automatic cleanup:** remove superseded fleet, dashboard and local admin
   paths as soon as every named consumer uses platform v1 and the conformance
   plus live vertical-slice gates pass. No manual sign-off or release-count
   delay remains.

A compatibility adapter cannot become permanent by omission. Each adapter
names its consumers and removal test; the cleanup issue becomes actionable
automatically when those tests pass.

## Program tracking

The cross-repository program is tracked by the central epic and repository
milestones below. GitHub is the live delivery view; this document owns the
architecture and acceptance contract.

<!-- TRACKING_LINKS_START -->
- Central epic: [bext-stack/automonique#66](https://github.com/bext-stack/automonique/issues/66)
- Documentation PR: [bext-stack/automonique#74](https://github.com/bext-stack/automonique/pull/74)

| Repository | Milestone | Issues |
|---|---|---|
| Automonique | [M9 — Unified client platform & operator surfaces](https://github.com/bext-stack/automonique/milestone/9) | [#67](https://github.com/bext-stack/automonique/issues/67), [#68](https://github.com/bext-stack/automonique/issues/68), [#69](https://github.com/bext-stack/automonique/issues/69), [#70](https://github.com/bext-stack/automonique/issues/70), [#71](https://github.com/bext-stack/automonique/issues/71), [#72](https://github.com/bext-stack/automonique/issues/72), [#73](https://github.com/bext-stack/automonique/issues/73) |
| AI Operations | [Unified platform — AI Operations federation](https://github.com/benfavre/bext/milestone/1) | [#144](https://github.com/benfavre/bext/issues/144), [#145](https://github.com/benfavre/bext/issues/145), [#146](https://github.com/benfavre/bext/issues/146), [#147](https://github.com/benfavre/bext/issues/147) |
| JCode | [Unified platform — JCode dual mode](https://github.com/benfavre/jcode/milestone/1) | [#2](https://github.com/benfavre/jcode/issues/2), [#3](https://github.com/benfavre/jcode/issues/3), [#4](https://github.com/benfavre/jcode/issues/4), [#5](https://github.com/benfavre/jcode/issues/5), [#6](https://github.com/benfavre/jcode/issues/6) |
| ShellDeck | [Unified platform — ShellDeck migration](https://github.com/benfavre/shelldeck/milestone/1) | [#75](https://github.com/benfavre/shelldeck/issues/75), [#76](https://github.com/benfavre/shelldeck/issues/76), [#77](https://github.com/benfavre/shelldeck/issues/77), [#78](https://github.com/benfavre/shelldeck/issues/78) |
<!-- TRACKING_LINKS_END -->

## Exit criteria

- One AI Operations job is approved, assigned, executed by JCode on an
  Automonique node and shown with consistent authority-qualified state in all
  three clients.
- Forced disconnects resume from cursors without a duplicate mutation, missing
  terminal state or blind retry.
- Model inventory reports its source and freshness and agrees across the TUI,
  ShellDeck and web client.
- Multiple observers attach concurrently while at most one valid local
  controller lease exists.
- ShellDeck contains no independent provider-job execution path.
- Remote and browser clients cannot exceed AI Operations or Automonique policy.
- Superseded APIs are absent after the automatic migration gate, and current
  conformance fixtures cover every remaining public operation.
