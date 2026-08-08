# ADR 001 — execution-host and session lifetime

**Status:** accepted for implementation planning

## Context

Automonique has four different lifetimes that must not be collapsed:

- a work item is the reviewed business action;
- an attempt is one scheduled execution of that work item;
- an execution host is the supervised process/cgroup containing an adapter/provider connection;
- a provider session is the backend conversation/thread identity.

A provider session may outlive one work item, an attempt may be retried, and some native providers benefit from a long-lived interactive process. Other fallback modes are inherently one-shot. Therefore neither “one runner per work item” nor “one runner forever per session” is correct for every adapter.

## Decision

Model work, attempts, hosts, provider sessions and turns independently.

```text
work item 1 ──< attempt/run N ──> execution host 0..1
                                  │
provider session 1 ──< turn N ────┘
```

Every scheduled or retried execution creates a new `attempt_id`/`run_id`. A work item may have several attempts but at most one nonterminal attempt unless an explicit hedging policy is added later.

Execution hosts support two modes:

1. **Session-scoped host** — `automonique-agent-<host-id>.service` (or an active legacy unit during migration) owns a native interactive adapter/provider process and accepts sequential turns for one provider session and immutable workspace/security context. Claude stream JSON, Codex App Server and opencode server normally use this mode. Jcode may bind to an external daemon only when that daemon attests and enforces the identical tenant/account/workspace/tool security context; otherwise the daemon is provisioned per compatible context.
2. **Attempt-scoped host** — `automonique-run-<run-id>.service` owns one fallback/one-shot process and terminates with the attempt.

The adapter capability probe chooses a supported host mode. It may not silently move an active session between modes.

## Invariants

- A host has exactly one provider, integration mode, identity/account context, workspace security context and provider binary/schema digest.
- A provider daemon outside the host cgroup is not assumed to inherit the host sandbox; its tool descendants must be proven equivalent or the integration is ineligible.
- At most one turn executes on a provider session unless the adapter explicitly passes concurrent-turn conformance.
- A provider session can remain resumable when no host exists.
- Killing an attempt-scoped host cancels only that attempt. Killing a session-scoped host may interrupt the active turn and must produce an explicit session reconciliation outcome.
- Cancellation tries native turn interrupt first, then bounded graceful shutdown, then cgroup termination.
- A follow-up targets an explicit provider session and creates a new work item/attempt/turn; it never mutates a completed run into running again.
- Retry creates a new attempt with a causation link and preserved reviewed revision. If retry changes capabilities, workspace revision or action scope, it requires a new review.
- Session-scoped hosts survive `automoniqued` reload and remain owned by systemd. They are not required to survive machine reboot.
- Machine reboot may recreate a host only after provider-session history/capabilities are reconciled.

## Idle and retention policy

After a turn becomes terminal, a session-scoped host enters `idle` for a bounded configurable TTL. It may accept a compatible follow-up during that period. It then drains and exits while the durable provider session remains resumable. Host retention considers provider billing, credentials, open tool processes, workspace locks and pending approvals.

A host waiting on a durable provider approval is not idle. It retains only the minimum resources needed for the wait and has an approval deadline/escalation policy.

## Attachment and control

TUI/SDK attachment targets the durable provider session plus optional active turn/run, not a PID or unit name. Observation survives host replacement by reconciling through the domain journal. Interactive controller leases bind to the current turn revision and are invalidated when the host/turn changes.

## Data consequences

- Remove the one-run-per-work uniqueness assumption.
- Add attempt number, retry cause, selected host mode and terminal reconciliation reason.
- Add execution-host records with unit, process identity, boot ID, protocol, heartbeat and idle deadline.
- Provider turns reference work item, attempt/run and host when present.
- Store host replacement/adoption as domain events.

## Rejected alternatives

- **One process per work item only:** loses efficient interactive control and makes native session attachment misleading.
- **One immortal process per provider session:** leaks resources, complicates upgrades and does not fit one-shot fallbacks.
- **Treat resume IDs as process identity:** confuses durable provider state with local process lifetime.

## Verification

Test sequential follow-ups, retries, native/fallback hosts, host idle expiry, provider crash/recreation, approval waits, Automonique reload, machine reboot, controller invalidation and cancellation escalation. The same provider session must never execute concurrently through two hosts without an advertised/tested capability.
