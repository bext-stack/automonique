# Deployment notifications

**Status.** Drafted 2026-08-15 as part of M2 #13. Authored in this repository —
not transferred planning material, and not derived from legacy source. The
precise semantics below are **owner-confirmable**: this is one of the four
properties `launch-roadmap.md` calls "decisions that cannot be inferred". It is
drafted rather than deferred because an unspecified safety property is not a
neutral gap — it is a behaviour that will be decided by whoever writes the code
first, and nobody will review that decision. Every constant an owner is expected
to weigh in on is marked *owner-confirmable* where it appears.

## The property

A deployment notice is published to the **dedicated deploy route** and to
nothing else.

If that route is unconfigured or unreachable, publication **fails closed**: the
attempt is refused with a typed reason, the refusal is written durably, an
operator alert is raised, and the notice is **never** delivered to ticket
intake or any other general-purpose destination.

There is no third outcome. A deployment notice is delivered to the deploy route,
or it is refused. "Delivered somewhere" is not a success.

## Why fallback is the failure mode worth naming

Nobody designs a system that posts deployment notices into the ticket queue. It
arrives by accident, and always the same way: a route lookup returns nothing, a
general-purpose send path is already in scope, and delivering somewhere looks
more responsible than delivering nowhere.

It is not more responsible. It costs twice:

- the notice lands in front of an audience that did not ask for it and cannot
  act on it, in a queue whose whole value is that everything in it is
  actionable;
- the operator who needed to know the deploy route was broken is told nothing,
  because from the system's point of view the notice was handled.

The second cost is the one that persists. A refusal is loud and gets fixed. A
successful delivery to the wrong place is silent and lasts until somebody
notices the deploy route has been dead for a month.

## Failure-mode semantics, exactly

| Route condition | Result | Recorded | Alert | Reaches intake |
|---|---|---|---|---|
| configured, reachable | delivered, with a receipt | one delivery record | no | no |
| unconfigured | refused, `route_unconfigured` | the refusal | yes, exactly one | **never** |
| unreachable | refused, `route_unreachable` | the refusal, with the attempt count | yes, exactly one | **never** |

Four bindings this table is making explicit:

1. **The two failure conditions stay distinct.** Unconfigured needs
   configuration; unreachable needs investigation. A system that collapses them
   into one error tells the operator to do the wrong thing half the time.
2. **The refusal is durable before the alert.** The alert asserts that a refusal
   happened; the record it refers to exists first. An alert with no record
   behind it cannot be audited after the fact.
3. **Every refusal raises its own alert.** Suppression and rate-limiting belong
   to the alert transport, which knows what an operator is already looking at.
   A publisher that alerts only on the first failure has decided, silently, that
   the second failure did not matter.
4. **Fail-closed is not fail-stuck.** When the route comes back, publication
   resumes with no operator intervention. A property that requires a human to
   un-wedge it will be removed the first time it wedges at an inconvenient hour.

### Retention of a refused notice

A refused notice is **not** queued for automatic retry by this contract. It is
refused, and the durable record is the evidence that it was. Whether a deferred
retry is layered on top — and with what expiry, so a stale deployment notice is
not delivered hours later as though it were current — is *owner-confirmable* and
deliberately out of scope here. What is in scope: a retry mechanism may never
change the destination. Retrying to the deploy route is a policy question;
retrying to intake is the violation this document exists to forbid.

## Conformance

The suite is `automonique_protocol::safety_conformance::deploy_route`
(`rust/crates/automonique-protocol/src/safety_conformance/deploy_route.rs`).
It is generic over one trait, `DeployNotifications`, with three methods: put the
route into a condition, publish a notice, read the durable journal.

| Case | What it pins |
|---|---|
| `a_configured_route_delivers_exactly_once` | one delivery, to the deploy route, not two |
| `an_unconfigured_route_refuses_and_alerts` | typed refusal, durable record, exactly one alert, nothing to intake |
| `an_unreachable_route_refuses_and_alerts` | the same, under the other condition, refusing by its own name |
| `repeated_refusal_never_drifts_into_intake` | three consecutive failures change nothing |
| `a_recovered_route_resumes_delivery` | fail-closed is not fail-stuck |
| `intake_is_never_a_deploy_target` | the whole run, not just the windows the other cases inspected |

`DeliveryTarget::TicketIntake` exists in the vocabulary **so that the violation
is expressible**. A suite cannot catch a delivery that its types make
impossible to write down, and an implementation that reaches for a
general-purpose send path is not constrained by this module's types.

The suite runs today against an in-memory reference model, and the verification
in `rust/crates/automonique-protocol/tests/safety_conformance.rs` also runs it
against four **mutants** — a notifier that falls back to intake, one that
refuses in silence, one that holds out for three refusals and then falls back,
and one that never recovers. Each must fail, at the named case that describes
what was broken. A gate nothing can fail is not a gate.

## What this does not prove

Passing the suite proves that an implementation of `DeployNotifications` has the
property. It proves nothing about what the daemon does, because nothing in the
daemon implements the trait yet. That binding is the launch roadmap's Increment
4, which is the first increment that sends anything outbound; until it lands,
`automonique_protocol::safety_conformance::PENDING_BINDINGS` carries the gap as
data rather than as a sentence somebody has to remember.

## Provenance

`reference/feature-parity.md` records the dedicated deployment-notifications row
as **Replace** with no fixture, and its evidence column says the property "must
be re-specified, not inferred". This document is that re-specification. It
imports no legacy behaviour: the contract above was written from the stated
requirement, not reconstructed from the prior implementation, which the
clean-room boundary in `PROVENANCE.md` keeps out of scope.
