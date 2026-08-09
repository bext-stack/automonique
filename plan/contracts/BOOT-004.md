# BOOT-004 — Parity-oracle boundary

| | |
|---|---|
| Epic | `BOOT` — repository readiness gates |
| Track | core |
| Depends on | `BOOT-001` |
| Closes | [`GATE-ORACLE`](../gates.md#gate-oracle) |
| Licence class | `Elastic-2.0` |
| Allowed paths | `tools/oracle/`, `plan/` |
| Hill-climbability | 45 — the objective is a negative property, provable only by adversarial testing |

## Objective

Let a parity oracle run against the legacy implementation without leaking that
implementation into any agent's context.

The measurable objective is: an adversarial suite that deliberately attempts to
exfiltrate source text, credentials, private identifiers and stack traces
through the oracle's output channel produces zero successful leaks.

## Why this blocks fixture work

`PROVENANCE.md` permits an oracle that "must expose only bounded behavior
results and must not emit source, private data, credentials, proprietary
identifiers, or implementation text." The AI harness depends on that comparison
(`docs/product-plan/requirements/ai-implementation-harness.md` § Differential
parity and shadow oracle).

Today nothing implements the separation. Running an oracle now would put legacy
source and implementing agents on the same side of the boundary and destroy the
clean room it exists to protect — quietly, and without a signal that it
happened.

Blocks `R0-02` (sanitized fixture corpus) and `R0-07` (provider transcript
corpus), because both capture output from systems holding legacy behavior.

## Scope

In scope:

- a documented process boundary naming what holds legacy source, what strips
  oracle output, who owns each side, and where the trust transition occurs;
- a stripping mechanism placed so that raw oracle output never reaches agent
  context, including on the error path;
- content scanning of oracle output before release;
- an adversarial test suite against the boundary.

Out of scope:

- capturing any actual fixture. That is `R0-02`, and it stays blocked until
  this closes;
- improving the oracle's comparison fidelity. Correctness of comparison is a
  separate objective from containment.

## The failure mode to design against

The obvious leaks are easy. The ones that matter:

- an exception whose traceback contains a legacy file path and source line;
- a diff report that quotes the legacy value it compared against;
- a timing or size measurement precise enough to reconstruct behavior;
- a "debug mode" that bypasses the stripper because it is only used locally;
- output that is stripped but then logged unstripped on the way to being stripped.

Design the boundary so raw output has no path to agent context at all, rather
than so every known raw-output path is filtered.

## Verification contract

| Check | Expected |
|---|---|
| Source text | oracle output containing legacy source is blocked |
| Traceback | an induced exception yields no legacy path or line |
| Credential | an injected credential in the legacy environment does not appear |
| Identifier | a private identifier in legacy data does not appear |
| Error path | a crash mid-comparison releases nothing unstripped |
| Log path | no log sink receives pre-strip output |
| Review record | the configured reviewer count and owner acceptance are recorded truthfully |

## Forbidden shortcuts

- filtering the output of a known set of code paths rather than constraining
  the channel;
- a bypass for local development;
- treating "the oracle runs on a private host" as containment — the leak
  vector is the output, not the host;
- claiming an independent review that did not occur.

## Completion evidence

- boundary document with the named owners on each side;
- adversarial suite results, all seven checks passing;
- the configured review record or explicit owner acceptance;
- confirmation that `R0-02` and `R0-07` are unblocked by this and nothing else.

## Integration and rollback

Self-contained under `tools/oracle/`. Rollback reopens `GATE-ORACLE` and
re-blocks `R0-02`/`R0-07`. Any fixture already captured under a rolled-back
boundary is quarantined, not retained.
