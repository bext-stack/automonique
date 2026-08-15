# Implementation plans (2026-08-15)

Per-milestone implementation plans for the improvement program in
[`../roadmap.md`](../roadmap.md), each grounded in the code at `c2f8b16` by a
dedicated architect pass. Every work item is an existing GitHub issue
(#4–#56) under an existing milestone (M1–M8) — these plans add **no** new
issues or milestones; they say *how* to build each one.

| Plan | Milestone | Issues | Theme |
| --- | --- | --- | --- |
| [M1](M1-disclosure-and-truth.md) | Disclosure closure & truth reconciliation | #4–#9 | Scrub live identifiers, make the docs true, repair authority/licence/identity |
| [M2](M2-parity-harness.md) | Parity harness & shadow gate | #10–#16 | Intended-action envelopes, golden traces, weighted score, safety specs |
| [M3](M3-approvals-and-audit.md) | Approvals, authority & audit | #17–#24 | Wire the approval lane; context-bound, TTL'd, fail-closed; hash-chained audit |
| [M4](M4-self-improvement-governance.md) | Self-improvement governance | #25–#28 | Align recipes with CI, gate on remote green, ladder, handoff-not-restart |
| [M5](M5-test-and-ci-hardening.md) | Test depth & CI hardening | #29–#35 | Property/fuzz on the codec, shared substrate, pinned toolchains, supply-chain |
| [M6](M6-streaming-ux.md) | Streaming UX & connector modernization | #36–#40, #56 | Normalized event stream, native streaming, sessions, provider hardening, fan-out |
| [M7](M7-observability-and-ops.md) | Observability & operations | #41–#44, #54–#55 | Metrics exporter, trace IDs, backup/restore, systemd, doctor checks |
| [M8](M8-scheduler-reload-isolation.md) | Scheduler, reload & isolation depth | #45–#53 | Scheduler core, generation handoff, uid separation, fenced writes, offline replay |

## What the grounded pass changed vs the roadmap

The architects found the substrate is friendlier than the roadmap assumed, and
corrected a few things:

- **Effect suppression for the parity harness (M2) needs no new architecture.**
  Every externally visible effect already passes through a narrow injected
  trait (`SlackTicketPoster`, `TicketActionSurface`, `EmailActionSurface`,
  `GitHubActionSurface`, `TelegramOutboundClient`); the shadow path is a
  recording decorator per trait plus a per-scope mode flag. Telegram already
  produces a content-digested, idempotency-keyed intended-action envelope in
  production (`send_outbound` → durable outbox) — the envelope design
  generalizes it rather than inventing beside it.
- **The normalized progress-event vocabulary (M6) largely exists**:
  `automonique-protocol/src/event.rs` already defines a 23-variant `EventKind`
  with a typed preview/recorded authority split and a resync-cursor type;
  #36 is mostly wiring + codegen, and the runner spool already carries an
  unused `AdapterEvent` kind.
- **The cancellation ledger (M3) is already wired** (`attempt_host.rs` composes
  it; `execute.rs` gate 8 registers every attempt) — #18 is only the wire verb
  and routes, not the ledger.
- **Roadmap dependency fix:** item 25's inline "(Depends on item 44)" was
  wrong — the real dependency is item 43 (generation handoff, issue #46), now
  corrected in `roadmap.md`.
- **Scope correction (M4):** the shipped self-improvement pipeline is the
  *daemon* path (`improvement_executor` + `improvement_worker` +
  `telegram_bridge`), not the ~11k-line `automonique-lab` harness the
  requirements describe; the governance work targets the daemon path.

## Cross-milestone sequencing

1. **M1 first and mostly alone.** F-01 is a live S0 disclosure; #4 must not be
   parallelized against its own file set, and M5/M2 tooling changes assume the
   scrubbed tree.
2. **M2 gates any new scope takeover** and retroactively covers the scopes
   already live. Its #15 (CI wiring) and #16 (GATE-ORACLE re-scope) are week-one
   quick wins that unblock the rest.
3. **M3 #17 (wire-or-delete)** precedes #18–#24; **M4 #28** and **M7 #54**
   both defer their real mechanism to **M8 #46** (generation handoff) — build
   the seams now, the mechanism there.
4. **M5–M7 parallelize behind M1.** Watch the shared edit points flagged in
   each plan: `rust.yml` (M5 #31/#33), the daemon serve loop (M6 #36, M7
   #41/#54/#55), and the protocol crate + generated SDK (M1-scrub, M6, M7).
5. **M8 is the spine finale** — its #50/#51 (fenced writes, boot-aware lease
   time) harden the lease substrate that #45/#46 build on; #52 (journal
   restructure) underpins offline replay used as a regression tool elsewhere.

Every plan respects three standing rules: no new external dependencies
(compose from `std::thread` + the 11 pinned crates), no F-01 identifiers in new
code/config/fixtures/commit messages, and refusal-first (a capability that
cannot be enforced refuses loudly rather than degrading).
