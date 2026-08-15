# Improvement plan — deep audit, state of the art, and program (2026-08-15)

This directory is the output of a deep audit of Automonique's features and
approach, calibrated against the 2026 state of the art for comparable
systems, and turned into an actionable program.

| Document | Contents |
| --- | --- |
| [`audit-findings.md`](audit-findings.md) | 14 findings (F-01…F-14), severity-ranked S0–S3, each verified against the tree — plus what is genuinely strong and must be preserved |
| [`state-of-the-art.md`](state-of-the-art.md) | External survey: chat control surfaces, human-in-the-loop approvals, strangler/parity practice, support automation, multi-provider abstraction, durable execution — each with an applicability verdict |
| [`roadmap.md`](roadmap.md) | 8 milestones / 53 work items, mirrored as GitHub milestones and issues, with sequencing and owner-decision markers |

## The audit in one paragraph

The durable core (epoch-fenced leases, transactional outbox,
ambiguity-not-free-slot reconciliation, STRICT ladder-replayed schemas) and
the sandbox composition path are genuinely strong — stronger than most of
what the external survey found. The risks are elsewhere: the repository is
public while leaking private client identifiers against its own open gate
(F-01); the self-improvement pipeline is gated more weakly than CI and
deploys by the restart mechanism the product exists to eliminate (F-02);
the strangler's parity gate — the launch plan's one governing rule — has no
enforcement mechanism, and customer-facing scopes shipped past it (F-03);
the status documents describe a far more constrained system than the one
running (F-04); ~16k lines of approval/automation/batch surface are read by
nothing (F-06); and the untrusted-input surface has no randomized testing
(F-07).

## The program in one paragraph

M1 closes the disclosure and makes the documents true again. M2 builds the
parity/shadow harness in the shape 2026 practice prescribes
(intended-action envelopes, golden traces, weighted confidence score,
known-deviation registry) so the launch roadmap's gate becomes enforceable.
M3 turns the dormant approval surface into a state-of-the-art
human-in-the-loop system (context-bound, TTL'd, fail-closed, hash-chained
audit). M4 subordinates self-improvement to the same gates as everything
else. M5 raises the testing/CI floor (property+fuzz on the protocol,
deduplicated credential redaction, pinned toolchains, supply-chain gates).
M6 modernizes the chat surfaces to native streaming with one normalized
progress-event stream. M7 makes the system observable and operable
(exporter, backup/restore, systemd). M8 completes the spine: scheduler
core, generation handoff, sandbox uid separation.
