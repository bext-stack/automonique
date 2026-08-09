<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — Codex session driver

| Field | Decision |
|---|---|
| Status | approved as owner-requested harness and policy preparation |
| Expected base | `a64283a4d64205f4f74e7728388dcc6b00a73933` |
| Work ID | bootstrap exception; follow-up to `R0-18`, no product behavior |
| Dependency evidence | the `R0-18` bounded harness is complete; this decision changes its interactive driver without satisfying or bypassing `R0-06` or `R0-19` |
| Objective | make an interactive Codex session the normal coordinator so the owner can say `continue` and have that session admit work, launch native subagents, integrate and verify a candidate |
| Allowed paths | `AGENTS.md`, `.codex/`, `.automonique/dev/`, `tools/`, `plan/` |
| Intended snapshot | durable session instructions, bounded Codex agent configuration, session claim/check/release commands, generated loop configuration, tests and operator documentation |
| Licence class | `Elastic-2.0` |
| Budget | one primary session; at most three concurrent native subagents; one claimed work item; no recursive agent trees; concurrent writes only to disjoint paths; existing objective iteration, time, failure and unchanged-result budgets remain authoritative |
| Tests | generated artifact verification, session packet and active-claim tests, harness tests, plan/DAG regression, compilation and repository hygiene |
| Review | zero independent reviewers; owner-supervised bootstrap |

## Authority and boundary

The primary Codex session is the coordinator. It may use native subagent tools
inside the existing session authority, but it must not launch Codex recursively
through a shell or treat the number of agents as a correctness metric. The
claim protocol creates no provider credential, model call, commit, push, merge,
release or deployment authority. Subagents receive bounded objectives and
disjoint write leases; the primary session owns integration and truthful
evidence.

The deterministic Bubblewrap worker remains available for explicit local
executables. It is not the provider-aware harness specified by `R0-19` and this
decision does not claim that later contract complete.

## Stop conditions

Stop on a dirty admission tree, an existing active attempt, stale generated
artifacts, dependency or gate disagreement, revision or branch drift,
out-of-lease changes, failed safety or contract checks, unavailable required
authority, or any objective budget. Release a stopped session claim explicitly;
never silently replace it.

## Publication

This decision authorizes local implementation and a local commit only. It does
not authorize a push or any other external repository mutation.
