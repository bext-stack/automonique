<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — direct Codex development

**Status: accepted by contemporaneous owner instruction on 2026-08-12.**

| Field | Recorded value |
|---|---|
| Immutable decision base | `c11ed0df400785de300d8dd8453f26c43c5caf89` |
| Effective | the first integrated commit containing this decision and the replacement `AGENTS.md`; descendants only |
| Objective | remove the claim/packet/lease/gate/evidence/broker workflow as a prerequisite for ordinary Codex development |
| Authority granted | direct repository inspection, editing, testing, parallel-agent coordination, ordinary commits, and non-force pushes for owner-requested repository work |
| Removed prerequisites | ready IDs, contracts before code, work claims, packets, leases, plan gates, mandatory reviews/subagents, evidence JSON, specification-debt movement, typed brokers, and exact-tree completion transactions |
| Authority withheld | production deployment or mutation, live transport/provider enablement, release signing, package publication, credential operations, repository administration, force-push, history rewrite, ref deletion, remote configuration, and mutation of other refs/remotes absent exact contemporaneous authority; the granted ordinary non-force push is excluded from this list |
| Recovery reference | base `c11ed0df400785de300d8dd8453f26c43c5caf89`; the unfinished pre-transition recovery edit is preserved in stash commit `070937bd216d676a09f1867031e9ada41c46b88c` |
| Licence | `Elastic-2.0` |

## Candidate report under the prior policy

| Field | Recorded value |
|---|---|
| Allowed paths | `AGENTS.md`, `GOVERNANCE.md`, `README.md`, `CONTRIBUTING.md`, `PROVENANCE.md`, `LICENSE-POLICY.md`, `.github/workflows/plan.yml`, `.github/workflows/identity.yml`, `.github/workflows/scrub.yml`, `.automonique/dev/README.md`, `plan/README.md`, `plan/kickoff.md`, `plan/gates.md`, this decision, `tools/check_licenses.py`, `tools/test_check_licenses.py` |
| Budget | one policy transition; no product behavior, dependency, lockfile, licence classification, credential, production, release, or destructive Git change |
| Checks | base checks: `plan/check.py --verify` pass, `tools/program.py --verify` pass, `tools/test_program.py` 47/47 pass, foreground lifecycle 3/3 pass, derived plan files unchanged, identity audit 38/38 pass; `plan/selftest.py` remains red on the immutable base and candidate with the same two legacy-identifier integrity failures, so no pass is claimed. Candidate checks: source-policy tests, development scrub, Rust workspace test/fmt/Clippy, workflow syntax inspection, `git diff --check`, exact path audit |
| Stop conditions | stop on decision-base drift, secret/private-data exposure, clean-room or licence weakening, destructive Git, production/release authority expansion, unrelated product edits, or a relevant check failure caused by this transition |
| Review | three read-only subagent streams inventoried enforcement, drafted the replacement, and audited CI; the primary integrates the final candidate |

## Decision

The owner finds that the executable plan and its development harness are now
hindering product development through Codex CLI. Those mechanisms are retained
as historical and optional tools, but they cease to be admission, integration,
or completion controls.

Normal development begins with the requested product outcome and ends with
relevant tests plus an ordinary commit/push when requested. The roadmap remains
useful context; it no longer has authority to refuse implementation because a
contract, graph edge, gate, evidence row, packet, or generated status file is
missing.

Default CI must test source policy, product behavior, and development secret
scanning. It must not fail ordinary development because harness self-tests,
candidate-identity history, or publication-only protected secrets are absent.

## Non-retroactivity

This decision does not certify unfinished work, reinterpret earlier evidence,
or declare an existing test failure successful. The transition candidate is
judged against the policy at the immutable decision base and uses that policy's
safe non-force integration route. The direct model applies only after the
transition is integrated.
