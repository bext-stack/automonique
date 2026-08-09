<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — supervised bootstrap authority

| Field | Decision |
|---|---|
| Status | approved for repository policy implementation |
| Repository base | `0a33948a577869155e0f4bfe5df028599773e37a` |
| Requested | 2026-08-09 through the owner-controlled repository workspace |
| Licence class | `Elastic-2.0` |
| Objective | remove controls that prevent supervised development while retaining external authority for protected integration, release and production |
| Allowed paths | `AGENTS.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `PROVENANCE.md`, `plan/`, `docs/product-plan/` |
| Budget | one bounded policy reconciliation; no licence, privacy, clean-room or production-authority change; `gates_open` is corrected to exclude advisory hardening |
| Verification | plan integrity, authority invariant checks, generated-graph reproducibility and existing plan self-tests |

## Decision

During the plans-only and early implementation phases, the repository operates
in **owner-supervised bootstrap** mode. A bounded agent may implement one work
unit, run its required checks and gate preflight, create an isolated candidate
branch or worktree, and create a local candidate commit containing only leased
paths. Review depth is selected by risk and the owner may accept routine,
reversible development work without provisioning autonomous workload identities
or independent reviewers first. Identity separation and review counts are
owner-configurable hardening rather than global gates.

The mode grants no push, protected-branch merge, repository administration,
release signing, package publication or production deployment authority. Those
remain external. Unattended protected integration requires exact-tree evidence
and an owner-configured integration credential, but does not universally
require separate author/reviewer identities.

Because advisory identity hardening no longer blocks work, the specification
debt metric `gates_open` excludes gates explicitly marked advisory. This is the
only metric-definition change in the decision and must not be used to
retroactively certify a candidate based before this policy is integrated.

Contract and policy preparation explicitly requested by the owner may begin
without a pre-existing ready work ID, because requiring a contract in order to
write the contract is circular. Such work must record its base, paths,
objective, checks and stop conditions in an owner-decision file before editing.

## Non-retroactivity

This decision does not declare an existing candidate correct, close a gate,
alter evidence results, or waive a failing test. Candidates based before the
policy change retain their recorded review state. They may be accepted only by
a subsequent owner decision or reviewed under the new policy after the policy
itself is integrated.

## Verification results

Implementer checks on the candidate policy tree:

- `python3 plan/check.py --verify`: pass; 375 items, 8 selectable and 28
  unblocked-but-unspecified;
- `python3 plan/selftest.py`: pass; all 9 negative cases detected, including
  protected-authority escalation, mandatory independent review and use of
  advisory identity hardening as a blocker;
- `python3 plan/generate.py --stdout | diff - plan/work-graph.toml`: pass;
- specification debt: 409, down from 420 through ten newly specified work contracts and
  exclusion of the advisory identity item from `gates_open`;
- licence/SPDX candidate regression: 82 repository files checked; six Rust
  tests and Clippy with warnings denied passed; and
- broken links, undefined work references and missing done-item evidence: zero.

These results are measurements, not a protected-branch integration receipt.

## Stop conditions

Stop and request the owner when work would:

- expose or use prior implementation source;
- change the software licence boundary, privacy or retention policy;
- grant an agent a protected-branch, release, publication or production
  credential;
- weaken or delete a required test or falsify evidence; or
- combine a policy change with a claim that the same change already passed the
  new policy.
