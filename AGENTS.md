# Automonique agent contract

This is a clean-room implementation repository. Prior implementation *source* —
code, tests, build scripts, configuration and Git history — is outside the
allowed context and must not be copied, mounted, searched, or used to generate
code.

## Permitted and forbidden inputs

Permitted:

- everything checked in under `docs/product-plan/` and `plan/`;
- **structural references** to the prior implementation: file and module names,
  directory shape, table and column names, command and environment names, and
  the porting map in `docs/product-plan/reference/migration-plan.md`. The owner
  authorized these. They record *where behavior lived* and *where it is going*;
- black-box input/output fixtures with recorded provenance;
- public standards and dependencies approved by the licence policy.

Forbidden:

- reading, mounting, cloning or searching the private archive;
- reproducing prior source text, control flow, algorithms or comments — quoted,
  paraphrased, or reconstructed from memory;
- treating a structural reference as licence to reconstruct the code behind it.

The distinction is deliberate. That Slack lifecycle lived in `index.ts` and
belongs in `automonique-transports` is orientation. How `index.ts` implemented
it is contamination. When unsure which side of the line an input falls on, stop
and ask rather than proceeding.

## Before implementation

- Select a ready work ID from `plan/ready.md`; its contract is
  `plan/contracts/<ID>.md` and its node is in `plan/work-graph.toml`.
- Record dependency evidence, allowed paths, expected base, objective, budget,
  tests, licence class, and stop conditions.
- Refuse work blocked by an unresolved gate in `plan/gates.md`.

Owner-requested contract or policy preparation is the bootstrap exception to
the first bullet: it may start without a pre-existing ready ID when a decision
under `plan/owner-decisions/` first records the immutable base, allowed paths,
objective, budget, checks, licence class and stop conditions. This exception
cannot implement product behavior or waive a gate; it exists to avoid requiring
a contract in order to write the contract.

## Codex session driver

The normal interactive entry point is an owner opening Codex in this
repository and asking it to continue. The primary Codex session is the
coordinator; do not start a nested Codex CLI process.

For a continuation request:

1. Run `python3 tools/harness_loop.py status`. Resume a valid
   `codex_session` claim, or run `python3 tools/harness_loop.py claim` to admit
   one ready, score-eligible work item and create its immutable packet.
2. Read the packet, contract, dependency evidence and applicable gates before
   editing. Stop if they disagree.
3. Use native subagents for bounded independent work. Launch at least one when
   the admitted objective has a useful independent exploration, implementation
   or verification stream; use no more than three concurrently. Give each
   subagent an exact objective, allowed paths, checks and requested return
   evidence.
4. Prefer parallel read-only exploration and verification. Concurrent writers
   must have disjoint path ownership. The primary session owns coordination,
   resolves conflicts and remains responsible for the integrated candidate.
5. Run the checks required for the current bounded slice and
   `python3 tools/harness_loop.py check` after integration. A partial slice may
   be committed and published through the typed exact-tree path when its actual
   checks pass, but its commit and report must say that it is partial. It may
   not mark the work item done, close a gate, or claim the full contract.
6. Declare full completion only through one exact-tree completion transaction
   that includes the final implementation, measured metrics, completion
   evidence and generated plan/status changes. Run every contract check against
   that same tree. If any check or required record is missing, keep the work
   partial and report the gap truthfully.
7. After verification, the primary session may use the configured typed
   integrator to compare-and-swap local `main` and publish that exact commit by
   a non-force fast-forward to configured `origin/main`. Stop on local or remote
   tip drift, ambiguity, a non-fast-forward, or a protected-control change that
   lacks exact-revision owner acceptance.
8. Use `python3 tools/harness_loop.py release --reason blocked` (or
   `user_cancelled`) if the attempt cannot continue safely.

Subagents inherit this contract. They may not expand the lease, approve or
integrate their own work, launch recursive agent trees, or push. If native
subagents are unavailable or the task is genuinely atomic, the primary session
may proceed alone but must say why in its completion evidence.

## Authority modes

`plan/authority.toml` selects the repository's current mode.

In `owner-supervised-bootstrap`, a bounded worker may run required checks and a
gate preflight, create an isolated candidate branch or worktree from the
expected base, and create a local candidate commit containing only leased
paths. The primary session may automatically advance local `main` to an exact
verified routine candidate by fast-forward compare-and-swap and may publish the
same commit only as a non-force fast-forward to the configured `origin/main`.
Review is risk-based and an owner may accept routine reversible work.

This narrow integration authority grants no generic push, merge, force,
history rewrite, other-ref or other-remote mutation, repository administration,
release signing, package publication or production deployment authority. The
local and remote expected tips, candidate commit and verified tree must be
exact. Separate identities and independent review are optional hardening, not
universal readiness gates.

## Hard rules

- Never commit credentials, private/customer data, logs, sessions, real
  infrastructure identifiers, personal email addresses, or absolute home paths.
- Never generate a shell command string from model output. Use explicit argv or
  typed APIs.
- Never edit outside the work unit's lease or recorded owner-decision scope.
  Never change the metric, baseline, licence, policy, or budget and then use the
  changed rule to certify the same candidate.
- Never delete, skip, ignore, or weaken a test; add a stub; bulk-refresh a
  golden; or widen unsafe/lint allowances to pass a gate.
- Never use a candidate's changes to governance, authority, licensing,
  security, required checks, integration credentials, branch rules, or the
  metric, baseline or budget judging that candidate to certify or integrate the
  same candidate. Routine exact-tree fast-forward integration is allowed under
  the pre-existing owner-configured policy; protected-control changes require
  external exact-revision owner acceptance. Release, package publication and
  production deployment always remain separate authorities. Self-review and
  deterministic gate preflight are allowed in owner-supervised bootstrap, but
  evidence must record the actual reviewer count and may not claim independence
  that did not occur.
- Never claim an unmeasured metric. Missing evidence is `null` with a reason.
- Product files use `Elastic-2.0`; `sdk/`, `integrations/`, and `connectors/`
  use `Apache-2.0`. Moving product code across that boundary requires owner
  review before distribution.

## Git authority

Workers use typed stage/commit operations for leased paths at an expected base.
In owner-supervised bootstrap they may create a candidate branch or worktree
and a local candidate commit. Only the primary session's bounded integrator may
then:

- fast-forward local `refs/heads/main` from the recorded expected local tip to
  the exact verified candidate using compare-and-swap; and
- publish that same commit to configured `origin/main` with an ordinary
  non-force fast-forward push whose advertised remote tip matches the recorded
  expected remote tip.

The integrator records an idempotent receipt and stops on drift, conflict,
ambiguous outcome or non-fast-forward rejection. It has no authority to merge,
force, rewrite history, change another ref or remote, edit remote configuration,
administer the repository, release, publish a package or deploy. Subagents and
workers cannot push.

Partial verified slices may use this path when the commit and evidence state
their partial scope and actual checks. Full completion requires the
implementation, all contract checks, measured metrics, completion evidence and
plan/status transition to be bound to one exact-tree completion transaction.
The policy judging a tree is the policy already integrated at its admitted
base; a candidate cannot make new authority retroactive to itself.

A contemporaneous owner instruction may delegate one exact publication or
history-rewrite operation outside the narrow configured fast-forward path
without creating standing worker authority. Before acting, record the remote,
branch, expected remote tip, intended snapshot, allowed operation and recovery
reference under `plan/owner-decisions/`. A rewrite must use compare-and-swap
protection such as `--force-with-lease` and must not alter any other branch,
tag, remote or repository setting.

## Verification

Report actual checks, counts, failure paths, restart behavior, compatibility,
licence classification, and provenance. Compilation alone is not completion.
