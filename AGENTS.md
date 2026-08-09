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
5. Run the contract checks and `python3 tools/harness_loop.py check` after
   integration. A successful check creates a candidate only; update plan
   evidence and completion state separately when the contract is actually met.
6. Use `python3 tools/harness_loop.py release --reason blocked` (or
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
paths. Review is risk-based and an owner may accept routine reversible work.

This mode never grants push, protected-branch merge, repository
administration, release signing, package publication or production deployment
authority. Unattended protected integration requires exact-tree evidence and
an owner-configured integration authority; separate identities and independent
review are optional hardening, not universal readiness gates.

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
- Never be the sole authority for a protected-branch merge, release,
  publication or production deployment. Self-review and deterministic gate
  preflight are allowed in owner-supervised bootstrap, but evidence must record
  the actual reviewer count and may not claim independence that did not occur.
- Never claim an unmeasured metric. Missing evidence is `null` with a reason.
- Product files use `Elastic-2.0`; `sdk/`, `integrations/`, and `connectors/`
  use `Apache-2.0`. Moving product code across that boundary requires owner
  review before distribution.

## Git authority

Workers use typed stage/commit operations for leased paths at an expected base.
In owner-supervised bootstrap they may create a candidate branch or worktree
and a local candidate commit. They cannot push, merge, force, rewrite existing
history, edit remotes, or administer the repository. Protected integration is
performed by the owner or an owner-configured bounded integration credential.

A contemporaneous owner instruction may delegate one exact publication or
history-rewrite operation without creating standing worker authority. Before
acting, record the remote, branch, expected remote tip, intended snapshot,
allowed operation and recovery reference under `plan/owner-decisions/`. A
rewrite must use compare-and-swap protection such as `--force-with-lease` and
must not alter any other branch, tag, remote or repository setting.

## Verification

Report actual checks, counts, failure paths, restart behavior, compatibility,
licence classification, and provenance. Compilation alone is not completion.
