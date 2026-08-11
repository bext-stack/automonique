# Governance and autonomous integration

Automonique is developed through bounded work units with durable evidence. The
degree of role separation depends on whether a human owner is supervising the
work or automation can integrate into a protected branch.

## Authority modes

### Owner-supervised bootstrap

This is the default during bootstrap. One agent may implement,
self-review, run deterministic checks and gate preflight, and create a local
candidate commit on an isolated candidate branch. Roles may coincide for
routine, reversible development work when the evidence says so truthfully.

The owner selects work, chooses review depth from the change's risk, and alone
configures integration policy. Under the current policy, the bounded primary
integrator may fast-forward local `main` by compare-and-swap and publish the
same exact verified commit by a non-force fast-forward to configured
`origin/main`. This grants no generic push, merge, force, history rewrite,
other-ref or other-remote mutation, repository administration, release signing,
package publication or production deployment authority.

An owner's contemporaneous, explicit instruction may delegate one bounded Git
publication operation outside the configured routine fast-forward path. The
repository must record the exact remote, branch, expected tip, snapshot and
recovery reference before execution. This is a single-use delegation, not a
change to the default authority mode. History rewrites additionally require
compare-and-swap protection and may not touch unlisted refs.

### Autonomous protected integration

When automation can integrate without an owner inspecting each candidate, the
owner configures the required checks, review policy and bounded integration
credential. Separate workload identities are recommended defense in depth but
are not a prerequisite. Exact candidate identity, deterministic checks and the
inability of workers to mint protected integration authority remain required.

## Roles

- **Implementer:** changes only leased paths and cannot perform protected
  integration.
- **Reviewer:** receives the immutable base, frozen diff, contract, and measured
  evidence; it cannot alter the candidate it reviews.
- **Fixer:** resolves blocking findings but cannot dismiss them.
- **Builder:** reproduces checks from an immutable source revision when the
  contract requires a separate build.
- **Merger:** performs one compare-and-swap integration after all policy gates
  pass; it cannot create or modify the candidate.

Which identity performs each of these roles is recorded in
`.github/identity/register.toml`, and `.github/identity/check_identity.py`
reads the role vocabulary from this section rather than restating it: a role
added here and assigned to nobody there fails the check. Roles coinciding on
one identity is permitted and is what the register describes today. Describing
them as separate when one credential does all of them is not.

Review is owner-configurable and risk-based. Zero independent reviewers is a
valid recorded outcome; it must never be represented as independent review.
An owner may require one or more fresh-context reviews for a particular
contract, and protected branch policy then enforces that declared requirement.
Identity diversity and multiple reviewers are hardening choices, not global
conditions for development or integration.

## Routine autonomous integration

The bounded integrator may advance local `refs/heads/main` and then configured
`origin/main` for a routine verified change only when:

- the candidate has exactly one parent and it is the recorded current local
  base revision;
- leased paths and licence boundaries match the reviewed plan;
- required builds, tests, security scans, provenance checks, and any reviews
  configured for that contract passed against the exact candidate tree;
- no unresolved blocking finding exists;
- local `main` advances by compare-and-swap fast-forward only;
- the advertised configured `origin/main` tip equals the recorded expected
  remote tip and the push is an ordinary non-force fast-forward of the same
  local commit;
- no merge, force operation, history rewrite, other ref or other remote is
  involved; and
- idempotent local and remote action receipts prove each effect was applied at
  most once or reconciled to the exact intended commit.

Conflicts, ambiguous outcomes, source drift, or missing evidence block and
reconcile; they never trigger a blind retry.

### Partial slices and completion

A bounded partial slice may be committed and pushed when its exact-tree checks
pass. Its commit, evidence and operator report must identify the slice as
partial, list the checks actually run and retain the work item as incomplete.
It cannot close a gate or imply that omitted contract checks passed.

Full completion is a single exact-tree transaction. The final implementation,
measured metrics, completion evidence and generated plan/status transition are
part of the same candidate tree, and every contract check runs against that
tree before either local or remote integration. Missing or failed evidence
leaves the work partial; compilation or an agent's self-report is not terminal
evidence.

## Protected policy changes

Candidates cannot autonomously modify or waive:

- software, commercial, contribution, or trademark licensing;
- this governance contract or the agent authority boundary;
- required checks, branch rules, merger credentials, or approval identities;
- security boundaries, production credentials, or deployment authority;
- the metric, baseline, or budget judging the same change; or
- retention, privacy, legal, or regulatory policy.

Such a change requires an external exact-revision policy decision. The final
repository commit may still be authored by the Automonique bot after that
decision is durably bound to the candidate.

Authority and policy changes are non-retroactive. A candidate cannot use a new
integration rule, changed required check, changed metric, changed baseline or
changed budget contained in its own tree to approve that tree. Automatic
local-main advancement and routine push apply only when the governing policy
was already integrated at the candidate's admitted base. A protected-control
candidate needs external owner acceptance bound to its exact revision before
integration, even when all deterministic checks pass.

Release signing, package publication, commercial agreement execution, and
production deployment use separate authorities and receipts.
