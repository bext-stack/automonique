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
accepts or integrates candidates. Agents have no push, protected-branch merge,
repository-administration, release-signing, publication or production-deploy
authority.

An owner's contemporaneous, explicit instruction may delegate one bounded Git
publication operation. The repository must record the exact remote, branch,
expected tip, snapshot and recovery reference before execution. This is a
single-use delegation, not a change to the default authority mode. History
rewrites additionally require compare-and-swap protection and may not touch
unlisted refs.

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

Review is owner-configurable and risk-based. Zero independent reviewers is a
valid recorded outcome; it must never be represented as independent review.
An owner may require one or more fresh-context reviews for a particular
contract, and protected branch policy then enforces that declared requirement.
Identity diversity and multiple reviewers are hardening choices, not global
conditions for development or integration.

## Routine autonomous integration

The merger service may merge a routine verified change into protected `main`
only when:

- the base revision is still current;
- leased paths and licence boundaries match the reviewed plan;
- required builds, tests, security scans, provenance checks, and any reviews
  configured for that contract passed against the exact candidate tree;
- no unresolved blocking finding exists;
- no force operation or history rewrite is required; and
- an idempotent action receipt proves the merge was applied at most once.

Conflicts, ambiguous outcomes, source drift, or missing evidence block and
reconcile; they never trigger a blind retry.

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

Release signing, package publication, commercial agreement execution, and
production deployment use separate authorities and receipts.
