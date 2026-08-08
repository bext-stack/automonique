# Governance and autonomous integration

Automonique is developed by bounded automated roles with durable evidence and
separated authority. Commit metadata uses dedicated workload identities rather
than personal identities.

## Roles

- **Implementer:** changes only leased paths and cannot approve or integrate.
- **Reviewer:** receives the immutable base, frozen diff, contract, and measured
  evidence; it cannot alter the candidate it reviews.
- **Fixer:** resolves blocking findings but cannot dismiss them.
- **Builder:** reproduces checks from an immutable source revision with a
  distinct identity.
- **Merger:** performs one compare-and-swap integration after all policy gates
  pass; it cannot create or modify the candidate.

Two independent reviewers are required for routine product changes. A candidate
cannot satisfy every required gate through one provider session, credential, or
workload identity.

## Routine autonomous integration

The merger service may merge a routine verified change into protected `main`
only when:

- the base revision is still current;
- leased paths and licence boundaries match the reviewed plan;
- required builds, tests, security scans, provenance checks, and independent
  reviews passed against the exact candidate tree;
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
