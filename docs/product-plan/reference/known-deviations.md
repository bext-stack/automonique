# Known deviations from the reference engine

The parity harness compares two engines' *intended actions* and classifies every
difference. There are exactly three classifications, and only one of them is a
judgement call: **parity** (the two engines agreed), **known deviation** (they
differed, and the difference is registered below with a reason and an owner), or
**regression** (they differed and nothing here explains it).

An unregistered difference is always a regression. That direction is deliberate:
a harness that could resolve an unexplained difference in the candidate's favour
would be scoring its own opinion, and the whole point of the gate is that it
scores evidence.

This document is the human record. `tools/parity/deviations.py` derives
`plan/ledgers/deviations.json` from it and refuses on drift, and the Rust
comparator loads that ledger, digests it, and pins the digest into every gate
decision it records — so a later edit here cannot retroactively rewrite what was
known when a scope was promoted.

## How to read a row

Each row registers **one field of one action kind in one scope**. It does not
excuse a scope, an action kind, or a field generally: a difference matches a row
only when the scope, the action kind, the comparison field and the relation all
agree. A comparison that produces two differences needs both of them registered
— a partly explained mismatch is an unexplained mismatch, and classifies as a
regression.

Registering a deviation is not an approval to ship. It is a statement that
somebody looked at a specific difference, decided it was intended, and put their
name and the date next to that decision.

## Closed vocabularies

Nothing outside these sets may appear in a row. They are the same spellings
`automonique_protocol::parity` defines, and `tools/parity/deviations.py` refuses
a row that steps outside them rather than passing an unknown value through to a
comparator that would then not match it.

| Column | Admitted values |
|---|---|
| Action kind | `slack-thread-reply`, `slack-channel-post`, `slack-approval-card`, `slack-decision-update`, `ticket-dispatch`, `ticket-confirm`, `ticket-decision`, `telegram-send`, `github-issue-action`, `support-email-send`, `no-action` |
| Field | `state_transition`, `action_effect`, `receipt`, `receipt_timestamp`, `rendered_message`, `provider_event`, `provider_event_id`, `resource_class` |
| Relation | `value_differs`, `absent_in_candidate`, `absent_in_reference`, `type_differs`, `order_differs`, `masked_nondeterministic` |
| Reason | `bug-fix`, `deliberate-improvement` |

The field and relation vocabularies are `tools/oracle/fields.json` and
`tools/oracle/vocabulary.py`, reused rather than restated, so a live-traffic
verdict and a future archive-differential verdict land in the same shape.

`receipt_timestamp` and `provider_event_id` are registered
approved-nondeterministic in `tools/oracle/fields.json`, and the comparator masks
them before comparing. A difference on one of those fields is therefore not
something a row here can be needed for — and a row that registers one is
reported as a finding rather than silently kept.

## Registered deviations

| Id | Scope | Action kind | Field | Relation | Reason | Owner | Date | Rationale |
|---|---|---|---|---|---|---|---|---|

**This table is empty, and that is a measurement rather than an omission.** No
difference between the two engines has been investigated and accepted yet,
because no production-representative comparison has been run — the harness
landed in this milestone and the traffic capture it needs is the next one. An
empty registry means every mismatch the corpus finds today classifies as a
regression, which is the correct posture for a scope nobody has examined.

## Adding a row

1. Investigate the mismatch. The comparison names the scope, the action kind,
   the field and the relation; it never carries the values, so the investigation
   happens against the shadow database on the host that recorded it.
2. Mint the fixture first. `python3 tools/parity/traces.py export` writes an
   anonymized golden trace, and the replay corpus picks it up on the next run.
   A registered deviation with no fixture is a claim nothing re-checks.
3. Add one row here, with an owner who is a person and a date that is the day
   the decision was taken.
4. Regenerate: `python3 tools/parity/deviations.py --write`, and commit
   `plan/ledgers/deviations.json` in the same change. CI refuses the two files
   out of step.

Removing a row is the same ritual in reverse, and it is not retroactive: gate
decisions already recorded pinned the registry digest they were taken against,
so they keep meaning what they meant.
