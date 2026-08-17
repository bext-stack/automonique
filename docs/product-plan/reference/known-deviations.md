# Known deviations from the reference engine

The parity harness compares two engines' *intended actions* and classifies every
difference. There are exactly three classifications, and only one of them is a
judgement call: **parity** (the two engines agreed), **known deviation** (they
differed, and the difference is registered below with a reason and an owner), or
**regression** (they differed and nothing here explains it).

An unregistered difference is reported as a regression by default. Callers may
provide an explicit deviation registry when a comparison needs one; no checked-in
registry or regeneration step is required.

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

The comparison API accepts the spellings below.

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

No deviations are registered in the repository. A local diagnostic run may
supply a registry file directly to the parity CLI.
