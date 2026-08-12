# Governance

Automonique uses a direct development model. The owner may ask Codex or a human
developer to inspect, edit, test, commit, and non-force-push repository changes
without first creating a work claim, packet, lease, contract, evidence record,
or plan status transition.

## Development authority

Routine repository development includes:

- reading the checked-in specification and current implementation;
- making bounded code, test, documentation, CI, and governance changes;
- coordinating parallel workers with disjoint write ownership;
- running local and CI verification;
- creating ordinary commits; and
- publishing those commits with a non-force push when requested.

Review depth is risk-based. Independent review is useful for security,
durability, compatibility, licence, and large cross-cutting changes, but it is
not a universal prerequisite. A report must never claim a review or measurement
that did not occur.

The former autonomous harness under `plan/`, `.automonique/dev/`, and `tools/`
is retained for reference and optional experiments. Its claims, brokers,
packets, graph gates, evidence schema, and completion transactions are not a
governance or integration boundary.

## Roles

These role names are retained for historical identity-register compatibility;
they are useful responsibilities, not mandatory isolated identities or
workflow stages.

- **Implementer:** creates a code, test, documentation, or policy change.
- **Reviewer:** inspects a change and reports concrete findings when review is used.
- **Fixer:** addresses accepted findings.
- **Builder:** runs the relevant build and test checks.
- **Merger:** creates or publishes the ordinary integrated commit.

## Safety boundaries

The clean-room, data-handling, licence, test-preservation, and Git-safety rules
in `AGENTS.md` remain mandatory.

The following require explicit contemporaneous owner authority for the exact
operation:

- production deployment or mutation;
- enabling a live transport, provider, or external-effect path;
- release signing or package publication;
- credential creation, rotation, or disclosure;
- repository administration or remote configuration changes; and
- force-push, history rewrite, ref deletion, or another destructive Git action.

Authority for routine repository development does not imply authority for any
of those operations.

## Integration

Prefer small, coherent commits and relevant checks. Preserve unrelated work.
Ordinary non-force pushes are allowed; stop on conflicts, non-fast-forward
rejection, or ambiguity rather than forcing through them.

CI exists to test product and repository safety properties, not to prove that
the plan agrees with itself. Roadmap and historical evidence files may still be
updated when useful, but product changes do not need matching graph, baseline,
packet, or evidence edits.
