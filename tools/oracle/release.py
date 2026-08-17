#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The trust transition. Bytes from the custody side become a clean verdict here.

Everything before this module is untrusted, including
`tools/oracle/runner.py`: it runs in the process that holds legacy source, so
it is contaminated by construction and its cooperation is never assumed. This
module is the control.

The rule the whole design rests on:

    no byte from the wire is ever stored in, or copied into, a released value.

The wire selects; this side supplies. A record names an outcome, a field, a
relation and a magnitude; every one of those names is looked up in a clean-side
table and the *table's* object is what goes into the verdict. A record that
selects nothing valid releases a `Refusal`, which is itself a member of a closed
set and carries no detail about what was rejected — not the offending bytes, not
their length, not an exception message.

`parse` never raises on hostile input and never logs. There is no verbosity
switch or debug bypass.
"""

from __future__ import annotations

import dataclasses
import json

from tools.oracle import scan
from tools.oracle import vocabulary as vocab

DIFFERENCE_KEYS = frozenset({"field", "relation", "magnitude"})
RECORD_KEYS = frozenset({"schema", "outcome", "differences"})


@dataclasses.dataclass(frozen=True)
class Difference:
    """One compared field that differed, in the closed vocabulary."""

    field: str
    relation: vocab.Relation
    magnitude: vocab.Magnitude


@dataclasses.dataclass(frozen=True)
class Verdict:
    """The only value that crosses into agent context."""

    outcome: vocab.Outcome
    differences: tuple[Difference, ...] = ()
    refusal: vocab.Refusal | None = None

    def render(self) -> str:
        """A human-readable line assembled only from clean-side constants."""
        parts = [f"outcome={self.outcome.value}"]
        if self.refusal is not None:
            parts.append(f"refusal={self.refusal.value}")
        parts.append(f"differences={len(self.differences)}")
        for difference in self.differences:
            parts.append(
                f"{difference.field}/{difference.relation.value}"
                f"/{difference.magnitude.value}"
            )
        return " ".join(parts)


def refused(reason: vocab.Refusal) -> Verdict:
    return Verdict(vocab.Outcome.REFUSED, (), reason)


TIMED_OUT = Verdict(vocab.Outcome.TIMEOUT, (), None)


def parse(
    raw: bytes | None,
    *,
    registry: vocab.Registry,
    policy: vocab.ReleasePolicy = vocab.ReleasePolicy.FIELD_RELATIONS,
    requested: tuple[str, ...] | None = None,
    limit: int = vocab.RECORD_LIMIT,
) -> Verdict:
    """Turn one custody-side record into a verdict, or refuse.

    Returns a `Verdict` for every possible input. It has no failure mode that
    propagates an exception, because an exception carries a message and a
    traceback, and both of those are exactly what must not cross.
    """
    if raw is None:
        return refused(vocab.Refusal.NO_RECORD)
    if not isinstance(raw, (bytes, bytearray)):
        return refused(vocab.Refusal.NOT_JSON)
    if len(raw) == 0:
        return refused(vocab.Refusal.EMPTY_RECORD)
    if len(raw) > limit:
        return refused(vocab.Refusal.OVERSIZE)
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return refused(vocab.Refusal.NOT_UTF8)
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return refused(vocab.Refusal.NOT_JSON)
    finally:
        del text
    verdict = _from_document(document, registry, policy, requested)
    del document
    try:
        scan.scan_verdict(verdict, registry)
    except scan.ScanError:
        return refused(vocab.Refusal.SCAN_REJECTED)
    return verdict


def _from_document(
    document: object,
    registry: vocab.Registry,
    policy: vocab.ReleasePolicy,
    requested: tuple[str, ...] | None,
) -> Verdict:
    if not isinstance(document, dict):
        return refused(vocab.Refusal.NOT_OBJECT)
    keys = set(document)
    if keys - RECORD_KEYS:
        return refused(vocab.Refusal.UNKNOWN_KEY)
    if RECORD_KEYS - keys:
        return refused(vocab.Refusal.MISSING_KEY)
    if document["schema"] != vocab.RELEASE_SCHEMA:
        return refused(vocab.Refusal.BAD_SCHEMA)

    wire_outcome = document["outcome"]
    if not isinstance(wire_outcome, str):
        return refused(vocab.Refusal.UNKNOWN_OUTCOME)
    if wire_outcome in {member.value for member in vocab.CLEAN_SIDE_ONLY}:
        return refused(vocab.Refusal.RESERVED_OUTCOME)
    outcome = vocab.WIRE_OUTCOMES.get(wire_outcome)
    if outcome is None:
        return refused(vocab.Refusal.UNKNOWN_OUTCOME)

    entries = document["differences"]
    if not isinstance(entries, list):
        return refused(vocab.Refusal.DIFFERENCES_NOT_LIST)
    if len(entries) > len(registry.fields):
        return refused(vocab.Refusal.TOO_MANY_DIFFERENCES)

    differences: list[Difference] = []
    claimed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return refused(vocab.Refusal.DIFFERENCE_NOT_OBJECT)
        entry_keys = set(entry)
        if entry_keys != DIFFERENCE_KEYS:
            return refused(vocab.Refusal.UNKNOWN_KEY)
        field = registry.get(entry["field"])
        if field is None:
            return refused(vocab.Refusal.UNKNOWN_FIELD)
        if requested is not None and field.field_id not in requested:
            return refused(vocab.Refusal.FIELD_NOT_REQUESTED)
        if field.field_id in claimed:
            return refused(vocab.Refusal.DUPLICATE_FIELD)
        relation = _member(vocab.Relation, entry["relation"])
        if relation is None:
            return refused(vocab.Refusal.UNKNOWN_RELATION)
        magnitude = _member(vocab.Magnitude, entry["magnitude"])
        if magnitude is None:
            return refused(vocab.Refusal.UNKNOWN_MAGNITUDE)
        if relation is vocab.Relation.MASKED_NONDETERMINISTIC and not field.masked:
            return refused(vocab.Refusal.MASK_NOT_REGISTERED)
        claimed.add(field.field_id)
        # `field.field_id` is the registry's own string object, never the
        # wire's. This assignment is where the wire stops.
        differences.append(Difference(field.field_id, relation, magnitude))

    if outcome in vocab.EMPTY_DIFFERENCES_REQUIRED and differences:
        return refused(vocab.Refusal.OUTCOME_DIFFERENCES_DISAGREE)
    if outcome in vocab.DIFFERENCES_REQUIRED and not differences:
        return refused(vocab.Refusal.OUTCOME_DIFFERENCES_DISAGREE)

    if policy is vocab.ReleasePolicy.OUTCOME_ONLY:
        # Validated in full, then discarded: the low-capacity setting still
        # refuses a malformed record rather than silently ignoring it.
        return Verdict(outcome, (), None)

    # Canonical order, so the order the inside chose carries nothing.
    differences.sort(key=lambda item: registry.index(item.field))
    return Verdict(outcome, tuple(differences), None)


def _member(enumeration: type, value: object) -> object | None:
    if not isinstance(value, str):
        return None
    for member in enumeration:
        if member.value == value:
            return member
    return None
