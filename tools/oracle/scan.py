#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Content scan of a verdict, run before it is allowed to leave the boundary.

The scan is a provenance test, not a pattern test. A pattern scanner can only
refuse the leaks somebody thought of; this refuses every string that is not
*the same object* as one of the clean side's own constants. A string that came
off the wire fails `is` even when it spells a legal value, so the scan cannot be
satisfied by an attacker who guesses the vocabulary — only by a verdict that was
rebuilt from this side's table.

It is deliberately the second line. The first is that `release.parse` never
puts wire bytes into a verdict at all.
"""

from __future__ import annotations

from tools.oracle import vocabulary as vocab


class ScanError(Exception):
    """The verdict is not made of clean-side constants."""


def interned_table(registry: vocab.Registry) -> tuple[str, ...]:
    """Every string a verdict is allowed to contain, as live objects."""
    return (
        *(field.field_id for field in registry.fields),
        *(outcome.value for outcome in vocab.Outcome),
        *(relation.value for relation in vocab.Relation),
        *(magnitude.value for magnitude in vocab.Magnitude),
        *(refusal.value for refusal in vocab.Refusal),
    )


def _require_interned(value: object, table: tuple[str, ...]) -> None:
    if not isinstance(value, str):
        raise ScanError("verdict holds a non-string where a constant belongs")
    for constant in table:
        if value is constant:
            return
    raise ScanError("verdict holds a string that is not a clean-side constant")


def scan_verdict(verdict: object, registry: vocab.Registry) -> None:
    """Raise `ScanError` unless every part of `verdict` came from this side."""
    from tools.oracle import release  # imported here to keep the cycle one-way

    if type(verdict) is not release.Verdict:
        raise ScanError("released value is not a Verdict")
    table = interned_table(registry)
    if verdict.outcome not in tuple(vocab.Outcome):
        raise ScanError("verdict outcome is not an Outcome member")
    _require_interned(verdict.outcome.value, table)
    if verdict.refusal is not None:
        if verdict.refusal not in tuple(vocab.Refusal):
            raise ScanError("verdict refusal is not a Refusal member")
        _require_interned(verdict.refusal.value, table)
    if type(verdict.differences) is not tuple:
        raise ScanError("verdict differences is not a tuple")
    if len(verdict.differences) > len(registry.fields):
        raise ScanError("verdict carries more differences than there are fields")
    for difference in verdict.differences:
        if type(difference) is not release.Difference:
            raise ScanError("verdict holds something that is not a Difference")
        _require_interned(difference.field, table)
        if registry.get(difference.field) is None:
            raise ScanError("verdict names a field that is not registered")
        if difference.relation not in tuple(vocab.Relation):
            raise ScanError("difference relation is not a Relation member")
        if difference.magnitude not in tuple(vocab.Magnitude):
            raise ScanError("difference magnitude is not a Magnitude member")
