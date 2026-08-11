#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Consume the `R0-09` restore dependency inventory; never invent one.

`plan/contracts/R0-10.md` requires that the restore dependency list from
`R0-09` is *consumed rather than reinvented*, and that a dependency the drill
discovers but the inventory lacks is reported back as a finding. `R0-09` has
not produced its inventory yet, so this module's live behavior is the second
half of that rule: it looks in the one declared publication path, finds
nothing, and reports every dependency the drill needs as a finding against
`R0-09` instead of quietly standing in for it.

The declared path is a proposal to `R0-09`, not a claim that it exists:

    spikes/inventory/restore-dependencies.json

It is deliberately outside this item's lease. This item cannot create it, so
the absence cannot be resolved by the same agent that reports it.

Two other jobs live here, because both are about the same list:

- `--write` regenerates `spikes/recovery/restore-dependencies.json` from the
  typed dependency table in `recovery_set.py`, atomically;
- `--check` fails when the checked-in copy is stale.

Wiring `--check` into `plan/check.py` is the follow-up for the integrator; this
module is self-contained and runnable on its own so that it can be wired
without being rewritten.

    python3 spikes/recovery/dependencies.py --check
    python3 spikes/recovery/dependencies.py --report
    python3 spikes/recovery/dependencies.py --report --inventory <path>

Exit codes: 0 clean, 1 stale or refused at parse, 2 findings recorded.
"""

from __future__ import annotations

import argparse
import enum
import json
import pathlib
import sys
from dataclasses import dataclass

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import recovery_set as rs  # noqa: E402

REPOSITORY_ROOT = HERE.parent.parent
GENERATED = HERE / "restore-dependencies.json"
GENERATED_SCHEMA = "automonique.recovery.restore-dependencies.v1"
INVENTORY_SCHEMA = "automonique.recovery.restore-dependencies.v1"
DECLARED_INVENTORY_PATH = "spikes/inventory/restore-dependencies.json"

ENTRY_KEYS = frozenset(
    {"id", "order", "kind", "source", "verified_by", "owner_class", "note"})
DOCUMENT_KEYS = frozenset({"schema", "item", "dependencies"})


class DependencyFinding(enum.Enum):
    """What consuming the inventory can find. A subset of the drill's codes."""

    INVENTORY_ABSENT = "inventory_absent"
    DEPENDENCY_MISSING_FROM_INVENTORY = "dependency_missing_from_inventory"
    DEPENDENCY_ORDER_CONFLICT = "dependency_order_conflict"
    DEPENDENCY_UNVERIFIED_IN_INVENTORY = "dependency_unverified_in_inventory"
    DEPENDENCY_NOT_EXERCISED = "dependency_not_exercised"


class Refusal(enum.Enum):
    """Why an inventory is refused at parse rather than partly believed."""

    NOT_AN_OBJECT = "not_an_object"
    UNKNOWN_SCHEMA = "unknown_schema"
    UNKNOWN_KEY = "unknown_key"
    MISSING_KEY = "missing_key"
    UNKNOWN_ENUM_VALUE = "unknown_enum_value"
    DUPLICATE_ID = "duplicate_id"
    BAD_ORDER = "bad_order"


class InventoryRefused(Exception):
    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class InventoryEntry:
    id: str
    order: int
    kind: rs.DependencyKind
    source: rs.DependencySource
    verified_by: rs.Verification
    owner_class: str
    note: str


def _enum_value(cls, raw: object, field: str, entry_id: str):
    try:
        return cls(raw)
    except ValueError:
        permitted = ", ".join(sorted(member.value for member in cls))
        raise InventoryRefused(
            Refusal.UNKNOWN_ENUM_VALUE,
            f"entry {entry_id!r} field {field!r} is {raw!r}; permitted values "
            f"are {permitted}") from None


def parse_inventory(document: object) -> list[InventoryEntry]:
    """Parse strictly. An entry that is not representable is refused, not fixed."""
    if not isinstance(document, dict):
        raise InventoryRefused(Refusal.NOT_AN_OBJECT,
                               "the inventory is not a JSON object")
    unknown = sorted(set(document) - DOCUMENT_KEYS)
    if unknown:
        raise InventoryRefused(Refusal.UNKNOWN_KEY,
                               f"document keys {unknown} are not in the schema")
    missing = sorted(DOCUMENT_KEYS - set(document))
    if missing:
        raise InventoryRefused(Refusal.MISSING_KEY,
                               f"document is missing {missing}")
    if document["schema"] != INVENTORY_SCHEMA:
        raise InventoryRefused(
            Refusal.UNKNOWN_SCHEMA,
            f"schema {document['schema']!r}; expected {INVENTORY_SCHEMA!r}")

    entries: list[InventoryEntry] = []
    seen: set[str] = set()
    raw_entries = document["dependencies"]
    if not isinstance(raw_entries, list):
        raise InventoryRefused(Refusal.NOT_AN_OBJECT,
                               "'dependencies' is not a list")
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise InventoryRefused(Refusal.NOT_AN_OBJECT,
                                   "a dependency entry is not an object")
        entry_id = str(raw.get("id", "<unnamed>"))
        unknown = sorted(set(raw) - ENTRY_KEYS)
        if unknown:
            raise InventoryRefused(
                Refusal.UNKNOWN_KEY,
                f"entry {entry_id!r} has keys {unknown} that are not in the schema")
        missing = sorted(ENTRY_KEYS - set(raw))
        if missing:
            raise InventoryRefused(Refusal.MISSING_KEY,
                                   f"entry {entry_id!r} is missing {missing}")
        order = raw["order"]
        if not isinstance(order, int) or isinstance(order, bool) or order < 1:
            raise InventoryRefused(
                Refusal.BAD_ORDER,
                f"entry {entry_id!r} order {order!r} is not a positive integer")
        if entry_id in seen:
            raise InventoryRefused(Refusal.DUPLICATE_ID,
                                   f"entry {entry_id!r} appears more than once")
        seen.add(entry_id)
        entries.append(InventoryEntry(
            id=entry_id,
            order=order,
            kind=_enum_value(rs.DependencyKind, raw["kind"], "kind", entry_id),
            source=_enum_value(rs.DependencySource, raw["source"], "source",
                               entry_id),
            verified_by=_enum_value(rs.Verification, raw["verified_by"],
                                    "verified_by", entry_id),
            owner_class=str(raw["owner_class"]),
            note=str(raw["note"]),
        ))
    return entries


def load_inventory(path: pathlib.Path) -> list[InventoryEntry]:
    return parse_inventory(json.loads(path.read_text()))


def _finding(code: DependencyFinding, subject: str, detail: str) -> dict[str, str]:
    return {"code": code.value, "subject": subject, "detail": detail}


def compare(entries: list[InventoryEntry]) -> list[dict[str, str]]:
    """Findings from the drill's needs against what the inventory records."""
    by_id = {entry.id: entry for entry in entries}
    findings: list[dict[str, str]] = []
    for needed in rs.RESTORE_DEPENDENCIES:
        entry = by_id.get(needed.id)
        if entry is None:
            findings.append(_finding(
                DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY, needed.id,
                f"the drill restores {needed.kind.value} at order "
                f"{needed.order} and the inventory does not list it"))
            continue
        if entry.order != needed.order:
            findings.append(_finding(
                DependencyFinding.DEPENDENCY_ORDER_CONFLICT, needed.id,
                f"the inventory restores it at order {entry.order}; the drill "
                f"restores it at order {needed.order}"))
        if (entry.verified_by is rs.Verification.NONE_DECLARED
                and needed.verified_by is not rs.Verification.NONE_DECLARED):
            findings.append(_finding(
                DependencyFinding.DEPENDENCY_UNVERIFIED_IN_INVENTORY, needed.id,
                f"the inventory declares no verification; the drill proves it "
                f"with {needed.verified_by.value}"))
    known = {needed.id for needed in rs.RESTORE_DEPENDENCIES}
    for entry in entries:
        if entry.id not in known:
            findings.append(_finding(
                DependencyFinding.DEPENDENCY_NOT_EXERCISED, entry.id,
                f"the inventory requires {entry.kind.value} from "
                f"{entry.source.value} at order {entry.order}; this drill does "
                f"not restore it"))
    return findings


def consume(inventory: pathlib.Path | None = None) -> dict[str, object]:
    """Read the inventory if it exists; otherwise report its absence.

    Never substitutes the drill's own dependency table for the inventory. The
    table is what the drill *needs*; the inventory is what the operations
    surface *has*, and only `R0-09` can say what that is.
    """
    path = inventory or (REPOSITORY_ROOT / DECLARED_INVENTORY_PATH)
    report: dict[str, object] = {
        "declared_inventory_path": DECLARED_INVENTORY_PATH,
        "inventory_path": path.relative_to(REPOSITORY_ROOT).as_posix()
        if path.is_relative_to(REPOSITORY_ROOT) else path.name,
        "inventory_present": path.is_file(),
        "refused": None,
        "consumed_entries": 0,
        "drill_dependencies": len(rs.RESTORE_DEPENDENCIES),
        "findings": [],
    }
    if not path.is_file():
        findings = [_finding(
            DependencyFinding.INVENTORY_ABSENT, "R0-09",
            f"no restore dependency inventory at {report['inventory_path']}; "
            f"the drill needs {len(rs.RESTORE_DEPENDENCIES)} dependencies and "
            f"none of them can be confirmed against an operations inventory")]
        findings.extend(
            _finding(DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY,
                     dependency.id,
                     f"the drill restores {dependency.kind.value} at order "
                     f"{dependency.order} from {dependency.source.value}; no "
                     f"inventory records it")
            for dependency in rs.RESTORE_DEPENDENCIES)
        report["findings"] = findings
        return report
    try:
        entries = load_inventory(path)
    except InventoryRefused as refusal:
        report["refused"] = {"code": refusal.refusal.value,
                             "detail": refusal.detail}
        return report
    report["consumed_entries"] = len(entries)
    report["findings"] = compare(entries)
    return report


# ---------------------------------------------------------------------------
# the generated copy of the drill's own dependency table


def render() -> bytes:
    document = {
        "schema": GENERATED_SCHEMA,
        "item": "R0-10",
        "generated_from": "spikes/recovery/recovery_set.py:RESTORE_DEPENDENCIES",
        "generated_by": "spikes/recovery/dependencies.py --write",
        "dependencies": [d.as_document() for d in rs.RESTORE_DEPENDENCIES],
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def write_generated() -> None:
    rs.write_atomic(GENERATED, render())


def check_generated() -> str | None:
    """`None` when the checked-in copy is current, else why it is not."""
    if not GENERATED.exists():
        return f"{GENERATED.name} is missing; run --write"
    current = GENERATED.read_bytes()
    expected = render()
    if current == expected:
        return None
    return (f"{GENERATED.name} is stale: {len(current)} byte(s) checked in, "
            f"{len(expected)} byte(s) generated from the dependency table")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="fail when the checked-in generated copy is stale")
    mode.add_argument("--write", action="store_true",
                      help="regenerate the checked-in copy atomically")
    mode.add_argument("--report", action="store_true",
                      help="consume the R0-09 inventory and print findings")
    parser.add_argument("--inventory", type=pathlib.Path,
                        help="inventory to consume; defaults to the declared "
                             "publication path")
    arguments = parser.parse_args(argv)

    if arguments.write:
        write_generated()
        print(f"wrote {GENERATED.name}")
        return 0
    if arguments.check:
        stale = check_generated()
        if stale is None:
            print(f"{GENERATED.name} is current "
                  f"({len(rs.RESTORE_DEPENDENCIES)} dependencies)")
            return 0
        print(f"FAIL: {stale}", file=sys.stderr)
        return 1

    report = consume(arguments.inventory)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["refused"] is not None:
        return 1
    return 2 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
