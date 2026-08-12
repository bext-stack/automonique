#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Strictly consume the canonical `R0-09` restore dependency inventory.

The only accepted producer is:

    plan/inventory/surface/restore-dependencies.json

Its schema is closed, its dependency order is checked as a contiguous
topological order, and its source digest is checked against the actual
`R0-09` source document.  Finally, this consumer calls the producer's public
``render_restore`` function over those actual source bytes and requires exact
byte equality.  A stale, hand-rewritten, or merely schema-shaped copy is
therefore refused rather than partly trusted.

Two legacy-local-description jobs remain here, but neither is accepted as
R0-09 authority:

- `--write` regenerates `spikes/recovery/restore-dependencies.json` from the
  typed dependency table in `recovery_set.py`, atomically;
- `--check` fails when the checked-in copy is stale.

`--check` verifies only that local description. Contract-facing consumption is
the canonical producer validation performed by `--report`.

    python3 spikes/recovery/dependencies.py --check
    python3 spikes/recovery/dependencies.py --report

Exit codes: 0 clean, 1 stale or refused at parse, 2 findings recorded.
"""

from __future__ import annotations

import argparse
import enum
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import recovery_set as rs  # noqa: E402
from tools.surface_inventory import render as surface_render  # noqa: E402

GENERATED = HERE / "restore-dependencies.json"
GENERATED_SCHEMA = "automonique.recovery.restore-dependencies.v1"
INVENTORY_SCHEMA = "automonique.restore-dependencies/v1"
DECLARED_INVENTORY_PATH = "plan/inventory/surface/restore-dependencies.json"
DECLARED_SOURCE_PATH = "plan/inventory/surface/inventory.json"
CANONICAL_INVENTORY = REPOSITORY_ROOT / DECLARED_INVENTORY_PATH
CANONICAL_SOURCE = REPOSITORY_ROOT / DECLARED_SOURCE_PATH

DOCUMENT_KEYS = frozenset({
    "schema", "work_item", "consumer", "source", "objectives", "order",
    "excluded",
})
SOURCE_KEYS = frozenset({"path", "sha256"})
OBJECTIVE_KEYS = frozenset({"id", "summary", "value", "unit", "source"})
OBJECTIVE_SOURCE_KEYS = frozenset({"path", "quote"})
ORDER_KEYS = frozenset(
    {"position", "id", "class", "requires", "verification", "summary"})
EXCLUDED_KEYS = frozenset({"id", "summary", "source"})
OBJECTIVE_IDS = frozenset({
    "recovery-point-objective-control-state",
    "recovery-time-objective-same-host-class",
})
OBJECTIVE_UNITS = frozenset({"minute"})
ORDER_CLASSES = frozenset(
    {"recovery-set-input", "verification-step", "enablement-gate"})
VERIFICATIONS = frozenset({
    "integrity-check",
    "hash-comparison",
    "version-comparison",
    "startup-in-disconnected-recovery",
    "credential-resolution",
    "audience-revalidation",
    "none-recorded",
})
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class DependencyFinding(enum.Enum):
    """What consuming the inventory can find. A subset of the drill's codes."""

    INVENTORY_ABSENT = "inventory_absent"
    DEPENDENCY_MISSING_FROM_INVENTORY = "dependency_missing_from_inventory"
    DEPENDENCY_ORDER_CONFLICT = "dependency_order_conflict"
    DEPENDENCY_UNVERIFIED_IN_INVENTORY = "dependency_unverified_in_inventory"
    DEPENDENCY_NOT_EXERCISED = "dependency_not_exercised"


class Refusal(enum.Enum):
    """Why an inventory is refused at parse rather than partly believed."""

    INVALID_JSON = "invalid_json"
    NOT_AN_OBJECT = "not_an_object"
    UNKNOWN_SCHEMA = "unknown_schema"
    UNKNOWN_KEY = "unknown_key"
    MISSING_KEY = "missing_key"
    DUPLICATE_KEY = "duplicate_key"
    TYPE_MISMATCH = "type_mismatch"
    WRONG_WORK_ITEM = "wrong_work_item"
    WRONG_CONSUMER = "wrong_consumer"
    PATH_MISMATCH = "path_mismatch"
    SOURCE_MISMATCH = "source_mismatch"
    SOURCE_DIGEST_MISMATCH = "source_digest_mismatch"
    UNKNOWN_ENUM_VALUE = "unknown_enum_value"
    DUPLICATE_ID = "duplicate_id"
    BAD_ORDER = "bad_order"
    BAD_REFERENCE = "bad_reference"
    BAD_OBJECTIVE = "bad_objective"
    BAD_EXCLUDED = "bad_excluded"
    RENDER_MISMATCH = "render_mismatch"


class InventoryRefused(Exception):
    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise InventoryRefused(
                Refusal.DUPLICATE_KEY, f"JSON object repeats key {key!r}")
        document[key] = value
    return document


def _object(value: object, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise InventoryRefused(
            Refusal.NOT_AN_OBJECT, f"{where} is not a JSON object")
    return value


def _keys(value: dict[str, Any], expected: frozenset[str], where: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        raise InventoryRefused(
            Refusal.UNKNOWN_KEY, f"{where} has unknown keys {unknown}")
    missing = sorted(expected - set(value))
    if missing:
        raise InventoryRefused(
            Refusal.MISSING_KEY, f"{where} is missing keys {missing}")


def _string(value: object, where: str) -> str:
    if type(value) is not str or not value:
        raise InventoryRefused(
            Refusal.TYPE_MISMATCH, f"{where} is not a non-empty string")
    return value


def _list(value: object, where: str) -> list[Any]:
    if type(value) is not list:
        raise InventoryRefused(
            Refusal.TYPE_MISMATCH, f"{where} is not a JSON array")
    return value


def _enum(value: object, permitted: frozenset[str], where: str) -> str:
    text = _string(value, where)
    if text not in permitted:
        raise InventoryRefused(
            Refusal.UNKNOWN_ENUM_VALUE,
            f"{where} is {text!r}; permitted values are {sorted(permitted)}")
    return text


def _validate_objectives(raw: object) -> None:
    objectives = _list(raw, "objectives")
    if len(objectives) != len(OBJECTIVE_IDS):
        raise InventoryRefused(
            Refusal.BAD_OBJECTIVE,
            f"objectives has {len(objectives)} entries; expected "
            f"{len(OBJECTIVE_IDS)}")
    seen: set[str] = set()
    for index, value in enumerate(objectives):
        where = f"objectives[{index}]"
        objective = _object(value, where)
        _keys(objective, OBJECTIVE_KEYS, where)
        objective_id = _string(objective["id"], f"{where}.id")
        if objective_id in seen:
            raise InventoryRefused(
                Refusal.DUPLICATE_ID, f"objective {objective_id!r} repeats")
        seen.add(objective_id)
        _string(objective["summary"], f"{where}.summary")
        threshold = objective["value"]
        if type(threshold) not in {int, float} or threshold <= 0:
            raise InventoryRefused(
                Refusal.BAD_OBJECTIVE,
                f"{where}.value is not a positive JSON number")
        _enum(objective["unit"], OBJECTIVE_UNITS, f"{where}.unit")
        source = _object(objective["source"], f"{where}.source")
        _keys(source, OBJECTIVE_SOURCE_KEYS, f"{where}.source")
        _string(source["path"], f"{where}.source.path")
        _string(source["quote"], f"{where}.source.quote")
    if seen != OBJECTIVE_IDS:
        raise InventoryRefused(
            Refusal.BAD_OBJECTIVE,
            f"objective IDs are {sorted(seen)}; expected {sorted(OBJECTIVE_IDS)}")


def _validate_order(raw: object) -> None:
    values = _list(raw, "order")
    if not values:
        raise InventoryRefused(Refusal.BAD_ORDER, "order is empty")
    entries: list[dict[str, Any]] = []
    by_id: dict[str, int] = {}
    for index, value in enumerate(values):
        where = f"order[{index}]"
        entry = _object(value, where)
        _keys(entry, ORDER_KEYS, where)
        position = entry["position"]
        if type(position) is not int or position != index + 1:
            raise InventoryRefused(
                Refusal.BAD_ORDER,
                f"{where}.position is {position!r}; expected {index + 1}")
        entry_id = _string(entry["id"], f"{where}.id")
        if entry_id in by_id:
            raise InventoryRefused(
                Refusal.DUPLICATE_ID, f"order ID {entry_id!r} repeats")
        by_id[entry_id] = position
        kind = _enum(entry["class"], ORDER_CLASSES, f"{where}.class")
        requires = _list(entry["requires"], f"{where}.requires")
        if any(type(item) is not str or not item for item in requires):
            raise InventoryRefused(
                Refusal.TYPE_MISMATCH,
                f"{where}.requires contains a non-string or empty ID")
        if len(set(requires)) != len(requires):
            raise InventoryRefused(
                Refusal.BAD_REFERENCE, f"{where}.requires repeats an ID")
        if kind == "recovery-set-input" and requires:
            raise InventoryRefused(
                Refusal.BAD_REFERENCE,
                f"{where} is a recovery-set input but has prerequisites")
        if kind != "recovery-set-input" and not requires:
            raise InventoryRefused(
                Refusal.BAD_REFERENCE,
                f"{where} is {kind!r} but has no prerequisite")
        _enum(entry["verification"], VERIFICATIONS, f"{where}.verification")
        _string(entry["summary"], f"{where}.summary")
        entries.append(entry)

    for index, entry in enumerate(entries):
        for dependency in entry["requires"]:
            position = by_id.get(dependency)
            if position is None:
                raise InventoryRefused(
                    Refusal.BAD_REFERENCE,
                    f"order[{index}].requires names unknown ID {dependency!r}")
            if position >= entry["position"]:
                raise InventoryRefused(
                    Refusal.BAD_ORDER,
                    f"order[{index}] requires {dependency!r} at position "
                    f"{position}, not an earlier position")


def _validate_excluded(raw: object) -> None:
    values = _list(raw, "excluded")
    if not values:
        raise InventoryRefused(
            Refusal.BAD_EXCLUDED, "excluded has no boundary record")
    seen: set[str] = set()
    for index, value in enumerate(values):
        where = f"excluded[{index}]"
        entry = _object(value, where)
        _keys(entry, EXCLUDED_KEYS, where)
        entry_id = _string(entry["id"], f"{where}.id")
        if entry_id in seen:
            raise InventoryRefused(
                Refusal.DUPLICATE_ID, f"excluded ID {entry_id!r} repeats")
        seen.add(entry_id)
        _string(entry["summary"], f"{where}.summary")
        _string(entry["source"], f"{where}.source")


def validate_inventory(
    encoded: bytes, *, source_bytes: bytes | None = None
) -> dict[str, Any]:
    """Validate canonical bytes and return their closed JSON document."""
    try:
        document = json.loads(encoded, object_pairs_hook=_pairs)
    except InventoryRefused:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryRefused(
            Refusal.INVALID_JSON, f"inventory JSON cannot be decoded: {exc}") from None
    document = _object(document, "document")
    _keys(document, DOCUMENT_KEYS, "document")
    schema = _string(document["schema"], "schema")
    if schema != INVENTORY_SCHEMA:
        raise InventoryRefused(
            Refusal.UNKNOWN_SCHEMA,
            f"schema {schema!r}; expected {INVENTORY_SCHEMA!r}")
    work_item = _string(document["work_item"], "work_item")
    if work_item != "R0-09":
        raise InventoryRefused(
            Refusal.WRONG_WORK_ITEM,
            f"work_item {work_item!r}; expected 'R0-09'")
    consumer = _string(document["consumer"], "consumer")
    if consumer != "R0-10":
        raise InventoryRefused(
            Refusal.WRONG_CONSUMER,
            f"consumer {consumer!r}; expected 'R0-10'")

    source = _object(document["source"], "source")
    _keys(source, SOURCE_KEYS, "source")
    source_path = _string(source["path"], "source.path")
    if source_path != DECLARED_SOURCE_PATH:
        raise InventoryRefused(
            Refusal.SOURCE_MISMATCH,
            f"source.path {source_path!r}; expected {DECLARED_SOURCE_PATH!r}")
    digest = source["sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise InventoryRefused(
            Refusal.TYPE_MISMATCH, "source.sha256 is not a lowercase SHA-256")

    actual_source = CANONICAL_SOURCE.read_bytes() if source_bytes is None else source_bytes
    actual_digest = hashlib.sha256(actual_source).hexdigest()
    if digest != actual_digest:
        raise InventoryRefused(
            Refusal.SOURCE_DIGEST_MISMATCH,
            f"source.sha256 is {digest}; actual source digest is {actual_digest}")

    _validate_objectives(document["objectives"])
    _validate_order(document["order"])
    _validate_excluded(document["excluded"])

    try:
        source_document = _object(
            json.loads(actual_source, object_pairs_hook=_pairs),
            "canonical source",
        )
        expected = surface_render.render_restore(source_document, actual_source)
    except InventoryRefused:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        surface_render.RenderError,
    ) as exc:
        raise InventoryRefused(
            Refusal.SOURCE_MISMATCH,
            f"canonical source cannot be independently rendered: {exc}") from None
    if encoded != expected:
        raise InventoryRefused(
            Refusal.RENDER_MISMATCH,
            "inventory bytes differ from render_restore(actual R0-09 source)")
    return document


def parse_inventory(document: object) -> dict[str, Any]:
    """Compatibility entry point; still subjects the value to byte equality."""
    encoded = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()
    return validate_inventory(encoded)


def _is_canonical_inventory_path(path: pathlib.Path) -> bool:
    if path not in (CANONICAL_INVENTORY, pathlib.Path(DECLARED_INVENTORY_PATH)):
        return False
    cursor = REPOSITORY_ROOT
    for part in pathlib.Path(DECLARED_INVENTORY_PATH).parts:
        cursor /= part
        if cursor.is_symlink():
            return False
    return True


def load_inventory(path: pathlib.Path = CANONICAL_INVENTORY) -> dict[str, Any]:
    if not _is_canonical_inventory_path(path):
        raise InventoryRefused(
            Refusal.PATH_MISMATCH,
            f"inventory path {path}; expected {DECLARED_INVENTORY_PATH}")
    return validate_inventory(CANONICAL_INVENTORY.read_bytes())


def _finding(code: DependencyFinding, subject: str, detail: str) -> dict[str, str]:
    return {"code": code.value, "subject": subject, "detail": detail}


def consume(inventory: pathlib.Path | None = None) -> dict[str, object]:
    """Consume only the canonical producer and preserve the drill report API."""
    path = inventory or CANONICAL_INVENTORY
    report: dict[str, object] = {
        "declared_inventory_path": DECLARED_INVENTORY_PATH,
        "inventory_path": path.relative_to(REPOSITORY_ROOT).as_posix()
        if path.is_relative_to(REPOSITORY_ROOT) else path.name,
        "inventory_present": path.is_file(),
        "refused": None,
        "consumed_entries": 0,
        "drill_dependencies": len(rs.RESTORE_DEPENDENCIES),
        "objectives": [],
        "excluded": [],
        "findings": [],
    }
    if not _is_canonical_inventory_path(path):
        refusal = InventoryRefused(
            Refusal.PATH_MISMATCH,
            f"inventory path {path}; expected {DECLARED_INVENTORY_PATH}")
        report["refused"] = {
            "code": refusal.refusal.value, "detail": refusal.detail}
        return report
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
        document = load_inventory(path)
    except InventoryRefused as refusal:
        report["refused"] = {"code": refusal.refusal.value,
                             "detail": refusal.detail}
        return report
    report["consumed_entries"] = len(document["order"])
    report["objectives"] = document["objectives"]
    report["excluded"] = document["excluded"]
    inventory_ids = {entry["id"] for entry in document["order"]}
    drill_ids = {entry.id for entry in rs.RESTORE_DEPENDENCIES}
    report["findings"] = [
        _finding(
            DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY,
            entry.id,
            "the existing local drill declares this need, but R0-09 does not "
            "contain the same typed dependency ID",
        )
        for entry in rs.RESTORE_DEPENDENCIES
        if entry.id not in inventory_ids
    ] + [
        _finding(
            DependencyFinding.DEPENDENCY_NOT_EXERCISED,
            entry["id"],
            "R0-09 requires this ordered position and the existing local drill "
            "does not yet emit a disposition receipt for it",
        )
        for entry in document["order"]
        if entry["id"] not in drill_ids
    ]
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
