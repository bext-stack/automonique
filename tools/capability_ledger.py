#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Verify the external capability ledger is complete, keyed and resolvable.

`plan/baseline.py` counts how many required fields the ledger is missing. That
counter falling proves cells are non-empty; it cannot prove they are *true*.
This checker adds the parts the counter cannot see: the track vocabulary is
closed, every ticket resolves to a real work-graph item, no row was dropped,
and the periodic review is scheduled as inspectable data.

    python3 tools/capability_ledger.py            # verify
    python3 tools/capability_ledger.py --summary  # verify and print coverage

Exit code is non-zero when the ledger is inconsistent, so CI can branch on it.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plan"))

import baseline as bl  # noqa: E402

LEDGER = bl.CAPABILITY_LEDGER
GRAPH = ROOT / "plan/work-graph.toml"
SCHEDULE = ROOT / "plan/capability-review.json"

REQUIRED_COLUMNS = ("capability", "automonique adaptation", "track", "owner",
                    "ticket", "fixture")
TRACKS = frozenset({"core", "expansion", "optional", "research"})
SCHEDULE_FIELDS = ("schema", "cadence_days", "scope", "owner", "next_review_trigger")
# 117 rows across 11 tables at the time the ledger was keyed. A drop means a
# capability was silently removed, which the contract forbids outright.
EXPECTED_ROWS = 117


class LedgerError(Exception):
    """The ledger cannot be verified."""


def work_item_ids() -> set[str]:
    with GRAPH.open("rb") as handle:
        return {item["id"] for item in tomllib.load(handle)["item"]}


def rows() -> list[dict[str, str]]:
    """Every ledger row as a column-keyed mapping."""
    collected: list[dict[str, str]] = []
    for header, table in bl.parse_tables(LEDGER):
        index = {name.strip().lower(): position for position, name in enumerate(header)}
        missing = [column for column in REQUIRED_COLUMNS
                   if not any(column in name for name in index)]
        if missing:
            raise LedgerError(f"a ledger table lacks column(s): {', '.join(missing)}")
        for row in table:
            entry: dict[str, str] = {}
            for column in REQUIRED_COLUMNS:
                position = next(p for name, p in index.items() if column in name)
                entry[column] = row[position].strip() if position < len(row) else ""
            collected.append(entry)
    return collected


def verify() -> list[dict[str, str]]:
    entries = rows()
    problems: list[str] = []

    if len(entries) < EXPECTED_ROWS:
        problems.append(
            f"ledger has {len(entries)} rows but {EXPECTED_ROWS} were keyed; "
            "a capability may have been dropped"
        )

    known = work_item_ids()
    for entry in entries:
        label = entry["capability"][:48] or "<unnamed>"
        for column in REQUIRED_COLUMNS:
            if not entry[column]:
                problems.append(f"{label}: {column} is blank")
        if entry["track"] and entry["track"] not in TRACKS:
            problems.append(f"{label}: track {entry['track']!r} is outside the closed set")
        ticket = entry["ticket"]
        if ticket and ticket not in known:
            problems.append(f"{label}: ticket {ticket!r} is not a work-graph item")

    if not SCHEDULE.exists():
        problems.append("plan/capability-review.json is missing")
    else:
        try:
            schedule = json.loads(SCHEDULE.read_text())
        except json.JSONDecodeError as exc:
            raise LedgerError(f"capability review schedule is not valid JSON: {exc}") from exc
        for field in SCHEDULE_FIELDS:
            if not schedule.get(field):
                problems.append(f"capability review schedule lacks {field}")
        cadence = schedule.get("cadence_days")
        if not isinstance(cadence, int) or cadence < 1:
            problems.append("capability review cadence_days must be a positive integer")

    if problems:
        raise LedgerError("\n  ".join(["ledger verification failed:"] + problems))
    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", action="store_true")
    arguments = parser.parse_args()
    try:
        entries = verify()
    except LedgerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    tracks = collections.Counter(entry["track"] for entry in entries)
    owners = {entry["owner"] for entry in entries}
    tickets = {entry["ticket"] for entry in entries}
    print(
        f"ok — {len(entries)} capabilities keyed across {len(owners)} owners "
        f"and {len(tickets)} tickets"
    )
    if arguments.summary:
        for track in sorted(tracks):
            print(f"  {track:<10} {tracks[track]}")
        unfixtured = sum(1 for e in entries if e["fixture"].startswith("none"))
        print(f"  awaiting a fixture: {unfixtured}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
