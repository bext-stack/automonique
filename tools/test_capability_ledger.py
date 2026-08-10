#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

from tools import capability_ledger


class LedgerShapeTests(unittest.TestCase):
    def test_every_row_is_keyed_and_resolvable(self) -> None:
        entries = capability_ledger.verify()
        self.assertGreaterEqual(len(entries), capability_ledger.EXPECTED_ROWS)
        known = capability_ledger.work_item_ids()
        for entry in entries:
            for column in capability_ledger.REQUIRED_COLUMNS:
                self.assertTrue(entry[column], f"{entry['capability']}: {column} blank")
            self.assertIn(entry["track"], capability_ledger.TRACKS)
            self.assertIn(entry["ticket"], known)

    def test_no_row_carries_an_invented_fixture_path(self) -> None:
        """Fixture capture is gate-blocked, so no row may claim a real fixture."""
        for entry in capability_ledger.verify():
            self.assertTrue(
                entry["fixture"].startswith("none"),
                f"{entry['capability']} claims fixture {entry['fixture']!r} while "
                "GATE-ORACLE holds fixture capture closed",
            )


class LedgerRefusalTests(unittest.TestCase):
    """The checker must fail on the shapes the contract forbids."""

    def ledger(self, body: str) -> pathlib.Path:
        directory = pathlib.Path(tempfile.mkdtemp())
        path = directory / "ledger.md"
        path.write_text(body)
        return path

    def table(self, track: str = "core", ticket: str = "R1-25") -> str:
        return (
            "| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |\n"
            "|---|---|---|---|---|---|\n"
            f"| Thing | Adaptation | {track} | automonique-core | {ticket} | none |\n"
        )

    def verify_with(self, body: str) -> None:
        with mock.patch.object(capability_ledger, "LEDGER", self.ledger(body)):
            capability_ledger.verify()

    def test_a_track_outside_the_closed_set_fails(self) -> None:
        with self.assertRaisesRegex(capability_ledger.LedgerError, "closed set"):
            self.verify_with(self.table(track="someday"))

    def test_a_ticket_that_names_no_work_item_fails(self) -> None:
        with self.assertRaisesRegex(capability_ledger.LedgerError, "not a work-graph item"):
            self.verify_with(self.table(ticket="R99-99"))

    def test_a_blank_required_cell_fails(self) -> None:
        body = (
            "| Capability | Automonique adaptation | Track | Owner | Ticket | Fixture |\n"
            "|---|---|---|---|---|---|\n"
            "| Thing | Adaptation | core |  | R1-25 | none |\n"
        )
        with self.assertRaisesRegex(capability_ledger.LedgerError, "owner is blank"):
            self.verify_with(body)

    def test_a_missing_column_fails(self) -> None:
        body = (
            "| Capability | Automonique adaptation | Track |\n"
            "|---|---|---|\n"
            "| Thing | Adaptation | core |\n"
        )
        with self.assertRaisesRegex(capability_ledger.LedgerError, "lacks column"):
            self.verify_with(body)

    def test_a_dropped_row_fails(self) -> None:
        with self.assertRaisesRegex(capability_ledger.LedgerError, "may have been dropped"):
            self.verify_with(self.table())


class ReviewScheduleTests(unittest.TestCase):
    def test_schedule_is_inspectable_data(self) -> None:
        schedule = json.loads(capability_ledger.SCHEDULE.read_text())
        for field in capability_ledger.SCHEDULE_FIELDS:
            self.assertTrue(schedule.get(field), f"{field} is missing")
        self.assertIsInstance(schedule["cadence_days"], int)
        self.assertGreater(schedule["cadence_days"], 0)

    def test_schedule_needs_no_network_or_calendar_service(self) -> None:
        rendered = capability_ledger.SCHEDULE.read_text().lower()
        for token in ("http://", "https://", "webhook", "cron@", "calendar.google"):
            self.assertNotIn(token, rendered)


if __name__ == "__main__":
    unittest.main()
