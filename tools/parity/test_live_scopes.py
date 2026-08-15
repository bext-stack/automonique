#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Negative controls for the live-scope enumeration (M2 #14).

The enumeration's whole value is that it refuses. `test_the_checked_in_tree_passes`
is the positive control; everything else breaks one declaration in a scratch copy
and requires the checker to say so, because a checker that only ever passes is
indistinguishable from one that measures nothing.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from parity import live_scopes

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Enumeration(unittest.TestCase):
    def test_the_checked_in_tree_passes(self):
        self.assertEqual(live_scopes.verify(ROOT), [])

    def test_main_exits_zero(self):
        self.assertEqual(live_scopes.main([]), 0)

    def test_summary_exits_zero(self):
        self.assertEqual(live_scopes.main(["--summary"]), 0)

    def test_every_scope_names_a_seam_and_a_parity_row(self):
        self.assertTrue(live_scopes.SCOPES)
        for scope in live_scopes.SCOPES:
            self.assertTrue(scope.seams, scope.id)
            self.assertTrue(scope.parity_rows, scope.id)

    def test_scope_ids_are_unique(self):
        ids = [scope.id for scope in live_scopes.SCOPES]
        self.assertEqual(len(ids), len(set(ids)))


class Refusals(unittest.TestCase):
    """Each case breaks one declaration and requires a matching complaint."""

    def scopes_with(self, **replacements):
        first = dataclasses.replace(live_scopes.SCOPES[0], **replacements)
        return (first,) + live_scopes.SCOPES[1:]

    def assertRefused(self, scopes, fragment):
        with mock.patch.object(live_scopes, "SCOPES", scopes):
            problems = live_scopes.verify(ROOT)
        self.assertTrue(problems, "the checker accepted a broken enumeration")
        self.assertTrue(
            any(fragment in problem for problem in problems),
            f"no problem mentioned {fragment!r}; got {problems}",
        )

    def test_a_seam_whose_trait_has_been_renamed_is_refused(self):
        moved = dataclasses.replace(
            live_scopes.SLACK_TICKET_POSTER, trait="SlackTicketPosterRenamed"
        )
        self.assertRefused(self.scopes_with(seams=(moved,)), "no longer contains")

    def test_a_seam_whose_file_has_moved_is_refused(self):
        moved = dataclasses.replace(
            live_scopes.SLACK_TICKET_POSTER,
            definition_file="rust/crates/automonique-daemon/src/gone.rs",
        )
        self.assertRefused(self.scopes_with(seams=(moved,)), "does not exist")

    def test_a_seam_whose_production_impl_has_gone_is_refused(self):
        moved = dataclasses.replace(
            live_scopes.SLACK_TICKET_POSTER,
            production_impl="impl SlackTicketPoster for SomethingElse",
        )
        self.assertRefused(self.scopes_with(seams=(moved,)), "production implementation")

    def test_a_parity_row_that_left_the_ledger_is_refused(self):
        self.assertRefused(
            self.scopes_with(parity_rows=("no-such-parity-row",)),
            "which the ledger no longer contains",
        )

    def test_a_scope_with_no_seam_is_refused(self):
        self.assertRefused(self.scopes_with(seams=()), "names no effect seam")

    def test_a_scope_with_no_parity_row_is_refused(self):
        self.assertRefused(self.scopes_with(parity_rows=()), "maps to no parity row")

    def test_a_status_outside_the_closed_set_is_refused(self):
        self.assertRefused(
            self.scopes_with(shadow_status="probably-fine"),
            "outside the closed set",
        )

    def test_a_duplicate_scope_id_is_refused(self):
        duplicated = live_scopes.SCOPES + (live_scopes.SCOPES[0],)
        self.assertRefused(duplicated, "is declared twice")

    def test_a_guessed_legacy_coverage_is_refused(self):
        self.assertRefused(
            self.scopes_with(legacy_coverage="still-serving"),
            "nothing in this repository can establish that",
        )

    def test_an_empty_enumeration_is_refused(self):
        with mock.patch.object(live_scopes, "SCOPES", ()):
            with self.assertRaises(live_scopes.ScopeError):
                live_scopes.verify(ROOT)


class VerificationClaims(unittest.TestCase):
    """The refusal this file exists for: no verified status without a harness."""

    def test_no_scope_claims_more_than_the_tree_supports(self):
        self.assertFalse(
            live_scopes.harness_present(ROOT),
            "the #10 harness has landed; revisit this enumeration and the memo "
            "before relaxing this test",
        )
        for scope in live_scopes.SCOPES:
            self.assertEqual(scope.shadow_status, "no-harness", scope.id)

    def test_claiming_a_comparison_without_the_harness_is_refused(self):
        for claimed in ("capturing", "scored", "decided"):
            with self.subTest(claimed=claimed):
                scopes = (
                    dataclasses.replace(live_scopes.SCOPES[0], shadow_status=claimed),
                ) + live_scopes.SCOPES[1:]
                with mock.patch.object(live_scopes, "SCOPES", scopes):
                    problems = live_scopes.verify(ROOT)
                self.assertTrue(
                    any("no comparison has been possible" in p for p in problems),
                    f"a {claimed!r} claim was accepted with no harness: {problems}",
                )

    def test_the_harness_artifacts_are_the_ones_issue_10_creates(self):
        # If #10 lands under different paths this test fails, which is the
        # signal to re-point the guard rather than let it pass vacuously by
        # watching for files nobody will ever create.
        for relative in live_scopes.HARNESS_ARTIFACTS:
            self.assertTrue(relative.startswith("rust/crates/"), relative)
            self.assertTrue(relative.endswith(".rs"), relative)


class ScratchTree(unittest.TestCase):
    """Cases that need the tree itself to differ, so they run on a copy."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name) / "tree"
        self.root.mkdir()
        for relative in (
            "plan/ledgers/parity.json",
            "plan/gates.md",
            live_scopes.OWNER_MEMO,
            live_scopes.GATE_SCOPE_DECISION,
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, destination)
        for scope in live_scopes.SCOPES:
            for seam in scope.seams:
                for relative in (seam.definition_file, seam.production_file):
                    destination = self.root / relative
                    if destination.exists():
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(ROOT / relative, destination)

    def test_the_copied_tree_passes(self):
        self.assertEqual(live_scopes.verify(self.root), [])

    def test_a_missing_owner_memo_is_refused(self):
        (self.root / live_scopes.OWNER_MEMO).unlink()
        problems = live_scopes.verify(self.root)
        self.assertTrue(any(live_scopes.OWNER_MEMO in p for p in problems), problems)

    def test_a_memo_that_stops_naming_a_scope_is_refused(self):
        memo = self.root / live_scopes.OWNER_MEMO
        memo.write_text(memo.read_text().replace("slack-ticket-routing", "elsewhere"))
        problems = live_scopes.verify(self.root)
        self.assertTrue(
            any("has no decision path" in p for p in problems), problems
        )

    def test_withdrawing_the_gate_oracle_narrowing_is_refused(self):
        gates = self.root / "plan/gates.md"
        gates.write_text(gates.read_text().replace("archive-differential", "all"))
        problems = live_scopes.verify(self.root)
        self.assertTrue(
            any("blocked again" in p for p in problems), problems
        )

    def test_deleting_gate_oracle_entirely_is_refused(self):
        gates = self.root / "plan/gates.md"
        gates.write_text(gates.read_text().replace("### GATE-ORACLE", "### GATE-GONE"))
        problems = live_scopes.verify(self.root)
        self.assertTrue(
            any("no longer defines GATE-ORACLE" in p for p in problems), problems
        )

    def test_an_unreadable_ledger_is_an_error_not_a_pass(self):
        (self.root / "plan/ledgers/parity.json").write_text("{not json")
        with self.assertRaises(live_scopes.ScopeError):
            live_scopes.verify(self.root)

    def test_a_present_harness_lets_a_capturing_status_stand(self):
        # The guard must relax exactly when the evidence appears, or it becomes
        # a permanent veto on the work it is meant to sequence.
        for relative in live_scopes.HARNESS_ARTIFACTS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("// placeholder\n")
        self.assertTrue(live_scopes.harness_present(self.root))
        scopes = (
            dataclasses.replace(live_scopes.SCOPES[0], shadow_status="capturing"),
        ) + live_scopes.SCOPES[1:]
        with mock.patch.object(live_scopes, "SCOPES", scopes):
            self.assertEqual(live_scopes.verify(self.root), [])

    def test_the_ledger_keys_read_are_the_ledgers_own(self):
        keys = live_scopes.ledger_keys(self.root)
        document = json.loads((self.root / "plan/ledgers/parity.json").read_text())
        self.assertEqual(keys, {e["key"] for e in document["entries"]})


if __name__ == "__main__":
    unittest.main()
