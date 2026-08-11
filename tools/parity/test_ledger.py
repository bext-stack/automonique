#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Break every parity-ledger rule deliberately, then prove it was restored.

A check that has never failed is a check nobody has tested, so each refusal
below has a matching positive control: the same call against the real,
unmodified tree must pass. The Markdown source is never edited in place — each
negative case works on a copy in a temporary directory, because
`docs/product-plan/reference/feature-parity.md` is owned by the plan, not by
this test.
"""

from __future__ import annotations

import base64
import json
import pathlib
import tempfile
import unittest

from tools.parity import ledger
from tools.scrub import scan as scrub


def doctor(source_text: str, ledger_text: str | None = None) -> tuple[
        pathlib.Path, pathlib.Path]:
    """A temporary (source, ledger) pair to break without touching the tree."""
    directory = pathlib.Path(tempfile.mkdtemp())
    source = directory / "feature-parity.md"
    source.write_text(source_text)
    target = directory / "parity.json"
    target.write_text(ledger_text if ledger_text is not None
                      else ledger.render(ledger.build(source)))
    return source, target


def real_source() -> str:
    return ledger.SOURCE.read_text()


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(
            f"the doctored fragment appears {text.count(old)} times, not once; "
            f"the test would not be breaking what it claims to break")
    return text.replace(old, new)


class CheckedInLedgerTests(unittest.TestCase):
    """The positive controls, run against the real tree."""

    def test_the_checked_in_ledger_is_not_stale(self) -> None:
        document, problems = ledger.verify()
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertEqual(document["schema"], ledger.SCHEMA)

    def test_regeneration_is_byte_identical(self) -> None:
        self.assertEqual(ledger.LEDGER.read_text(),
                         ledger.render(ledger.build()))

    def test_the_main_entry_point_exits_zero(self) -> None:
        self.assertEqual(ledger.main([]), 0)
        self.assertEqual(ledger.main(["--summary"]), 0)

    def test_every_entry_carries_owner_fixture_and_evidence(self) -> None:
        document = ledger.load()
        self.assertEqual(ledger.check_required_fields(document), [])
        for entry in document["entries"]:
            self.assertTrue(entry["owner"] or entry["owner_reason"])
            self.assertTrue(entry["fixture"]["reference"]
                            or entry["fixture"]["reason"])
            self.assertTrue(entry["evidence"]["reference"]
                            or entry["evidence"]["reason"])

    def test_every_status_is_in_the_closed_vocabulary_or_unclassified(self) -> None:
        for entry in ledger.load()["entries"]:
            if entry["status"] is None:
                self.assertTrue(entry["status_reason"])
            else:
                self.assertIn(entry["status"], ledger.STATUSES)

    def test_the_write_leaves_no_staging_file_behind(self) -> None:
        directory = pathlib.Path(tempfile.mkdtemp())
        target = directory / "parity.json"
        ledger.write(ledger.build(), target)
        self.assertEqual([p.name for p in directory.iterdir()], ["parity.json"])
        self.assertEqual(target.read_text(), ledger.render(ledger.build()))


class StatusVocabularyTests(unittest.TestCase):
    def test_only_the_four_statuses_are_recognised(self) -> None:
        self.assertEqual(ledger.directive("Preserve exact fixtures"), "preserve")
        self.assertEqual(ledger.directive("**Replace** — rebuild"), "replace")
        self.assertEqual(ledger.directive("isolate and preserve"), "isolate")
        self.assertEqual(ledger.directive("Retire only by decision after use"),
                         "retire only by decision")

    def test_a_bare_retire_is_not_promoted_to_the_closed_spelling(self) -> None:
        self.assertIsNone(ledger.directive("Retire when convenient"))

    def test_an_unclassifiable_row_becomes_a_finding_not_a_guess(self) -> None:
        document = ledger.load()
        unclassified = [e for e in document["entries"] if e["status"] is None]
        self.assertEqual(
            [e["key"] for e in unclassified],
            ["codex-worker-guard-hooks-and-sandbox-launcher"])
        self.assertIn("Strengthen", unclassified[0]["status_reason"])
        kinds = [f["kind"] for f in document["findings"]
                 if f["subject"] == unclassified[0]["key"]]
        self.assertEqual(kinds, ["unclassified-status"])

    def test_a_status_outside_the_closed_set_is_refused_at_parse(self) -> None:
        document = ledger.load()
        document["entries"][0]["status"] = "retire"
        _, target = doctor(real_source(), json.dumps(document))
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.load(target)
        self.assertIn("outside the closed vocabulary", str(caught.exception))

    def test_a_null_status_without_a_reason_is_refused_at_parse(self) -> None:
        document = ledger.load()
        document["entries"][0]["status"] = None
        document["entries"][0]["status_reason"] = None
        _, target = doctor(real_source(), json.dumps(document))
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.load(target)
        self.assertIn("must record why", str(caught.exception))

    def test_an_evidence_state_outside_the_closed_set_is_refused(self) -> None:
        document = ledger.load()
        document["entries"][0]["evidence"]["state"] = "mostly"
        _, target = doctor(real_source(), json.dumps(document))
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.load(target)
        self.assertIn("evidence state", str(caught.exception))


class RequiredFieldTests(unittest.TestCase):
    def test_an_unevidenced_row_spelled_preserve_fails(self) -> None:
        text = replace_once(
            real_source(),
            "| Browser desktop notifications | SDK/dashboard notification "
            "service | **Replace** — rebuild to provide permission UX and "
            "server-side notification state | **none** — replace by decision "
            "2026-08-09 | no fixture |",
            "| Browser desktop notifications | SDK/dashboard notification "
            "service | Preserve permission UX and server-side notification "
            "state | **none** — not captured | no fixture |")
        source, target = doctor(text)
        document, problems = ledger.verify(source, target)
        self.assertTrue(
            any("spelled" in p and "preserve" in p for p in problems), problems)
        self.assertEqual(
            document["entries"][
                [e["key"] for e in document["entries"]].index(
                    "browser-desktop-notifications")]["status"], "preserve")

    def test_a_missing_owner_reason_fails(self) -> None:
        document = ledger.load()
        document["entries"][0]["owner"] = ""
        document["entries"][0]["owner_reason"] = None
        self.assertIn("owner is null with no reason",
                      " ".join(ledger.check_required_fields(document)))


class DecisionProvenanceTests(unittest.TestCase):
    def test_the_owner_decision_is_carried_as_cited_data(self) -> None:
        document = ledger.load()
        decision, = document["decisions"]
        self.assertEqual(decision["id"], "owner-decision-2026-08-09")
        self.assertEqual(decision["cites"]["document"],
                         "docs/product-plan/reference/feature-parity.md")
        self.assertEqual(decision["declared_counts"]["none"],
                         document["counts"]["covered_by_owner_decision"])
        self.assertEqual(ledger.check_decision_provenance(document), [])

    def test_a_cited_row_whose_own_cell_disagrees_is_refused(self) -> None:
        """The generator will not resolve the disagreement by reclassifying."""
        text = replace_once(
            real_source(),
            "| Screenshot proof | artifact pipeline | **Replace** — rebuild",
            "| Screenshot proof | artifact pipeline | Preserve — rebuild")
        source = doctor(text, "{}")[0]
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.build(source)
        self.assertIn("will not resolve that disagreement", str(caught.exception))

    def test_status_never_comes_from_an_absent_fixture(self) -> None:
        """Removing a fixture must not turn a preserve row into a replace row."""
        text = replace_once(
            real_source(),
            "| Client request portal | support/fleet integration | Preserve "
            "tenant fencing, safe lifecycle, context additions and relaunch "
            "after review | `support-inbox-query` (3) | pinned |",
            "| Client request portal | support/fleet integration | Preserve "
            "tenant fencing, safe lifecycle, context additions and relaunch "
            "after review | **none** — not captured | no fixture |")
        source, target = doctor(text)
        document = ledger.load(target)
        entry, = [e for e in document["entries"]
                  if e["key"] == "client-request-portal"]
        self.assertEqual(entry["status"], "preserve")
        self.assertIsNone(entry["decision_ref"])

    def test_the_declared_unevidenced_count_must_match_the_citing_rows(self) -> None:
        text = replace_once(real_source(),
                            "and 19 have no\nbehavioral evidence at all.**",
                            "and 18 have no\nbehavioral evidence at all.**")
        source, target = doctor(text)
        _, problems = ledger.verify(source, target)
        self.assertTrue(any("declares 18 unevidenced row(s) but 19" in p
                            for p in problems), problems)

    def test_a_declared_count_that_diverges_is_recorded_as_a_finding(self) -> None:
        document = ledger.load()
        divergences = {f["subject"]: f["detail"] for f in document["findings"]
                       if f["kind"] == "declared-count-divergence"}
        self.assertEqual(sorted(divergences), ["partial", "pinned"])
        self.assertIn("declares 15 pinned row(s); the tables measure 14",
                      divergences["pinned"])


class RowCoverageTests(unittest.TestCase):
    def test_every_named_surface_resolves_to_an_entry_or_a_declared_gap(self) -> None:
        document = ledger.load()
        self.assertEqual(ledger.check_row_coverage(document), [])
        gaps = [s["surface"] for s in document["surfaces"] if not s["entries"]]
        self.assertEqual(gaps, ["audits"])
        self.assertEqual(
            [f["subject"] for f in document["findings"]
             if f["kind"] == "surface-without-row"], ["audits"])

    def test_dropping_a_named_surface_entry_fails(self) -> None:
        document = ledger.load()
        document["entries"] = [e for e in document["entries"]
                               if e["key"] != "client-request-portal"]
        document["counts"]["table_rows"] -= 1
        problems = ledger.check_row_coverage(document)
        self.assertTrue(any("client portal" in p for p in problems), problems)
        self.assertTrue(any("silently removed" in p for p in problems), problems)

    def test_a_removed_parity_row_fails_the_forward_drift_check(self) -> None:
        source_text = real_source()
        row = [l for l in source_text.splitlines()
               if l.startswith("| Screenshot proof |")][0]
        source, target = doctor(source_text)
        source.write_text(replace_once(source_text, row + "\n", ""))
        _, problems = ledger.verify(source, target)
        self.assertTrue(any("does not match what" in p for p in problems),
                        problems)

    def test_an_edited_cell_fails_the_forward_drift_check(self) -> None:
        source_text = real_source()
        source, target = doctor(source_text)
        source.write_text(replace_once(source_text, "| Screenshot proof |",
                                       "| Screenshot evidence |"))
        _, problems = ledger.verify(source, target)
        self.assertTrue(any("does not match what" in p for p in problems),
                        problems)

    def test_the_row_count_is_cross_checked_against_the_prose(self) -> None:
        text = replace_once(real_source(), "Of 39 rows:", "Of 38 rows:")
        source, target = doctor(text)
        _, problems = ledger.verify(source, target)
        self.assertTrue(any("declares 38 parity rows but the tables measure 39"
                            in p for p in problems), problems)

    def test_an_independent_parser_agrees_on_the_row_count(self) -> None:
        self.assertEqual(ledger.check_parser_agreement(ledger.load()), [])


class ReverseDriftTests(unittest.TestCase):
    def test_an_invented_entry_fails_the_reverse_drift_check(self) -> None:
        document = ledger.load()
        invented = json.loads(json.dumps(document["entries"][0]))
        invented["key"] = "invented-capability"
        invented["capability"] = "Invented capability"
        document["entries"].append(invented)
        problems = ledger.check_drift_reverse(document)
        self.assertTrue(any("invented-capability" in p for p in problems),
                        problems)

    def test_an_entry_whose_cells_were_edited_fails_the_reverse_check(self) -> None:
        document = ledger.load()
        document["entries"][0]["owner"] = "somebody else"
        problems = ledger.check_drift_reverse(document)
        self.assertTrue(any("does not carry the cells" in p for p in problems),
                        problems)

    def test_a_citation_that_stops_pointing_at_the_decision_fails(self) -> None:
        document = ledger.load()
        document["decisions"][0]["cites"]["line"] = 3
        problems = ledger.check_drift_reverse(document)
        self.assertTrue(any("does not carry the heading" in p
                            for p in problems), problems)

    def test_the_reverse_check_passes_on_the_checked_in_ledger(self) -> None:
        self.assertEqual(ledger.check_drift_reverse(ledger.load()), [])


class PublicationHygieneTests(unittest.TestCase):
    def test_the_generated_ledger_carries_no_fingerprinted_value(self) -> None:
        self.assertEqual(
            ledger.check_publication_hygiene(ledger.LEDGER.read_text()), [])

    def test_a_third_party_product_name_in_the_ledger_is_refused(self) -> None:
        vectors = {v["rule_id"]: base64.b64decode(v["value_base64"]).decode()
                   for v in json.loads(
                       (pathlib.Path(scrub.__file__).parent
                        / "synthetic-vectors.json").read_text())["vectors"]}
        poisoned = ledger.LEDGER.read_text().replace(
            "Screenshot proof",
            f"Screenshot proof compared with "
            f"{vectors['synthetic-third-party-product']}", 1)
        problems = ledger.check_publication_hygiene(poisoned)
        self.assertTrue(
            any("synthetic-third-party-product" in p for p in problems),
            problems)

    def test_a_private_identifier_in_the_ledger_is_refused(self) -> None:
        vectors = {v["rule_id"]: base64.b64decode(v["value_base64"]).decode()
                   for v in json.loads(
                       (pathlib.Path(scrub.__file__).parent
                        / "synthetic-vectors.json").read_text())["vectors"]}
        poisoned = ledger.LEDGER.read_text().replace(
            "Screenshot proof", vectors["synthetic-legacy-name"], 1)
        problems = ledger.check_publication_hygiene(poisoned)
        self.assertTrue(any("synthetic-legacy-name" in p for p in problems),
                        problems)

    def test_no_finding_ever_prints_the_matched_value(self) -> None:
        vectors = {v["rule_id"]: base64.b64decode(v["value_base64"]).decode()
                   for v in json.loads(
                       (pathlib.Path(scrub.__file__).parent
                        / "synthetic-vectors.json").read_text())["vectors"]}
        value = vectors["synthetic-third-party-product"]
        for problem in ledger.check_publication_hygiene(
                ledger.LEDGER.read_text() + value):
            self.assertNotIn(value, problem)


class MissingLedgerTests(unittest.TestCase):
    def test_a_missing_ledger_is_refused_rather_than_treated_as_empty(self) -> None:
        directory = pathlib.Path(tempfile.mkdtemp())
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.verify(ledger.SOURCE, directory / "absent.json")
        self.assertIn("is missing", str(caught.exception))

    def test_a_source_without_the_owner_decision_is_refused(self) -> None:
        text = replace_once(real_source(), "Of 39 rows: ", "Of some rows: ")
        source = doctor(text, "{}")[0]
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.build(source)
        self.assertIn("will not re-derive them", str(caught.exception))


if __name__ == "__main__":                                    # pragma: no cover
    unittest.main()
