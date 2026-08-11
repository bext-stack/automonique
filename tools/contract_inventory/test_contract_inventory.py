#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Break every rule the inventory claims to enforce, and watch it fail.

    python3 -m unittest tools.contract_inventory.test_contract_inventory

Each negative control sits beside a positive one. A checker that has only ever
passed is a checker nobody has measured, and a fixture that restates the value
it is checking proves only that the implementation equals itself — so the
forbidden legacy token below is recovered from the sanctioned inventory by its
fingerprint rather than written down here.

The mutations happen in a temporary copy of `docs/product-plan/`, never in the
tree, so a failing test cannot leave a source edited.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.contract_inventory import build, check  # noqa: E402
from tools.contract_inventory.sources import SourceError  # noqa: E402

sys.path.insert(0, str(_REPO / "plan"))
import check as plan_check  # noqa: E402


def failures(root: pathlib.Path) -> list[str]:
    checker = check.Checker(root)
    checker.run()
    return checker.problems


def says(problems: list[str], fragment: str) -> bool:
    return any(fragment in problem for problem in problems)


class InventoryFixture(unittest.TestCase):
    """A throwaway repository holding the real sources and a fresh inventory."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        shutil.copytree(_REPO / "docs", self.root / "docs")
        (self.root / "AGENTS.md").write_text("stand-in for an existing repository file\n")
        for relative, text in build.Builder(self.root).build().items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.inventory = self.root / build.INVENTORY

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------

    def document(self) -> dict:
        return json.loads(self.inventory.read_text())

    def rewrite(self, document: dict) -> None:
        self.inventory.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")

    def entry(self, document: dict, prefix: str) -> dict:
        for entry in document["entries"]:
            if entry["id"].startswith(prefix):
                return entry
        raise AssertionError(f"no entry starting {prefix!r}")

    def source(self, name: str) -> pathlib.Path:
        return self.root / "docs/product-plan/reference" / name


class TestPositiveControls(InventoryFixture):
    def test_a_freshly_generated_inventory_verifies(self):
        self.assertEqual([], failures(self.root))

    def test_the_checked_in_inventory_verifies_against_the_real_sources(self):
        self.assertEqual([], failures(_REPO))

    def test_regenerating_is_byte_identical(self):
        first = build.Builder(self.root).build()
        second = build.Builder(self.root).build()
        self.assertEqual(first, second)
        for relative, text in first.items():
            self.assertEqual((self.root / relative).read_text(), text)

    def test_the_seven_classes_are_all_represented(self):
        per_class = self.document()["counts"]["per_class"]
        self.assertEqual(sorted(per_class), sorted(build.SURFACE_CLASSES))
        self.assertTrue(all(count > 0 for count in per_class.values()), per_class)


class TestDrift(InventoryFixture):
    def test_a_source_that_gains_a_row_makes_the_checked_in_copy_stale(self):
        path = self.source("legacy-inventory.md")
        text = path.read_text()
        path.write_text(text.replace(
            "| Terminal | `/api/term`,",
            "| Invented | `/api/invented` |\n| Terminal | `/api/term`,"))
        problems = failures(self.root)
        self.assertTrue(says(problems, "is not what its sources generate"), problems)
        path.write_text(text)
        self.assertEqual([], failures(self.root))

    def test_a_source_that_loses_a_row_makes_the_checked_in_copy_stale(self):
        path = self.source("legacy-inventory.md")
        text = path.read_text()
        path.write_text(text.replace("| Ignored | `/api/ignored/remove` |\n", ""))
        problems = failures(self.root)
        self.assertTrue(says(problems, "is not what its sources generate"), problems)
        path.write_text(text)
        self.assertEqual([], failures(self.root))

    def test_a_changed_source_invalidates_the_recorded_digest(self):
        path = self.source("migration-plan.md")
        text = path.read_text()
        path.write_text(text + "\nA sentence nobody generated from.\n")
        problems = failures(self.root)
        self.assertTrue(says(problems, "has changed since the inventory recorded its digest"),
                        problems)
        path.write_text(text)
        self.assertEqual([], failures(self.root))

    def test_a_file_nothing_generates_is_refused(self):
        stray = self.root / build.OUTPUT_DIR / "notes.md"
        stray.write_text("hand-written\n")
        problems = failures(self.root)
        self.assertTrue(says(problems, "carries file(s) nothing generates"), problems)
        stray.unlink()
        self.assertEqual([], failures(self.root))

    def test_a_deleted_artifact_is_refused(self):
        path = self.root / build.COVERAGE
        text = path.read_text()
        path.unlink()
        problems = failures(self.root)
        self.assertTrue(says(problems, "is missing; a fresh build produces it"), problems)
        path.write_text(text)
        self.assertEqual([], failures(self.root))


class TestEntryIntegrity(InventoryFixture):
    def test_an_entry_the_source_does_not_evidence_is_refused(self):
        document = self.document()
        invented = copy.deepcopy(document["entries"][0])
        invented["id"] = "dashboard-route:/api/invented"
        invented["name"] = "/api/invented"
        invented["citations"] = [{
            "source": "legacy-inventory",
            "path": "docs/product-plan/reference/legacy-inventory.md",
            "section": "## Dashboard API",
            "quote": "`/api/invented`",
        }]
        document["entries"].append(invented)
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "does not say '`/api/invented`'"), problems)

    def test_an_invented_target_owner_is_refused(self):
        document = self.document()
        entry = self.entry(document, "dashboard-route:")
        entry["owner"] = "automonique-invented"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is not a destination any permitted source names"),
                        problems)

    def test_an_owner_outside_its_porting_map_row_is_refused(self):
        document = self.document()
        entry = self.entry(document, "dashboard-route:")
        entry["owner"] = "automonique-lab"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "does not send its area to automonique-lab"), problems)

    def test_a_null_owner_without_a_reason_is_refused(self):
        document = self.document()
        entry = next(e for e in document["entries"] if e["owner"] is None)
        entry["owner_reason"] = ""
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "a null owner must carry a reason"), problems)

    def test_an_uncited_entry_is_refused(self):
        document = self.document()
        entry = self.entry(document, "command:")
        entry["citations"] = []
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "an entry without a citation is invalid"), problems)

    def test_a_class_outside_the_seven_is_refused(self):
        document = self.document()
        entry = self.entry(document, "command:")
        entry["surface_class"] = "policy decision"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is outside the seven"), problems)

    def test_a_duplicate_entry_id_is_refused(self):
        document = self.document()
        document["entries"].append(copy.deepcopy(document["entries"][0]))
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "duplicate entry id"), problems)


class TestFixturePlans(InventoryFixture):
    def test_a_claimed_capture_that_does_not_exist_is_refused(self):
        document = self.document()
        entry = self.entry(document, "command:")
        entry["fixture_plan"]["corpus_status"] = "present"
        entry["fixture_plan"]["corpus_path"] = "plan/fixtures/commands.json"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "claims a sanitized capture at"), problems)

        # Positive control: the same claim naming a file that exists passes the
        # rule, so the rule is about existence and not about the word "present".
        entry["fixture_plan"]["corpus_path"] = "AGENTS.md"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertFalse(says(problems, "claims a sanitized capture at"), problems)

    def test_a_blocked_class_cannot_claim_to_be_unblocked(self):
        document = self.document()
        entry = next(e for e in document["entries"]
                     if e["fixture_plan"]["class"] == "effect-recording")
        entry["fixture_plan"]["blocked"] = False
        entry["fixture_plan"]["blocking_reason"] = None
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is blocked by construction"), problems)

    def test_a_blocked_plan_must_name_its_blockers(self):
        document = self.document()
        entry = next(e for e in document["entries"] if e["fixture_plan"]["blocked"])
        entry["fixture_plan"]["blocking_reason"] = {"blockers": [], "detail": "because"}
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "a blocked plan must name its blockers"), problems)

    def test_a_fixture_plan_without_observable_outputs_is_refused(self):
        document = self.document()
        entry = self.entry(document, "durable-table:")
        entry["fixture_plan"]["outputs"] = ""
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "must name its observable outputs"), problems)


class TestFindingsAndCounts(InventoryFixture):
    def test_an_unclassified_finding_without_a_reason_is_refused(self):
        document = self.document()
        document["unclassified"][0]["why_no_class"] = ""
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "must say why no class fits"), problems)

    def test_a_gap_kind_outside_the_set_is_refused(self):
        document = self.document()
        document["gaps"][0]["kind"] = "probably-fine"
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is outside the closed set"), problems)

    def test_a_gap_that_does_not_say_what_would_close_it_is_refused(self):
        document = self.document()
        document["gaps"][0]["needed_to_close"] = ""
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "a gap must say what would close it"), problems)

    def test_counts_that_disagree_with_the_entries_are_refused(self):
        document = self.document()
        document["counts"]["entries"] += 1
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is not the"), problems)

    def test_a_widened_vocabulary_is_refused(self):
        document = self.document()
        document["vocabulary"]["surface_classes"].append("miscellaneous")
        self.rewrite(document)
        problems = failures(self.root)
        self.assertTrue(says(problems, "is not the closed set the generator enforces"), problems)


class TestSourceReconciliation(InventoryFixture):
    def test_a_count_the_source_states_is_reconciled_against_its_enumeration(self):
        gaps = {gap["id"] for gap in self.document()["gaps"]}
        self.assertIn("command-count-discrepancy", gaps)

        # Positive control: make the stated count match the enumeration and the
        # gap disappears, which is what proves the gap was measured.
        path = self.source("legacy-inventory.md")
        text = path.read_text()
        path.write_text(text.replace("**Commands (21):**", "**Commands (19):**"))
        rebuilt = json.loads(build.Builder(self.root).build()[build.INVENTORY])
        self.assertNotIn("command-count-discrepancy", {g["id"] for g in rebuilt["gaps"]})
        path.write_text(text)

    def test_a_parity_row_with_no_classification_refuses_the_build(self):
        path = self.source("feature-parity.md")
        text = path.read_text()
        path.write_text(text.replace(
            "| Multi-ticket split |",
            "| Invented capability | invented owner | invented decision | **none** | none |\n"
            "| Multi-ticket split |"))
        with self.assertRaises(build.InventoryError) as caught:
            build.Builder(self.root).build()
        self.assertIn("has no classification in rules.toml", str(caught.exception))
        path.write_text(text)
        self.assertEqual([], failures(self.root))

    def test_the_two_documents_must_agree_on_the_parity_row_count(self):
        path = self.source("legacy-inventory.md")
        text = path.read_text()
        path.write_text(text.replace(
            "| Ops-command proposal classification | `privileged-actions` | 3 |\n", ""))
        problems = failures(self.root)
        self.assertTrue(says(problems, "the two documents disagree"), problems)
        path.write_text(text)
        self.assertEqual([], failures(self.root))

    def test_an_ambiguous_heading_is_refused_rather_than_answered(self):
        with self.assertRaises(SourceError) as caught:
            build.Builder(self.root).docs.section("migration-plan", "### Work")
        self.assertIn("ambiguous", str(caught.exception))


class TestCleanRoom(InventoryFixture):
    def forbidden_word(self) -> str:
        """Recover the token from the one file permitted to carry it.

        Never written down here: the rule is a fingerprint in `plan/check.py`,
        and a fixture that copied the value would both violate the rule it
        tests and stop meaning anything if the rule changed.
        """
        lengths = {rule["length"] for rule in plan_check.LEGACY_TOKEN_FINGERPRINTS}
        digests = {rule["digest"] for rule in plan_check.LEGACY_TOKEN_FINGERPRINTS}
        text = (self.root / "docs/product-plan/reference/legacy-inventory.md").read_text()
        for word in plan_check.WORD.findall(text):
            if len(word) in lengths and \
                    hashlib.sha256(word.lower().encode()).hexdigest() in digests:
                return word
        raise AssertionError("the sanctioned inventory no longer carries the token the "
                             "location rule is about")

    def test_a_legacy_identifier_cannot_reach_a_generated_file(self):
        word = self.forbidden_word()
        with self.assertRaises(build.InventoryError) as caught:
            build.refuse_legacy_tokens("plan/inventory/contracts/inventory.json",
                                       f"a quotation carrying {word}_DB")
        self.assertIn("legacy identifier", str(caught.exception))
        self.assertNotIn(word, str(caught.exception))

    def test_neutral_text_is_not_refused(self):
        build.refuse_legacy_tokens("plan/inventory/contracts/inventory.json",
                                   "the predecessor's mandatory database override")

    def test_the_generated_files_carry_no_legacy_identifier(self):
        for relative in check.EXPECTED_FILES:
            build.refuse_legacy_tokens(relative, (_REPO / relative).read_text())

    def test_only_the_four_permitted_sources_are_readable(self):
        with self.assertRaises(SourceError) as caught:
            build.Builder(self.root).docs.text("legacy-source-tree")
        self.assertIn("not a permitted source", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
