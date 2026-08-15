#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The known-deviation registry: closed vocabularies, drift, and refusal.

Two properties carry the weight. The vocabularies here must be the ones
`automonique_protocol::parity` defines — an entry the comparator can never match
is worse than no entry, because it reads as an explanation and is not one — so
those are checked against the Rust source rather than against a copy. And the
ledger must fail whether it gained a row or lost one, because the registry ships
empty and the failure nobody would notice is a row appearing.
"""

from __future__ import annotations

import pathlib
import re
import tempfile
import unittest

from tools.parity import deviations
from tools.scrub import scan as scrub

RUST_PARITY = deviations.ROOT / "rust/crates/automonique-protocol/src/parity.rs"

HEADER = "| " + " | ".join(deviations.COLUMNS) + " |"
SEPARATOR = "|" + "|".join(["---"] * len(deviations.COLUMNS)) + "|"


def document(rows: list[str], *, heading: str = "Registered deviations") -> str:
    body = "\n".join(rows)
    return (
        "# Known deviations\n\n"
        "Prose above the table.\n\n"
        f"## {heading}\n\n"
        f"{HEADER}\n{SEPARATOR}\n"
        f"{body}\n" if body else
        "# Known deviations\n\n"
        "Prose above the table.\n\n"
        f"## {heading}\n\n"
        f"{HEADER}\n{SEPARATOR}\n"
    )


def row(
    identifier: str = "dev-0001",
    scope: str = "slack-ticket-routing",
    kind: str = "slack-thread-reply",
    field: str = "rendered_message",
    relation: str = "value_differs",
    reason: str = "deliberate-improvement",
    owner: str = "owner",
    date: str = "2026-08-15",
    rationale: str = "the candidate names the gate explicitly",
) -> str:
    return (
        f"| {identifier} | {scope} | {kind} | {field} | {relation} | "
        f"{reason} | {owner} | {date} | {rationale} |"
    )


def source_file(case: unittest.TestCase, text: str) -> pathlib.Path:
    directory = pathlib.Path(case.enterContext(tempfile.TemporaryDirectory()))
    path = directory / "known-deviations.md"
    path.write_text(text)
    return path


class VocabularyTest(unittest.TestCase):
    """The closed sets here are the ones the Rust comparator matches against."""

    def rust_variants(self, enum_name: str) -> list[str]:
        text = RUST_PARITY.read_text()
        start = text.index(f"impl {enum_name} {{")
        segment = text[start : text.index("\n}\n", start)]
        body_start = segment.index("pub const fn as_str(")
        body = segment[body_start : segment.index("    }", body_start)]
        return re.findall(r'=> "([a-z0-9_.\-]+)"', body)

    def test_action_kinds_match_the_rust_enum(self) -> None:
        self.assertEqual(
            sorted(deviations.ACTION_KINDS), sorted(self.rust_variants("ActionKind"))
        )

    def test_fields_match_the_rust_enum(self) -> None:
        self.assertEqual(
            sorted(deviations.FIELDS), sorted(self.rust_variants("ComparisonField"))
        )

    def test_relations_match_the_rust_enum(self) -> None:
        self.assertEqual(
            sorted(deviations.RELATIONS), sorted(self.rust_variants("Relation"))
        )

    def test_reasons_match_the_rust_enum(self) -> None:
        self.assertEqual(
            sorted(deviations.REASONS), sorted(self.rust_variants("DeviationReason"))
        )

    def test_masked_fields_are_the_ones_the_oracle_registers(self) -> None:
        registry = (deviations.ROOT / "tools/oracle/fields.json").read_text()
        masked = re.findall(
            r'"id": "([a-z_]+)",\s*"area": "[a-z_]+",\s*"masked": true', registry
        )
        self.assertEqual(sorted(deviations.MASKED_FIELDS), sorted(masked))


class ParseTest(unittest.TestCase):
    def build(self, text: str) -> dict:
        return deviations.build(source_file(self, text))

    def test_an_empty_registry_derives_an_empty_ledger(self) -> None:
        built = self.build(document([]))
        self.assertEqual(built["entries"], [])
        self.assertEqual(built["counts"]["entries"], 0)

    def test_one_row_derives_one_entry(self) -> None:
        built = self.build(document([row()]))
        self.assertEqual(len(built["entries"]), 1)
        entry = built["entries"][0]
        self.assertEqual(entry["id"], "dev-0001")
        self.assertEqual(entry["field"], "rendered_message")
        self.assertEqual(entry["reason"], "deliberate-improvement")

    def test_entries_sort_by_identifier_not_by_source_order(self) -> None:
        built = self.build(
            document([row(identifier="dev-0002"), row(identifier="dev-0001")])
        )
        self.assertEqual(
            [entry["id"] for entry in built["entries"]], ["dev-0001", "dev-0002"]
        )

    def test_a_value_outside_a_closed_vocabulary_is_refused(self) -> None:
        for override in [
            {"kind": "slack-thread-reply-2"},
            {"field": "rendered_messages"},
            {"relation": "value_differ"},
            {"reason": "seemed-fine"},
        ]:
            with self.subTest(**override), self.assertRaises(deviations.DeviationError):
                self.build(document([row(**override)]))

    def test_a_malformed_identifier_scope_or_date_is_refused(self) -> None:
        for override in [
            {"identifier": "Dev-0001"},
            {"identifier": "d"},
            {"scope": "Slack Ticket Routing"},
            {"date": "15-08-2026"},
            {"owner": ""},
        ]:
            with self.subTest(**override), self.assertRaises(deviations.DeviationError):
                self.build(document([row(**override)]))

    def test_a_repeated_identifier_is_refused(self) -> None:
        with self.assertRaises(deviations.DeviationError):
            self.build(document([row(), row(scope="telegram-conversation")]))

    def test_a_second_registry_heading_is_refused(self) -> None:
        text = document([row()]) + "\n## Registered deviations\n\nsecond table\n"
        with self.assertRaises(deviations.DeviationError):
            self.build(text)

    def test_an_absent_registry_heading_is_refused(self) -> None:
        with self.assertRaises(deviations.DeviationError):
            self.build(document([row()], heading="Deviations"))

    def test_a_table_with_other_columns_is_refused(self) -> None:
        text = (
            "# Known deviations\n\n## Registered deviations\n\n"
            "| Id | Scope |\n|---|---|\n| dev-0001 | slack |\n"
        )
        with self.assertRaises(deviations.DeviationError):
            self.build(text)

    def test_a_row_with_the_wrong_cell_count_is_refused(self) -> None:
        text = document([row()]).replace(
            " | the candidate names the gate explicitly |", " |"
        )
        with self.assertRaises(deviations.DeviationError):
            self.build(text)


class FindingTest(unittest.TestCase):
    def build(self, text: str) -> dict:
        return deviations.build(source_file(self, text))

    def test_registering_a_masked_field_is_a_finding_not_a_refusal(self) -> None:
        # It is a well-formed row that explains nothing, which is a property of
        # the document to report rather than a parse error to raise.
        built = self.build(document([row(field="receipt_timestamp")]))
        self.assertEqual(len(built["entries"]), 1)
        kinds = [finding["kind"] for finding in built["findings"]]
        self.assertIn("masked-field-registered", kinds)

    def test_a_row_with_no_rationale_is_a_finding(self) -> None:
        built = self.build(document([row(rationale="")]))
        self.assertIn(
            "deviation-without-rationale",
            [finding["kind"] for finding in built["findings"]],
        )

    def test_every_finding_kind_is_in_the_closed_set(self) -> None:
        built = self.build(document([row(field="receipt_timestamp", rationale="")]))
        for finding in built["findings"]:
            self.assertIn(finding["kind"], deviations.FINDING_KINDS)


class DriftTest(unittest.TestCase):
    def paths(self, text: str) -> tuple[pathlib.Path, pathlib.Path]:
        source = source_file(self, text)
        ledger = source.parent / "deviations.json"
        deviations.write(deviations.build(source), ledger)
        return source, ledger

    def test_a_freshly_written_ledger_verifies(self) -> None:
        source, ledger = self.paths(document([row()]))
        _, problems = deviations.verify(source, ledger)
        self.assertEqual(problems, [])

    def test_a_ledger_that_gained_a_row_by_hand_fails(self) -> None:
        source, ledger = self.paths(document([]))
        text = ledger.read_text().replace(
            '"entries": [],',
            '"entries": [{"action_kind": "no-action", "date": "2026-08-15",'
            ' "field": "receipt", "id": "smuggled", "owner": "nobody",'
            ' "rationale": "", "reason": "bug-fix", "relation": "value_differs",'
            ' "scope": "slack-ticket-routing"}],',
        )
        ledger.write_text(text)
        _, problems = deviations.verify(source, ledger)
        self.assertTrue(problems)

    def test_a_ledger_that_lost_a_row_by_hand_fails(self) -> None:
        source, ledger = self.paths(document([row()]))
        ledger.write_text(ledger.read_text().replace('"dev-0001"', '"dev-0002"'))
        _, problems = deviations.verify(source, ledger)
        self.assertTrue(problems)

    def test_a_widened_vocabulary_in_the_ledger_fails(self) -> None:
        source, ledger = self.paths(document([]))
        ledger.write_text(
            ledger.read_text().replace(
                '"bug-fix",\n  "deliberate-improvement"',
                '"bug-fix",\n  "deliberate-improvement",\n  "seemed-fine"',
            )
        )
        _, problems = deviations.verify(source, ledger)
        self.assertTrue(problems)

    def test_an_absent_ledger_names_the_command_that_writes_it(self) -> None:
        source = source_file(self, document([]))
        with self.assertRaises(deviations.DeviationError) as raised:
            deviations.verify(source, source.parent / "absent.json")
        self.assertIn("--write", str(raised.exception))

    def test_a_ledger_that_is_not_this_schema_is_refused(self) -> None:
        source, ledger = self.paths(document([]))
        ledger.write_text('{"schema": "something.else/v1"}')
        with self.assertRaises(deviations.DeviationError):
            deviations.verify(source, ledger)


class HygieneTest(unittest.TestCase):
    def test_a_fingerprinted_value_in_the_ledger_is_a_problem(self) -> None:
        import base64
        import json

        vectors = {
            entry["rule_id"]: base64.b64decode(
                entry["value_base64"], validate=True
            ).decode("utf-8")
            for entry in json.loads(
                pathlib.Path(scrub.__file__)
                .with_name("synthetic-vectors.json")
                .read_text()
            )["vectors"]
        }
        leak = vectors["synthetic-internal-product"]
        problems = deviations.check_publication_hygiene(
            f'{{"rationale": "{leak}"}}', deviations.LEDGER
        )
        self.assertTrue(problems)
        self.assertNotIn(leak, " ".join(problems))


class CheckedInRegistryTest(unittest.TestCase):
    def test_the_checked_in_ledger_matches_its_source(self) -> None:
        _, problems = deviations.verify()
        self.assertEqual(problems, [])

    def test_the_checked_in_registry_ships_empty_and_says_so(self) -> None:
        document, _ = deviations.verify()
        self.assertEqual(document["counts"]["entries"], 0)
        self.assertIn(
            "This table is empty",
            deviations.SOURCE.read_text(),
            "an empty registry must state that it is a measurement",
        )

    def test_the_source_enumerates_every_closed_vocabulary(self) -> None:
        text = deviations.SOURCE.read_text()
        for admitted in (
            deviations.ACTION_KINDS
            + deviations.FIELDS
            + deviations.RELATIONS
            + deviations.REASONS
        ):
            with self.subTest(value=admitted):
                self.assertIn(f"`{admitted}`", text)

    def test_the_entry_point_exits_zero_on_the_checked_in_tree(self) -> None:
        self.assertEqual(deviations.main([]), 0)


if __name__ == "__main__":
    unittest.main()
