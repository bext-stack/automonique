#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Contract tests for the canonical R0-09 restore-dependency consumer."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import dependencies as dep  # noqa: E402
from tools.surface_inventory import render as surface_render  # noqa: E402


class CanonicalDependencyConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.encoded = dep.CANONICAL_INVENTORY.read_bytes()
        self.source = dep.CANONICAL_SOURCE.read_bytes()
        self.document = json.loads(self.encoded)

    @staticmethod
    def encode(document: object) -> bytes:
        return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()

    def assert_refused(
        self, expected: dep.Refusal, encoded: bytes, *, source: bytes | None = None
    ) -> None:
        with self.assertRaises(dep.InventoryRefused) as caught:
            dep.validate_inventory(
                encoded,
                source_bytes=self.source if source is None else source,
            )
        self.assertIs(caught.exception.refusal, expected)

    def test_real_r0_09_producer_is_consumed_and_independently_rendered(self) -> None:
        source_document = json.loads(self.source)
        self.assertEqual(
            self.encoded,
            surface_render.render_restore(source_document, self.source),
        )
        report = dep.consume()
        self.assertTrue(report["inventory_present"])
        self.assertIsNone(report["refused"])
        self.assertEqual(report["consumed_entries"], len(self.document["order"]))
        self.assertEqual(report["objectives"], self.document["objectives"])
        self.assertEqual(report["excluded"], self.document["excluded"])
        codes = [finding["code"] for finding in report["findings"]]
        self.assertEqual(
            codes.count(dep.DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY.value),
            8,
        )
        self.assertEqual(
            codes.count(dep.DependencyFinding.DEPENDENCY_NOT_EXERCISED.value),
            20,
        )

    def test_a_changed_objective_threshold_cannot_pose_as_the_producer(self) -> None:
        changed = json.loads(self.encoded)
        changed["objectives"][0]["value"] += 1
        self.assert_refused(dep.Refusal.RENDER_MISMATCH, self.encode(changed))

    def test_positions_must_be_contiguous_and_match_array_order(self) -> None:
        changed = json.loads(self.encoded)
        changed["order"][1]["position"] = changed["order"][0]["position"]
        self.assert_refused(dep.Refusal.BAD_ORDER, self.encode(changed))

    def test_every_reference_names_an_earlier_order_entry(self) -> None:
        changed = json.loads(self.encoded)
        dependent = next(entry for entry in changed["order"] if entry["requires"])
        dependent["requires"][0] = dependent["id"]
        self.assert_refused(dep.Refusal.BAD_ORDER, self.encode(changed))

    def test_only_the_canonical_inventory_path_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            alternate = pathlib.Path(directory) / dep.CANONICAL_INVENTORY.name
            alternate.write_bytes(self.encoded)
            report = dep.consume(alternate)
        self.assertEqual(report["refused"]["code"], dep.Refusal.PATH_MISMATCH.value)
        self.assertEqual(report["consumed_entries"], 0)

    def test_a_symlink_alias_to_the_canonical_file_is_not_the_canonical_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            alias = pathlib.Path(directory) / dep.CANONICAL_INVENTORY.name
            alias.symlink_to(dep.CANONICAL_INVENTORY)
            report = dep.consume(alias)
        self.assertEqual(report["refused"]["code"], dep.Refusal.PATH_MISMATCH.value)
        self.assertEqual(report["consumed_entries"], 0)

    def test_the_embedded_source_path_is_exact(self) -> None:
        changed = json.loads(self.encoded)
        changed["source"]["path"] += ".moved"
        self.assert_refused(dep.Refusal.SOURCE_MISMATCH, self.encode(changed))

    def test_actual_source_byte_drift_is_refused_by_digest(self) -> None:
        drifted_source = self.source + b" "
        self.assert_refused(
            dep.Refusal.SOURCE_DIGEST_MISMATCH,
            self.encoded,
            source=drifted_source,
        )

    def test_closed_shapes_types_and_enums_each_have_a_negative_control(self) -> None:
        cases = []

        unknown_key = json.loads(self.encoded)
        unknown_key["unexpected"] = None
        cases.append((dep.Refusal.UNKNOWN_KEY, unknown_key))

        wrong_type = json.loads(self.encoded)
        wrong_type["objectives"][0]["summary"] = []
        cases.append((dep.Refusal.TYPE_MISMATCH, wrong_type))

        wrong_class = json.loads(self.encoded)
        wrong_class["order"][0]["class"] += "-unknown"
        cases.append((dep.Refusal.UNKNOWN_ENUM_VALUE, wrong_class))

        wrong_verification = json.loads(self.encoded)
        wrong_verification["order"][0]["verification"] += "-unknown"
        cases.append((dep.Refusal.UNKNOWN_ENUM_VALUE, wrong_verification))

        wrong_unit = json.loads(self.encoded)
        wrong_unit["objectives"][0]["unit"] += "s"
        cases.append((dep.Refusal.UNKNOWN_ENUM_VALUE, wrong_unit))

        wrong_excluded = json.loads(self.encoded)
        wrong_excluded["excluded"][0]["extra"] = True
        cases.append((dep.Refusal.UNKNOWN_KEY, wrong_excluded))

        wrong_work_item = json.loads(self.encoded)
        wrong_work_item["work_item"] += "-other"
        cases.append((dep.Refusal.WRONG_WORK_ITEM, wrong_work_item))

        wrong_consumer = json.loads(self.encoded)
        wrong_consumer["consumer"] += "-other"
        cases.append((dep.Refusal.WRONG_CONSUMER, wrong_consumer))

        for expected, document in cases:
            with self.subTest(expected=expected.value):
                self.assert_refused(expected, self.encode(document))


if __name__ == "__main__":
    unittest.main()
