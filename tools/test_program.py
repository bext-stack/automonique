#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest

from tools import program
from tools import runtime_topology


class ProgramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = program.build_document()
        self.committed = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())

    def test_coverage_and_authority_match(self) -> None:
        graph = program.read_graph(program.DEFAULT_GRAPH)
        self.assertEqual(375, len(self.committed["items"]))
        self.assertEqual(graph["item_count"], len(self.committed["items"]))
        by_id = {item["id"]: item for item in self.committed["items"]}
        for source in graph["item"]:
            actual = by_id[source["id"]]
            self.assertEqual(source.get("depends_on", []), actual["depends_on"])
            self.assertEqual(source.get("blocked_by_gates", []), actual["blocked_by_gates"])
            self.assertEqual(source["licence"], actual["licence"])
            self.assertEqual(source.get("allowed_paths", []), actual["allowed_paths"])
            self.assertEqual(source["status"], actual["status"])

    def test_unspecified_item_is_not_runnable(self) -> None:
        item = next(item for item in self.committed["items"] if item["id"] == "R0-01")
        self.assertIsNone(item["contract"])
        self.assertFalse(item["runnable"])

    def test_generation_is_byte_reproducible(self) -> None:
        self.assertEqual(program.generate(), program.generate())
        self.assertEqual(program.DEFAULT_PROGRAM.read_bytes(), program.generate())

    def test_source_node_removal_is_named(self) -> None:
        changed = copy.deepcopy(self.expected)
        removed = changed["items"].pop()
        errors = program.semantic_errors(changed, self.committed)
        self.assertIn(f"generated-only item {removed['id']}", errors)

    def test_source_edge_removal_is_named(self) -> None:
        changed = copy.deepcopy(self.expected)
        item = next(item for item in changed["items"] if item["depends_on"])
        item["depends_on"] = []
        errors = program.semantic_errors(changed, self.committed)
        self.assertIn(f"item {item['id']} field depends_on differs from source", errors)

    def test_generated_node_invention_is_named(self) -> None:
        changed = copy.deepcopy(self.committed)
        invented = copy.deepcopy(changed["items"][0])
        invented["id"] = "R99-99"
        changed["items"].append(invented)
        errors = program.semantic_errors(self.expected, changed)
        self.assertIn("generated-only item R99-99", errors)

    def test_cli_verify_rejects_changed_program(self) -> None:
        changed = copy.deepcopy(self.committed)
        changed["items"][0]["licence"] = "Apache-2.0"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "program.yaml"
            path.write_bytes(program.render_document(changed))
            _, errors = program.verify(program.DEFAULT_GRAPH, program.DEFAULT_CONTRACTS, path)
        self.assertIn(
            f"item {changed['items'][0]['id']} field licence differs from source",
            errors,
        )

    def test_rendered_body_is_json_compatible_yaml(self) -> None:
        body = program.generate().decode().split("\n", 1)[1]
        self.assertEqual(program.SCHEMA, json.loads(body)["schema"])

    def test_schema_declares_exact_item_fields(self) -> None:
        schema_path = program.ROOT / ".automonique/dev/program.schema.json"
        schema = json.loads(schema_path.read_text())
        item = schema["$defs"]["item"]
        self.assertFalse(item["additionalProperties"])
        self.assertEqual(set(program.PROGRAM_FIELDS), set(item["required"]))
        self.assertEqual(set(program.PROGRAM_FIELDS), set(item["properties"]))


class RuntimeTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.decision = runtime_topology.load_json(runtime_topology.DEFAULT_DECISION)
        self.evidence = runtime_topology.load_json(runtime_topology.DEFAULT_EVIDENCE)
        self.digest = runtime_topology.digest(runtime_topology.DEFAULT_EVIDENCE)

    def errors(self, decision: dict) -> list[str]:
        return runtime_topology.semantic_errors(decision, self.evidence, self.digest)

    def test_committed_runtime_topology_is_valid(self) -> None:
        self.assertEqual([], runtime_topology.verify())

    def test_source_evidence_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.decision)
        changed["source_evidence"]["sha256"] = "0" * 64
        self.assertIn(
            "source evidence SHA-256 differs from the current R0-03 evidence",
            self.errors(changed),
        )

    def test_optional_adapter_cannot_become_core(self) -> None:
        changed = copy.deepcopy(self.decision)
        systemd = next(adapter for adapter in changed["adapters"] if adapter["id"] == "systemd")
        systemd["required_for_core"] = True
        self.assertIn("systemd has an invalid core requirement", self.errors(changed))

    def test_failure_outcome_cannot_allow_two_owners(self) -> None:
        changed = copy.deepcopy(self.decision)
        changed["failure_behavior"][0]["allows_dual_active"] = True
        self.assertIn("pre-ready must prohibit dual active owners", self.errors(changed))

    def test_recommendation_requires_zero_orphans(self) -> None:
        changed = copy.deepcopy(self.decision)
        changed["revisit_rule"]["maximum_orphaned_processes"] = 1
        self.assertIn("revisit maximum_orphaned_processes must be zero", self.errors(changed))


def load_tests(
    loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None
) -> unittest.TestSuite:
    suite = unittest.TestSuite([tests])
    suite.addTests(loader.loadTestsFromName("tools.test_guides"))
    suite.addTests(loader.loadTestsFromName("tools.test_harness_loop"))
    return suite


if __name__ == "__main__":
    unittest.main()
