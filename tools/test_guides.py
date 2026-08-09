#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import copy
import unittest

from tools import guides, program


class GuideObjectiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.program = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
        self.manifest, self.objectives, _ = guides.expected_files()

    def test_six_guide_families_and_sources_validate(self) -> None:
        self.assertEqual(6, len(self.manifest["guides"]))
        self.assertEqual([], guides.validate_guides(self.manifest))

    def test_every_runnable_node_has_a_valid_objective(self) -> None:
        self.assertEqual([], guides.validate_objectives(self.objectives, self.program))
        objective_ids = {entry["work_id"] for entry in self.objectives["objectives"]}
        runnable_ids = {
            item["id"] for item in self.program["items"] if item["runnable"]
        }
        self.assertTrue(runnable_ids <= objective_ids)

    def test_objective_schema_requires_all_contract_fields(self) -> None:
        schema = guides.build_objective_schema()
        required = schema["properties"]["objectives"]["items"]["required"]
        self.assertEqual(set(guides.OBJECTIVE_FIELDS), set(required))

    def test_low_score_cannot_remain_autonomously_eligible(self) -> None:
        changed = copy.deepcopy(self.objectives)
        objective = changed["objectives"][0]
        objective["hill_climbability"] = guides.HILL_THRESHOLD - 1
        objective["autonomous_eligible"] = True
        errors = guides.validate_objectives(changed, self.program)
        self.assertTrue(
            any("autonomous eligibility contradicts" in error for error in errors)
        )

    def test_contradiction_names_both_source_locations(self) -> None:
        changed = copy.deepcopy(self.manifest)
        original = changed["guides"][0]["rules"][0]
        changed["guides"][1]["rules"].append(
            {
                "id": "opposite",
                "subject": original["subject"],
                "effect": "require",
                "statement": "synthetic contradiction",
                "location": "fixture/opposite.md#opposite",
            }
        )
        errors = guides.contradictions(changed)
        self.assertEqual(1, len(errors))
        self.assertIn(original["location"], errors[0])
        self.assertIn("fixture/opposite.md#opposite", errors[0])

    def test_generation_is_byte_reproducible(self) -> None:
        first = guides.expected_files()[2]
        second = guides.expected_files()[2]
        self.assertEqual(first, second)

    def test_codex_session_is_the_bounded_default_driver(self) -> None:
        config = guides.build_loop_config()
        session = config["drivers"]["codex_session"]
        self.assertEqual("codex_session", config["default_driver"])
        self.assertTrue(session["native_subagents"])
        self.assertEqual(3, session["max_concurrent_subagents"])
        self.assertEqual("disjoint_paths_only", session["concurrent_writes"])


if __name__ == "__main__":
    unittest.main()
