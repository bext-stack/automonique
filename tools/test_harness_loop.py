#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

from tools import guides, harness_loop, program


class HarnessLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.program = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
        self.objectives = guides.build_objectives(self.program)
        self.budget = {
            "max_iterations": 3,
            "max_wall_seconds": 1800,
            "max_worker_seconds": 1200,
            "max_unchanged_results": 1,
            "max_failures": 2,
        }

    def test_selection_is_deterministic_and_refuses_low_scores(self) -> None:
        eligible = harness_loop.eligible_items(self.program, self.objectives)
        by_id = {
            objective["work_id"]: objective
            for objective in self.objectives["objectives"]
        }
        expected = [
            item["id"]
            for item in self.program["items"]
            if item["runnable"] and by_id[item["id"]]["autonomous_eligible"]
        ]
        self.assertEqual(expected, [item["id"] for item, _ in eligible])
        with self.assertRaisesRegex(
            harness_loop.LoopError, "below the autonomous threshold"
        ):
            harness_loop.select_item(self.program, self.objectives, "BOOT-002")

    def test_out_of_lease_path_is_named(self) -> None:
        self.assertEqual(
            ["rust/outside.rs"],
            harness_loop.lease_errors(
                ["plan/evidence/R0-18.json", "rust/outside.rs"],
                ["plan/", "tools/"],
            ),
        )
        self.assertFalse(
            harness_loop.path_is_leased("GOVERNANCE.md.backup", ["GOVERNANCE.md"])
        )

    def test_rename_checks_both_source_and_destination_paths(self) -> None:
        paths = harness_loop.parse_porcelain_z(
            b"R  plan/new.py\0outside.py\0?? tools/new.py\0"
        )
        self.assertEqual(["plan/new.py", "outside.py", "tools/new.py"], paths)
        self.assertEqual(
            ["outside.py"], harness_loop.lease_errors(paths, ["plan/", "tools/"])
        )

    def test_worker_argv_is_explicit_and_packet_is_final(self) -> None:
        packet = pathlib.Path("packet.json")
        self.assertEqual(
            ["worker", "--mode", "bounded", "packet.json"],
            harness_loop.worker_argv(
                ["worker", "--mode", "bounded"], packet
            ),
        )
        with self.assertRaises(harness_loop.LoopError):
            harness_loop.worker_argv([], packet)

    def test_session_packet_declares_native_bounded_delegation(self) -> None:
        item, objective = harness_loop.select_item(
            self.program, self.objectives, "R0-06"
        )
        config = guides.build_loop_config()
        packet = harness_loop.packet_document(
            "session_test",
            1,
            "abc123",
            item,
            objective,
            config,
            None,
            driver="codex_session",
        )
        coordination = packet["session_coordination"]
        self.assertEqual("codex_session", packet["driver"])
        self.assertTrue(coordination["native_subagents"])
        self.assertEqual(3, coordination["max_concurrent_subagents"])
        self.assertFalse(coordination["recursive_agent_trees"])
        self.assertNotIn("worker_interface", packet)
        self.assertEqual(
            harness_loop.file_sha256(guides.OBJECTIVES),
            packet["objectives_sha256"],
        )

    def test_active_claim_refuses_a_second_attempt(self) -> None:
        original = harness_loop.read_state
        harness_loop.read_state = lambda config: {
            "status": "claimed",
            "driver": "codex_session",
            "run_id": "session_test",
            "work_id": "R0-06",
        }
        try:
            with self.assertRaisesRegex(harness_loop.LoopError, "already owns"):
                harness_loop.refuse_active_attempt({})
        finally:
            harness_loop.read_state = original

    def test_stopped_claim_does_not_block_a_new_attempt(self) -> None:
        original = harness_loop.read_state
        harness_loop.read_state = lambda config: {
            "status": "stopped",
            "driver": "codex_session",
        }
        try:
            harness_loop.refuse_active_attempt({})
        finally:
            harness_loop.read_state = original

    def test_single_worker_lock_rejects_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {"state_path": str(pathlib.Path(directory) / "state.json")}
            first = harness_loop.acquire_loop_lock(config)
            try:
                with self.assertRaisesRegex(harness_loop.LoopError, "already owns"):
                    harness_loop.acquire_loop_lock(config)
            finally:
                first.close()

    def test_worker_sandbox_hides_authority_and_limits_writes(self) -> None:
        probe = harness_loop.ROOT / "tools/fixtures/sandbox_probe.py"
        argv = harness_loop.sandbox_worker_argv(
            [sys.executable, str(probe)], guides.LOOP_CONFIG, ["tools/"]
        )
        exit_code, forced_stop = harness_loop.run_worker(argv, 5)
        self.assertEqual(0, exit_code)
        self.assertIsNone(forced_stop)

    def test_unchanged_result_stops_without_retry_loop(self) -> None:
        reason = harness_loop.stop_reason(
            exit_code=1,
            checks_passed=True,
            changed=False,
            iteration=1,
            failures=1,
            unchanged_results=1,
            elapsed_seconds=1,
            budget=self.budget,
        )
        self.assertEqual("unchanged_evidence", reason)

    def test_failure_and_iteration_budgets_stop(self) -> None:
        failure = harness_loop.stop_reason(
            exit_code=1,
            checks_passed=True,
            changed=True,
            iteration=2,
            failures=2,
            unchanged_results=0,
            elapsed_seconds=2,
            budget=self.budget,
        )
        iteration = harness_loop.stop_reason(
            exit_code=1,
            checks_passed=True,
            changed=True,
            iteration=3,
            failures=1,
            unchanged_results=0,
            elapsed_seconds=3,
            budget=self.budget,
        )
        self.assertEqual("failure_budget", failure)
        self.assertEqual("iteration_budget", iteration)

    def test_wall_budget_stops(self) -> None:
        reason = harness_loop.stop_reason(
            exit_code=1,
            checks_passed=True,
            changed=True,
            iteration=1,
            failures=1,
            unchanged_results=0,
            elapsed_seconds=1800,
            budget=self.budget,
        )
        self.assertEqual("wall_budget", reason)

    def test_zero_exit_with_changed_tree_yields_candidate_only(self) -> None:
        reason = harness_loop.stop_reason(
            exit_code=0,
            checks_passed=True,
            changed=True,
            iteration=1,
            failures=0,
            unchanged_results=0,
            elapsed_seconds=1,
            budget=self.budget,
        )
        self.assertEqual("candidate_ready", reason)


if __name__ == "__main__":
    unittest.main()
