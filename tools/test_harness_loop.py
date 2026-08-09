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
        item, objective = harness_loop.eligible_items(
            self.program, self.objectives
        )[0]
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

    def test_unreconciled_candidate_and_unknown_state_refuse_new_attempt(self) -> None:
        original = harness_loop.read_state
        try:
            for status in ("candidate_ready", "commit_intent", "mystery"):
                harness_loop.read_state = lambda config, value=status: {
                    "status": value,
                    "driver": "codex_session",
                    "run_id": "session_test",
                    "work_id": "R0-19",
                }
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

    def test_integrated_candidate_does_not_block_a_new_attempt(self) -> None:
        original = harness_loop.read_state
        harness_loop.read_state = lambda config: {
            "status": "integrated_and_pushed",
            "driver": "codex_session",
        }
        try:
            harness_loop.refuse_active_attempt({})
        finally:
            harness_loop.read_state = original

    def test_candidate_commit_without_integration_blocks_a_new_attempt(self) -> None:
        original = harness_loop.read_state
        harness_loop.read_state = lambda config: {
            "status": "candidate_committed",
            "driver": "codex_session",
            "run_id": "session_test",
            "work_id": "R0-19",
        }
        try:
            with self.assertRaisesRegex(harness_loop.LoopError, "already owns"):
                harness_loop.refuse_active_attempt({})
        finally:
            harness_loop.read_state = original

    def test_candidate_snapshot_revalidation_detects_path_and_tree_drift(self) -> None:
        state = {
            "candidate_paths": ["tools/one.py", "plan/evidence/one.json"],
            "last_tree_digest": "abc123",
            "candidate_tree": "tree123",
        }
        self.assertTrue(
            harness_loop.candidate_snapshot_matches(
                state,
                ["plan/evidence/one.json", "tools/one.py"],
                "abc123",
                "tree123",
            )
        )
        self.assertFalse(
            harness_loop.candidate_snapshot_matches(
                state, ["tools/one.py"], "abc123", "tree123"
            )
        )
        self.assertFalse(
            harness_loop.candidate_snapshot_matches(
                state,
                ["tools/one.py", "plan/evidence/one.json"],
                "changed",
                "tree123",
            )
        )

    def test_tree_fingerprint_distinguishes_untracked_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory(dir=harness_loop.ROOT / "tools") as directory:
            root = pathlib.Path(directory)
            link = root / "link"
            relative = link.relative_to(harness_loop.ROOT).as_posix()
            link.symlink_to("first-target")
            first = harness_loop.tree_fingerprint([relative])
            link.unlink()
            link.symlink_to("second-target")
            second = harness_loop.tree_fingerprint([relative])
            self.assertNotEqual(first, second)

    def test_candidate_request_derives_git_authority_from_state_and_packet(self) -> None:
        request = harness_loop.candidate_request(
            {
                "run_id": "session_test",
                "work_id": "R0-19",
                "base": "a" * 40,
                "branch": "main",
                "candidate_paths": ["tools/two.py", "tools/one.py"],
                "candidate_tree": "b" * 40,
            },
            {"objective": {"allowed_paths": ["tools/", "plan/"]}},
            "Create typed candidate",
        )
        self.assertEqual(harness_loop.git_broker.OPERATION, request.operation)
        self.assertEqual(("tools/one.py", "tools/two.py"), request.candidate_paths)
        self.assertEqual(("tools/", "plan/"), request.allowed_paths)
        self.assertEqual("a" * 40, request.expected_base)
        self.assertEqual("b" * 40, request.expected_tree)
        self.assertEqual("safety-pass", request.attestation.checks)
        self.assertEqual(64, len(request.attestation.metrics_sha256))
        evidence = harness_loop.ROOT / "plan/evidence/R0-19.json"
        self.assertEqual(
            harness_loop.file_sha256(evidence),
            request.attestation.evidence_sha256,
        )
        self.assertEqual(0, request.attestation.reviewers)
        self.assertEqual(0, request.attestation.blocking_findings)
        self.assertFalse(request.attestation.completion)

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
