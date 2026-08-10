#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import pathlib
import subprocess
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

    def selectable_leasing(self, path: str) -> str:
        """An autonomously selectable item whose lease covers `path`.

        Recovery needs *a* selectable item that may write the fixture path, not
        one particular ticket. Naming a live graph ID here coupled this test to
        the plan: when GATE-HARNESS froze the harness tail, a test about
        recovery durability failed for reasons that had nothing to do with
        recovery.
        """
        for item, _ in harness_loop.eligible_items(self.program, self.objectives):
            if path in item.get("allowed_paths", []):
                return item["id"]
        raise AssertionError(f"no selectable work item leases {path}")

    def test_selection_is_deterministic_and_refuses_low_scores(self) -> None:
        eligible = harness_loop.eligible_items(self.program, self.objectives)
        by_id = {
            objective["work_id"]: objective
            for objective in self.objectives["objectives"]
        }
        expected = [
            item["id"]
            for item in self.program["items"]
            if item["runnable"]
            and by_id[item["id"]]["autonomous_eligible"]
            and not harness_loop.owner_blocked_reason(item["id"])
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
        review = json.loads(evidence.read_text())["review"]
        self.assertEqual(review["reviewers"], request.attestation.reviewers)
        self.assertEqual(
            review["blocking_findings"],
            request.attestation.blocking_findings,
        )
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

    def test_recovery_state_schema_rejects_ambiguous_and_non_utc_state(self) -> None:
        state = {
            "schema": harness_loop.STATE_SCHEMA,
            "run_id": "session_20260810T000000Z_deadbeef",
            "driver": "codex_session",
            "work_id": "R0-19",
            "base": "a" * 40,
            "branch": "main",
            "status": "stopped",
            "packet": ".automonique/state/runs/session_20260810T000000Z_deadbeef/packet.json",
            "iteration": 1,
            "failures": 0,
            "unchanged_results": 0,
            "stop_reason": "wall_budget",
            "started_at": "2026-08-10T00:00:00+00:00",
            "deadline_at": "2026-08-10T00:30:00+00:00",
            "updated_at": "2026-08-10T00:30:00+00:00",
            "packet_sha256": "b" * 64,
        }
        harness_loop.validate_recoverable_state(state)
        ambiguous = dict(state, candidate_ref="refs/automonique/candidates/test")
        with self.assertRaisesRegex(harness_loop.LoopError, "unexpected candidate_ref"):
            harness_loop.validate_recoverable_state(ambiguous)
        naive = dict(state, updated_at="2026-08-10T00:30:00")
        with self.assertRaisesRegex(harness_loop.LoopError, "updated_at is invalid"):
            harness_loop.validate_recoverable_state(naive)

    def test_recovery_rejects_stale_candidate_snapshot(self) -> None:
        original_paths = harness_loop.porcelain_paths
        original_fingerprint = harness_loop.tree_fingerprint
        original_tree = harness_loop.exact_candidate_tree
        with tempfile.TemporaryDirectory() as directory:
            config = {"state_path": str(pathlib.Path(directory) / "state.json")}
            state = {
                "run_id": "session_20260810T000000Z_deadbeef",
                "candidate_paths": ["tools/change.py"],
                "last_tree_digest": "a" * 64,
                "candidate_tree": "b" * 40,
            }
            pathlib.Path(config["state_path"]).write_text("{}\n")
            try:
                harness_loop.porcelain_paths = lambda: ["tools/change.py"]
                harness_loop.tree_fingerprint = lambda paths: "c" * 64
                harness_loop.exact_candidate_tree = (
                    lambda state_value, packet, config_value, paths: "b" * 40
                )
                with self.assertRaisesRegex(harness_loop.LoopError, "differs"):
                    harness_loop.recovery_snapshot_document(
                        state,
                        {"objective": {"allowed_paths": ["tools/"]}},
                        config,
                    )
            finally:
                harness_loop.porcelain_paths = original_paths
                harness_loop.tree_fingerprint = original_fingerprint
                harness_loop.exact_candidate_tree = original_tree

    def test_recovery_is_durable_idempotent_and_one_shot(self) -> None:
        original_root = harness_loop.ROOT
        original_load_inputs = harness_loop.load_inputs
        original_safety_checks = harness_loop.run_safety_checks
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)

            def run_git(*args: str) -> str:
                completed = subprocess.run(
                    ["git", *args],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            try:
                harness_loop.ROOT = root
                subprocess.run(
                    ["git", "init", "--initial-branch=main"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
                run_git("config", "user.name", "Recovery Test")
                run_git("config", "user.email", "recovery@example.invalid")
                (root / "tools").mkdir()
                (root / "tools/base.py").write_text("BASE = True\n")
                (root / ".gitignore").write_text("/.automonique/state/\n")
                run_git("add", ".gitignore", "tools/base.py")
                run_git("commit", "-m", "test base")
                base = run_git("rev-parse", "HEAD")

                work_id = self.selectable_leasing("tools/")
                item, objective = harness_loop.select_item(
                    self.program, self.objectives, work_id
                )
                config = guides.build_loop_config()
                config["safety_checks"] = [[sys.executable, "-c", "pass"]]
                run_id = "session_20260810T000000Z_deadbeef"
                packet = harness_loop.packet_document(
                    run_id,
                    1,
                    base,
                    item,
                    objective,
                    config,
                    None,
                    driver="codex_session",
                )
                packet_path = (
                    root / ".automonique/state/runs" / run_id / "packet.json"
                )
                harness_loop.write_json_atomic(packet_path, packet)
                state = {
                    "schema": harness_loop.STATE_SCHEMA,
                    "run_id": run_id,
                    "driver": "codex_session",
                    "work_id": work_id,
                    "base": base,
                    "branch": "main",
                    "status": "stopped",
                    "packet": packet_path.relative_to(root).as_posix(),
                    "iteration": 1,
                    "failures": 0,
                    "unchanged_results": 0,
                    "stop_reason": "wall_budget",
                    "started_at": "2026-08-10T00:00:00+00:00",
                    "deadline_at": "2026-08-10T00:30:00+00:00",
                    "updated_at": "2026-08-10T00:30:00+00:00",
                    "packet_sha256": harness_loop.file_sha256(packet_path),
                }
                loop_state = root / config["state_path"]
                harness_loop.write_json_atomic(loop_state, state)
                dirty = root / "tools/recovery-change.py"
                dirty.write_text("RECOVERED = True\n")
                harness_loop.load_inputs = lambda: (
                    self.program,
                    self.objectives,
                    config,
                )

                self.assertEqual(
                    1,
                    subprocess.run(
                        [
                            "git",
                            "show-ref",
                            "--verify",
                            "--quiet",
                            f"refs/automonique/candidates/{run_id}",
                        ],
                        cwd=root,
                        check=False,
                    ).returncode,
                )
                outside = root / "outside.txt"
                outside.write_text("not leased\n")
                with self.assertRaisesRegex(harness_loop.LoopError, "out-of-lease"):
                    harness_loop._recover_session_locked()
                outside.unlink()

                ambiguous_effect = (
                    root
                    / ".automonique/state/git-candidates"
                    / run_id
                    / "intent.json"
                )
                ambiguous_effect.parent.mkdir(parents=True)
                ambiguous_effect.symlink_to("missing-intent")
                with self.assertRaisesRegex(harness_loop.LoopError, "ambiguous"):
                    harness_loop._recover_session_locked()
                ambiguous_effect.unlink()
                run_git(
                    "update-ref",
                    f"refs/automonique/candidates/{run_id}",
                    base,
                )
                with self.assertRaisesRegex(harness_loop.LoopError, "candidate ref"):
                    harness_loop._recover_session_locked()
                run_git("update-ref", "-d", f"refs/automonique/candidates/{run_id}")

                changed_packet = json.loads(json.dumps(packet))
                changed_packet["unexpected"] = True
                harness_loop.write_json_atomic(packet_path, changed_packet)
                changed_state = dict(state)
                changed_state["packet_sha256"] = harness_loop.file_sha256(packet_path)
                harness_loop.write_json_atomic(loop_state, changed_state)
                with self.assertRaisesRegex(harness_loop.LoopError, "closed v1"):
                    harness_loop._recover_session_locked()
                harness_loop.write_json_atomic(packet_path, packet)
                harness_loop.write_json_atomic(loop_state, state)

                def mutate_raw_state(config_value: dict, phase: str) -> None:
                    original_safety_checks(config_value, phase)
                    with loop_state.open("a") as handle:
                        handle.write(" ")

                harness_loop.run_safety_checks = mutate_raw_state
                try:
                    with self.assertRaisesRegex(
                        harness_loop.LoopError, "changed before recovery compare-and-swap"
                    ):
                        harness_loop._recover_session_locked()
                finally:
                    harness_loop.run_safety_checks = original_safety_checks
                harness_loop.write_json_atomic(loop_state, state)

                self.assertEqual(0, harness_loop._recover_session_locked())
                claimed = harness_loop.load_json(loop_state)
                self.assertEqual("claimed", claimed["status"])
                self.assertEqual(run_id, claimed["run_id"])
                self.assertEqual(base, claimed["base"])
                self.assertEqual(
                    1800,
                    int(
                        (
                            harness_loop.parse_utc_seconds(
                                claimed["deadline_at"], "deadline"
                            )
                            - harness_loop.parse_utc_seconds(
                                claimed["started_at"], "started"
                            )
                        ).total_seconds()
                    ),
                )
                self.assertEqual("RECOVERED = True\n", dirty.read_text())

                snapshot_path, intent_path, receipt_path = harness_loop.recovery_paths(
                    config, run_id
                )
                self.assertTrue(snapshot_path.exists())
                self.assertTrue(intent_path.exists())
                self.assertTrue(receipt_path.exists())
                intent = harness_loop.load_json(intent_path)
                deadline = claimed["deadline_at"]

                receipt_path.unlink()
                harness_loop.write_json_atomic(loop_state, state)
                self.assertEqual(0, harness_loop._recover_session_locked())
                self.assertEqual(deadline, harness_loop.load_json(loop_state)["deadline_at"])

                receipt_path.unlink()
                corrupt = json.loads(json.dumps(intent))
                corrupt["replacement_state"]["base"] = "f" * 40
                corrupt["replacement_state_sha256"] = harness_loop.canonical_sha256(
                    corrupt["replacement_state"]
                )
                harness_loop.write_json_atomic(intent_path, corrupt)
                with self.assertRaisesRegex(
                    harness_loop.LoopError, "immutable stopped-session fields"
                ):
                    harness_loop._recover_session_locked()

                harness_loop.write_json_atomic(intent_path, intent)
                self.assertEqual(0, harness_loop._recover_session_locked())
                self.assertEqual(deadline, harness_loop.load_json(loop_state)["deadline_at"])

                repeated_stop = dict(claimed)
                repeated_stop.update(status="stopped", stop_reason="wall_budget")
                harness_loop.write_json_atomic(loop_state, repeated_stop)
                with self.assertRaisesRegex(harness_loop.LoopError, "already consumed"):
                    harness_loop._recover_session_locked()
            finally:
                harness_loop.ROOT = original_root
                harness_loop.load_inputs = original_load_inputs
                harness_loop.run_safety_checks = original_safety_checks


if __name__ == "__main__":
    unittest.main()


class OwnerBlockedSelectionTests(unittest.TestCase):
    """Autonomous selection must route around work a worker cannot finish."""

    PROGRAM = {
        "items": [
            {"id": "AAA-1", "runnable": True},
            {"id": "AAA-2", "runnable": True},
        ]
    }
    OBJECTIVES = {
        "objectives": [
            {"work_id": "AAA-1", "autonomous_eligible": True, "hill_climbability": 90},
            {"work_id": "AAA-2", "autonomous_eligible": True, "hill_climbability": 80},
        ]
    }

    def evidence_root(self, directory: str, blocked: dict | None) -> pathlib.Path:
        root = pathlib.Path(directory)
        (root / "plan" / "evidence").mkdir(parents=True)
        if blocked is not None:
            (root / "plan" / "evidence" / "AAA-1.json").write_text(
                json.dumps({"item": "AAA-1", "external_completion_check": blocked})
            )
        return root

    def select(self, blocked: dict | None) -> str:
        original = harness_loop.ROOT
        with tempfile.TemporaryDirectory() as directory:
            try:
                harness_loop.ROOT = self.evidence_root(directory, blocked)
                item, _ = harness_loop.select_item(self.PROGRAM, self.OBJECTIVES, None)
                return item["id"]
            finally:
                harness_loop.ROOT = original

    def test_unresolved_external_check_is_skipped(self) -> None:
        self.assertEqual(
            "AAA-2", self.select({"result": None, "reason": "owner secret missing"})
        )

    def test_resolved_external_check_stays_selectable(self) -> None:
        self.assertEqual("AAA-1", self.select({"result": "pass"}))

    def test_item_without_evidence_stays_selectable(self) -> None:
        self.assertEqual("AAA-1", self.select(None))

    def test_reason_is_reported_verbatim(self) -> None:
        original = harness_loop.ROOT
        with tempfile.TemporaryDirectory() as directory:
            try:
                harness_loop.ROOT = self.evidence_root(
                    directory, {"result": None, "reason": "owner secret missing"}
                )
                self.assertEqual(
                    "owner secret missing", harness_loop.owner_blocked_reason("AAA-1")
                )
                self.assertIsNone(harness_loop.owner_blocked_reason("AAA-2"))
            finally:
                harness_loop.ROOT = original
