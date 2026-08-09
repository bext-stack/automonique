#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import hashlib
import pathlib
import sqlite3
import tempfile
import threading
import unittest

from tools import lab_state


BASE = "a" * 40


class LabStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "src").mkdir()
        (self.repository / "docs").mkdir()
        self.database = self.root / "state" / "lab.sqlite3"
        self.store = lab_state.LabStateStore(self.database, self.repository)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def create(
        self, attempt_id: str = "attempt_1", leases: tuple[str, ...] = ("src/",)
    ) -> lab_state.Attempt:
        return self.store.create_attempt(attempt_id, "R0-19", BASE, leases)

    def test_durability_pragmas_are_enabled(self) -> None:
        values = self.store.pragma_values()
        self.assertEqual("wal", str(values["journal_mode"]).lower())
        self.assertEqual(2, values["synchronous"])
        self.assertEqual(1, values["foreign_keys"])
        self.assertEqual(5000, values["busy_timeout"])
        self.assertEqual(0o600, self.database.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.database.parent.stat().st_mode & 0o777)

    def test_existing_state_directory_permissions_are_reapplied(self) -> None:
        path = self.root / "permissive" / "state.sqlite3"
        path.parent.mkdir(mode=0o755)
        path.parent.chmod(0o755)
        with lab_state.LabStateStore(path, self.repository):
            self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)

    def test_symlinked_state_database_or_parent_is_refused(self) -> None:
        real_parent = self.root / "real-state"
        real_parent.mkdir()
        linked_parent = self.root / "linked-state"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(lab_state.ValidationError, "symlink"):
            lab_state.LabStateStore(linked_parent / "lab.sqlite3", self.repository)

        safe_parent = self.root / "safe-state"
        safe_parent.mkdir()
        target = self.root / "target.sqlite3"
        target.write_bytes(b"")
        linked_database = safe_parent / "lab.sqlite3"
        linked_database.symlink_to(target)
        with self.assertRaisesRegex(lab_state.ValidationError, "symlink"):
            lab_state.LabStateStore(linked_database, self.repository)

    def test_failed_begin_does_not_attempt_spurious_rollback(self) -> None:
        contender = lab_state.LabStateStore(
            self.database, self.repository, busy_timeout_ms=1
        )
        try:
            contender._connection.execute("BEGIN IMMEDIATE")
            self.store._connection.execute("PRAGMA busy_timeout=1")
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                self.store.create_attempt("locked", "R0-20", BASE, ("src/",))
            self.assertFalse(self.store._connection.in_transaction)
            contender._connection.execute("ROLLBACK")
            created = self.store.create_attempt("after_lock", "R0-20", BASE, ("src/",))
            self.assertEqual(lab_state.AttemptState.QUEUED, created.state)
        finally:
            if contender._connection.in_transaction:
                contender._connection.execute("ROLLBACK")
            contender.close()

    def test_restart_preserves_attempt_checkpoints_events_and_evidence(self) -> None:
        attempt = self.create()
        self.assertEqual(lab_state.AttemptState.QUEUED, attempt.state)
        attempt = self.store.transition_attempt(
            attempt.attempt_id,
            attempt.revision,
            lab_state.AttemptState.RUNNING,
            reason="admitted",
        )
        checkpoint = self.store.append_checkpoint(
            attempt.attempt_id, "checkpoint_1", "build.saved", {"step": 1}
        )
        event = self.store.append_event(
            attempt.attempt_id, "event_1", "build.output", {"bytes": 12}
        )
        evidence = self.store.append_evidence(
            attempt.attempt_id,
            "evidence_1",
            "check.passed",
            lab_state.EvidenceAuthority.DETERMINISTIC_CHECK,
            {"exit": 0},
        )
        attempt = self.store.transition_attempt(
            attempt.attempt_id,
            attempt.revision,
            lab_state.AttemptState.PAUSED,
            reason="checkpointed",
        )
        sequences = [checkpoint.sequence, event.sequence, evidence.sequence]
        self.assertEqual(sorted(sequences), sequences)

        self.store.close()
        self.store = lab_state.LabStateStore(self.database, self.repository)
        restored = self.store.get_attempt("attempt_1")
        self.assertEqual(lab_state.AttemptState.PAUSED, restored.state)
        records = self.store.get_journal("attempt_1")
        self.assertEqual(list(range(1, restored.last_sequence + 1)), [r.sequence for r in records])
        self.assertEqual(
            {"checkpoint", "event", "evidence"},
            {record.kind.value for record in records},
        )
        self.assertIn(("attempt_1", "src"), self.store.active_leases())
        restored_evidence = next(
            record for record in records if record.record_id == "evidence_1"
        )
        self.assertEqual(
            lab_state.EvidenceAuthority.DETERMINISTIC_CHECK,
            restored_evidence.authority,
        )

    def test_segment_prefix_conflicts_across_connections(self) -> None:
        self.create(leases=("src/lib/",))
        with lab_state.LabStateStore(self.database, self.repository) as other:
            for path in ("src/", "src/lib", "src/lib/module.py"):
                with self.subTest(path=path):
                    with self.assertRaises(lab_state.ConflictError):
                        other.create_attempt(
                            "conflict_" + str(len(path)), "R0-20", BASE, (path,)
                        )
            disjoint = other.create_attempt("disjoint", "R0-20", BASE, ("docs/",))
            self.assertEqual(lab_state.AttemptState.QUEUED, disjoint.state)

    def test_lease_survives_close_and_releases_only_on_terminal_transition(self) -> None:
        attempt = self.create()
        self.store.close()
        self.store = lab_state.LabStateStore(self.database, self.repository)
        with self.assertRaises(lab_state.ConflictError):
            self.store.create_attempt("blocked", "R0-20", BASE, ("src/file.py",))

        attempt = self.store.get_attempt(attempt.attempt_id)
        with self.assertRaises(lab_state.TransitionError):
            self.store.transition_attempt(
                attempt.attempt_id,
                attempt.revision,
                lab_state.AttemptState.SUCCEEDED,
                reason="invalid",
            )
        self.assertIn((attempt.attempt_id, "src"), self.store.active_leases())

        attempt = self.store.transition_attempt(
            attempt.attempt_id,
            attempt.revision,
            lab_state.AttemptState.CANCELLED,
            reason="operator_cancel",
        )
        self.assertEqual((), self.store.active_leases())
        replacement = self.store.create_attempt("replacement", "R0-20", BASE, ("src/",))
        self.assertEqual(lab_state.AttemptState.QUEUED, replacement.state)

    def test_revision_conflict_and_terminal_state_are_fail_closed(self) -> None:
        attempt = self.create()
        with self.assertRaises(lab_state.ConflictError):
            self.store.transition_attempt(
                attempt.attempt_id,
                99,
                lab_state.AttemptState.RUNNING,
                reason="stale",
            )
        attempt = self.store.transition_attempt(
            attempt.attempt_id,
            attempt.revision,
            lab_state.AttemptState.CANCELLED,
            reason="operator_cancel",
        )
        with self.assertRaises(lab_state.TransitionError):
            self.store.transition_attempt(
                attempt.attempt_id,
                attempt.revision,
                lab_state.AttemptState.RUNNING,
                reason="resurrect",
            )

    def test_success_and_failure_states_survive_restart(self) -> None:
        succeeded = self.create("will_succeed", ("src/",))
        failed = self.create("will_fail", ("docs/",))
        succeeded = self.store.transition_attempt(
            succeeded.attempt_id,
            succeeded.revision,
            lab_state.AttemptState.RUNNING,
            reason="admitted",
        )
        succeeded = self.store.transition_attempt(
            succeeded.attempt_id,
            succeeded.revision,
            lab_state.AttemptState.SUCCEEDED,
            reason="checks_passed",
        )
        failed = self.store.transition_attempt(
            failed.attempt_id,
            failed.revision,
            lab_state.AttemptState.FAILED,
            reason="admission_failed",
        )
        self.store.close()
        self.store = lab_state.LabStateStore(self.database, self.repository)
        self.assertEqual(
            lab_state.AttemptState.SUCCEEDED,
            self.store.get_attempt(succeeded.attempt_id).state,
        )
        self.assertEqual(
            lab_state.AttemptState.FAILED,
            self.store.get_attempt(failed.attempt_id).state,
        )
        self.assertEqual((), self.store.active_leases())

    def test_effect_prepare_and_completion_are_idempotent(self) -> None:
        self.create()
        request_digest = hashlib.sha256(b"request").hexdigest()
        prepared = self.store.prepare_effect(
            "effect_1", "attempt_1", "candidate.commit", request_digest
        )
        repeated = self.store.prepare_effect(
            "effect_1", "attempt_1", "candidate.commit", request_digest
        )
        self.assertEqual(prepared, repeated)
        self.store.close()
        self.store = lab_state.LabStateStore(self.database, self.repository)
        self.assertEqual(prepared, self.store.get_effect("effect_1"))
        result = {"commit": "b" * 40}
        first = self.store.complete_effect("effect_1", request_digest, result)
        second = self.store.complete_effect("effect_1", request_digest, result)
        self.assertEqual(first, second)
        self.assertEqual(lab_state.EffectStatus.COMPLETED, first.status)
        with self.assertRaises(lab_state.ConflictError):
            self.store.complete_effect(
                "effect_1", request_digest, {"commit": "c" * 40}
            )
        with self.assertRaises(lab_state.ConflictError):
            self.store.prepare_effect(
                "effect_1",
                "attempt_1",
                "candidate.commit",
                hashlib.sha256(b"different").hexdigest(),
            )

    def test_non_standard_json_and_maximum_id_edge_are_bounded(self) -> None:
        attempt_id = "a" * lab_state.MAX_ID_LENGTH
        self.store.create_attempt(attempt_id, "R0-19", BASE, ("src/",))
        record = self.store.append_event(
            attempt_id, "event_1", "worker.output", {"finite": 1.5}
        )
        self.assertEqual(2, record.sequence)
        with self.assertRaises(lab_state.ValidationError):
            self.store.append_event(
                attempt_id, "event_nan", "worker.output", {"value": float("nan")}
            )

    def test_duplicate_record_does_not_advance_sequence(self) -> None:
        attempt = self.create()
        first = self.store.append_event(
            attempt.attempt_id, "event_1", "worker.started", {}
        )
        with self.assertRaises(lab_state.ConflictError):
            self.store.append_event(
                attempt.attempt_id, "event_1", "worker.started", {}
            )
        restored = self.store.get_attempt(attempt.attempt_id)
        self.assertEqual(first.sequence, restored.last_sequence)

    def test_invalid_and_symlink_paths_are_rejected_without_state(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.repository / "escape").symlink_to(outside, target_is_directory=True)
        invalid = (
            "",
            "/absolute",
            "../escape",
            "src/../docs",
            "src/./file",
            ".git/config",
            "src\0bad",
            "src\nbad",
            "src\\bad",
            "escape/file",
        )
        for index, path in enumerate(invalid):
            with self.subTest(path=repr(path)):
                with self.assertRaises(lab_state.ValidationError):
                    self.store.create_attempt(
                        f"invalid_{index}", "R0-20", BASE, (path,)
                    )
        with self.assertRaises(lab_state.NotFoundError):
            self.store.get_attempt("invalid_0")

    def test_two_connections_racing_for_same_lease_have_one_winner(self) -> None:
        self.store.close()
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def contender(attempt_id: str) -> None:
            with lab_state.LabStateStore(self.database, self.repository) as store:
                barrier.wait(timeout=5)
                try:
                    store.create_attempt(attempt_id, "R0-20", BASE, ("src/",))
                    outcome = "won"
                except lab_state.ConflictError:
                    outcome = "conflict"
                with lock:
                    outcomes.append(outcome)

        threads = [
            threading.Thread(target=contender, args=("racer_1",)),
            threading.Thread(target=contender, args=("racer_2",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(["won", "conflict"], outcomes)
        self.store = lab_state.LabStateStore(self.database, self.repository)
        self.assertEqual(1, len(self.store.active_leases()))


if __name__ == "__main__":
    unittest.main()
