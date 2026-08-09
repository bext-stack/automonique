#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

from tools import git_broker


class GitBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.repository = root / "repository"
        self.state = root / "state"
        self.repository.mkdir()
        self.git("init", "-b", "main")
        (self.repository / "leased").mkdir()
        (self.repository / "leased/a.txt").write_text("base\n", encoding="utf-8")
        (self.repository / "outside.txt").write_text("outside\n", encoding="utf-8")
        self.git("add", "leased/a.txt", "outside.txt")
        self.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@automonique.invalid",
            "commit", "-m", "fixture base",
        )
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.broker = git_broker.CandidateBroker(self.repository, self.state)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments], cwd=self.repository, capture_output=True,
            text=True, check=check,
        )

    def request(
        self,
        *,
        run_id: str = "run_1",
        operation: str = git_broker.OPERATION,
        allowed: tuple[str, ...] = ("leased/",),
        paths: tuple[str, ...] = ("leased/a.txt",),
        base: str | None = None,
        branch: str = "main",
    ) -> git_broker.CandidateRequest:
        expected_tree = self.broker.snapshot(
            expected_base=self.base,
            expected_branch="main",
            allowed_paths=("leased/",),
            candidate_paths=("leased/a.txt",),
        )
        return git_broker.CandidateRequest(
            operation=operation,
            run_id=run_id,
            work_id="R0-19",
            expected_base=base or self.base,
            expected_branch=branch,
            allowed_paths=allowed,
            candidate_paths=paths,
            expected_tree=expected_tree,
            summary="Create bounded candidate",
        )

    def modify_leased_file(self) -> None:
        (self.repository / "leased/a.txt").write_text("candidate\n", encoding="utf-8")

    def test_candidate_uses_private_index_and_namespaced_ref(self) -> None:
        self.modify_leased_file()
        index_before = (self.repository / ".git/index").read_bytes()
        head_before = self.git("rev-parse", "HEAD").stdout.strip()

        receipt = self.broker.create(self.request())

        self.assertEqual("candidate_committed", receipt["status"])
        self.assertEqual(head_before, self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual("main", self.git("branch", "--show-current").stdout.strip())
        self.assertEqual(index_before, (self.repository / ".git/index").read_bytes())
        self.assertEqual(
            receipt["commit_oid"],
            self.git("rev-parse", "refs/automonique/candidates/run_1").stdout.strip(),
        )
        self.assertEqual(
            self.base, self.git("rev-parse", f"{receipt['commit_oid']}^").stdout.strip()
        )
        self.assertEqual(
            receipt["tree_oid"],
            self.git("rev-parse", f"{receipt['commit_oid']}^{{tree}}").stdout.strip(),
        )
        self.assertEqual("M leased/a.txt", self.git("status", "--short").stdout.strip())

    def test_forbidden_and_unknown_operations_are_denied(self) -> None:
        self.modify_leased_file()
        for operation in sorted(git_broker.FORBIDDEN_OPERATIONS | {"arbitrary_argv"}):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(git_broker.BrokerError, "operation"):
                    self.broker.prepare(self.request(run_id="deny_" + operation, operation=operation))

    def test_base_branch_and_lease_are_exact(self) -> None:
        self.modify_leased_file()
        with self.assertRaisesRegex(git_broker.BrokerError, "expected base"):
            self.broker.prepare(self.request(run_id="bad_base", base="f" * 40))
        with self.assertRaisesRegex(git_broker.BrokerError, "expected branch"):
            self.broker.prepare(self.request(run_id="bad_branch", branch="other"))
        with self.assertRaisesRegex(git_broker.BrokerError, "out-of-lease"):
            self.broker.prepare(
                self.request(run_id="outside", paths=("outside.txt",))
            )
        for path in ("../escape", "/absolute", ".git/config", "leased/../outside.txt"):
            with self.subTest(path=path):
                with self.assertRaises(git_broker.BrokerError):
                    self.broker.prepare(self.request(run_id="path_" + str(len(path)), paths=(path,)))

    def test_intent_only_restart_reconciles_once(self) -> None:
        self.modify_leased_file()
        request = self.request(run_id="restart_intent")
        intent = self.broker.prepare(request)
        self.assertEqual("commit_intent", intent["status"])
        self.assertIsNone(self.broker._ref_oid(intent["ref"]))

        restarted = git_broker.CandidateBroker(self.repository, self.state)
        first = restarted.reconcile(request.run_id)
        second = restarted.reconcile(request.run_id)

        self.assertEqual(first, second)
        self.assertEqual(first["commit_oid"], restarted._ref_oid(intent["ref"]))

    def test_ref_written_before_receipt_reconciles_same_commit(self) -> None:
        self.modify_leased_file()
        request = self.request(run_id="restart_ref")
        intent = self.broker.prepare(request)
        commit = self.broker._commit_oid(intent, request)
        self.git("update-ref", intent["ref"], commit, git_broker.ZERO_OID)

        receipt = git_broker.CandidateBroker(self.repository, self.state).reconcile(request.run_id)

        self.assertEqual(commit, receipt["commit_oid"])
        self.assertEqual("candidate_committed", receipt["status"])

    def test_mismatched_existing_ref_fails_closed(self) -> None:
        self.modify_leased_file()
        request = self.request(run_id="mismatch")
        intent = self.broker.prepare(request)
        self.git("update-ref", intent["ref"], self.base, git_broker.ZERO_OID)

        with self.assertRaisesRegex(git_broker.BrokerError, "different commit"):
            self.broker.reconcile(request.run_id)

        state = json.loads(
            (self.state / "git-candidates/mismatch/intent.json").read_text(encoding="utf-8")
        )
        self.assertEqual("reconciliation_required", state["status"])
        self.assertEqual(self.base, self.git("rev-parse", intent["ref"]).stdout.strip())
        with self.assertRaisesRegex(git_broker.BrokerError, "must be reconciled"):
            self.broker.abandon(request.run_id)

    def test_source_drift_after_intent_creates_no_ref(self) -> None:
        self.modify_leased_file()
        request = self.request(run_id="drift")
        intent = self.broker.prepare(request)
        (self.repository / "outside.txt").write_text("drift\n", encoding="utf-8")

        with self.assertRaisesRegex(git_broker.BrokerError, "dirty paths differ"):
            self.broker.reconcile(request.run_id)

        self.assertIsNone(self.broker._ref_oid(intent["ref"]))
        state = json.loads(
            (self.state / "git-candidates/drift/intent.json").read_text(encoding="utf-8")
        )
        self.assertEqual("reconciliation_required", state["status"])
        self.assertEqual("abandoned", self.broker.abandon(request.run_id)["status"])

    def test_same_path_change_after_snapshot_is_refused(self) -> None:
        self.modify_leased_file()
        request = self.request(run_id="same_path_drift")
        (self.repository / "leased/a.txt").write_text("changed again\n", encoding="utf-8")

        with self.assertRaisesRegex(git_broker.BrokerError, "checked snapshot"):
            self.broker.prepare(request)

        self.assertFalse((self.state / "git-candidates/same_path_drift/intent.json").exists())

    def test_repository_content_filter_is_refused_without_execution(self) -> None:
        self.modify_leased_file()
        marker = pathlib.Path(self.temporary.name) / "filter-ran"
        filter_program = pathlib.Path(self.temporary.name) / "filter.py"
        filter_program.write_text(
            "import pathlib,sys\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        info_attributes = self.repository / ".git/info/attributes"
        info_attributes.write_text("leased/a.txt filter=fixture\n", encoding="utf-8")
        self.git("config", "filter.fixture.clean", f"python3 {filter_program}")

        with self.assertRaisesRegex(git_broker.BrokerError, "content filter"):
            self.broker.prepare(self.request(run_id="filter_denied"))

        self.assertFalse(marker.exists())

    def test_repository_fsmonitor_is_disabled_without_execution(self) -> None:
        self.modify_leased_file()
        marker = pathlib.Path(self.temporary.name) / "fsmonitor-ran"
        monitor = pathlib.Path(self.temporary.name) / "fsmonitor.py"
        monitor.write_text(
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        self.git("config", "core.fsmonitor", f"python3 {monitor}")

        self.broker.prepare(self.request(run_id="fsmonitor_disabled"))

        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
