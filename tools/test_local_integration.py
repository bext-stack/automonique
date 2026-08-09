#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

from tools import git_broker, local_integration


class LocalIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.remote = root / "remote.git"
        self.repository = root / "repository"
        self.candidate_state = root / "candidate-state"
        self.integration_state = root / "integration-state"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        self.repository.mkdir()
        self.git("init", "-b", "main")
        self.git("remote", "add", "origin", str(self.remote))
        (self.repository / "leased").mkdir()
        (self.repository / "leased/a.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "leased/a.txt")
        self.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@automonique.invalid",
            "commit", "-m", "base",
        )
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("push", "origin", "main")
        self.authority = root / "authority.toml"
        self.write_authority(push=True)
        self.integration = local_integration.LocalIntegration(
            self.repository,
            self.integration_state,
            self.authority,
            local_integration.file_sha256(self.authority),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments], cwd=self.repository, capture_output=True,
            text=True, check=check,
        )

    def write_authority(self, *, push: bool) -> None:
        self.authority.write_text(
            "\n".join(
                [
                    'schema = "automonique.authority/v1"',
                    'decision = "fixture-owner-decision"',
                    "advance_verified_local_main = true",
                    f"publish_verified_origin_main_fast_forward = {'true' if push else 'false'}",
                    'local_main_ref = "refs/heads/main"',
                    'publication_remote = "origin"',
                    'publication_ref = "refs/heads/main"',
                    "require_exact_tree_verification = true",
                    "require_fast_forward = true",
                    "require_expected_tip = true",
                    "push = false",
                    "merge_protected_branch = false",
                    "force_update = false",
                    "history_rewrite = false",
                    "edit_remote = false",
                    "other_ref_update = false",
                    "other_remote_update = false",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def make_candidate(self, run_id: str = "run_1") -> tuple[pathlib.Path, str, dict]:
        (self.repository / "leased/a.txt").write_text("candidate\n", encoding="utf-8")
        broker = git_broker.CandidateBroker(self.repository, self.candidate_state)
        tree = broker.snapshot(
            expected_base=self.base,
            expected_branch="main",
            allowed_paths=("leased/",),
            candidate_paths=("leased/a.txt",),
        )
        request = git_broker.CandidateRequest(
            operation=git_broker.OPERATION,
            run_id=run_id,
            work_id="R0-19",
            expected_base=self.base,
            expected_branch="main",
            allowed_paths=("leased/",),
            candidate_paths=("leased/a.txt",),
            expected_tree=tree,
            summary="Candidate fixture",
            attestation=git_broker.CandidateAttestation(
                checks="safety-pass",
                reviewers=0,
                blocking_findings=0,
                metrics_sha256="0" * 64,
                completion=False,
                evidence_sha256=None,
            ),
        )
        receipt = broker.create(request)
        path = self.candidate_state / "git-candidates" / run_id / "receipt.json"
        return path, local_integration.file_sha256(path), receipt

    def remote_oid(self) -> str:
        output = self.git("ls-remote", "--refs", "origin", "refs/heads/main").stdout
        return output.split()[0]

    def test_integrates_local_main_and_pushes_exact_commit(self) -> None:
        path, digest, candidate = self.make_candidate()

        receipt = self.integration.integrate(path, digest)

        self.assertEqual("integrated_and_pushed", receipt["status"])
        self.assertEqual(candidate["commit_oid"], self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual(candidate["commit_oid"], self.remote_oid())
        self.assertEqual("", self.git("status", "--porcelain").stdout)
        self.assertEqual(
            candidate["commit_oid"],
            self.git("rev-parse", "refs/automonique/candidates/run_1").stdout.strip(),
        )

    def test_authority_digest_and_push_flag_are_required(self) -> None:
        path, digest, _ = self.make_candidate()
        wrong = local_integration.LocalIntegration(
            self.repository, self.integration_state, self.authority, "0" * 64
        )
        with self.assertRaisesRegex(local_integration.IntegrationError, "digest"):
            wrong.prepare(path, digest)

        self.write_authority(push=False)
        denied = local_integration.LocalIntegration(
            self.repository,
            self.integration_state,
            self.authority,
            local_integration.file_sha256(self.authority),
        )
        with self.assertRaisesRegex(local_integration.IntegrationError, "denies push"):
            denied.prepare(path, digest)
        self.assertEqual(self.base, self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual(self.base, self.remote_oid())

    def test_candidate_receipt_ref_parent_and_tree_are_exact(self) -> None:
        path, digest, candidate = self.make_candidate()
        tampered = dict(candidate)
        tampered["tree_oid"] = self.base
        path.write_text(json.dumps(tampered), encoding="utf-8")

        with self.assertRaisesRegex(local_integration.IntegrationError, "tree or parent"):
            self.integration.prepare(path, local_integration.file_sha256(path))

        self.assertEqual(self.base, self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual(self.base, self.remote_oid())

    def test_restart_after_intent_is_idempotent(self) -> None:
        path, digest, candidate = self.make_candidate(run_id="intent_restart")
        self.integration.prepare(path, digest)

        restarted = local_integration.LocalIntegration(
            self.repository,
            self.integration_state,
            self.authority,
            local_integration.file_sha256(self.authority),
        )
        first = restarted.reconcile("intent_restart")
        second = restarted.reconcile("intent_restart")

        self.assertEqual(first, second)
        self.assertEqual(candidate["commit_oid"], self.remote_oid())

    def test_remote_already_has_commit_reconciles_ambiguous_push(self) -> None:
        path, digest, candidate = self.make_candidate(run_id="push_restart")
        intent = self.integration.prepare(path, digest)
        payload = intent["payload"]
        self.git("read-tree", payload["candidate_tree"])
        self.git(
            "update-ref", "refs/heads/main", payload["candidate_commit"], payload["expected_parent"]
        )
        self.git("push", "origin", f"{payload['candidate_commit']}:refs/heads/main")

        receipt = self.integration.reconcile("push_restart")

        self.assertEqual(candidate["commit_oid"], receipt["commit_oid"])
        self.assertEqual(candidate["commit_oid"], self.remote_oid())
        self.assertEqual("", self.git("status", "--porcelain").stdout)

    def test_remote_drift_fails_without_force(self) -> None:
        path, digest, candidate = self.make_candidate(run_id="remote_drift")
        self.integration.prepare(path, digest)
        other = pathlib.Path(self.temporary.name) / "other"
        subprocess.run(["git", "clone", str(self.remote), str(other)], check=True, capture_output=True)
        subprocess.run(["git", "checkout", "main"], cwd=other, check=True, capture_output=True)
        (other / "remote.txt").write_text("other\n", encoding="utf-8")
        subprocess.run(["git", "add", "remote.txt"], cwd=other, check=True)
        subprocess.run(
            [
                "git", "-c", "user.name=Fixture", "-c",
                "user.email=fixture@automonique.invalid", "commit", "-m", "remote drift",
            ],
            cwd=other,
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "push", "origin", "main"], cwd=other, check=True, capture_output=True)
        remote_drift = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=other, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

        with self.assertRaisesRegex(local_integration.IntegrationError, "origin/main"):
            self.integration.reconcile("remote_drift")

        self.assertEqual(candidate["commit_oid"], self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual(remote_drift, self.remote_oid())
        intent_state = json.loads(
            (self.integration_state / "local-integrations/remote_drift/intent.json").read_text()
        )
        self.assertEqual("reconciliation_required", intent_state["status"])


if __name__ == "__main__":
    unittest.main()
