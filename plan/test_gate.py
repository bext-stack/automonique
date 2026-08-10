#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from plan import baseline
from plan import gate


class BaselineDigestTests(unittest.TestCase):
    def test_digest_is_full_sha256(self) -> None:
        snapshot = {"counters": {"one": 1, "two": 2}}
        payload = json.dumps(snapshot, sort_keys=True)
        expected = hashlib.sha256(payload.encode()).hexdigest()

        actual = baseline.digest(snapshot)

        self.assertEqual(expected, actual)
        self.assertEqual(64, len(actual))


class GateEvidenceTests(unittest.TestCase):
    def evidence(self, result: str | None, reason: str | None = None) -> dict:
        check = {"name": "Measured check", "result": result}
        if reason is not None:
            check["reason"] = reason
        return {
            "item": "TEST-1",
            "checks": [check],
            "review": {"reviewers": 0, "blocking_findings": 0},
        }

    def write_evidence(self, root: pathlib.Path, document: dict) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "TEST-1.json").write_text(json.dumps(document), encoding="utf-8")

    def test_null_result_with_reason_never_authorizes_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = pathlib.Path(directory)
            self.write_evidence(evidence, self.evidence(None, "fixture unavailable"))
            gate.reset_diagnostics()
            with mock.patch.object(gate, "EVIDENCE", evidence):
                gate.check_evidence(
                    {"id": "TEST-1"}, ["Measured check"], completion=True
                )

        self.assertTrue(
            any("cannot authorize completion" in refusal for refusal in gate.refusals)
        )

    def test_partial_preflight_reports_null_without_claiming_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = pathlib.Path(directory)
            self.write_evidence(evidence, self.evidence(None, "fixture unavailable"))
            gate.reset_diagnostics()
            with mock.patch.object(gate, "EVIDENCE", evidence):
                gate.check_evidence(
                    {"id": "TEST-1"}, ["Measured check"], completion=False
                )

        self.assertEqual([], gate.refusals)
        self.assertTrue(any("partial preflight only" in note for note in gate.notices))

    def test_attestation_requires_and_emits_full_digest(self) -> None:
        evidence = {"review": {"reviewers": 2, "blocking_findings": 0}}
        digest = "a" * 64

        trailers = gate.attestation_trailers(
            {"id": "R0-19"}, evidence, {"digest": digest}
        )

        self.assertIn(f"Automonique-Metrics: sha256:{digest}", trailers)
        with self.assertRaisesRegex(ValueError, "full 64-hex"):
            gate.attestation_trailers(
                {"id": "R0-19"}, evidence, {"digest": "a" * 16}
            )

    def test_unresolved_blocking_review_never_authorizes_completion(self) -> None:
        document = self.evidence("pass")
        document["review"]["blocking_findings"] = 1
        with tempfile.TemporaryDirectory() as directory:
            evidence = pathlib.Path(directory)
            self.write_evidence(evidence, document)
            gate.reset_diagnostics()
            with mock.patch.object(gate, "EVIDENCE", evidence):
                gate.check_evidence(
                    {"id": "TEST-1"}, ["Measured check"], completion=True
                )

        self.assertTrue(any("unresolved blocking" in value for value in gate.refusals))


class CompletionLeaseTests(unittest.TestCase):
    """A completion may write its own closing artifacts and nothing else."""

    ITEM = {"id": "R1-02", "allowed_paths": ["rust/crates/automonique-protocol/"]}

    def lease(self, declared: list[str], *, completion: bool) -> None:
        gate.reset_diagnostics()
        with (
            mock.patch.object(gate, "dirty_paths", return_value=declared),
            mock.patch.object(gate, "staged_deletions", return_value=set()),
            mock.patch.object(
                gate, "lease_at_head", return_value=self.ITEM["allowed_paths"]
            ),
        ):
            gate.check_lease(self.ITEM, declared, completion=completion)

    def test_completion_may_write_its_own_evidence_and_artifacts(self) -> None:
        self.lease(
            [
                "rust/crates/automonique-protocol/src/primitives.rs",
                "plan/evidence/R1-02.json",
                "plan/generate.py",
                "plan/work-graph.toml",
                "plan/history.jsonl",
                "plan/baseline.json",
                ".automonique/dev/program.yaml",
            ],
            completion=True,
        )
        self.assertEqual([], gate.refusals)

    def test_completion_may_not_write_another_items_evidence(self) -> None:
        self.lease(["plan/evidence/R1-25.json"], completion=True)
        self.assertTrue(any("diff touches" in value for value in gate.refusals))

    def test_completion_may_not_widen_authority_or_contracts(self) -> None:
        for path in ("plan/authority.toml", "plan/contracts/R1-02.md", "AGENTS.md",
                     "plan/gate.py"):
            with self.subTest(path=path):
                self.lease([path], completion=True)
                self.assertTrue(
                    any("diff touches" in value for value in gate.refusals),
                    f"{path} must stay outside a completion transaction",
                )

    def test_completion_may_not_change_the_machinery_that_judges_it(self) -> None:
        """Even inside the lease. R0-16 leases tools/, which covers the harness."""
        item = {"id": "R0-16", "allowed_paths": ["plan/", "tools/"]}
        for path in gate.COMPLETION_FORBIDDEN:
            with self.subTest(path=path):
                gate.reset_diagnostics()
                with (
                    mock.patch.object(gate, "dirty_paths", return_value=[path]),
                    mock.patch.object(gate, "staged_deletions", return_value=set()),
                    mock.patch.object(
                        gate, "lease_at_head", return_value=item["allowed_paths"]
                    ),
                ):
                    gate.check_lease(item, [path], completion=True)
                self.assertTrue(
                    any("machinery that judges it" in v for v in gate.refusals),
                    f"{path} must not ride along in a completion",
                )

    def test_a_partial_slice_may_still_change_the_machinery(self) -> None:
        item = {"id": "R0-16", "allowed_paths": ["tools/"]}
        gate.reset_diagnostics()
        with (
            mock.patch.object(gate, "dirty_paths", return_value=["tools/harness_loop.py"]),
            mock.patch.object(gate, "staged_deletions", return_value=set()),
            mock.patch.object(gate, "lease_at_head", return_value=item["allowed_paths"]),
        ):
            gate.check_lease(item, ["tools/harness_loop.py"], completion=False)
        self.assertEqual([], gate.refusals)

    def test_partial_slice_keeps_the_narrow_implementation_lease(self) -> None:
        self.lease(["plan/evidence/R1-02.json"], completion=False)
        self.assertTrue(any("diff touches" in value for value in gate.refusals))


class SelfWidenedLeaseTests(unittest.TestCase):
    """A candidate cannot widen its own lease and be judged against the wider one."""

    ITEM = {"id": "R0-16", "allowed_paths": ["plan/", "tools/", "docs/"]}

    def check(self, head_lease: list[str] | None) -> None:
        gate.reset_diagnostics()
        declared = ["docs/ledger.md"]
        with (
            mock.patch.object(gate, "dirty_paths", return_value=declared),
            mock.patch.object(gate, "staged_deletions", return_value=set()),
            mock.patch.object(gate, "lease_at_head", return_value=head_lease),
        ):
            gate.check_lease(dict(self.ITEM), declared, completion=True)

    def test_a_lease_widened_in_this_transaction_is_refused(self) -> None:
        self.check(["plan/", "tools/"])
        self.assertTrue(any("changes its own lease" in v for v in gate.refusals))

    def test_a_lease_already_committed_is_honoured(self) -> None:
        self.check(["plan/", "tools/", "docs/"])
        self.assertEqual([], gate.refusals)

    def test_an_item_absent_from_head_falls_back_with_a_notice(self) -> None:
        self.check(None)
        self.assertEqual([], gate.refusals)
        self.assertTrue(any("not in the committed graph" in n for n in gate.notices))


class CompletionStatusTests(unittest.TestCase):
    """The done flip belongs to the transaction the gate is judging."""

    ITEM = {"id": "R1-02", "depends_on": [], "status": "done", "_all": []}

    def readiness(self, head_status: str | None) -> None:
        gate.reset_diagnostics()
        with mock.patch.object(gate, "status_at_head", return_value=head_status):
            gate.check_readiness(dict(self.ITEM))

    def test_uncommitted_done_flip_is_the_transaction_under_judgement(self) -> None:
        self.readiness("blocked")
        self.assertEqual([], gate.refusals)
        self.assertTrue(any("flipped to done" in note for note in gate.notices))

    def test_already_committed_done_is_still_refused(self) -> None:
        self.readiness("done")
        self.assertTrue(any("already marked done" in value for value in gate.refusals))


class GateModeTests(unittest.TestCase):
    def argv(self, mode: str | None) -> list[str]:
        arguments = [
            "gate.py",
            "--item",
            "R0-19",
            "--summary",
            "bounded slice",
            "--files",
            "tools/example.py",
        ]
        if mode:
            arguments.append(mode)
        return arguments

    def test_commit_refuses_before_inspection_or_mutation(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", self.argv("--commit")),
            mock.patch.object(
                gate, "load_item", side_effect=AssertionError("must not inspect")
            ),
            mock.patch.object(
                gate, "git", side_effect=AssertionError("must not mutate Git")
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = gate.main()

        self.assertEqual(1, result)
        self.assertIn("one exact completion tree", stderr.getvalue())

    def test_legacy_recording_mode_refuses_instead_of_writing_metadata(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", self.argv(None)),
            mock.patch.object(
                gate, "load_item", side_effect=AssertionError("must not inspect")
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = gate.main()

        self.assertEqual(1, result)
        self.assertIn("choose --dry-run", stderr.getvalue())

    def test_full_dry_run_emits_attestation_without_writing(self) -> None:
        item = {
            "id": "R0-19",
            "title": "Minimal lab",
            "licence": "Elastic-2.0",
            "epic": "R0",
        }
        evidence = {
            "review": {"reviewers": 0, "blocking_findings": 0},
        }
        after = {
            "total": 1,
            "counters": {"contracts_missing": 1},
            "digest": "b" * 64,
        }
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = pathlib.Path(directory) / "baseline.json"
            history_path = pathlib.Path(directory) / "history.jsonl"
            baseline_path.write_text("baseline-before\n", encoding="utf-8")
            history_path.write_text("history-before\n", encoding="utf-8")
            with (
                mock.patch.object(sys, "argv", self.argv("--dry-run")),
                mock.patch.object(gate, "BASELINE", baseline_path),
                mock.patch.object(gate, "HISTORY", history_path),
                mock.patch.object(gate, "load_item", return_value=item),
                mock.patch.object(gate, "contract_checks", return_value=["check"]),
                mock.patch.object(gate, "check_readiness"),
                mock.patch.object(gate, "check_evidence", return_value=evidence),
                mock.patch.object(gate, "check_lease", return_value=["tools/example.py"]),
                mock.patch.object(gate, "check_plan_integrity"),
                mock.patch.object(gate, "check_metric", return_value=({}, after)),
                mock.patch.object(
                    gate, "git", side_effect=AssertionError("dry-run must not use Git")
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main()

            self.assertEqual("baseline-before\n", baseline_path.read_text())
            self.assertEqual("history-before\n", history_path.read_text())

        self.assertEqual(0, result)
        self.assertIn("Automonique-Metrics: sha256:" + "b" * 64, stdout.getvalue())
        self.assertIn("nothing recorded", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
