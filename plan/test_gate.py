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
