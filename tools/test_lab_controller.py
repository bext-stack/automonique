#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

from tools import lab_controller


def _git(repository: pathlib.Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Automonique Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            *arguments,
        ],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(repository.parent / "fixture-home"),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    return completed.stdout.strip()


class LabControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "src").mkdir()
        (self.repository / "src" / "fixture.txt").write_text(
            "fixture\n", encoding="utf-8"
        )
        _git(self.repository, "init", "--quiet", "--initial-branch=main")
        _git(self.repository, "add", "src/fixture.txt")
        _git(self.repository, "commit", "--quiet", "-m", "fixture")
        self.base = _git(self.repository, "rev-parse", "HEAD")
        self.state_root = self.root / "runtime"
        self.controller = lab_controller.LabController(
            self.repository, self.state_root, "R0-19", ("src/",)
        )

    def tearDown(self) -> None:
        self.controller.close()
        self.temporary.cleanup()

    def select_request(
        self, *, request_id: str = "select_1", objective_id: str = "R0-19"
    ) -> dict[str, object]:
        return {
            "protocol": lab_controller.LAB_PROTOCOL,
            "requestId": request_id,
            "op": "select",
            "objectiveId": objective_id,
            "expectedBase": self.base,
            "execution": "synthetic",
            "providerPolicy": copy.deepcopy(lab_controller.SYNTHETIC_POLICY),
            "budget": copy.deepcopy(lab_controller.SYNTHETIC_BUDGET),
        }

    def observe_request(
        self, unit_id: str, after: int = 0, *, request_id: str = "observe_1"
    ) -> dict[str, object]:
        return {
            "protocol": lab_controller.LAB_PROTOCOL,
            "requestId": request_id,
            "op": "observe",
            "objectiveId": "R0-19",
            "unitId": unit_id,
            "afterSequence": after,
            "limit": 100,
        }

    @staticmethod
    def resume_request(
        unit: dict[str, object], *, request_id: str = "resume_1"
    ) -> dict[str, object]:
        return {
            "protocol": lab_controller.LAB_PROTOCOL,
            "requestId": request_id,
            "op": "resume",
            "objectiveId": "R0-19",
            "unitId": unit["unitId"],
            "checkpointId": unit["checkpointId"],
            "expectedRevision": unit["revision"],
            "idempotencyKey": "resume_once",
        }

    @staticmethod
    def cancel_request(
        unit: dict[str, object], *, request_id: str = "cancel_1"
    ) -> dict[str, object]:
        return {
            "protocol": lab_controller.LAB_PROTOCOL,
            "requestId": request_id,
            "op": "cancel",
            "objectiveId": "R0-19",
            "unitId": unit["unitId"],
            "expectedRevision": unit["revision"],
            "idempotencyKey": "cancel_once",
            "reason": "operator_request",
        }

    def test_select_observe_restart_resume_duplicate_and_cancel(self) -> None:
        selected = self.controller.handle(self.select_request())
        self.assertEqual("selected", selected["kind"])
        unit = selected["unit"]
        self.assertEqual("paused", unit["state"])
        self.assertEqual("checkpoint_1", unit["checkpointId"])
        self.assertEqual(2, unit["revision"])

        build_operations = list(
            (self.state_root / "builds" / str(unit["unitId"]) / "operations").iterdir()
        )
        self.assertEqual(1, len(build_operations))
        allocation_receipt = (
            self.state_root
            / "allocations"
            / "worktrees"
            / str(unit["unitId"])
            / "receipt.json"
        )
        self.assertTrue(allocation_receipt.is_file())
        receipt = json.loads(allocation_receipt.read_text(encoding="utf-8"))
        self.assertLessEqual(
            receipt["materialized_bytes"],
            lab_controller.SYNTHETIC_BUDGET["maxDiskBytes"],
        )

        observed = self.controller.handle(self.observe_request(str(unit["unitId"])))
        self.assertEqual("observed", observed["kind"])
        sequences = [event["sequence"] for event in observed["events"]]
        self.assertEqual(list(range(1, unit["lastSequence"] + 1)), sequences)
        self.assertEqual(unit["lastSequence"], observed["nextSequence"])
        self.assertIn("unit.selected", [event["type"] for event in observed["events"]])

        resume = self.resume_request(unit)
        self.controller.close()
        self.controller = lab_controller.LabController(
            self.repository, self.state_root, "R0-19", ("src/",)
        )
        resumed = self.controller.handle(resume)
        self.assertEqual("accepted", resumed["receipt"]["status"])
        self.assertEqual("running", resumed["unit"]["state"])
        self.assertIsNone(resumed["unit"]["checkpointId"])
        sequence_after_resume = resumed["unit"]["lastSequence"]

        replayed_select = self.controller.handle(
            self.select_request(request_id="select_replay")
        )
        self.assertEqual("selected", replayed_select["kind"])
        self.assertEqual("running", replayed_select["unit"]["state"])
        self.assertEqual(sequence_after_resume, replayed_select["unit"]["lastSequence"])

        duplicate = self.controller.handle({**resume, "requestId": "resume_2"})
        self.assertEqual("already_applied", duplicate["receipt"]["status"])
        self.assertEqual(sequence_after_resume, duplicate["unit"]["lastSequence"])

        cancel = self.cancel_request(duplicate["unit"])
        cancelled = self.controller.handle(cancel)
        self.assertEqual("accepted", cancelled["receipt"]["status"])
        self.assertEqual("cancelled", cancelled["unit"]["state"])
        sequence_after_cancel = cancelled["unit"]["lastSequence"]
        duplicate_cancel = self.controller.handle({**cancel, "requestId": "cancel_2"})
        self.assertEqual("already_applied", duplicate_cancel["receipt"]["status"])
        self.assertEqual(
            sequence_after_cancel, duplicate_cancel["unit"]["lastSequence"]
        )

        receipt_text = allocation_receipt.read_text(encoding="utf-8")
        self.assertIn('"status": "released"', receipt_text)
        tail = self.controller.handle(
            self.observe_request(
                str(unit["unitId"]), unit["lastSequence"], request_id="observe_2"
            )
        )
        self.assertEqual(
            [unit["lastSequence"] + 1, unit["lastSequence"] + 2],
            [event["sequence"] for event in tail["events"]],
        )
        self.assertEqual(
            ["unit.resumed", "unit.cancelled"],
            [event["type"] for event in tail["events"]],
        )

    def test_stale_revision_conflicts_without_an_effect(self) -> None:
        unit = self.controller.handle(self.select_request())["unit"]
        stale = self.resume_request(unit)
        stale["expectedRevision"] = 0
        response = self.controller.handle(stale)
        self.assertEqual("action", response["kind"])
        self.assertEqual("conflict", response["receipt"]["status"])
        self.assertEqual(0, response["receipt"]["effectCount"])
        observed = self.controller.handle(self.observe_request(str(unit["unitId"])))
        self.assertEqual(unit["lastSequence"], observed["unit"]["lastSequence"])

    def test_tampered_allocation_denies_resume_without_state_change(self) -> None:
        unit = self.controller.handle(self.select_request())["unit"]
        checkout_file = (
            self.state_root
            / "allocations"
            / "worktrees"
            / str(unit["unitId"])
            / "checkout"
            / "src"
            / "fixture.txt"
        )
        checkout_file.write_text("tampered\n", encoding="utf-8")
        response = self.controller.handle(self.resume_request(unit))
        self.assertEqual("action", response["kind"])
        self.assertEqual("denied", response["receipt"]["status"])
        self.assertEqual(0, response["receipt"]["effectCount"])
        self.assertEqual("paused", response["unit"]["state"])
        self.assertEqual(unit["revision"], response["unit"]["revision"])
        self.assertEqual(unit["lastSequence"], response["unit"]["lastSequence"])

    def test_repository_head_drift_is_denied_before_state_creation(self) -> None:
        request = self.select_request()
        (self.repository / "src" / "second.txt").write_text("next\n", encoding="utf-8")
        _git(self.repository, "add", "src/second.txt")
        _git(self.repository, "commit", "--quiet", "-m", "second")
        response = self.controller.handle(request)
        self.assertEqual("denied", response["kind"])
        self.assertEqual("base_drift", response["code"])

    def test_overlapping_lease_is_denied_across_controllers(self) -> None:
        first = self.controller.handle(self.select_request())
        self.assertEqual("selected", first["kind"])
        other = lab_controller.LabController(
            self.repository, self.state_root, "R0-20", ("src/fixture.txt",)
        )
        try:
            response = other.handle(
                self.select_request(request_id="select_other", objective_id="R0-20")
            )
            self.assertEqual("denied", response["kind"])
            self.assertEqual("broker_denied", response["code"])
        finally:
            other.close()

    def test_provider_budget_unknown_operation_and_self_report_are_denied(self) -> None:
        unsafe = self.select_request()
        unsafe["providerPolicy"] = {
            **lab_controller.SYNTHETIC_POLICY,
            "network": "allow",
        }
        response = self.controller.handle(unsafe)
        self.assertEqual("provider_denied", response["code"])

        over_budget = self.select_request(request_id="select_2")
        over_budget["budget"] = {
            **lab_controller.SYNTHETIC_BUDGET,
            "maxModelCalls": 1,
        }
        self.assertEqual("budget_denied", self.controller.handle(over_budget)["code"])

        self_report = {
            "protocol": lab_controller.LAB_PROTOCOL,
            "requestId": "self_report",
            "op": "succeed",
            "objectiveId": "R0-19",
            "result": "passed",
        }
        response = self.controller.handle(self_report)
        self.assertEqual("unsupported_operation", response["code"])

        selected = self.controller.handle(self.select_request(request_id="select_3"))
        forged_resume = self.resume_request(selected["unit"])
        forged_resume["result"] = "succeeded"
        response = self.controller.handle(forged_resume)
        self.assertEqual("invalid_request", response["code"])
        self.assertEqual("paused", selected["unit"]["state"])
