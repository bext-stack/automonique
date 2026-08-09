#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import copy
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import unittest

from tools import lab_api, lab_controller


def _git(repository: pathlib.Path, *arguments: str) -> str:
    return subprocess.run(
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
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    ).stdout.strip()


class LabScenarioIntegrationTests(unittest.TestCase):
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
        self.state_root = self.root / "state"
        self.socket_path = self.root / "socket" / "lab.sock"
        self.controller = self._controller()

    def tearDown(self) -> None:
        self.controller.close()
        self.temporary.cleanup()

    def _controller(self) -> lab_controller.LabController:
        return lab_controller.LabController(
            self.repository, self.state_root, "R0-19", ("src/",)
        )

    def _exchange(self, request: dict[str, object]) -> dict[str, object]:
        errors: list[BaseException] = []
        responses: list[dict[str, object]] = []
        with lab_api.LabApiServer(self.socket_path, self.controller.handle) as server:
            def request_from_client() -> None:
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(2)
                        client.connect(os.fspath(self.socket_path))
                        client.sendall(
                            lab_api.encode_frame(request, server.max_frame_size)
                        )
                        responses.append(
                            lab_api.receive_frame(client, server.max_frame_size)
                        )
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=request_from_client)
            thread.start()
            server.serve_once()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]
        self.assertEqual(1, len(responses))
        return responses[0]

    def test_direct_socket_scenario_survives_controller_and_server_restart(self) -> None:
        selected = self._exchange(
            {
                "protocol": lab_controller.LAB_PROTOCOL,
                "requestId": "select",
                "op": "select",
                "objectiveId": "R0-19",
                "expectedBase": self.base,
                "execution": "synthetic",
                "providerPolicy": copy.deepcopy(lab_controller.SYNTHETIC_POLICY),
                "budget": copy.deepcopy(lab_controller.SYNTHETIC_BUDGET),
            }
        )
        self.assertEqual("selected", selected["kind"])
        unit = selected["unit"]
        self.assertIsInstance(unit, dict)
        assert isinstance(unit, dict)
        self.assertEqual("paused", unit["state"])

        self.controller.close()
        self.controller = self._controller()
        observed = self._exchange(
            {
                "protocol": lab_controller.LAB_PROTOCOL,
                "requestId": "observe",
                "op": "observe",
                "objectiveId": "R0-19",
                "unitId": unit["unitId"],
                "afterSequence": 0,
                "limit": 100,
            }
        )
        self.assertEqual("observed", observed["kind"])
        events = observed["events"]
        self.assertIsInstance(events, list)
        assert isinstance(events, list)
        self.assertEqual(
            list(range(1, int(unit["lastSequence"]) + 1)),
            [event["sequence"] for event in events],
        )

        resumed = self._exchange(
            {
                "protocol": lab_controller.LAB_PROTOCOL,
                "requestId": "resume",
                "op": "resume",
                "objectiveId": "R0-19",
                "unitId": unit["unitId"],
                "checkpointId": unit["checkpointId"],
                "expectedRevision": unit["revision"],
                "idempotencyKey": "resume_once",
            }
        )
        self.assertEqual("accepted", resumed["receipt"]["status"])
        resumed_unit = resumed["unit"]
        self.assertEqual("running", resumed_unit["state"])

        cancelled = self._exchange(
            {
                "protocol": lab_controller.LAB_PROTOCOL,
                "requestId": "cancel",
                "op": "cancel",
                "objectiveId": "R0-19",
                "unitId": resumed_unit["unitId"],
                "expectedRevision": resumed_unit["revision"],
                "idempotencyKey": "cancel_once",
                "reason": "operator_request",
            }
        )
        self.assertEqual("accepted", cancelled["receipt"]["status"])
        self.assertEqual("cancelled", cancelled["unit"]["state"])


if __name__ == "__main__":
    unittest.main()
