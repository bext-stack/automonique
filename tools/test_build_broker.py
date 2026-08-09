#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from tools import build_broker


class BuildBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state = pathlib.Path(self.temporary.name) / "state"
        self.broker = build_broker.BuildBroker(self.state)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        recipe: build_broker.Recipe,
        *,
        wall: float = 3,
        cpu: int = 2,
        output: int = 4096,
        processes: int = 2,
        disk: int = 8192,
    ) -> build_broker.BuildRequest:
        return build_broker.BuildRequest(
            recipe=recipe,
            limits=build_broker.BuildLimits(
                wall_seconds=wall,
                cpu_seconds=cpu,
                output_bytes=output,
                process_count=processes,
                writable_bytes=disk,
            ),
        )

    def test_success_is_bounded_and_environment_is_scrubbed(self) -> None:
        result = self.broker.run(self.request(build_broker.Recipe.SUCCESS))

        self.assertEqual("success", result["outcome"])
        self.assertEqual("ok\n", result["stdout_stderr"])
        self.assertEqual("scrubbed", result["attestation"]["environment"])
        self.assertLessEqual(result["attestation"]["captured_output_bytes"], 4096)
        self.assertLessEqual(result["attestation"]["peak_process_count"], 2)

    def test_wall_cpu_output_and_disk_limits(self) -> None:
        cases = (
            (build_broker.Recipe.WALL, {"wall": 0.1}, "wall_limit"),
            (build_broker.Recipe.CPU, {"wall": 3, "cpu": 1, "processes": 1}, "cpu_limit"),
            (build_broker.Recipe.OUTPUT, {"output": 1024}, "output_limit"),
            (build_broker.Recipe.DISK, {"disk": 4096}, "disk_limit"),
        )
        for recipe, limits, expected in cases:
            with self.subTest(recipe=recipe.value):
                result = self.broker.run(self.request(recipe, **limits))
                self.assertEqual(expected, result["outcome"])
                self.assertLessEqual(
                    result["attestation"]["captured_output_bytes"],
                    result["attestation"]["captured_output_limit"],
                )
                self.assertLessEqual(
                    result["attestation"]["peak_writable_bytes"],
                    result["attestation"]["writable_limit"],
                )

    def test_pid_limit_refuses_before_spawn(self) -> None:
        request = self.request(
            build_broker.Recipe.DESCENDANT, processes=1, cpu=2, wall=0.1
        )
        with mock.patch("subprocess.Popen") as popen:
            with self.assertRaises(build_broker.BuildLimitRejected):
                self.broker.run(request)
            popen.assert_not_called()

    def test_missing_proc_capability_refuses_before_spawn(self) -> None:
        unavailable = build_broker.BuildBroker(
            self.state / "unavailable", pathlib.Path(self.temporary.name) / "no-proc"
        )
        request = self.request(build_broker.Recipe.DESCENDANT, wall=0.1)
        with mock.patch("subprocess.Popen") as popen:
            with self.assertRaises(build_broker.HostCapabilityMissing):
                unavailable.run(request)
            popen.assert_not_called()

    def test_symlink_state_root_is_rejected_before_resolution(self) -> None:
        target = pathlib.Path(self.temporary.name) / "state-target"
        target.mkdir()
        link = pathlib.Path(self.temporary.name) / "state-link"
        link.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(build_broker.BuildError, "symlink"):
            build_broker.BuildBroker(link)

    def test_preexisting_operation_directory_is_forced_to_private_mode(self) -> None:
        request = self.request(build_broker.Recipe.SUCCESS)
        operation = self.state / "operations" / self.broker.operation_id(request)
        operation.mkdir(parents=True)
        operation.chmod(0o755)

        self.broker.run(request)

        self.assertEqual(0o700, operation.stat().st_mode & 0o777)
        self.assertEqual(0o700, operation.parent.stat().st_mode & 0o777)

    def test_descendant_is_reaped_by_group_cleanup(self) -> None:
        result = self.broker.run(
            self.request(build_broker.Recipe.DESCENDANT, wall=0.15, processes=2, cpu=2)
        )

        self.assertEqual("wall_limit", result["outcome"])
        child = int(result["stdout_stderr"].strip())
        for _ in range(30):
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("descendant survived TERM/KILL process-group cleanup")

    def test_unknown_recipe_is_denied_without_spawn(self) -> None:
        request = self.request(build_broker.Recipe.SUCCESS)
        object.__setattr__(request, "recipe", "arbitrary-command")
        with mock.patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(build_broker.BuildError, "unknown"):
                self.broker.run(request)
            popen.assert_not_called()

    def test_completed_receipt_prevents_duplicate_spawn(self) -> None:
        request = self.request(build_broker.Recipe.SUCCESS)
        first = self.broker.run(request)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("duplicate spawn")):
            second = build_broker.BuildBroker(self.state).run(request)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
