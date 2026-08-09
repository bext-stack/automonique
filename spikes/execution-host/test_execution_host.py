#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest

import runner
import trial
from protocol import Endpoint, ProtocolError


class ExecutionHostTests(unittest.TestCase):
    def test_complete_trial(self) -> None:
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=trial.HERE.parent.parent,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        completed = subprocess.run(
            [
                sys.executable,
                str(trial.HERE / "trial.py"),
                "--base",
                base,
                "--timeout",
                "5",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("pass", result["status"])
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual([], result["cleanup_fallbacks"])
        self.assertIsNone(result["environment"]["service_manager"])

    def test_registry_replaces_atomically_and_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "registry.json"
            runner.write_json_atomic(path, {"state": "starting"})
            runner.write_json_atomic(path, {"state": "running"})
            self.assertEqual({"state": "running"}, json.loads(path.read_text()))
            self.assertEqual(0, path.stat().st_mode & 0o077)
            self.assertFalse(path.with_suffix(".json.new").exists())

    def test_protocol_rejects_oversized_frame(self) -> None:
        left, right = socket.socketpair()
        try:
            endpoint = Endpoint(left, 1)
            with self.assertRaises(ProtocolError):
                endpoint.send({"type": "oversized", "value": "x" * 5000})
            endpoint.close()
        finally:
            right.close()

    def test_fixed_runner_command_contains_no_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command = trial.fixed_runner_command(
                pathlib.Path(directory), "host-0123456789abcdef", "normal", 5
            )
        self.assertEqual(sys.executable, command[0])
        self.assertNotIn("-c", command)
        self.assertNotIn("sh", [pathlib.Path(part).name for part in command])


if __name__ == "__main__":
    unittest.main()
