#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest

import lifecycle
from protocol import Endpoint, ProtocolError


class LifecycleTests(unittest.TestCase):
    def test_complete_foreground_trial(self) -> None:
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=lifecycle.HERE.parent.parent,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        completed = subprocess.run(
            [
                sys.executable,
                str(lifecycle.HERE / "lifecycle.py"),
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

    def test_owner_record_replaces_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "owner.json"
            lifecycle.write_owner(path, "fixture-old", 1, "initial")
            lifecycle.write_owner(path, "fixture-new", 2, "handoff")
            self.assertEqual(
                {
                    "active_generation": "fixture-new",
                    "epoch": 2,
                    "reason": "handoff",
                },
                lifecycle.read_owner(path),
            )
            self.assertFalse(path.with_suffix(".new").exists())

    def test_protocol_rejects_oversized_frame(self) -> None:
        left, right = socket.socketpair()
        try:
            endpoint = Endpoint(left)
            with self.assertRaises(ProtocolError):
                endpoint.send({"type": "oversized", "value": "x" * 5000})
            endpoint.close()
        finally:
            right.close()


if __name__ == "__main__":
    unittest.main()
