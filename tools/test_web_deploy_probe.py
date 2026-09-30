# SPDX-License-Identifier: Elastic-2.0
"""Deployment must not claim success when its explicit health probe fails."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parent / "deploy" / "deploy-web-entry.sh"
REVISION = "a" * 40


class WebDeploymentProbeTests(unittest.TestCase):
    def deploy(self, responses):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            commands.mkdir()
            release = root / "release"
            release.mkdir()
            binary = root / "web-entry"
            binary.write_text(
                '#!/bin/sh\nprintf \'{"source_revision":"' + REVISION
                + '","provenance":"declared"}\\n\'\n'
            )
            binary.chmod(0o755)
            (commands / "systemctl").write_text(
                '#!/bin/sh\ncase "$*" in *is-active*) echo active ;; esac\n'
            )
            (commands / "sleep").write_text("#!/bin/sh\nexit 0\n")
            (commands / "curl").write_text(
                '#!/usr/bin/env python3\n'
                'import os\nfrom pathlib import Path\n'
                'path = Path(os.environ["PROBE_COUNT"])\n'
                'index = int(path.read_text()) if path.exists() else 0\n'
                'path.write_text(str(index + 1))\n'
                'values = os.environ["PROBE_RESPONSES"].split(",")\n'
                'code = values[min(index, len(values) - 1)]\n'
                'print(code, end="")\n'
                'raise SystemExit(7 if code == "000" else 0)\n'
            )
            for command in commands.iterdir():
                command.chmod(0o755)
            count = root / "count"
            result = subprocess.run(
                ["bash", str(SCRIPT), "--root", str(release), "--service", "fixture.service",
                 "--binary", str(binary), "--source-sha", REVISION,
                 "--probe", "http://health.invalid/healthz"],
                env={**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                     "PROBE_COUNT": str(count), "PROBE_RESPONSES": ",".join(responses)},
                capture_output=True, text=True, timeout=20,
            )
            return result, int(count.read_text())

    def test_connection_failure_then_readiness_is_retried(self):
        result, attempts = self.deploy(["000", "503", "200"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 3)
        self.assertIn("-> 200", result.stdout)
        self.assertTrue(result.stdout.rstrip().endswith("deployed."))

    def test_failed_probe_never_reports_deployed(self):
        for code in ["000", "503", "404"]:
            with self.subTest(code=code):
                result, attempts = self.deploy([code])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(attempts, 30)
                self.assertNotIn("deployed.", result.stdout)
                self.assertIn("explicit health probe did not succeed", result.stderr)
                self.assertNotIn("000000", result.stdout)


if __name__ == "__main__":
    unittest.main()
