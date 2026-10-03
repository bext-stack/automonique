#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0
"""Exercise the production publisher without starting a worker or contacting Manage."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).parent / "run_manage_fleet_worker.sh").read_text()
PUBLISH = "publish_process_snapshot()" + SOURCE.split("publish_process_snapshot()", 1)[1].split("refresh_process_snapshot()", 1)[0]


class ProcessSnapshotTests(unittest.TestCase):
    def test_large_output_inventory_refreshes_terminal_status_and_keeps_final_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            jobs = []
            for index in range(40):
                job_id = f"fixture-job-{index:04}"
                lines = [{"at_ms": 1, "kind": "tool_input", "text": "x" * 1000, "truncated": False} for _ in range(12)]
                (output / f"{job_id}.json").write_text(json.dumps({"schema": "automonique.manage-process-output/v1", "job_id": job_id, "lines": lines}))
                jobs.append({"id": job_id, "status": "done", "instance_id": "fixture-worker", "updated_at": "2026-01-01T01:00:00.000Z", "result": "Verified completion receipt"})
            # Over Linux's per-argument limit; the old --argjson publisher failed here.
            self.assertGreater(sum(path.stat().st_size for path in output.iterdir()), 131072)
            snapshot = root / "snapshot.json"
            snapshot.write_text(json.dumps({"ok": True, "instances": [{"id": "fixture-worker", "status": "online"}], "jobs": jobs}))
            script = 'set -uo pipefail\nauth_health_status() { printf authenticated; }\n' + PUBLISH + '\npublish_process_snapshot "$(cat "$fixture_snapshot")"\n'
            env = dict(os.environ, state_dir=directory, runtime_dir=directory, output_dir=str(output), fleet_instance="fixture-worker", selected_provider="jcode", fleet_base="https://manage.example.test", max_concurrency="3", fixture_snapshot=str(snapshot))
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            data = json.loads((root / "processes.json").read_text())
            self.assertEqual(data["stats"]["running"], 0)
            self.assertEqual(data["stats"]["completed"], 40)
            self.assertEqual(data["worker"]["active_jobs"], 0)
            self.assertEqual(len(data["jobs"][0]["output"]), 12)
            self.assertEqual(data["jobs"][0]["output"][-1]["kind"], "final")
            self.assertEqual(data["jobs"][0]["output"][-1]["text"], "Verified completion receipt")
            self.assertEqual(data["jobs"][0]["output"][-1]["at_ms"], 1767229200000)
            self.assertEqual(data["jobs"][10]["output"], [])
            self.assertEqual((root / "processes.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
