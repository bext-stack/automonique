# SPDX-License-Identifier: Elastic-2.0
"""Exercise the fleet worker with fake providers, never a configured service."""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest


WORKER = Path(__file__).with_name("run_manage_fleet_worker.sh").read_text()


def function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", WORKER, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing worker function {name}")
    return match.group(0)


def running(pid, patience=5.0):
    """Whether a process is still running after a short wait for its exit."""
    deadline = time.monotonic() + patience
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0]
        except (FileNotFoundError, ProcessLookupError):
            return False
        if state == "Z":
            return False
        time.sleep(0.05)
    return True


PROVIDER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

prompt = sys.stdin.read()
assert "Monique completion receipt contract" in prompt
provider = os.environ["TEST_PROVIDER"]
if provider == "codex":
    first = {"type": "item.started", "item": {"type": "command_execution"}}
elif provider == "jcode":
    first = {"type": "tool_start", "name": "fixture"}
else:
    first = {"type": "assistant", "message": {"content": [{"type": "text", "text": "working"}]}}
print(json.dumps(first), flush=True)
# A terminal-only replay of the log cannot satisfy this handshake.
deadline = time.monotonic() + 3
while not Path(os.environ["TEST_LOG_READY"]).exists():
    if time.monotonic() > deadline:
        sys.exit(42)
    time.sleep(0.01)
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
Path(os.environ["TEST_CHILD_PID"]).write_text(str(child.pid))
receipt = "https://github.com/example/project/issues/1#issuecomment-1"
if provider == "codex":
    print(json.dumps({"type": "thread.started", "thread_id": "fixture-session"}), flush=True)
    final = {"type": "item.completed", "item": {"type": "agent_message", "text": receipt}}
elif provider == "jcode":
    final = {"type": "done", "session_id": "fixture-session", "text": receipt}
else:
    final = {"type": "result", "session_id": "fixture-session", "result": receipt}
print(json.dumps(final), flush=True)
sys.stderr.write("fixture diagnostic without a final newline")
sys.stderr.flush()
sys.exit(int(os.environ["TEST_EXIT_CODE"]))
'''


STUBS = r'''
local_work_brief() { return 1; }
workspace_for() { printf '%s\n' "$runtime_dir"; }
report_job() {
    printf '%s\n' "$2" >> "$runtime_dir/reports"
    # The wall-clock figure differs run to run; the rest is exact.
    jq -c 'del(.duration_ms)' <<<"${5:-null}" >> "$runtime_dir/telemetry"
}
post_job_log() {
    printf '%s\t%s\n' "$2" "$3" >> "$runtime_dir/logs"
    if [[ "$2" == item.started || "$2" == tool_start || "$2" == assistant ]]; then
        touch "$TEST_LOG_READY"
    fi
}
completion_comment_permalink() { printf '%s\n' "$1"; }
completion_comment_body() { printf 'Demande 1\nVerification: fixture\n'; }
probe_local_auth() { return 0; }
write_auth_health() { return 0; }
refresh_process_snapshot() { return 0; }
auth_failure_reason() { return 1; }
'''


class ProviderLifecycleTests(unittest.TestCase):
    def run_provider(self, provider, exit_code):
        with tempfile.TemporaryDirectory(prefix="monique-worker-test-") as directory:
            root = Path(directory)
            binary = root / "fake-provider"
            binary.write_text(PROVIDER)
            binary.chmod(0o700)
            script = "\n".join(
                ["set -uo pipefail", "umask 077", STUBS]
                + [
                    function(name)
                    for name in (
                        "log_provider_line",
                        "completion_report_is_structured",
                        "process_group_alive",
                        "terminate_process_group",
                        "start_job_watchdog",
                        "abort_job_run",
                        "run_telemetry",
                        "wait_for_provider",
                        "run_job",
                    )
                ]
                + ['run_job "$TEST_JOB"']
            )
            env = {
                **os.environ,
                "state_dir": directory,
                "runtime_dir": directory,
                "selected_provider": provider,
                "selected_home": directory,
                "selected_binary": str(binary),
                "job_timeout_seconds": "7200",
                "kill_grace_seconds": "20",
                "worker_group": "",
                "TEST_PROVIDER": provider,
                "TEST_EXIT_CODE": str(exit_code),
                "TEST_LOG_READY": str(root / "log-ready"),
                "TEST_CHILD_PID": str(root / "child-pid"),
                "TEST_JOB": json.dumps(
                    {"id": "fixture-job-0001", "prompt": "Test the fixture", "cwd": directory}
                ),
            }
            process = subprocess.Popen(
                ["bash", "-c", script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                self.assertNotIn(b"command not found", stderr)
                child = int((root / "child-pid").read_text())
                # The provider's exit alone ends the run: its child would hold
                # the output open for 30 seconds, far past this test's bound.
                # What the run left behind is then stopped with its process
                # group rather than kept in the worker's service.
                self.assertIn(b"left processes behind", stderr)
                self.assertFalse(running(child), "the run's leftover child survived")
                expected = "done" if exit_code == 0 else "failed"
                self.assertEqual((root / "reports").read_text().splitlines(), ["running", expected])
                self.assertEqual(
                    (root / "telemetry").read_text().splitlines()[-1:],
                    [json.dumps({"session_id": "fixture-session"}, separators=(",", ":"))],
                )
                logs = (root / "logs").read_text().splitlines()
                self.assertEqual(
                    sum(line.startswith("provider_stderr\tfixture diagnostic") for line in logs),
                    1,
                )
                output = (root / "fixture-job-0001.jsonl").read_text()
                self.assertIn("issuecomment-1", output)
                self.assertEqual(
                    (root / "fixture-job-0001.stderr").read_text(),
                    "fixture diagnostic without a final newline",
                )
            finally:
                # Only the isolated fixture's process group, never a live worker.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()

    def test_completed_providers_release_capacity_with_inherited_output_open(self):
        for provider in ("codex", "jcode", "claude"):
            with self.subTest(provider=provider):
                self.run_provider(provider, 0)

    def test_nonzero_exit_is_failed_even_when_output_contains_a_success_receipt(self):
        self.run_provider("jcode", 7)


if __name__ == "__main__":
    unittest.main()
