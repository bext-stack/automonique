#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Run the R0-04 execution-host ownership and reconnect trial."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

from protocol import Endpoint

HERE = pathlib.Path(__file__).resolve().parent
RUNNER = HERE / "runner.py"
BASE_RE = re.compile(r"^[0-9a-f]{40}$")


class TrialError(Exception):
    pass


def read_state(path: pathlib.Path, expected: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        try:
            state = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            state = None
        if isinstance(state, dict) and state.get("state") == expected:
            return state
        if time.monotonic() >= deadline:
            observed = state.get("state") if isinstance(state, dict) else None
            raise TrialError(f"timed out waiting for {expected}; observed {observed}")
        time.sleep(0.01)


def connect(directory: pathlib.Path, registry: dict[str, Any], timeout: float) -> Endpoint:
    socket_name = registry.get("control_socket")
    if not isinstance(socket_name, str) or pathlib.Path(socket_name).name != socket_name:
        raise TrialError("registry control socket is not a local basename")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(str(directory / socket_name))
    return Endpoint(connection, timeout)


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def group_alive(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_owned_group(process_group: int, timeout: float) -> bool:
    """Return True when SIGKILL was needed for a recorded fixture group."""
    if not group_alive(process_group):
        return False
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = time.monotonic() + timeout
    while group_alive(process_group) and time.monotonic() < deadline:
        time.sleep(0.01)
    if not group_alive(process_group):
        return False
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return False
    return True


def fixed_runner_command(
    directory: pathlib.Path, host_id: str, behavior: str, timeout: float
) -> list[str]:
    return [
        sys.executable,
        str(RUNNER),
        "--directory",
        str(directory),
        "--host-id",
        host_id,
        "--behavior",
        behavior,
        "--timeout",
        str(timeout),
    ]


def start_runner(
    directory: pathlib.Path, host_id: str, behavior: str, timeout: float
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        fixed_runner_command(directory, host_id, behavior, timeout),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def run_trial(base: str, timeout: float) -> dict[str, Any]:
    if not BASE_RE.fullmatch(base):
        raise TrialError("base must be a full lowercase Git object ID")
    if not 0.1 <= timeout <= 30:
        raise TrialError("timeout must be between 0.1 and 30 seconds")

    checks: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    runners: list[tuple[str, pathlib.Path, subprocess.Popen[bytes]]] = []
    cleanup_fallbacks: list[str] = []
    root = pathlib.Path(tempfile.mkdtemp(prefix="automonique-r0-04-"))
    os.chmod(root, 0o700)
    result: dict[str, Any] = {
        "schema": "automonique.r0-04-result/v1",
        "base": base,
        "environment": {
            "kernel": platform.release(),
            "python": platform.python_version(),
            "backend": "direct-process",
            "timeout_seconds": timeout,
            "service_manager": None,
            "privileged": False,
        },
        "checks": checks,
        "observations": observations,
    }
    try:
        normal_dir = root / "normal"
        normal_dir.mkdir(mode=0o700)
        host_id = "host-" + secrets.token_hex(8)
        runner = start_runner(normal_dir, host_id, "normal", timeout)
        runners.append((host_id, normal_dir, runner))
        registry_path = normal_dir / "registry.json"
        initial = read_state(registry_path, "running", timeout)
        descendants = initial.get("descendant_pids")
        if not isinstance(descendants, list) or len(descendants) != 2:
            raise TrialError("registry did not name exactly two descendants")
        if not all(isinstance(pid, int) for pid in descendants):
            raise TrialError("registry descendant PIDs are invalid")

        first = connect(normal_dir, initial, timeout)
        first.send({"type": "status"})
        first_status = first.receive()
        first.close()
        checks["initial_controller_observed"] = (
            first_status.get("type") == "status"
            and first_status.get("host_id") == host_id
            and first_status.get("state") == "running"
        )
        checks["runner_survived_disconnect"] = runner.poll() is None

        rediscovered = json.loads(registry_path.read_text())
        second = connect(normal_dir, rediscovered, timeout)
        second.send({"type": "status"})
        second_status = second.receive()
        checks["reconnect_same_host"] = (
            second_status.get("host_id") == host_id
            and second_status.get("runner_pid") == runner.pid
            and second_status.get("descendant_pids") == descendants
        )
        checks["discoverable_owned_tree"] = (
            rediscovered.get("host_id") == host_id
            and rediscovered.get("process_group") == descendants[0]
            and all(pid_alive(pid) for pid in descendants)
        )
        capabilities = second_status.get("capabilities", {})
        optional_names = ("cgroup", "systemd", "container", "remote_executor")
        checks["optional_capabilities_null"] = all(
            capabilities.get(name, {}).get("available") is None
            and capabilities.get(name, {}).get("reason")
            for name in optional_names
        )
        observations["optional_capabilities"] = {
            name: capabilities.get(name) for name in optional_names
        }
        checks["protected_local_state"] = (
            normal_dir.stat().st_mode & 0o077 == 0
            and registry_path.stat().st_mode & 0o077 == 0
            and (normal_dir / "control.sock").stat().st_mode & 0o077 == 0
        )
        second.close()

        cancellation = connect(normal_dir, rediscovered, timeout)
        cancellation.send({"type": "cancel"})
        cancelled = cancellation.receive()
        cancellation.close()
        runner_exit = runner.wait(timeout=timeout)
        cancellation_ms = cancelled.get("cancellation_ms")
        checks["typed_cancel"] = (
            cancelled.get("type") == "cancelled"
            and cancelled.get("state") == "cancelled"
            and runner_exit == 0
        )
        checks["all_descendants_stopped"] = not any(pid_alive(pid) for pid in descendants)
        checks["cancel_without_escalation"] = cancelled.get("cleanup_escalated") is False
        observations["cancellation_ms"] = cancellation_ms
        observations["descendant_count"] = len(descendants)
        observations["peer_check"] = second_status.get("peer_check")

        failure_dir = root / "failure"
        failure_dir.mkdir(mode=0o700)
        failure_host = "host-" + secrets.token_hex(8)
        failed_runner = start_runner(failure_dir, failure_host, "fail-launch", timeout)
        runners.append((failure_host, failure_dir, failed_runner))
        failed = read_state(failure_dir / "registry.json", "failed", timeout)
        failure_exit = failed_runner.wait(timeout=timeout)
        checks["launch_failure_truthful"] = (
            failure_exit == 20
            and failed.get("worker_pid") is None
            and failed.get("descendant_pids") == []
            and failed.get("control_socket") is None
            and not (failure_dir / "control.sock").exists()
        )
        observations["launch_failure_exit"] = failure_exit
    except (OSError, TrialError, json.JSONDecodeError, TimeoutError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for host_id, directory, runner in reversed(runners):
            if runner.poll() is None:
                cleanup_fallbacks.append(host_id)
                os.killpg(runner.pid, signal.SIGTERM)
                try:
                    runner.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(runner.pid, signal.SIGKILL)
                    runner.wait(timeout=timeout)
            try:
                registry = json.loads((directory / "registry.json").read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                registry = {}
            process_group = registry.get("process_group")
            if isinstance(process_group, int) and group_alive(process_group):
                if host_id not in cleanup_fallbacks:
                    cleanup_fallbacks.append(host_id)
                stop_owned_group(process_group, timeout)
        live_runners = [
            host_id for host_id, _directory, runner in runners if runner.poll() is None
        ]
        shutil.rmtree(root)
        checks["cleanup"] = (
            not live_runners and not cleanup_fallbacks and not root.exists()
        )
        result["cleanup_fallbacks"] = cleanup_fallbacks
        result["status"] = (
            "pass" if checks and all(checks.values()) and "error" not in result else "fail"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    try:
        result = run_trial(args.base, args.timeout)
    except TrialError as exc:
        result = {
            "schema": "automonique.r0-04-result/v1",
            "status": "fail",
            "error": str(exc),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
