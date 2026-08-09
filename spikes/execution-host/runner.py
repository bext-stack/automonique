#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Synthetic reconnectable execution host for the R0-04 fixture."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Any

from protocol import Endpoint, ProtocolError

HERE = pathlib.Path(__file__).resolve().parent
HOST_RE = re.compile(r"^host-[0-9a-f]{16}$")


def write_json_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w") as handle:
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_json_when_ready(path: pathlib.Path, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        try:
            document = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for {path.name}")
            time.sleep(0.01)
            continue
        if not isinstance(document, dict):
            raise ValueError(f"{path.name} must contain an object")
        return document


def peer_is_same_user(connection: socket.socket) -> bool | None:
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid == os.getuid()


def stop_process_group(process: subprocess.Popen[bytes], timeout: float) -> tuple[bool, int]:
    escalated = False
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        escalated = True
        os.killpg(process.pid, signal.SIGKILL)
        exit_code = process.wait(timeout=timeout)
    return escalated, exit_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--behavior", choices=("normal", "fail-launch"), default="normal")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if not HOST_RE.fullmatch(args.host_id):
        parser.error("host ID must be an opaque host- plus 16 lowercase hex characters")
    if not 0.1 <= args.timeout <= 30:
        parser.error("timeout must be between 0.1 and 30 seconds")
    if args.directory.stat().st_mode & 0o077:
        parser.error("directory must not be accessible to group or other users")

    registry_path = args.directory / "registry.json"
    socket_path = args.directory / "control.sock"
    tree_path = args.directory / "tree.json"
    ready_path = args.directory / "grandchild-ready.json"
    capabilities = {
        "process_group": {"available": True, "reason": "measured by the fixture"},
        "cgroup": {"available": None, "reason": "not probed or mutated"},
        "systemd": {"available": None, "reason": "not queried or required"},
        "container": {"available": None, "reason": "no container runtime used"},
        "remote_executor": {"available": None, "reason": "no remote executor used"},
    }
    base_status: dict[str, Any] = {
        "schema": "automonique.execution-host-status/v1",
        "host_id": args.host_id,
        "runner_pid": os.getpid(),
        "environment": {
            "kernel": platform.release(),
            "python": platform.python_version(),
            "backend": "direct-process",
        },
        "capabilities": capabilities,
    }
    if args.behavior == "fail-launch":
        write_json_atomic(
            registry_path,
            {
                **base_status,
                "state": "failed",
                "worker_pid": None,
                "descendant_pids": [],
                "control_socket": None,
                "failure": "synthetic-launch-failure",
            },
        )
        return 20

    terminating = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal terminating
        terminating = True

    signal.signal(signal.SIGTERM, request_stop)
    workload_command = [
        sys.executable,
        str(HERE / "workload.py"),
        "--role",
        "workload",
        "--host-id",
        args.host_id,
        "--tree-path",
        str(tree_path),
        "--ready-path",
        str(ready_path),
    ]
    workload = subprocess.Popen(
        workload_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    listener: socket.socket | None = None
    exit_code = 0
    try:
        tree = read_json_when_ready(tree_path, args.timeout)
        if tree.get("host_id") != args.host_id:
            raise ValueError("tree host ID differs")
        if tree.get("worker_pid") != workload.pid:
            raise ValueError("tree worker PID differs")
        if tree.get("process_group") != workload.pid:
            raise ValueError("workload is not its own process-group leader")
        descendants = [workload.pid, tree.get("grandchild_pid")]
        if not all(isinstance(pid, int) and pid > 1 for pid in descendants):
            raise ValueError("tree contains invalid descendant PID")
        status = {
            **base_status,
            "state": "running",
            "worker_pid": workload.pid,
            "process_group": workload.pid,
            "descendant_pids": descendants,
            "control_socket": socket_path.name,
            "peer_check": "same-uid" if hasattr(socket, "SO_PEERCRED") else None,
        }
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(4)
        listener.settimeout(0.1)
        write_json_atomic(registry_path, status)

        cancelled = False
        while not cancelled and not terminating:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                if workload.poll() is not None:
                    raise RuntimeError("workload exited before cancellation")
                continue
            with connection:
                peer_result = peer_is_same_user(connection)
                if peer_result is False:
                    continue
                endpoint = Endpoint(connection, args.timeout)
                try:
                    request = endpoint.receive()
                    if request["type"] == "status":
                        endpoint.send({"type": "status", **status})
                    elif request["type"] == "cancel":
                        started = time.monotonic()
                        status = {**status, "state": "cancelling"}
                        write_json_atomic(registry_path, status)
                        escalated, worker_exit = stop_process_group(workload, args.timeout)
                        status = {
                            **status,
                            "state": "cancelled",
                            "worker_exit": worker_exit,
                            "cleanup_escalated": escalated,
                            "cancellation_ms": round(
                                (time.monotonic() - started) * 1000, 3
                            ),
                        }
                        write_json_atomic(registry_path, status)
                        endpoint.send({"type": "cancelled", **status})
                        cancelled = True
                    else:
                        endpoint.send(
                            {"type": "error", "error": "unsupported-request"}
                        )
                except ProtocolError:
                    continue
        if terminating and workload.poll() is None:
            stop_process_group(workload, args.timeout)
            exit_code = 143
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        if workload.poll() is None:
            stop_process_group(workload, args.timeout)
        write_json_atomic(
            registry_path,
            {
                **base_status,
                "state": "failed",
                "worker_pid": workload.pid,
                "descendant_pids": [],
                "control_socket": None,
                "failure": type(exc).__name__,
            },
        )
        exit_code = 64
    finally:
        if listener is not None:
            listener.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
