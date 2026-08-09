#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Fixed synthetic workload and grandchild for the R0-04 fixture."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

HOST_RE = re.compile(r"^host-[0-9a-f]{16}$")
HERE = pathlib.Path(__file__).resolve().parent


def write_json_atomic(path: pathlib.Path, document: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w") as handle:
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def wait_for(path: pathlib.Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path.name}")
        time.sleep(0.01)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("workload", "grandchild"), required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--tree-path", type=pathlib.Path, required=True)
    parser.add_argument("--ready-path", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not HOST_RE.fullmatch(args.host_id):
        parser.error("host ID must be an opaque host- plus 16 lowercase hex characters")

    stopping = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    if args.role == "grandchild":
        write_json_atomic(
            args.ready_path,
            {
                "host_id": args.host_id,
                "grandchild_pid": os.getpid(),
                "process_group": os.getpgrp(),
            },
        )
        while not stopping:
            signal.pause()
        return 0

    command = [
        sys.executable,
        str(HERE / "workload.py"),
        "--role",
        "grandchild",
        "--host-id",
        args.host_id,
        "--tree-path",
        str(args.tree_path),
        "--ready-path",
        str(args.ready_path),
    ]
    grandchild = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        wait_for(args.ready_path, 5)
        ready = json.loads(args.ready_path.read_text())
        if ready.get("grandchild_pid") != grandchild.pid:
            return 65
        if ready.get("process_group") != os.getpgrp():
            return 66
        write_json_atomic(
            args.tree_path,
            {
                "host_id": args.host_id,
                "worker_pid": os.getpid(),
                "grandchild_pid": grandchild.pid,
                "process_group": os.getpgrp(),
            },
        )
        while not stopping:
            signal.pause()
    finally:
        if grandchild.poll() is None:
            grandchild.send_signal(signal.SIGTERM)
        try:
            grandchild.wait(timeout=2)
        except subprocess.TimeoutExpired:
            grandchild.kill()
            grandchild.wait(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
