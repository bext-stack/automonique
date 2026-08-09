#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Run the R0-03 portable foreground generation lifecycle trial."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

from protocol import Endpoint, ProtocolError

HERE = pathlib.Path(__file__).resolve().parent
GENERATION = HERE / "generation.py"
BASE_RE = re.compile(r"^[0-9a-f]{40}$")


class TrialError(Exception):
    pass


class ManagedGeneration:
    def __init__(
        self,
        generation: str,
        behavior: str,
        timeout: float,
        transitions: list[dict[str, Any]],
    ) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        command = [
            sys.executable,
            str(GENERATION),
            "--control-fd",
            str(child.fileno()),
            "--generation",
            generation,
            "--behavior",
            behavior,
        ]
        try:
            self.process = subprocess.Popen(
                command,
                pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            child.close()
        self.generation = generation
        self.timeout = timeout
        self.transitions = transitions
        self.endpoint = Endpoint(parent)
        try:
            self.expect("started")
        except (OSError, ProtocolError, TrialError):
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=timeout)
            self.endpoint.close()
            raise

    def send(self, kind: str, **fields: object) -> None:
        self.endpoint.send({"type": kind, **fields})

    def expect(self, kind: str) -> dict[str, Any]:
        event = self.endpoint.receive(self.timeout)
        self.transitions.append(event)
        if event.get("generation") != self.generation:
            raise TrialError(f"event generation differs for {self.generation}")
        if event.get("pid") != self.process.pid:
            raise TrialError(f"event PID differs for {self.generation}")
        if event.get("type") != kind:
            raise TrialError(
                f"{self.generation} emitted {event.get('type')!r}, expected {kind!r}"
            )
        return event

    def command(self, kind: str, expected: str, **fields: object) -> dict[str, Any]:
        self.send(kind, **fields)
        return self.expect(expected)

    def probe(self) -> str:
        return str(self.command("probe", "state")["state"])

    def wait(self) -> int:
        try:
            return self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise TrialError(f"{self.generation} did not exit within timeout") from exc

    def cleanup(self) -> bool:
        """Return True only when the typed graceful path was sufficient."""
        graceful = True
        if self.process.poll() is None:
            try:
                self.send("shutdown")
                self.expect("stopping")
                self.expect("stopped")
                self.wait()
            except (OSError, ProtocolError, TrialError):
                graceful = False
        if self.process.poll() is None:
            graceful = False
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=self.timeout)
        self.endpoint.close()
        return graceful


def write_owner(path: pathlib.Path, generation: str, epoch: int, reason: str) -> None:
    document = {"active_generation": generation, "epoch": epoch, "reason": reason}
    temporary = path.with_suffix(".new")
    with temporary.open("w") as handle:
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def read_owner(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def run_trial(base: str, timeout: float) -> dict[str, Any]:
    if not BASE_RE.fullmatch(base):
        raise TrialError("base must be a full lowercase Git object ID")
    if not 0.1 <= timeout <= 30:
        raise TrialError("timeout must be between 0.1 and 30 seconds")

    transitions: list[dict[str, Any]] = []
    ownership: list[dict[str, Any]] = []
    generations: list[ManagedGeneration] = []
    checks: dict[str, bool] = {}
    active_sets: list[dict[str, Any]] = []
    cleanup_fallbacks: list[str] = []
    directory = pathlib.Path(tempfile.mkdtemp(prefix="automonique-r0-03-"))
    owner_path = directory / "owner.json"

    result: dict[str, Any] = {
        "schema": "automonique.r0-03-result/v1",
        "base": base,
        "environment": {
            "kernel": platform.release(),
            "python": platform.python_version(),
            "process_mode": "direct-foreground",
            "service_manager": None,
            "timeout_seconds": timeout,
        },
        "cleanup_plan": "typed shutdown, bounded wait, isolated process-group kill only on recorded failure, remove private temporary state",
        "checks": checks,
        "ownership": ownership,
        "active_sets": active_sets,
        "transitions": transitions,
    }

    def observe_active(label: str) -> list[str]:
        active = [
            generation.generation
            for generation in generations
            if generation.process.poll() is None and generation.probe() == "active"
        ]
        active_sets.append({"at": label, "generations": active})
        return active

    try:
        old = ManagedGeneration("fixture-old", "normal", timeout, transitions)
        generations.append(old)
        old.command("complete_warmup", "ready")
        old.command("activate", "active", epoch=1)
        write_owner(owner_path, old.generation, 1, "initial")
        ownership.append(read_owner(owner_path))
        checks["single_owner_initial"] = observe_active("initial") == [old.generation]

        pre = ManagedGeneration("fixture-pre-failure", "fail-before-ready", timeout, transitions)
        generations.append(pre)
        pre.send("complete_warmup")
        pre.expect("failed")
        checks["pre_ready_failure_exit"] = pre.wait() == 20
        checks["pre_ready_old_remains_active"] = old.probe() == "active"
        checks["pre_ready_owner_unchanged"] = read_owner(owner_path)["active_generation"] == old.generation
        checks["single_owner_after_pre_failure"] = observe_active("pre-failure") == [old.generation]

        post = ManagedGeneration("fixture-post-failure", "fail-after-ready", timeout, transitions)
        generations.append(post)
        checks["old_active_during_post_warmup"] = old.probe() == "active"
        post.command("complete_warmup", "ready")
        old.command("quiesce", "quiesced")
        checks["no_owner_while_post_candidate_fenced"] = observe_active("post-fenced") == []
        write_owner(owner_path, post.generation, 2, "post-ready-candidate")
        ownership.append(read_owner(owner_path))
        post.send("activate", epoch=2)
        post.expect("failed")
        checks["post_ready_failure_exit"] = post.wait() == 21
        write_owner(owner_path, old.generation, 3, "post-ready-fallback")
        ownership.append(read_owner(owner_path))
        old.command("activate", "active", epoch=3)
        checks["post_ready_owner_converged"] = (
            read_owner(owner_path)["active_generation"] == old.generation
            and old.probe() == "active"
        )
        checks["single_owner_after_post_fallback"] = observe_active("post-fallback") == [old.generation]

        new = ManagedGeneration("fixture-new", "normal", timeout, transitions)
        generations.append(new)
        checks["old_active_during_successful_warmup"] = old.probe() == "active"
        new.command("complete_warmup", "ready")
        old.command("quiesce", "quiesced")
        checks["no_owner_while_success_candidate_fenced"] = observe_active("success-fenced") == []
        write_owner(owner_path, new.generation, 4, "successful-handoff")
        ownership.append(read_owner(owner_path))
        new.command("activate", "active", epoch=4)
        old.send("drain")
        old.expect("draining")
        old.expect("drained")
        checks["old_drained_after_new_ready"] = old.wait() == 0
        checks["successful_owner"] = (
            read_owner(owner_path)["active_generation"] == new.generation
            and new.probe() == "active"
        )
        checks["single_owner_after_handoff"] = observe_active("successful-handoff") == [new.generation]
        checks["no_dual_active_owner"] = all(
            len(observation["generations"]) <= 1 for observation in active_sets
        )

        signal_started = time.monotonic()
        os.kill(new.process.pid, signal.SIGTERM)
        new.expect("stopping")
        new.expect("stopped")
        checks["signal_shutdown"] = new.wait() == 0
        result["signal_shutdown_ms"] = round(
            (time.monotonic() - signal_started) * 1000, 3
        )
        checks["typed_foreground_protocol"] = all(
            isinstance(event.get("type"), str) for event in transitions
        )
    except (OSError, ProtocolError, TrialError, json.JSONDecodeError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for generation in reversed(generations):
            if not generation.cleanup():
                cleanup_fallbacks.append(generation.generation)
        live = [generation.generation for generation in generations if generation.process.poll() is None]
        shutil.rmtree(directory)
        checks["cleanup"] = not live and not directory.exists() and not cleanup_fallbacks
        result["cleanup_fallbacks"] = cleanup_fallbacks
        result["status"] = "pass" if checks and all(checks.values()) and "error" not in result else "fail"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    try:
        result = run_trial(args.base, args.timeout)
    except TrialError as exc:
        result = {"schema": "automonique.r0-03-result/v1", "status": "fail", "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
