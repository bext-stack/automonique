#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Typed bounded execution for synthetic harness fixtures only."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import os
import pathlib
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


INTENT_SCHEMA = "automonique.build-intent/v1"
RESULT_SCHEMA = "automonique.build-result/v1"


class BuildError(Exception):
    """A typed build request cannot be executed safely."""


class HostCapabilityMissing(BuildError):
    """The host cannot prove a required aggregate ceiling before spawn."""


class BuildLimitRejected(BuildError):
    """The request is smaller than the fixed recipe's statically proven needs."""


class Recipe(str, enum.Enum):
    SUCCESS = "synthetic_success"
    WALL = "synthetic_wall_limit"
    CPU = "synthetic_cpu_limit"
    OUTPUT = "synthetic_output_limit"
    DISK = "synthetic_disk_limit"
    DESCENDANT = "synthetic_descendant_cleanup"


@dataclasses.dataclass(frozen=True)
class BuildLimits:
    wall_seconds: float
    cpu_seconds: int
    output_bytes: int
    process_count: int
    writable_bytes: int


@dataclasses.dataclass(frozen=True)
class BuildRequest:
    recipe: Recipe
    limits: BuildLimits

    def document(self) -> dict[str, Any]:
        return {
            "recipe": self.recipe.value,
            "limits": dataclasses.asdict(self.limits),
        }


@dataclasses.dataclass(frozen=True)
class _RecipeSpec:
    program: str
    maximum_processes: int
    maximum_files_per_process: int
    requires_proc: bool = False


_SPECS = {
    Recipe.SUCCESS: _RecipeSpec("import sys; sys.stdout.write('ok\\n')", 1, 0),
    Recipe.WALL: _RecipeSpec("import time; time.sleep(60)", 1, 0),
    Recipe.CPU: _RecipeSpec("while True: pass", 1, 0),
    Recipe.OUTPUT: _RecipeSpec(
        "import os\nb=b'x'*4096\nwhile True: os.write(1,b)", 1, 0
    ),
    Recipe.DISK: _RecipeSpec(
        "import os\nf=open('artifact.bin','wb',buffering=0)\n"
        "b=b'x'*4096\nwhile True: f.write(b)",
        1,
        1,
    ),
    Recipe.DESCENDANT: _RecipeSpec(
        "import signal,subprocess,sys,time\n"
        "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
        "print(c.pid,flush=True)\n"
        "def stop(*_):\n"
        " c.wait(timeout=2)\n"
        " raise SystemExit(143)\n"
        "signal.signal(signal.SIGTERM,stop)\n"
        "time.sleep(60)",
        2,
        0,
        requires_proc=True,
    ),
}


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _atomic_json(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read durable build state: {exc}") from exc
    if not isinstance(document, dict):
        raise BuildError("durable build state is not an object")
    return document


class BuildBroker:
    """Execute only fixed synthetic recipes under explicit resource ceilings."""

    def __init__(self, state_root: pathlib.Path, proc_root: pathlib.Path = pathlib.Path("/proc")):
        supplied = pathlib.Path(os.path.abspath(os.fspath(state_root)))
        current = pathlib.Path(supplied.anchor)
        for part in supplied.parts[1:]:
            current /= part
            if current.is_symlink():
                raise BuildError("build state path must not contain a symlink")
        self.state_root = supplied.resolve()
        self.proc_root = proc_root
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_root, 0o700)

    def _validate(self, request: BuildRequest) -> _RecipeSpec:
        if not isinstance(request.recipe, Recipe) or request.recipe not in _SPECS:
            raise BuildError("unknown synthetic build recipe")
        limits = request.limits
        if (
            not isinstance(limits.wall_seconds, (int, float))
            or not math.isfinite(limits.wall_seconds)
            or limits.wall_seconds <= 0
            or not isinstance(limits.cpu_seconds, int)
            or limits.cpu_seconds <= 0
            or not isinstance(limits.output_bytes, int)
            or limits.output_bytes < 0
            or not isinstance(limits.process_count, int)
            or limits.process_count <= 0
            or not isinstance(limits.writable_bytes, int)
            or limits.writable_bytes <= 0
        ):
            raise BuildLimitRejected("build limits must be finite positive typed values")
        spec = _SPECS[request.recipe]
        if limits.process_count < spec.maximum_processes:
            raise BuildLimitRejected(
                f"recipe requires a statically bounded {spec.maximum_processes} processes"
            )
        if limits.cpu_seconds % spec.maximum_processes:
            raise BuildLimitRejected(
                "aggregate CPU limit must divide across the fixed process ceiling"
            )
        for name in ("RLIMIT_CPU", "RLIMIT_FSIZE"):
            if not hasattr(resource, name):
                raise HostCapabilityMissing(f"host lacks {name}")
        if not hasattr(os, "killpg") or not hasattr(os, "setsid"):
            raise HostCapabilityMissing("host lacks process-group lifecycle controls")
        if spec.requires_proc and not (self.proc_root / "self/stat").is_file():
            raise HostCapabilityMissing("host lacks readable process accounting")
        return spec

    def operation_id(self, request: BuildRequest) -> str:
        self._validate(request)
        return _digest(request.document())

    def _operation_dir(self, operation_id: str) -> pathlib.Path:
        operations = self.state_root / "operations"
        if operations.is_symlink():
            raise BuildError("build operations path must not be a symlink")
        operations.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(operations, 0o700)
        operation = operations / operation_id
        if operation.is_symlink():
            raise BuildError("build operation path must not be a symlink")
        operation.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(operation, 0o700)
        return operation

    def _preexec(self, per_process_cpu: int, per_file_bytes: int) -> Any:
        def apply_limits() -> None:
            os.setsid()
            resource.setrlimit(resource.RLIMIT_CPU, (per_process_cpu, per_process_cpu))
            resource.setrlimit(resource.RLIMIT_FSIZE, (per_file_bytes, per_file_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return apply_limits

    def _process_count(self, process_group: int) -> int:
        count = 0
        try:
            entries = list(self.proc_root.iterdir())
        except OSError as exc:
            raise HostCapabilityMissing(f"process accounting became unavailable: {exc}") from exc
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(encoding="utf-8")
                closing = stat.rfind(")")
                fields = stat[closing + 2 :].split()
                group = int(fields[2])
            except (OSError, ValueError, IndexError):
                continue
            if group == process_group:
                count += 1
        return count

    @staticmethod
    def _directory_bytes(path: pathlib.Path) -> int:
        total = 0
        for candidate in path.rglob("*"):
            try:
                if candidate.is_file() and not candidate.is_symlink():
                    total += candidate.stat().st_size
            except FileNotFoundError:
                continue
        return total

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=0.5)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            raise BuildError("process group did not terminate after SIGKILL")

    def run(self, request: BuildRequest) -> dict[str, Any]:
        spec = self._validate(request)
        request_document = request.document()
        operation_id = _digest(request_document)
        operation_dir = self._operation_dir(operation_id)
        result_path = operation_dir / "result.json"
        intent_path = operation_dir / "intent.json"
        if result_path.exists():
            result = _load_json(result_path)
            if (
                result.get("schema") != RESULT_SCHEMA
                or result.get("operation_id") != operation_id
                or result.get("request_sha256") != operation_id
            ):
                raise BuildError("durable build result differs from the request")
            return result
        if intent_path.exists():
            intent = _load_json(intent_path)
            if intent.get("request_sha256") != operation_id:
                raise BuildError("durable build intent differs from the request")
            if intent.get("status") == "spawned":
                raise HostCapabilityMissing(
                    "an interrupted spawned build needs external PID-identity reconciliation"
                )
        else:
            _atomic_json(
                intent_path,
                {
                    "schema": INTENT_SCHEMA,
                    "status": "prepared",
                    "operation_id": operation_id,
                    "request": request_document,
                    "request_sha256": operation_id,
                },
            )

        work = pathlib.Path(tempfile.mkdtemp(prefix="work-", dir=operation_dir))
        os.chmod(work, 0o700)
        limits = request.limits
        per_process_cpu = limits.cpu_seconds // spec.maximum_processes
        per_file_bytes = max(1, limits.writable_bytes // max(1, spec.maximum_files_per_process))
        environment = {
            "PATH": os.path.dirname(sys.executable),
            "HOME": str(work),
            "TMPDIR": str(work),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        before_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        captured = bytearray()
        outcome: str | None = None
        peak_processes = 0
        peak_disk = 0
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-c", spec.program],
                cwd=work,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=False,
                preexec_fn=self._preexec(per_process_cpu, per_file_bytes),
            )
            _atomic_json(
                intent_path,
                {
                    "schema": INTENT_SCHEMA,
                    "status": "spawned",
                    "operation_id": operation_id,
                    "request": request_document,
                    "request_sha256": operation_id,
                    "pid": process.pid,
                },
            )
            selector = selectors.DefaultSelector()
            assert process.stdout is not None and process.stderr is not None
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while process.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= limits.wall_seconds:
                    outcome = "wall_limit"
                    break
                if spec.requires_proc:
                    peak_processes = max(peak_processes, self._process_count(process.pid))
                    if peak_processes > limits.process_count:
                        outcome = "process_limit"
                        break
                else:
                    peak_processes = max(peak_processes, 1)
                peak_disk = max(peak_disk, self._directory_bytes(work))
                if peak_disk > limits.writable_bytes:
                    outcome = "disk_limit"
                    break
                for key, _ in selector.select(timeout=min(0.02, limits.wall_seconds - elapsed)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = limits.output_bytes - len(captured)
                    if len(chunk) > remaining:
                        captured.extend(chunk[: max(0, remaining)])
                        outcome = "output_limit"
                        break
                    captured.extend(chunk)
                if outcome is not None:
                    break
            if outcome is not None:
                self._terminate_group(process)
            else:
                process.wait(timeout=1)
            for stream in (process.stdout, process.stderr):
                while len(captured) < limits.output_bytes:
                    chunk = os.read(stream.fileno(), min(65536, limits.output_bytes - len(captured)))
                    if not chunk:
                        break
                    captured.extend(chunk)
            selector.close()
            process.stdout.close()
            process.stderr.close()
            peak_disk = max(peak_disk, self._directory_bytes(work))
            if outcome is None:
                if request.recipe is Recipe.CPU and process.returncode != 0:
                    outcome = "cpu_limit"
                elif request.recipe is Recipe.DISK and process.returncode != 0:
                    outcome = "disk_limit"
                elif process.returncode == 0:
                    outcome = "success"
                else:
                    outcome = "failed"
        finally:
            if process is not None:
                self._terminate_group(process)

        elapsed = time.monotonic() - started
        after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_seconds = max(
            0.0,
            (after_usage.ru_utime + after_usage.ru_stime)
            - (before_usage.ru_utime + before_usage.ru_stime),
        )
        return_code = process.returncode if process is not None else None
        shutil.rmtree(work)
        result = {
            "schema": RESULT_SCHEMA,
            "operation_id": operation_id,
            "request_sha256": operation_id,
            "recipe": request.recipe.value,
            "outcome": outcome,
            "return_code": return_code,
            "stdout_stderr": captured.decode("utf-8", "replace"),
            "attestation": {
                "wall_seconds": round(elapsed, 6),
                "wall_limit": limits.wall_seconds,
                "cpu_seconds": round(cpu_seconds, 6),
                "cpu_aggregate_limit": limits.cpu_seconds,
                "cpu_enforcement": "RLIMIT_CPU divided across statically bounded recipe processes",
                "captured_output_bytes": len(captured),
                "captured_output_limit": limits.output_bytes,
                "peak_process_count": peak_processes,
                "process_limit": limits.process_count,
                "process_bound": spec.maximum_processes,
                "peak_writable_bytes": peak_disk,
                "writable_limit": limits.writable_bytes,
                "writable_enforcement": "RLIMIT_FSIZE plus private-directory accounting for fixed recipe files",
                "environment": "scrubbed",
                "process_group_cleanup": "TERM-then-KILL",
            },
        }
        _atomic_json(result_path, result)
        _atomic_json(
            intent_path,
            {
                "schema": INTENT_SCHEMA,
                "status": "completed",
                "operation_id": operation_id,
                "request": request_document,
                "request_sha256": operation_id,
                "result_sha256": _digest(result),
            },
        )
        return result
