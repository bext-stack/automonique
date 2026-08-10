#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Admission and bounded execution helpers over the generated development DAG."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import signal
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import git_broker, guides, local_integration, program  # noqa: E402
from plan import baseline as plan_baseline  # noqa: E402
from plan import gate as gate_module  # noqa: E402

STATE_SCHEMA = "automonique.harness-loop-state/v1"
PACKET_SCHEMA = "automonique.harness-objective-packet/v1"
RECOVERY_SNAPSHOT_SCHEMA = "automonique.harness-recovery-snapshot/v1"
RECOVERY_INTENT_SCHEMA = "automonique.harness-recovery-intent/v1"
RECOVERY_RECEIPT_SCHEMA = "automonique.harness-recovery-receipt/v1"
TERMINAL_STATUSES = frozenset({"integrated_and_pushed", "stopped"})
CHECKABLE_SESSION_STATUSES = frozenset({"claimed", "candidate_ready"})
CLAIMED_SESSION_STATE_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "driver",
        "work_id",
        "base",
        "branch",
        "status",
        "packet",
        "iteration",
        "failures",
        "unchanged_results",
        "stop_reason",
        "started_at",
        "deadline_at",
        "updated_at",
        "packet_sha256",
    }
)
RECOVERABLE_STOP_STATE_FIELDS = CLAIMED_SESSION_STATE_FIELDS | frozenset(
    {"candidate_paths", "last_tree_digest", "candidate_tree", "checked_at"}
)


class LoopError(Exception):
    """The harness loop cannot safely admit or continue work."""


def git(*args: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=text, check=True
    )
    return completed.stdout.strip() if text else completed.stdout


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        try:
            label = path.relative_to(ROOT)
        except ValueError:
            label = path
        raise LoopError(f"cannot read {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise LoopError(f"{path} root is not an object")
    return document


def write_json_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(
        path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def parse_utc_seconds(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise LoopError(f"{label} is invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+00:00").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise LoopError(f"{label} is invalid") from exc
    if parsed.isoformat(timespec="seconds") != value:
        raise LoopError(f"{label} is invalid")
    return parsed


def valid_identifier(value: Any, maximum: int, allow_dot: bool = False) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value[0].isalnum()
        and value[0].isascii()
        and all(
            character.isascii()
            and (character.isalnum() or character in "_-" or (allow_dot and character == "."))
            for character in value
        )
    )


def valid_branch(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 255
        and not value.startswith(("/", ".", "-"))
        and not value.endswith(("/", "."))
        and ".." not in value
        and "//" not in value
        and all(
            character.isascii() and (character.isalnum() or character in "/._-")
            for character in value
        )
    )


def valid_repo_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value.encode()) > 4096:
        return False
    path = pathlib.PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and all(part not in ("", ".", "..") for part in path.parts)
        and not value.endswith("/")
        and not any(character == "\x00" or ord(character) < 32 for character in value)
    )


def require_exact_fields(
    document: dict[str, Any], fields: frozenset[str], label: str
) -> None:
    actual = frozenset(document)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise LoopError(f"{label} fields differ: {'; '.join(details)}")


def load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _, _, errors = guides.verify()
    if errors:
        raise LoopError("guide/objective verification failed: " + "; ".join(errors[:4]))
    program_document = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
    objectives = load_json(guides.OBJECTIVES)
    config = load_json(guides.LOOP_CONFIG)
    if config.get("schema") != guides.LOOP_SCHEMA:
        raise LoopError("loop configuration schema differs")
    if config.get("max_workers") != 1:
        raise LoopError("bootstrap loop requires exactly one worker")
    drivers = config.get("drivers")
    session = drivers.get("codex_session") if isinstance(drivers, dict) else None
    if config.get("default_driver") != "codex_session" or not isinstance(
        session, dict
    ):
        raise LoopError("loop configuration must define the Codex session driver")
    if session.get("max_concurrent_subagents") != 3:
        raise LoopError("Codex session driver requires a three-subagent ceiling")
    return program_document, objectives, config


def objective_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["work_id"]: entry for entry in document.get("objectives", [])}


def owner_blocked_reason(item_id: str) -> str | None:
    """Why an item cannot be finished by a worker, from its own evidence.

    An item records `external_completion_check` with a null result when the
    last step needs something outside worker authority — an owner-held secret,
    an external approval. Autonomous selection must route around those, or the
    loop re-claims the same unfinishable item forever.
    """
    path = ROOT / "plan" / "evidence" / f"{item_id}.json"
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    check = document.get("external_completion_check")
    if not isinstance(check, dict) or check.get("result") is not None:
        return None
    reason = check.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()
    return "an external completion check is recorded unresolved"


def eligible_items(
    program_document: dict[str, Any], objective_document: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    objectives = objective_map(objective_document)
    eligible: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in program_document.get("items", []):
        objective = objectives.get(item.get("id"))
        if item.get("runnable") and objective and objective.get("autonomous_eligible"):
            if owner_blocked_reason(item.get("id")):
                continue
            eligible.append((item, objective))
    return eligible


def select_item(
    program_document: dict[str, Any],
    objective_document: dict[str, Any],
    requested: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    eligible = eligible_items(program_document, objective_document)
    if requested is None:
        if not eligible:
            raise LoopError("no score-eligible runnable work item exists")
        return eligible[0]
    objectives = objective_map(objective_document)
    item = next(
        (entry for entry in program_document.get("items", []) if entry.get("id") == requested),
        None,
    )
    if item is None:
        raise LoopError(f"unknown work item {requested}")
    objective = objectives.get(requested)
    if objective is None:
        raise LoopError(f"work item {requested} has no validated objective")
    if not item.get("runnable"):
        raise LoopError(f"work item {requested} is not runnable")
    if not objective.get("autonomous_eligible"):
        score = objective.get("hill_climbability")
        raise LoopError(
            f"work item {requested} score {score} is below the autonomous threshold"
        )
    blocked = owner_blocked_reason(requested)
    if blocked:
        # Explicit request still proceeds: a driver may legitimately work a
        # blocked item's remaining slice. Only automatic selection routes away.
        print(
            f"note: {requested} cannot be completed by a worker — {blocked}",
            file=sys.stderr,
        )
    return item, objective


def parse_porcelain_z(output: bytes) -> list[str]:
    entries = output.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise LoopError("cannot parse Git porcelain status entry")
        status = entry[:2]
        paths.append(os.fsdecode(entry[3:]))
        if b"R" in status or b"C" in status:
            if index >= len(entries) or not entries[index]:
                raise LoopError("Git rename/copy status is missing its source path")
            paths.append(os.fsdecode(entries[index]))
            index += 1
    return paths


def porcelain_paths() -> list[str]:
    output = git("status", "--porcelain=v1", "-z", "--untracked-files=all", text=False)
    assert isinstance(output, bytes)
    return parse_porcelain_z(output)


def path_is_leased(path: str, allowed_paths: list[str]) -> bool:
    return any(
        path.startswith(allowed)
        if allowed.endswith("/")
        else path == allowed
        for allowed in allowed_paths
    )


def lease_errors(paths: list[str], allowed_paths: list[str]) -> list[str]:
    return sorted(path for path in paths if not path_is_leased(path, allowed_paths))


def tree_fingerprint(paths: list[str]) -> str:
    digest = hashlib.sha256()
    diff = git("diff", "--binary", "--no-ext-diff", text=False)
    assert isinstance(diff, bytes)
    digest.update(diff)
    for relative in sorted(paths):
        digest.update(os.fsencode(relative))
        path = ROOT / relative
        try:
            status = path.lstat()
        except FileNotFoundError:
            digest.update(b"missing")
            continue
        digest.update(str(status.st_mode).encode())
        if path.is_symlink():
            digest.update(os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def candidate_snapshot_matches(
    state: dict[str, Any], paths: list[str], digest: str, tree: str
) -> bool:
    expected_paths = state.get("candidate_paths")
    expected_digest = state.get("last_tree_digest")
    return (
        isinstance(expected_paths, list)
        and all(isinstance(path, str) for path in expected_paths)
        and sorted(paths) == sorted(expected_paths)
        and digest == expected_digest
        and tree == state.get("candidate_tree")
    )


def exact_candidate_tree(
    state: dict[str, Any], packet: dict[str, Any], config: dict[str, Any], paths: list[str]
) -> str:
    objective = packet.get("objective")
    allowed_paths = objective.get("allowed_paths") if isinstance(objective, dict) else None
    if not isinstance(allowed_paths, list) or not all(
        isinstance(path, str) for path in allowed_paths
    ):
        raise LoopError("objective packet lacks a typed path lease")
    broker = git_broker.CandidateBroker(ROOT, (ROOT / config["state_path"]).parent)
    return broker.snapshot(
        expected_base=state["base"],
        expected_branch=state["branch"],
        allowed_paths=tuple(allowed_paths),
        candidate_paths=tuple(sorted(paths)),
    )


def run_check(argv: list[str]) -> bool:
    print(f"check: {' '.join(argv)}", flush=True)
    return subprocess.run(argv, cwd=ROOT, check=False).returncode == 0


def terminate_group(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run_worker(argv: list[str], timeout: int) -> tuple[int | None, str | None]:
    process = subprocess.Popen(
        argv, cwd=ROOT, stdin=subprocess.DEVNULL, start_new_session=True
    )
    try:
        return process.wait(timeout=timeout), None
    except subprocess.TimeoutExpired:
        terminate_group(process)
        return None, "worker_timeout"
    except KeyboardInterrupt:
        terminate_group(process)
        raise


def worker_argv(explicit_argv: list[str], packet: pathlib.Path) -> list[str]:
    if not explicit_argv or any(not argument for argument in explicit_argv):
        raise LoopError("run requires a non-empty explicit worker argument vector")
    return [*explicit_argv, str(packet)]


def sandbox_worker_argv(
    explicit_argv: list[str], packet: pathlib.Path, allowed_paths: list[str]
) -> list[str]:
    binary = shutil.which("bwrap")
    if binary is None:
        raise LoopError("worker execution requires the configured bwrap sandbox")
    home = pathlib.Path.home().resolve()
    root = ROOT.resolve()
    try:
        relative_root = root.relative_to(home)
    except ValueError as exc:
        raise LoopError("repository must be below the hidden worker home") from exc
    argv = [
        binary,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        str(home),
    ]
    current = home
    for part in relative_root.parts:
        current /= part
        argv.extend(["--dir", str(current)])
    argv.extend(
        [
            "--ro-bind",
            str(root),
            str(root),
            "--tmpfs",
            str(root / ".git"),
        ]
    )
    for allowed in allowed_paths:
        target = root / allowed.rstrip("/")
        if not target.exists():
            raise LoopError(f"writable lease path does not exist: {allowed}")
        if target.is_symlink():
            raise LoopError(f"writable lease path is a symlink: {allowed}")
        argv.extend(["--bind", str(target), str(target)])
    argv.extend(
        [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--chdir",
            str(root),
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "LANG",
            "C.UTF-8",
            *worker_argv(explicit_argv, packet),
        ]
    )
    return argv


def stop_reason(
    *,
    exit_code: int | None,
    checks_passed: bool,
    changed: bool,
    iteration: int,
    failures: int,
    unchanged_results: int,
    elapsed_seconds: float,
    budget: dict[str, int],
) -> str | None:
    if not checks_passed:
        return "safety_check_failed"
    if exit_code == 0 and changed:
        return "candidate_ready"
    if unchanged_results >= budget["max_unchanged_results"]:
        return "unchanged_evidence"
    if failures >= budget["max_failures"]:
        return "failure_budget"
    if elapsed_seconds >= budget["max_wall_seconds"]:
        return "wall_budget"
    if iteration >= budget["max_iterations"]:
        return "iteration_budget"
    return None


def packet_document(
    run_id: str,
    iteration: int,
    base: str,
    item: dict[str, Any],
    objective: dict[str, Any],
    config: dict[str, Any],
    prior: dict[str, Any] | None,
    driver: str = "local_process",
) -> dict[str, Any]:
    guides_digest = file_sha256(guides.GUIDE_MANIFEST)
    objectives_digest = file_sha256(guides.OBJECTIVES)
    program_digest = file_sha256(program.DEFAULT_PROGRAM)
    packet = {
        "schema": PACKET_SCHEMA,
        "run_id": run_id,
        "driver": driver,
        "iteration": iteration,
        "immutable_base": base,
        "work_item": item,
        "objective": objective,
        "attempt_baseline": {
            "git_head": base,
            "worktree_clean": True,
            "admission_safety_checks": "pass",
            "guides_sha256": guides_digest,
            "objectives_sha256": objectives_digest,
            "program_sha256": program_digest,
        },
        "guides_sha256": guides_digest,
        "objectives_sha256": objectives_digest,
        "program_sha256": program_digest,
        "integration_ceiling": config["integration_ceiling"],
        "prior_iteration": prior,
    }
    if driver == "codex_session":
        session = config["drivers"]["codex_session"]
        packet["session_coordination"] = {
            "primary_role": "coordinate, integrate, verify, and report",
            "native_subagents": session["native_subagents"],
            "max_concurrent_subagents": session["max_concurrent_subagents"],
            "recursive_agent_trees": session["recursive_agent_trees"],
            "concurrent_writes": session["concurrent_writes"],
            "integration_owner": session["integration_owner"],
            "subagent_prompt_fields": [
                "bounded objective",
                "allowed paths",
                "required checks",
                "return evidence",
            ],
        }
    else:
        packet["worker_interface"] = (
            "this packet path is the final explicit argv element"
        )
    return packet


def print_next(item: dict[str, Any], objective: dict[str, Any]) -> None:
    print(
        json.dumps(
            {
                "work_id": item["id"],
                "recommended_driver": "codex_session",
                "title": item["title"],
                "hill_climbability": objective["hill_climbability"],
                "objective": objective["objective"],
                "allowed_paths": objective["allowed_paths"],
                "budget": objective["budget"],
                "tests": objective["tests"],
                "stop_conditions": objective["stop_conditions"],
            },
            indent=2,
        )
    )


def acquire_loop_lock(config: dict[str, Any]) -> Any:
    state_path = ROOT / config["state_path"]
    lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("w")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise LoopError("another harness loop already owns the single-worker lock") from exc
    return handle


def state_path(config: dict[str, Any]) -> pathlib.Path:
    return ROOT / config["state_path"]


def read_state(config: dict[str, Any]) -> dict[str, Any] | None:
    path = state_path(config)
    return load_json(path) if path.exists() else None


def refuse_active_attempt(config: dict[str, Any]) -> None:
    state = read_state(config)
    if state is not None and state.get("status") not in TERMINAL_STATUSES:
        raise LoopError(
            f"active {state.get('driver', 'unknown')} attempt {state.get('run_id')} "
            f"already owns work item {state.get('work_id')}"
        )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_safety_checks(config: dict[str, Any], phase: str) -> None:
    for argv in config["safety_checks"]:
        if not run_check(argv):
            raise LoopError(f"{phase} safety check failed: {argv}")


def recovery_paths(
    config: dict[str, Any], run_id: str
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    if (
        not run_id.startswith("session_")
        or len(run_id) > 64
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
               for character in run_id)
    ):
        raise LoopError("recovery run ID is invalid")
    recovery_root = state_path(config).parent / "recoveries"
    operation = recovery_root / run_id
    if recovery_root.is_symlink() or operation.is_symlink():
        raise LoopError("recovery state path is a symlink")
    paths = (
        operation / "stop-snapshot.json",
        operation / "intent.json",
        operation / "receipt.json",
    )
    if any(path.is_symlink() or path.with_suffix(path.suffix + ".new").is_symlink() for path in paths):
        raise LoopError("recovery journal path is a symlink")
    return paths


def recovery_packet_path(state: dict[str, Any]) -> pathlib.Path:
    relative = state.get("packet")
    if not isinstance(relative, str):
        raise LoopError("stopped session packet path is invalid")
    packet_path = pathlib.Path(relative)
    if packet_path.is_absolute() or ".." in packet_path.parts:
        raise LoopError("stopped session packet escapes the repository")
    resolved = (ROOT / packet_path).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise LoopError("stopped session packet escapes the repository") from exc
    if resolved != ROOT / packet_path:
        raise LoopError("stopped session packet traverses a symlink")
    expected = pathlib.Path(".automonique/state/runs") / state["run_id"] / "packet.json"
    if packet_path != expected:
        raise LoopError("stopped session packet path is not its admitted run packet")
    return resolved


def validated_safety_checks(config: dict[str, Any]) -> list[list[str]]:
    checks = config.get("safety_checks")
    if (
        not isinstance(checks, list)
        or not checks
        or any(
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) or not argument for argument in argv)
            for argv in checks
        )
    ):
        raise LoopError("recovery safety checks are not fixed explicit argument vectors")
    return [list(argv) for argv in checks]


def validate_recoverable_state(state: dict[str, Any]) -> None:
    actual_fields = frozenset(state)
    if actual_fields not in (
        CLAIMED_SESSION_STATE_FIELDS,
        RECOVERABLE_STOP_STATE_FIELDS,
    ):
        unexpected = sorted(actual_fields - RECOVERABLE_STOP_STATE_FIELDS)
        missing = sorted(CLAIMED_SESSION_STATE_FIELDS - actual_fields)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        if not details:
            details.append("candidate snapshot fields are incomplete")
        raise LoopError("stopped session state fields differ: " + "; ".join(details))
    required_types: dict[str, type[Any]] = {
        "schema": str,
        "run_id": str,
        "driver": str,
        "work_id": str,
        "base": str,
        "branch": str,
        "status": str,
        "packet": str,
        "iteration": int,
        "failures": int,
        "unchanged_results": int,
        "stop_reason": str,
        "started_at": str,
        "deadline_at": str,
        "updated_at": str,
        "packet_sha256": str,
    }
    missing = [name for name in required_types if name not in state]
    if missing:
        raise LoopError("stopped session state is incomplete: " + ", ".join(missing))
    for name, expected in required_types.items():
        value = state[name]
        if expected is int:
            valid = type(value) is int and value >= 0
        else:
            valid = isinstance(value, expected)
        if not valid:
            raise LoopError(f"stopped session state field {name} is invalid")
    if state["schema"] != STATE_SCHEMA:
        raise LoopError("stopped session state schema differs")
    if state["driver"] != "codex_session":
        raise LoopError("stopped state does not belong to the Codex session driver")
    if state["status"] != "stopped" or state["stop_reason"] != "wall_budget":
        raise LoopError("only a wall-budget-stopped Codex session can be recovered")
    if not valid_identifier(state["run_id"], 64):
        raise LoopError("stopped session run ID is invalid")
    if not valid_identifier(state["work_id"], 80, allow_dot=True):
        raise LoopError("stopped session work ID is invalid")
    if not valid_branch(state["branch"]):
        raise LoopError("stopped session branch is invalid")
    if any(state[name] > 1_000_000 for name in ("iteration", "failures", "unchanged_results")):
        raise LoopError("stopped session counter exceeds its bound")
    if not is_lower_hex(state["base"], 40):
        raise LoopError("stopped session base is invalid")
    for name in ("packet_sha256",):
        value = state[name]
        if not is_lower_hex(value, 64):
            raise LoopError(f"stopped session {name} is invalid")
    for name in ("started_at", "deadline_at", "updated_at"):
        parse_utc_seconds(state[name], f"stopped session {name}")
    if actual_fields == RECOVERABLE_STOP_STATE_FIELDS:
        candidate_paths = state["candidate_paths"]
        if (
            not isinstance(candidate_paths, list)
            or not candidate_paths
            or len(candidate_paths) > 1024
            or any(not isinstance(path, str) for path in candidate_paths)
            or any(not valid_repo_path(path) for path in candidate_paths)
            or not is_lower_hex(state["last_tree_digest"], 64)
            or not is_lower_hex(state["candidate_tree"], 40)
        ):
            raise LoopError("stopped session candidate snapshot is invalid")
        parse_utc_seconds(state["checked_at"], "stopped session checked_at")


def validate_recovery_snapshot(snapshot: dict[str, Any]) -> None:
    require_exact_fields(
        snapshot,
        frozenset(
            {
                "schema",
                "run_id",
                "captured_at",
                "stopped_state",
                "stopped_state_sha256",
                "stopped_state_file_sha256",
                "packet_sha256",
                "guides_sha256",
                "objectives_sha256",
                "program_sha256",
                "allowed_paths",
                "safety_checks",
                "dirty_paths",
                "dirty_digest",
                "dirty_tree",
            }
        ),
        "recovery stop snapshot",
    )
    stopped = snapshot.get("stopped_state")
    if snapshot.get("schema") != RECOVERY_SNAPSHOT_SCHEMA or not isinstance(stopped, dict):
        raise LoopError("recovery stop snapshot schema differs")
    validate_recoverable_state(stopped)
    if canonical_sha256(stopped) != snapshot.get("stopped_state_sha256"):
        raise LoopError("recovery stop snapshot state digest differs")
    if snapshot.get("run_id") != stopped["run_id"]:
        raise LoopError("recovery stop snapshot run ID differs")
    string_digests = (
        "stopped_state_file_sha256",
        "packet_sha256",
        "guides_sha256",
        "objectives_sha256",
        "program_sha256",
        "dirty_digest",
    )
    if any(
        not is_lower_hex(snapshot.get(name), 64)
        for name in string_digests
    ):
        raise LoopError("recovery stop snapshot digest is invalid")
    if not is_lower_hex(snapshot.get("dirty_tree"), 40):
        raise LoopError("recovery stop snapshot tree is invalid")
    parse_utc_seconds(snapshot.get("captured_at"), "recovery snapshot captured_at")
    for name in ("allowed_paths", "dirty_paths"):
        value = snapshot.get(name)
        if not isinstance(value, list) or any(not isinstance(entry, str) for entry in value):
            raise LoopError(f"recovery stop snapshot {name} is invalid")
    validated_safety_checks({"safety_checks": snapshot.get("safety_checks")})


def validate_recovery_intent(intent: dict[str, Any]) -> None:
    require_exact_fields(
        intent,
        frozenset(
            {
                "schema",
                "run_id",
                "created_at",
                "stop_snapshot_sha256",
                "stopped_state_sha256",
                "replacement_state",
                "replacement_state_sha256",
            }
        ),
        "recovery intent",
    )
    replacement = intent.get("replacement_state")
    if intent.get("schema") != RECOVERY_INTENT_SCHEMA or not isinstance(replacement, dict):
        raise LoopError("recovery intent schema differs")
    require_exact_fields(replacement, CLAIMED_SESSION_STATE_FIELDS, "recovery replacement state")
    if canonical_sha256(replacement) != intent.get("replacement_state_sha256"):
        raise LoopError("recovery replacement state digest differs")
    if (
        replacement.get("schema") != STATE_SCHEMA
        or replacement.get("driver") != "codex_session"
        or replacement.get("status") != "claimed"
        or replacement.get("stop_reason") is not None
        or replacement.get("run_id") != intent.get("run_id")
    ):
        raise LoopError("recovery replacement state is invalid")
    for name in (
        "stop_snapshot_sha256",
        "stopped_state_sha256",
        "replacement_state_sha256",
    ):
        value = intent.get(name)
        if (
            not is_lower_hex(value, 64)
        ):
            raise LoopError(f"recovery intent {name} is invalid")
    parse_utc_seconds(intent.get("created_at"), "recovery intent creation time")


def validate_intent_against_snapshot(
    intent: dict[str, Any],
    snapshot: dict[str, Any],
    objective: dict[str, Any],
    snapshot_file_sha256: str,
) -> None:
    validate_recovery_intent(intent)
    stopped = snapshot["stopped_state"]
    replacement = intent["replacement_state"]
    invariant_fields = (
        "schema",
        "run_id",
        "driver",
        "work_id",
        "base",
        "branch",
        "packet",
        "iteration",
        "failures",
        "unchanged_results",
        "packet_sha256",
    )
    changed = [name for name in invariant_fields if replacement[name] != stopped[name]]
    if changed:
        raise LoopError(
            "recovery intent changes immutable stopped-session fields: "
            + ", ".join(changed)
        )
    if (
        intent["run_id"] != stopped["run_id"]
        or intent["stopped_state_sha256"] != snapshot["stopped_state_sha256"]
        or intent["stop_snapshot_sha256"] != snapshot_file_sha256
    ):
        raise LoopError("recovery intent differs from its exact stop snapshot")
    started = parse_utc_seconds(
        replacement["started_at"], "recovery replacement started_at"
    )
    updated = parse_utc_seconds(
        replacement["updated_at"], "recovery replacement updated_at"
    )
    deadline = parse_utc_seconds(
        replacement["deadline_at"], "recovery replacement deadline_at"
    )
    max_wall_seconds = objective.get("budget", {}).get("max_wall_seconds")
    if (
        type(max_wall_seconds) is not int
        or max_wall_seconds < 1
        or started != updated
        or deadline - started != dt.timedelta(seconds=max_wall_seconds)
    ):
        raise LoopError("recovery replacement wall budget differs from the objective")


def validate_recovery_receipt(receipt: dict[str, Any]) -> None:
    require_exact_fields(
        receipt,
        frozenset(
            {
                "schema",
                "run_id",
                "recovered_at",
                "intent_sha256",
                "replacement_state_sha256",
                "status",
            }
        ),
        "recovery receipt",
    )
    if receipt.get("schema") != RECOVERY_RECEIPT_SCHEMA or receipt.get("status") != "claimed":
        raise LoopError("recovery receipt schema or status differs")
    for name in ("intent_sha256", "replacement_state_sha256"):
        value = receipt.get(name)
        if (
            not is_lower_hex(value, 64)
        ):
            raise LoopError(f"recovery receipt {name} is invalid")
    parse_utc_seconds(receipt.get("recovered_at"), "recovery receipt recovered_at")


def recovery_snapshot_document(
    state: dict[str, Any], packet: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    allowed_paths = packet["objective"]["allowed_paths"]
    paths = sorted(porcelain_paths())
    if len(paths) > 1024 or any(not valid_repo_path(path) for path in paths):
        raise LoopError("recovery dirty path snapshot is invalid or exceeds its bound")
    outside = lease_errors(paths, allowed_paths)
    if outside:
        raise LoopError("recovery found out-of-lease paths: " + ", ".join(outside))
    dirty_digest = tree_fingerprint(paths)
    dirty_tree = exact_candidate_tree(state, packet, config, paths)
    if "candidate_paths" in state and (
        sorted(state["candidate_paths"]) != paths
        or state["last_tree_digest"] != dirty_digest
        or state["candidate_tree"] != dirty_tree
    ):
        raise LoopError("stopped candidate snapshot differs from the exact dirty tree")
    return {
        "schema": RECOVERY_SNAPSHOT_SCHEMA,
        "run_id": state["run_id"],
        "captured_at": utc_now(),
        "stopped_state": state,
        "stopped_state_sha256": canonical_sha256(state),
        "stopped_state_file_sha256": file_sha256(state_path(config)),
        "packet_sha256": state["packet_sha256"],
        "guides_sha256": packet["guides_sha256"],
        "objectives_sha256": packet["objectives_sha256"],
        "program_sha256": packet["program_sha256"],
        "allowed_paths": allowed_paths,
        "safety_checks": validated_safety_checks(config),
        "dirty_paths": paths,
        "dirty_digest": dirty_digest,
        "dirty_tree": dirty_tree,
    }


def validate_recovery_inputs(
    state: dict[str, Any],
    program_document: dict[str, Any],
    objectives: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    validate_recoverable_state(state)
    packet_path = recovery_packet_path(state)
    if file_sha256(packet_path) != state["packet_sha256"]:
        raise LoopError("immutable stopped-session packet changed after admission")
    packet = load_json(packet_path)
    if packet.get("schema") != PACKET_SCHEMA:
        raise LoopError("stopped-session packet schema differs")
    if (
        packet.get("run_id") != state["run_id"]
        or packet.get("driver") != "codex_session"
        or packet.get("immutable_base") != state["base"]
        or packet.get("iteration") != state["iteration"]
    ):
        raise LoopError("stopped session and immutable packet disagree")
    item, objective = select_item(program_document, objectives, state["work_id"])
    if packet.get("work_item") != item or packet.get("objective") != objective:
        raise LoopError("stopped-session objective differs from the current executable plan")
    expected_packet = packet_document(
        state["run_id"],
        state["iteration"],
        state["base"],
        item,
        objective,
        config,
        None,
        driver="codex_session",
    )
    if packet != expected_packet:
        raise LoopError("stopped-session packet differs from its closed v1 document")
    current_digests = {
        "guides_sha256": file_sha256(guides.GUIDE_MANIFEST),
        "objectives_sha256": file_sha256(guides.OBJECTIVES),
        "program_sha256": file_sha256(program.DEFAULT_PROGRAM),
    }
    drifted = [
        name for name, digest in current_digests.items() if packet.get(name) != digest
    ]
    if drifted:
        raise LoopError("stopped-session admission inputs changed: " + ", ".join(drifted))
    if git("rev-parse", "HEAD") != state["base"]:
        raise LoopError("recovery Git revision differs from the admitted base")
    if git("branch", "--show-current") != state["branch"]:
        raise LoopError("recovery Git branch differs from the admitted branch")
    validated_safety_checks(config)
    state_root = state_path(config).parent
    effect_paths = (
        state_root / "git-candidates" / state["run_id"] / "intent.json",
        state_root / "git-candidates" / state["run_id"] / "receipt.json",
        state_root / "local-integrations" / state["run_id"] / "intent.json",
        state_root / "local-integrations" / state["run_id"] / "receipt.json",
    )
    existing_effects = [path for path in effect_paths if os.path.lexists(path)]
    if existing_effects:
        raise LoopError("recovery found an ambiguous candidate or integration effect")
    candidate_ref = f"refs/automonique/candidates/{state['run_id']}"
    inspected_ref = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", candidate_ref],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected_ref.returncode == 0:
        raise LoopError("recovery found an ambiguous candidate ref")
    if inspected_ref.returncode != 1:
        raise LoopError("recovery could not inspect the candidate ref")
    return packet


def snapshot_facts(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if key != "captured_at"}


def replacement_claim(
    stopped: dict[str, Any], objective: dict[str, Any], now: dt.datetime
) -> dict[str, Any]:
    max_wall_seconds = objective.get("budget", {}).get("max_wall_seconds")
    if type(max_wall_seconds) is not int or max_wall_seconds < 1:
        raise LoopError("recovery objective wall budget is invalid")
    timestamp = now.isoformat(timespec="seconds")
    deadline = now + dt.timedelta(seconds=max_wall_seconds)
    return {
        "schema": STATE_SCHEMA,
        "run_id": stopped["run_id"],
        "driver": "codex_session",
        "work_id": stopped["work_id"],
        "base": stopped["base"],
        "branch": stopped["branch"],
        "status": "claimed",
        "packet": stopped["packet"],
        "iteration": stopped["iteration"],
        "failures": stopped["failures"],
        "unchanged_results": stopped["unchanged_results"],
        "stop_reason": None,
        "started_at": timestamp,
        "deadline_at": deadline.isoformat(timespec="seconds"),
        "updated_at": timestamp,
        "packet_sha256": stopped["packet_sha256"],
    }


def _write_recovery_receipt(
    path: pathlib.Path, intent: dict[str, Any]
) -> dict[str, Any]:
    receipt = {
        "schema": RECOVERY_RECEIPT_SCHEMA,
        "run_id": intent["run_id"],
        "recovered_at": utc_now(),
        "intent_sha256": canonical_sha256(intent),
        "replacement_state_sha256": intent["replacement_state_sha256"],
        "status": "claimed",
    }
    write_json_atomic(path, receipt)
    return receipt


def _recover_session_locked() -> int:
    program_document, objectives, config = load_inputs()
    state = read_state(config)
    if state is None:
        raise LoopError("no stopped Codex session claim exists")
    run_id = state.get("run_id")
    if not isinstance(run_id, str):
        raise LoopError("stopped session run ID is invalid")
    snapshot_path, intent_path, receipt_path = recovery_paths(config, run_id)

    if receipt_path.exists():
        receipt = load_json(receipt_path)
        validate_recovery_receipt(receipt)
        if not intent_path.exists() or not snapshot_path.exists():
            raise LoopError("recovery receipt exists without its durable journal")
        intent = load_json(intent_path)
        snapshot = load_json(snapshot_path)
        validate_recovery_snapshot(snapshot)
        packet = validate_recovery_inputs(
            snapshot["stopped_state"], program_document, objectives, config
        )
        validate_intent_against_snapshot(
            intent,
            snapshot,
            packet["objective"],
            file_sha256(snapshot_path),
        )
        if (
            receipt["run_id"] != run_id
            or receipt["intent_sha256"] != canonical_sha256(intent)
            or receipt["replacement_state_sha256"] != intent["replacement_state_sha256"]
        ):
            raise LoopError("recovery receipt differs from its durable intent")
        if state != intent["replacement_state"]:
            raise LoopError("wall-budget recovery was already consumed; repeat renewal is forbidden")
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0

    if intent_path.exists():
        intent = load_json(intent_path)
        validate_recovery_intent(intent)
        if intent["run_id"] != run_id:
            raise LoopError("recovery intent run ID differs")
        if not snapshot_path.exists():
            raise LoopError("recovery intent exists without its stop snapshot")
        snapshot = load_json(snapshot_path)
        validate_recovery_snapshot(snapshot)
        packet = validate_recovery_inputs(
            snapshot["stopped_state"], program_document, objectives, config
        )
        validate_intent_against_snapshot(
            intent,
            snapshot,
            packet["objective"],
            file_sha256(snapshot_path),
        )
        if state == intent["replacement_state"]:
            receipt = _write_recovery_receipt(receipt_path, intent)
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 0
        if state != snapshot["stopped_state"]:
            raise LoopError("live session state differs from its durable recovery intent")

    packet = validate_recovery_inputs(state, program_document, objectives, config)
    current_snapshot = recovery_snapshot_document(state, packet, config)
    if snapshot_path.exists():
        snapshot = load_json(snapshot_path)
        validate_recovery_snapshot(snapshot)
        if snapshot_facts(snapshot) != snapshot_facts(current_snapshot):
            raise LoopError("stopped session or its exact recovery snapshot changed")
    else:
        snapshot = current_snapshot
        write_json_atomic(snapshot_path, snapshot)

    fixed_checks = snapshot["safety_checks"]
    run_safety_checks({"safety_checks": fixed_checks}, "recovery")

    current_program, current_objectives, current_config = load_inputs()
    if validated_safety_checks(current_config) != fixed_checks:
        raise LoopError("recovery safety checks changed while they were running")
    current_state = read_state(current_config)
    if (
        current_state is None
        or canonical_sha256(current_state) != snapshot["stopped_state_sha256"]
        or file_sha256(state_path(current_config))
        != snapshot["stopped_state_file_sha256"]
    ):
        raise LoopError("stopped session changed before recovery compare-and-swap")
    current_packet = validate_recovery_inputs(
        current_state, current_program, current_objectives, current_config
    )
    verified_snapshot = recovery_snapshot_document(
        current_state, current_packet, current_config
    )
    if snapshot_facts(verified_snapshot) != snapshot_facts(snapshot):
        raise LoopError("recovery inputs changed while safety checks were running")

    if intent_path.exists():
        intent = load_json(intent_path)
        validate_intent_against_snapshot(
            intent,
            snapshot,
            current_packet["objective"],
            file_sha256(snapshot_path),
        )
    else:
        replacement = replacement_claim(
            current_state,
            current_packet["objective"],
            dt.datetime.now(dt.timezone.utc),
        )
        intent = {
            "schema": RECOVERY_INTENT_SCHEMA,
            "run_id": run_id,
            "created_at": utc_now(),
            "stop_snapshot_sha256": file_sha256(snapshot_path),
            "stopped_state_sha256": snapshot["stopped_state_sha256"],
            "replacement_state": replacement,
            "replacement_state_sha256": canonical_sha256(replacement),
        }
        write_json_atomic(intent_path, intent)

    validate_intent_against_snapshot(
        intent,
        snapshot,
        current_packet["objective"],
        file_sha256(snapshot_path),
    )

    reread = read_state(current_config)
    if (
        reread is None
        or canonical_sha256(reread) != intent["stopped_state_sha256"]
        or file_sha256(state_path(current_config))
        != snapshot["stopped_state_file_sha256"]
    ):
        raise LoopError("stopped session lost the recovery compare-and-swap")
    write_json_atomic(state_path(current_config), intent["replacement_state"])
    receipt = _write_recovery_receipt(receipt_path, intent)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def recover_session() -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        return _recover_session_locked()
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _claim_session_locked(requested: str | None) -> int:
    program_document, objectives, config = load_inputs()
    refuse_active_attempt(config)
    item, objective = select_item(program_document, objectives, requested)
    if porcelain_paths():
        raise LoopError("worktree must be clean before session admission")
    base = git("rev-parse", "HEAD")
    branch = git("branch", "--show-current")
    assert isinstance(base, str) and isinstance(branch, str)
    run_safety_checks(config, "admission")
    run_id = (
        "session_"
        + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ_")
        + uuid.uuid4().hex[:8]
    )
    run_dir = state_path(config).parent / "runs" / run_id
    packet_path = run_dir / "packet.json"
    packet = packet_document(
        run_id, 1, base, item, objective, config, None, driver="codex_session"
    )
    write_json_atomic(packet_path, packet)
    relative_packet = packet_path.relative_to(ROOT).as_posix()
    started = dt.datetime.now(dt.timezone.utc)
    now = started.isoformat(timespec="seconds")
    deadline = started + dt.timedelta(seconds=objective["budget"]["max_wall_seconds"])
    state = {
        "schema": STATE_SCHEMA,
        "run_id": run_id,
        "driver": "codex_session",
        "work_id": item["id"],
        "base": base,
        "branch": branch,
        "status": "claimed",
        "packet": relative_packet,
        "iteration": 1,
        "failures": 0,
        "unchanged_results": 0,
        "stop_reason": None,
        "started_at": now,
        "deadline_at": deadline.isoformat(timespec="seconds"),
        "updated_at": now,
        "packet_sha256": file_sha256(packet_path),
    }
    write_json_atomic(state_path(config), state)
    print(
        json.dumps(
            {
                "status": "claimed",
                "driver": "codex_session",
                "work_id": item["id"],
                "packet": relative_packet,
                "max_concurrent_subagents": config["drivers"]["codex_session"][
                    "max_concurrent_subagents"
                ],
            },
            indent=2,
        )
    )
    return 0


def claim_session(requested: str | None) -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        return _claim_session_locked(requested)
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _check_session_locked() -> int:
    program_document, objectives, config = load_inputs()
    state = read_state(config)
    if state is None:
        raise LoopError("no Codex session claim exists")
    if state.get("driver") != "codex_session":
        raise LoopError("active state does not belong to the Codex session driver")
    original_status = state.get("status")
    if original_status not in CHECKABLE_SESSION_STATUSES:
        raise LoopError(f"Codex session claim is not active: {state.get('status')}")
    packet_path = ROOT / state["packet"]
    if file_sha256(packet_path) != state.get("packet_sha256"):
        raise LoopError("immutable session objective packet changed after admission")
    packet = load_json(packet_path)
    if packet.get("run_id") != state.get("run_id"):
        raise LoopError("session state and objective packet disagree")
    item, objective = select_item(
        program_document, objectives, state.get("work_id")
    )
    if packet.get("work_item") != item or packet.get("objective") != objective:
        raise LoopError("session objective differs from the current executable plan")
    current_digests = {
        "guides_sha256": file_sha256(guides.GUIDE_MANIFEST),
        "objectives_sha256": file_sha256(guides.OBJECTIVES),
        "program_sha256": file_sha256(program.DEFAULT_PROGRAM),
    }
    drifted = [
        name for name, digest in current_digests.items() if packet.get(name) != digest
    ]
    if drifted:
        raise LoopError("session admission inputs changed: " + ", ".join(drifted))
    if dt.datetime.now(dt.timezone.utc) > dt.datetime.fromisoformat(
        state["deadline_at"]
    ):
        state.update(
            {"status": "stopped", "stop_reason": "wall_budget", "updated_at": utc_now()}
        )
        write_json_atomic(state_path(config), state)
        raise LoopError("Codex session claim exceeded its wall-time budget")
    if git("rev-parse", "HEAD") != state["base"]:
        raise LoopError("session changed the admitted Git revision")
    if git("branch", "--show-current") != state["branch"]:
        raise LoopError("session changed the admitted Git branch")
    paths = porcelain_paths()
    outside = lease_errors(paths, packet["objective"]["allowed_paths"])
    if outside:
        raise LoopError("session changed out-of-lease paths: " + ", ".join(outside))
    if original_status == "candidate_ready":
        actual_digest = tree_fingerprint(paths)
        actual_tree = exact_candidate_tree(state, packet, config, paths)
        if not candidate_snapshot_matches(state, paths, actual_digest, actual_tree):
            state.update(
                {
                    "status": "reconciliation_required",
                    "stop_reason": "candidate_drift",
                    "updated_at": utc_now(),
                }
            )
            write_json_atomic(state_path(config), state)
            raise LoopError("candidate changed after it was declared ready")
        run_safety_checks(config, "candidate revalidation")
        if exact_candidate_tree(state, packet, config, paths) != actual_tree:
            raise LoopError("candidate changed while safety checks were running")
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    if not paths:
        print(json.dumps({"status": "claimed", "candidate": "unchanged"}, indent=2))
        return 2
    candidate_tree = exact_candidate_tree(state, packet, config, paths)
    run_safety_checks(config, "candidate")
    if exact_candidate_tree(state, packet, config, paths) != candidate_tree:
        raise LoopError("candidate changed while safety checks were running")
    now = utc_now()
    state.update(
        {
            "status": "candidate_ready",
            "stop_reason": "candidate_ready",
            "candidate_paths": paths,
            "last_tree_digest": tree_fingerprint(paths),
            "candidate_tree": candidate_tree,
            "updated_at": now,
            "checked_at": now,
        }
    )
    write_json_atomic(state_path(config), state)
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def check_session() -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        return _check_session_locked()
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def candidate_request(
    state: dict[str, Any], packet: dict[str, Any], summary: str
) -> git_broker.CandidateRequest:
    objective = packet.get("objective")
    allowed_paths = objective.get("allowed_paths") if isinstance(objective, dict) else None
    candidate_paths = state.get("candidate_paths")
    if not isinstance(allowed_paths, list) or not isinstance(candidate_paths, list):
        raise LoopError("candidate state lacks its typed path lease")
    if not all(isinstance(path, str) for path in allowed_paths + candidate_paths):
        raise LoopError("candidate path lease contains a non-string value")
    required = ("run_id", "work_id", "base", "branch")
    if any(not isinstance(state.get(field), str) for field in required):
        raise LoopError("candidate state identity is incomplete")
    metric_snapshot = plan_baseline.snapshot()
    metrics_sha256 = hashlib.sha256(
        json.dumps({"counters": metric_snapshot["counters"]}, sort_keys=True).encode()
    ).hexdigest()
    evidence_path = ROOT / "plan" / "evidence" / f"{state['work_id']}.json"
    evidence_sha256: str | None = None
    reviewers = 0
    blocking_findings = 0
    if evidence_path.exists():
        evidence = load_json(evidence_path)
        if evidence.get("item") != state["work_id"]:
            raise LoopError("completion evidence names a different work item")
        review = evidence.get("review")
        if not isinstance(review, dict):
            raise LoopError("completion evidence lacks a review record")
        reviewers = review.get("reviewers")
        blocking_findings = review.get("blocking_findings")
        if any(
            type(value) is not int or value < 0
            for value in (reviewers, blocking_findings)
        ):
            raise LoopError("completion evidence review counts are invalid")
        evidence_sha256 = file_sha256(evidence_path)
    return git_broker.CandidateRequest(
        operation=git_broker.OPERATION,
        run_id=state["run_id"],
        work_id=state["work_id"],
        expected_base=state["base"],
        expected_branch=state["branch"],
        allowed_paths=tuple(allowed_paths),
        candidate_paths=tuple(sorted(candidate_paths)),
        expected_tree=state.get("candidate_tree", ""),
        summary=summary,
        attestation=git_broker.CandidateAttestation(
            checks="safety-pass",
            reviewers=reviewers,
            blocking_findings=blocking_findings,
            metrics_sha256=metrics_sha256,
            completion=False,
            evidence_sha256=evidence_sha256,
        ),
    )


def _commit_candidate_locked(summary: str) -> int:
    _, _, config = load_inputs()
    state = read_state(config)
    if state is None or state.get("driver") != "codex_session":
        raise LoopError("no Codex session candidate exists")
    status = state.get("status")
    if status == "candidate_ready":
        _check_session_locked()
        state = read_state(config)
        assert state is not None
        candidate_request(state, load_json(ROOT / state["packet"]), summary)
        state.update(
            {
                "status": "commit_intent",
                "stop_reason": "commit_intent",
                "candidate_ref": f"refs/automonique/candidates/{state['run_id']}",
                "candidate_summary": summary,
                "updated_at": utc_now(),
            }
        )
        write_json_atomic(state_path(config), state)
    elif status not in {"commit_intent", "reconciliation_required"}:
        raise LoopError(f"candidate cannot be committed from state {status}")

    state = read_state(config)
    assert state is not None
    stored_summary = state.get("candidate_summary")
    if not isinstance(stored_summary, str):
        raise LoopError("commit intent lacks its candidate summary")
    if summary != stored_summary:
        raise LoopError("candidate summary differs from the durable commit intent")
    packet = load_json(ROOT / state["packet"])
    request = candidate_request(state, packet, stored_summary)
    broker = git_broker.CandidateBroker(ROOT, (ROOT / config["state_path"]).parent)
    try:
        broker.prepare(request)
        receipt = broker.reconcile(state["run_id"])
    except git_broker.BrokerError as exc:
        state.update(
            {
                "status": "reconciliation_required",
                "stop_reason": "candidate_reconciliation_required",
                "updated_at": utc_now(),
            }
        )
        write_json_atomic(state_path(config), state)
        raise LoopError("candidate broker requires reconciliation") from exc
    state.update(
        {
            "status": "candidate_committed",
            "stop_reason": "candidate_committed",
            "candidate_ref": receipt["ref"],
            "candidate_commit": receipt["commit_oid"],
            "candidate_tree": receipt["tree_oid"],
            "updated_at": utc_now(),
        }
    )
    write_json_atomic(state_path(config), state)
    authority_path = ROOT / "plan/authority.toml"
    candidate_receipt = (
        (ROOT / config["state_path"]).parent
        / "git-candidates"
        / state["run_id"]
        / "receipt.json"
    )
    integrator = local_integration.LocalIntegration(
        ROOT,
        (ROOT / config["state_path"]).parent,
        authority_path,
        file_sha256(authority_path),
    )
    try:
        integration_receipt = integrator.integrate(
            candidate_receipt, file_sha256(candidate_receipt)
        )
    except local_integration.IntegrationError as exc:
        state.update(
            {
                "status": "reconciliation_required",
                "stop_reason": "integration_reconciliation_required",
                "updated_at": utc_now(),
            }
        )
        write_json_atomic(state_path(config), state)
        raise LoopError("local or remote integration requires reconciliation") from exc
    state.update(
        {
            "status": "integrated_and_pushed",
            "stop_reason": "integrated_and_pushed",
            "integrated_commit": integration_receipt["commit_oid"],
            "integration_receipt_sha256": local_integration.canonical_sha256(
                integration_receipt
            ),
            "updated_at": utc_now(),
        }
    )
    write_json_atomic(state_path(config), state)
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def commit_candidate(summary: str) -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        return _commit_candidate_locked(summary)
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def release_session(reason: str) -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        state = read_state(config)
        if state is None or state.get("driver") != "codex_session":
            raise LoopError("no Codex session claim exists")
        status = state.get("status")
        if status not in {
            "claimed",
            "candidate_ready",
            "reconciliation_required",
        }:
            raise LoopError(f"Codex session claim is not active: {state.get('status')}")
        if status == "reconciliation_required":
            git_broker.CandidateBroker(
                ROOT, (ROOT / config["state_path"]).parent
            ).abandon(state["run_id"])
        state.update({"status": "stopped", "stop_reason": reason, "updated_at": utc_now()})
        write_json_atomic(state_path(config), state)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _run_loop_locked(
    requested: str | None, explicit_argv: list[str], limit: int | None
) -> int:
    program_document, objectives, config = load_inputs()
    refuse_active_attempt(config)
    item, objective = select_item(program_document, objectives, requested)
    if porcelain_paths():
        raise LoopError("worktree must be clean before loop admission")
    base = git("rev-parse", "HEAD")
    branch = git("branch", "--show-current")
    assert isinstance(base, str) and isinstance(branch, str)
    budget = dict(objective["budget"])
    if limit is not None:
        if limit < 1:
            raise LoopError("--max-iterations must be positive")
        budget["max_iterations"] = min(limit, budget["max_iterations"])
    worker_argv(explicit_argv, pathlib.Path("admission-packet"))

    run_safety_checks(config, "admission")

    run_id = (
        "devrun_"
        + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ_")
        + uuid.uuid4().hex[:8]
    )
    state_path = ROOT / config["state_path"]
    run_dir = state_path.parent / "runs" / run_id
    started = time.monotonic()
    failures = 0
    unchanged = 0
    prior: dict[str, Any] | None = None
    state: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "run_id": run_id,
        "driver": "local_process",
        "work_id": item["id"],
        "base": base,
        "branch": branch,
        "status": "running",
        "iteration": 0,
        "failures": 0,
        "unchanged_results": 0,
        "stop_reason": None,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    write_json_atomic(state_path, state)

    try:
        for iteration in range(1, budget["max_iterations"] + 1):
            if git("rev-parse", "HEAD") != base or git("branch", "--show-current") != branch:
                raise LoopError("worker changed the admitted Git revision or branch")
            packet_path = run_dir / f"packet-{iteration:03d}.json"
            packet = packet_document(
                run_id, iteration, base, item, objective, config, prior
            )
            write_json_atomic(packet_path, packet)
            before_paths = porcelain_paths()
            before = tree_fingerprint(before_paths)
            argv = sandbox_worker_argv(
                explicit_argv, packet_path, objective["allowed_paths"]
            )
            print(f"iteration {iteration}/{budget['max_iterations']}: {item['id']}", flush=True)
            remaining = budget["max_wall_seconds"] - (time.monotonic() - started)
            if remaining <= 0:
                state.update({"status": "stopped", "stop_reason": "wall_budget"})
                write_json_atomic(state_path, state)
                print("stopped: wall_budget")
                return 2
            worker_timeout = max(1, min(budget["max_worker_seconds"], int(remaining)))
            exit_code, forced_stop = run_worker(argv, worker_timeout)
            after_paths = porcelain_paths()
            outside = lease_errors(after_paths, objective["allowed_paths"])
            if outside:
                raise LoopError("worker changed out-of-lease paths: " + ", ".join(outside))
            if git("rev-parse", "HEAD") != base or git("branch", "--show-current") != branch:
                raise LoopError("worker changed the admitted Git revision or branch")
            after = tree_fingerprint(after_paths)
            changed = after != before
            if not changed:
                unchanged += 1
            if exit_code != 0:
                failures += 1
            checks_passed = forced_stop is None
            if checks_passed:
                checks_passed = all(run_check(check) for check in config["safety_checks"])
            elapsed = time.monotonic() - started
            reason = forced_stop or stop_reason(
                exit_code=exit_code,
                checks_passed=checks_passed,
                changed=changed,
                iteration=iteration,
                failures=failures,
                unchanged_results=unchanged,
                elapsed_seconds=elapsed,
                budget=budget,
            )
            prior = {
                "iteration": iteration,
                "exit_code": exit_code,
                "changed": changed,
                "tree_digest": after,
                "checks_passed": checks_passed,
                "stop_reason": reason,
            }
            state.update(
                {
                    "iteration": iteration,
                    "failures": failures,
                    "unchanged_results": unchanged,
                    "last_tree_digest": after,
                    "last_exit_code": exit_code,
                    "stop_reason": reason,
                    "status": "stopped" if reason else "running",
                    "elapsed_seconds": round(elapsed, 3),
                    "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                }
            )
            write_json_atomic(state_path, state)
            if reason:
                print(f"stopped: {reason}")
                return 0 if reason == "candidate_ready" else 2
    except KeyboardInterrupt:
        state.update({"status": "stopped", "stop_reason": "user_cancelled"})
        write_json_atomic(state_path, state)
        print("stopped: user_cancelled", file=sys.stderr)
        return 130
    except Exception:
        state.update({"status": "stopped", "stop_reason": "runner_error"})
        write_json_atomic(state_path, state)
        raise
    return 2


def run_loop(requested: str | None, explicit_argv: list[str], limit: int | None) -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        return _run_loop_locked(requested, explicit_argv, limit)
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


COMPLETION_REGENERATORS = (
    ("plan", "generate.py"),
    ("tools", "program.py"),
    ("tools", "guides.py"),
    ("plan", "check.py"),
    ("plan", "baseline.py"),
)


def _run_repo_script(*parts: str) -> None:
    """Run a repository script by explicit argv and fail loudly."""
    script = "/".join(parts)
    result = subprocess.run(
        [sys.executable, script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LoopError(f"{script} failed during completion: {detail}")


def mark_item_done(item_id: str) -> bool:
    """Add `item_id` to the generator's done set. Returns False if already there."""
    source = ROOT / "plan" / "generate.py"
    text = source.read_text()
    match = re.search(r"^ITEM_STATUS = \{\n(.*?)^\}$", text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise LoopError("plan/generate.py has no ITEM_STATUS block to update")
    body = match.group(1)
    entry = f'    "{item_id}": "done",\n'
    if f'"{item_id}"' in body:
        return False
    updated = text[: match.start(1)] + body + entry + text[match.end(1) :]
    source.write_text(updated)
    return True


def dirty_repo_paths() -> list[str]:
    output = git("status", "--porcelain=v1", "-z", "--untracked-files=all", text=False)
    assert isinstance(output, bytes)
    # Reuse the broker's own parser so the declared paths and the paths the
    # broker will validate can never disagree.
    return sorted(git_broker.parse_status(output))


def append_history(
    item: dict[str, Any], summary: str, files: list[str], reason: str | None
) -> None:
    snapshot = plan_baseline.snapshot()
    record: dict[str, Any] = {
        "at": utc_now(),
        "item": item["id"],
        "epic": item.get("epic"),
        "summary": summary,
        "files": files,
        "debt_total": snapshot["total"],
        "counters": snapshot["counters"],
        "digest": plan_baseline.digest(snapshot)[:16],
        "head": git("rev-parse", "HEAD"),
    }
    if reason:
        record["no_metric_change_reason"] = reason
    history = ROOT / "plan" / "history.jsonl"
    with history.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _complete_item_locked(item_id: str, summary: str, reason: str | None) -> int:
    program_document, _, config = load_inputs()
    item = next(
        (i for i in program_document["items"] if i["id"] == item_id),
        None,
    )
    if item is None:
        raise LoopError(f"{item_id} is not in the work graph")
    if item.get("contract") is None:
        raise LoopError(f"{item_id} has no contract and cannot be completed")
    evidence_path = ROOT / "plan" / "evidence" / f"{item_id}.json"
    if not evidence_path.exists():
        raise LoopError(f"{item_id} has no evidence at plan/evidence/{item_id}.json")
    if load_json(evidence_path).get("item") != item_id:
        raise LoopError("completion evidence names a different work item")

    base = git("rev-parse", "HEAD")
    branch = git("branch", "--show-current")
    if not mark_item_done(item_id):
        raise LoopError(f"{item_id} is already recorded done in plan/generate.py")
    for parts in COMPLETION_REGENERATORS:
        _run_repo_script(*parts)

    files = dirty_repo_paths()
    append_history(item, summary, files, reason)
    files = dirty_repo_paths()

    gate = [sys.executable, "plan/gate.py", "--item", item_id, "--summary", summary,
            "--files", *files, "--dry-run"]
    if reason:
        gate.extend(["--allow-no-metric-change", reason])
    verdict = subprocess.run(gate, cwd=ROOT, capture_output=True, text=True, check=False)
    print(verdict.stdout, end="")
    if verdict.returncode != 0:
        print(verdict.stderr, end="", file=sys.stderr)
        raise LoopError(f"{item_id} did not pass the landing gate; nothing was committed")

    allowed = tuple(item["allowed_paths"]) + gate_module.completion_paths(item_id)
    metric_snapshot = plan_baseline.snapshot()
    metrics_sha256 = hashlib.sha256(
        json.dumps({"counters": metric_snapshot["counters"]}, sort_keys=True).encode()
    ).hexdigest()
    evidence = load_json(evidence_path)
    review = evidence.get("review")
    if not isinstance(review, dict):
        raise LoopError("completion evidence lacks a review record")
    broker = git_broker.CandidateBroker(ROOT, (ROOT / config["state_path"]).parent)
    run_id = f"complete_{item_id.replace('-', '_').lower()}_{base[:8]}"
    request = git_broker.CandidateRequest(
        operation=git_broker.OPERATION,
        run_id=run_id,
        work_id=item_id,
        expected_base=base,
        expected_branch=branch,
        allowed_paths=allowed,
        candidate_paths=tuple(files),
        expected_tree=broker.snapshot(
            expected_base=base,
            expected_branch=branch,
            allowed_paths=allowed,
            candidate_paths=tuple(files),
        ),
        summary=summary,
        attestation=git_broker.CandidateAttestation(
            checks="contract-pass",
            reviewers=review.get("reviewers", 0),
            blocking_findings=review.get("blocking_findings", 0),
            metrics_sha256=metrics_sha256,
            completion=True,
            evidence_sha256=file_sha256(evidence_path),
        ),
    )
    receipt = broker.create(request)
    authority_path = ROOT / "plan/authority.toml"
    integrator = local_integration.LocalIntegration(
        ROOT, (ROOT / config["state_path"]).parent, authority_path,
        file_sha256(authority_path),
    )
    receipt_path = (
        (ROOT / config["state_path"]).parent / "git-candidates" / run_id / "receipt.json"
    )
    integration = integrator.integrate(receipt_path, file_sha256(receipt_path))
    print(json.dumps({"candidate": receipt, "integration": integration},
                     indent=2, sort_keys=True))
    return 0


def complete_item(item_id: str, summary: str, reason: str | None) -> int:
    _, _, config = load_inputs()
    lock = acquire_loop_lock(config)
    try:
        return _complete_item_locked(item_id, summary, reason)
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--state", type=pathlib.Path)
    next_parser = subparsers.add_parser("next")
    next_parser.add_argument("--item")
    claim_parser = subparsers.add_parser("claim")
    claim_parser.add_argument("--item")
    subparsers.add_parser("recover")
    subparsers.add_parser("check")
    candidate_parser = subparsers.add_parser("candidate")
    candidate_parser.add_argument("--summary", required=True)
    complete_parser = subparsers.add_parser("complete")
    complete_parser.add_argument("--item", required=True)
    complete_parser.add_argument("--summary", required=True)
    complete_parser.add_argument(
        "--reason",
        help="honest reason no specification-debt counter moved, recorded in history",
    )
    release_parser = subparsers.add_parser("release")
    release_parser.add_argument(
        "--reason", required=True, choices=("blocked", "user_cancelled", "superseded")
    )
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--item")
    run_parser.add_argument("--max-iterations", type=int)
    run_parser.add_argument(
        "--worker-arg",
        action="append",
        default=[],
        help="one explicit worker argv element; repeat in order",
    )
    args = parser.parse_args()
    try:
        if args.command == "status":
            _, _, config = load_inputs()
            state_path = args.state or ROOT / config["state_path"]
            if not state_path.exists():
                print(json.dumps({"status": "idle"}, indent=2))
            else:
                print(json.dumps(load_json(state_path), indent=2, sort_keys=True))
            return 0
        if args.command == "next":
            program_document, objectives, _ = load_inputs()
            item, objective = select_item(program_document, objectives, args.item)
            print_next(item, objective)
            return 0
        if args.command == "claim":
            return claim_session(args.item)
        if args.command == "recover":
            return recover_session()
        if args.command == "check":
            return check_session()
        if args.command == "candidate":
            return commit_candidate(args.summary)
        if args.command == "complete":
            return complete_item(args.item, args.summary, args.reason)
        if args.command == "release":
            return release_session(args.reason)
        return run_loop(args.item, args.worker_arg, args.max_iterations)
    except (
        LoopError,
        git_broker.BrokerError,
        local_integration.IntegrationError,
        program.ProgramError,
        OSError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
