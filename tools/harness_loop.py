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
import signal
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import guides, program  # noqa: E402

STATE_SCHEMA = "automonique.harness-loop-state/v1"
PACKET_SCHEMA = "automonique.harness-objective-packet/v1"
ACTIVE_STATUSES = frozenset({"claimed", "running"})


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


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def eligible_items(
    program_document: dict[str, Any], objective_document: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    objectives = objective_map(objective_document)
    eligible: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in program_document.get("items", []):
        objective = objectives.get(item.get("id"))
        if item.get("runnable") and objective and objective.get("autonomous_eligible"):
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
        digest.update(relative.encode())
        path = ROOT / relative
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
    return digest.hexdigest()


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
    if state is not None and state.get("status") in ACTIVE_STATUSES:
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
    if state.get("status") == "candidate_ready":
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    if state.get("status") != "claimed":
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
    if not paths:
        print(json.dumps({"status": "claimed", "candidate": "unchanged"}, indent=2))
        return 2
    run_safety_checks(config, "candidate")
    now = utc_now()
    state.update(
        {
            "status": "candidate_ready",
            "stop_reason": "candidate_ready",
            "candidate_paths": paths,
            "last_tree_digest": tree_fingerprint(paths),
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


def release_session(reason: str) -> int:
    config = load_json(guides.LOOP_CONFIG)
    lock = acquire_loop_lock(config)
    try:
        state = read_state(config)
        if state is None or state.get("driver") != "codex_session":
            raise LoopError("no Codex session claim exists")
        if state.get("status") != "claimed":
            raise LoopError(f"Codex session claim is not active: {state.get('status')}")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--state", type=pathlib.Path)
    next_parser = subparsers.add_parser("next")
    next_parser.add_argument("--item")
    claim_parser = subparsers.add_parser("claim")
    claim_parser.add_argument("--item")
    subparsers.add_parser("check")
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
        if args.command == "check":
            return check_session()
        if args.command == "release":
            return release_session(args.reason)
        return run_loop(args.item, args.worker_arg, args.max_iterations)
    except (LoopError, program.ProgramError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
