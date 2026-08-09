#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Crash-reconcilable allocation of detached, immutable-base worktrees."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
from typing import Any


SCHEMA = "automonique.worktree-allocation/v1"
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
OID = re.compile(r"^[0-9a-f]{40}$")


class AllocationError(Exception):
    """An isolated worktree cannot be allocated without weakening a bound."""


@dataclasses.dataclass(frozen=True)
class AllocationRequest:
    run_id: str
    expected_base: str
    max_materialized_bytes: int

    def document(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _atomic_json(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
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


def _load(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AllocationError(f"allocation state is unreadable: {path.name}") from exc
    if not isinstance(document, dict):
        raise AllocationError("allocation state is not an object")
    return document


class WorktreeAllocator:
    """Allocate one detached worktree at an exact Git commit per run ID."""

    def __init__(self, repository: pathlib.Path, state_root: pathlib.Path) -> None:
        repository_input = pathlib.Path(os.path.abspath(os.fspath(repository)))
        state_input = pathlib.Path(os.path.abspath(os.fspath(state_root)))
        if self._has_symlink_component(repository_input) or self._has_symlink_component(
            state_input
        ):
            raise AllocationError("repository and state roots cannot be symlinks")
        self.repository = repository_input.resolve()
        self.state_root = state_input.resolve()
        if not (self.repository / ".git").exists():
            raise AllocationError("allocator requires a Git repository")
        executable = shutil.which("git")
        if executable is None:
            raise AllocationError("Git executable is unavailable")
        self.git = str(pathlib.Path(executable).resolve())
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_root.chmod(0o700)

    @staticmethod
    def _has_symlink_component(path: pathlib.Path) -> bool:
        current = pathlib.Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            if current.is_symlink():
                return True
        return False

    def _env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.state_root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def _git(self, *arguments: str, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            [
                self.git,
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
                *arguments,
            ],
            cwd=cwd or self.repository,
            capture_output=True,
            check=False,
            env=self._env(),
        )
        if completed.returncode != 0:
            raise AllocationError("typed Git worktree operation failed")
        return completed

    def _paths(self, run_id: str) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        operation = self.state_root / "worktrees" / run_id
        return operation, operation / "intent.json", operation / "receipt.json"

    def _validate(self, request: AllocationRequest) -> None:
        if not RUN_ID.fullmatch(request.run_id):
            raise AllocationError("run ID is invalid")
        if not OID.fullmatch(request.expected_base):
            raise AllocationError("base is not a full SHA-1 object ID")
        if not isinstance(request.max_materialized_bytes, int) or isinstance(
            request.max_materialized_bytes, bool
        ) or not 1 <= request.max_materialized_bytes <= 10 * 1024 * 1024 * 1024:
            raise AllocationError("materialized-byte budget is invalid")
        resolved = self._git("rev-parse", f"{request.expected_base}^{{commit}}").stdout.decode().strip()
        if resolved != request.expected_base:
            raise AllocationError("base does not resolve to the exact commit")

    def _tree_inventory(self, base: str) -> tuple[int, list[tuple[str, str]]]:
        raw = self._git("ls-tree", "-rlz", base).stdout
        total = 0
        attributes: list[tuple[str, str]] = []
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            try:
                metadata, encoded_path = entry.split(b"\t", 1)
                mode, kind, oid, size = metadata.decode("ascii").split()
            except (ValueError, UnicodeDecodeError) as exc:
                raise AllocationError("Git tree inventory is malformed") from exc
            if kind == "blob":
                if size == "-":
                    raise AllocationError("Git blob lacks a materialized size")
                total += int(size)
            path = os.fsdecode(encoded_path)
            if pathlib.PurePosixPath(path).name == ".gitattributes":
                attributes.append((oid, path))
            if mode == "160000":
                raise AllocationError("submodules are not supported in isolated worktrees")
        return total, attributes

    def _reject_external_filters(self, attributes: list[tuple[str, str]]) -> None:
        for oid, _path in attributes:
            body = self._git("cat-file", "blob", oid).stdout
            for raw_line in body.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(b"#"):
                    continue
                fields = line.split()[1:]
                if any(field == b"filter" or field.startswith(b"filter=") for field in fields):
                    raise AllocationError("repository attributes require a content filter")
        info_attributes = self.repository / ".git" / "info" / "attributes"
        if info_attributes.is_file():
            for raw_line in info_attributes.read_bytes().splitlines():
                fields = raw_line.strip().split()[1:]
                if any(field == b"filter" or field.startswith(b"filter=") for field in fields):
                    raise AllocationError("repository-local attributes require a content filter")

    @staticmethod
    def _materialized_bytes(root: pathlib.Path) -> int:
        total = 0
        for directory, names, files in os.walk(root, followlinks=False):
            directory_path = pathlib.Path(directory)
            for name in [*names, *files]:
                path = directory_path / name
                if path == root / ".git":
                    continue
                status = path.lstat()
                if path.is_symlink():
                    total += len(os.fsencode(os.readlink(path)))
                elif path.is_file():
                    total += status.st_size
        return total

    def _verify_worktree(self, path: pathlib.Path, request: AllocationRequest) -> None:
        if path.is_symlink() or not path.is_dir():
            raise AllocationError("allocated worktree path is absent or unsafe")
        head = self._git("rev-parse", "HEAD", cwd=path).stdout.decode().strip()
        branch = self._git("branch", "--show-current", cwd=path).stdout.decode().strip()
        status = self._git("status", "--porcelain=v1", "-z", cwd=path).stdout
        if head != request.expected_base or branch or status:
            raise AllocationError("allocated worktree differs from its immutable base")
        if self._materialized_bytes(path) > request.max_materialized_bytes:
            raise AllocationError("materialized worktree exceeds its byte budget")

    def _is_registered(self, path: pathlib.Path) -> bool:
        output = self._git("worktree", "list", "--porcelain", "-z").stdout
        expected = os.fsencode(str(path.resolve(strict=False)))
        return any(
            field.startswith(b"worktree ") and field.removeprefix(b"worktree ") == expected
            for field in output.split(b"\0")
        )

    def allocate(self, request: AllocationRequest) -> dict[str, Any]:
        self._validate(request)
        operation, intent_path, receipt_path = self._paths(request.run_id)
        worktree = operation / "checkout"
        digest = hashlib.sha256(_canonical(request.document())).hexdigest()
        if receipt_path.exists():
            receipt = _load(receipt_path)
            if receipt.get("request_sha256") != digest or receipt.get("status") != "allocated":
                raise AllocationError("existing allocation receipt conflicts with request")
            self._verify_worktree(worktree, request)
            return receipt
        total, attributes = self._tree_inventory(request.expected_base)
        if total > request.max_materialized_bytes:
            raise AllocationError("Git tree exceeds its materialized-byte budget")
        self._reject_external_filters(attributes)
        intent = {
            "schema": SCHEMA,
            "status": "intent",
            "request": request.document(),
            "request_sha256": digest,
        }
        if intent_path.exists():
            existing = _load(intent_path)
            if existing != intent:
                raise AllocationError("existing allocation intent conflicts with request")
        else:
            operation.mkdir(parents=True, exist_ok=True, mode=0o700)
            operation.chmod(0o700)
            _atomic_json(intent_path, intent)
        if not worktree.exists():
            self._git("worktree", "add", "--detach", str(worktree), request.expected_base)
        self._verify_worktree(worktree, request)
        receipt = {
            "schema": SCHEMA,
            "status": "allocated",
            "run_id": request.run_id,
            "base": request.expected_base,
            "request_sha256": digest,
            "materialized_bytes": self._materialized_bytes(worktree),
            "relative_state_path": f"worktrees/{request.run_id}/checkout",
        }
        _atomic_json(receipt_path, receipt)
        return receipt

    def release(self, request: AllocationRequest) -> dict[str, Any]:
        self._validate(request)
        operation, _intent_path, receipt_path = self._paths(request.run_id)
        worktree = operation / "checkout"
        receipt = _load(receipt_path)
        digest = hashlib.sha256(_canonical(request.document())).hexdigest()
        if receipt.get("request_sha256") != digest:
            raise AllocationError("allocation receipt conflicts with release request")
        if receipt.get("status") == "released":
            if worktree.exists():
                raise AllocationError("released worktree still exists")
            return receipt
        if not worktree.exists():
            if self._is_registered(worktree):
                raise AllocationError("missing worktree remains registered")
            released = {**receipt, "status": "released"}
            _atomic_json(receipt_path, released)
            return released
        self._verify_worktree(worktree, request)
        self._git("worktree", "remove", str(worktree))
        released = {**receipt, "status": "released"}
        _atomic_json(receipt_path, released)
        return released
