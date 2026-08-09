#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Typed, proposal-only creation of local Git candidate commits.

The broker exposes no arbitrary Git argument surface.  It builds a candidate
tree through a private index, records intent before publishing a namespaced
local ref, and reconciles an interrupted publication idempotently.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
from typing import Any


INTENT_SCHEMA = "automonique.git-candidate-intent/v1"
RECEIPT_SCHEMA = "automonique.git-candidate-receipt/v1"
OPERATION = "create_local_candidate"
ZERO_OID = "0" * 40
FORBIDDEN_OPERATIONS = frozenset(
    {
        "push",
        "merge",
        "force",
        "reset",
        "stash",
        "checkout",
        "switch",
        "rebase",
        "remote",
        "tag",
        "history_rewrite",
    }
)
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
WORK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
OID = re.compile(r"^[0-9a-f]{40}$")


class BrokerError(Exception):
    """A candidate request cannot be performed without violating policy."""


@dataclasses.dataclass(frozen=True)
class CandidateRequest:
    operation: str
    run_id: str
    work_id: str
    expected_base: str
    expected_branch: str
    allowed_paths: tuple[str, ...]
    candidate_paths: tuple[str, ...]
    expected_tree: str
    summary: str

    def document(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "run_id": self.run_id,
            "work_id": self.work_id,
            "expected_base": self.expected_base,
            "expected_branch": self.expected_branch,
            "allowed_paths": list(self.allowed_paths),
            "candidate_paths": list(self.candidate_paths),
            "expected_tree": self.expected_tree,
            "summary": self.summary,
        }


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _sha256(document: dict[str, Any] | bytes) -> str:
    body = _canonical_json(document) if isinstance(document, dict) else document
    return hashlib.sha256(body).hexdigest()


def _write_json_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerError(f"cannot read broker state {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise BrokerError(f"broker state {path.name} is not an object")
    return document


def _validate_path(path: str) -> str:
    if not path or "\0" in path or "\n" in path or "\r" in path or "\\" in path:
        raise BrokerError(f"invalid repository path: {path!r}")
    pure = pathlib.PurePosixPath(path.rstrip("/"))
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise BrokerError(f"repository path is not canonical and relative: {path!r}")
    if ".git" in pure.parts:
        raise BrokerError(f"Git metadata cannot be leased: {path!r}")
    return pure.as_posix() + ("/" if path.endswith("/") else "")


def _is_leased(path: str, leases: tuple[str, ...]) -> bool:
    return any(path.startswith(lease) if lease.endswith("/") else path == lease for lease in leases)


def _parse_status(output: bytes) -> tuple[str, ...]:
    fields = output.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(fields):
        entry = fields[index]
        index += 1
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise BrokerError("cannot parse Git porcelain status")
        status = entry[:2]
        paths.append(os.fsdecode(entry[3:]))
        if b"R" in status or b"C" in status:
            if index >= len(fields) or not fields[index]:
                raise BrokerError("rename or copy status lacks its source path")
            paths.append(os.fsdecode(fields[index]))
            index += 1
    return tuple(sorted(set(paths)))


class CandidateBroker:
    """A narrow local Git capability scoped to one repository and state root."""

    def __init__(self, repository: pathlib.Path, state_root: pathlib.Path) -> None:
        self.repository = repository.resolve()
        self.state_root = state_root.resolve()
        if not (self.repository / ".git").exists():
            raise BrokerError("candidate broker requires a Git worktree")
        if self.repository.is_symlink() or self.state_root.is_symlink():
            raise BrokerError("broker roots must not be symlinks")
        executable = shutil.which("git")
        if executable is None:
            raise BrokerError("Git executable is unavailable")
        self.git_executable = pathlib.Path(executable).resolve()

    def _environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(self.state_root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        if additions:
            environment.update(additions)
        return environment

    def _git(
        self,
        *arguments: str,
        input_text: str | None = None,
        environment: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [
                str(self.git_executable),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                *arguments,
            ],
            cwd=self.repository,
            input=input_text,
            capture_output=True,
            text=True,
            env=self._environment(environment),
            check=False,
        )
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            raise BrokerError(f"typed Git operation failed: {detail[0] if detail else 'unknown error'}")
        return completed

    def _git_bytes(self, *arguments: str) -> bytes:
        completed = subprocess.run(
            [
                str(self.git_executable),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                *arguments,
            ],
            cwd=self.repository,
            capture_output=True,
            env=self._environment(),
            check=False,
        )
        if completed.returncode != 0:
            raise BrokerError("typed Git inspection failed")
        return completed.stdout

    def _operation_dir(self, run_id: str) -> pathlib.Path:
        return self.state_root / "git-candidates" / run_id

    def _intent_path(self, run_id: str) -> pathlib.Path:
        return self._operation_dir(run_id) / "intent.json"

    def _receipt_path(self, run_id: str) -> pathlib.Path:
        return self._operation_dir(run_id) / "receipt.json"

    def _validate_request(self, request: CandidateRequest) -> CandidateRequest:
        if request.operation != OPERATION:
            label = "forbidden" if request.operation in FORBIDDEN_OPERATIONS else "unknown"
            raise BrokerError(f"{label} Git operation: {request.operation}")
        if not RUN_ID.fullmatch(request.run_id):
            raise BrokerError("run ID cannot form a safe candidate ref")
        if not WORK_ID.fullmatch(request.work_id):
            raise BrokerError("work ID is invalid")
        if not OID.fullmatch(request.expected_base):
            raise BrokerError("expected base is not a full SHA-1 object ID")
        if not request.expected_branch or any(ch in request.expected_branch for ch in "\0\n\r"):
            raise BrokerError("expected branch is invalid")
        if not request.summary or len(request.summary) > 100 or request.summary.strip() != request.summary:
            raise BrokerError("summary must be a non-empty trimmed line of at most 100 characters")
        if any(ord(ch) < 32 for ch in request.summary):
            raise BrokerError("summary contains a control character")
        leases = tuple(_validate_path(path) for path in request.allowed_paths)
        paths = tuple(sorted({_validate_path(path) for path in request.candidate_paths}))
        if not leases or not paths:
            raise BrokerError("candidate and lease paths must be non-empty")
        if len(paths) != len(request.candidate_paths):
            raise BrokerError("candidate paths must be unique and sorted canonically")
        outside = [path for path in paths if not _is_leased(path, leases)]
        if outside:
            raise BrokerError("candidate contains out-of-lease paths: " + ", ".join(outside))
        for relative in paths:
            current = self.repository
            for part in pathlib.PurePosixPath(relative).parts:
                current /= part
                if current.exists() and current.is_symlink():
                    raise BrokerError(f"candidate path traverses a symlink: {relative}")
        if not OID.fullmatch(request.expected_tree):
            raise BrokerError("expected candidate tree is not a full object ID")
        return dataclasses.replace(request, allowed_paths=leases, candidate_paths=paths)

    def _validate_source(self, request: CandidateRequest) -> None:
        head = self._git("rev-parse", "HEAD").stdout.strip()
        branch = self._git("branch", "--show-current").stdout.strip()
        if head != request.expected_base:
            raise BrokerError("Git HEAD differs from the expected base")
        if branch != request.expected_branch:
            raise BrokerError("Git branch differs from the expected branch")
        actual = _parse_status(
            self._git_bytes("status", "--porcelain=v1", "-z", "--untracked-files=all")
        )
        if actual != request.candidate_paths:
            raise BrokerError(
                "dirty paths differ from the candidate request: "
                f"expected {list(request.candidate_paths)!r}, observed {list(actual)!r}"
            )

    def _prepare_tree(self, request: CandidateRequest) -> str:
        operation_dir = self._operation_dir(request.run_id)
        operation_dir.mkdir(parents=True, exist_ok=True)
        index = operation_dir / "private.index"
        if index.exists():
            index.unlink()
        index_environment = {"GIT_INDEX_FILE": str(index)}
        try:
            self._git("read-tree", request.expected_base, environment=index_environment)
            attributes = self._git_bytes(
                "check-attr", "-z", "filter", "--", *request.candidate_paths
            ).split(b"\0")
            values = attributes[2::3]
            if any(value not in {b"", b"unspecified", b"unset"} for value in values):
                raise BrokerError("candidate paths require a Git content filter")
            self._git(
                "add", "-A", "--", *request.candidate_paths, environment=index_environment
            )
            tree = self._git("write-tree", environment=index_environment).stdout.strip()
        finally:
            if index.exists():
                index.unlink()
        if not OID.fullmatch(tree):
            raise BrokerError("private index did not produce a tree object")
        changed = tuple(
            sorted(
                field.decode("utf-8", "surrogateescape")
                for field in self._git_bytes(
                    "diff-tree", "--no-commit-id", "--name-only", "-z", "-r",
                    request.expected_base, tree,
                ).split(b"\0")
                if field
            )
        )
        if changed != request.candidate_paths:
            raise BrokerError(
                "candidate tree paths differ from the typed request: "
                f"expected {list(request.candidate_paths)!r}, tree {list(changed)!r}"
            )
        return tree

    def snapshot(
        self,
        *,
        expected_base: str,
        expected_branch: str,
        allowed_paths: tuple[str, ...],
        candidate_paths: tuple[str, ...],
    ) -> str:
        """Return the exact private-index tree for a validated dirty snapshot."""

        request = CandidateRequest(
            operation=OPERATION,
            run_id="snapshot",
            work_id="snapshot",
            expected_base=expected_base,
            expected_branch=expected_branch,
            allowed_paths=allowed_paths,
            candidate_paths=candidate_paths,
            expected_tree=expected_base,
            summary="Snapshot candidate",
        )
        request = self._validate_request(request)
        self._validate_source(request)
        return self._prepare_tree(request)

    def prepare(self, request: CandidateRequest) -> dict[str, Any]:
        """Validate and durably record intent without publishing a Git ref."""

        request = self._validate_request(request)
        request_document = request.document()
        request_digest = _sha256(request_document)
        intent_path = self._intent_path(request.run_id)
        receipt_path = self._receipt_path(request.run_id)
        if receipt_path.exists():
            receipt = _load_json(receipt_path)
            if receipt.get("request_sha256") != request_digest:
                raise BrokerError("run ID already has a different candidate receipt")
            self._verify_receipt(receipt)
            return _load_json(intent_path)
        if intent_path.exists():
            intent = _load_json(intent_path)
            if intent.get("request_sha256") != request_digest:
                raise BrokerError("run ID already has a different candidate intent")
            return intent

        self._validate_source(request)
        tree = self._prepare_tree(request)
        if tree != request.expected_tree:
            raise BrokerError("candidate tree differs from the checked snapshot")
        created_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        message = (
            f"{request.summary}\n\n"
            f"Automonique-Work: {request.work_id}\n"
            f"Automonique-Run: {request.run_id}\n"
            f"Automonique-Tree: {tree}\n"
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "status": "commit_intent",
            "operation": OPERATION,
            "request": request_document,
            "request_sha256": request_digest,
            "tree_oid": tree,
            "ref": f"refs/automonique/candidates/{request.run_id}",
            "commit_message": message,
            "commit_message_sha256": _sha256(message.encode()),
            "created_at": created_at,
        }
        _write_json_atomic(intent_path, intent)
        return intent

    def _request_from_intent(self, intent: dict[str, Any]) -> CandidateRequest:
        if intent.get("schema") != INTENT_SCHEMA or intent.get("operation") != OPERATION:
            raise BrokerError("candidate intent schema or operation is invalid")
        raw = intent.get("request")
        if not isinstance(raw, dict) or _sha256(raw) != intent.get("request_sha256"):
            raise BrokerError("candidate intent request digest differs")
        try:
            request = CandidateRequest(
                operation=raw["operation"],
                run_id=raw["run_id"],
                work_id=raw["work_id"],
                expected_base=raw["expected_base"],
                expected_branch=raw["expected_branch"],
                allowed_paths=tuple(raw["allowed_paths"]),
                candidate_paths=tuple(raw["candidate_paths"]),
                expected_tree=raw["expected_tree"],
                summary=raw["summary"],
            )
        except (KeyError, TypeError) as exc:
            raise BrokerError("candidate intent request is incomplete") from exc
        request = self._validate_request(request)
        expected_ref = f"refs/automonique/candidates/{request.run_id}"
        if intent.get("ref") != expected_ref or not OID.fullmatch(str(intent.get("tree_oid", ""))):
            raise BrokerError("candidate intent ref or tree is invalid")
        message = intent.get("commit_message")
        if not isinstance(message, str) or _sha256(message.encode()) != intent.get(
            "commit_message_sha256"
        ):
            raise BrokerError("candidate intent message digest differs")
        if not isinstance(intent.get("created_at"), str):
            raise BrokerError("candidate intent timestamp is missing")
        return request

    def _commit_oid(self, intent: dict[str, Any], request: CandidateRequest) -> str:
        timestamp = intent["created_at"]
        environment = {
            "GIT_AUTHOR_NAME": "Automonique Candidate",
            "GIT_AUTHOR_EMAIL": "candidate@automonique.invalid",
            "GIT_COMMITTER_NAME": "Automonique Candidate",
            "GIT_COMMITTER_EMAIL": "candidate@automonique.invalid",
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_DATE": timestamp,
        }
        commit = self._git(
            "commit-tree",
            intent["tree_oid"],
            "-p",
            request.expected_base,
            input_text=intent["commit_message"],
            environment=environment,
        ).stdout.strip()
        if not OID.fullmatch(commit):
            raise BrokerError("Git did not return a candidate commit object ID")
        return commit

    def _ref_oid(self, ref: str) -> str | None:
        result = self._git("rev-parse", "--verify", "--quiet", ref, check=False)
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise BrokerError("cannot inspect candidate ref")
        oid = result.stdout.strip()
        if not OID.fullmatch(oid):
            raise BrokerError("candidate ref does not resolve to a commit ID")
        return oid

    def _mark_reconciliation_required(self, run_id: str, intent: dict[str, Any], reason: str) -> None:
        updated = dict(intent)
        updated.update(
            {
                "status": "reconciliation_required",
                "reconciliation_reason": reason,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            }
        )
        _write_json_atomic(self._intent_path(run_id), updated)

    def _verify_receipt(self, receipt: dict[str, Any]) -> None:
        if receipt.get("schema") != RECEIPT_SCHEMA:
            raise BrokerError("candidate receipt schema is invalid")
        ref = receipt.get("ref")
        commit = receipt.get("commit_oid")
        if not isinstance(ref, str) or not OID.fullmatch(str(commit or "")):
            raise BrokerError("candidate receipt ref or commit is invalid")
        if self._ref_oid(ref) != commit:
            raise BrokerError("candidate ref differs from its receipt")
        tree = self._git("rev-parse", f"{commit}^{{tree}}").stdout.strip()
        parent = self._git("rev-parse", f"{commit}^").stdout.strip()
        if tree != receipt.get("tree_oid") or parent != receipt.get("parent_oid"):
            raise BrokerError("candidate commit tree or parent differs from its receipt")

    def reconcile(self, run_id: str) -> dict[str, Any]:
        """Complete or verify one previously recorded candidate intent."""

        if not RUN_ID.fullmatch(run_id):
            raise BrokerError("run ID cannot form a safe candidate ref")
        intent = _load_json(self._intent_path(run_id))
        request = self._request_from_intent(intent)
        receipt_path = self._receipt_path(run_id)
        if receipt_path.exists():
            receipt = _load_json(receipt_path)
            if receipt.get("request_sha256") != intent.get("request_sha256"):
                raise BrokerError("candidate receipt belongs to a different request")
            self._verify_receipt(receipt)
            return receipt

        commit = self._commit_oid(intent, request)
        existing = self._ref_oid(intent["ref"])
        if existing is None:
            try:
                self._validate_source(request)
                if (
                    self._prepare_tree(request) != intent["tree_oid"]
                    or intent["tree_oid"] != request.expected_tree
                ):
                    raise BrokerError("candidate worktree changed after intent")
                updated = self._git(
                    "update-ref", intent["ref"], commit, ZERO_OID, check=False
                )
                if updated.returncode != 0:
                    existing = self._ref_oid(intent["ref"])
                    if existing != commit:
                        raise BrokerError("candidate ref compare-and-swap failed")
            except BrokerError as exc:
                self._mark_reconciliation_required(run_id, intent, str(exc))
                raise
        elif existing != commit:
            reason = "candidate ref exists with a different commit"
            self._mark_reconciliation_required(run_id, intent, reason)
            raise BrokerError(reason)

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": "candidate_committed",
            "operation": OPERATION,
            "run_id": run_id,
            "work_id": request.work_id,
            "request_sha256": intent["request_sha256"],
            "ref": intent["ref"],
            "commit_oid": commit,
            "tree_oid": intent["tree_oid"],
            "parent_oid": request.expected_base,
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        }
        _write_json_atomic(receipt_path, receipt)
        completed_intent = dict(intent)
        completed_intent.update(
            {
                "status": "candidate_committed",
                "commit_oid": commit,
                "receipt_sha256": _sha256(receipt),
                "updated_at": receipt["completed_at"],
            }
        )
        _write_json_atomic(self._intent_path(run_id), completed_intent)
        return receipt

    def create(self, request: CandidateRequest) -> dict[str, Any]:
        """Prepare and reconcile one typed candidate operation."""

        self.prepare(request)
        return self.reconcile(request.run_id)

    def abandon(self, run_id: str) -> dict[str, Any]:
        """Abandon only an operation proven to have no published candidate ref."""

        if not RUN_ID.fullmatch(run_id):
            raise BrokerError("run ID cannot form a safe candidate ref")
        intent_path = self._intent_path(run_id)
        ref = f"refs/automonique/candidates/{run_id}"
        if self._ref_oid(ref) is not None:
            raise BrokerError("published candidate ref must be reconciled, not abandoned")
        if intent_path.exists():
            intent = _load_json(intent_path)
            self._request_from_intent(intent)
            intent.update(
                {
                    "status": "abandoned",
                    "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                }
            )
            _write_json_atomic(intent_path, intent)
        return {"status": "abandoned", "run_id": run_id, "ref": ref}
