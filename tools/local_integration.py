#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Typed local-main integration followed by an exact fast-forward-only push."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tomllib
from typing import Any


INTENT_SCHEMA = "automonique.local-integration-intent/v1"
RECEIPT_SCHEMA = "automonique.local-integration-receipt/v1"
CANDIDATE_RECEIPT_SCHEMA = "automonique.git-candidate-receipt/v1"
AUTHORITY_SCHEMA = "automonique.authority/v1"
LOCAL_REF = "refs/heads/main"
REMOTE = "origin"
REMOTE_REF = "refs/heads/main"
OID = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class IntegrationError(Exception):
    """The exact integration cannot be completed or reconciled safely."""


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def file_sha256(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_sha256(document: dict[str, Any]) -> str:
    return sha256_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )


def write_json_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise IntegrationError(f"{path.name} is not a JSON object")
    return document


def parse_status(output: bytes) -> tuple[str, ...]:
    fields = output.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(fields):
        entry = fields[index]
        index += 1
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise IntegrationError("cannot parse Git worktree status")
        status = entry[:2]
        paths.append(os.fsdecode(entry[3:]))
        if b"R" in status or b"C" in status:
            if index >= len(fields) or not fields[index]:
                raise IntegrationError("rename or copy status is incomplete")
            paths.append(os.fsdecode(fields[index]))
            index += 1
    return tuple(sorted(set(paths)))


class LocalIntegration:
    """Integrate one exact candidate into local and configured remote main."""

    def __init__(
        self,
        repository: pathlib.Path,
        state_root: pathlib.Path,
        authority_path: pathlib.Path,
        authority_sha256: str,
    ) -> None:
        self.repository = repository.resolve()
        self.state_root = state_root.resolve()
        self.authority_path = authority_path.resolve()
        self.authority_sha256 = authority_sha256
        if not (self.repository / ".git").exists():
            raise IntegrationError("local integration requires a Git worktree")
        if self.repository.is_symlink() or self.state_root.is_symlink():
            raise IntegrationError("integration roots must not be symlinks")
        executable = shutil.which("git")
        if executable is None:
            raise IntegrationError("Git executable is unavailable")
        self.git_executable = pathlib.Path(executable).resolve()
        try:
            relative_state = self.state_root.relative_to(self.repository)
        except ValueError:
            relative_state = None
        if relative_state is not None and not self._is_ignored(relative_state.as_posix()):
            raise IntegrationError("integration state inside the worktree must be ignored")

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
        environment: dict[str, str] | None = None,
        check: bool = True,
        binary: bool = False,
    ) -> subprocess.CompletedProcess[Any]:
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
            text=not binary,
            env=self._environment(environment),
            check=False,
        )
        if check and completed.returncode != 0:
            output = completed.stderr or completed.stdout
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            detail = output.strip().splitlines()
            raise IntegrationError(
                f"typed Git operation failed: {detail[0] if detail else 'unknown error'}"
            )
        return completed

    def _is_ignored(self, relative: str) -> bool:
        return self._git("check-ignore", "--quiet", "--", relative, check=False).returncode == 0

    def _operation_dir(self, run_id: str) -> pathlib.Path:
        return self.state_root / "local-integrations" / run_id

    def _intent_path(self, run_id: str) -> pathlib.Path:
        return self._operation_dir(run_id) / "intent.json"

    def _receipt_path(self, run_id: str) -> pathlib.Path:
        return self._operation_dir(run_id) / "receipt.json"

    def _authority(self) -> dict[str, Any]:
        try:
            body = self.authority_path.read_bytes()
            document = tomllib.loads(body.decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise IntegrationError(f"cannot read integration authority: {exc}") from exc
        if sha256_bytes(body) != self.authority_sha256:
            raise IntegrationError("integration authority digest differs")
        if document.get("schema") != AUTHORITY_SCHEMA:
            raise IntegrationError("integration authority schema differs")
        if document.get("advance_verified_local_main") is not True:
            raise IntegrationError("authority denies local main integration")
        if document.get("publish_verified_origin_main_fast_forward") is not True:
            raise IntegrationError("authority denies push")
        if document.get("local_main_ref") != LOCAL_REF:
            raise IntegrationError("authority does not select local main")
        if document.get("publication_remote") != REMOTE:
            raise IntegrationError("authority does not select origin")
        if document.get("publication_ref") != REMOTE_REF:
            raise IntegrationError("authority does not select main")
        required = (
            "require_exact_tree_verification",
            "require_fast_forward",
            "require_expected_tip",
        )
        if any(document.get(field) is not True for field in required):
            raise IntegrationError("authority lacks required exact integration controls")
        denied = (
            "push",
            "merge_protected_branch",
            "force_update",
            "history_rewrite",
            "edit_remote",
            "other_ref_update",
            "other_remote_update",
        )
        if any(document.get(field) is not False for field in denied):
            raise IntegrationError("authority must explicitly deny force and remote edits")
        return document

    def _ref_oid(self, ref: str) -> str | None:
        result = self._git("rev-parse", "--verify", "--quiet", ref, check=False)
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise IntegrationError(f"cannot inspect ref {ref}")
        oid = result.stdout.strip()
        if not OID.fullmatch(oid):
            raise IntegrationError(f"ref {ref} is not a full object ID")
        return oid

    def _remote_oid(self) -> str | None:
        result = self._git("ls-remote", "--refs", REMOTE, REMOTE_REF)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) != 1:
            raise IntegrationError("origin/main resolved ambiguously")
        fields = lines[0].split()
        if len(fields) != 2 or fields[1] != REMOTE_REF or not OID.fullmatch(fields[0]):
            raise IntegrationError("origin/main returned an invalid advertisement")
        return fields[0]

    def _validate_candidate(self, candidate: dict[str, Any]) -> dict[str, Any]:
        if candidate.get("schema") != CANDIDATE_RECEIPT_SCHEMA:
            raise IntegrationError("candidate receipt schema differs")
        if (
            candidate.get("status") != "candidate_committed"
            or candidate.get("operation") != "create_local_candidate"
        ):
            raise IntegrationError("candidate receipt is not a completed local candidate")
        required = ("run_id", "ref", "commit_oid", "tree_oid", "parent_oid")
        if any(not isinstance(candidate.get(field), str) for field in required):
            raise IntegrationError("candidate receipt is incomplete")
        run_id = candidate["run_id"]
        if not RUN_ID.fullmatch(run_id):
            raise IntegrationError("candidate run ID is invalid")
        expected_ref = f"refs/automonique/candidates/{run_id}"
        if candidate["ref"] != expected_ref:
            raise IntegrationError("candidate receipt names an unexpected ref")
        for field in ("commit_oid", "tree_oid", "parent_oid"):
            if not OID.fullmatch(candidate[field]):
                raise IntegrationError(f"candidate {field} is not a full object ID")
        if self._ref_oid(expected_ref) != candidate["commit_oid"]:
            raise IntegrationError("candidate ref differs from its receipt")
        commit = candidate["commit_oid"]
        tree = self._git("rev-parse", f"{commit}^{{tree}}").stdout.strip()
        parent = self._git("rev-parse", f"{commit}^").stdout.strip()
        if tree != candidate["tree_oid"] or parent != candidate["parent_oid"]:
            raise IntegrationError("candidate commit tree or parent differs from its receipt")
        return candidate

    def _worktree_tree(self, parent: str, run_id: str) -> str:
        operation = self._operation_dir(run_id)
        operation.mkdir(parents=True, exist_ok=True)
        index = operation / "snapshot.index"
        if index.exists():
            index.unlink()
        environment = {"GIT_INDEX_FILE": str(index)}
        status = self._git(
            "status", "--porcelain=v1", "-z", "--untracked-files=all", binary=True
        ).stdout
        paths = parse_status(status)
        if paths:
            attributes = self._git(
                "check-attr", "-z", "filter", "--", *paths, binary=True
            ).stdout.split(b"\0")
            if any(
                value not in {b"", b"unspecified", b"unset"}
                for value in attributes[2::3]
            ):
                raise IntegrationError("worktree requires a Git content filter")
        try:
            self._git("read-tree", parent, environment=environment)
            if paths:
                self._git("add", "-A", "--", *paths, environment=environment)
            tree = self._git("write-tree", environment=environment).stdout.strip()
        finally:
            if index.exists():
                index.unlink()
        if not OID.fullmatch(tree):
            raise IntegrationError("worktree snapshot did not produce a tree")
        return tree

    def _validate_start(self, candidate: dict[str, Any]) -> None:
        if self._git("branch", "--show-current").stdout.strip() != "main":
            raise IntegrationError("current branch is not main")
        if self._ref_oid(LOCAL_REF) != candidate["parent_oid"]:
            raise IntegrationError("local main differs from candidate parent")
        if self._worktree_tree(candidate["parent_oid"], candidate["run_id"]) != candidate[
            "tree_oid"
        ]:
            raise IntegrationError("worktree differs from the exact candidate tree")
        remote = self._remote_oid()
        if remote != candidate["parent_oid"]:
            raise IntegrationError("origin/main differs from candidate parent")

    def prepare(
        self, candidate_receipt: pathlib.Path, candidate_receipt_sha256: str
    ) -> dict[str, Any]:
        """Validate inputs and persist intent before index or ref mutation."""

        authority = self._authority()
        if file_sha256(candidate_receipt) != candidate_receipt_sha256:
            raise IntegrationError("candidate receipt digest differs")
        candidate = self._validate_candidate(load_json(candidate_receipt))
        run_id = candidate["run_id"]
        intent_path = self._intent_path(run_id)
        receipt_path = self._receipt_path(run_id)
        if receipt_path.exists():
            receipt = load_json(receipt_path)
            self._verify_receipt(receipt)
            return load_json(intent_path)
        if intent_path.exists():
            intent = load_json(intent_path)
            if intent.get("candidate_receipt_sha256") != candidate_receipt_sha256:
                raise IntegrationError("run already has a different integration intent")
            self._validate_intent(intent)
            return intent
        self._validate_start(candidate)
        payload = {
            "run_id": run_id,
            "candidate_ref": candidate["ref"],
            "candidate_commit": candidate["commit_oid"],
            "candidate_tree": candidate["tree_oid"],
            "expected_parent": candidate["parent_oid"],
            "local_ref": LOCAL_REF,
            "remote": REMOTE,
            "remote_ref": REMOTE_REF,
            "candidate_receipt_sha256": candidate_receipt_sha256,
            "authority_sha256": self.authority_sha256,
            "authority_decision": authority.get("decision"),
        }
        intent = {
            "schema": INTENT_SCHEMA,
            "status": "integration_intent",
            "payload": payload,
            "payload_sha256": canonical_sha256(payload),
            "candidate_receipt_sha256": candidate_receipt_sha256,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        }
        write_json_atomic(intent_path, intent)
        return intent

    def _validate_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("schema") != INTENT_SCHEMA:
            raise IntegrationError("integration intent schema differs")
        payload = intent.get("payload")
        if not isinstance(payload, dict) or canonical_sha256(payload) != intent.get(
            "payload_sha256"
        ):
            raise IntegrationError("integration intent payload digest differs")
        if payload.get("authority_sha256") != self.authority_sha256:
            raise IntegrationError("integration intent authority digest differs")
        if payload.get("local_ref") != LOCAL_REF or payload.get("remote") != REMOTE:
            raise IntegrationError("integration intent targets an unexpected ref or remote")
        if payload.get("remote_ref") != REMOTE_REF:
            raise IntegrationError("integration intent targets an unexpected remote ref")
        for field in ("candidate_commit", "candidate_tree", "expected_parent"):
            if not OID.fullmatch(str(payload.get(field, ""))):
                raise IntegrationError("integration intent contains an invalid object ID")
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise IntegrationError("integration intent run ID is invalid")
        if payload.get("candidate_ref") != f"refs/automonique/candidates/{run_id}":
            raise IntegrationError("integration intent candidate ref differs")
        return payload

    def _mark_required(self, run_id: str, intent: dict[str, Any], reason: str) -> None:
        updated = dict(intent)
        updated.update(
            {
                "status": "reconciliation_required",
                "reason": reason,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            }
        )
        write_json_atomic(self._intent_path(run_id), updated)

    def _verify_receipt(self, receipt: dict[str, Any]) -> None:
        if receipt.get("schema") != RECEIPT_SCHEMA:
            raise IntegrationError("integration receipt schema differs")
        commit = receipt.get("commit_oid")
        if not OID.fullmatch(str(commit or "")):
            raise IntegrationError("integration receipt commit is invalid")
        if self._ref_oid(LOCAL_REF) != commit or self._remote_oid() != commit:
            raise IntegrationError("local or remote main differs from the integration receipt")

    def reconcile(self, run_id: str) -> dict[str, Any]:
        """Reconcile local CAS and ambiguous exact push without force."""

        if not RUN_ID.fullmatch(run_id):
            raise IntegrationError("integration run ID is invalid")
        self._authority()
        intent = load_json(self._intent_path(run_id))
        payload = self._validate_intent(intent)
        receipt_path = self._receipt_path(run_id)
        if receipt_path.exists():
            receipt = load_json(receipt_path)
            self._verify_receipt(receipt)
            return receipt
        try:
            if self._ref_oid(payload["candidate_ref"]) != payload["candidate_commit"]:
                raise IntegrationError("candidate ref changed before integration")
            commit_tree = self._git(
                "rev-parse", f"{payload['candidate_commit']}^{{tree}}"
            ).stdout.strip()
            commit_parent = self._git(
                "rev-parse", f"{payload['candidate_commit']}^"
            ).stdout.strip()
            if commit_tree != payload["candidate_tree"] or commit_parent != payload[
                "expected_parent"
            ]:
                raise IntegrationError("candidate object changed before integration")

            if self._git("branch", "--show-current").stdout.strip() != "main":
                raise IntegrationError("current branch changed before integration")
            local = self._ref_oid(LOCAL_REF)
            if local == payload["expected_parent"]:
                if self._worktree_tree(
                    payload["expected_parent"], run_id
                ) != payload["candidate_tree"]:
                    raise IntegrationError("worktree changed before integration")
                self._git("read-tree", payload["candidate_tree"])
                update = self._git(
                    "update-ref",
                    LOCAL_REF,
                    payload["candidate_commit"],
                    payload["expected_parent"],
                    check=False,
                )
                if update.returncode != 0 and self._ref_oid(LOCAL_REF) != payload[
                    "candidate_commit"
                ]:
                    raise IntegrationError("local main compare-and-swap failed")
            elif local != payload["candidate_commit"]:
                raise IntegrationError("local main has an unrelated revision")

            remote = self._remote_oid()
            if remote == payload["expected_parent"]:
                pushed = self._git(
                    "push",
                    "--porcelain",
                    REMOTE,
                    f"{payload['candidate_commit']}:{REMOTE_REF}",
                    check=False,
                )
                remote = self._remote_oid()
                if pushed.returncode != 0 and remote != payload["candidate_commit"]:
                    raise IntegrationError("exact fast-forward push failed")
            if remote != payload["candidate_commit"]:
                raise IntegrationError("origin/main has an unrelated revision")

            if self._worktree_tree(
                payload["candidate_commit"], run_id
            ) != payload["candidate_tree"]:
                raise IntegrationError("worktree differs after local integration")
            self._git("read-tree", payload["candidate_tree"])
        except IntegrationError as exc:
            self._mark_required(run_id, intent, str(exc))
            raise

        completed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": "integrated_and_pushed",
            "run_id": run_id,
            "commit_oid": payload["candidate_commit"],
            "tree_oid": payload["candidate_tree"],
            "parent_oid": payload["expected_parent"],
            "local_ref": LOCAL_REF,
            "remote": REMOTE,
            "remote_ref": REMOTE_REF,
            "authority_sha256": self.authority_sha256,
            "completed_at": completed_at,
        }
        write_json_atomic(receipt_path, receipt)
        completed = dict(intent)
        completed.update(
            {
                "status": "integrated_and_pushed",
                "receipt_sha256": canonical_sha256(receipt),
                "updated_at": completed_at,
            }
        )
        write_json_atomic(self._intent_path(run_id), completed)
        return receipt

    def integrate(
        self, candidate_receipt: pathlib.Path, candidate_receipt_sha256: str
    ) -> dict[str, Any]:
        intent = self.prepare(candidate_receipt, candidate_receipt_sha256)
        payload = self._validate_intent(intent)
        return self.reconcile(payload["run_id"])
