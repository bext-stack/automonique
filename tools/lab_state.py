#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Durable state and lease primitives for the proposal-only lab harness."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import enum
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat
from collections.abc import Iterator, Sequence
from typing import Any


SCHEMA = "automonique.lab-state/v1"
MAX_ID_LENGTH = 80
MAX_PAYLOAD_BYTES = 64 * 1024
OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
TERMINAL_STATES = frozenset({"cancelled", "succeeded", "failed"})


class LabStateError(Exception):
    """Base class for state-store denials."""


class ValidationError(LabStateError):
    """An input is not a bounded canonical value."""


class ConflictError(LabStateError):
    """A lease, revision, identifier, or effect conflicts with durable state."""


class NotFoundError(LabStateError):
    """A requested durable object does not exist."""


class TransitionError(LabStateError):
    """An attempt state transition is not allowed."""


class AttemptState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class RecordKind(str, enum.Enum):
    EVENT = "event"
    CHECKPOINT = "checkpoint"
    EVIDENCE = "evidence"


class EvidenceAuthority(str, enum.Enum):
    BROKER_OBSERVED = "broker_observed"
    DETERMINISTIC_CHECK = "deterministic_check"
    WORKER_REPORTED = "worker_reported"
    PROVIDER_REPORTED = "provider_reported"


class EffectStatus(str, enum.Enum):
    PREPARED = "prepared"
    COMPLETED = "completed"


@dataclasses.dataclass(frozen=True)
class Attempt:
    attempt_id: str
    work_id: str
    expected_base: str
    state: AttemptState
    revision: int
    last_sequence: int
    created_at: str
    updated_at: str


@dataclasses.dataclass(frozen=True)
class JournalRecord:
    attempt_id: str
    sequence: int
    kind: RecordKind
    record_id: str
    name: str
    authority: EvidenceAuthority | None
    payload: dict[str, Any]
    created_at: str


@dataclasses.dataclass(frozen=True)
class Effect:
    effect_id: str
    attempt_id: str
    kind: str
    request_sha256: str
    status: EffectStatus
    result_sha256: str | None
    result: dict[str, Any] | None
    created_at: str
    updated_at: str


_TRANSITIONS: dict[AttemptState, frozenset[AttemptState]] = {
    AttemptState.QUEUED: frozenset(
        {AttemptState.RUNNING, AttemptState.CANCELLED, AttemptState.FAILED}
    ),
    AttemptState.RUNNING: frozenset(
        {
            AttemptState.PAUSED,
            AttemptState.CANCELLED,
            AttemptState.SUCCEEDED,
            AttemptState.FAILED,
        }
    ),
    AttemptState.PAUSED: frozenset(
        {AttemptState.RUNNING, AttemptState.CANCELLED, AttemptState.FAILED}
    ),
    AttemptState.CANCELLED: frozenset(),
    AttemptState.SUCCEEDED: frozenset(),
    AttemptState.FAILED: frozenset(),
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _bounded_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not OPAQUE_ID.fullmatch(value):
        raise ValidationError(
            f"{label} must be an opaque identifier of at most {MAX_ID_LENGTH} characters"
        )
    return value


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _payload_document(value: dict[str, Any], label: str) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} is not JSON serializable") from exc
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValidationError(f"{label} exceeds {MAX_PAYLOAD_BYTES} bytes")
    return encoded.decode("utf-8"), hashlib.sha256(encoded).hexdigest()


def canonical_repo_path(repository: pathlib.Path, raw_path: str) -> str:
    """Return one canonical relative path or fail before lease acquisition."""

    if not isinstance(raw_path, str) or not raw_path:
        raise ValidationError("lease path must be a non-empty string")
    if any(character in raw_path for character in ("\0", "\n", "\r", "\\")):
        raise ValidationError("lease path contains a forbidden character")
    if raw_path.startswith("/"):
        raise ValidationError("lease path must be repository-relative")
    stripped = raw_path[:-1] if raw_path.endswith("/") else raw_path
    segments = stripped.split("/")
    if not stripped or any(segment in {"", ".", ".."} for segment in segments):
        raise ValidationError("lease path is not canonical")
    if ".git" in segments:
        raise ValidationError("Git metadata cannot be leased")

    repository = repository.resolve(strict=True)
    current = repository
    for segment in segments:
        current = current / segment
        try:
            current.lstat()
        except FileNotFoundError:
            continue
        if current.is_symlink():
            try:
                resolved = current.resolve(strict=True)
                resolved.relative_to(repository)
            except (OSError, ValueError) as exc:
                raise ValidationError("lease path escapes through a symlink") from exc
            raise ValidationError("lease path traverses a symlink")
    return "/".join(segments)


def _paths_overlap(left: str, right: str) -> bool:
    left_parts = left.split("/")
    right_parts = right.split("/")
    shorter = min(len(left_parts), len(right_parts))
    return left_parts[:shorter] == right_parts[:shorter]


def _absolute_without_resolving(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: pathlib.Path, label: str) -> None:
    """Reject every existing symlink in a lexical absolute path."""

    absolute = _absolute_without_resolving(path)
    current = pathlib.Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValidationError(f"{label} contains a symlink component")


class LabStateStore:
    """SQLite-backed attempts, records, effects, and persistent path leases."""

    def __init__(
        self,
        state_path: pathlib.Path,
        repository: pathlib.Path,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if busy_timeout_ms < 1 or busy_timeout_ms > 60_000:
            raise ValidationError("busy timeout must be between 1 and 60000 ms")
        state_path = _absolute_without_resolving(pathlib.Path(state_path))
        _reject_symlink_components(state_path, "state path")
        state_path.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_components(state_path.parent, "state directory")
        directory_mode = state_path.parent.lstat().st_mode
        if not stat.S_ISDIR(directory_mode):
            raise ValidationError("state directory must be a directory")
        os.chmod(state_path.parent, 0o700, follow_symlinks=False)
        if stat.S_IMODE(state_path.parent.lstat().st_mode) != 0o700:
            raise ValidationError("state directory must have mode 0700")
        database_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        database_fd = os.open(state_path, database_flags, 0o600)
        os.close(database_fd)
        _reject_symlink_components(state_path, "state path")
        raw_repository = pathlib.Path(repository)
        if raw_repository.is_symlink():
            raise ValidationError("repository root must not be a symlink")
        self.repository = raw_repository.resolve(strict=True)
        if not self.repository.is_dir():
            raise ValidationError("repository root must be a directory")
        self.state_path = state_path
        self._connection = sqlite3.connect(
            self.state_path,
            isolation_level=None,
            timeout=busy_timeout_ms / 1000,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        self._create_schema()
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            self.close()
            raise

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None  # type: ignore[assignment]

    def __enter__(self) -> LabStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection
        began = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            began = True
            yield connection
            connection.execute("COMMIT")
            began = False
        except Exception:
            if began and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                work_id TEXT NOT NULL,
                expected_base TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('queued','running','paused','cancelled','succeeded','failed')
                ),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leases (
                attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                released_at TEXT,
                PRIMARY KEY (attempt_id, path)
            );
            CREATE INDEX IF NOT EXISTS active_leases
                ON leases(path) WHERE released_at IS NULL;
            CREATE TABLE IF NOT EXISTS journal (
                attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                kind TEXT NOT NULL CHECK (kind IN ('event','checkpoint','evidence')),
                record_id TEXT NOT NULL,
                name TEXT NOT NULL,
                authority TEXT CHECK (
                    (kind != 'evidence' AND authority IS NULL) OR
                    (kind = 'evidence' AND authority IN (
                        'broker_observed','deterministic_check',
                        'worker_reported','provider_reported'
                    ))
                ),
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (attempt_id, sequence),
                UNIQUE (attempt_id, kind, record_id)
            );
            CREATE TABLE IF NOT EXISTS effects (
                effect_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('prepared','completed')),
                result_sha256 TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='schema'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES('schema',?)", (SCHEMA,)
                )
            elif row["value"] != SCHEMA:
                raise LabStateError("state database schema is unsupported")

    def pragma_values(self) -> dict[str, int | str]:
        """Expose non-sensitive database durability settings for verification."""

        return {
            "journal_mode": self._connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0],
            "synchronous": self._connection.execute(
                "PRAGMA synchronous"
            ).fetchone()[0],
            "foreign_keys": self._connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0],
            "busy_timeout": self._connection.execute(
                "PRAGMA busy_timeout"
            ).fetchone()[0],
        }

    def create_attempt(
        self,
        attempt_id: str,
        work_id: str,
        expected_base: str,
        lease_paths: Sequence[str],
    ) -> Attempt:
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        work_id = _bounded_id(work_id, "work ID")
        if not isinstance(expected_base, str) or not OID.fullmatch(expected_base):
            raise ValidationError("expected base must be a full lowercase Git object ID")
        if isinstance(lease_paths, (str, bytes)) or not lease_paths:
            raise ValidationError("an attempt requires at least one path lease")
        canonical = tuple(
            sorted({canonical_repo_path(self.repository, path) for path in lease_paths})
        )
        if len(canonical) != len(lease_paths):
            raise ValidationError("lease paths must be unique after canonicalization")
        for index, path in enumerate(canonical):
            if any(_paths_overlap(path, other) for other in canonical[index + 1 :]):
                raise ValidationError("one attempt cannot request overlapping path leases")

        now = _utc_now()
        try:
            with self._transaction() as connection:
                active = connection.execute(
                    "SELECT attempt_id,path FROM leases WHERE released_at IS NULL"
                ).fetchall()
                for path in canonical:
                    for row in active:
                        if _paths_overlap(path, row["path"]):
                            raise ConflictError(
                                f"path lease conflicts with active attempt {row['attempt_id']}"
                            )
                connection.execute(
                    """
                    INSERT INTO attempts(
                        attempt_id,work_id,expected_base,state,revision,last_sequence,
                        created_at,updated_at
                    ) VALUES(?,?,?,'queued',0,0,?,?)
                    """,
                    (attempt_id, work_id, expected_base, now, now),
                )
                connection.executemany(
                    "INSERT INTO leases(attempt_id,path,acquired_at) VALUES(?,?,?)",
                    ((attempt_id, path, now) for path in canonical),
                )
                self._append_locked(
                    connection,
                    attempt_id,
                    RecordKind.EVENT,
                    "state.0",
                    "attempt.queued",
                    {"state": "queued"},
                    now,
                    None,
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("attempt or journal identifier already exists") from exc
        return self.get_attempt(attempt_id)

    def get_attempt(self, attempt_id: str) -> Attempt:
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        row = self._connection.execute(
            "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"attempt {attempt_id} does not exist")
        return self._attempt(row)

    def transition_attempt(
        self,
        attempt_id: str,
        expected_revision: int,
        new_state: AttemptState,
        *,
        reason: str,
    ) -> Attempt:
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValidationError("expected revision must be a non-negative integer")
        try:
            new_state = AttemptState(new_state)
        except (TypeError, ValueError) as exc:
            raise ValidationError("attempt state is unknown") from exc
        reason = _bounded_id(reason, "transition reason")
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"attempt {attempt_id} does not exist")
            old_state = AttemptState(row["state"])
            if row["revision"] != expected_revision:
                raise ConflictError("attempt revision differs from expected revision")
            if new_state not in _TRANSITIONS[old_state]:
                raise TransitionError(
                    f"attempt cannot transition from {old_state.value} to {new_state.value}"
                )
            cursor = connection.execute(
                """
                UPDATE attempts SET state=?,revision=revision+1,updated_at=?
                WHERE attempt_id=? AND revision=?
                """,
                (new_state.value, now, attempt_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise ConflictError("attempt revision changed during transition")
            self._append_locked(
                connection,
                attempt_id,
                RecordKind.EVENT,
                f"state.{expected_revision + 1}",
                "attempt.state_changed",
                {
                    "from": old_state.value,
                    "to": new_state.value,
                    "reason": reason,
                },
                now,
                None,
            )
            if new_state.value in TERMINAL_STATES:
                connection.execute(
                    """
                    UPDATE leases SET released_at=?
                    WHERE attempt_id=? AND released_at IS NULL
                    """,
                    (now, attempt_id),
                )
        return self.get_attempt(attempt_id)

    def append_event(
        self, attempt_id: str, event_id: str, name: str, payload: dict[str, Any]
    ) -> JournalRecord:
        return self._append(attempt_id, RecordKind.EVENT, event_id, name, payload)

    def append_checkpoint(
        self,
        attempt_id: str,
        checkpoint_id: str,
        name: str,
        payload: dict[str, Any],
    ) -> JournalRecord:
        return self._append(
            attempt_id, RecordKind.CHECKPOINT, checkpoint_id, name, payload
        )

    def append_evidence(
        self,
        attempt_id: str,
        evidence_id: str,
        name: str,
        authority: EvidenceAuthority,
        payload: dict[str, Any],
    ) -> JournalRecord:
        try:
            authority = EvidenceAuthority(authority)
        except ValueError as exc:
            raise ValidationError("evidence authority is unknown") from exc
        return self._append(
            attempt_id,
            RecordKind.EVIDENCE,
            evidence_id,
            name,
            payload,
            authority=authority,
        )

    def _append(
        self,
        attempt_id: str,
        kind: RecordKind,
        record_id: str,
        name: str,
        payload: dict[str, Any],
        *,
        authority: EvidenceAuthority | None = None,
    ) -> JournalRecord:
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        record_id = _bounded_id(record_id, "record ID")
        name = _bounded_id(name, "record name")
        now = _utc_now()
        try:
            with self._transaction() as connection:
                sequence = self._append_locked(
                    connection,
                    attempt_id,
                    kind,
                    record_id,
                    name,
                    payload,
                    now,
                    authority,
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("record identifier already exists") from exc
        return self.get_journal(attempt_id, after_sequence=sequence - 1)[0]

    def _append_locked(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        kind: RecordKind,
        record_id: str,
        name: str,
        payload: dict[str, Any],
        now: str,
        authority: EvidenceAuthority | None,
    ) -> int:
        record_id = _bounded_id(record_id, "record ID")
        name = _bounded_id(name, "record name")
        payload_json, _ = _payload_document(payload, "record payload")
        row = connection.execute(
            "SELECT last_sequence FROM attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"attempt {attempt_id} does not exist")
        sequence = row["last_sequence"] + 1
        connection.execute(
            """
            INSERT INTO journal(
                attempt_id,sequence,kind,record_id,name,authority,payload_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                attempt_id,
                sequence,
                kind.value,
                record_id,
                name,
                authority.value if authority is not None else None,
                payload_json,
                now,
            ),
        )
        connection.execute(
            "UPDATE attempts SET last_sequence=?,updated_at=? WHERE attempt_id=?",
            (sequence, now, attempt_id),
        )
        return sequence

    def get_journal(
        self, attempt_id: str, *, after_sequence: int = 0, limit: int = 1000
    ) -> tuple[JournalRecord, ...]:
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValidationError("after sequence must be a non-negative integer")
        if type(limit) is not int or limit < 1 or limit > 1000:
            raise ValidationError("journal limit must be between 1 and 1000")
        if self._connection.execute(
            "SELECT 1 FROM attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone() is None:
            raise NotFoundError(f"attempt {attempt_id} does not exist")
        rows = self._connection.execute(
            """
            SELECT * FROM journal
            WHERE attempt_id=? AND sequence>?
            ORDER BY sequence LIMIT ?
            """,
            (attempt_id, after_sequence, limit),
        ).fetchall()
        return tuple(self._journal(row) for row in rows)

    def active_leases(self) -> tuple[tuple[str, str], ...]:
        rows = self._connection.execute(
            """
            SELECT attempt_id,path FROM leases
            WHERE released_at IS NULL ORDER BY path,attempt_id
            """
        ).fetchall()
        return tuple((row["attempt_id"], row["path"]) for row in rows)

    def prepare_effect(
        self, effect_id: str, attempt_id: str, kind: str, request_sha256: str
    ) -> Effect:
        effect_id = _bounded_id(effect_id, "effect ID")
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        kind = _bounded_id(kind, "effect kind")
        request_sha256 = _digest(request_sha256, "request digest")
        now = _utc_now()
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["attempt_id"] != attempt_id
                    or existing["kind"] != kind
                    or existing["request_sha256"] != request_sha256
                ):
                    raise ConflictError("effect ID belongs to a different request")
                return self._effect(existing)
            if connection.execute(
                "SELECT 1 FROM attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone() is None:
                raise NotFoundError(f"attempt {attempt_id} does not exist")
            connection.execute(
                """
                INSERT INTO effects(
                    effect_id,attempt_id,kind,request_sha256,status,created_at,updated_at
                ) VALUES(?,?,?,?,'prepared',?,?)
                """,
                (effect_id, attempt_id, kind, request_sha256, now, now),
            )
        return self.get_effect(effect_id)

    def complete_effect(
        self,
        effect_id: str,
        request_sha256: str,
        result: dict[str, Any],
    ) -> Effect:
        effect_id = _bounded_id(effect_id, "effect ID")
        request_sha256 = _digest(request_sha256, "request digest")
        result_json, result_sha256 = _payload_document(result, "effect result")
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"effect {effect_id} does not exist")
            if row["request_sha256"] != request_sha256:
                raise ConflictError("effect request digest differs")
            if row["status"] == EffectStatus.COMPLETED.value:
                if row["result_sha256"] != result_sha256:
                    raise ConflictError("completed effect has a different result")
                return self._effect(row)
            connection.execute(
                """
                UPDATE effects SET status='completed',result_sha256=?,result_json=?,updated_at=?
                WHERE effect_id=? AND status='prepared'
                """,
                (result_sha256, result_json, now, effect_id),
            )
        return self.get_effect(effect_id)

    def apply_transition_effect(
        self,
        effect_id: str,
        attempt_id: str,
        kind: str,
        request_sha256: str,
        expected_revision: int,
        new_state: AttemptState,
        *,
        reason: str,
        result: dict[str, Any],
    ) -> tuple[Attempt, Effect, bool]:
        """Atomically apply or replay one revisioned state-changing effect."""

        effect_id = _bounded_id(effect_id, "effect ID")
        attempt_id = _bounded_id(attempt_id, "attempt ID")
        kind = _bounded_id(kind, "effect kind")
        request_sha256 = _digest(request_sha256, "request digest")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValidationError("expected revision must be a non-negative integer")
        try:
            new_state = AttemptState(new_state)
        except (TypeError, ValueError) as exc:
            raise ValidationError("attempt state is unknown") from exc
        reason = _bounded_id(reason, "transition reason")
        result_json, result_sha256 = _payload_document(result, "effect result")
        now = _utc_now()
        applied = False
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["attempt_id"] != attempt_id
                    or existing["kind"] != kind
                    or existing["request_sha256"] != request_sha256
                ):
                    raise ConflictError("effect ID belongs to a different request")
                if existing["status"] != EffectStatus.COMPLETED.value:
                    raise ConflictError("effect is prepared but not atomically completed")
                if existing["result_sha256"] != result_sha256:
                    raise ConflictError("completed effect has a different result")
            else:
                row = connection.execute(
                    "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"attempt {attempt_id} does not exist")
                old_state = AttemptState(row["state"])
                if row["revision"] != expected_revision:
                    raise ConflictError("attempt revision differs from expected revision")
                if new_state not in _TRANSITIONS[old_state]:
                    raise TransitionError(
                        f"attempt cannot transition from {old_state.value} to {new_state.value}"
                    )
                connection.execute(
                    """
                    INSERT INTO effects(
                        effect_id,attempt_id,kind,request_sha256,status,
                        result_sha256,result_json,created_at,updated_at
                    ) VALUES(?,?,?,?,'completed',?,?,?,?)
                    """,
                    (
                        effect_id,
                        attempt_id,
                        kind,
                        request_sha256,
                        result_sha256,
                        result_json,
                        now,
                        now,
                    ),
                )
                cursor = connection.execute(
                    """
                    UPDATE attempts SET state=?,revision=revision+1,updated_at=?
                    WHERE attempt_id=? AND revision=?
                    """,
                    (new_state.value, now, attempt_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("attempt revision changed during transition")
                self._append_locked(
                    connection,
                    attempt_id,
                    RecordKind.EVENT,
                    f"state.{expected_revision + 1}",
                    "attempt.state_changed",
                    {
                        "from": old_state.value,
                        "to": new_state.value,
                        "reason": reason,
                    },
                    now,
                    None,
                )
                if new_state.value in TERMINAL_STATES:
                    connection.execute(
                        """
                        UPDATE leases SET released_at=?
                        WHERE attempt_id=? AND released_at IS NULL
                        """,
                        (now, attempt_id),
                    )
                applied = True
        return self.get_attempt(attempt_id), self.get_effect(effect_id), applied

    def get_effect(self, effect_id: str) -> Effect:
        effect_id = _bounded_id(effect_id, "effect ID")
        row = self._connection.execute(
            "SELECT * FROM effects WHERE effect_id=?", (effect_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"effect {effect_id} does not exist")
        return self._effect(row)

    @staticmethod
    def _attempt(row: sqlite3.Row) -> Attempt:
        return Attempt(
            attempt_id=row["attempt_id"],
            work_id=row["work_id"],
            expected_base=row["expected_base"],
            state=AttemptState(row["state"]),
            revision=row["revision"],
            last_sequence=row["last_sequence"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _journal(row: sqlite3.Row) -> JournalRecord:
        return JournalRecord(
            attempt_id=row["attempt_id"],
            sequence=row["sequence"],
            kind=RecordKind(row["kind"]),
            record_id=row["record_id"],
            name=row["name"],
            authority=(
                EvidenceAuthority(row["authority"])
                if row["authority"] is not None
                else None
            ),
            payload=json.loads(row["payload_json"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _effect(row: sqlite3.Row) -> Effect:
        result = json.loads(row["result_json"]) if row["result_json"] else None
        return Effect(
            effect_id=row["effect_id"],
            attempt_id=row["attempt_id"],
            kind=row["kind"],
            request_sha256=row["request_sha256"],
            status=EffectStatus(row["status"]),
            result_sha256=row["result_sha256"],
            result=result,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
