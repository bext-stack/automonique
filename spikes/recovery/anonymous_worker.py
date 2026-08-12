#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Pure verifier for the fixed anonymous R0-10 recovery package.

This module is intentionally non-launchable.  It accepts package bytes, checks
their complete closed structure and semantics, and returns a non-authorizing
record.  It opens no path, descriptor, socket or process and grants no recovery
or execution authority.  A later reviewed base may pin this file's digest for
use by a separately reviewed boundary launcher.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import re
import sqlite3
from typing import Any

PACKAGE_SCHEMA = "automonique.synthetic-recovery-package/anonymous-online-v1"
PACKAGE_APPLICATION_ID = 0x41524B31
PACKAGE_USER_VERSION = 1
PACKAGE_LIMIT = 16 * 1024 * 1024
EXPECTED_PACKAGE_SIZE = 45_056
EXPECTED_PACKAGE_SHA256 = (
    "d5edac7cbf5474314d5ed7d1a3f40d7225d343eda21a134ba283b0d62b91bbd8"
)
ENTRY_LIMIT = 2 * 1024 * 1024
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

PACKAGE_SCHEMA_OBJECTS = (
    (
        "entries",
        "table",
        "CREATE TABLE entries (\n"
        "    entry_id TEXT PRIMARY KEY,\n"
        "    path_name TEXT NOT NULL UNIQUE,\n"
        "    artifact_class TEXT NOT NULL,\n"
        "    payload BLOB NOT NULL,\n"
        "    size INTEGER NOT NULL CHECK (size >= 0),\n"
        "    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),\n"
        "    CHECK (size = length(payload))\n"
        ") STRICT",
    ),
    (
        "package_manifest",
        "table",
        "CREATE TABLE package_manifest (\n"
        "    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\n"
        "    schema TEXT NOT NULL,\n"
        "    root_sha256 TEXT NOT NULL CHECK (length(root_sha256) = 64),\n"
        "    entry_count INTEGER NOT NULL CHECK (entry_count > 0)\n"
        ") STRICT",
    ),
)

CONTROL_SCHEMA_OBJECTS = (
    (
        "artifacts",
        "table",
        "CREATE TABLE artifacts (artifact_index INTEGER PRIMARY KEY, "
        "artifact_id TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, "
        "size_bytes INTEGER NOT NULL) STRICT",
    ),
    (
        "events",
        "table",
        "CREATE TABLE events (event_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
        "artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id), "
        "written_ns INTEGER NOT NULL) STRICT",
    ),
)

ENTRY_COORDINATES = {
    "artifact-blob": (
        "artifacts/blobs/sha256/fixture", "artifact-blob"),
    "artifact-metadata": (
        "artifacts/metadata.json", "artifact-metadata"),
    "audit-journal": (
        "journal/events.jsonl", "audit-journal"),
    "configuration-workspaces": (
        "configuration/workspaces.json", "configuration-workspace"),
    "context-memory-automation": (
        "context/state.json", "context-memory-automation"),
    "control-database": (
        "database/control.sqlite3", "control-database"),
    "corresponding-source-locks": (
        "source/locks.json", "corresponding-source-lock"),
    "disconnected-start-bundle": (
        "startup/disconnected.json", "disconnected-start-bundle"),
    "last-known-good-seed-verifier": (
        "bootstrap/seed-verifier.json", "bootstrap-seed-verifier"),
    "policy-bundle-hashes": (
        "policy/bundles.json", "policy-bundle"),
    "release-manifests-schemas": (
        "release/manifests.json", "release-schema"),
    "snapshot-metadata": (
        "database/snapshot.json", "snapshot-metadata"),
    "synthetic-credential-descriptor": (
        "credentials/descriptors.json", "credential-descriptor"),
    "tool-extension-manifests": (
        "tools/extensions.json", "tool-extension"),
}
ENTRY_IDS = tuple(sorted(ENTRY_COORDINATES))

CHECK_NAMES = (
    "package_bytes_bounded",
    "package_database_integrity",
    "package_schema_exact",
    "manifest_exact",
    "entry_coordinates_exact",
    "entry_digests_exact",
    "root_digest_exact",
    "control_database_integrity",
    "control_database_schema_exact",
    "event_journal_exact",
    "artifact_blob_relationships_exact",
    "snapshot_exact",
    "configuration_policy_release_exact",
    "disconnected_definition_exact",
    "credential_metadata_only_exact",
    "context_source_seed_tool_exact",
)

class RefusalCode(enum.Enum):
    TYPE_INVALID = "type_invalid"
    PACKAGE_SIZE_INVALID = "package_size_invalid"
    PACKAGE_DIGEST_INVALID = "package_digest_invalid"
    PACKAGE_DATABASE_INVALID = "package_database_invalid"
    PACKAGE_SCHEMA_INVALID = "package_schema_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    ENTRY_INVALID = "entry_invalid"
    DIGEST_INVALID = "digest_invalid"
    ROOT_DIGEST_INVALID = "root_digest_invalid"
    CONTROL_DATABASE_INVALID = "control_database_invalid"
    SEMANTIC_INVALID = "semantic_invalid"


class WorkerRefused(ValueError):
    def __init__(self, code: RefusalCode, detail: str) -> None:
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class RecoveryPoint:
    fixed_backup_cadence_seconds: int
    snapshot_watermark_unix_ns: int
    newest_durable_at_loss_unix_ns: int
    derived_rpo_seconds: float
    scope: str
    objective_eligible: bool

    def as_document(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ExternalAuthority:
    credentials: bool = False
    network: bool = False
    providers: bool = False
    tools: bool = False
    transports: bool = False

    def as_document(self) -> dict[str, bool]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class WorkerVerification:
    schema: str
    package_sha256: str
    root_sha256: str
    package_size: int
    entry_count: int
    recovery_point: RecoveryPoint
    event_count: int
    artifact_count: int
    checks: tuple[str, ...]
    external_authority: ExternalAuthority
    scope: str = "pure-anonymous-package-verifier"
    launchable: bool = False
    authorizing: bool = False
    position_receipts_emitted: tuple[str, ...] = ()

    def as_document(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "package_sha256": self.package_sha256,
            "root_sha256": self.root_sha256,
            "package_size": self.package_size,
            "entry_count": self.entry_count,
            "recovery_point": self.recovery_point.as_document(),
            "event_count": self.event_count,
            "artifact_count": self.artifact_count,
            "checks": list(self.checks),
            "external_authority": self.external_authority.as_document(),
            "scope": self.scope,
            "launchable": self.launchable,
            "authorizing": self.authorizing,
            "position_receipts_emitted": list(self.position_receipts_emitted),
        }


@dataclasses.dataclass(frozen=True)
class _Entry:
    entry_id: str
    path_name: str
    artifact_class: str
    payload: bytes
    size: int
    sha256: str


def _canonical_json(value: object) -> bytes:
    return (json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ) + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_object(payload: bytes, subject: str) -> dict[str, Any]:
    try:
        document = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            f"{subject} is not unique-key JSON: {exc}",
        ) from exc
    if type(document) is not dict:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID, f"{subject} is not an object")
    try:
        canonical = _canonical_json(document)
    except (UnicodeEncodeError, ValueError) as exc:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            f"{subject} is outside canonical JSON: {exc}",
        ) from exc
    if payload != canonical:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID, f"{subject} is not canonical JSON")
    return document


def _database_from_bytes(payload: bytes, subject: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(payload)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection
    except (sqlite3.Error, MemoryError) as exc:
        connection.close()
        raise WorkerRefused(
            RefusalCode.PACKAGE_DATABASE_INVALID,
            f"{subject} cannot be deserialized: {type(exc).__name__}",
        ) from exc


def _schema(connection: sqlite3.Connection) -> tuple[tuple[Any, ...], ...]:
    return tuple(connection.execute(
        "SELECT name,type,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"))


def _root_digest(entries: tuple[_Entry, ...]) -> str:
    digest = hashlib.sha256(
        b"automonique.synthetic-recovery-package/root/v1\0")
    for entry in entries:
        for value in (
            entry.entry_id,
            entry.path_name,
            entry.artifact_class,
            str(entry.size),
            entry.sha256,
        ):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def _read_entries(connection: sqlite3.Connection) -> tuple[_Entry, ...]:
    try:
        rows = connection.execute(
            "SELECT entry_id,path_name,artifact_class,payload,size,sha256 "
            "FROM entries ORDER BY entry_id").fetchall()
    except sqlite3.Error as exc:
        raise WorkerRefused(
            RefusalCode.ENTRY_INVALID, "entry rows cannot be read") from exc
    if len(rows) != len(ENTRY_IDS):
        raise WorkerRefused(
            RefusalCode.ENTRY_INVALID,
            f"entry count differs: {len(rows)}",
        )
    entries: list[_Entry] = []
    for row in rows:
        entry_id, path_name, artifact_class, payload, size, digest = row
        if (
            type(entry_id) is not str
            or type(path_name) is not str
            or type(artifact_class) is not str
            or type(payload) is not bytes
            or not payload
            or len(payload) > ENTRY_LIMIT
            or type(size) is not int
            or type(digest) is not str
            or SHA256.fullmatch(digest) is None
        ):
            raise WorkerRefused(
                RefusalCode.ENTRY_INVALID,
                "an entry has malformed types or bounds",
            )
        if ENTRY_COORDINATES.get(entry_id) != (path_name, artifact_class):
            raise WorkerRefused(
                RefusalCode.ENTRY_INVALID,
                f"entry {entry_id!r} changes canonical coordinates",
            )
        if size != len(payload) or hashlib.sha256(payload).hexdigest() != digest:
            raise WorkerRefused(
                RefusalCode.DIGEST_INVALID,
                f"entry {entry_id!r} size or digest differs",
            )
        entries.append(_Entry(
            entry_id, path_name, artifact_class, payload, size, digest))
    result = tuple(entries)
    if tuple(entry.entry_id for entry in result) != ENTRY_IDS:
        raise WorkerRefused(
            RefusalCode.ENTRY_INVALID, "entry ID set or ordering differs")
    return result


def _control_state(payload: bytes) -> tuple[
    list[tuple[int, str, str, int]],
    list[tuple[int, str, str, int]],
]:
    connection = _database_from_bytes(payload, "control database")
    try:
        try:
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise WorkerRefused(
                    RefusalCode.CONTROL_DATABASE_INVALID,
                    "control database integrity check differs",
                )
            if _schema(connection) != CONTROL_SCHEMA_OBJECTS:
                raise WorkerRefused(
                    RefusalCode.CONTROL_DATABASE_INVALID,
                    "control database SQL schema differs",
                )
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_keys:
                raise WorkerRefused(
                    RefusalCode.CONTROL_DATABASE_INVALID,
                    "control database foreign-key check differs",
                )
            events = list(connection.execute(
                "SELECT event_id,kind,artifact_id,written_ns "
                "FROM events ORDER BY event_id"))
            artifacts = list(connection.execute(
                "SELECT artifact_index,artifact_id,sha256,size_bytes "
                "FROM artifacts ORDER BY artifact_index"))
        except sqlite3.Error as exc:
            raise WorkerRefused(
                RefusalCode.CONTROL_DATABASE_INVALID,
                f"control database query refused: {type(exc).__name__}",
            ) from exc
    finally:
        connection.close()
    return events, artifacts


def _verify_semantics(
    entries: tuple[_Entry, ...],
) -> tuple[RecoveryPoint, int, int]:
    by_id = {entry.entry_id: entry for entry in entries}
    metadata = _json_object(
        by_id["artifact-metadata"].payload, "artifact metadata")
    blobs = _json_object(by_id["artifact-blob"].payload, "artifact blobs")
    snapshot = _json_object(
        by_id["snapshot-metadata"].payload, "snapshot metadata")
    configuration = _json_object(
        by_id["configuration-workspaces"].payload, "configuration")
    context = _json_object(
        by_id["context-memory-automation"].payload, "context state")
    source = _json_object(
        by_id["corresponding-source-locks"].payload, "source locks")
    startup = _json_object(
        by_id["disconnected-start-bundle"].payload, "disconnected definition")
    seed = _json_object(
        by_id["last-known-good-seed-verifier"].payload, "seed verifier")
    policy = _json_object(
        by_id["policy-bundle-hashes"].payload, "policy bundle")
    credentials = _json_object(
        by_id["synthetic-credential-descriptor"].payload,
        "credential descriptor",
    )
    release = _json_object(
        by_id["release-manifests-schemas"].payload, "release manifest")
    tools = _json_object(
        by_id["tool-extension-manifests"].payload, "tool manifest")
    events, artifacts = _control_state(by_id["control-database"].payload)

    expected_events = [
        (index, "artifact_recorded", f"artifact-{index:06d}",
         index * 1_000_000_000)
        for index in range(1, 5)
    ]
    if events != expected_events:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "control events are not the exact deterministic sequence",
        )
    expected_journal = b"".join(_canonical_json({
        "artifact_id": row[2],
        "event_id": row[0],
        "kind": row[1],
        "written_ns": row[3],
    }) for row in expected_events)
    if by_id["audit-journal"].payload != expected_journal:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "audit journal differs from the exact control events",
        )

    if (
        set(blobs) != {"schema", "blobs"}
        or blobs.get("schema") != "automonique.anonymous-blobs/v1"
    ):
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "anonymous blob envelope or schema differs")
    raw_blobs = blobs.get("blobs")
    if type(raw_blobs) is not list or len(raw_blobs) != 4:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID, "anonymous blob set differs")
    observed_blobs: dict[str, bytes] = {}
    for item in raw_blobs:
        if type(item) is not dict or set(item) != {"payload_hex", "sha256", "size"}:
            raise WorkerRefused(
                RefusalCode.SEMANTIC_INVALID, "blob member shape differs")
        if (
            type(item["payload_hex"]) is not str
            or type(item["sha256"]) is not str
            or type(item["size"]) is not int
        ):
            raise WorkerRefused(
                RefusalCode.SEMANTIC_INVALID, "blob member types differ")
        try:
            payload = bytes.fromhex(item["payload_hex"])
        except ValueError as exc:
            raise WorkerRefused(
                RefusalCode.SEMANTIC_INVALID, "blob hex encoding differs") from exc
        digest = hashlib.sha256(payload).hexdigest()
        if (
            payload.hex() != item["payload_hex"]
            or len(payload) != item["size"]
            or digest != item["sha256"]
            or digest in observed_blobs
        ):
            raise WorkerRefused(
                RefusalCode.SEMANTIC_INVALID,
                "blob encoding, size, digest or uniqueness differs",
            )
        observed_blobs[digest] = payload

    expected_artifacts: list[dict[str, Any]] = []
    expected_members = {
        "control.db": by_id["control-database"].sha256,
        "config.json": by_id["configuration-workspaces"].sha256,
    }
    expected_rows: list[tuple[int, str, str, int]] = []
    for index in range(1, 5):
        payload = (hashlib.sha256(f"20260811:{index}".encode()).digest() * 5)[:128]
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = f"artifact-{index:06d}"
        expected_rows.append((index, artifact_id, digest, 128))
        expected_artifacts.append({
            "id": artifact_id, "sha256": digest, "size": 128})
        expected_members[f"blobs/{digest[:2]}/{digest}"] = digest
        if observed_blobs.get(digest) != payload:
            raise WorkerRefused(
                RefusalCode.SEMANTIC_INVALID,
                f"deterministic blob {index} differs",
            )
    if artifacts != expected_rows:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "artifact database rows differ from deterministic bytes",
        )
    expected_metadata = {
        "artifacts": expected_artifacts,
        "manifest": {
            "members": expected_members,
            "schema": "automonique.anonymous-backup-manifest/v1",
            "watermark_event_id": 4,
            "watermark_ns": 4_000_000_000,
        },
        "profile": "anonymous-online-v1",
        "tombstones": [],
    }
    if metadata != expected_metadata:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "artifact metadata or exact manifest differs",
        )

    expected_snapshot = {
        "derived_rpo_seconds": 1.0,
        "fixed_backup_cadence_seconds": 60,
        "method": "anonymous-online-backup",
        "newest_durable_at_loss_unix_ns": 5_000_000_000,
        "objective_eligible": False,
        "scope": "anonymous-synthetic",
        "snapshot_watermark_unix_ns": 4_000_000_000,
        "watermark_event_id": 4,
    }
    if snapshot != expected_snapshot:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID, "snapshot coordinates differ")
    expected_configuration = {
        "configuration_revision": 1,
        "history": [1],
        "schema": "automonique.anonymous-config/v1",
        "secret_values": None,
    }
    expected_policy = {
        "configuration_revision": 1,
        "policy_revision": 1,
        "sha256": "5" * 64,
    }
    expected_release = {
        "configuration_revision": 1,
        "policy_revision": 1,
        "release": "anonymous-v1",
        "schema_versions": [1],
    }
    if (
        configuration != expected_configuration
        or policy != expected_policy
        or release != expected_release
    ):
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "configuration, policy or release coordinates differ",
        )
    if startup != {
        "mode": "disconnected",
        "network_authority": False,
        "provider_authority": False,
    }:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "disconnected startup definition differs",
        )
    if credentials != {
        "descriptors": [{
            "audience": "recovery-fixture.invalid",
            "id": "fixture-bot",
            "provider": "synthetic",
            "version": "v1",
        }],
        "schema": "automonique.synthetic-credential-descriptors/v1",
    }:
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "credential entry is not exact metadata-only synthetic input",
        )
    if (
        context != {"automations": [], "context": [], "memory": []}
        or source != {
            "dependency_lock_sha256": "1" * 64,
            "source_sha256": "2" * 64,
        }
        or seed != {
            "seed_sha256": "3" * 64,
            "verifier_sha256": "4" * 64,
        }
        or tools != {"extensions": [], "hooks": [], "tools": []}
    ):
        raise WorkerRefused(
            RefusalCode.SEMANTIC_INVALID,
            "context, source locks, seed verifier or tool manifest differs",
        )
    return (
        RecoveryPoint(
            60, 4_000_000_000, 5_000_000_000,
            1.0, "anonymous-synthetic", False,
        ),
        len(events),
        len(artifacts),
    )


def verify_package_bytes(package: bytes) -> WorkerVerification:
    """Independently verify one canonical anonymous package byte image.

    Success is a statement about these synthetic bytes only.  It is not launch,
    restore, credential, provider, transport, position-receipt or completion
    authority.
    """
    if type(package) is not bytes:
        raise WorkerRefused(
            RefusalCode.TYPE_INVALID, "package must be exact bytes")
    if not package or len(package) > PACKAGE_LIMIT:
        raise WorkerRefused(
            RefusalCode.PACKAGE_SIZE_INVALID,
            "package size is outside the fixed 1..16 MiB bound",
        )
    package_sha256 = hashlib.sha256(package).hexdigest()
    if len(package) != EXPECTED_PACKAGE_SIZE:
        raise WorkerRefused(
            RefusalCode.PACKAGE_SIZE_INVALID,
            "package size differs from the fixed anonymous profile",
        )
    if package_sha256 != EXPECTED_PACKAGE_SHA256:
        raise WorkerRefused(
            RefusalCode.PACKAGE_DIGEST_INVALID,
            "package digest differs from the fixed anonymous profile",
        )
    connection = _database_from_bytes(package, "package database")
    try:
        try:
            application_id = connection.execute(
                "PRAGMA application_id").fetchone()[0]
            user_version = connection.execute(
                "PRAGMA user_version").fetchone()[0]
            integrity = connection.execute("PRAGMA integrity_check").fetchall()
            schema = _schema(connection)
        except sqlite3.Error as exc:
            raise WorkerRefused(
                RefusalCode.PACKAGE_DATABASE_INVALID,
                f"package database query refused: {type(exc).__name__}",
            ) from exc
        if integrity != [("ok",)]:
            raise WorkerRefused(
                RefusalCode.PACKAGE_DATABASE_INVALID,
                "package database integrity check differs",
            )
        if (
            application_id != PACKAGE_APPLICATION_ID
            or user_version != PACKAGE_USER_VERSION
            or schema != PACKAGE_SCHEMA_OBJECTS
        ):
            raise WorkerRefused(
                RefusalCode.PACKAGE_SCHEMA_INVALID,
                "package application ID, version or exact SQL schema differs",
            )
        try:
            manifest = connection.execute(
                "SELECT schema,root_sha256,entry_count "
                "FROM package_manifest WHERE singleton=1").fetchall()
        except sqlite3.Error as exc:
            raise WorkerRefused(
                RefusalCode.MANIFEST_INVALID,
                "package manifest cannot be read",
            ) from exc
        entries = _read_entries(connection)
    finally:
        connection.close()
    if (
        len(manifest) != 1
        or manifest[0][0] != PACKAGE_SCHEMA
        or type(manifest[0][1]) is not str
        or SHA256.fullmatch(manifest[0][1]) is None
        or type(manifest[0][2]) is not int
        or manifest[0][2] != len(entries)
    ):
        raise WorkerRefused(
            RefusalCode.MANIFEST_INVALID,
            "package manifest schema, root or entry count differs",
        )
    root_sha256 = _root_digest(entries)
    if root_sha256 != manifest[0][1]:
        raise WorkerRefused(
            RefusalCode.ROOT_DIGEST_INVALID,
            "computed package root differs from its manifest",
        )
    recovery_point, event_count, artifact_count = _verify_semantics(entries)
    return WorkerVerification(
        schema="automonique.anonymous-worker-verification/v1",
        package_sha256=package_sha256,
        root_sha256=root_sha256,
        package_size=len(package),
        entry_count=len(entries),
        recovery_point=recovery_point,
        event_count=event_count,
        artifact_count=artifact_count,
        checks=CHECK_NAMES,
        external_authority=ExternalAuthority(),
    )
