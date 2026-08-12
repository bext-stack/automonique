#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Content-addressed synthetic recovery package authority.

The package is a single deterministic SQLite image.  Creation writes and
fsyncs an exclusive, no-follow staging inode, atomically publishes it without
overwrite, and fsyncs the parent directory; verification reads and deserializes one
bounded snapshot from an already-open descriptor, so no pathname is trusted
after admission.  The fixture contains metadata only and grants no recovery,
credential, transport, provider, deployment, or production authority.
"""

from __future__ import annotations

import dataclasses
import enum
import fcntl
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat


SCHEMA = "automonique.synthetic-recovery-package/v1"
ANONYMOUS_SCHEMA = "automonique.synthetic-recovery-package/anonymous-online-v1"
SCHEMA_VERSION = 1
APPLICATION_ID = 0x41524B31
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
MAX_ENTRY_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 64
MAX_ID_BYTES = 128
MAX_PATH_BYTES = 256
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
ENTRY_ID = re.compile(r"\A[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?\Z")


class ArtifactClass(enum.Enum):
    ARTIFACT_METADATA = "artifact-metadata"
    ARTIFACT_BLOB = "artifact-blob"
    AUDIT_JOURNAL = "audit-journal"
    SNAPSHOT_METADATA = "snapshot-metadata"
    CONTROL_DATABASE = "control-database"
    CONFIGURATION = "configuration-workspace"
    CONTEXT_STATE = "context-memory-automation"
    SOURCE_LOCK = "corresponding-source-lock"
    DISCONNECTED_BUNDLE = "disconnected-start-bundle"
    BOOTSTRAP_VERIFIER = "bootstrap-seed-verifier"
    POLICY_BUNDLE = "policy-bundle"
    CREDENTIAL_DESCRIPTOR = "credential-descriptor"
    RELEASE_SCHEMA = "release-schema"
    TOOL_EXTENSION = "tool-extension"


class ArtifactRefusal(enum.Enum):
    INVALID_PATH = "invalid-path"
    SYMLINK_OR_TYPE = "symlink-or-type"
    ALREADY_EXISTS = "already-exists"
    INVALID_ENTRY = "invalid-entry"
    DUPLICATE_ENTRY = "duplicate-entry"
    MISSING_ENTRY = "missing-entry"
    EXTRA_ENTRY = "extra-entry"
    OVERSIZED = "oversized"
    INVALID_PACKAGE = "invalid-package"
    SCHEMA_MISMATCH = "schema-mismatch"
    DIGEST_MISMATCH = "digest-mismatch"
    MUTATED_DURING_READ = "mutated-during-read"
    INVALID_CREDENTIAL_DESCRIPTOR = "invalid-credential-descriptor"
    SEMANTIC_MISMATCH = "semantic-mismatch"


class ArtifactRefused(Exception):
    def __init__(self, refusal: ArtifactRefusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class ArtifactEntry:
    entry_id: str
    path_name: str
    artifact_class: ArtifactClass
    payload: bytes

    @property
    def size(self) -> int:
        return len(self.payload)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclasses.dataclass(frozen=True)
class PackageReceipt:
    schema: str
    root_sha256: str
    package_sha256: str
    package_size: int
    entry_count: int


@dataclasses.dataclass(frozen=True)
class SealedPackage:
    descriptor: int
    receipt: PackageReceipt


@dataclasses.dataclass(frozen=True)
class VerifiedPackage:
    receipt: PackageReceipt
    entries: tuple[ArtifactEntry, ...]
    recovery_point: SyntheticRecoveryPoint


@dataclasses.dataclass(frozen=True)
class SyntheticRecoveryPoint:
    fixed_backup_cadence_seconds: int
    snapshot_watermark_unix_ns: int
    newest_durable_at_loss_unix_ns: int
    derived_rpo_seconds: float
    scope: str
    objective_eligible: bool


@dataclasses.dataclass(frozen=True)
class RequiredEntry:
    entry_id: str
    path_name: str
    artifact_class: ArtifactClass


REQUIRED_ENTRIES = (
    RequiredEntry("artifact-metadata", "artifacts/metadata.json", ArtifactClass.ARTIFACT_METADATA),
    RequiredEntry("artifact-blob", "artifacts/blobs/sha256/fixture", ArtifactClass.ARTIFACT_BLOB),
    RequiredEntry("audit-journal", "journal/events.jsonl", ArtifactClass.AUDIT_JOURNAL),
    RequiredEntry("snapshot-metadata", "database/snapshot.json", ArtifactClass.SNAPSHOT_METADATA),
    RequiredEntry("control-database", "database/control.sqlite3", ArtifactClass.CONTROL_DATABASE),
    RequiredEntry("configuration-workspaces", "configuration/workspaces.json", ArtifactClass.CONFIGURATION),
    RequiredEntry("context-memory-automation", "context/state.json", ArtifactClass.CONTEXT_STATE),
    RequiredEntry("corresponding-source-locks", "source/locks.json", ArtifactClass.SOURCE_LOCK),
    RequiredEntry("disconnected-start-bundle", "startup/disconnected.json", ArtifactClass.DISCONNECTED_BUNDLE),
    RequiredEntry("last-known-good-seed-verifier", "bootstrap/seed-verifier.json", ArtifactClass.BOOTSTRAP_VERIFIER),
    RequiredEntry("policy-bundle-hashes", "policy/bundles.json", ArtifactClass.POLICY_BUNDLE),
    RequiredEntry("synthetic-credential-descriptor", "credentials/descriptors.json", ArtifactClass.CREDENTIAL_DESCRIPTOR),
    RequiredEntry("release-manifests-schemas", "release/manifests.json", ArtifactClass.RELEASE_SCHEMA),
    RequiredEntry("tool-extension-manifests", "tools/extensions.json", ArtifactClass.TOOL_EXTENSION),
)
REQUIRED_BY_ID = {entry.entry_id: entry for entry in REQUIRED_ENTRIES}


SCHEMA_SQL = """
CREATE TABLE package_manifest (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema TEXT NOT NULL,
    root_sha256 TEXT NOT NULL CHECK (length(root_sha256) = 64),
    entry_count INTEGER NOT NULL CHECK (entry_count > 0)
) STRICT;
CREATE TABLE entries (
    entry_id TEXT PRIMARY KEY,
    path_name TEXT NOT NULL UNIQUE,
    artifact_class TEXT NOT NULL,
    payload BLOB NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    CHECK (size = length(payload))
) STRICT;
"""
EXPECTED_SCHEMA = (
    ("entries", "table", "CREATE TABLE entries (\n    entry_id TEXT PRIMARY KEY,\n    path_name TEXT NOT NULL UNIQUE,\n    artifact_class TEXT NOT NULL,\n    payload BLOB NOT NULL,\n    size INTEGER NOT NULL CHECK (size >= 0),\n    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),\n    CHECK (size = length(payload))\n) STRICT"),
    ("package_manifest", "table", "CREATE TABLE package_manifest (\n    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\n    schema TEXT NOT NULL,\n    root_sha256 TEXT NOT NULL CHECK (length(root_sha256) = 64),\n    entry_count INTEGER NOT NULL CHECK (entry_count > 0)\n) STRICT"),
)


def canonical_fixture_entries() -> tuple[ArtifactEntry, ...]:
    """Return the complete synthetic, non-secret recovery input set."""
    blob = b"synthetic artifact bytes\n"
    blob_digest = hashlib.sha256(blob).hexdigest()
    payloads = {
        "artifact-metadata": _json({"artifacts": [{"id": "fixture", "sha256": blob_digest}], "tombstones": [{"id": "deleted-fixture", "revision": 1}]}),
        "artifact-blob": blob,
        "audit-journal": b'{"event_id":1,"kind":"fixture.created"}\n',
        "snapshot-metadata": _json({"derived_rpo_seconds": 60.0, "fixed_backup_cadence_seconds": 60, "method": "synthetic-package-fixture", "newest_durable_at_loss_unix_ns": 61_000_000_000, "objective_eligible": False, "scope": "synthetic-fixture", "snapshot_watermark_unix_ns": 1_000_000_000, "watermark_event_id": 1}),
        "control-database": _fixture_control_database(),
        "configuration-workspaces": _json({"configuration_revision": 1, "workspaces": [{"id": "fixture-workspace", "revision": 1}]}),
        "context-memory-automation": _json({"automations": [], "context": [], "memory": []}),
        "corresponding-source-locks": _json({"dependency_lock_sha256": "1" * 64, "source_sha256": "2" * 64}),
        "disconnected-start-bundle": _json({"mode": "disconnected", "network_authority": False, "provider_authority": False}),
        "last-known-good-seed-verifier": _json({"seed_sha256": "3" * 64, "verifier_sha256": "4" * 64}),
        "policy-bundle-hashes": _json({"configuration_revision": 1, "policy_revision": 1, "sha256": "5" * 64}),
        "synthetic-credential-descriptor": _json({"descriptors": [{"audience": "recovery-fixture.invalid", "id": "fixture-bot", "provider": "synthetic", "version": "v1"}], "schema": "automonique.synthetic-credential-descriptors/v1"}),
        "release-manifests-schemas": _json({"configuration_revision": 1, "policy_revision": 1, "release": "synthetic-v1", "required_credential_descriptors": [{"audience": "recovery-fixture.invalid", "id": "fixture-bot", "version": "v1"}], "schema_versions": [1]}),
        "tool-extension-manifests": _json({"extensions": [], "hooks": [], "tools": []}),
    }
    return tuple(
        ArtifactEntry(required.entry_id, required.path_name, required.artifact_class, payloads[required.entry_id])
        for required in REQUIRED_ENTRIES
    )


def create_package(path: pathlib.Path, entries: tuple[ArtifactEntry, ...]) -> PackageReceipt:
    """Atomically publish one new package without following path symlinks."""
    validated = _validate_entries(entries)
    _validate_semantics(validated)
    image, root_sha256 = _render_package(validated)
    if len(image) > MAX_PACKAGE_BYTES:
        raise ArtifactRefused(ArtifactRefusal.OVERSIZED, "rendered package exceeds byte limit")
    parent_fd, leaf = _open_parent(path)
    file_fd = -1
    staging_leaf = f".recovery-package-stage-{os.urandom(16).hex()}"
    staging_created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            file_fd = os.open(staging_leaf, flags, 0o600, dir_fd=parent_fd)
            staging_created = True
        except OSError as error:
            raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, f"package staging refused: {error.errno}") from None
        _write_all(file_fd, image)
        os.fsync(file_fd)
        try:
            os.link(
                staging_leaf,
                leaf,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise ArtifactRefused(ArtifactRefusal.ALREADY_EXISTS, "package path already exists") from None
        except OSError as error:
            raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, f"package publication refused: {error.errno}") from None
        os.unlink(staging_leaf, dir_fd=parent_fd)
        staging_created = False
        os.fsync(parent_fd)
    except Exception:
        if file_fd >= 0:
            os.close(file_fd)
            file_fd = -1
        if staging_created:
            try:
                os.unlink(staging_leaf, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)
    return PackageReceipt(SCHEMA, root_sha256, hashlib.sha256(image).hexdigest(), len(image), len(validated))


def _create_sealed_anonymous_package(entries: tuple[ArtifactEntry, ...]) -> SealedPackage:
    """Internal route for the closed anonymous producer; no caller payload API."""
    validated = _validate_entries(entries)
    _validate_anonymous_semantics(validated)
    image, root_sha256 = _render_package(validated, ANONYMOUS_SCHEMA)
    if len(image) > MAX_PACKAGE_BYTES:
        raise ArtifactRefused(ArtifactRefusal.OVERSIZED, "rendered package exceeds byte limit")
    descriptor = os.memfd_create("automonique-recovery-package", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        _write_all(descriptor, image)
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)
        receipt = PackageReceipt(ANONYMOUS_SCHEMA, root_sha256, hashlib.sha256(image).hexdigest(), len(image), len(validated))
        if not attest_package_seals(descriptor) or verify_package_fd(descriptor).receipt != receipt:
            raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "sealed package attestation differs")
        return SealedPackage(descriptor, receipt)
    except Exception:
        os.close(descriptor)
        raise


def attest_package_seals(descriptor: int) -> bool:
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    try:
        return fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == required
    except OSError:
        return False


def open_package(path: pathlib.Path) -> int:
    """Open a package read-only/no-follow and return the caller-owned FD."""
    parent_fd, leaf = _open_parent(path)
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent_fd)
        except OSError as error:
            raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, f"package open refused: {error.errno}") from None
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, "package is not a regular file")
    return descriptor


def verify_package_fd(descriptor: int) -> VerifiedPackage:
    """Verify exactly the bounded bytes observed through an already-open FD."""
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, "descriptor is not a regular file")
    if before.st_size <= 0 or before.st_size > MAX_PACKAGE_BYTES:
        raise ArtifactRefused(ArtifactRefusal.OVERSIZED, "package size is outside bounds")
    image = _pread_exact(descriptor, before.st_size)
    after = os.fstat(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after):
        raise ArtifactRefused(ArtifactRefusal.MUTATED_DURING_READ, "package changed while its snapshot was read")
    package_sha256 = hashlib.sha256(image).hexdigest()
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(image)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        _verify_schema(connection)
        manifest = connection.execute("SELECT schema, root_sha256, entry_count FROM package_manifest WHERE singleton = 1").fetchall()
        if len(manifest) != 1:
            raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "package has no unique manifest row")
        schema, recorded_root, entry_count = manifest[0]
        if schema not in {SCHEMA, ANONYMOUS_SCHEMA} or type(recorded_root) is not str or SHA256.fullmatch(recorded_root) is None or type(entry_count) is not int:
            raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "manifest fields are malformed")
        if schema == ANONYMOUS_SCHEMA and not attest_package_seals(descriptor):
            raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "anonymous package descriptor lacks exact seals")
        rows = connection.execute("SELECT entry_id, path_name, artifact_class, payload, size, sha256 FROM entries ORDER BY entry_id").fetchall()
    except ArtifactRefused:
        raise
    except sqlite3.Error as error:
        raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, f"SQLite package refused: {type(error).__name__}") from None
    finally:
        connection.close()
    entries = tuple(_entry_from_row(row) for row in rows)
    validated = _validate_entries(entries)
    recovery_point = _validate_semantics(validated) if schema == SCHEMA else _validate_anonymous_semantics(validated)
    if entry_count != len(validated):
        raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "manifest entry count disagrees")
    root_sha256 = _root_digest(validated)
    if root_sha256 != recorded_root:
        raise ArtifactRefused(ArtifactRefusal.DIGEST_MISMATCH, "package root digest disagrees")
    return VerifiedPackage(PackageReceipt(schema, root_sha256, package_sha256, len(image), len(validated)), validated, recovery_point)


def _render_package(entries: tuple[ArtifactEntry, ...], schema: str = SCHEMA) -> tuple[bytes, str]:
    root_sha256 = _root_digest(entries)
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_SQL)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.execute("INSERT INTO package_manifest VALUES (1, ?, ?, ?)", (schema, root_sha256, len(entries)))
        connection.executemany(
            "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?)",
            [(entry.entry_id, entry.path_name, entry.artifact_class.value, entry.payload, entry.size, entry.sha256) for entry in entries],
        )
        connection.commit()
        return connection.serialize(), root_sha256
    finally:
        connection.close()


def _verify_schema(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise ArtifactRefused(ArtifactRefusal.SCHEMA_MISMATCH, "package version or application ID differs")
    observed = tuple(connection.execute("SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"))
    if observed != EXPECTED_SCHEMA:
        raise ArtifactRefused(ArtifactRefusal.SCHEMA_MISMATCH, "SQLite schema differs from the closed package schema")
    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise ArtifactRefused(ArtifactRefusal.INVALID_PACKAGE, "SQLite quick check did not pass")


def _validate_entries(entries: tuple[ArtifactEntry, ...]) -> tuple[ArtifactEntry, ...]:
    if type(entries) is not tuple or not entries or len(entries) > MAX_ENTRIES:
        raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entries must be a bounded non-empty tuple")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for entry in entries:
        if type(entry) is not ArtifactEntry or type(entry.entry_id) is not str or ENTRY_ID.fullmatch(entry.entry_id) is None or len(entry.entry_id.encode()) > MAX_ID_BYTES:
            raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entry ID is not canonical")
        _validate_relative(entry.path_name)
        if not isinstance(entry.artifact_class, ArtifactClass) or type(entry.payload) is not bytes or not entry.payload or len(entry.payload) > MAX_ENTRY_BYTES:
            raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, f"entry {entry.entry_id!r} fields are malformed")
        if entry.entry_id in seen_ids or entry.path_name in seen_paths:
            raise ArtifactRefused(ArtifactRefusal.DUPLICATE_ENTRY, f"entry {entry.entry_id!r} duplicates an ID or path")
        seen_ids.add(entry.entry_id)
        seen_paths.add(entry.path_name)
        required = REQUIRED_BY_ID.get(entry.entry_id)
        if required is not None and (entry.path_name != required.path_name or entry.artifact_class is not required.artifact_class):
            raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, f"entry {entry.entry_id!r} changes its canonical coordinates")
        if entry.artifact_class is ArtifactClass.CREDENTIAL_DESCRIPTOR:
            _validate_credential_descriptor(entry.payload)
    missing = sorted(set(REQUIRED_BY_ID) - seen_ids)
    extra = sorted(seen_ids - set(REQUIRED_BY_ID))
    if missing:
        raise ArtifactRefused(ArtifactRefusal.MISSING_ENTRY, f"package omits {missing}")
    if extra:
        raise ArtifactRefused(ArtifactRefusal.EXTRA_ENTRY, f"package adds {extra}")
    return tuple(sorted(entries, key=lambda entry: entry.entry_id))


def _validate_credential_descriptor(payload: bytes) -> None:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtifactRefused(ArtifactRefusal.INVALID_CREDENTIAL_DESCRIPTOR, "credential descriptor is not JSON") from None
    if type(document) is not dict or set(document) != {"schema", "descriptors"} or document["schema"] != "automonique.synthetic-credential-descriptors/v1" or type(document["descriptors"]) is not list or not document["descriptors"]:
        raise ArtifactRefused(ArtifactRefusal.INVALID_CREDENTIAL_DESCRIPTOR, "credential descriptor envelope differs")
    for descriptor in document["descriptors"]:
        if type(descriptor) is not dict or set(descriptor) != {"id", "provider", "version", "audience"} or descriptor.get("provider") != "synthetic" or not all(type(descriptor.get(field)) is str and descriptor[field] for field in ("id", "version", "audience")) or not descriptor["audience"].endswith(".invalid"):
            raise ArtifactRefused(ArtifactRefusal.INVALID_CREDENTIAL_DESCRIPTOR, "credential descriptor is not metadata-only synthetic input")
    if payload != _json(document):
        raise ArtifactRefused(ArtifactRefusal.INVALID_CREDENTIAL_DESCRIPTOR, "credential descriptor is not canonical JSON")


def _validate_semantics(entries: tuple[ArtifactEntry, ...]) -> SyntheticRecoveryPoint:
    by_id = {entry.entry_id: entry for entry in entries}
    canonical_payloads = {
        entry.entry_id: entry.payload for entry in canonical_fixture_entries()
    }
    changed = sorted(
        entry_id
        for entry_id, entry in by_id.items()
        if entry.payload != canonical_payloads[entry_id]
    )
    if changed:
        raise ArtifactRefused(
            ArtifactRefusal.SEMANTIC_MISMATCH,
            f"synthetic fixture payloads differ from the closed canonical set: {changed}",
        )
    artifact_metadata = _json_document(by_id["artifact-metadata"].payload, "artifact metadata")
    artifacts = artifact_metadata.get("artifacts")
    tombstones = artifact_metadata.get("tombstones")
    if (
        type(artifacts) is not list
        or len(artifacts) != 1
        or type(tombstones) is not list
        or len(tombstones) != 1
        or type(tombstones[0]) is not dict
        or artifacts[0] != {"id": "fixture", "sha256": by_id["artifact-blob"].sha256}
        or tombstones[0] != {"id": "deleted-fixture", "revision": 1}
    ):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "artifact metadata, blob, and tombstone disagree")

    try:
        journal = [json.loads(line) for line in by_id["audit-journal"].payload.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "audit journal is malformed") from None
    snapshot = _json_document(by_id["snapshot-metadata"].payload, "snapshot metadata")
    configuration = _json_document(by_id["configuration-workspaces"].payload, "configuration")
    policy = _json_document(by_id["policy-bundle-hashes"].payload, "policy bundle")
    release = _json_document(by_id["release-manifests-schemas"].payload, "release manifest")
    credentials = _json_document(by_id["synthetic-credential-descriptor"].payload, "credential descriptor")
    if not journal or any(type(event) is not dict or type(event.get("event_id")) is not int for event in journal):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "audit journal has no typed event IDs")
    watermark = snapshot.get("watermark_event_id")
    configuration_revision = configuration.get("configuration_revision")
    database_watermark, database_configuration = _control_coordinates(by_id["control-database"].payload)
    if max(event["event_id"] for event in journal) != watermark or database_watermark != watermark or database_configuration != configuration_revision:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "journal, snapshot, database, and configuration coordinates disagree")
    if release.get("schema_versions") != [SCHEMA_VERSION] or release.get("configuration_revision") != configuration_revision or release.get("policy_revision") != policy.get("policy_revision") or policy.get("configuration_revision") != configuration_revision:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "release, schema, policy, and configuration coordinates disagree")
    descriptor_coordinates = [
        {field: descriptor[field] for field in ("audience", "id", "version")}
        for descriptor in credentials["descriptors"]
    ]
    if release.get("required_credential_descriptors") != descriptor_coordinates:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "release credential coordinates disagree with descriptor metadata")

    fields = (
        "fixed_backup_cadence_seconds",
        "snapshot_watermark_unix_ns",
        "newest_durable_at_loss_unix_ns",
    )
    if any(type(snapshot.get(field)) is not int or snapshot[field] < 0 for field in fields) or type(snapshot.get("derived_rpo_seconds")) not in {int, float}:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "synthetic recovery point fields are malformed")
    elapsed_ns = snapshot["newest_durable_at_loss_unix_ns"] - snapshot["snapshot_watermark_unix_ns"]
    derived_rpo = elapsed_ns / 1_000_000_000
    if elapsed_ns < 0 or derived_rpo != snapshot["derived_rpo_seconds"] or derived_rpo > snapshot["fixed_backup_cadence_seconds"] or snapshot.get("scope") != "synthetic-fixture" or snapshot.get("objective_eligible") is not False:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "synthetic recovery point ordering, derivation, or scope disagrees")
    return SyntheticRecoveryPoint(
        snapshot["fixed_backup_cadence_seconds"],
        snapshot["snapshot_watermark_unix_ns"],
        snapshot["newest_durable_at_loss_unix_ns"],
        float(derived_rpo),
        snapshot["scope"],
        False,
    )


def _validate_anonymous_semantics(entries: tuple[ArtifactEntry, ...]) -> SyntheticRecoveryPoint:
    by_id = {entry.entry_id: entry for entry in entries}
    canonical = {entry.entry_id: entry.payload for entry in canonical_fixture_entries()}
    fixed = {"context-memory-automation", "corresponding-source-locks", "disconnected-start-bundle", "last-known-good-seed-verifier", "synthetic-credential-descriptor", "tool-extension-manifests"}
    if any(by_id[name].payload != canonical[name] for name in fixed):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous fixed entries differ")
    metadata = _json_document(by_id["artifact-metadata"].payload, "anonymous metadata")
    blobs = _json_document(by_id["artifact-blob"].payload, "anonymous blobs")
    snapshot = _json_document(by_id["snapshot-metadata"].payload, "anonymous snapshot")
    config = _json_document(by_id["configuration-workspaces"].payload, "anonymous configuration")
    policy = _json_document(by_id["policy-bundle-hashes"].payload, "anonymous policy")
    release = _json_document(by_id["release-manifests-schemas"].payload, "anonymous release")
    if set(metadata) != {"artifacts", "manifest", "profile", "tombstones"} or metadata["profile"] != "anonymous-online-v1" or metadata["tombstones"] != []:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous metadata shape differs")
    if set(blobs) != {"blobs", "schema"} or blobs["schema"] != "automonique.anonymous-blobs/v1" or type(blobs["blobs"]) is not list:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous blob shape differs")
    events, rows = _anonymous_database(by_id["control-database"].payload)
    expected_rows = []
    expected_members = {"control.db": by_id["control-database"].sha256, "config.json": by_id["configuration-workspaces"].sha256}
    observed_blobs = {}
    for item in blobs["blobs"]:
        if type(item) is not dict or set(item) != {"payload_hex", "sha256", "size"}:
            raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous blob member shape differs")
        try:
            payload = bytes.fromhex(item["payload_hex"])
        except (TypeError, ValueError):
            raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous blob encoding differs") from None
        if item["payload_hex"] != payload.hex() or item["size"] != len(payload) or item["sha256"] != hashlib.sha256(payload).hexdigest():
            raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous blob digest differs")
        observed_blobs[item["sha256"]] = payload
    for index, artifact_id, digest, size in rows:
        seed = hashlib.sha256(f"20260811:{index}".encode()).digest()
        expected_payload = (seed * 5)[:128]
        if artifact_id != f"artifact-{index:06d}" or digest != hashlib.sha256(expected_payload).hexdigest() or size != 128 or observed_blobs.get(digest) != expected_payload:
            raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous deterministic artifact differs")
        expected_rows.append({"id": artifact_id, "sha256": digest, "size": size})
        expected_members[f"blobs/{digest[:2]}/{digest}"] = digest
    expected_digests = {row[2] for row in rows}
    if len(blobs["blobs"]) != len(rows) or set(observed_blobs) != expected_digests:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous blob set differs from database rows")
    if metadata["artifacts"] != expected_rows or metadata["manifest"] != {"members": expected_members, "schema": "automonique.anonymous-backup-manifest/v1", "watermark_event_id": 4, "watermark_ns": 4_000_000_000}:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous exact manifest differs")
    journal = b"".join(_json({"artifact_id": row[2], "event_id": row[0], "kind": row[1], "written_ns": row[3]}) for row in events)
    expected_events = [(index, "artifact_recorded", f"artifact-{index:06d}", index * 1_000_000_000) for index in range(1, 5)]
    if by_id["audit-journal"].payload != journal or events != expected_events:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous journal differs")
    if config != {"configuration_revision": 1, "history": [1], "schema": "automonique.anonymous-config/v1", "secret_values": None}:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous configuration differs")
    if policy != {"configuration_revision": 1, "policy_revision": 1, "sha256": "5" * 64} or release != {"configuration_revision": 1, "policy_revision": 1, "release": "anonymous-v1", "schema_versions": [1]}:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous policy or release differs")
    expected_snapshot = {"derived_rpo_seconds": 1.0, "fixed_backup_cadence_seconds": 60, "method": "anonymous-online-backup", "newest_durable_at_loss_unix_ns": 5_000_000_000, "objective_eligible": False, "scope": "anonymous-synthetic", "snapshot_watermark_unix_ns": 4_000_000_000, "watermark_event_id": 4}
    if snapshot != expected_snapshot:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous cadence or endpoint differs")
    return SyntheticRecoveryPoint(60, 4_000_000_000, 5_000_000_000, 1.0, "anonymous-synthetic", False)


def _anonymous_database(payload: bytes) -> tuple[list[tuple[int, str, str, int]], list[tuple[int, str, str, int]]]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(payload)
        connection.execute("PRAGMA query_only=ON")
        objects = tuple(connection.execute("SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"))
        expected = (
            ("artifacts", "table", "CREATE TABLE artifacts (artifact_index INTEGER PRIMARY KEY, artifact_id TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL) STRICT"),
            ("events", "table", "CREATE TABLE events (event_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id), written_ns INTEGER NOT NULL) STRICT"),
        )
        if objects != expected:
            raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous database schema differs")
        events = list(connection.execute("SELECT event_id,kind,artifact_id,written_ns FROM events ORDER BY event_id"))
        rows = list(connection.execute("SELECT artifact_index,artifact_id,sha256,size_bytes FROM artifacts ORDER BY artifact_index"))
    except sqlite3.Error:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "anonymous database cannot be inspected") from None
    finally:
        connection.close()
    return events, rows


def _json_document(payload: bytes, subject: str) -> dict[str, object]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, f"{subject} is not JSON") from None
    if type(document) is not dict or payload != _json(document):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, f"{subject} is not canonical JSON")
    return document


def _control_coordinates(payload: bytes) -> tuple[int, int]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(payload)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        schema = tuple(connection.execute("SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"))
        rows = connection.execute("SELECT watermark_event_id, configuration_revision FROM snapshot_state").fetchall()
    except sqlite3.Error:
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "control database cannot be inspected") from None
    finally:
        connection.close()
    if schema != (("snapshot_state", "table"),) or len(rows) != 1 or any(type(value) is not int for value in rows[0]):
        raise ArtifactRefused(ArtifactRefusal.SEMANTIC_MISMATCH, "control database schema or coordinates differ")
    return rows[0]


def _root_digest(entries: tuple[ArtifactEntry, ...]) -> str:
    digest = hashlib.sha256(b"automonique.synthetic-recovery-package/root/v1\0")
    for entry in entries:
        for value in (entry.entry_id, entry.path_name, entry.artifact_class.value, str(entry.size), entry.sha256):
            encoded = value.encode()
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def _entry_from_row(row: tuple[object, ...]) -> ArtifactEntry:
    entry_id, path_name, raw_class, payload, size, digest = row
    if type(size) is not int or type(digest) is not str or SHA256.fullmatch(digest) is None or type(payload) is not bytes or size != len(payload) or hashlib.sha256(payload).hexdigest() != digest:
        raise ArtifactRefused(ArtifactRefusal.DIGEST_MISMATCH, "entry size or digest disagrees")
    try:
        artifact_class = ArtifactClass(raw_class)
    except (TypeError, ValueError):
        raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entry class is unknown") from None
    if type(entry_id) is not str or type(path_name) is not str:
        raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entry coordinates have wrong types")
    return ArtifactEntry(entry_id, path_name, artifact_class, payload)


def _validate_relative(value: str) -> None:
    if type(value) is not str or not value or len(value.encode()) > MAX_PATH_BYTES or "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entry path is malformed")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactRefused(ArtifactRefusal.INVALID_ENTRY, "entry path is not canonical relative")


def _open_parent(path: pathlib.Path) -> tuple[int, str]:
    if not isinstance(path, pathlib.Path) or not path.name or path.name in {".", ".."}:
        raise ArtifactRefused(ArtifactRefusal.INVALID_PATH, "package path has no canonical leaf")
    parts = path.parts
    if ".." in parts:
        raise ArtifactRefused(ArtifactRefusal.INVALID_PATH, "package path traverses a parent")
    descriptor = os.open("/" if path.is_absolute() else ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parents = parts[1:-1] if path.is_absolute() else parts[:-1]
        for part in parents:
            flags = os.O_RDONLY | os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, path.name
    except OSError as error:
        os.close(descriptor)
        raise ArtifactRefused(ArtifactRefusal.SYMLINK_OR_TYPE, f"package parent refused: {error.errno}") from None


def _pread_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(65536, size - offset), offset)
        if not chunk:
            raise ArtifactRefused(ArtifactRefusal.MUTATED_DURING_READ, "package became truncated")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short package write")
        view = view[written:]


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _fixture_control_database() -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE snapshot_state (watermark_event_id INTEGER NOT NULL, configuration_revision INTEGER NOT NULL) STRICT")
        connection.execute("INSERT INTO snapshot_state VALUES (1, 1)")
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()
